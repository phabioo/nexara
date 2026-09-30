package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// LocalNames returns the DNS names the hub answers to: hostname,
// hostname.local (mDNS), the short hostname if the hostname is an FQDN, and
// "localhost". Sorted and de-duplicated.
func LocalNames() []string {
	set := map[string]bool{"localhost": true}
	if h, err := os.Hostname(); err == nil {
		h = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(h), "."))
		if h != "" {
			set[h] = true
			short := h
			if i := strings.IndexByte(h, '.'); i > 0 {
				short = h[:i]
				set[short] = true
			}
			if !strings.HasSuffix(short, ".local") {
				set[short+".local"] = true
			}
		}
	}
	return sortedKeys(set)
}

// LocalIPs returns all non-loopback, non-link-local unicast interface
// addresses plus 127.0.0.1 and ::1. Sorted and de-duplicated.
func LocalIPs() []net.IP {
	set := map[string]net.IP{}
	add := func(ip net.IP) {
		if v4 := ip.To4(); v4 != nil {
			ip = v4
		}
		set[ip.String()] = ip
	}
	add(net.IPv4(127, 0, 0, 1))
	add(net.IPv6loopback)
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
			ip.IsMulticast() || ip.IsUnspecified() {
			continue
		}
		add(ip)
	}
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]net.IP, 0, len(keys))
	for _, k := range keys {
		out = append(out, set[k])
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func normalizeNames(names []string) []string {
	set := map[string]bool{}
	for _, n := range names {
		n = strings.ToLower(strings.TrimSpace(n))
		if n != "" {
			set[n] = true
		}
	}
	return sortedKeys(set)
}

func normalizeIPs(ips []net.IP) []string {
	set := map[string]bool{}
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		set[ip.String()] = true // String() is canonical (IPv4-mapped IPv6 prints as IPv4)
	}
	return sortedKeys(set)
}

// EnsureServerCert issues server.pem / server.key in dir when they are
// missing or unusable, when the certificate's SANs differ from names+ips,
// when it was not issued by ca, or when it is within RenewBefore of expiry.
// server.pem holds the leaf followed by the CA certificate, so clients that
// pin the CA fingerprint (enrollment) can see the CA in the handshake. It
// reports whether a new certificate was written.
func EnsureServerCert(ca *CA, dir string, names []string, ips []net.IP, now time.Time) (bool, error) {
	wantNames := normalizeNames(names)
	wantIPs := normalizeIPs(ips)
	if len(wantNames) == 0 && len(wantIPs) == 0 {
		return false, errors.New("pki: server certificate needs at least one name or IP")
	}

	certPath := filepath.Join(dir, ServerCertFile)
	keyPath := filepath.Join(dir, ServerKeyFile)
	if serverCertCurrent(ca, certPath, keyPath, wantNames, wantIPs, now) {
		return false, nil
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return false, fmt.Errorf("pki: create %s: %w", dir, err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return false, fmt.Errorf("pki: generate server key: %w", err)
	}
	serial, err := newSerial()
	if err != nil {
		return false, err
	}
	cn := "nexus"
	if len(wantNames) > 0 {
		cn = wantNames[0]
	}
	if h, err := os.Hostname(); err == nil {
		if h = strings.ToLower(strings.TrimSpace(h)); h != "" {
			cn = h
		}
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              now.Add(LeafValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              wantNames,
	}
	for _, s := range wantIPs {
		tmpl.IPAddresses = append(tmpl.IPAddresses, net.ParseIP(s))
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		return false, fmt.Errorf("pki: sign server certificate: %w", err)
	}
	keyPEM, err := encodeKeyPEM(key)
	if err != nil {
		return false, err
	}
	chain := append(encodeCertPEM(der), ca.CertPEM()...)
	// Key before certificate: a reloader that sees the new key with the old
	// cert fails the pair check and keeps serving the old pair until the cert
	// lands a moment later.
	if err := writeFileAtomic(keyPath, keyPEM, 0o600); err != nil {
		return false, err
	}
	if err := writeFileAtomic(certPath, chain, 0o644); err != nil {
		return false, err
	}
	return true, nil
}

func serverCertCurrent(ca *CA, certPath, keyPath string, wantNames, wantIPs []string, now time.Time) bool {
	pair, err := tls.LoadX509KeyPair(certPath, keyPath) // also proves cert and key match
	if err != nil || len(pair.Certificate) == 0 {
		return false
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return false
	}
	if cert.CheckSignatureFrom(ca.Cert) != nil || NeedsRenewal(cert, now) {
		return false
	}
	if len(pair.Certificate) < 2 { // chain must carry the CA for pinned enrollment
		return false
	}
	if !equalStrings(normalizeNames(cert.DNSNames), wantNames) || !equalStrings(normalizeIPs(cert.IPAddresses), wantIPs) {
		return false
	}
	return true
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// NewAgentKeyAndCSR creates a new ECDSA P-256 key and a CSR for it (agent
// side). It returns PEM encodings; the key is PKCS#8.
func NewAgentKeyAndCSR(hostname string) (keyPEM, csrPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("pki: generate agent key: %w", err)
	}
	if hostname == "" {
		hostname = "grid-agent"
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: hostname},
	}, key)
	if err != nil {
		return nil, nil, errors.New("pki: create certificate request")
	}
	keyPEM, err = encodeKeyPEM(key)
	if err != nil {
		return nil, nil, err
	}
	return keyPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

// SignAgentCSR verifies the CSR's self-signature and issues a client
// certificate for hostID. Everything the agent asked for except its public key
// is ignored: CN is hostID, no SANs, no extensions, ExtKeyUsage ClientAuth
// only, 1 year validity, random 128-bit serial. It returns the certificate as
// PEM and parsed.
func SignAgentCSR(ca *CA, csrPEM []byte, hostID string, now time.Time) ([]byte, *x509.Certificate, error) {
	if hostID == "" || len(hostID) > 64 || strings.ContainsFunc(hostID, func(r rune) bool { return r < 0x21 || r == 0x7f }) {
		return nil, nil, errors.New("pki: invalid host id")
	}
	blk, _ := pem.Decode(csrPEM)
	if blk == nil || blk.Type != "CERTIFICATE REQUEST" {
		return nil, nil, errors.New("pki: no certificate request found")
	}
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil {
		return nil, nil, errors.New("pki: malformed certificate request")
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, nil, errors.New("pki: certificate request signature invalid")
	}
	pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, nil, errors.New("pki: certificate request must use an ECDSA P-256 key")
	}
	serial, err := newSerial()
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: hostID},
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              now.Add(LeafValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, pub, ca.Key)
	if err != nil {
		return nil, nil, fmt.Errorf("pki: sign agent certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("pki: parse agent certificate: %w", err)
	}
	return encodeCertPEM(der), cert, nil
}
