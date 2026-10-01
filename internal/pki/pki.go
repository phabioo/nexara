// Package pki implements the hub's own small certificate authority, the
// server certificate shared by browsers and agents, agent client
// certificates and the TLS configurations built on them.
//
// Private keys never appear in errors or logs; callers get file paths and
// generic failure reasons only.
package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// CAValidity is 5 years since security review S-05 (decision #45);
	// LeafValidity and RenewBefore follow docs/concept.md ("Zertifikate & Name
	// im Netz"). CAs created before that change keep their 10 years.
	CAValidity   = 5 * 365 * 24 * time.Hour
	LeafValidity = 365 * 24 * time.Hour
	RenewBefore  = 30 * 24 * time.Hour

	// clockSkew backdates NotBefore: Raspberry Pis have no RTC and may boot
	// with a slightly wrong clock.
	clockSkew = 5 * time.Minute

	CACertFile     = "ca.pem"
	CAKeyFile      = "ca.key"
	ServerCertFile = "server.pem"
	ServerKeyFile  = "server.key"
)

// CA is the hub's certificate authority.
type CA struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
}

// CertPEM returns the PEM encoding of the CA certificate.
func (ca *CA) CertPEM() []byte { return encodeCertPEM(ca.Cert.Raw) }

// Fingerprint returns the lower-case hex SHA-256 of the CA certificate.
func (ca *CA) Fingerprint() string { return Fingerprint(ca.Cert) }

// LoadOrCreateCA loads ca.pem / ca.key from dir or creates a new CA there.
//
// A new CA carries critical NameConstraints (decision #45, S-05): DNS "local"
// (all *.local), "localhost", the hub's own host names and every entry of
// permitted (DNS names or IP addresses, e.g. the configured agent host), plus
// loopback, RFC 1918, link-local and IPv6 ULA ranges. Device trust stores that
// honor the extension then cannot be abused for other domains.
//
// An existing CA is loaded as it is, constraints or not: there is no forced
// rotation, because that would invalidate every installed trust anchor and
// agent. Only CAs created after this change are constrained.
func LoadOrCreateCA(dir string, permitted ...string) (*CA, error) {
	certPath := filepath.Join(dir, CACertFile)
	keyPath := filepath.Join(dir, CAKeyFile)

	certPEM, certErr := os.ReadFile(certPath)
	keyPEM, keyErr := os.ReadFile(keyPath)
	switch {
	case certErr == nil && keyErr == nil:
		return parseCA(certPEM, keyPEM, time.Now())
	case errors.Is(certErr, os.ErrNotExist) && errors.Is(keyErr, os.ErrNotExist):
		return createCA(dir, time.Now(), permitted)
	case certErr != nil && !errors.Is(certErr, os.ErrNotExist):
		return nil, fmt.Errorf("pki: read %s: %w", certPath, certErr)
	case keyErr != nil && !errors.Is(keyErr, os.ErrNotExist):
		return nil, fmt.Errorf("pki: read %s: %w", keyPath, keyErr)
	default:
		// One file without the other: never overwrite what is there.
		return nil, fmt.Errorf("pki: incomplete CA in %s (need both %s and %s)", dir, CACertFile, CAKeyFile)
	}
}

func parseCA(certPEM, keyPEM []byte, now time.Time) (*CA, error) {
	cert, err := ParseCertPEM(certPEM)
	if err != nil {
		return nil, fmt.Errorf("pki: CA certificate: %w", err)
	}
	key, err := parseKeyPEM(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("pki: CA key: %w", err)
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&key.PublicKey) {
		return nil, errors.New("pki: CA key does not match CA certificate")
	}
	if !cert.IsCA {
		return nil, errors.New("pki: CA certificate is not a CA")
	}
	if now.After(cert.NotAfter) {
		return nil, fmt.Errorf("pki: CA certificate expired on %s", cert.NotAfter.UTC().Format(time.RFC3339))
	}
	return &CA{Cert: cert, Key: key}, nil
}

func createCA(dir string, now time.Time, permitted []string) (*CA, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("pki: create %s: %w", dir, err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("pki: generate CA key: %w", err)
	}
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	host, _ := os.Hostname()
	if host == "" {
		host = "nexus"
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Nexara Nexus CA " + host},
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              now.Add(CAValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	applyNameConstraints(tmpl, permitted)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("pki: sign CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("pki: parse CA certificate: %w", err)
	}
	keyPEM, err := encodeKeyPEM(key)
	if err != nil {
		return nil, err
	}
	// Key first: a key without its cert is reported as incomplete, never as a
	// usable CA.
	if err := writeFileAtomic(filepath.Join(dir, CAKeyFile), keyPEM, 0o600); err != nil {
		return nil, err
	}
	if err := writeFileAtomic(filepath.Join(dir, CACertFile), encodeCertPEM(der), 0o644); err != nil {
		return nil, err
	}
	return &CA{Cert: cert, Key: key}, nil
}

// ParseCertPEM parses the first CERTIFICATE block of data.
func ParseCertPEM(data []byte) (*x509.Certificate, error) {
	for {
		var blk *pem.Block
		blk, data = pem.Decode(data)
		if blk == nil {
			return nil, errors.New("no certificate PEM block found")
		}
		if blk.Type == "CERTIFICATE" {
			return x509.ParseCertificate(blk.Bytes)
		}
	}
}

func parseKeyPEM(data []byte) (*ecdsa.PrivateKey, error) {
	blk, _ := pem.Decode(data)
	if blk == nil {
		return nil, errors.New("no PEM block found")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, errors.New("not a PKCS#8 private key")
	}
	ek, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an ECDSA private key")
	}
	return ek, nil
}

func encodeKeyPEM(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, errors.New("pki: encode private key")
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func encodeCertPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// newSerial returns a random positive 128-bit serial number.
func newSerial() (*big.Int, error) {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("pki: random serial: %w", err)
	}
	return n.Add(n, big.NewInt(1)), nil
}

// SerialHex formats a certificate serial the way it is stored in hosts.cert_serial.
func SerialHex(cert *x509.Certificate) string { return cert.SerialNumber.Text(16) }

// NeedsRenewal reports whether cert expires within RenewBefore of now.
func NeedsRenewal(cert *x509.Certificate, now time.Time) bool {
	return !now.Add(RenewBefore).Before(cert.NotAfter)
}

// Fingerprint is the lower-case hex SHA-256 of the certificate's DER encoding
// (the format stored in hosts.cert_fingerprint).
func Fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// DisplayFingerprint is the upper-case, colon separated form shown in the
// installer output and the Trust step ("4F:9A:...").
func DisplayFingerprint(cert *x509.Certificate) string {
	up := strings.ToUpper(Fingerprint(cert))
	parts := make([]string, 0, len(up)/2)
	for i := 0; i+1 < len(up); i += 2 {
		parts = append(parts, up[i:i+2])
	}
	return strings.Join(parts, ":")
}

// FingerprintFromPEM returns the Fingerprint of the first certificate in data.
func FingerprintFromPEM(data []byte) (string, error) {
	cert, err := ParseCertPEM(data)
	if err != nil {
		return "", err
	}
	return Fingerprint(cert), nil
}

// NormalizeFingerprint accepts hex with or without colons/spaces in any case
// and returns the lower-case hex form, or an error if it is not a SHA-256.
func NormalizeFingerprint(s string) (string, error) {
	s = strings.NewReplacer(":", "", " ", "", "-", "").Replace(strings.TrimSpace(s))
	s = strings.ToLower(s)
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != sha256.Size {
		return "", errors.New("pki: fingerprint must be 64 hex digits (SHA-256)")
	}
	return s, nil
}

// writeFileAtomic writes data to a temp file in the same directory and renames
// it over path, so readers never see a partial file.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp*")
	if err != nil {
		return fmt.Errorf("pki: write %s: %w", path, err)
	}
	name := tmp.Name()
	fail := func(err error) error {
		_ = tmp.Close()
		_ = os.Remove(name)
		return fmt.Errorf("pki: write %s: %w", path, err)
	}
	if err := tmp.Chmod(perm); err != nil {
		return fail(err)
	}
	if _, err := tmp.Write(data); err != nil {
		return fail(err)
	}
	if err := tmp.Sync(); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		return fail(err)
	}
	if err := os.Rename(name, path); err != nil {
		return fail(err)
	}
	return nil
}

// privateIPRanges are the IP ranges a hub CA may ever certify: loopback,
// RFC 1918, link-local and IPv6 ULA (decision #45).
var privateIPRanges = []string{
	"127.0.0.0/8", "::1/128",
	"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
	"169.254.0.0/16", "fe80::/10", "fc00::/7",
}

// applyNameConstraints sets critical permitted-subtree constraints on the CA
// template. extra holds additional DNS names or IP addresses (e.g. the
// configured agent host); an IP inside the private ranges is redundant but
// harmless.
func applyNameConstraints(tmpl *x509.Certificate, extra []string) {
	dns := map[string]bool{"local": true}
	for _, n := range LocalNames() {
		dns[n] = true
	}
	var ranges []*net.IPNet
	for _, r := range privateIPRanges {
		_, n, err := net.ParseCIDR(r)
		if err == nil {
			ranges = append(ranges, n)
		}
	}
	for _, e := range extra {
		e = strings.ToLower(strings.TrimSpace(strings.Trim(strings.TrimSpace(e), "[]")))
		e = strings.TrimSuffix(e, ".")
		switch ip := net.ParseIP(e); {
		case e == "":
		case ip != nil:
			if v4 := ip.To4(); v4 != nil {
				ranges = append(ranges, &net.IPNet{IP: v4, Mask: net.CIDRMask(32, 32)})
			} else {
				ranges = append(ranges, &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)})
			}
		default:
			dns[e] = true
		}
	}
	tmpl.PermittedDNSDomainsCritical = true
	tmpl.PermittedDNSDomains = sortedKeys(dns)
	tmpl.PermittedIPRanges = ranges
}

// Permits reports whether the CA's name constraints allow a leaf certificate
// to carry name (a DNS name or an IP address). A CA without constraints (older
// installs) permits everything. The check mirrors x509.Verify so the hub can
// drop SANs that would make the whole certificate fail validation.
func (ca *CA) Permits(name string) bool {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if ip := net.ParseIP(strings.Trim(name, "[]")); ip != nil {
		return ca.permitsIP(ip)
	}
	if len(ca.Cert.PermittedDNSDomains) == 0 {
		return true
	}
	for _, d := range ca.Cert.PermittedDNSDomains {
		d = strings.ToLower(strings.TrimPrefix(d, "."))
		if name == d || strings.HasSuffix(name, "."+d) {
			return true
		}
	}
	return false
}

func (ca *CA) permitsIP(ip net.IP) bool {
	if len(ca.Cert.PermittedIPRanges) == 0 {
		return true
	}
	for _, r := range ca.Cert.PermittedIPRanges {
		if r.Contains(ip) {
			return true
		}
	}
	return false
}
