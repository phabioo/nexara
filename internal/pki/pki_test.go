package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

func newCA(t *testing.T) (*CA, string) {
	t.Helper()
	dir := t.TempDir()
	ca, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	return ca, dir
}

func readServerCert(t *testing.T, dir string) *x509.Certificate {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, ServerCertFile))
	if err != nil {
		t.Fatal(err)
	}
	c, err := ParseCertPEM(b)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCACreateAndReload(t *testing.T) {
	ca, dir := newCA(t)
	if !ca.Cert.IsCA || !strings.HasPrefix(ca.Cert.Subject.CommonName, "Nexara Nexus CA ") {
		t.Fatalf("unexpected CA cert: %+v", ca.Cert.Subject)
	}
	if got := ca.Cert.NotAfter.Sub(ca.Cert.NotBefore); got < 3649*24*time.Hour || got > 3651*24*time.Hour {
		t.Fatalf("CA validity = %v", got)
	}
	if runtime.GOOS != "windows" {
		st, err := os.Stat(filepath.Join(dir, CAKeyFile))
		if err != nil || st.Mode().Perm() != 0o600 {
			t.Fatalf("ca.key mode: %v %v", st, err)
		}
		st, _ = os.Stat(filepath.Join(dir, CACertFile))
		if st.Mode().Perm() != 0o644 {
			t.Fatalf("ca.pem mode: %v", st.Mode())
		}
	}
	again, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	if again.Fingerprint() != ca.Fingerprint() || !again.Key.Equal(ca.Key) {
		t.Fatal("reloaded CA differs")
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp") {
			t.Fatalf("temp file left behind: %s", e.Name())
		}
	}
}

func TestCAIncompleteOrBroken(t *testing.T) {
	_, dir := newCA(t)
	if err := os.Remove(filepath.Join(dir, CAKeyFile)); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateCA(dir); err == nil {
		t.Fatal("missing key must be an error, not a new CA")
	}
	// key from another CA
	_, other := newCA(t)
	k, _ := os.ReadFile(filepath.Join(other, CAKeyFile))
	if err := os.WriteFile(filepath.Join(dir, CAKeyFile), k, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateCA(dir); err == nil {
		t.Fatal("mismatching key must be rejected")
	}
}

func TestEnsureServerCert(t *testing.T) {
	ca, _ := newCA(t)
	now := time.Now()
	names := []string{"frpi5", "frpi5.local", "localhost"}
	ips := []net.IP{net.ParseIP("192.168.1.10"), net.ParseIP("127.0.0.1"), net.ParseIP("::1")}

	tests := []struct {
		name    string
		names   []string
		ips     []net.IP
		now     time.Time
		reissue bool
	}{
		{"first issue", names, ips, now, true},
		{"unchanged", names, ips, now, false},
		{"unchanged, other order and case", []string{"LOCALHOST", "frpi5.local", "frpi5"}, []net.IP{ips[2], ips[1], ips[0]}, now, false},
		{"new IP", names, append(slices.Clone(ips), net.ParseIP("10.0.0.5")), now, true},
		{"unchanged after new IP", names, append(slices.Clone(ips), net.ParseIP("10.0.0.5")), now, false},
		{"name removed", []string{"frpi5", "localhost"}, append(slices.Clone(ips), net.ParseIP("10.0.0.5")), now, true},
		{"near expiry", []string{"frpi5", "localhost"}, append(slices.Clone(ips), net.ParseIP("10.0.0.5")), now.Add(LeafValidity - 29*24*time.Hour), true},
		{"fresh after renewal", []string{"frpi5", "localhost"}, append(slices.Clone(ips), net.ParseIP("10.0.0.5")), now.Add(LeafValidity - 29*24*time.Hour), false},
	}
	dir := t.TempDir()
	for _, tc := range tests {
		got, err := EnsureServerCert(ca, dir, tc.names, tc.ips, tc.now)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got != tc.reissue {
			t.Errorf("%s: reissued = %v, want %v", tc.name, got, tc.reissue)
		}
	}

	// SAN set, usage and chain of the current certificate
	if _, err := EnsureServerCert(ca, dir, names, ips, now); err != nil { // reissue with original set
		t.Fatal(err)
	}
	cert := readServerCert(t, dir)
	if !slices.Equal(cert.DNSNames, []string{"frpi5", "frpi5.local", "localhost"}) {
		t.Errorf("DNS SANs = %v", cert.DNSNames)
	}
	gotIPs := normalizeIPs(cert.IPAddresses)
	if !slices.Equal(gotIPs, normalizeIPs(ips)) {
		t.Errorf("IP SANs = %v", gotIPs)
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth || cert.IsCA {
		t.Errorf("bad usage: %v ca=%v", cert.ExtKeyUsage, cert.IsCA)
	}
	pair, err := tls.LoadX509KeyPair(filepath.Join(dir, ServerCertFile), filepath.Join(dir, ServerKeyFile))
	if err != nil || len(pair.Certificate) != 2 {
		t.Fatalf("server.pem must hold leaf + CA: %v (%d certs)", err, len(pair.Certificate))
	}
}

func TestEnsureServerCertReissuesForOtherCAOrBrokenFiles(t *testing.T) {
	ca, _ := newCA(t)
	other, _ := newCA(t)
	dir := t.TempDir()
	now := time.Now()
	names := []string{"localhost"}
	if _, err := EnsureServerCert(ca, dir, names, nil, now); err != nil {
		t.Fatal(err)
	}
	if re, err := EnsureServerCert(other, dir, names, nil, now); err != nil || !re {
		t.Fatalf("new CA must trigger reissue: %v %v", re, err)
	}
	if err := os.WriteFile(filepath.Join(dir, ServerKeyFile), []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if re, err := EnsureServerCert(other, dir, names, nil, now); err != nil || !re {
		t.Fatalf("broken key must trigger reissue: %v %v", re, err)
	}
	if _, err := EnsureServerCert(other, dir, nil, nil, now); err == nil {
		t.Fatal("empty SAN set must be rejected")
	}
}

func TestLocalNamesAndIPs(t *testing.T) {
	names := LocalNames()
	if !slices.Contains(names, "localhost") {
		t.Errorf("names = %v", names)
	}
	if h, _ := os.Hostname(); h != "" {
		short := strings.ToLower(strings.SplitN(h, ".", 2)[0])
		if !slices.Contains(names, short+".local") {
			t.Errorf("missing %s.local in %v", short, names)
		}
	}
	ips := normalizeIPs(LocalIPs())
	if !slices.Contains(ips, "127.0.0.1") || !slices.Contains(ips, "::1") {
		t.Errorf("ips = %v", ips)
	}
	for _, s := range ips {
		ip := net.ParseIP(s)
		if s != "127.0.0.1" && s != "::1" && (ip.IsLoopback() || ip.IsLinkLocalUnicast()) {
			t.Errorf("unexpected address %s", s)
		}
	}
}

func TestSignAgentCSR(t *testing.T) {
	ca, _ := newCA(t)
	now := time.Now()
	keyPEM, csrPEM, err := NewAgentKeyAndCSR("pi-kitchen")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(csrPEM), "PRIVATE") || !strings.Contains(string(keyPEM), "PRIVATE KEY") {
		t.Fatal("PEM mixup")
	}
	certPEM, cert, err := SignAgentCSR(ca, csrPEM, "h_123", now)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseCertPEM(certPEM)
	if err != nil || Fingerprint(parsed) != Fingerprint(cert) {
		t.Fatalf("returned PEM and cert differ: %v", err)
	}
	if cert.Subject.CommonName != "h_123" {
		t.Errorf("CN = %q", cert.Subject.CommonName)
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Errorf("ExtKeyUsage = %v", cert.ExtKeyUsage)
	}
	if len(cert.DNSNames)+len(cert.IPAddresses)+len(cert.EmailAddresses)+len(cert.URIs) != 0 || cert.IsCA {
		t.Errorf("unexpected SANs/CA flag")
	}
	if got := cert.NotAfter.Sub(now); got < 364*24*time.Hour || got > 366*24*time.Hour {
		t.Errorf("validity = %v", got)
	}
	if cert.SerialNumber.Sign() <= 0 || cert.SerialNumber.BitLen() < 100 {
		t.Errorf("serial too small: %v", cert.SerialNumber)
	}
	if _, cert2, _ := SignAgentCSR(ca, csrPEM, "h_123", now); cert2.SerialNumber.Cmp(cert.SerialNumber) == 0 {
		t.Error("serials repeat")
	}
	if SerialHex(cert) == "" || NeedsRenewal(cert, now) || !NeedsRenewal(cert, now.Add(336*24*time.Hour)) {
		t.Error("renewal window wrong")
	}
	if err := cert.CheckSignatureFrom(ca.Cert); err != nil {
		t.Error(err)
	}
}

func TestSignAgentCSRIgnoresRequestedSANs(t *testing.T) {
	ca, _ := newCA(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:        pkix.Name{CommonName: "evil"},
		DNSNames:       []string{"frpi5.local"},
		IPAddresses:    []net.IP{net.ParseIP("10.0.0.1")},
		EmailAddresses: []string{"a@b.c"},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	_, cert, err := SignAgentCSR(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}), "host-1", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "host-1" || len(cert.DNSNames) != 0 || len(cert.IPAddresses) != 0 || len(cert.EmailAddresses) != 0 {
		t.Fatalf("requested identity leaked into certificate: %+v", cert)
	}
}

func TestSignAgentCSRRejects(t *testing.T) {
	ca, _ := newCA(t)
	_, goodCSR, _ := NewAgentKeyAndCSR("x")
	tampered := tamperCSR(t, goodCSR)

	tests := []struct {
		name   string
		csr    []byte
		hostID string
	}{
		{"bad signature", tampered, "h1"},
		{"not PEM", []byte("hello"), "h1"},
		{"wrong block type", []byte(strings.ReplaceAll(string(goodCSR), "CERTIFICATE REQUEST", "CERTIFICATE")), "h1"},
		{"empty host id", goodCSR, ""},
		{"host id with space", goodCSR, "a b"},
		{"host id too long", goodCSR, strings.Repeat("a", 65)},
	}
	for _, tc := range tests {
		if _, _, err := SignAgentCSR(ca, tc.csr, tc.hostID, time.Now()); err == nil {
			t.Errorf("%s: expected error", tc.name)
		}
	}
}

func TestFingerprints(t *testing.T) {
	ca, _ := newCA(t)
	hexFP := Fingerprint(ca.Cert)
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(hexFP) {
		t.Fatalf("fingerprint %q", hexFP)
	}
	disp := DisplayFingerprint(ca.Cert)
	if !regexp.MustCompile(`^([0-9A-F]{2}:){31}[0-9A-F]{2}$`).MatchString(disp) {
		t.Fatalf("display fingerprint %q", disp)
	}
	if strings.ToLower(strings.ReplaceAll(disp, ":", "")) != hexFP {
		t.Fatal("display and hex form disagree")
	}
	fromPEM, err := FingerprintFromPEM(ca.CertPEM())
	if err != nil || fromPEM != hexFP {
		t.Fatalf("FingerprintFromPEM = %q %v", fromPEM, err)
	}
	if _, err := FingerprintFromPEM([]byte("nope")); err == nil {
		t.Fatal("expected error")
	}
	for _, in := range []string{hexFP, disp, " " + disp + " ", strings.ToUpper(hexFP)} {
		if got, err := NormalizeFingerprint(in); err != nil || got != hexFP {
			t.Errorf("NormalizeFingerprint(%q) = %q %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "abc", strings.Repeat("zz", 32), hexFP + "00"} {
		if _, err := NormalizeFingerprint(bad); err == nil {
			t.Errorf("NormalizeFingerprint(%q) accepted", bad)
		}
	}
}
