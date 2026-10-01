package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// issueLeaf signs a server leaf with arbitrary SANs, bypassing the filtering
// in EnsureServerCert, to see what a verifier does with the CA's constraints.
func issueLeaf(t *testing.T, ca *CA, names []string, ips []string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := newSerial()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "leaf"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     names,
	}
	for _, s := range ips {
		tmpl.IPAddresses = append(tmpl.IPAddresses, net.ParseIP(s))
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func verifies(ca *CA, leaf *x509.Certificate, usage x509.ExtKeyUsage) error {
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	_, err := leaf.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{usage}})
	return err
}

func TestCANameConstraints(t *testing.T) {
	dir := t.TempDir()
	ca, err := LoadOrCreateCA(dir, "hub.example.org", "203.0.113.7", "2001:db8::7", "frpi5")
	if err != nil {
		t.Fatal(err)
	}
	if !ca.Cert.PermittedDNSDomainsCritical {
		t.Error("name constraints must be critical")
	}
	if len(ca.Cert.ExcludedDNSDomains) != 0 || len(ca.Cert.ExcludedIPRanges) != 0 {
		t.Error("only permitted subtrees are expected")
	}
	for _, want := range []string{"local", "localhost", "hub.example.org", "frpi5"} {
		if !slices.Contains(ca.Cert.PermittedDNSDomains, want) {
			t.Errorf("permitted DNS domains %v lack %q", ca.Cert.PermittedDNSDomains, want)
		}
	}
	// The constraint survives the PEM round trip.
	again, err := LoadOrCreateCA(dir)
	if err != nil || !again.Cert.PermittedDNSDomainsCritical || len(again.Cert.PermittedIPRanges) != len(ca.Cert.PermittedIPRanges) {
		t.Fatalf("reloaded CA lost its constraints: %v", err)
	}

	tests := []struct {
		name  string
		names []string
		ips   []string
		ok    bool
	}{
		{"mDNS name", []string{"frpi5.local"}, nil, true},
		{"nested local name", []string{"a.b.local"}, nil, true},
		{"localhost", []string{"localhost"}, nil, true},
		{"short host name", []string{"frpi5"}, nil, true},
		{"agent host DNS", []string{"hub.example.org"}, nil, true},
		{"agent host subdomain", []string{"x.hub.example.org"}, nil, true},
		{"loopback v4", nil, []string{"127.0.0.1"}, true},
		{"loopback v6", nil, []string{"::1"}, true},
		{"10/8", nil, []string{"10.1.2.3"}, true},
		{"172.16/12", nil, []string{"172.31.255.1"}, true},
		{"192.168/16", nil, []string{"192.168.1.10"}, true},
		{"link-local v4", nil, []string{"169.254.3.4"}, true},
		{"link-local v6", nil, []string{"fe80::1"}, true},
		{"ULA", nil, []string{"fd12:3456::1"}, true},
		{"agent host IPv4", nil, []string{"203.0.113.7"}, true},
		{"agent host IPv6", nil, []string{"2001:db8::7"}, true},
		{"everything at once", []string{"frpi5", "frpi5.local", "localhost"}, []string{"192.168.1.10", "127.0.0.1", "::1", "fd00::5"}, true},

		{"public domain", []string{"example.com"}, nil, false},
		{"domain with permitted suffix inside", []string{"hub.example.org.evil.com"}, nil, false},
		{"parent of agent host", []string{"example.org"}, nil, false},
		{"lookalike of local", []string{"foo.notlocal"}, nil, false},
		{"public IPv4", nil, []string{"8.8.8.8"}, false},
		{"other agent-host-like IPv4", nil, []string{"203.0.113.8"}, false},
		{"CGNAT", nil, []string{"100.64.1.1"}, false},
		{"172.32 is outside 172.16/12", nil, []string{"172.32.0.1"}, false},
		{"global IPv6", nil, []string{"2a00:1450::1"}, false},
		{"one bad SAN spoils the cert", []string{"frpi5.local", "example.com"}, []string{"192.168.1.10"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			leaf := issueLeaf(t, ca, tc.names, tc.ips)
			err := verifies(ca, leaf, x509.ExtKeyUsageServerAuth)
			if (err == nil) != tc.ok {
				t.Errorf("x509.Verify err = %v, want ok=%v", err, tc.ok)
			}
			// Permits mirrors the verifier for every single name.
			if tc.ok {
				for _, n := range append(slices.Clone(tc.names), tc.ips...) {
					if !ca.Permits(n) {
						t.Errorf("Permits(%q) = false, verifier accepts it", n)
					}
				}
			} else if len(tc.names)+len(tc.ips) == 1 {
				for _, n := range append(slices.Clone(tc.names), tc.ips...) {
					if ca.Permits(n) {
						t.Errorf("Permits(%q) = true, verifier rejects it", n)
					}
				}
			}
		})
	}
}

func TestNewCAWithoutExtraNamesStillCoversLocalHub(t *testing.T) {
	ca, err := LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range LocalNames() {
		if !ca.Permits(n) {
			t.Errorf("hub's own name %q is not permitted", n)
		}
	}
	if ca.Permits("example.com") {
		t.Error("public name permitted")
	}
}

func TestServerCertUnderConstrainedCA(t *testing.T) {
	ca, err := LoadOrCreateCA(t.TempDir(), "hub.example.org", "203.0.113.7")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	names := []string{"frpi5.local", "localhost", "hub.example.org", "evil.example.com"}
	ips := []net.IP{net.ParseIP("192.168.1.10"), net.ParseIP("127.0.0.1"), net.ParseIP("::1"),
		net.ParseIP("203.0.113.7"), net.ParseIP("8.8.8.8"), net.ParseIP("100.64.0.9"), net.ParseIP("2a00:1450::1")}
	issued, err := EnsureServerCert(ca, dir, names, ips, time.Now())
	if err != nil || !issued {
		t.Fatalf("EnsureServerCert: %v issued=%v", err, issued)
	}
	// Unchanged input must not reissue just because SANs were dropped.
	if again, err := EnsureServerCert(ca, dir, names, ips, time.Now()); err != nil || again {
		t.Fatalf("second call: %v reissued=%v", err, again)
	}
	leaf := readServerCert(t, dir)
	if err := verifies(ca, leaf, x509.ExtKeyUsageServerAuth); err != nil {
		t.Fatalf("server cert does not verify under the constrained CA: %v", err)
	}
	// Every SAN of the certificate verifies by name (the way a client checks it).
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	for _, n := range leaf.DNSNames {
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: n}); err != nil {
			t.Errorf("verify %q: %v", n, err)
		}
	}
	for _, ip := range leaf.IPAddresses {
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: ip.String()}); err != nil {
			t.Errorf("verify %s: %v", ip, err)
		}
	}
	if slices.Contains(leaf.DNSNames, "evil.example.com") {
		t.Error("unpermitted DNS name was put into the certificate")
	}
	for _, ip := range leaf.IPAddresses {
		if ip.String() == "8.8.8.8" || ip.String() == "100.64.0.9" || ip.String() == "2a00:1450::1" {
			t.Errorf("unpermitted IP %s in certificate", ip)
		}
	}
	for _, want := range []string{"hub.example.org", "frpi5.local", "localhost"} {
		if !slices.Contains(leaf.DNSNames, want) {
			t.Errorf("DNS SANs %v lack %q", leaf.DNSNames, want)
		}
	}
	if !slices.ContainsFunc(leaf.IPAddresses, func(ip net.IP) bool { return ip.Equal(net.ParseIP("203.0.113.7")) }) {
		t.Error("configured agent host IP missing")
	}
}

func TestAgentCertUnderConstrainedCA(t *testing.T) {
	ca, err := LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	_, csr, err := NewAgentKeyAndCSR("raspberrypi")
	if err != nil {
		t.Fatal(err)
	}
	_, cert, err := SignAgentCSR(ca, csr, "h_0123456789abcdef", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.DNSNames)+len(cert.IPAddresses)+len(cert.EmailAddresses)+len(cert.URIs) != 0 {
		t.Fatalf("agent certificates must carry no SANs: %+v", cert)
	}
	if err := verifies(ca, cert, x509.ExtKeyUsageClientAuth); err != nil {
		t.Fatalf("agent cert does not verify under the constrained CA: %v", err)
	}
}

// legacyCA writes a CA the way versions before decision #45 did: no name
// constraints, 10 years.
func legacyCA(t *testing.T, dir string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := newSerial()
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "Nexara Nexus CA old"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, BasicConstraintsValid: true,
		IsCA: true, MaxPathLen: 0, MaxPathLenZero: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, _ := encodeKeyPEM(key)
	if err := os.WriteFile(filepath.Join(dir, CAKeyFile), keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, CACertFile), encodeCertPEM(der), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestExistingCAWithoutConstraintsKeepsWorking(t *testing.T) {
	dir := t.TempDir()
	legacyCA(t, dir)
	before, _ := os.ReadFile(filepath.Join(dir, CACertFile))
	ca, err := LoadOrCreateCA(dir, "hub.example.org") // must not rotate or add constraints
	if err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(filepath.Join(dir, CACertFile))
	if string(before) != string(after) {
		t.Fatal("existing CA was rewritten")
	}
	if ca.Cert.PermittedDNSDomainsCritical || len(ca.Cert.PermittedDNSDomains) != 0 {
		t.Fatal("existing CA must stay unconstrained")
	}
	if !ca.Permits("example.com") || !ca.Permits("8.8.8.8") {
		t.Error("an unconstrained CA permits everything")
	}
	srv := t.TempDir()
	if _, err := EnsureServerCert(ca, srv, []string{"example.com", "frpi5.local"}, []net.IP{net.ParseIP("8.8.8.8")}, time.Now()); err != nil {
		t.Fatal(err)
	}
	leaf := readServerCert(t, srv)
	if !slices.Contains(leaf.DNSNames, "example.com") || len(leaf.IPAddresses) != 1 {
		t.Errorf("legacy CA: SANs were filtered: %v %v", leaf.DNSNames, leaf.IPAddresses)
	}
}
