package pki

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"
)

func tamperCSR(t *testing.T, csrPEM []byte) []byte {
	t.Helper()
	blk, _ := pem.Decode(csrPEM)
	der := slices.Clone(blk.Bytes)
	der[len(der)-1] ^= 0xff
	if _, err := x509.ParseCertificateRequest(der); err != nil {
		t.Fatalf("tampered CSR must still parse: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

// hub is a loopback TLS listener using ServerTLSConfig.
type hub struct {
	ca       *CA
	dir      string
	addr     string
	mu       sync.Mutex
	revoked  map[string]bool
	ln       net.Listener
	seenPeer chan string // CN of the client cert per accepted connection ("" = none)
}

func startHub(t *testing.T) *hub {
	t.Helper()
	ca, dir := newCA(t)
	if _, err := EnsureServerCert(ca, dir, []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")}, time.Now()); err != nil {
		t.Fatal(err)
	}
	h := &hub{ca: ca, dir: dir, revoked: map[string]bool{}, seenPeer: make(chan string, 16)}
	cfg, err := ServerTLSConfig(ca, filepath.Join(dir, ServerCertFile), filepath.Join(dir, ServerKeyFile), func(fp string) bool {
		h.mu.Lock()
		defer h.mu.Unlock()
		return h.revoked[fp]
	})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	h.ln, h.addr = ln, ln.Addr().String()
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				tc := c.(*tls.Conn)
				_ = tc.SetDeadline(time.Now().Add(5 * time.Second))
				if tc.Handshake() != nil {
					return
				}
				peer := ""
				if ps := tc.ConnectionState().PeerCertificates; len(ps) > 0 {
					peer = ps[0].Subject.CommonName
				}
				h.seenPeer <- peer
				_, _ = tc.Write([]byte("ok"))
			}()
		}
	}()
	return h
}

func (h *hub) revoke(fp string) {
	h.mu.Lock()
	h.revoked[fp] = true
	h.mu.Unlock()
}

// exchange dials the hub and reads the greeting. TLS 1.3 reports a rejected
// client certificate on the first read, so the read is part of the check.
// It returns the leaf certificate the server presented.
func (h *hub) exchange(cfg *tls.Config) (*x509.Certificate, error) {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", h.addr, cfg)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 2)
	if _, err := conn.Read(buf); err != nil {
		return nil, err
	}
	return conn.ConnectionState().PeerCertificates[0], nil
}

// issueAgent signs a new agent cert and writes it to a temp dir.
func issueAgent(t *testing.T, ca *CA, hostID string) (certFile, keyFile string, cert *x509.Certificate) {
	t.Helper()
	keyPEM, csrPEM, err := NewAgentKeyAndCSR("agent-" + hostID)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, cert, err := SignAgentCSR(ca, csrPEM, hostID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile, keyFile = filepath.Join(dir, "agent.pem"), filepath.Join(dir, "agent.key")
	if err := os.WriteFile(certFile, certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile, cert
}

func TestTLSHandshakes(t *testing.T) {
	h := startHub(t)
	certFile, keyFile, agentCert := issueAgent(t, h.ca, "host-1")
	agentCfg, err := AgentTLSConfig(h.ca.CertPEM(), certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(h.ca.Cert)

	// Agent with a valid certificate is accepted and identified.
	if _, err := h.exchange(agentCfg); err != nil {
		t.Fatalf("agent: %v", err)
	}
	if got := <-h.seenPeer; got != "host-1" {
		t.Fatalf("server saw client CN %q", got)
	}

	// Browser without a client certificate is accepted.
	if _, err := h.exchange(&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}); err != nil {
		t.Fatalf("browser: %v", err)
	}
	if got := <-h.seenPeer; got != "" {
		t.Fatalf("browser CN %q", got)
	}

	// TLS 1.2 is refused.
	if _, err := h.exchange(&tls.Config{RootCAs: pool, MaxVersion: tls.VersionTLS12}); err == nil {
		t.Fatal("TLS 1.2 accepted")
	}

	// Client certificate from a foreign CA is rejected.
	foreign, _ := newCA(t)
	fc, fk, _ := issueAgent(t, foreign, "host-x")
	foreignCfg, err := AgentTLSConfig(h.ca.CertPEM(), fc, fk)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.exchange(foreignCfg); err == nil {
		t.Fatal("foreign client certificate accepted")
	}

	// Revoked agent certificate is rejected, others are not affected.
	h.revoke(Fingerprint(agentCert))
	if _, err := h.exchange(agentCfg); err == nil {
		t.Fatal("revoked agent accepted")
	}
	c2, k2, _ := issueAgent(t, h.ca, "host-2")
	cfg2, _ := AgentTLSConfig(h.ca.CertPEM(), c2, k2)
	if _, err := h.exchange(cfg2); err != nil {
		t.Fatalf("second agent: %v", err)
	}

	// Agent does not trust a hub from another CA.
	otherAgentCfg, _ := AgentTLSConfig(foreign.CertPEM(), fc, fk)
	if _, err := h.exchange(otherAgentCfg); err == nil {
		t.Fatal("agent accepted a hub signed by an untrusted CA")
	}
}

func TestPinnedTLSConfig(t *testing.T) {
	h := startHub(t)
	good := DisplayFingerprint(h.ca.Cert)

	tests := []struct {
		name string
		fp   string
		ok   bool
	}{
		{"matching colon fingerprint", good, true},
		{"matching hex fingerprint", h.ca.Fingerprint(), true},
		{"foreign CA fingerprint", func() string { c, _ := newCA(t); return c.Fingerprint() }(), false},
		{"leaf fingerprint is not the CA", func() string {
			b, _ := os.ReadFile(filepath.Join(h.dir, ServerCertFile))
			fp, _ := FingerprintFromPEM(b)
			return fp
		}(), false},
	}
	for _, tc := range tests {
		cfg, err := PinnedTLSConfig(tc.fp)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		_, err = h.exchange(cfg)
		if (err == nil) != tc.ok {
			t.Errorf("%s: err = %v, want ok=%v", tc.name, err, tc.ok)
		}
	}

	// Right pin, but a server certificate that does not match the name asked for.
	cfg, _ := PinnedTLSConfig(good)
	cfg.ServerName = "other.example"
	if _, err := h.exchange(cfg); err == nil {
		t.Error("pinned config accepted a wrong host name")
	}

	// Right pin, server signed by a different CA that reuses nothing of the pinned one.
	evil := startHub(t)
	cfg, _ = PinnedTLSConfig(good)
	if _, err := evil.exchange(cfg); err == nil {
		t.Error("pinned config accepted a hub with a different CA")
	}

	if _, err := PinnedTLSConfig("not-a-fingerprint"); err == nil {
		t.Error("invalid fingerprint accepted")
	}
}

func TestServerCertReload(t *testing.T) {
	h := startHub(t)
	pool := x509.NewCertPool()
	pool.AddCert(h.ca.Cert)
	cfg := &tls.Config{RootCAs: pool}

	before, err := h.exchange(cfg)
	if err != nil {
		t.Fatal(err)
	}
	re, err := EnsureServerCert(h.ca, h.dir, []string{"localhost", "frpi5.local"}, []net.IP{net.ParseIP("127.0.0.1")}, time.Now())
	if err != nil || !re {
		t.Fatalf("reissue: %v %v", re, err)
	}
	after, err := h.exchange(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if before.SerialNumber.Cmp(after.SerialNumber) == 0 || !slices.Contains(after.DNSNames, "frpi5.local") {
		t.Fatal("server did not pick up the re-issued certificate")
	}
}

func TestServerTLSConfigMissingFiles(t *testing.T) {
	ca, dir := newCA(t)
	if _, err := ServerTLSConfig(ca, filepath.Join(dir, "nope.pem"), filepath.Join(dir, "nope.key"), nil); err == nil {
		t.Fatal("expected error")
	}
	if _, err := AgentTLSConfig([]byte("junk"), "a", "b"); err == nil {
		t.Fatal("expected error for junk CA")
	}
}
