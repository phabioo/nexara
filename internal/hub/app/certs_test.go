package app

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/phabioo/nexara/internal/pki"
)

type certEnv struct {
	m    *certManager
	ca   *pki.CA
	dir  string
	now  time.Time
	cfg  *tls.Config
	ln   net.Listener
	name []string
	ips  []net.IP
}

func newCertEnv(t *testing.T) *certEnv {
	t.Helper()
	dir := t.TempDir()
	ca, err := pki.LoadOrCreateCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	log, _ := testLogger()
	e := &certEnv{ca: ca, dir: dir, now: time.Now(), name: []string{"hub.local", "localhost"}, ips: []net.IP{net.IPv4(127, 0, 0, 1)}}
	e.m = newCertManager(ca, dir, log, func() time.Time { return e.now })
	e.m.localNames = func() []string { return e.name }
	e.m.localIPs = func() []net.IP { return e.ips }
	return e
}

// serve starts a TLS listener with the production config (reloading certificate).
func (e *certEnv) serve(t *testing.T) {
	t.Helper()
	cfg, err := pki.ServerTLSConfig(e.ca, filepath.Join(e.dir, pki.ServerCertFile), filepath.Join(e.dir, pki.ServerKeyFile), nil)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.(*tls.Conn).Handshake()
			}()
		}
	}()
	e.ln = ln
}

// peer returns the leaf certificate a new connection receives.
func (e *certEnv) peer(t *testing.T) *x509.Certificate {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(e.ca.Cert)
	conn, err := tls.Dial("tcp", e.ln.Addr().String(), &tls.Config{RootCAs: pool, ServerName: "localhost"})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	return conn.ConnectionState().PeerCertificates[0]
}

func TestCertManagerReissuesWithoutRestart(t *testing.T) {
	e := newCertEnv(t)
	issued, err := e.m.Ensure()
	if err != nil || !issued {
		t.Fatalf("first Ensure: %v %v", issued, err)
	}
	if issued, err := e.m.Ensure(); err != nil || issued {
		t.Fatalf("second Ensure must be a no-op: %v %v", issued, err)
	}
	e.serve(t)
	first := e.peer(t)
	if !slices.Contains(first.DNSNames, "hub.local") {
		t.Fatalf("first certificate names = %v", first.DNSNames)
	}

	// The device gets a new address and the operator chose an agent name in the wizard.
	e.ips = append(e.ips, net.IPv4(192, 0, 2, 44))
	e.m.SetAgentHost("frpi5.example")
	issued, err = e.m.Ensure()
	if err != nil || !issued {
		t.Fatalf("Ensure after a change: %v %v", issued, err)
	}
	second := e.peer(t) // same listener, new handshake
	if second.SerialNumber.Cmp(first.SerialNumber) == 0 {
		t.Fatal("the listener still serves the old certificate")
	}
	if !slices.Contains(second.DNSNames, "frpi5.example") || len(second.IPAddresses) != 2 {
		t.Errorf("new certificate: names %v ips %v", second.DNSNames, second.IPAddresses)
	}
	if err := second.VerifyHostname("frpi5.example"); err != nil {
		t.Errorf("agent host not covered: %v", err)
	}

	// An IP as agent address lands in the IP SANs.
	e.m.SetAgentHost("192.0.2.99")
	if issued, err := e.m.Ensure(); err != nil || !issued {
		t.Fatalf("Ensure for an IP agent address: %v %v", issued, err)
	}
	if err := e.peer(t).VerifyHostname("192.0.2.99"); err != nil {
		t.Errorf("agent IP not covered: %v", err)
	}
}

func TestCertManagerRenewsBeforeExpiry(t *testing.T) {
	e := newCertEnv(t)
	if _, err := e.m.Ensure(); err != nil {
		t.Fatal(err)
	}
	e.now = e.now.Add(pki.LeafValidity - pki.RenewBefore - time.Hour)
	if issued, _ := e.m.Ensure(); issued {
		t.Error("renewed too early")
	}
	e.now = e.now.Add(2 * time.Hour)
	if issued, err := e.m.Ensure(); err != nil || !issued {
		t.Errorf("not renewed inside the renewal window: %v %v", issued, err)
	}
}

func TestCertManagerRunChecksPeriodically(t *testing.T) {
	e := newCertEnv(t)
	if _, err := e.m.Ensure(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := contextWithCancel(t)
	done := make(chan struct{})
	go func() { e.m.Run(ctx, 5*time.Millisecond); close(done) }()

	e.m.SetAgentHost("late.example")
	deadline := time.Now().Add(5 * time.Second)
	for {
		cert, err := tls.LoadX509KeyPair(filepath.Join(e.dir, pki.ServerCertFile), filepath.Join(e.dir, pki.ServerKeyFile))
		if err == nil {
			leaf, _ := x509.ParseCertificate(cert.Certificate[0])
			if slices.Contains(leaf.DNSNames, "late.example") {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("the periodic check did not re-issue the certificate")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}
}
