package grid

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/phabioo/nexara/internal/hub/agentbin"
	"github.com/phabioo/nexara/internal/hub/store"
	"github.com/phabioo/nexara/internal/pki"
	"github.com/phabioo/nexara/internal/protocol"
)

func TestRemoveHostOnline(t *testing.T) {
	e := newEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events := e.g.Subscribe(ctx)
	id := e.addHost("alpha", protocol.CapServices)
	a := e.connect("alpha", helloFor("0.1.0", protocol.CapServices), answerRefresh)

	actor := Actor{Operator: "op1", IP: "192.168.1.20"}
	if err := e.g.RemoveHost(ctx, actor, id); err != nil {
		t.Fatal(err)
	}
	a.waitDone() // the live connection is closed
	ev := waitEvent(t, events, EventHostRemoved)
	if ev.Host != id || ev.Payload.(HostInfo).Name != "alpha" {
		t.Fatalf("event %+v", ev)
	}
	if _, ok := e.g.Host(id); ok {
		t.Error("host still in the registry")
	}
	for _, h := range e.g.Hosts() {
		if h.ID == id {
			t.Error("host still listed")
		}
	}
	if !e.g.IsRevoked("fp-alpha") {
		t.Error("certificate not rejected after removal")
	}
	if _, ok := e.g.Snapshot(id); ok {
		t.Error("snapshot of a removed host")
	}

	got := e.waitAudit("host.remove")
	if got.User != "op1" || got.Host != "alpha" || got.Result != store.AuditOK || got.Detail != "from 192.168.1.20" {
		t.Errorf("audit entry %+v", got)
	}

	// Revoked in the database; the name is free for a new host.
	row, err := e.st.GetHost(ctx, string(id))
	if err != nil || !row.Revoked || row.Name == "alpha" {
		t.Fatalf("row after removal: %+v, %v", row, err)
	}
	if _, err := e.st.CreateHost(ctx, store.Host{Name: "alpha", CertFingerprint: "fp-alpha-2"}); err != nil {
		t.Fatalf("name not freed: %v", err)
	}
	// A restart does not bring it back.
	g2, err := NewGrid(Options{Store: e.st})
	if err != nil {
		t.Fatal(err)
	}
	defer g2.Close()
	for _, h := range g2.Hosts() {
		if h.ID == id {
			t.Error("removed host reloaded after restart")
		}
	}
	if !g2.IsRevoked("fp-alpha") {
		t.Error("restarted grid accepts the removed certificate")
	}
}

func TestRemoveHostOfflineAndErrors(t *testing.T) {
	e := newEnv(t)
	id := e.addHost("beta")
	other := e.addHost("gamma")

	tests := []struct {
		name string
		id   HostID
		err  error
	}{
		{"unknown host", "ffffffffffffffff", ErrHostNotFound},
		{"offline host", id, nil},
		{"already removed", id, ErrHostNotFound},
	}
	for _, tc := range tests {
		err := e.g.RemoveHost(context.Background(), Actor{Operator: "op"}, tc.id)
		if !errors.Is(err, tc.err) {
			t.Errorf("%s: err = %v, want %v", tc.name, err, tc.err)
		}
	}
	if _, ok := e.g.Host(other); !ok {
		t.Error("an unrelated host disappeared")
	}
	n := 0
	for _, a := range e.auditEntries() {
		if a.Action == "host.remove" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("host.remove audit entries = %d, want 1 (failed lookups are not host removals)", n)
	}
}

// TestRemovedHostRejectedOnReconnect runs the real mTLS path: a removed host's
// certificate is refused in the TLS handshake (IsRevoked) and, as a second
// barrier, by identifyTLS (database).
func TestRemovedHostRejectedOnReconnect(t *testing.T) {
	dir := t.TempDir()
	ca, err := pki.LoadOrCreateCA(filepath.Join(dir, "pki"))
	if err != nil {
		t.Fatal(err)
	}
	pkiDir := filepath.Join(dir, "pki")
	if _, err := pki.EnsureServerCert(ca, pkiDir, []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")}, time.Now()); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(dir, "hub.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	g, err := NewGrid(Options{Store: st, AgentBinary: func(string, string) (agentbin.Binary, bool) { return agentbin.Binary{}, false }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(g.Close)

	srvCfg, err := pki.ServerTLSConfig(ca, filepath.Join(pkiDir, pki.ServerCertFile), filepath.Join(pkiDir, pki.ServerKeyFile), g.IsRevoked)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", srvCfg)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(g.AgentHandler())
	srv.Listener = ln // httptest would replace the config's GetCertificate with its own certificate
	srv.Start()
	t.Cleanup(srv.Close)

	// Enroll "alpha" the way the enroll package does: CSR -> cert -> store -> Register.
	keyPEM, csrPEM, err := pki.NewAgentKeyAndCSR("alpha")
	if err != nil {
		t.Fatal(err)
	}
	h, err := st.CreateHost(context.Background(), store.Host{Name: "alpha", Capabilities: []string{protocol.CapServices}})
	if err != nil {
		t.Fatal(err)
	}
	certPEM, cert, err := pki.SignAgentCSR(ca, csrPEM, h.ID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetHostCert(context.Background(), h.ID, pki.Fingerprint(cert), pki.SerialHex(cert), cert.NotAfter); err != nil {
		t.Fatal(err)
	}
	h.CertFingerprint = pki.Fingerprint(cert)
	if err := g.Register(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	certFile, keyFile := filepath.Join(dir, "agent.pem"), filepath.Join(dir, "agent.key")
	if err := os.WriteFile(certFile, certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	cliCfg, err := pki.AgentTLSConfig(ca.CertPEM(), certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}

	dial := func() (*websocket.Conn, error) {
		ctx, cancel := context.WithTimeout(context.Background(), waitFor)
		defer cancel()
		ws, _, err := websocket.Dial(ctx, "wss://"+srv.Listener.Addr().String(), &websocket.DialOptions{
			HTTPClient: &http.Client{Transport: &http.Transport{TLSClientConfig: cliCfg.Clone()}},
		})
		return ws, err
	}
	hello := func(ws *websocket.Conn) error {
		ctx, cancel := context.WithTimeout(context.Background(), waitFor)
		defer cancel()
		b, _ := protocol.Encode(protocol.TypeHello, "h1", helloFor("0.1.0", protocol.CapServices))
		if err := ws.Write(ctx, websocket.MessageText, b); err != nil {
			return err
		}
		_, _, err := ws.Read(ctx)
		return err
	}

	ws, err := dial()
	if err != nil {
		t.Fatalf("connect before removal: %v", err)
	}
	if err := hello(ws); err != nil {
		t.Fatalf("hello before removal: %v", err)
	}
	eventually(t, func() bool { i, _ := g.Host(HostID(h.ID)); return i.Online })

	if err := g.RemoveHost(context.Background(), Actor{Operator: "op"}, HostID(h.ID)); err != nil {
		t.Fatal(err)
	}
	// The open connection is closed by the hub.
	rctx, rcancel := context.WithTimeout(context.Background(), waitFor)
	defer rcancel()
	for {
		// Requests the hub queued before the removal may still arrive; the read
		// must end with an error, not block.
		if _, _, err := ws.Read(rctx); err != nil {
			if rctx.Err() != nil {
				t.Fatal("connection of the removed host was not closed")
			}
			break
		}
	}
	_ = ws.CloseNow()

	// Reconnecting with the same certificate fails.
	if ws2, err := dial(); err == nil {
		err = hello(ws2) // TLS 1.3 reports the rejected client cert on first use
		_ = ws2.CloseNow()
		if err == nil {
			t.Fatal("removed host reconnected")
		}
	}
	if !g.IsRevoked(pki.Fingerprint(cert)) {
		t.Error("IsRevoked = false for the removed certificate")
	}
	// Second barrier: even if the handshake let it through, the database refuses.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	if _, err := g.authenticate(req); err == nil {
		t.Error("authenticate accepted the removed host's certificate")
	}
}
