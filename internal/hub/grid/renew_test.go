package grid

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/phabioo/nexara/internal/hub/store"
	"github.com/phabioo/nexara/internal/pki"
	"github.com/phabioo/nexara/internal/protocol"
)

const day = 24 * time.Hour

type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// renewEnv is a Grid behind a real mTLS listener (the hub's own CA, the
// production server TLS configuration and revocation check), so renewal is
// tested through the same handshake path as in production.
//
// The hub clock starts at the real time. TLS verification uses the real time,
// so certificates that must work in a handshake are issued "now"; the hub
// clock only moves forward for expiry of pending certificates.
type renewEnv struct {
	t    *testing.T
	st   *store.Store
	g    *Grid
	ca   *pki.CA
	clk  *testClock
	srv  *httptest.Server
	pool *x509.CertPool
	logs *syncBuf
	// version is the agent version in hello (default "dev").
	version string
}

func newRenewEnv(t *testing.T, mods ...func(*Options)) *renewEnv {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "hub.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ca, err := pki.LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	e := &renewEnv{t: t, st: st, ca: ca, version: "dev", clk: &testClock{t: time.Now().UTC().Truncate(time.Second)}, logs: &syncBuf{}}
	opts := Options{
		Store: st, CA: ca, Now: e.clk.Now, OfflineAfter: time.Minute, HubVersion: "dev",
		Logger: slog.New(slog.NewTextHandler(e.logs, nil)),
	}
	for _, m := range mods {
		m(&opts)
	}
	g, err := NewGrid(opts)
	if err != nil {
		t.Fatal(err)
	}
	e.g = g
	t.Cleanup(g.Close)

	dir := t.TempDir()
	if _, err := pki.EnsureServerCert(ca, dir, []string{"localhost"}, nil, time.Now()); err != nil {
		t.Fatal(err)
	}
	tlsCfg, err := pki.ServerTLSConfig(ca, filepath.Join(dir, pki.ServerCertFile), filepath.Join(dir, pki.ServerKeyFile), g.IsRevoked)
	if err != nil {
		t.Fatal(err)
	}
	tlsCfg.NextProtos = []string{"http/1.1"}
	mux := http.NewServeMux()
	mux.Handle("GET /grid/connect", g.AgentHandler())
	e.srv = httptest.NewUnstartedServer(mux)
	e.srv.TLS = tlsCfg
	e.srv.StartTLS()
	t.Cleanup(e.srv.Close)

	e.pool = x509.NewCertPool()
	e.pool.AddCert(ca.Cert)
	return e
}

// agentCreds is an agent's key and certificate.
type agentCreds struct {
	pair    tls.Certificate
	keyPEM  []byte
	certPEM []byte
	cert    *x509.Certificate
}

func (e *renewEnv) newCreds(hostID string, notAfterIn time.Duration) agentCreds {
	e.t.Helper()
	keyPEM, csrPEM, err := pki.NewAgentKeyAndCSR(hostID)
	if err != nil {
		e.t.Fatal(err)
	}
	// SignAgentCSR issues for LeafValidity from the given time.
	certPEM, cert, err := pki.SignAgentCSR(e.ca, csrPEM, hostID, time.Now().Add(notAfterIn-pki.LeafValidity))
	if err != nil {
		e.t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		e.t.Fatal(err)
	}
	return agentCreds{pair: pair, keyPEM: keyPEM, certPEM: certPEM, cert: cert}
}

// enroll creates a host whose certificate expires in notAfterIn (hub clock = real time).
func (e *renewEnv) enroll(name string, notAfterIn time.Duration) (HostID, agentCreds) {
	e.t.Helper()
	h, err := e.st.CreateHost(context.Background(), store.Host{Name: name, DisplayName: name, Address: name + ".local"})
	if err != nil {
		e.t.Fatal(err)
	}
	c := e.newCreds(h.ID, notAfterIn)
	if err := e.st.SetHostCert(context.Background(), h.ID, pki.Fingerprint(c.cert), pki.SerialHex(c.cert), c.cert.NotAfter); err != nil {
		e.t.Fatal(err)
	}
	h, _ = e.st.GetHost(context.Background(), h.ID)
	if err := e.g.Register(context.Background(), h); err != nil {
		e.t.Fatal(err)
	}
	return HostID(h.ID), c
}

// suppressAutoRenew makes the hub believe it asked a moment ago, so a connect does not trigger cert.renew.
func (e *renewEnv) suppressAutoRenew(id HostID) {
	e.g.mu.Lock()
	e.g.hosts[id].renewRequested = e.clk.Now()
	e.g.mu.Unlock()
}

func (e *renewEnv) dial(c agentCreds) (*websocket.Conn, context.CancelFunc, error) {
	ctx, cancel := context.WithTimeout(context.Background(), waitFor)
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: e.pool, ServerName: "localhost", Certificates: []tls.Certificate{c.pair}},
	}}
	ws, _, err := websocket.Dial(ctx, "wss://"+e.srv.Listener.Addr().String()+"/grid/connect", &websocket.DialOptions{HTTPClient: client})
	if err != nil {
		cancel()
		return nil, nil, err
	}
	return ws, cancel, nil
}

// connect connects as the agent with the given credentials and completes the hello exchange.
func (e *renewEnv) connect(c agentCreds, handler func(*fakeAgent, protocol.Envelope) bool) *fakeAgent {
	e.t.Helper()
	a, err := e.tryConnect(c, handler)
	if err != nil {
		e.t.Fatalf("connect: %v", err)
	}
	return a
}

func (e *renewEnv) connOfID(id HostID) *agentConn {
	e.g.mu.Lock()
	defer e.g.mu.Unlock()
	if st, ok := e.g.hosts[id]; ok {
		return st.conn
	}
	return nil
}

func (e *renewEnv) tryConnect(c agentCreds, handler func(*fakeAgent, protocol.Envelope) bool) (*fakeAgent, error) {
	id := HostID(c.cert.Subject.CommonName)
	before := e.connOfID(id)
	ws, cancel, err := e.dial(c)
	if err != nil {
		return nil, err
	}
	ws.SetReadLimit(protocol.MaxMessageSize)
	ctx, cancelRun := context.WithCancel(context.Background())
	cancelAll := func() { cancelRun(); cancel() }
	a := &fakeAgent{t: e.t, ws: ws, ctx: ctx, cancel: cancelAll, handler: handler,
		inbox: make(chan protocol.Envelope, 1024), done: make(chan struct{})}
	e.t.Cleanup(a.close)
	a.send(protocol.TypeHello, "h1", helloFor(e.version))
	rctx, rcancel := context.WithTimeout(ctx, waitFor)
	defer rcancel()
	_, data, err := ws.Read(rctx)
	if err != nil {
		return nil, err
	}
	env, err := protocol.Decode(data)
	if err != nil || env.Type != protocol.TypeHelloAck {
		e.t.Fatalf("bad ack %+v %v", env, err)
	}
	if a.ack, err = protocol.DecodeData[protocol.HelloAck](env); err != nil {
		e.t.Fatal(err)
	}
	if !a.ack.Accepted {
		return nil, fmt.Errorf("not accepted: %s", a.ack.Reason)
	}
	go a.run()
	// The ack is sent before the grid installs the connection; wait for it.
	eventually(e.t, func() bool { cur := e.connOfID(id); return cur != nil && cur != before })
	return a, nil
}

// request sends cert.csr and returns the hub's answer.
func (a *fakeAgent) csr(id string, csrPEM []byte) protocol.Envelope {
	a.t.Helper()
	a.send(protocol.TypeCertCSR, id, protocol.CertCSR{CSRPEM: string(csrPEM)})
	select {
	case env := <-a.inbox:
		if env.ID != id {
			a.t.Fatalf("answer id %q (%s), want %q", env.ID, env.Type, id)
		}
		return env
	case <-timeAfterWait():
		a.t.Fatal("no answer to cert.csr")
	}
	return protocol.Envelope{}
}

// issued requires a cert.issued answer, checks the certificate against the key and returns the credentials.
func (e *renewEnv) issued(env protocol.Envelope, keyPEM []byte, hostID HostID) agentCreds {
	e.t.Helper()
	if env.Type != protocol.TypeCertIssued {
		e.t.Fatalf("answer = %s %s, want cert.issued", env.Type, env.Data)
	}
	iss := decode[protocol.CertIssued](e.t, env)
	pair, err := tls.X509KeyPair([]byte(iss.CertPEM), keyPEM)
	if err != nil {
		e.t.Fatalf("issued certificate does not match the new key: %v", err)
	}
	cert, err := pki.ParseCertPEM([]byte(iss.CertPEM))
	if err != nil {
		e.t.Fatal(err)
	}
	if cert.Subject.CommonName != string(hostID) || len(cert.DNSNames) != 0 {
		e.t.Errorf("subject %v SANs %v, want CN=%s and no SANs", cert.Subject, cert.DNSNames, hostID)
	}
	if !iss.NotAfter.Equal(cert.NotAfter) {
		e.t.Errorf("not_after %v != certificate %v", iss.NotAfter, cert.NotAfter)
	}
	return agentCreds{pair: pair, keyPEM: keyPEM, certPEM: []byte(iss.CertPEM), cert: cert}
}

func (e *renewEnv) hostRow(id HostID) store.Host {
	e.t.Helper()
	h, err := e.st.GetHost(context.Background(), string(id))
	if err != nil {
		e.t.Fatal(err)
	}
	return h
}

func (e *renewEnv) audit(action string) []store.AuditEntry {
	var out []store.AuditEntry
	entries, err := e.st.ListAudit(context.Background(), 1000)
	if err != nil {
		e.t.Fatal(err)
	}
	for _, a := range entries {
		if a.Action == action {
			out = append(out, a)
		}
	}
	return out
}

func freshCSR(t *testing.T, cn string) (keyPEM, csrPEM []byte) {
	t.Helper()
	k, c, err := pki.NewAgentKeyAndCSR(cn)
	if err != nil {
		t.Fatal(err)
	}
	return k, c
}

// swallowRenew answers a hub-initiated cert.renew with ok and counts it.
func swallowRenew(n *atomic.Int32) func(*fakeAgent, protocol.Envelope) bool {
	return func(a *fakeAgent, env protocol.Envelope) bool {
		if env.Type != protocol.TypeCertRenew {
			return false
		}
		n.Add(1)
		a.result(env, true, "")
		return true
	}
}

func TestRenewalAgentInitiated(t *testing.T) {
	e := newRenewEnv(t)
	id, old := e.enroll("pi5", 25*day)
	oldFP := pki.Fingerprint(old.cert)
	e.suppressAutoRenew(id)

	a := e.connect(old, nil)
	newKey, csr := freshCSR(t, string(id))
	fresh := e.issued(a.csr("c1", csr), newKey, id)
	newFP := pki.Fingerprint(fresh.cert)

	if got, want := fresh.cert.NotAfter, e.clk.Now().Add(pki.LeafValidity); got.Sub(want) > time.Second || want.Sub(got) > time.Second {
		t.Errorf("new certificate expires %v, want about %v (the normal agent lifetime)", got, want)
	}
	if err := fresh.cert.CheckSignatureFrom(e.ca.Cert); err != nil {
		t.Error(err)
	}

	// Issued, not yet used: the database still names the old certificate and both are accepted.
	if row := e.hostRow(id); row.CertFingerprint != oldFP {
		t.Errorf("fingerprint of record changed before first use: %s", row.CertFingerprint)
	}
	if e.g.IsRevoked(oldFP) || e.g.IsRevoked(newFP) {
		t.Fatal("during the grace window both certificates must be accepted")
	}
	if issued := e.audit("cert.renew"); len(issued) != 1 || issued[0].Result != store.AuditOK || issued[0].Host != "pi5" ||
		!strings.Contains(issued[0].Detail, "issued") || strings.Contains(issued[0].Detail, "PRIVATE") {
		t.Fatalf("audit after issuing = %+v", issued)
	}

	// First use of the new certificate activates it.
	a2 := e.connect(fresh, nil)
	eventually(t, func() bool { return e.hostRow(id).CertFingerprint == newFP })
	row := e.hostRow(id)
	if row.CertSerial != pki.SerialHex(fresh.cert) || !row.CertNotAfter.Equal(fresh.cert.NotAfter) {
		t.Errorf("row after activation = %+v: fingerprint, serial and expiry must change together", row)
	}
	if !e.g.IsRevoked(oldFP) || e.g.IsRevoked(newFP) {
		t.Error("after activation only the new certificate is accepted")
	}
	if _, err := e.tryConnect(old, nil); err == nil {
		t.Error("the old certificate still connects after the new one was used")
	}
	if info, _ := e.g.Host(id); info.CertNotAfter.IsZero() || !info.CertNotAfter.Equal(fresh.cert.NotAfter) {
		t.Errorf("HostInfo.CertNotAfter = %v", info.CertNotAfter)
	}
	if got := e.audit("cert.renew"); len(got) != 2 || !strings.Contains(got[0].Detail+got[1].Detail, "activated") {
		t.Errorf("audit = %+v, want issued and activated", got)
	}
	a2.close()
	a.close()
}

func TestRenewalNotDueIsRefused(t *testing.T) {
	e := newRenewEnv(t)
	id, old := e.enroll("pi5", 200*day)
	a := e.connect(old, nil)
	key, csr := freshCSR(t, string(id))
	env := a.csr("c1", csr)
	if env.Type != protocol.TypeError {
		t.Fatalf("answer = %s, want error", env.Type)
	}
	if pe := decode[protocol.Error](t, env); pe.Code != protocol.CodeInvalidArgument {
		t.Errorf("code = %s", pe.Code)
	}
	_ = key
	if got := e.audit("cert.renew"); len(got) != 1 || got[0].Result != store.AuditDenied {
		t.Errorf("audit = %+v", got)
	}
}

func TestRenewalCSRValidation(t *testing.T) {
	e := newRenewEnv(t)
	id, old := e.enroll("pi5", 20*day)
	otherID, _ := e.enroll("pi3", 20*day)
	e.suppressAutoRenew(id)
	a := e.connect(old, nil)

	tests := []struct {
		name string
		csr  func() []byte
		code string
	}{
		{"foreign common name", func() []byte { _, c := freshCSR(t, string(otherID)); return c }, protocol.CodeInvalidArgument},
		{"free-form common name", func() []byte { _, c := freshCSR(t, "pi5"); return c }, protocol.CodeInvalidArgument},
		{"same key as the certificate in use", func() []byte { return csrForKey(t, old, string(id)) }, protocol.CodeInvalidArgument},
		{"garbage", func() []byte {
			return []byte("-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n")
		}, protocol.CodeInvalidArgument},
	}
	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := a.csr("c"+string(rune('a'+i)), tc.csr())
			if env.Type != protocol.TypeError {
				t.Fatalf("answer = %s, want error", env.Type)
			}
			if pe := decode[protocol.Error](t, env); pe.Code != tc.code {
				t.Errorf("code = %s, want %s", pe.Code, tc.code)
			}
			e.g.mu.Lock()
			n := len(e.g.pending)
			e.g.mu.Unlock()
			if n != 0 {
				t.Errorf("%d pending certificates after a refused request", n)
			}
		})
	}
	// None of the refusals disturbed the old certificate.
	if e.g.IsRevoked(pki.Fingerprint(old.cert)) {
		t.Error("old certificate lost")
	}
	denied := 0
	for _, en := range e.audit("cert.renew") {
		if en.Result == store.AuditError {
			denied++
		}
	}
	if denied != len(tests) {
		t.Errorf("%d error audit entries, want %d", denied, len(tests))
	}

	// Oversized and empty requests are bad requests.
	a.send(protocol.TypeCertCSR, "big", protocol.CertCSR{CSRPEM: strings.Repeat("A", maxCSRSize+1)})
	if env := a.expect(protocol.TypeError); decode[protocol.Error](t, env).Code != protocol.CodeBadRequest {
		t.Errorf("oversized: %s", env.Data)
	}
	a.send(protocol.TypeCertCSR, "empty", protocol.CertCSR{})
	if env := a.expect(protocol.TypeError); decode[protocol.Error](t, env).Code != protocol.CodeBadRequest {
		t.Errorf("empty: %s", env.Data)
	}
}

// csrForKey builds a CSR for the key of existing credentials.
func csrForKey(t *testing.T, c agentCreds, cn string) []byte {
	t.Helper()
	blk, _ := pem.Decode(c.keyPEM)
	key, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func TestRenewalDuplicateRequestKeepsTheFirstCertificate(t *testing.T) {
	e := newRenewEnv(t)
	id, old := e.enroll("pi5", 20*day)
	e.suppressAutoRenew(id)
	a := e.connect(old, nil)

	key1, csr1 := freshCSR(t, string(id))
	fresh := e.issued(a.csr("c1", csr1), key1, id)
	_, csr2 := freshCSR(t, string(id))
	env := a.csr("c2", csr2)
	if env.Type != protocol.TypeError || decode[protocol.Error](t, env).Code != protocol.CodeBusy {
		t.Fatalf("second request on the same connection = %s %s, want busy", env.Type, env.Data)
	}
	// The certificate from the first request still works.
	a2 := e.connect(fresh, nil)
	eventually(t, func() bool { return e.hostRow(id).CertFingerprint == pki.Fingerprint(fresh.cert) })
	a2.close()
}

func TestRenewalInterruptedBeforeStagingRecovers(t *testing.T) {
	e := newRenewEnv(t)
	id, old := e.enroll("pi5", 20*day)
	e.suppressAutoRenew(id)

	// The agent receives a certificate and crashes before it writes it down.
	a := e.connect(old, nil)
	key1, csr1 := freshCSR(t, string(id))
	lost := e.issued(a.csr("c1", csr1), key1, id)
	a.close()
	a.waitDone()

	// It comes back with the old certificate (which never stopped working) and asks again.
	eventually(t, func() bool { info, _ := e.g.Host(id); return !info.Online })
	e.suppressAutoRenew(id)
	b := e.connect(old, nil)
	key2, csr2 := freshCSR(t, string(id))
	fresh := e.issued(b.csr("c2", csr2), key2, id)

	if !e.g.IsRevoked(pki.Fingerprint(lost.cert)) {
		t.Error("the superseded certificate is still accepted")
	}
	if e.g.IsRevoked(pki.Fingerprint(fresh.cert)) || e.g.IsRevoked(pki.Fingerprint(old.cert)) {
		t.Error("old and new certificate must both be accepted")
	}
	if _, err := e.tryConnect(lost, nil); err == nil {
		t.Error("the lost certificate connects")
	}
	c := e.connect(fresh, nil)
	eventually(t, func() bool { return e.hostRow(id).CertFingerprint == pki.Fingerprint(fresh.cert) })
	c.close()
}

func TestRenewalPendingExpires(t *testing.T) {
	e := newRenewEnv(t)
	id, old := e.enroll("pi5", 20*day)
	e.suppressAutoRenew(id)
	a := e.connect(old, nil)
	key, csr := freshCSR(t, string(id))
	fresh := e.issued(a.csr("c1", csr), key, id)

	e.clk.Advance(pendingCertTTL - time.Minute)
	if e.g.IsRevoked(pki.Fingerprint(fresh.cert)) {
		t.Fatal("pending certificate expired early")
	}
	e.clk.Advance(2 * time.Minute)
	if !e.g.IsRevoked(pki.Fingerprint(fresh.cert)) {
		t.Fatal("pending certificate outlived the grace window")
	}
	if _, err := e.tryConnect(fresh, nil); err == nil {
		t.Error("an expired pending certificate connects")
	}
	// The old certificate was never replaced, so the agent is not locked out.
	if e.g.IsRevoked(pki.Fingerprint(old.cert)) {
		t.Fatal("old certificate rejected after an unused renewal")
	}
	b := e.connect(old, nil)
	b.close()
	if row := e.hostRow(id); row.CertFingerprint != pki.Fingerprint(old.cert) {
		t.Errorf("row changed without a first use: %+v", row)
	}
}

func TestRenewalHubInitiated(t *testing.T) {
	e := newRenewEnv(t)
	id, old := e.enroll("pi5", 200*day) // not due: only an operator action gets it signed
	var renews atomic.Int32
	a := e.connect(old, swallowRenew(&renews))
	if renews.Load() != 0 {
		t.Fatal("hub asked a healthy certificate to renew on connect")
	}

	if err := e.g.RenewCert(context.Background(), Actor{Operator: "op1", IP: "10.0.0.2"}, id); err != nil {
		t.Fatalf("RenewCert: %v", err)
	}
	if renews.Load() != 1 {
		t.Fatalf("cert.renew messages = %d", renews.Load())
	}
	key, csr := freshCSR(t, string(id))
	fresh := e.issued(a.csr("c1", csr), key, id)

	got := e.audit("cert.renew")
	var requested, issuedN bool
	for _, en := range got {
		requested = requested || (en.User == "op1" && strings.Contains(en.Detail, "requested") && strings.Contains(en.Detail, "10.0.0.2"))
		issuedN = issuedN || strings.Contains(en.Detail, "issued")
	}
	if !requested || !issuedN {
		t.Errorf("audit = %+v, want the operator's request and the issue", got)
	}

	// A second operator request while the new certificate waits for its first use is refused.
	if err := e.g.RenewCert(context.Background(), Actor{Operator: "op1"}, id); !errors.Is(err, ErrRenewInProgress) {
		t.Errorf("RenewCert while pending = %v, want ErrRenewInProgress", err)
	}
	b := e.connect(fresh, nil)
	b.close()
	a.close()

	if err := e.g.RenewCert(context.Background(), Actor{Operator: "op1"}, "nope"); !errors.Is(err, ErrHostNotFound) {
		t.Errorf("unknown host: %v", err)
	}
}

func TestRenewalHubInitiatedOnConnectAndDaily(t *testing.T) {
	e := newRenewEnv(t)
	dueID, due := e.enroll("due", 25*day)
	_, fine := e.enroll("fine", 300*day)

	var dueRenews, fineRenews atomic.Int32
	e.connect(fine, swallowRenew(&fineRenews))
	a := e.connect(due, swallowRenew(&dueRenews))
	eventually(t, func() bool { return dueRenews.Load() == 1 })
	if fineRenews.Load() != 0 {
		t.Error("a certificate with 300 days left was asked to renew")
	}

	// The daily sweep does not nag: one request per renewRetryAfter.
	e.g.CheckRenewals(context.Background())
	if dueRenews.Load() != 1 {
		t.Errorf("renew requests after an immediate sweep = %d, want 1", dueRenews.Load())
	}
	e.clk.Advance(renewRetryAfter + time.Minute)
	e.g.CheckRenewals(context.Background())
	// The agent reads the request asynchronously.
	eventually(t, func() bool { return dueRenews.Load() == 2 })
	// Once a certificate waits for its first use there is nothing left to ask.
	key, csr := freshCSR(t, string(dueID))
	e.issued(a.csr("c1", csr), key, dueID)
	e.clk.Advance(renewRetryAfter + time.Minute)
	e.g.CheckRenewals(context.Background())
	if dueRenews.Load() != 2 {
		t.Errorf("renew requests with a pending certificate = %d, want 2", dueRenews.Load())
	}
}

func TestRenewalConcurrentRequestsAreDeduplicated(t *testing.T) {
	e := newRenewEnv(t)
	id, old := e.enroll("pi5", 200*day)
	var renews atomic.Int32
	release := make(chan struct{})
	a := e.connect(old, func(a *fakeAgent, env protocol.Envelope) bool {
		if env.Type != protocol.TypeCertRenew {
			return false
		}
		renews.Add(1)
		<-release // the agent takes its time answering
		a.result(env, true, "")
		return true
	})
	defer a.close()

	const n = 8
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		go func() { errs <- e.g.RenewCert(context.Background(), Actor{Operator: "op"}, id) }()
	}
	// All but one return at once with ErrRenewInProgress.
	for i := 0; i < n-1; i++ {
		select {
		case err := <-errs:
			if !errors.Is(err, ErrRenewInProgress) {
				t.Fatalf("concurrent RenewCert = %v, want ErrRenewInProgress", err)
			}
		case <-timeAfterWait():
			t.Fatal("concurrent requests did not return")
		}
	}
	close(release)
	if err := <-errs; err != nil {
		t.Fatalf("the winning RenewCert = %v", err)
	}
	if renews.Load() != 1 {
		t.Fatalf("agent received %d cert.renew messages, want 1", renews.Load())
	}
}

func TestRenewalOldAgentWithoutSupport(t *testing.T) {
	e := newRenewEnv(t)
	id, old := e.enroll("pi5", 3*day) // within 7 days: the failure must be loud
	var renews atomic.Int32
	handler := func(a *fakeAgent, env protocol.Envelope) bool {
		if env.Type != protocol.TypeCertRenew {
			return false
		}
		renews.Add(1)
		a.send(protocol.TypeError, env.ID, protocol.Error{Code: protocol.CodeUnknownType, Message: "unknown message type"})
		return true
	}
	a := e.connect(old, handler)
	eventually(t, func() bool { return renews.Load() == 1 })
	eventually(t, func() bool {
		return strings.Contains(e.logs.String(), "renewal keeps failing") || strings.Contains(e.logs.String(), "relying on the automatic agent update")
	})

	// The connection survives, and the hub stops asking.
	if err := e.g.RenewCert(context.Background(), SystemActor, id); !errors.Is(err, ErrUnsupported) {
		t.Errorf("RenewCert on an old agent = %v, want ErrUnsupported", err)
	}
	if renews.Load() != 1 {
		t.Errorf("hub sent cert.renew again to an agent that does not know it (%d)", renews.Load())
	}
	if info, _ := e.g.Host(id); !info.Online {
		t.Error("an old agent was dropped because it does not know cert.renew")
	}
	if !strings.Contains(e.logs.String(), "level=ERROR") || !strings.Contains(e.logs.String(), "expires soon") {
		t.Errorf("an agent certificate within 7 days that cannot be renewed was not logged as an error:\n%s", e.logs.String())
	}
	a.close()
}

func TestRenewalWithoutCA(t *testing.T) {
	e := newRenewEnv(t, func(o *Options) { o.CA = nil })
	id, old := e.enroll("pi5", 20*day)
	var renews atomic.Int32
	a := e.connect(old, swallowRenew(&renews))
	defer a.close()
	if err := e.g.RenewCert(context.Background(), SystemActor, id); !errors.Is(err, ErrUnsupported) {
		t.Errorf("RenewCert without a CA = %v", err)
	}
	_, csr := freshCSR(t, string(id))
	env := a.csr("c1", csr)
	if env.Type != protocol.TypeError || decode[protocol.Error](t, env).Code != protocol.CodeUnsupported {
		t.Errorf("cert.csr without a CA = %s %s", env.Type, env.Data)
	}
	if renews.Load() != 0 {
		t.Error("hub asked for a renewal it cannot sign")
	}
}

func TestRenewalRemovedHostLosesPendingCertificate(t *testing.T) {
	e := newRenewEnv(t)
	id, old := e.enroll("pi5", 20*day)
	e.suppressAutoRenew(id)
	a := e.connect(old, nil)
	key, csr := freshCSR(t, string(id))
	fresh := e.issued(a.csr("c1", csr), key, id)

	if err := e.g.RemoveHost(context.Background(), Actor{Operator: "op"}, id); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]agentCreds{"old": old, "pending": fresh} {
		if !e.g.IsRevoked(pki.Fingerprint(c.cert)) {
			t.Errorf("%s certificate still accepted after the host was removed", name)
		}
		if _, err := e.tryConnect(c, nil); err == nil {
			t.Errorf("%s certificate connects after the host was removed", name)
		}
	}
	e.g.mu.Lock()
	n := len(e.g.pending)
	e.g.mu.Unlock()
	if n != 0 {
		t.Errorf("%d pending certificates left", n)
	}
}

func TestRenewalActivationRacesWithAnotherChange(t *testing.T) {
	e := newRenewEnv(t)
	id, old := e.enroll("pi5", 20*day)
	e.suppressAutoRenew(id)
	a := e.connect(old, nil)
	key, csr := freshCSR(t, string(id))
	fresh := e.issued(a.csr("c1", csr), key, id)

	// Somebody replaced the certificate of record in the meantime: the swap must not overwrite it.
	if err := e.st.SetHostCert(context.Background(), string(id), "other-fp", "99", time.Time{}); err != nil {
		t.Fatal(err)
	}
	// The agent is not acknowledged: it must keep its old pair instead of promoting the new one.
	if _, err := e.tryConnect(fresh, nil); err == nil || !strings.Contains(err.Error(), "not accepted") {
		t.Fatalf("connect with an unactivatable certificate = %v, want a refused hello", err)
	}
	if row := e.hostRow(id); row.CertFingerprint != "other-fp" {
		t.Errorf("activation overwrote a newer certificate of record: %+v", row)
	}
	failed := false
	for _, en := range e.audit("cert.renew") {
		failed = failed || (en.Result == store.AuditError && strings.Contains(en.Detail, "activation failed"))
	}
	if !failed {
		t.Error("a failed activation was not audited")
	}
}

func TestCertDue(t *testing.T) {
	now := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)
	tests := []struct {
		name     string
		notAfter time.Time
		want     bool
	}{
		{"unknown expiry", time.Time{}, true},
		{"expired", now.Add(-time.Hour), true},
		{"1 day left", now.Add(day), true},
		{"exactly 30 days left", now.Add(30 * day), true},
		{"30 days and a second left", now.Add(30*day + time.Second), false},
		{"a year left", now.Add(365 * day), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := certDue(store.Host{CertNotAfter: tc.notAfter}, now); got != tc.want {
				t.Errorf("certDue = %v, want %v", got, tc.want)
			}
		})
	}
}

// An agent older than the hub is updated first (decision #20); it renews after
// it came back with the new version. The hub must not ask the old one.
func TestRenewalWaitsForTheAgentUpdate(t *testing.T) {
	e := newRenewEnv(t, func(o *Options) { o.HubVersion = "0.2.0" })
	_, old := e.enroll("pi5", 20*day)
	var renews atomic.Int32
	e.version = "0.1.0"
	a := e.connect(old, swallowRenew(&renews))
	defer a.close()
	e.g.CheckRenewals(context.Background())
	if renews.Load() != 0 {
		t.Fatal("hub asked an outdated agent to renew on connect")
	}
	// The updated agent reconnects and is asked.
	e.version = "0.2.0"
	b := e.connect(old, swallowRenew(&renews))
	defer b.close()
	eventually(t, func() bool { return renews.Load() == 1 })
}

func TestSweepLogsOfflineHostsWithExpiringCertificates(t *testing.T) {
	tests := []struct {
		name string
		left time.Duration
		want string // substring of the log, "" = nothing logged at error level
	}{
		{"within 7 days", 3 * day, "host is offline"},
		{"already expired", -time.Hour, "has expired"},
		{"due but not yet urgent", 20 * day, ""},
		{"healthy", 200 * day, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newRenewEnv(t)
			if tc.left < 0 {
				// Issued in the past so that it is expired for the hub clock only.
				e.clk.Advance(-tc.left + time.Minute)
				tc.left = time.Minute
			}
			e.enroll("pi5", tc.left)
			e.g.CheckRenewals(context.Background())
			logs := e.logs.String()
			if tc.want == "" {
				if strings.Contains(logs, "level=ERROR") {
					t.Errorf("unexpected error log:\n%s", logs)
				}
				return
			}
			if !strings.Contains(logs, "level=ERROR") || !strings.Contains(logs, tc.want) {
				t.Errorf("log does not contain an error about %q:\n%s", tc.want, logs)
			}
		})
	}
}
