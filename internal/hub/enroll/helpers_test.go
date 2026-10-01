package enroll

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/phabioo/nexara/internal/hub/agentbin"
	"github.com/phabioo/nexara/internal/hub/grid"
	"github.com/phabioo/nexara/internal/hub/store"
	"github.com/phabioo/nexara/internal/pki"
	"github.com/phabioo/nexara/internal/protocol"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type testEnv struct {
	t        *testing.T
	svc      *Service
	st       *store.Store
	ca       *pki.CA
	dir      string
	clock    *fakeClock
	logs     *bytes.Buffer
	mu       sync.Mutex
	enrolled []store.Host
}

func (e *testEnv) enrolledHosts() []store.Host {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]store.Host(nil), e.enrolled...)
}

var testBinary = agentbin.Binary{OS: "linux", Arch: "arm64", Version: "0.1.0-test", SHA256: "00", Data: []byte("\x7fELF-fake-agent")}

func newEnv(t *testing.T, mods ...func(*Options)) *testEnv {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "nexus.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ca, err := pki.LoadOrCreateCA(filepath.Join(dir, "pki"))
	if err != nil {
		t.Fatal(err)
	}
	clock := &fakeClock{t: time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)}
	if _, err := pki.EnsureServerCert(ca, filepath.Join(dir, "pki"), []string{"frpi5.local"}, []net.IP{net.IPv4(127, 0, 0, 1)}, clock.Now()); err != nil {
		t.Fatal(err)
	}
	e := &testEnv{t: t, st: st, ca: ca, dir: dir, clock: clock, logs: &bytes.Buffer{}}
	opts := Options{
		Store: st, CA: ca,
		ServerCertFile: filepath.Join(dir, "pki", pki.ServerCertFile),
		HubAddress:     "frpi5.local", Port: 8443,
		DataDir: dir,
		Logger:  slog.New(slog.NewTextHandler(&lockedWriter{w: e.logs}, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Now:     clock.Now,
		OnEnrolled: func(_ context.Context, h store.Host) {
			e.mu.Lock()
			e.enrolled = append(e.enrolled, h)
			e.mu.Unlock()
		},
		AgentBinary: func(goos, goarch string) (agentbin.Binary, bool) {
			if goos == "linux" && goarch == "arm64" {
				return testBinary, true
			}
			return agentbin.Binary{}, false
		},
	}
	for _, m := range mods {
		m(&opts)
	}
	svc, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	e.svc = svc
	return e
}

type lockedWriter struct {
	mu sync.Mutex
	w  *bytes.Buffer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// newCode creates an enrollment code through the public API.
func (e *testEnv) newCode(caps []string) string {
	e.t.Helper()
	c, err := e.svc.NewEnrollCode(context.Background(), grid.Actor{Operator: "1", IP: "192.0.2.1"}, grid.EnrollOptions{Capabilities: caps})
	if err != nil {
		e.t.Fatal(err)
	}
	return c.Code
}

// post sends an enrollment request as an agent with hostname from ip.
func (e *testEnv) post(token, hostname, ip string) (*httptest.ResponseRecorder, protocol.EnrollResponse) {
	e.t.Helper()
	_, csr, err := pki.NewAgentKeyAndCSR(hostname)
	if err != nil {
		e.t.Fatal(err)
	}
	return e.postRaw(protocol.EnrollRequest{
		Token:  token,
		CSRPEM: string(csr),
		Hello: protocol.Hello{
			AgentVersion: "0.1.0", ProtocolVersion: protocol.ProtocolVersion, Hostname: hostname,
			OS: "linux", Arch: "arm64", Capabilities: []string{"monitoring", "packages"}, MAC: "DC:A6:32:11:22:33",
		},
	}, ip)
}

func helloRequest(token, hostname, goos, arch, csr string) protocol.EnrollRequest {
	return protocol.EnrollRequest{
		Token:  token,
		CSRPEM: csr,
		Hello: protocol.Hello{
			AgentVersion: "0.1.0", ProtocolVersion: protocol.ProtocolVersion, Hostname: hostname,
			OS: goos, Arch: arch, Capabilities: []string{"monitoring"},
		},
	}
}

func (e *testEnv) postRaw(req protocol.EnrollRequest, ip string) (*httptest.ResponseRecorder, protocol.EnrollResponse) {
	e.t.Helper()
	body, _ := json.Marshal(req)
	return e.postBody(body, ip)
}

func (e *testEnv) postBody(body []byte, ip string) (*httptest.ResponseRecorder, protocol.EnrollResponse) {
	e.t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/grid/enroll", bytes.NewReader(body))
	r.RemoteAddr = net.JoinHostPort(ip, "40000")
	w := httptest.NewRecorder()
	e.svc.Handler().ServeHTTP(w, r)
	var resp protocol.EnrollResponse
	if w.Code == http.StatusOK {
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			e.t.Fatalf("bad response body: %v", err)
		}
	}
	return w, resp
}

func (e *testEnv) auditActions() []store.AuditEntry {
	e.t.Helper()
	list, err := e.st.ListAudit(context.Background(), 100)
	if err != nil {
		e.t.Fatal(err)
	}
	return list
}
