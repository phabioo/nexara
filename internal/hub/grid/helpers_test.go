package grid

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/phabioo/nexara/internal/hub/agentbin"
	"github.com/phabioo/nexara/internal/hub/store"
	"github.com/phabioo/nexara/internal/protocol"
)

const waitFor = 5 * time.Second

type testEnv struct {
	t   *testing.T
	st  *store.Store
	g   *Grid
	srv *httptest.Server
}

// newEnv starts a Grid with an injected identity check (header X-Test-Host
// carries the host name) behind an httptest server.
func newEnv(t *testing.T, mods ...func(*Options)) *testEnv {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "hub.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	e := &testEnv{t: t, st: st}
	opts := Options{
		Store:        st,
		OfflineAfter: time.Minute,
		HubVersion:   "dev",
		Identify:     e.identify,
		AgentBinary:  func(string, string) (agentbin.Binary, bool) { return agentbin.Binary{}, false },
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

	mux := http.NewServeMux()
	mux.Handle("GET /grid/connect", g.AgentHandler())
	mux.Handle("GET /grid/agent/{os}/{arch}", g.AgentDownloadHandler())
	e.srv = httptest.NewServer(mux)
	t.Cleanup(e.srv.Close)
	return e
}

func (e *testEnv) identify(r *http.Request) (store.Host, error) {
	name := r.Header.Get("X-Test-Host")
	if name == "" {
		return store.Host{}, errors.New("no test identity")
	}
	return e.st.GetHostByName(r.Context(), name)
}

// addHost creates a host in the store and announces it to the grid.
func (e *testEnv) addHost(name string, caps ...string) HostID {
	e.t.Helper()
	h, err := e.st.CreateHost(context.Background(), store.Host{
		Name: name, DisplayName: strings.ToUpper(name), Address: name + ".local",
		CertFingerprint: "fp-" + name, Capabilities: caps,
	})
	if err != nil {
		e.t.Fatal(err)
	}
	if err := e.g.Register(context.Background(), h); err != nil {
		e.t.Fatal(err)
	}
	return HostID(h.ID)
}

func (e *testEnv) wsURL() string {
	return "ws" + strings.TrimPrefix(e.srv.URL, "http") + "/grid/connect"
}

func (e *testEnv) auditEntries() []store.AuditEntry {
	entries, err := e.st.ListAudit(context.Background(), 1000)
	if err != nil {
		e.t.Fatal(err)
	}
	return entries
}

// waitAudit waits for an audit entry with the action and returns it.
func (e *testEnv) waitAudit(action string) store.AuditEntry {
	e.t.Helper()
	var found store.AuditEntry
	eventually(e.t, func() bool {
		for _, a := range e.auditEntries() {
			if a.Action == action {
				found = a
				return true
			}
		}
		return false
	})
	return found
}

func eventually(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(waitFor)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not met in time")
}

// waitEvent returns the next event of the kind, skipping others.
func waitEvent(t *testing.T, ch <-chan Event, kind EventKind) Event {
	t.Helper()
	timeout := time.After(waitFor)
	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				t.Fatalf("event channel closed while waiting for %s", kind)
			}
			if ev.Kind == kind {
				return ev
			}
		case <-timeout:
			t.Fatalf("no %s event in time", kind)
		}
	}
}

func helloFor(version string, caps ...string) protocol.Hello {
	return protocol.Hello{
		AgentVersion: version, ProtocolVersion: protocol.ProtocolVersion, Hostname: "pi",
		OS: "linux", Arch: "arm64", Kernel: "6.6.31", Model: "Raspberry Pi 5", Capabilities: caps, MAC: "aa:bb:cc:dd:ee:ff",
	}
}

// fakeAgent is the agent end of a real WebSocket to the grid.
type fakeAgent struct {
	t       *testing.T
	ws      *websocket.Conn
	ctx     context.Context
	cancel  context.CancelFunc
	ack     protocol.HelloAck
	handler func(a *fakeAgent, env protocol.Envelope) bool // true = handled, not queued in inbox
	inbox   chan protocol.Envelope
	done    chan struct{} // closed when the connection ended
}

// connect dials the grid as the named host and performs the hello exchange.
// handler may be nil; messages it does not handle land in the inbox.
func (e *testEnv) connect(name string, hello protocol.Hello, handler func(*fakeAgent, protocol.Envelope) bool) *fakeAgent {
	e.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	ws, _, err := websocket.Dial(ctx, e.wsURL(), &websocket.DialOptions{HTTPHeader: http.Header{"X-Test-Host": {name}}})
	if err != nil {
		cancel()
		e.t.Fatalf("dial: %v", err)
	}
	ws.SetReadLimit(protocol.MaxMessageSize)
	a := &fakeAgent{t: e.t, ws: ws, ctx: ctx, cancel: cancel, handler: handler,
		inbox: make(chan protocol.Envelope, 1024), done: make(chan struct{})}
	e.t.Cleanup(a.close)
	a.send(protocol.TypeHello, "h1", hello)
	rctx, rcancel := context.WithTimeout(ctx, waitFor)
	defer rcancel()
	_, data, err := ws.Read(rctx)
	if err != nil {
		e.t.Fatalf("read ack: %v", err)
	}
	env, err := protocol.Decode(data)
	if err != nil || env.Type != protocol.TypeHelloAck || env.ID != "h1" {
		e.t.Fatalf("bad ack %+v, %v", env, err)
	}
	a.ack, err = protocol.DecodeData[protocol.HelloAck](env)
	if err != nil {
		e.t.Fatal(err)
	}
	go a.run()
	return a
}

func (a *fakeAgent) close() {
	a.cancel()
	_ = a.ws.CloseNow()
}

func (a *fakeAgent) run() {
	defer close(a.done)
	for {
		_, data, err := a.ws.Read(a.ctx)
		if err != nil {
			return
		}
		env, err := protocol.Decode(data)
		if err != nil {
			continue
		}
		if a.handler != nil && a.handler(a, env) {
			continue
		}
		select {
		case a.inbox <- env:
		case <-a.ctx.Done():
			return
		}
	}
}

func (a *fakeAgent) send(typ, id string, data any) {
	a.t.Helper()
	b, err := protocol.Encode(typ, id, data)
	if err != nil {
		a.t.Errorf("encode %s: %v", typ, err)
		return
	}
	ctx, cancel := context.WithTimeout(a.ctx, waitFor)
	defer cancel()
	if err := a.ws.Write(ctx, websocket.MessageText, b); err != nil && a.ctx.Err() == nil {
		a.t.Errorf("agent write %s: %v", typ, err)
	}
}

func (a *fakeAgent) result(req protocol.Envelope, ok bool, msg string) {
	a.send(protocol.TypeResult, req.ID, protocol.Result{OK: ok, Error: msg})
}

// expect waits for the next inbox message and requires its type.
func (a *fakeAgent) expect(typ string) protocol.Envelope {
	a.t.Helper()
	select {
	case env := <-a.inbox:
		if env.Type != typ {
			a.t.Fatalf("got message %q, want %q", env.Type, typ)
		}
		return env
	case <-time.After(waitFor):
		a.t.Fatalf("no %q message in time", typ)
	}
	return protocol.Envelope{}
}

func (a *fakeAgent) waitDone() {
	a.t.Helper()
	select {
	case <-a.done:
	case <-time.After(waitFor):
		a.t.Fatal("connection not closed in time")
	}
}

func decode[T any](t *testing.T, env protocol.Envelope) T {
	t.Helper()
	v, err := protocol.DecodeData[T](env)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// chain runs handlers in order until one handles the message.
func chain(hs ...func(*fakeAgent, protocol.Envelope) bool) func(*fakeAgent, protocol.Envelope) bool {
	return func(a *fakeAgent, env protocol.Envelope) bool {
		for _, h := range hs {
			if h(a, env) {
				return true
			}
		}
		return false
	}
}

// answerRefresh answers services.list and packages.list with fixed data.
func answerRefresh(a *fakeAgent, env protocol.Envelope) bool {
	switch env.Type {
	case protocol.TypeServicesList:
		a.send(protocol.TypeServices, env.ID, protocol.Services{Units: []protocol.ServiceUnit{
			{Name: "ssh.service", ActiveState: "active", SubState: "running"},
		}})
		return true
	case protocol.TypePackagesList:
		a.send(protocol.TypePackages, env.ID, protocol.Packages{
			Items:          []protocol.Package{{Name: "htop", State: protocol.PackageUpdate}},
			RebootRequired: true,
		})
		return true
	}
	return false
}

func timeAfterWait() <-chan time.Time { return time.After(waitFor) }
