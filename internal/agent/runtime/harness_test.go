package runtime

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/phabioo/nexara/internal/agent/metrics"
	"github.com/phabioo/nexara/internal/agent/shell"
	"github.com/phabioo/nexara/internal/config"
	"github.com/phabioo/nexara/internal/protocol"
)

const testTimeout = 5 * time.Second

// stopTimeout bounds how long Run may take to return after cancel. It must
// exceed coder/websocket's own 5 s wait for the peer's close frame: fake hubs
// that stopped reading never answer it.
const stopTimeout = 10 * time.Second

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(testTimeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func recvChan[T any](t *testing.T, ch <-chan T, what string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(testTimeout):
		t.Fatalf("timed out waiting for %s", what)
		panic("unreachable")
	}
}

func mustData[T any](t *testing.T, env protocol.Envelope) T {
	t.Helper()
	v, err := protocol.DecodeData[T](env)
	if err != nil {
		t.Fatalf("decode %s: %v", env.Type, err)
	}
	return v
}

// ---- fake hub ----

type hubConn struct {
	t *testing.T
	c *websocket.Conn
}

func (h *hubConn) recv() protocol.Envelope {
	h.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	_, data, err := h.c.Read(ctx)
	if err != nil {
		h.t.Fatalf("hub read: %v", err)
	}
	env, err := protocol.Decode(data)
	if err != nil {
		h.t.Fatalf("hub decode: %v", err)
	}
	return env
}

func (h *hubConn) recvType(typ string) protocol.Envelope {
	h.t.Helper()
	env := h.recv()
	if env.Type != typ {
		h.t.Fatalf("got %s (%s), want %s", env.Type, env.Data, typ)
	}
	return env
}

func (h *hubConn) send(typ, id string, data any) {
	h.t.Helper()
	b, err := protocol.Encode(typ, id, data)
	if err != nil {
		h.t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	if err := h.c.Write(ctx, websocket.MessageText, b); err != nil {
		h.t.Fatalf("hub write: %v", err)
	}
}

// rpc sends a request and returns the next message (monitoring must be off).
func (h *hubConn) rpc(typ, id string, data any) protocol.Envelope {
	h.t.Helper()
	h.send(typ, id, data)
	env := h.recv()
	if env.ID != id {
		h.t.Fatalf("answer id %q, want %q (%s)", env.ID, id, env.Type)
	}
	return env
}

// handshake reads the hello and answers it.
func (h *hubConn) handshake(ack protocol.HelloAck) protocol.Hello {
	h.t.Helper()
	env := h.recvType(protocol.TypeHello)
	hello := mustData[protocol.Hello](h.t, env)
	h.send(protocol.TypeHelloAck, env.ID, ack)
	return hello
}

func (h *hubConn) accept() protocol.Hello {
	h.t.Helper()
	return h.handshake(protocol.HelloAck{Accepted: true})
}

// drain keeps reading so the close handshake can complete; call it when the
// test no longer reads from the connection itself.
func (h *hubConn) drain() {
	go func() {
		for {
			if _, _, err := h.c.Read(context.Background()); err != nil {
				return
			}
		}
	}()
}

// sync round-trips an unknown message; once it is answered the agent's read
// loop is running (the connection is fully established).
func (h *hubConn) sync() {
	h.t.Helper()
	env := h.rpc("sync.ping", "sync", nil)
	if env.Type != protocol.TypeError {
		h.t.Fatalf("sync answer %s", env.Type)
	}
}

type fakeHub struct {
	t     *testing.T
	srv   *httptest.Server
	conns chan *hubConn
}

func newFakeHub(t *testing.T) *fakeHub {
	h := &fakeHub{t: t, conns: make(chan *hubConn, 16)}
	h.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		c.SetReadLimit(protocol.MaxMessageSize + 4096)
		h.conns <- &hubConn{t: t, c: c}
	}))
	t.Cleanup(h.srv.Close)
	return h
}

func (h *fakeHub) dial(ctx context.Context, _ string) (*websocket.Conn, error) {
	c, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(h.srv.URL, "http")+"/", nil)
	if err == nil {
		c.SetReadLimit(protocol.MaxMessageSize + 4096)
	}
	return c, err
}

func (h *fakeHub) next() *hubConn {
	h.t.Helper()
	c := recvChan(h.t, h.conns, "agent connection")
	h.t.Cleanup(func() { _ = c.c.CloseNow() })
	return c
}

// ---- fake clock ----

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
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// ---- fake capabilities ----

type fakeMetrics struct {
	n atomic.Int64
}

func (f *fakeMetrics) Collect(context.Context) (protocol.Metrics, error) {
	n := f.n.Add(1)
	return protocol.Metrics{Timestamp: time.Unix(n, 0).UTC(), CPUPercent: float64(n)}, nil
}

type fakeServices struct {
	mu         sync.Mutex
	restarted  []string
	restartErr error
}

func (f *fakeServices) List(context.Context) (protocol.Services, error) {
	return protocol.Services{Units: []protocol.ServiceUnit{{Name: "ssh.service", ActiveState: "active", SubState: "running"}}}, nil
}

func (f *fakeServices) Restart(_ context.Context, unit string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.restarted = append(f.restarted, unit)
	return f.restartErr
}

type fakePackages struct {
	run func(ctx context.Context, job protocol.JobStart, out func(protocol.JobOutput)) protocol.JobDone
}

func (f *fakePackages) List(context.Context) (protocol.Packages, error) {
	return protocol.Packages{Items: []protocol.Package{{Name: "curl", State: protocol.PackageInstalled}}, RebootRequired: true}, nil
}

func (f *fakePackages) Search(_ context.Context, q string) ([]protocol.Package, error) {
	return []protocol.Package{{Name: q, State: protocol.PackageAvailable}}, nil
}

func (f *fakePackages) Run(ctx context.Context, job protocol.JobStart, out func(protocol.JobOutput)) protocol.JobDone {
	return f.run(ctx, job, out)
}

type fakeSession struct {
	out      chan []byte
	eof      chan struct{}
	closed   chan struct{}
	in       chan []byte
	resizes  chan [2]int
	pending  []byte
	closeOne sync.Once
	eofOne   sync.Once
}

func newFakeSession() *fakeSession {
	return &fakeSession{
		out: make(chan []byte, 16), eof: make(chan struct{}), closed: make(chan struct{}),
		in: make(chan []byte, 16), resizes: make(chan [2]int, 16),
	}
}

func (f *fakeSession) Read(p []byte) (int, error) {
	if len(f.pending) == 0 {
		select {
		case b := <-f.out:
			f.pending = b
		case <-f.eof:
			return 0, io.EOF
		case <-f.closed:
			return 0, io.EOF
		}
	}
	n := copy(p, f.pending)
	f.pending = f.pending[n:]
	return n, nil
}

func (f *fakeSession) Write(p []byte) (int, error) {
	f.in <- append([]byte(nil), p...)
	return len(p), nil
}

func (f *fakeSession) Close() error { f.closeOne.Do(func() { close(f.closed) }); return nil }

func (f *fakeSession) Resize(cols, rows int) error { f.resizes <- [2]int{cols, rows}; return nil }

// exit simulates the shell process ending on its own.
func (f *fakeSession) exit() { f.eofOne.Do(func() { close(f.eof) }) }

type fakeSpawner struct {
	opened chan *fakeSession
}

func (f *fakeSpawner) Open(cols, rows int) (shell.Session, error) {
	s := newFakeSession()
	f.opened <- s
	return s, nil
}

// ---- harness ----

type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

type harness struct {
	t     *testing.T
	hub   *fakeHub
	agent *Agent
	cfg   config.AgentConfig
	clock *fakeClock
	logs  *lockedBuf

	metrics  *fakeMetrics
	services *fakeServices
	packages *fakePackages
	sessions *shell.Sessions
	spawner  *fakeSpawner

	cancel context.CancelFunc
	done   chan error
	exits  chan int

	mu         sync.Mutex
	sleeps     []time.Duration
	gate       chan struct{} // if set, Sleep blocks until it is closed
	entered    chan struct{} // receives one token per blocked Sleep
	failDials  atomic.Int32
	dialCount  atomic.Int32
	httpClient *http.Client
}

func newHarness(t *testing.T, mutate func(*config.AgentConfig)) *harness {
	t.Helper()
	cfg := config.DefaultAgent()
	cfg.Hub.URL = "wss://hub.test:8443/grid/connect"
	cfg.Shell.User = "pi"
	cfg.Capabilities.Monitoring = false
	cfg.Capabilities.Power = false
	if mutate != nil {
		mutate(&cfg)
	}
	h := &harness{
		t: t, hub: newFakeHub(t), cfg: cfg,
		clock:    &fakeClock{t: time.Unix(1_700_000_000, 0)},
		logs:     &lockedBuf{},
		metrics:  &fakeMetrics{},
		services: &fakeServices{},
		packages: &fakePackages{},
		spawner:  &fakeSpawner{opened: make(chan *fakeSession, 32)},
		done:     make(chan error, 1),
		exits:    make(chan int, 4),
		entered:  make(chan struct{}, 64),
	}
	h.sessions = shell.NewSessions(h.spawner)
	return h
}

func (h *harness) sleepFn(ctx context.Context, d time.Duration) error {
	h.mu.Lock()
	h.sleeps = append(h.sleeps, d)
	gate := h.gate
	h.mu.Unlock()
	if gate != nil {
		h.entered <- struct{}{}
		select {
		case <-gate:
		case <-ctx.Done():
			return ctx.Err()
		}
		return nil
	}
	return ctx.Err()
}

func (h *harness) gotSleeps() []time.Duration {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]time.Duration(nil), h.sleeps...)
}

// start builds the agent (options may be tweaked by opt) and runs it.
func (h *harness) start(opt func(*Options)) {
	h.t.Helper()
	opts := Options{
		Config:  h.cfg,
		Metrics: h.metrics,
		Facts: func() metrics.HostFacts {
			return metrics.HostFacts{Hostname: "frpi5", OS: "linux", Arch: "arm64", Kernel: "6.6", Model: "Pi 5", MAC: "aa:bb:cc:dd:ee:ff"}
		},
		Services: h.services,
		Packages: h.packages,
		Shell:    h.sessions,
		Logger:   slog.New(slog.NewTextHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Now:      h.clock.Now,
		Sleep:    h.sleepFn,
		Jitter:   func(d time.Duration) time.Duration { return d },
		Dial: func(ctx context.Context, url string) (*websocket.Conn, error) {
			h.dialCount.Add(1)
			if h.failDials.Add(-1) >= 0 {
				return nil, io.ErrUnexpectedEOF
			}
			return h.hub.dial(ctx, url)
		},
		HTTPClient:      h.httpClient,
		MetricsInterval: 5 * time.Millisecond,
		Exit:            func(code int) { h.exits <- code },
	}
	if opt != nil {
		opt(&opts)
	}
	h.agent = New(opts)
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	go func() { h.done <- h.agent.Run(ctx) }()
	h.t.Cleanup(func() {
		cancel()
		select {
		case <-h.done:
		case <-time.After(stopTimeout):
			h.t.Error("agent did not stop")
		}
	})
}

// stop cancels the agent and waits for Run to return.
func (h *harness) stop() error {
	h.t.Helper()
	h.cancel()
	select {
	case err := <-h.done:
		h.done <- err // keep for cleanup
		return err
	case <-time.After(stopTimeout):
		h.t.Fatal("agent did not stop")
		return nil
	}
}
