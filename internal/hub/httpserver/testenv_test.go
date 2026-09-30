package httpserver

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/phabioo/nexara/internal/hub/auth"
	"github.com/phabioo/nexara/internal/hub/grid"
	"github.com/phabioo/nexara/internal/hub/setup"
	"github.com/phabioo/nexara/internal/hub/store"
	"github.com/phabioo/nexara/internal/protocol"
)

var testParams = auth.HashParams{Memory: 64, Time: 1, Threads: 1, KeyLen: 32, SaltLen: 16}

const (
	testOperator = "frank"
	testPass     = "correct horse battery staple"
	testPeerAddr = "192.0.2.10:40000"
)

// --- fakes ---------------------------------------------------------------------

type fakeUsers struct{ n atomic.Int32 }

func (f *fakeUsers) CountUsers(context.Context) (int, error) { return int(f.n.Load()), nil }

type fakeHub struct {
	mu    sync.Mutex
	hosts []grid.HostInfo
	snaps map[grid.HostID]grid.Snapshot
	jobs  map[grid.HostID][]grid.Job
	subs  map[chan grid.Event]struct{}

	shell    *fakeShell
	openErr  error
	openArgs chan openArgs
}

type openArgs struct {
	actor      grid.Actor
	host       grid.HostID
	cols, rows int
}

func newFakeHub() *fakeHub {
	return &fakeHub{
		snaps:    map[grid.HostID]grid.Snapshot{},
		jobs:     map[grid.HostID][]grid.Job{},
		subs:     map[chan grid.Event]struct{}{},
		openArgs: make(chan openArgs, 8),
	}
}

func (h *fakeHub) Hosts() []grid.HostInfo {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]grid.HostInfo(nil), h.hosts...)
}

func (h *fakeHub) Host(id grid.HostID) (grid.HostInfo, bool) {
	for _, x := range h.Hosts() {
		if x.ID == id {
			return x, true
		}
	}
	return grid.HostInfo{}, false
}

func (h *fakeHub) Snapshot(id grid.HostID) (grid.Snapshot, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	s, ok := h.snaps[id]
	return s, ok
}

func (h *fakeHub) Subscribe(ctx context.Context) <-chan grid.Event {
	ch := make(chan grid.Event, 16)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	go func() {
		<-ctx.Done()
		h.mu.Lock()
		delete(h.subs, ch)
		h.mu.Unlock()
		close(ch)
	}()
	return ch
}

func (h *fakeHub) setOpenErr(err error) {
	h.mu.Lock()
	h.openErr = err
	h.mu.Unlock()
}

func (h *fakeHub) subscribers() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.subs)
}

func (h *fakeHub) emit(ev grid.Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs {
		ch <- ev
	}
}

func (h *fakeHub) Jobs(id grid.HostID) []grid.Job {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.jobs[id]
}

func (h *fakeHub) OpenShell(_ context.Context, actor grid.Actor, id grid.HostID, cols, rows int) (grid.ShellSession, error) {
	h.openArgs <- openArgs{actor, id, cols, rows}
	h.mu.Lock()
	err := h.openErr
	h.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return h.shell, nil
}

var errFake = errors.New("fake: not implemented")

func (h *fakeHub) RefreshServices(context.Context, grid.HostID) error { return errFake }
func (h *fakeHub) RefreshPackages(context.Context, grid.HostID) error { return errFake }
func (h *fakeHub) SearchPackages(context.Context, grid.HostID, string) ([]protocol.Package, error) {
	return nil, errFake
}
func (h *fakeHub) RestartService(context.Context, grid.Actor, grid.HostID, string) error {
	return errFake
}
func (h *fakeHub) StartJob(context.Context, grid.Actor, grid.HostID, grid.JobSpec) (grid.Job, error) {
	return grid.Job{}, errFake
}
func (h *fakeHub) CancelJob(context.Context, grid.Actor, string) error        { return errFake }
func (h *fakeHub) UpdateAgent(context.Context, grid.Actor, grid.HostID) error { return errFake }

type fakeShell struct {
	out     chan []byte
	writes  chan []byte
	resizes chan [2]int
	closed  chan struct{}
	done    chan struct{}
	once    sync.Once
	cOnce   sync.Once
}

func newFakeShell() *fakeShell {
	return &fakeShell{
		out: make(chan []byte, 8), writes: make(chan []byte, 8), resizes: make(chan [2]int, 8),
		closed: make(chan struct{}), done: make(chan struct{}),
	}
}

func (s *fakeShell) Read(p []byte) (int, error) {
	select {
	case b := <-s.out:
		return copy(p, b), nil
	case <-s.done:
		return 0, io.EOF
	}
}

func (s *fakeShell) Write(p []byte) (int, error) {
	s.writes <- append([]byte(nil), p...)
	return len(p), nil
}

func (s *fakeShell) Resize(cols, rows int) error {
	s.resizes <- [2]int{cols, rows}
	return nil
}

func (s *fakeShell) exit() { s.once.Do(func() { close(s.done) }) }

func (s *fakeShell) Close() error {
	s.cOnce.Do(func() { close(s.closed) })
	s.exit()
	return nil
}

// --- environment ---------------------------------------------------------------

type env struct {
	t     *testing.T
	srv   *Server
	st    *store.Store
	svc   *auth.Service
	hub   *fakeHub
	users *fakeUsers
	mode  *setup.Mode
	logs  *syncBuffer
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func newEnv(t *testing.T) *env {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "nexus.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	key := make([]byte, auth.SecretKeyLen)
	for i := range key {
		key[i] = byte(i + 1)
	}
	svc, err := auth.NewService(auth.Config{
		Store: st, SecretKey: key, IdleTimeout: 12 * time.Hour,
		RateAttempts: 5, RateWindow: 15 * time.Minute, HashParams: testParams,
	})
	if err != nil {
		t.Fatal(err)
	}
	hash, err := auth.HashPassword(testPass, testParams)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateUser(context.Background(), store.User{OperatorID: testOperator, PassHash: hash}); err != nil {
		t.Fatal(err)
	}

	users := &fakeUsers{}
	users.n.Store(1)
	mode := setup.NewMode(users)
	logs := &syncBuffer{}
	hub := newFakeHub()
	hub.hosts = []grid.HostInfo{
		{ID: "a1", Name: "alpha", Address: "192.0.2.21", Online: true},
		{ID: "b2", Name: "beta", DisplayName: "Beta Pi", Address: "192.0.2.22", Online: false},
	}
	srv, err := New(Options{
		Auth: svc,
		Setup: SetupDeps{
			Codes: setup.NewCodes(setup.CodeOptions{}), Sessions: setup.NewSessions(setup.SessionOptions{}), Mode: mode,
		},
		Hub: hub,
		Static: fstest.MapFS{
			"css/a.css":                &fstest.MapFile{Data: []byte("body{}")},
			"img/manifest.webmanifest": &fstest.MapFile{Data: []byte(`{"name":"Nexara Nexus"}`)},
			"img/favicon.svg":          &fstest.MapFile{Data: []byte("<svg/>")},
		},
		AgentHandler:  http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "agent-ok") }),
		EnrollHandler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "enroll-ok") }),
		Logger:        slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		SecureCookies: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &env{t: t, srv: srv, st: st, svc: svc, hub: hub, users: users, mode: mode, logs: logs}
}

func (e *env) setSetupMode(active bool) {
	if active {
		e.users.n.Store(0)
	} else {
		e.users.n.Store(1)
	}
	e.mode.Invalidate()
}

// signIn creates a session directly through the auth service.
func (e *env) signIn() (cookie *http.Cookie, csrf string) {
	e.t.Helper()
	res, err := e.svc.Login(context.Background(), testOperator, testPass, "192.0.2.10", "test", false)
	if err != nil {
		e.t.Fatal(err)
	}
	return &http.Cookie{Name: auth.SessionCookieName, Value: res.SessionID}, e.svc.CSRFToken(res.Session)
}

func (e *env) addTOTP() string {
	e.t.Helper()
	enr, err := auth.NewTOTP(testOperator)
	if err != nil {
		e.t.Fatal(err)
	}
	sealed, err := e.svc.SealTOTPSecret(enr.Secret)
	if err != nil {
		e.t.Fatal(err)
	}
	u, err := e.st.GetUserByOperatorID(context.Background(), testOperator)
	if err != nil {
		e.t.Fatal(err)
	}
	if err := e.st.SetTOTP(context.Background(), u.ID, sealed, true); err != nil {
		e.t.Fatal(err)
	}
	return enr.Secret
}

// jar is a minimal cookie jar for recorder-based tests.
type jar map[string]*http.Cookie

func (j jar) absorb(rec *httptest.ResponseRecorder) {
	for _, c := range rec.Result().Cookies() {
		if c.MaxAge < 0 || c.Value == "" {
			delete(j, c.Name)
			continue
		}
		j[c.Name] = c
	}
}

type reqOpt func(*http.Request)

func withCookies(cs ...*http.Cookie) reqOpt {
	return func(r *http.Request) {
		for _, c := range cs {
			r.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
		}
	}
}

func withJar(j jar) reqOpt {
	return func(r *http.Request) {
		for _, c := range j {
			r.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
		}
	}
}

func withHeader(k, v string) reqOpt { return func(r *http.Request) { r.Header.Set(k, v) } }

func withForm(v url.Values) reqOpt {
	return func(r *http.Request) {
		r.Body = io.NopCloser(strings.NewReader(v.Encode()))
		r.ContentLength = int64(len(v.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
}

func (e *env) do(h http.Handler, method, target string, opts ...reqOpt) *httptest.ResponseRecorder {
	e.t.Helper()
	r := httptest.NewRequest(method, target, nil)
	r.RemoteAddr = testPeerAddr
	for _, o := range opts {
		o(r)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func (e *env) get(target string, opts ...reqOpt) *httptest.ResponseRecorder {
	return e.do(e.srv.Handler(), http.MethodGet, target, opts...)
}

func (e *env) post(target string, opts ...reqOpt) *httptest.ResponseRecorder {
	return e.do(e.srv.Handler(), http.MethodPost, target, opts...)
}

func findCookie(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func assertCookieAttrs(t *testing.T, c *http.Cookie) {
	t.Helper()
	if c == nil {
		t.Fatal("cookie missing")
	}
	if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteStrictMode {
		t.Errorf("cookie %s: HttpOnly=%v Secure=%v SameSite=%v, want all strict", c.Name, c.HttpOnly, c.Secure, c.SameSite)
	}
}

func codeFor(secret string) string {
	c, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		panic(err)
	}
	return c
}

func wrongCodeFor(secret string) string {
	for i := 0; ; i++ {
		c := fmt.Sprintf("%06d", i)
		if _, ok := auth.MatchTOTP(secret, c, time.Now()); !ok {
			return c
		}
	}
}
