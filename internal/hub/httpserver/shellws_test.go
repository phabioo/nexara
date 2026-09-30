package httpserver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/phabioo/nexara/internal/hub/grid"
)

type wsEnv struct {
	*env
	ts     *httptest.Server
	cookie *http.Cookie
	csrf   string
	shell  *fakeShell
}

func newWSEnv(t *testing.T, tweak ...func(*Server)) *wsEnv {
	t.Helper()
	e := newEnv(t)
	e.srv.shellPing = time.Hour
	for _, f := range tweak {
		f(e.srv)
	}
	w := &wsEnv{env: e, shell: newFakeShell()}
	e.hub.shell = w.shell
	w.ts = httptest.NewServer(e.srv.Handler())
	t.Cleanup(w.ts.Close)
	w.cookie, w.csrf = e.signIn()
	return w
}

func (w *wsEnv) origin() string { return w.ts.URL }

func (w *wsEnv) dial(t *testing.T, path string, query url.Values, hdr map[string]string) (*websocket.Conn, *http.Response, error) {
	t.Helper()
	h := http.Header{}
	for k, v := range hdr {
		h.Set(k, v)
	}
	u := "ws" + strings.TrimPrefix(w.ts.URL, "http") + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)
	return websocket.Dial(ctx, u, &websocket.DialOptions{HTTPHeader: h})
}

func (w *wsEnv) goodHeaders() map[string]string {
	return map[string]string{"Cookie": w.cookie.Name + "=" + w.cookie.Value, "Origin": w.origin()}
}

func (w *wsEnv) open(t *testing.T, query url.Values) *websocket.Conn {
	t.Helper()
	if query == nil {
		query = url.Values{}
	}
	query.Set("csrf", w.csrf)
	c, resp, err := w.dial(t, "/hosts/alpha/shell/ws", query, w.goodHeaders())
	if err != nil {
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		t.Fatalf("dial: %v (status %d)", err, status)
	}
	t.Cleanup(func() { _ = c.CloseNow() })
	return c
}

func TestShellWSRejections(t *testing.T) {
	w := newWSEnv(t)
	good := w.goodHeaders()
	withOrigin := func(o string) map[string]string {
		return map[string]string{"Cookie": good["Cookie"], "Origin": o}
	}
	tests := []struct {
		name   string
		path   string
		csrf   string
		hdr    map[string]string
		status int
	}{
		{"wrong csrf", "/hosts/alpha/shell/ws", "wrong", good, 403},
		{"missing csrf", "/hosts/alpha/shell/ws", "", good, 403},
		{"other origin", "/hosts/alpha/shell/ws", w.csrf, withOrigin("http://evil.example"), 403},
		{"same host other scheme", "/hosts/alpha/shell/ws", w.csrf, withOrigin("https://" + strings.TrimPrefix(w.ts.URL, "http://")), 403},
		{"origin with other port", "/hosts/alpha/shell/ws", w.csrf, withOrigin("http://127.0.0.1:1"), 403},
		{"missing origin", "/hosts/alpha/shell/ws", w.csrf, map[string]string{"Cookie": good["Cookie"]}, 403},
		{"no session", "/hosts/alpha/shell/ws", w.csrf, map[string]string{"Origin": w.origin()}, 401},
		{"unknown host", "/hosts/ghost/shell/ws", w.csrf, good, 404},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			q := url.Values{}
			if tc.csrf != "" {
				q.Set("csrf", tc.csrf)
			}
			_, resp, err := w.dial(t, tc.path, q, tc.hdr)
			if err == nil {
				t.Fatal("dial succeeded, want rejection")
			}
			if resp == nil || resp.StatusCode != tc.status {
				t.Fatalf("response %v, want status %d", resp, tc.status)
			}
		})
	}
	select {
	case a := <-w.hub.openArgs:
		t.Errorf("a shell was opened by a rejected request: %+v", a)
	default:
	}
}

func TestShellWSOtherSessionsTokenRejected(t *testing.T) {
	w := newWSEnv(t)
	_, otherToken := w.signIn()
	_, resp, err := w.dial(t, "/hosts/alpha/shell/ws", url.Values{"csrf": {otherToken}}, w.goodHeaders())
	if err == nil || resp == nil || resp.StatusCode != 403 {
		t.Fatalf("err=%v resp=%v, want 403", err, resp)
	}
}

func TestShellWSProxiesBothWays(t *testing.T) {
	w := newWSEnv(t)
	c := w.open(t, url.Values{"cols": {"100"}, "rows": {"30"}})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	args := <-w.hub.openArgs
	if args.host != "a1" || args.cols != 100 || args.rows != 30 || args.actor.Operator != testOperator || args.actor.IP == "" {
		t.Errorf("OpenShell args = %+v", args)
	}

	// shell -> browser
	w.shell.out <- []byte("hello\r\n")
	typ, data, err := c.Read(ctx)
	if err != nil || typ != websocket.MessageBinary || string(data) != "hello\r\n" {
		t.Fatalf("read: %v %v %q", err, typ, data)
	}

	// browser -> shell
	if err := c.Write(ctx, websocket.MessageBinary, []byte("ls\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-w.shell.writes:
		if string(got) != "ls\n" {
			t.Errorf("shell received %q", got)
		}
	case <-ctx.Done():
		t.Fatal("shell did not receive input")
	}

	// resize
	for _, tc := range []struct {
		msg  string
		want [2]int
	}{
		{`{"type":"resize","cols":120,"rows":40}`, [2]int{120, 40}},
		{`{"type":"resize","cols":9999,"rows":1}`, [2]int{500, 5}},
		{`{"type":"resize","cols":0,"rows":0}`, [2]int{10, 5}},
	} {
		if err := c.Write(ctx, websocket.MessageText, []byte(tc.msg)); err != nil {
			t.Fatal(err)
		}
		select {
		case got := <-w.shell.resizes:
			if got != tc.want {
				t.Errorf("resize %s -> %v, want %v", tc.msg, got, tc.want)
			}
		case <-ctx.Done():
			t.Fatal("resize not forwarded")
		}
	}

	// unknown control types are ignored, the session continues
	_ = c.Write(ctx, websocket.MessageText, []byte(`{"type":"noop"}`))
	_ = c.Write(ctx, websocket.MessageBinary, []byte("x"))
	if got := <-w.shell.writes; string(got) != "x" {
		t.Errorf("after ignored control message shell got %q", got)
	}
}

func TestShellWSSizeBounds(t *testing.T) {
	tests := []struct {
		query      url.Values
		cols, rows int
	}{
		{nil, 80, 24},
		{url.Values{"cols": {"5"}, "rows": {"999"}}, 10, 200},
		{url.Values{"cols": {"9999"}, "rows": {"1"}}, 500, 5},
		{url.Values{"cols": {"abc"}, "rows": {"-3"}}, 80, 5},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			w := newWSEnv(t)
			w.open(t, tc.query)
			a := <-w.hub.openArgs
			if a.cols != tc.cols || a.rows != tc.rows {
				t.Errorf("got %dx%d, want %dx%d", a.cols, a.rows, tc.cols, tc.rows)
			}
		})
	}
}

func TestShellWSShellExitClosesSocket(t *testing.T) {
	w := newWSEnv(t)
	c := w.open(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	w.shell.exit()
	_, _, err := c.Read(ctx)
	if websocket.CloseStatus(err) != websocket.StatusNormalClosure {
		t.Fatalf("close status %v (err %v), want normal closure", websocket.CloseStatus(err), err)
	}
	waitClosed(t, w.shell)
}

func TestShellWSClientCloseClosesShell(t *testing.T) {
	w := newWSEnv(t)
	c := w.open(t, nil)
	_ = c.Close(websocket.StatusNormalClosure, "bye")
	waitClosed(t, w.shell)
}

func TestShellWSClientDropClosesShell(t *testing.T) {
	w := newWSEnv(t)
	c := w.open(t, nil)
	_ = c.CloseNow()
	waitClosed(t, w.shell)
}

func TestShellWSInvalidControlMessage(t *testing.T) {
	w := newWSEnv(t)
	c := w.open(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = c.Write(ctx, websocket.MessageText, []byte("not json"))
	_, _, err := c.Read(ctx)
	if websocket.CloseStatus(err) != websocket.StatusInvalidFramePayloadData {
		t.Fatalf("close status %v, want 1007", websocket.CloseStatus(err))
	}
	waitClosed(t, w.shell)
}

func TestShellWSOpenFailures(t *testing.T) {
	tests := []struct {
		err  error
		want websocket.StatusCode
	}{
		{grid.ErrHostOffline, websocket.StatusTryAgainLater},
		{grid.ErrCapabilityDisabled, websocket.StatusPolicyViolation},
		{errors.New("secret internal detail"), websocket.StatusInternalError},
	}
	for _, tc := range tests {
		t.Run(tc.err.Error(), func(t *testing.T) {
			w := newWSEnv(t)
			w.hub.setOpenErr(tc.err)
			c := w.open(t, nil)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_, _, err := c.Read(ctx)
			if got := websocket.CloseStatus(err); got != tc.want {
				t.Fatalf("close status %v (err %v), want %v", got, err, tc.want)
			}
			if strings.Contains(fmt.Sprint(err), "secret internal detail") {
				t.Error("internal error leaked to the client")
			}
		})
	}
}

func TestShellWSServerShutdownClosesStream(t *testing.T) {
	w := newWSEnv(t)
	c := w.open(t, nil)
	w.srv.stopStreams.Do(func() { close(w.srv.streamsDone) })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, _, err := c.Read(ctx); err == nil {
		t.Fatal("read succeeded after shutdown")
	}
	waitClosed(t, w.shell)
}

func TestShellWSPing(t *testing.T) {
	w := newWSEnv(t, func(s *Server) { s.shellPing = 10 * time.Millisecond })
	c := w.open(t, nil)
	// The client answers pings while it reads; a failing ping loop would tear
	// the session down. Give it a few rounds.
	errc := make(chan error, 1)
	go func() {
		_, _, err := c.Read(context.Background())
		errc <- err
	}()
	time.Sleep(200 * time.Millisecond)
	select {
	case err := <-errc:
		t.Fatalf("session ended during ping rounds: %v", err)
	case <-w.shell.closed:
		t.Fatal("shell closed during ping rounds")
	default:
	}
}

func TestOriginMatches(t *testing.T) {
	tests := []struct {
		name, origin, host string
		tls                bool
		want               bool
	}{
		{"match http", "http://hub.local:8443", "hub.local:8443", false, true},
		{"match https", "https://hub.local:8443", "hub.local:8443", true, true},
		{"case insensitive host", "https://HUB.local:8443", "hub.local:8443", true, true},
		{"missing", "", "hub.local:8443", true, false},
		{"other host", "https://evil.example", "hub.local:8443", true, false},
		{"subdomain", "https://x.hub.local:8443", "hub.local:8443", true, false},
		{"other port", "https://hub.local:9", "hub.local:8443", true, false},
		{"scheme downgrade", "http://hub.local:8443", "hub.local:8443", true, false},
		{"null origin", "null", "hub.local:8443", true, false},
		{"garbage", "://", "hub.local:8443", true, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.Host = tc.host
			if tc.origin != "" {
				r.Header.Set("Origin", tc.origin)
			}
			if tc.tls {
				r.TLS = &tlsState
			}
			if got := originMatches(r); got != tc.want {
				t.Errorf("originMatches = %v, want %v", got, tc.want)
			}
		})
	}
}

func waitClosed(t *testing.T, s *fakeShell) {
	t.Helper()
	select {
	case <-s.closed:
	case <-time.After(3 * time.Second):
		t.Fatal("shell session was not closed")
	}
}
