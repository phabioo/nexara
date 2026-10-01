package httpserver

import (
	"bufio"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/phabioo/nexara/internal/hub/grid"
)

func TestFormatSSE(t *testing.T) {
	tests := []struct {
		name, event, data, want string
	}{
		{"single line", "metrics", "<b>1</b>", "event: metrics\ndata: <b>1</b>\n\n"},
		{"multi line", "x", "a\nb\n\nc", "event: x\ndata: a\ndata: b\ndata: \ndata: c\n\n"},
		{"crlf", "x", "a\r\nb\rc", "event: x\ndata: a\ndata: b\ndata: c\n\n"},
		{"trailing newline", "x", "a\n", "event: x\ndata: a\ndata: \n\n"},
		{"event name injection", "a\r\nb: evil", "d", "event: ab: evil\ndata: d\n\n"},
		{"no event name", "", "d", "data: d\n\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := string(formatSSE(tc.event, tc.data)); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// sseClient reads lines of an open event stream.
type sseClient struct {
	lines  chan string
	cancel context.CancelFunc
	resp   *http.Response
}

func openStream(t *testing.T, ts *httptest.Server, path string, opts ...reqOpt) *sseClient {
	t.Helper()
	return openStreamURL(t, ts.URL, path, opts...)
}

func openStreamURL(t *testing.T, base, path string, opts ...reqOpt) *sseClient {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, "GET", base+path, nil)
	for _, o := range opts {
		o(req)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	c := &sseClient{lines: make(chan string, 64), cancel: cancel, resp: resp}
	go func() {
		defer close(c.lines)
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			c.lines <- sc.Text()
		}
	}()
	t.Cleanup(func() { cancel(); _ = resp.Body.Close() })
	return c
}

func (c *sseClient) next(t *testing.T) string {
	t.Helper()
	select {
	case l, ok := <-c.lines:
		if !ok {
			t.Fatal("stream closed")
		}
		return l
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for a line")
		return ""
	}
}

// nextEvent returns the lines of the next non-comment event block.
func (c *sseClient) nextEvent(t *testing.T) []string {
	t.Helper()
	var block []string
	for {
		l := c.next(t)
		if l == "" {
			if len(block) > 0 {
				return block
			}
			continue
		}
		if strings.HasPrefix(l, ":") || strings.HasPrefix(l, "retry:") {
			continue
		}
		block = append(block, l)
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", what)
}

func TestSSEDeliversFilteredEvents(t *testing.T) {
	e := newEnv(t)
	e.srv.sseHeartbeat = time.Hour
	// A fresh registry: the stream must not depend on what the views registered.
	e.srv.sse = newEventRegistry()
	e.srv.sse.Register(grid.EventMetrics, func(r *http.Request, ev grid.Event) (string, string, bool) {
		return "metrics", "<div>\n  cpu " + string(ev.Host) + "\n</div>", true
	})
	e.srv.sse.Register(grid.EventHostOffline, func(_ *http.Request, ev grid.Event) (string, string, bool) {
		return "tabs", "offline " + string(ev.Host), true
	})
	e.srv.sse.Register(grid.EventServices, func(*http.Request, grid.Event) (string, string, bool) {
		return "", "", false // renderer declines
	})
	ts := httptest.NewServer(e.srv.Handler())
	t.Cleanup(ts.Close)
	cookie, _ := e.signIn()

	c := openStream(t, ts, "/events?host=alpha", withCookies(cookie))
	if c.resp.StatusCode != 200 || c.resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("status %d type %q", c.resp.StatusCode, c.resp.Header.Get("Content-Type"))
	}
	if c.resp.Header.Get("Content-Security-Policy") == "" || c.resp.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("headers missing on stream: %v", c.resp.Header)
	}
	waitFor(t, "subscription", func() bool { return e.hub.subscribers() == 1 })

	e.hub.emit(grid.Event{Kind: grid.EventMetrics, Host: "b2"})     // other host: filtered
	e.hub.emit(grid.Event{Kind: grid.EventServices, Host: "a1"})    // renderer declines
	e.hub.emit(grid.Event{Kind: grid.EventPackages, Host: "a1"})    // no renderer
	e.hub.emit(grid.Event{Kind: grid.EventHostOffline, Host: "b2"}) // host-level: passes the filter
	e.hub.emit(grid.Event{Kind: grid.EventMetrics, Host: "a1"})

	ev := c.nextEvent(t)
	if strings.Join(ev, "|") != "event: tabs|data: offline b2" {
		t.Fatalf("first event = %q", ev)
	}
	ev = c.nextEvent(t)
	want := "event: metrics|data: <div>|data:   cpu a1|data: </div>"
	if strings.Join(ev, "|") != want {
		t.Fatalf("second event = %q, want %q", ev, want)
	}
}

func TestSSEHeartbeat(t *testing.T) {
	e := newEnv(t)
	e.srv.sseHeartbeat = 20 * time.Millisecond
	ts := httptest.NewServer(e.srv.Handler())
	t.Cleanup(ts.Close)
	cookie, _ := e.signIn()
	c := openStream(t, ts, "/events", withCookies(cookie))
	for {
		if c.next(t) == ": ping" {
			return
		}
	}
}

func TestSSEDisconnectEndsSubscription(t *testing.T) {
	e := newEnv(t)
	ts := httptest.NewServer(e.srv.Handler())
	t.Cleanup(ts.Close)
	cookie, _ := e.signIn()
	c := openStream(t, ts, "/events?host=alpha", withCookies(cookie))
	waitFor(t, "subscription", func() bool { return e.hub.subscribers() == 1 })
	c.cancel()
	waitFor(t, "unsubscribe", func() bool { return e.hub.subscribers() == 0 })
}

func TestSSERequirements(t *testing.T) {
	e := newEnv(t)
	cookie, _ := e.signIn()
	if rec := e.get("/events"); rec.Code != 401 {
		t.Errorf("without session = %d, want 401", rec.Code)
	}
	if rec := e.get("/events?host=ghost", withCookies(cookie)); rec.Code != 404 {
		t.Errorf("unknown host = %d, want 404", rec.Code)
	}
}
