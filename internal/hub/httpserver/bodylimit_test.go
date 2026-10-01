package httpserver

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// deadlineRecorder records the read deadlines the middleware sets
// (http.ResponseController finds SetReadDeadline on the writer).
type deadlineRecorder struct {
	*httptest.ResponseRecorder
	deadlines []time.Time
}

func (d *deadlineRecorder) SetReadDeadline(t time.Time) error {
	d.deadlines = append(d.deadlines, t)
	return nil
}

func TestBodyLimitsDeadline(t *testing.T) {
	e := newEnv(t)
	e.srv.bodyTimeout = 30 * time.Second
	var readErr error
	h := e.srv.bodyLimits(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		_, readErr = io.Copy(io.Discard, r.Body)
	}))

	tests := []struct {
		name, method, path string
		body               string
		wantDeadline       bool
	}{
		{"form post", "POST", "/login", "a=b", true},
		{"htmx post", "POST", "/hosts/alpha/packages/search", "q=x", true},
		{"enrollment post", "POST", "/grid/enroll", "{}", true},
		{"setup post", "POST", "/setup/unlock", "code=x", true},
		{"post without a body", "POST", "/logout", "", false},
		{"get", "GET", "/", "", false},
		{"event stream", "GET", "/events", "", false},
		{"shell websocket", "GET", "/hosts/alpha/shell/ws", "", false},
		{"agent websocket", "GET", "/grid/connect", "", false},
		{"agent helper", "POST", "/grid/agent/x", "payload", false},
		{"event ping", "GET", "/events/ping", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var body io.Reader
			if tc.body != "" {
				body = strings.NewReader(tc.body)
			}
			r := httptest.NewRequest(tc.method, tc.path, body)
			rec := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
			start := time.Now()
			readErr = nil
			h.ServeHTTP(rec, r)
			if readErr != nil {
				t.Fatalf("body read: %v", readErr)
			}
			if !tc.wantDeadline {
				if len(rec.deadlines) != 0 {
					t.Fatalf("deadlines %v set on a path that must be exempt", rec.deadlines)
				}
				return
			}
			if len(rec.deadlines) != 2 {
				t.Fatalf("deadlines = %v, want one deadline and its removal", rec.deadlines)
			}
			if d := rec.deadlines[0]; d.Before(start.Add(29*time.Second)) || d.After(time.Now().Add(31*time.Second)) {
				t.Errorf("deadline %v is not ~30 s ahead", d)
			}
			if !rec.deadlines[1].IsZero() {
				t.Errorf("deadline not lifted after the body was read: %v", rec.deadlines[1])
			}
		})
	}
}

// S-02 (body size): the cap holds on every non-stream path, also where the
// CSRF middleware does not look at the body.
func TestBodyLimitsSizeCap(t *testing.T) {
	e := newEnv(t)
	tests := []struct {
		name, path string
		size       int
		wantErr    bool
	}{
		{"exactly the cap", "/login", maxFormBody, false},
		{"one byte over", "/login", maxFormBody + 1, true},
		{"large enrollment body", "/grid/enroll", 4 << 20, true},
		{"agent endpoints are not capped", "/grid/agent/x", 4 << 20, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var got error
			h := e.srv.bodyLimits(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				_, got = io.Copy(io.Discard, r.Body)
			}))
			r := httptest.NewRequest("POST", tc.path, bytes.NewReader(make([]byte, tc.size)))
			h.ServeHTTP(httptest.NewRecorder(), r) // no SetReadDeadline: the cap still applies
			var mbe *http.MaxBytesError
			if errors.As(got, &mbe) != tc.wantErr {
				t.Fatalf("read error = %v, want error: %v", got, tc.wantErr)
			}
		})
	}
}

// S-02: a client that announces a body and then stalls must be dropped.
// Over a real connection, because the deadline lives on the net.Conn.
func TestSlowBodyIsDropped(t *testing.T) {
	// Only /login reads its body without a session; the others never look at it (and answer at once).
	paths := []string{"/login"}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			e := newEnv(t)
			e.srv.bodyTimeout = 150 * time.Millisecond
			ts := httptest.NewServer(e.srv.Handler())
			t.Cleanup(ts.Close)

			conn, err := net.Dial("tcp", ts.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			// Announce 1000 bytes, send three, then say nothing.
			_, err = io.WriteString(conn, "POST "+path+" HTTP/1.1\r\nHost: hub\r\nContent-Type: application/x-www-form-urlencoded\r\n"+
				"Content-Length: 1000\r\n\r\nabc")
			if err != nil {
				t.Fatal(err)
			}
			// The server must answer or hang up on its own; this deadline is only the failure bound.
			_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err != nil {
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() {
					t.Fatal("connection with a stalled body is still held open")
				}
				return // closed without an answer: dropped, which is fine
			}
			resp.Body.Close()
			if resp.StatusCode < 400 {
				t.Fatalf("status %d for a request whose body never arrived", resp.StatusCode)
			}
		})
	}
}

// A body that arrives in time is unaffected, and the deadline does not
// outlive it (a slow handler after the body is not cut off).
func TestBodyDeadlineDoesNotAffectNormalPosts(t *testing.T) {
	e := newEnv(t)
	e.srv.bodyTimeout = 150 * time.Millisecond
	done := make(chan struct{})
	slow := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		<-done // keep the request open well past the body timeout (released below)
		_, _ = w.Write(b)
	})
	ts := httptest.NewServer(e.srv.bodyLimits(slow))
	t.Cleanup(ts.Close)

	type result struct {
		body string
		err  error
	}
	res := make(chan result, 1)
	go func() {
		resp, err := http.Post(ts.URL+"/login", "text/plain", strings.NewReader("hello"))
		if err != nil {
			res <- result{err: err}
			return
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		res <- result{string(b), err}
	}()
	time.Sleep(400 * time.Millisecond) // more than twice the body timeout; the handler is still waiting
	close(done)
	r := <-res
	if r.err != nil || r.body != "hello" {
		t.Fatalf("response %q, err %v", r.body, r.err)
	}
}
