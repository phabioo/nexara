package httpserver

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/phabioo/nexara/internal/hub/auth"
	"github.com/phabioo/nexara/internal/hub/grid"
)

// ended reports whether the server closed the stream within the test timeout.
func (c *sseClient) ended() bool {
	timeout := time.After(3 * time.Second)
	for {
		select {
		case _, ok := <-c.lines:
			if !ok {
				return true
			}
		case <-timeout:
			return false
		}
	}
}

type signedIn struct {
	cookie *http.Cookie
	csrf   string
}

// sessionEnds are the ways a session can end while a stream is open (S-01).
// Revocations are signalled at once (the tests keep the heartbeat at an hour
// so only the signal can end the stream); the idle timeout is found by the heartbeat.
var sessionEnds = []struct {
	name      string
	immediate bool
	end       func(t *testing.T, e *env, s signedIn)
}{
	{"logout", true, func(t *testing.T, e *env, s signedIn) {
		if rec := e.post("/logout", withCookies(s.cookie), withHeader(auth.CSRFHeader, s.csrf)); rec.Code != http.StatusSeeOther {
			t.Fatalf("logout = %d", rec.Code)
		}
	}},
	{"sign out everywhere", true, func(t *testing.T, e *env, _ signedIn) {
		u, _ := e.st.GetUserByOperatorID(context.Background(), testOperator)
		if n, err := e.svc.Sessions().DeleteAllForUser(context.Background(), u.ID); err != nil || n < 1 {
			t.Fatalf("DeleteAllForUser = %d, %v", n, err)
		}
	}},
	{"operator reset", true, func(t *testing.T, e *env, _ signedIn) {
		if _, err := e.svc.ResetOperators(context.Background()); err != nil {
			t.Fatal(err)
		}
	}},
	{"idle timeout", false, func(_ *testing.T, e *env, _ signedIn) { e.clock.Advance(12*time.Hour + time.Minute) }},
}

func TestSSEEndsWhenSessionEnds(t *testing.T) {
	for _, tc := range sessionEnds {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			e.srv.sseHeartbeat = time.Hour
			if !tc.immediate {
				e.srv.sseHeartbeat = 10 * time.Millisecond
			}
			ts := httptest.NewServer(e.srv.Handler())
			t.Cleanup(ts.Close)
			cookie, csrf := e.signIn()
			c := openStream(t, ts, "/events", withCookies(cookie))
			waitFor(t, "subscription", func() bool { return e.hub.subscribers() == 1 })

			tc.end(t, e, signedIn{cookie, csrf})

			if !c.ended() {
				t.Fatal("event stream still open after the session ended")
			}
			waitFor(t, "unsubscribe", func() bool { return e.hub.subscribers() == 0 })
			// The reconnect of the browser is refused, which nexus.js turns into the login page.
			if tc.name != "operator reset" { // after a reset the hub is in setup mode (503)
				if rec := e.get("/events", withCookies(cookie)); rec.Code != http.StatusUnauthorized {
					t.Errorf("reconnect = %d, want 401", rec.Code)
				}
			}
		})
	}
}

// Ending another session must not touch this one.
func TestSSEKeepsRunningWhenAnotherSessionEnds(t *testing.T) {
	e := newEnv(t)
	e.srv.sseHeartbeat = 10 * time.Millisecond
	e.srv.sse = newEventRegistry()
	e.srv.sse.Register(grid.EventMetrics, func(*http.Request, grid.Event) (string, string, bool) { return "m", "x", true })
	ts := httptest.NewServer(e.srv.Handler())
	t.Cleanup(ts.Close)
	cookie, _ := e.signIn()
	other, otherCSRF := e.signIn()
	c := openStream(t, ts, "/events", withCookies(cookie))
	waitFor(t, "subscription", func() bool { return e.hub.subscribers() == 1 })

	if rec := e.post("/logout", withCookies(other), withHeader(auth.CSRFHeader, otherCSRF)); rec.Code != http.StatusSeeOther {
		t.Fatalf("logout = %d", rec.Code)
	}
	// Several heartbeats pass; the stream must still deliver.
	time.Sleep(60 * time.Millisecond)
	e.hub.emit(grid.Event{Kind: grid.EventMetrics, Host: "a1"})
	if ev := c.nextEvent(t); len(ev) != 3 || ev[0] != "event: m" || ev[1] != "id: alpha" {
		t.Fatalf("event = %q", ev)
	}
}

func closeInfo(t *testing.T, c *websocket.Conn) (websocket.StatusCode, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, _, err := c.Read(ctx)
	var ce websocket.CloseError
	if !errors.As(err, &ce) {
		t.Fatalf("read ended with %v, want a close frame", err)
	}
	return ce.Code, ce.Reason
}

func TestShellWSClosesWhenSessionEnds(t *testing.T) {
	for _, tc := range sessionEnds {
		t.Run(tc.name, func(t *testing.T) {
			w := newWSEnv(t, func(s *Server) {
				if !tc.immediate {
					s.shellPing = 10 * time.Millisecond
				}
			})
			c := w.open(t, nil)
			tc.end(t, w.env, signedIn{w.cookie, w.csrf})

			code, reason := closeInfo(t, c)
			if code != websocket.StatusPolicyViolation || reason != "session ended" {
				t.Fatalf("close = %d %q, want 1008 %q", code, reason, "session ended")
			}
			waitClosed(t, w.shell)

			var found bool
			entries, _ := w.st.ListAudit(context.Background(), 100)
			for _, a := range entries {
				if a.Action == auth.ActionShellSessionEnded {
					found = a.User == testOperator && a.Host == "alpha" && a.Result == "ok"
				}
			}
			if !found {
				t.Fatalf("no %s audit entry for the operator on alpha: %+v", auth.ActionShellSessionEnded, entries)
			}
		})
	}
}

// A shell whose session stays valid is not closed by the checks.
func TestShellWSStaysOpenWhileSessionLives(t *testing.T) {
	w := newWSEnv(t, func(s *Server) { s.shellPing = 5 * time.Millisecond })
	c := w.open(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, _, err := c.Read(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("read = %v, want it to block until the test timeout", err)
	}
}
