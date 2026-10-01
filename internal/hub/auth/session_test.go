package auth

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/phabioo/nexara/internal/hub/store"
)

func TestSessionCreateValidate(t *testing.T) {
	e := newEnv(t)
	u := e.addUser("alice", testPass)
	m := e.svc.Sessions()

	raw, sess, err := m.Create(e.ctx, u, false, testIP, testUA)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 43 || strings.ContainsAny(raw, "+/=") {
		t.Fatalf("raw ID %q is not 32 bytes of unpadded base64url", raw)
	}
	raw2, _, _ := m.Create(e.ctx, u, false, testIP, testUA)
	if raw == raw2 {
		t.Fatal("session IDs must be unique")
	}

	// Only the hash is stored.
	stored, err := e.store.GetSession(e.ctx, HashSessionID(raw))
	if err != nil {
		t.Fatal(err)
	}
	if stored.IDHash == raw || len(stored.IDHash) != 64 {
		t.Fatalf("stored id %q", stored.IDHash)
	}
	if _, err := e.store.GetSession(e.ctx, raw); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("the raw ID must not be a key in the store")
	}
	if stored.IP != testIP || stored.UserAgent != testUA || stored.UserID != u.ID {
		t.Fatalf("stored session %+v", stored)
	}
	if want := e.clock.Now().Add(AbsoluteLifetime); !stored.ExpiresAt.Equal(want) {
		t.Fatalf("expires %v, want %v", stored.ExpiresAt, want)
	}
	if sess.IDHash != stored.IDHash {
		t.Fatal("returned session differs from stored one")
	}

	user, got, err := m.Validate(e.ctx, raw)
	if err != nil || user.ID != u.ID || got.IDHash != sess.IDHash {
		t.Fatalf("Validate = %+v, %+v, %v", user, got, err)
	}
}

func TestSessionValidateRejects(t *testing.T) {
	e := newEnv(t)
	e.addUser("alice", testPass)
	m := e.svc.Sessions()
	for name, raw := range map[string]string{
		"empty":   "",
		"unknown": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"huge":    strings.Repeat("x", 10000),
		"hash":    HashSessionID("x"),
	} {
		if _, _, err := m.Validate(e.ctx, raw); !errors.Is(err, ErrSessionExpired) {
			t.Errorf("%s: err = %v, want ErrSessionExpired", name, err)
		}
	}
}

func TestSessionExpiry(t *testing.T) {
	const idle = 12 * time.Hour
	tests := []struct {
		name    string
		persist bool
		// steps: advance the clock, then Validate; wantErr says whether that Validate must fail
		steps []struct {
			advance time.Duration
			wantErr bool
		}
	}{
		{
			name: "idle timeout from creation",
			steps: []struct {
				advance time.Duration
				wantErr bool
			}{{idle - time.Second, false}, {0, false}, {idle, true}},
		},
		{
			name: "exactly at the idle limit is expired",
			steps: []struct {
				advance time.Duration
				wantErr bool
			}{{idle, true}},
		},
		{
			name: "activity keeps the session alive",
			steps: []struct {
				advance time.Duration
				wantErr bool
			}{{11 * time.Hour, false}, {11 * time.Hour, false}, {11 * time.Hour, false}, {idle, true}},
		},
		{
			name:    "persistent sessions have the same idle timeout",
			persist: true,
			steps: []struct {
				advance time.Duration
				wantErr bool
			}{{idle + time.Minute, true}},
		},
		{
			name: "expired session stays expired",
			steps: []struct {
				advance time.Duration
				wantErr bool
			}{{idle, true}, {-idle, true}},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			u := e.addUser("alice", testPass)
			m := e.svc.Sessions()
			raw, _, err := m.Create(e.ctx, u, tc.persist, testIP, testUA)
			if err != nil {
				t.Fatal(err)
			}
			for i, st := range tc.steps {
				e.clock.Advance(st.advance)
				_, _, err := m.Validate(e.ctx, raw)
				if st.wantErr != errors.Is(err, ErrSessionExpired) || (!st.wantErr && err != nil) {
					t.Fatalf("step %d: err = %v, wantErr %v", i, err, st.wantErr)
				}
			}
		})
	}
}

func TestSessionAbsoluteLimit(t *testing.T) {
	e := newEnv(t)
	u := e.addUser("alice", testPass)
	m := e.svc.Sessions()
	raw, _, _ := m.Create(e.ctx, u, true, testIP, testUA)

	// Stay active every 11 hours; the session must still die after 30 days.
	var elapsed time.Duration
	for elapsed+11*time.Hour < AbsoluteLifetime {
		e.clock.Advance(11 * time.Hour)
		elapsed += 11 * time.Hour
		if _, _, err := m.Validate(e.ctx, raw); err != nil {
			t.Fatalf("after %v: %v", elapsed, err)
		}
	}
	e.clock.Advance(AbsoluteLifetime - elapsed) // exactly 30 days after creation
	if _, _, err := m.Validate(e.ctx, raw); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("at 30 days: err = %v, want ErrSessionExpired", err)
	}
	if _, err := e.store.GetSession(e.ctx, HashSessionID(raw)); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("expired session should have been removed")
	}
}

func TestSessionTouchThrottle(t *testing.T) {
	e := newEnv(t)
	u := e.addUser("alice", testPass)
	m := e.svc.Sessions()
	raw, sess, _ := m.Create(e.ctx, u, false, testIP, testUA)
	hash := sess.IDHash
	created := sess.LastSeenAt

	lastSeen := func() time.Time {
		s, err := e.store.GetSession(e.ctx, hash)
		if err != nil {
			t.Fatal(err)
		}
		return s.LastSeenAt
	}

	tests := []struct {
		name    string
		advance time.Duration
		touched bool
	}{
		{"10 s later: not written", 10 * time.Second, false},
		{"59 s after creation: not written", 49 * time.Second, false},
		{"61 s after creation: written", 2 * time.Second, true},
		{"30 s after that: not written", 30 * time.Second, false},
		{"another 31 s: written", 31 * time.Second, true},
	}
	prev := created
	for _, tc := range tests {
		e.clock.Advance(tc.advance)
		_, got, err := m.Validate(e.ctx, raw)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		stored := lastSeen()
		if tc.touched {
			if !stored.Equal(e.clock.Now()) || !got.LastSeenAt.Equal(e.clock.Now()) {
				t.Errorf("%s: stored %v returned %v, want %v", tc.name, stored, got.LastSeenAt, e.clock.Now())
			}
			prev = stored
		} else if !stored.Equal(prev) {
			t.Errorf("%s: last_seen moved to %v", tc.name, stored)
		}
	}
}

func TestSessionDeleteAndCleanup(t *testing.T) {
	e := newEnv(t)
	alice := e.addUser("alice", testPass)
	bob := e.addUser("bob", testPass)
	m := e.svc.Sessions()

	a1, _, _ := m.Create(e.ctx, alice, false, testIP, testUA)
	a2, _, _ := m.Create(e.ctx, alice, false, testIP, testUA)
	b1, _, _ := m.Create(e.ctx, bob, false, testIP, testUA)

	if err := m.Delete(e.ctx, a1); err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.Validate(e.ctx, a1); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("deleted session still valid: %v", err)
	}
	if err := m.Delete(e.ctx, "no-such-session"); err != nil {
		t.Fatalf("deleting an unknown session must not fail: %v", err)
	}

	n, err := m.DeleteAllForUser(e.ctx, alice.ID)
	if err != nil || n != 1 {
		t.Fatalf("DeleteAllForUser = %d, %v; want 1", n, err)
	}
	if _, _, err := m.Validate(e.ctx, a2); !errors.Is(err, ErrSessionExpired) {
		t.Fatal("alice's other session survived")
	}
	if _, _, err := m.Validate(e.ctx, b1); err != nil {
		t.Fatalf("bob's session must be unaffected: %v", err)
	}

	// Cleanup removes idle and absolutely expired sessions, keeps live ones.
	c1, _, _ := m.Create(e.ctx, alice, false, testIP, testUA)
	e.clock.Advance(13 * time.Hour)
	c2, _, _ := m.Create(e.ctx, alice, false, testIP, testUA)
	removed, err := m.Cleanup(e.ctx)
	if err != nil || removed != 2 { // b1 and c1 are idle
		t.Fatalf("Cleanup = %d, %v; want 2", removed, err)
	}
	if _, _, err := m.Validate(e.ctx, c2); err != nil {
		t.Fatalf("fresh session removed by cleanup: %v", err)
	}
	_ = c1
}

func TestCookieAttributes(t *testing.T) {
	e := newEnv(t)
	u := e.addUser("alice", testPass)
	m := e.svc.Sessions()

	rawP, sessP, _ := m.Create(e.ctx, u, true, testIP, testUA)
	rawN, sessN, _ := m.Create(e.ctx, u, false, testIP, testUA)

	check := func(t *testing.T, c *http.Cookie, secure bool) {
		t.Helper()
		wantName := "nexus_session"
		if secure {
			wantName = "__Host-nexus_session"
		}
		if c.Name != wantName || c.Path != "/" || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Secure != secure {
			t.Fatalf("cookie %+v", c)
		}
		if c.Domain != "" {
			t.Fatalf("Domain must be unset (host-only cookie), got %q", c.Domain)
		}
	}

	t.Run("persistent has max-age of the remaining absolute lifetime", func(t *testing.T) {
		c := e.svc.Cookies().Session(rawP, sessP)
		check(t, c, true)
		if c.Value != rawP || c.MaxAge != int(AbsoluteLifetime/time.Second) {
			t.Fatalf("MaxAge %d, value %q", c.MaxAge, c.Value)
		}
		e.clock.Advance(48 * time.Hour)
		c = e.svc.Cookies().Session(rawP, sessP)
		if want := int((AbsoluteLifetime - 48*time.Hour) / time.Second); c.MaxAge != want {
			t.Fatalf("MaxAge %d, want %d", c.MaxAge, want)
		}
		if !strings.Contains(c.String(), "Max-Age=") || !strings.Contains(c.String(), "SameSite=Strict") ||
			!strings.Contains(c.String(), "HttpOnly") || !strings.Contains(c.String(), "Secure") {
			t.Fatalf("header %q", c.String())
		}
	})
	t.Run("non-persistent is a browser-session cookie", func(t *testing.T) {
		c := e.svc.Cookies().Session(rawN, sessN)
		check(t, c, true)
		if c.MaxAge != 0 || !c.Expires.IsZero() {
			t.Fatalf("must have neither Max-Age nor Expires: %+v", c)
		}
		if strings.Contains(c.String(), "Max-Age") || strings.Contains(c.String(), "Expires") {
			t.Fatalf("header %q", c.String())
		}
	})
	t.Run("expired persistent never gets a zero or negative max-age", func(t *testing.T) {
		e.clock.Advance(AbsoluteLifetime)
		if c := e.svc.Cookies().Session(rawP, sessP); c.MaxAge < 1 {
			t.Fatalf("MaxAge %d", c.MaxAge)
		}
	})
	t.Run("secure can be disabled explicitly", func(t *testing.T) {
		c := NewCookies(WithSecure(false)).Session(rawN, sessN)
		check(t, c, false)
	})
	t.Run("default builder is secure", func(t *testing.T) {
		check(t, NewCookies().Session(rawN, sessN), true)
	})
	t.Run("clear", func(t *testing.T) {
		c := e.svc.Cookies().ClearSession()
		check(t, c, true)
		if c.MaxAge >= 0 || c.Value != "" {
			t.Fatalf("clear cookie %+v", c)
		}
	})
	t.Run("csrf cookie", func(t *testing.T) {
		c := e.svc.Cookies().CSRF("tok")
		if c.Name != "__Host-nexus_csrf" || !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteStrictMode || c.MaxAge != 0 || c.Path != "/" {
			t.Fatalf("csrf cookie %+v", c)
		}
		if cc := NewCookies(WithSecure(false)).CSRF("tok"); cc.Secure || cc.Name != "nexus_csrf" {
			t.Fatalf("WithSecure(false) must apply to the CSRF cookie too and drop the prefix: %+v", cc)
		}
		if c := e.svc.Cookies().ClearCSRF(); c.MaxAge >= 0 {
			t.Fatal("ClearCSRF must delete")
		}
	})
}
