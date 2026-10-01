package auth

import (
	"errors"
	"testing"
	"time"
)

func signalled(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

// S-01: long-lived streams re-check their session without keeping it alive.
func TestCheckHash(t *testing.T) {
	e := newEnv(t)
	u := e.addUser("alice", testPass)
	m := e.svc.Sessions()

	tests := []struct {
		name   string
		mutate func(raw, hash string)
		want   error
	}{
		{"live", func(string, string) {}, nil},
		{"unknown hash", func(_, _ string) {}, ErrSessionExpired}, // checked with another hash below
		{"deleted", func(raw, _ string) { _ = m.Delete(e.ctx, raw) }, ErrSessionExpired},
		{"idle for 12 h", func(string, string) { e.clock.Advance(12 * time.Hour) }, ErrSessionExpired},
		{"older than 30 days", func(string, string) { e.clock.Advance(AbsoluteLifetime) }, ErrSessionExpired},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw, sess, err := m.Create(e.ctx, u, true, testIP, testUA)
			if err != nil {
				t.Fatal(err)
			}
			tc.mutate(raw, sess.IDHash)
			hash := sess.IDHash
			if tc.name == "unknown hash" {
				hash = HashSessionID("nope")
			}
			if err := m.CheckHash(e.ctx, hash); !errors.Is(err, tc.want) {
				t.Fatalf("CheckHash = %v, want %v", err, tc.want)
			}
		})
	}

	t.Run("does not refresh last_seen", func(t *testing.T) {
		_, sess, _ := m.Create(e.ctx, u, false, testIP, testUA)
		// A stream that checks every few minutes must not keep an idle
		// session alive: after 12 h without a request it is over.
		for i := 0; i < 11; i++ {
			e.clock.Advance(time.Hour)
			if err := m.CheckHash(e.ctx, sess.IDHash); err != nil {
				t.Fatalf("hour %d: %v", i+1, err)
			}
		}
		e.clock.Advance(time.Hour)
		if err := m.CheckHash(e.ctx, sess.IDHash); !errors.Is(err, ErrSessionExpired) {
			t.Fatalf("CheckHash after 12 h = %v, want ErrSessionExpired", err)
		}
	})
}

func TestRevokedSignal(t *testing.T) {
	e := newEnv(t)
	u := e.addUser("alice", testPass)
	m := e.svc.Sessions()

	tests := []struct {
		name string
		do   func()
		want bool
	}{
		{"creating a session is not a revocation", func() { _, _, _ = m.Create(e.ctx, u, false, testIP, testUA) }, false},
		{"Delete", func() {
			raw, _, _ := m.Create(e.ctx, u, false, testIP, testUA)
			_ = m.Delete(e.ctx, raw)
		}, true},
		{"DeleteAllForUser", func() { _, _ = m.DeleteAllForUser(e.ctx, u.ID) }, true},
		{"Logout", func() {
			raw, _, _ := m.Create(e.ctx, u, false, testIP, testUA)
			if err := e.svc.Logout(e.ctx, raw, testIP); err != nil {
				t.Fatal(err)
			}
		}, true},
		{"ResetOperators", func() {
			if _, err := e.svc.ResetOperators(e.ctx); err != nil {
				t.Fatal(err)
			}
		}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ch := m.Revoked()
			if signalled(ch) {
				t.Fatal("fresh channel already closed")
			}
			tc.do()
			if got := signalled(ch); got != tc.want {
				t.Fatalf("signalled = %v, want %v", got, tc.want)
			}
			if signalled(m.Revoked()) {
				t.Fatal("the next channel must be open again")
			}
		})
	}
}
