package setup

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAttemptLimiter(t *testing.T) {
	clock := newClock()
	l := NewAttemptLimiter(clock.Now, 3, 10*time.Minute)

	for i := 0; i < 3; i++ {
		if ok, _ := l.Allow("a"); !ok {
			t.Fatalf("attempt %d refused", i+1)
		}
		clock.Advance(time.Minute)
	}
	ok, retry := l.Allow("a")
	if ok || retry != 7*time.Minute {
		t.Fatalf("4th attempt: ok=%v retry=%v, want refused with 7m", ok, retry)
	}
	// Refused attempts are not recorded: the block still lifts when the first hit leaves the window.
	clock.Advance(7 * time.Minute)
	if ok, _ := l.Allow("a"); !ok {
		t.Fatal("must be allowed again once the oldest attempt left the window")
	}
	if ok, _ := l.Allow("b"); !ok {
		t.Fatal("keys are independent")
	}
}

func TestAttemptLimiterBoundsMemory(t *testing.T) {
	clock := newClock()
	l := NewAttemptLimiter(clock.Now, 1, time.Hour)
	for i := 0; i < maxLimiterKeys+50; i++ {
		l.Allow(string(rune('a'+i%26)) + time.Duration(i).String())
	}
	if n := len(l.hits); n > maxLimiterKeys {
		t.Fatalf("%d keys tracked, limit %d", n, maxLimiterKeys)
	}
}

func TestRestoreLimits(t *testing.T) {
	clock := newClock()
	r := NewRestoreLimits(clock.Now)

	t.Run("per address", func(t *testing.T) {
		for i := 0; i < RestorePerIPAttempts; i++ {
			if ok, _ := r.Allow("192.0.2.1"); !ok {
				t.Fatalf("attempt %d refused", i+1)
			}
		}
		if ok, retry := r.Allow("192.0.2.1"); ok || retry <= 0 || retry > RestoreWindow {
			t.Fatalf("ok=%v retry=%v", ok, retry)
		}
		if ok, _ := r.Allow("192.0.2.2"); !ok {
			t.Fatal("another address must not be affected")
		}
	})

	t.Run("global, and the address is not charged for it", func(t *testing.T) {
		r := NewRestoreLimits(clock.Now)
		for i := 0; i < RestoreGlobalAttempts; i++ {
			ip := "198.51.100." + string(rune('0'+i/5)) // three addresses stay below the per-address limit
			if ok, _ := r.Allow(ip); !ok {
				t.Fatalf("attempt %d refused", i+1)
			}
		}
		if ok, _ := r.Allow("203.0.113.9"); ok {
			t.Fatal("the global limit must refuse a new address")
		}
		clock.Advance(RestoreWindow + time.Second)
		if ok, _ := r.Allow("203.0.113.9"); !ok {
			t.Fatal("the window must lift the global limit")
		}
		// A refused attempt must not count against the address: after the global
		// window it has its full budget.
		r2 := NewRestoreLimits(clock.Now)
		for i := 0; i < RestoreGlobalAttempts; i++ {
			r2.Allow("10.0.0." + string(rune('a'+i)))
		}
		for i := 0; i < 10; i++ {
			r2.Allow("192.0.2.77")
		}
		clock.Advance(RestoreWindow + time.Second)
		for i := 0; i < RestorePerIPAttempts; i++ {
			if ok, _ := r2.Allow("192.0.2.77"); !ok {
				t.Fatalf("attempt %d of the refused address was charged", i+1)
			}
		}
	})

	t.Run("single flight", func(t *testing.T) {
		r := NewRestoreLimits(clock.Now)
		rel, ok := r.Begin()
		if !ok {
			t.Fatal("first Begin must succeed")
		}
		if _, ok := r.Begin(); ok {
			t.Fatal("second Begin must be refused while the first runs")
		}
		rel()
		rel() // idempotent
		if rel2, ok := r.Begin(); !ok {
			t.Fatal("Begin must work after release")
		} else {
			rel2()
		}
	})
}

func writeUpload(t *testing.T, dir, name string) Upload {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	return Upload{Path: p, Name: "b.nxbk", Size: 1, Passphrase: "secret passphrase"}
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

func TestUploadLifecycle(t *testing.T) {
	dir := t.TempDir()
	clock := newClock()
	newSess := func() (*Sessions, *Session, string) {
		ss := NewSessions(SessionOptions{Now: clock.Now, Idle: time.Hour, UploadDir: dir})
		tok, sess, err := ss.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		return ss, sess, tok
	}

	if got := NewSessions(SessionOptions{}).UploadDir(); got != os.TempDir() {
		t.Errorf("default upload dir = %q", got)
	}

	tests := []struct {
		name string
		end  func(ss *Sessions, tok string)
	}{
		{"Clear", func(ss *Sessions, _ string) { ss.Clear() }},
		{"new Unlock replaces the session", func(ss *Sessions, _ string) {
			if _, _, err := ss.Unlock(); err != nil {
				t.Fatal(err)
			}
		}},
		{"idle expiry", func(ss *Sessions, tok string) {
			clock.Advance(2 * time.Hour)
			if _, ok := ss.Lookup(tok); ok {
				t.Fatal("session must have expired")
			}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ss, sess, tok := newSess()
			up := writeUpload(t, dir, "u1")
			sess.SetUpload(up)
			if got, ok := sess.Upload(); !ok || got.Passphrase != up.Passphrase {
				t.Fatalf("Upload() = %+v, %v", got, ok)
			}
			tc.end(ss, tok)
			if exists(up.Path) {
				t.Fatal("the uploaded file must be deleted when the session ends")
			}
		})
	}

	t.Run("replacing and dropping delete the file", func(t *testing.T) {
		_, sess, _ := newSess()
		first, second := writeUpload(t, dir, "u2"), writeUpload(t, dir, "u3")
		sess.SetUpload(first)
		sess.SetUpload(second)
		if exists(first.Path) || !exists(second.Path) {
			t.Fatalf("first exists=%v second exists=%v", exists(first.Path), exists(second.Path))
		}
		sess.DropUpload()
		if exists(second.Path) {
			t.Fatal("DropUpload must delete the file")
		}
		if _, ok := sess.Upload(); ok {
			t.Fatal("no upload expected")
		}
	})

	t.Run("TakeUpload hands the file over exactly once", func(t *testing.T) {
		_, sess, _ := newSess()
		up := writeUpload(t, dir, "u4")
		sess.SetUpload(up)
		got, ok := sess.TakeUpload()
		if !ok || got.Path != up.Path {
			t.Fatalf("TakeUpload = %+v, %v", got, ok)
		}
		if _, ok := sess.TakeUpload(); ok {
			t.Fatal("a second TakeUpload must find nothing")
		}
		if !exists(up.Path) {
			t.Fatal("the taker owns the file; the session must not delete it")
		}
	})
}
