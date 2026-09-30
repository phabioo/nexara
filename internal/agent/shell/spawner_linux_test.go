//go:build linux

package shell

import (
	"errors"
	"io"
	"os"
	"os/user"
	"strings"
	"sync"
	"testing"
	"time"
)

func currentUser(t *testing.T) string {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("test needs a non-root user")
	}
	u, err := user.Current()
	if err != nil {
		t.Skip("cannot determine current user:", err)
	}
	return u.Username
}

func openTestSession(t *testing.T) *session {
	t.Helper()
	sp, err := newSpawner(currentUser(t), "/bin/sh")
	if err != nil {
		t.Fatal(err)
	}
	sess, err := sp.Open(80, 24)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sess.Close() })
	return sess.(*session)
}

// output collects everything the session prints.
type output struct {
	mu  sync.Mutex
	buf strings.Builder
	eof chan struct{}
}

func collect(s Session) *output {
	o := &output{eof: make(chan struct{})}
	go func() {
		defer close(o.eof)
		b := make([]byte, 4096)
		for {
			n, err := s.Read(b)
			o.mu.Lock()
			o.buf.Write(b[:n])
			o.mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	return o
}

func (o *output) String() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.buf.String()
}

func (o *output) waitFor(t *testing.T, sub string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(o.String(), sub) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %q, got %q", sub, o.String())
}

func (o *output) waitEOF(t *testing.T) {
	t.Helper()
	select {
	case <-o.eof:
	case <-time.After(10 * time.Second):
		t.Fatal("timeout waiting for EOF")
	}
}

func TestEchoRoundtrip(t *testing.T) {
	s := openTestSession(t)
	out := collect(s)
	if _, err := s.Write([]byte("echo rt-$((20+22))\n")); err != nil {
		t.Fatal(err)
	}
	out.waitFor(t, "rt-42")
}

func TestShellExitGivesEOF(t *testing.T) {
	s := openTestSession(t)
	out := collect(s)
	_, _ = s.Write([]byte("exit\n"))
	out.waitEOF(t)
}

func TestResize(t *testing.T) {
	s := openTestSession(t)
	out := collect(s)
	for _, bad := range [][2]int{{0, 24}, {80, 0}, {1001, 24}, {80, 1001}} {
		if err := s.Resize(bad[0], bad[1]); !errors.Is(err, ErrInvalidSize) {
			t.Errorf("Resize(%v) = %v, want ErrInvalidSize", bad, err)
		}
	}
	if err := s.Resize(100, 40); err != nil {
		t.Fatal(err)
	}
	_, _ = s.Write([]byte("stty size\n"))
	out.waitFor(t, "40 100")
}

func TestCloseKillsAndEOF(t *testing.T) {
	s := openTestSession(t)
	out := collect(s)
	_, _ = s.Write([]byte("echo up\n"))
	out.waitFor(t, "up")
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	out.waitEOF(t)
	select {
	case <-s.done:
	default:
		t.Fatal("process not reaped after Close")
	}
	if _, err := s.Write([]byte("x")); err == nil {
		t.Error("Write after Close succeeded")
	}
	if err := s.Resize(80, 24); err == nil {
		t.Error("Resize after Close succeeded")
	}
	if err := s.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

func TestCloseKillsSighupIgnoringShell(t *testing.T) {
	s := openTestSession(t)
	out := collect(s)
	_, _ = s.Write([]byte("trap '' HUP; echo armed\n"))
	out.waitFor(t, "armed")
	start := time.Now()
	_ = s.Close()
	if time.Since(start) > reapTimeout+5*time.Second {
		t.Fatal("Close took too long")
	}
	out.waitEOF(t)
}

func TestConcurrentClose(t *testing.T) {
	s := openTestSession(t)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(3)
		go func() { defer wg.Done(); _ = s.Close() }()
		go func() { defer wg.Done(); _, _ = s.Write([]byte("x")) }()
		go func() { defer wg.Done(); _ = s.Resize(90, 30) }()
	}
	wg.Wait()
	buf := make([]byte, 16)
	for {
		if _, err := s.Read(buf); err != nil {
			if err != io.EOF {
				t.Fatalf("Read err = %v, want EOF", err)
			}
			break
		}
	}
}

func TestEnvironmentIsClean(t *testing.T) {
	t.Setenv("NEXARA_LEAK_MARKER", "secret")
	s := openTestSession(t)
	out := collect(s)
	_, _ = s.Write([]byte("echo LEAK[$NEXARA_LEAK_MARKER]END\n"))
	out.waitFor(t, "LEAK[]END")
	if strings.Contains(out.String(), "LEAK[secret]") {
		t.Fatal("agent environment leaked into shell")
	}
	_, _ = s.Write([]byte("echo H=$HOME T=$TERM\n"))
	cu, _ := user.Current()
	home := cu.HomeDir
	out.waitFor(t, "H="+home+" T=xterm-256color")
}

func TestRefuseRoot(t *testing.T) {
	for _, name := range []string{"root", ""} {
		if _, err := NewSpawner(name); !errors.Is(err, ErrRootRefused) {
			t.Errorf("NewSpawner(%q) = %v, want ErrRootRefused", name, err)
		}
	}
}

func TestRefuseOtherUserWhenNotRoot(t *testing.T) {
	cur := currentUser(t)
	// Find some other existing non-root user; skip when none is found.
	for _, name := range []string{"nobody", "daemon", "bin"} {
		if name == cur {
			continue
		}
		if _, err := user.Lookup(name); err != nil {
			continue
		}
		if _, err := NewSpawner(name); err == nil {
			t.Fatalf("NewSpawner(%q) as non-root succeeded, want error", name)
		}
		return
	}
	t.Skip("no other user available")
}

func TestRegistryWithRealSpawner(t *testing.T) {
	sp, err := newSpawner(currentUser(t), "/bin/sh")
	if err != nil {
		t.Fatal(err)
	}
	reg := NewSessions(sp)
	defer reg.CloseAll()
	for i := range MaxSessions {
		if _, err := reg.Open(string(rune('a'+i)), 80, 24); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := reg.Open("x", 80, 24); !errors.Is(err, ErrTooManySessions) {
		t.Fatalf("err = %v", err)
	}
}
