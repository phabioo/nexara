package app

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/phabioo/nexara/internal/hub/setup"
)

func newBackend(t *testing.T) (adminBackend, *commitEnv) {
	t.Helper()
	e := newCommitEnv(t, false)
	return adminBackend{codes: e.codes, mode: e.mode, sessions: e.sessions, auth: e.auth}, e
}

func TestAdminSetupCode(t *testing.T) {
	b, e := newBackend(t)
	ctx := context.Background()

	code, exp, err := b.setupCode(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(code) != 9 || code[4] != '-' || !exp.After(time.Now()) {
		t.Errorf("code = %q, expires %v", code, exp)
	}
	if e.codes.Verify(e.setupCode) == nil {
		t.Error("the previous code still works after rotating")
	}
	if err := e.codes.Verify(code); err != nil {
		t.Errorf("new code rejected: %v", err)
	}

	// With an operator there is nothing to unlock.
	createOperator(t, e.st, testOperator, testPass)
	e.mode.Invalidate()
	if _, _, err := b.setupCode(ctx); err == nil || !strings.Contains(err.Error(), "user reset") {
		t.Errorf("err = %v, want a hint to `nexus user reset`", err)
	}
}

func TestAdminUserReset(t *testing.T) {
	b, e := newBackend(t)
	ctx := context.Background()
	createOperator(t, e.st, testOperator, testPass)
	e.mode.Invalidate()
	if e.mode.Active(ctx) {
		t.Fatal("setup mode must be off while an operator exists")
	}
	token, _, err := e.sessions.Unlock()
	if err != nil {
		t.Fatal(err)
	}

	msg, err := b.userReset(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if e.users() != 0 || !e.mode.Active(ctx) {
		t.Errorf("users = %d, setup mode active = %v", e.users(), e.mode.Active(ctx))
	}
	if _, ok := e.sessions.Lookup(token); ok {
		t.Error("setup session survived the reset")
	}
	code, _, ok := e.codes.Current()
	if !ok || !strings.Contains(msg, setup.FormatCode(code)) || !strings.Contains(msg, "Removed 1") {
		t.Errorf("message %q does not announce the new code %q", msg, code)
	}

	// Resetting again reports that there was nothing to remove and still works.
	msg, err = b.userReset(ctx)
	if err != nil || !strings.Contains(msg, "no operator") {
		t.Errorf("second reset: %q %v", msg, err)
	}
}

// shortTempDir avoids the sun_path length limit of Unix sockets.
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "nx")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func startAdminServer(t *testing.T, h setup.AdminHandlers) string {
	t.Helper()
	path := filepath.Join(shortTempDir(t), "admin.sock")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- setup.ServeAdmin(ctx, path, h) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("ServeAdmin: %v", err)
		}
	})
	deadline := time.Now().Add(5 * time.Second)
	for {
		if c, err := net.Dial("unix", path); err == nil {
			c.Close()
			return path
		}
		if time.Now().After(deadline) {
			t.Skip("unix sockets are not available here")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestCallAdmin(t *testing.T) {
	b, e := newBackend(t)
	path := startAdminServer(t, b.handlers())

	resp, err := CallAdmin(path, setup.CmdSetupCode)
	if err != nil || !resp.OK || resp.Code == "" {
		t.Fatalf("setup-code: %+v %v", resp, err)
	}
	if err := e.codes.Verify(resp.Code); err != nil {
		t.Errorf("code from the socket does not verify: %v", err)
	}

	// A refusal by the hub becomes an error with the hub's message.
	createOperator(t, e.st, testOperator, testPass)
	e.mode.Invalidate()
	if _, err := CallAdmin(path, setup.CmdSetupCode); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("err = %v, want the hub's refusal", err)
	}

	resp, err = CallAdmin(path, setup.CmdUserReset)
	if err != nil || !strings.Contains(resp.Message, "Setup code:") {
		t.Errorf("user-reset: %+v %v", resp, err)
	}
	if e.users() != 0 {
		t.Error("user-reset did not remove the operator")
	}

	if _, err := CallAdmin(path, "bogus"); err == nil || !strings.Contains(err.Error(), "unknown command") {
		t.Errorf("unknown command: %v", err)
	}
}

func TestCallAdminConnectionErrors(t *testing.T) {
	dir := shortTempDir(t)
	missing := filepath.Join(dir, "missing.sock")
	if _, err := CallAdmin(missing, setup.CmdSetupCode); err == nil ||
		!strings.Contains(err.Error(), missing) || !strings.Contains(err.Error(), "does not exist") || !strings.Contains(err.Error(), "systemctl") {
		t.Errorf("missing socket: %v", err)
	}

	// A socket file nobody listens on (service crashed).
	stale := filepath.Join(dir, "stale.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: stale, Net: "unix"})
	if err != nil {
		t.Skipf("unix sockets are not available here: %v", err)
	}
	ln.SetUnlinkOnClose(false)
	ln.Close()
	if _, err := CallAdmin(stale, setup.CmdSetupCode); err == nil || !strings.Contains(err.Error(), "not running") {
		t.Errorf("stale socket: %v", err)
	}
}

func TestAdminConnError(t *testing.T) {
	const sock = "/run/nexus/admin.sock"
	tests := []struct {
		name string
		err  error
		want []string
	}{
		{"permission", fmt.Errorf("connect to nexus admin socket: %w", &net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.EACCES)}), []string{"permission denied", "sudo", sock}},
		{"permission sentinel", fmt.Errorf("x: %w", fs.ErrPermission), []string{"permission denied", "sudo"}},
		{"missing", fmt.Errorf("x: %w", &net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.ENOENT)}), []string{"does not exist", "nexus service", sock}},
		{"refused", fmt.Errorf("x: %w", &net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}), []string{"not running", sock}},
		{"other", errors.New("boom"), []string{"cannot talk", "boom"}},
	}
	for _, tt := range tests {
		got := adminConnError(sock, tt.err).Error()
		for _, w := range tt.want {
			if !strings.Contains(got, w) {
				t.Errorf("%s: %q does not contain %q", tt.name, got, w)
			}
		}
	}
}
