package main

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/phabioo/nexara/internal/hub/setup"
)

// fakeAdmin replaces the socket client for one test.
func fakeAdmin(t *testing.T, resp setup.AdminResponse, err error) *[]string {
	t.Helper()
	var calls []string
	orig := adminCall
	adminCall = func(socket, cmd string) (setup.AdminResponse, error) {
		calls = append(calls, socket+" "+cmd)
		return resp, err
	}
	t.Cleanup(func() { adminCall = orig })
	return &calls
}

func TestSetupCode(t *testing.T) {
	calls := fakeAdmin(t, setup.AdminResponse{OK: true, Message: "New setup code: ABCD-EFGH (valid until 22:00)"}, nil)
	code, out, errOut := runCtxArgs(context.Background(), "", "setup", "code", "--admin-socket", "/tmp/x.sock")
	if code != 0 || !strings.Contains(out, "ABCD-EFGH") || errOut != "" {
		t.Fatalf("code %d stdout %q stderr %q", code, out, errOut)
	}
	if len(*calls) != 1 || (*calls)[0] != "/tmp/x.sock "+setup.CmdSetupCode {
		t.Errorf("calls = %v", *calls)
	}

	// Default socket path.
	*calls = nil
	runCtxArgs(context.Background(), "", "setup", "code")
	if len(*calls) != 1 || !strings.HasPrefix((*calls)[0], "/run/nexus/admin.sock ") {
		t.Errorf("default socket: %v", *calls)
	}
}

func TestSetupCodeErrors(t *testing.T) {
	fakeAdmin(t, setup.AdminResponse{}, errors.New("permission denied on /run/nexus/admin.sock: run this command with sudo"))
	code, out, errOut := runCtxArgs(context.Background(), "", "setup", "code")
	if code != 1 || out != "" || !strings.Contains(errOut, "sudo") {
		t.Fatalf("code %d stdout %q stderr %q", code, out, errOut)
	}

	if code, _, errOut := runCtxArgs(context.Background(), "", "setup", "code", "--bogus"); code != 2 || !strings.Contains(errOut, "not defined") {
		t.Errorf("bad flag: %d %q", code, errOut)
	}
}

// With the real client and no running hub the operator gets a message that says what to do.
func TestSetupCodeWithoutRunningHub(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "admin.sock")
	for _, args := range [][]string{
		{"setup", "code", "--admin-socket", missing},
		{"user", "reset", "--yes", "--admin-socket", missing},
	} {
		code, out, errOut := runCtxArgs(context.Background(), "", args...)
		if code != 1 || out != "" || !strings.Contains(errOut, "does not exist") || !strings.Contains(errOut, "nexus service") {
			t.Errorf("%v: code %d stdout %q stderr %q", args, code, out, errOut)
		}
	}
}

func TestUserReset(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		stdin     string
		wantCalls int
		code      int
		stderrHas string
	}{
		{"yes flag skips the question", []string{"--yes"}, "", 1, 0, ""},
		{"answer y", nil, "y\n", 1, 0, ""},
		{"answer yes, any case", nil, " YES \n", 1, 0, ""},
		{"answer n", nil, "n\n", 0, 1, "cancelled"},
		{"empty answer is no", nil, "\n", 0, 1, "cancelled"},
		{"closed stdin is no", nil, "", 0, 1, "cancelled"},
		{"anything else is no", nil, "sure\n", 0, 1, "cancelled"},
	}
	for _, tt := range tests {
		calls := fakeAdmin(t, setup.AdminResponse{OK: true, Message: "Removed 1 operator account(s)."}, nil)
		args := append([]string{"user", "reset"}, tt.args...)
		code, out, errOut := runCtxArgs(context.Background(), tt.stdin, args...)
		if code != tt.code || len(*calls) != tt.wantCalls || !strings.Contains(errOut, tt.stderrHas) {
			t.Errorf("%s: code %d calls %v stderr %q", tt.name, code, *calls, errOut)
		}
		if tt.wantCalls == 1 && (!strings.Contains(out, "Removed 1") || !strings.HasSuffix((*calls)[0], setup.CmdUserReset)) {
			t.Errorf("%s: stdout %q calls %v", tt.name, out, *calls)
		}
		asked := strings.Contains(out, "Continue? [y/N]")
		if asked != (len(tt.args) == 0) {
			t.Errorf("%s: question asked = %v, stdout %q", tt.name, asked, out)
		}
	}
}

func TestUserResetError(t *testing.T) {
	fakeAdmin(t, setup.AdminResponse{}, errors.New("reset failed"))
	code, _, errOut := runCtxArgs(context.Background(), "", "user", "reset", "--yes")
	if code != 1 || !strings.Contains(errOut, "reset failed") {
		t.Fatalf("code %d stderr %q", code, errOut)
	}
}
