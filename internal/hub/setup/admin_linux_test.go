package setup

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func startAdmin(t *testing.T, h AdminHandlers) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "admin.sock")
	// A stale file must not block startup.
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- ServeAdmin(ctx, path, h) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("ServeAdmin: %v", err)
		}
	})
	for i := 0; i < 100; i++ {
		if c, err := net.Dial("unix", path); err == nil {
			c.Close()
			return path
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("socket did not come up")
	return ""
}

func TestAdminRoundtrip(t *testing.T) {
	codes := NewCodes(CodeOptions{})
	resets := 0
	path := startAdmin(t, AdminHandlers{
		SetupCode: func(context.Context) (string, time.Time, error) {
			c, exp, err := codes.Rotate()
			return FormatCode(c), exp, err
		},
		UserReset: func(context.Context) (string, error) { resets++; return "operator reset", nil },
	})
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o660 {
		t.Fatalf("socket mode: %v %v", fi, err)
	}

	resp, err := AdminCall(path, CmdSetupCode)
	if err != nil || !resp.OK || resp.Expires == nil {
		t.Fatalf("setup-code: %+v %v", resp, err)
	}
	if err := codes.Verify(resp.Code); err != nil {
		t.Fatalf("returned code invalid: %v", err)
	}
	if !strings.Contains(resp.Message, resp.Code) {
		t.Fatalf("message %q", resp.Message)
	}

	resp, err = AdminCall(path, CmdUserReset)
	if err != nil || !resp.OK || resp.Message != "operator reset" || resets != 1 {
		t.Fatalf("user-reset: %+v %v", resp, err)
	}
}

func TestAdminHandlerErrorAndUnknown(t *testing.T) {
	path := startAdmin(t, AdminHandlers{
		UserReset: func(context.Context) (string, error) { return "", errors.New("boom") },
	})
	for cmd, wantMsg := range map[string]string{
		CmdUserReset: "boom",
		CmdSetupCode: "not available",
		"rm-rf":      "unknown command",
		"":           "unknown command",
	} {
		resp, err := AdminCall(path, cmd)
		if err != nil || resp.OK || !strings.Contains(resp.Message, wantMsg) {
			t.Errorf("cmd %q: %+v %v", cmd, resp, err)
		}
	}
}

func TestAdminBadAndOversizedRequest(t *testing.T) {
	path := startAdmin(t, AdminHandlers{})
	for _, payload := range []string{"not json\n", strings.Repeat("x", 10000) + "\n"} {
		c, err := net.Dial("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		c.Write([]byte(payload))
		buf := make([]byte, 256)
		n, _ := c.Read(buf)
		c.Close()
		if !strings.Contains(string(buf[:n]), `"ok":false`) {
			t.Errorf("response %q", buf[:n])
		}
	}
}
