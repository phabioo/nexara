package main

import (
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func runArgs(args ...string) (code int, stdout, stderr string) {
	var o, e bytes.Buffer
	code = run(args, &o, &e)
	return code, o.String(), e.String()
}

func runCtxArgs(ctx context.Context, stdin string, args ...string) (code int, stdout, stderr string) {
	var o, e bytes.Buffer
	code = runContext(ctx, args, strings.NewReader(stdin), &o, &e)
	return code, o.String(), e.String()
}

func TestVersion(t *testing.T) {
	code, out, _ := runArgs("version")
	if code != 0 || !strings.HasPrefix(out, "nexus ") || !strings.Contains(out, "protocol 1") {
		t.Fatalf("%d %q", code, out)
	}
}

func TestDispatch(t *testing.T) {
	tests := []struct {
		args      []string
		code      int
		stderrHas string
	}{
		{nil, 2, "Usage"},
		{[]string{"bogus"}, 2, "unknown command"},
		{[]string{"help"}, 0, ""},
		{[]string{"dev"}, 2, "--demo is required"},
		{[]string{"dev", "--demo", "--addr", "0.0.0.0:8080"}, 2, "loopback"},
		{[]string{"dev", "--demo", "--addr", ":8080"}, 2, "loopback"},
		{[]string{"dev", "--demo", "--addr", "192.168.1.5:8080"}, 2, "loopback"},
		{[]string{"dev", "--demo", "--addr", "nonsense"}, 2, "invalid listen address"},
		{[]string{"dev", "--nope"}, 2, "flag provided but not defined"},
		{[]string{"setup"}, 2, "Usage: nexus setup code"},
		{[]string{"user"}, 2, "Usage: nexus user reset"},
		{[]string{"uninstall", "--nope"}, 2, "flag provided but not defined"},
		{[]string{"uninstall", "extra"}, 2, "unexpected argument"},
		{[]string{"serve", "--nope"}, 2, "flag provided but not defined"},
		{[]string{"serve", "--config", filepath.Join(t.TempDir(), "missing.yaml")}, 1, "cannot load configuration"},
	}
	for _, tt := range tests {
		code, _, errOut := runArgs(tt.args...)
		if code != tt.code || !strings.Contains(errOut, tt.stderrHas) {
			t.Errorf("%v: code %d stderr %q, want code %d containing %q", tt.args, code, errOut, tt.code, tt.stderrHas)
		}
	}
}

func TestServeCannotListen(t *testing.T) {
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "nexus.yaml")
	yaml := "hub:\n  listen: \"" + busy.Addr().String() + "\"\n" +
		"tls:\n  dir: \"" + filepath.ToSlash(filepath.Join(dir, "pki")) + "\"\n" +
		"storage:\n  database: \"" + filepath.ToSlash(filepath.Join(dir, "data", "nexus.db")) + "\"\n"
	if err := os.WriteFile(cfg, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, errOut := runCtxArgs(context.Background(), "", "serve", "--config", cfg, "--admin-socket", "")
	if code != 1 || !strings.Contains(errOut, "cannot listen") {
		t.Fatalf("code %d stderr %q", code, errOut)
	}
}

func TestDevStopsWithTheContext(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	t.Setenv("TMP", tmp)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // a signal arrived right away: start, then shut down cleanly
	code, out, errOut := runCtxArgs(ctx, "", "dev", "--demo", "--addr", "127.0.0.1:0")
	if code != 0 {
		t.Fatalf("code %d stderr %q", code, errOut)
	}
	if !strings.Contains(out, "Setup code: ") || !strings.Contains(out, "dev mode") {
		t.Errorf("console output %q", out)
	}
	if entries, _ := os.ReadDir(tmp); len(entries) != 0 {
		t.Errorf("temporary data left behind: %v", entries)
	}

	ctx, cancel = context.WithCancel(context.Background())
	cancel()
	// A stop request while the demo operator is being created is not a failure either.
	code, out, errOut = runCtxArgs(ctx, "", "dev", "--demo", "--seed", "--addr", "localhost:0")
	if code != 0 || strings.Contains(out, "Setup code") {
		t.Fatalf("seeded: code %d stdout %q stderr %q", code, out, errOut)
	}
}
