package main

import (
	"bytes"
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
		{[]string{"dev", "--demo"}, 2, "not implemented yet"},
		{[]string{"dev", "--demo", "--addr", "127.0.0.1:9"}, 2, "not implemented yet"},
		{[]string{"setup", "code"}, 2, "not implemented yet"},
		{[]string{"setup"}, 2, "Usage: nexus setup code"},
		{[]string{"user", "reset"}, 2, "not implemented yet"},
		{[]string{"uninstall"}, 2, "not implemented yet"},
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

func TestServeOpensStoreAndExits(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "nexus.yaml")
	db := filepath.ToSlash(filepath.Join(dir, "nexus.db"))
	if err := os.WriteFile(cfg, []byte("storage:\n  database: \""+db+"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, errOut := runArgs("serve", "--config", cfg)
	if code != 0 || !strings.Contains(errOut, "nexus ready") {
		t.Fatalf("code %d stderr %q", code, errOut)
	}
	if _, err := os.Stat(filepath.Join(dir, "nexus.db")); err != nil {
		t.Fatalf("database not created: %v", err)
	}
}
