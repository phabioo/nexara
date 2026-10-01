package main

import (
	"context"
	"strings"
	"testing"
)

// --demo-large only changes the demo data; the command starts and stops like plain --demo.
func TestDevLargeFlag(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	t.Setenv("TMP", tmp)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	code, out, errOut := runCtxArgs(ctx, "", "dev", "--demo", "--demo-large", "--seed", "--addr", "127.0.0.1:0")
	if code != 0 || strings.Contains(errOut, "flag provided but not defined") {
		t.Fatalf("code %d stdout %q stderr %q", code, out, errOut)
	}
}
