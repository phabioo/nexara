package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/phabioo/nexara/internal/hub/app"
)

func TestCmdUninstall(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		stdin      string
		err        error
		wantCode   int
		wantPurge  bool
		wantAsk    bool // a confirmation is passed to Uninstall
		wantAnswer bool // and the typed answer is accepted
		stderrHas  string
	}{
		{name: "remove asks, yes", args: nil, stdin: "y\n", wantAsk: true, wantAnswer: true},
		{name: "remove asks, no", args: nil, stdin: "n\n", wantAsk: true, wantAnswer: false},
		{name: "no input is a no", args: nil, stdin: "", wantAsk: true, wantAnswer: false},
		{name: "purge", args: []string{"--purge"}, stdin: "yes\n", wantPurge: true, wantAsk: true, wantAnswer: true},
		{name: "--yes skips the question", args: []string{"--yes"}},
		{name: "purge --yes", args: []string{"--purge", "--yes"}, wantPurge: true},
		{name: "not root", args: []string{"--yes"}, err: app.ErrNotRoot, wantCode: 1, stderrHas: "must run as root"},
		{name: "not packaged", args: []string{"--yes"}, err: app.ErrNotPackaged, wantCode: 1, stderrHas: "delete the binaries"},
		{name: "cancelled", args: nil, stdin: "n\n", err: app.ErrCancelled, wantCode: 1, wantAsk: true, stderrHas: "cancelled"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got app.UninstallOptions
			var answer bool
			old := uninstall
			uninstall = func(_ context.Context, o app.UninstallOptions) error {
				got = o
				if o.Confirm != nil {
					answer = o.Confirm("Sure? [y/N] ")
				}
				return tt.err
			}
			t.Cleanup(func() { uninstall = old })

			code, out, errOut := runCtxArgs(context.Background(), tt.stdin, append([]string{"uninstall"}, tt.args...)...)
			if code != tt.wantCode {
				t.Fatalf("code %d (stderr %q), want %d", code, errOut, tt.wantCode)
			}
			if got.Purge != tt.wantPurge {
				t.Errorf("purge = %v", got.Purge)
			}
			if (got.Confirm != nil) != tt.wantAsk {
				t.Errorf("confirm set = %v, want %v", got.Confirm != nil, tt.wantAsk)
			}
			if tt.wantAsk && answer != tt.wantAnswer {
				t.Errorf("answer = %v, want %v", answer, tt.wantAnswer)
			}
			if tt.wantAsk && !strings.Contains(out, "Sure? [y/N] ") {
				t.Errorf("question not printed: %q", out)
			}
			if !strings.Contains(errOut, tt.stderrHas) {
				t.Errorf("stderr %q lacks %q", errOut, tt.stderrHas)
			}
		})
	}
}

func TestCmdUninstallGenericError(t *testing.T) {
	old := uninstall
	uninstall = func(context.Context, app.UninstallOptions) error { return errors.New("apt exploded") }
	t.Cleanup(func() { uninstall = old })
	code, _, errOut := runCtxArgs(context.Background(), "", "uninstall", "--yes")
	if code != 1 || !strings.Contains(errOut, "apt exploded") {
		t.Fatalf("%d %q", code, errOut)
	}
}

func TestUsageMentionsUninstallFlags(t *testing.T) {
	_, out, _ := runArgs("help")
	if !strings.Contains(out, "uninstall [--purge] [--yes]") {
		t.Fatalf("usage lacks uninstall flags:\n%s", out)
	}
}
