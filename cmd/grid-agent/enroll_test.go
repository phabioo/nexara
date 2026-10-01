package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// --token-file keeps the one-time code off the command line (S-19). Everything
// that is wrong with the file is reported before any network access.
func TestEnrollTokenFile(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	base := []string{"enroll", "--hub", "https://localhost:1", "--ca-fingerprint", strings.Repeat("ab", 32)}
	tests := []struct {
		name      string
		extra     []string
		unixOnly  bool
		code      int
		stderrHas string
	}{
		{"missing file", []string{"--token-file", filepath.Join(dir, "missing")}, false, exitEnrollFailed, "open token file"},
		{"malformed content", []string{"--token-file", write("bad", "nope\n", 0o600)}, false, exitEnrollFailed, "malformed"},
		{"readable by others", []string{"--token-file", write("open", "GRID-ABCD-EFGH-JKMN-PQRS\n", 0o644)}, true, exitEnrollFailed, "must not be accessible"},
		{"token and file together", []string{"--token", "x", "--token-file", "y"}, false, exitUsageOrStub, "either --token or --token-file"},
		{"neither", nil, false, exitUsageOrStub, "--token or --token-file is required"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.unixOnly && runtime.GOOS == "windows" {
				t.Skip("file modes are not enforced on Windows")
			}
			code, _, errOut := runArgs(append(append([]string(nil), base...), tt.extra...)...)
			if code != tt.code || !strings.Contains(errOut, tt.stderrHas) {
				t.Fatalf("code %d stderr %q, want %d containing %q", code, errOut, tt.code, tt.stderrHas)
			}
			if strings.Contains(errOut, "GRID-ABCD") {
				t.Fatalf("the code was printed: %q", errOut)
			}
		})
	}
}
