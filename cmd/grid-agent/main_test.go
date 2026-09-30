package main

import (
	"bytes"
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
	if code != 0 || !strings.HasPrefix(out, "grid-agent ") || !strings.Contains(out, "protocol 1") {
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
		{[]string{"run"}, 2, "not implemented yet"},
		{[]string{"run", "--config", "/tmp/x.yaml"}, 2, "not implemented yet"},
		{[]string{"enroll"}, 2, "--hub and --token are required"},
		{[]string{"enroll", "--hub", "frpi5.local:8443", "--token", "abc"}, 2, "not implemented yet"},
		{[]string{"run", "--nope"}, 2, "flag provided but not defined"},
	}
	for _, tt := range tests {
		code, _, errOut := runArgs(tt.args...)
		if code != tt.code || !strings.Contains(errOut, tt.stderrHas) {
			t.Errorf("%v: code %d stderr %q, want code %d containing %q", tt.args, code, errOut, tt.code, tt.stderrHas)
		}
	}
}
