package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
)

type fakeRun struct {
	calls  []string
	status string           // dpkg-query output
	fail   map[string]error // command line prefix -> error
}

func (f *fakeRun) run(_ context.Context, out io.Writer, name string, args ...string) error {
	line := strings.TrimSpace(name + " " + strings.Join(args, " "))
	f.calls = append(f.calls, line)
	if name == "dpkg-query" {
		io.WriteString(out, f.status)
	}
	for prefix, err := range f.fail {
		if strings.HasPrefix(line, prefix) {
			io.WriteString(out, "Failed to disable unit: Unit file grid-agent.service does not exist.\n")
			return err
		}
	}
	return nil
}

func TestUninstall(t *testing.T) {
	const installed = "install ok installed"
	errBoom := errors.New("boom")
	tests := []struct {
		name      string
		purge     bool
		euid      int
		status    string
		fail      map[string]error
		confirm   func(string) bool
		wantErr   error
		wantErrIs string
		wantCalls []string
		wantOut   []string
	}{
		{
			name: "remove", euid: 0, status: installed,
			wantCalls: []string{
				"dpkg-query -W -f=${Status} nexus",
				"systemctl disable --now grid-agent.service",
				"systemctl disable --now nexus.service",
				"apt-get remove -y nexus",
			},
			wantOut: []string{"kept in /etc/nexus", "sudo nexus uninstall --purge"},
		},
		{
			name: "purge", purge: true, euid: 0, status: installed,
			wantCalls: []string{
				"dpkg-query -W -f=${Status} nexus",
				"systemctl disable --now grid-agent.service",
				"systemctl disable --now nexus.service",
				"apt-get purge -y nexus",
			},
			wantOut: []string{"together with its configuration"},
		},
		{name: "not root", euid: 1000, status: installed, wantErr: ErrNotRoot},
		{name: "not root is checked before anything runs", euid: -1, wantErr: ErrNotRoot},
		{
			name: "not installed via dpkg", euid: 0, status: "unknown ok not-installed",
			wantErr: ErrNotPackaged, wantCalls: []string{"dpkg-query -W -f=${Status} nexus"},
		},
		{
			name: "dpkg-query missing", euid: 0, fail: map[string]error{"dpkg-query": errBoom},
			wantErr: ErrNotPackaged, wantCalls: []string{"dpkg-query -W -f=${Status} nexus"},
		},
		{
			name: "removed but config remains is not installed", euid: 0, status: "deinstall ok config-files",
			wantErr: ErrNotPackaged, wantCalls: []string{"dpkg-query -W -f=${Status} nexus"},
		},
		{
			name: "declined", purge: true, euid: 0, status: installed,
			confirm: func(q string) bool { return false }, wantErr: ErrCancelled,
			wantCalls: []string{"dpkg-query -W -f=${Status} nexus"},
		},
		{
			name: "unit not loaded is tolerated", euid: 0, status: installed,
			fail: map[string]error{"systemctl disable --now grid-agent": errBoom},
			wantCalls: []string{
				"dpkg-query -W -f=${Status} nexus",
				"systemctl disable --now grid-agent.service",
				"systemctl disable --now nexus.service",
				"apt-get remove -y nexus",
			},
			wantOut: []string{"Unit file grid-agent.service does not exist"},
		},
		{
			name: "apt fails", euid: 0, status: installed,
			fail:      map[string]error{"apt-get": errBoom},
			wantErrIs: "apt-get remove nexus failed: boom",
			wantCalls: []string{
				"dpkg-query -W -f=${Status} nexus",
				"systemctl disable --now grid-agent.service",
				"systemctl disable --now nexus.service",
				"apt-get remove -y nexus",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &fakeRun{status: tt.status, fail: tt.fail}
			var out bytes.Buffer
			var asked string
			confirm := tt.confirm
			if confirm != nil {
				inner := confirm
				confirm = func(q string) bool { asked = q; return inner(q) }
			}
			err := Uninstall(context.Background(), UninstallOptions{
				Purge: tt.purge, Confirm: confirm, Out: &out, Run: f.run, Geteuid: func() int { return tt.euid },
			})
			switch {
			case tt.wantErr != nil:
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("err = %v, want %v", err, tt.wantErr)
				}
			case tt.wantErrIs != "":
				if err == nil || err.Error() != tt.wantErrIs {
					t.Fatalf("err = %v, want %q", err, tt.wantErrIs)
				}
			case err != nil:
				t.Fatal(err)
			}
			if tt.wantCalls == nil && tt.euid != 0 {
				if len(f.calls) != 0 {
					t.Fatalf("commands ran without root: %v", f.calls)
				}
			} else if !reflect.DeepEqual(f.calls, tt.wantCalls) {
				t.Fatalf("calls:\n got %q\nwant %q", f.calls, tt.wantCalls)
			}
			for _, want := range tt.wantOut {
				if !strings.Contains(out.String(), want) {
					t.Errorf("output lacks %q:\n%s", want, out.String())
				}
			}
			if tt.confirm != nil && !strings.Contains(asked, "DELETES ALL ITS DATA") {
				t.Errorf("purge warning missing: %q", asked)
			}
		})
	}
}

func TestUninstallConfirmText(t *testing.T) {
	for _, purge := range []bool{false, true} {
		var asked string
		f := &fakeRun{status: "install ok installed"}
		err := Uninstall(context.Background(), UninstallOptions{
			Purge: purge, Run: f.run, Geteuid: func() int { return 0 },
			Confirm: func(q string) bool { asked = q; return true },
		})
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.Contains(asked, "DELETES ALL ITS DATA"); got != purge {
			t.Errorf("purge=%v: warning present = %v (%q)", purge, got, asked)
		}
		if !strings.HasSuffix(asked, "[y/N] ") {
			t.Errorf("question %q does not end with a prompt", asked)
		}
	}
}

func TestExecRunnerCapturesOutputAndErrors(t *testing.T) {
	var out bytes.Buffer
	if err := ExecRunner(context.Background(), &out, "sh", "-c", "echo hi; echo err >&2"); err != nil {
		t.Skipf("no sh: %v", err)
	}
	if !strings.Contains(out.String(), "hi") || !strings.Contains(out.String(), "err") {
		t.Fatalf("output %q", out.String())
	}
	if err := ExecRunner(context.Background(), io.Discard, "sh", "-c", "exit 3"); err == nil {
		t.Fatal("exit status 3 not reported")
	}
	if err := ExecRunner(context.Background(), io.Discard, "definitely-not-a-command-nexara"); err == nil {
		t.Fatal(fmt.Sprint("missing command not reported"))
	}
}
