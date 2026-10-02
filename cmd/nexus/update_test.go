package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/phabioo/nexara/internal/hub/app"
	"github.com/phabioo/nexara/internal/hub/update"
)

func TestCmdUpdateApply(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		euid      int
		res       update.Result
		err       error
		wantCode  int
		wantCall  bool
		stdoutHas string
		stderrHas string
		check     func(t *testing.T, o update.ApplyOptions)
	}{
		{name: "ok", euid: 0, wantCall: true, res: update.Result{Status: update.StatusOK, Message: "updated from 0.1.0 to 0.2.0"},
			stdoutHas: "updated from 0.1.0 to 0.2.0",
			check: func(t *testing.T, o update.ApplyOptions) {
				if o.DataDir != update.DefaultDataDir || o.StateDir != update.DefaultStateDir || o.NoRollback || o.AllowDowngrade ||
					o.HealthTimeout != 60*time.Second || o.Health == nil {
					t.Fatalf("options = %+v", o)
				}
			}},
		{name: "flags are passed", euid: 0, wantCall: true, res: update.Result{Status: update.StatusOK, Message: "m"},
			args: []string{"--no-rollback", "--allow-downgrade", "--data-dir", "/d", "--state-dir", "/s", "--health-timeout", "5s"},
			check: func(t *testing.T, o update.ApplyOptions) {
				if !o.NoRollback || !o.AllowDowngrade || o.DataDir != "/d" || o.StateDir != "/s" || o.HealthTimeout != 5*time.Second {
					t.Fatalf("options = %+v", o)
				}
			}},
		{name: "nothing pending is fine", euid: 0, wantCall: true, err: update.ErrNoRequest, stdoutHas: "no update request pending"},
		{name: "rolled back fails the unit", euid: 0, wantCall: true, wantCode: 1,
			res: update.Result{Status: update.StatusRolledBack, Message: "restored 0.1.0"}, stderrHas: "rolled_back: restored 0.1.0"},
		{name: "error fails the unit", euid: 0, wantCall: true, wantCode: 1,
			res: update.Result{Status: update.StatusError, Message: "bad signature"}, stderrHas: "error: bad signature"},
		{name: "infrastructure failure", euid: 0, wantCall: true, wantCode: 1, err: errors.New("disk full"), stderrHas: "disk full"},
		{name: "not root", euid: 1000, wantCode: 1, stderrHas: "must run as root"},
		{name: "extra argument", euid: 0, args: []string{"now"}, wantCode: 2, stderrHas: "unexpected argument"},
		{name: "bad flag", euid: 0, args: []string{"--nope"}, wantCode: 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called := false
			var got update.ApplyOptions
			oldApply, oldEuid := updateApply, geteuid
			updateApply = func(_ context.Context, o update.ApplyOptions) (update.Result, error) {
				called, got = true, o
				return tt.res, tt.err
			}
			geteuid = func() int { return tt.euid }
			t.Cleanup(func() { updateApply, geteuid = oldApply, oldEuid })

			code, out, errOut := runCtxArgs(context.Background(), "", append([]string{"update-apply"}, tt.args...)...)
			if code != tt.wantCode {
				t.Fatalf("code %d (stderr %q), want %d", code, errOut, tt.wantCode)
			}
			if called != tt.wantCall {
				t.Fatalf("helper called = %v, want %v", called, tt.wantCall)
			}
			if !strings.Contains(out, tt.stdoutHas) {
				t.Errorf("stdout %q lacks %q", out, tt.stdoutHas)
			}
			if !strings.Contains(errOut, tt.stderrHas) {
				t.Errorf("stderr %q lacks %q", errOut, tt.stderrHas)
			}
			if tt.check != nil && called {
				tt.check(t, got)
			}
			if called && got.Health == nil {
				t.Error("no health check wired")
			}
		})
	}
}

func TestUpdateApplyDefaultsMatchTheHub(t *testing.T) {
	// The health check must ask the socket the hub listens on.
	if app.DefaultAdminSocket != "/run/nexus/admin.sock" {
		t.Fatalf("admin socket default changed: %s", app.DefaultAdminSocket)
	}
	code, out, _ := runCtxArgs(context.Background(), "", "help")
	if code != 0 || !strings.Contains(out, "update-apply") {
		t.Fatalf("usage does not mention update-apply: %q", out)
	}
}
