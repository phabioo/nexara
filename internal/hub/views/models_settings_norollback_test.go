package views

import (
	"strings"
	"testing"

	"github.com/phabioo/nexara/internal/hub/update"
)

func TestSettingsLastNoRollbackHint(t *testing.T) {
	tests := []struct {
		name string
		res  update.Result
		hint bool
	}{
		{"refused for missing rollback material", update.Result{Status: update.StatusError, Phase: update.PhaseVerify,
			Message: update.MsgNoRollback + " (x); run `" + update.NoRollbackCommand + "`"}, true},
		{"any other failure keeps the plain message", update.Result{Status: update.StatusError, Phase: update.PhaseVerify, Message: "signature check failed"}, false},
		{"a rollback is not a refusal", update.Result{Status: update.StatusRolledBack, Message: update.MsgNoRollback}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := tc.res
			r.FinishedAt = settingsNow
			u := NewSettingsUpdates(settingsNow, updStatus(func(s *update.Status) { s.Last = &r }), nil)
			l := u.Last
			if l == nil || l.NoRollback != tc.hint {
				t.Fatalf("last = %+v, want hint %v", l, tc.hint)
			}
			if !tc.hint {
				if l.Command != "" || l.Why != "" || len(l.Steps) != 0 {
					t.Errorf("hint fields set: %+v", l)
				}
				return
			}
			if l.Command != "sudo nexus update-apply --no-rollback" || l.Why == "" || len(l.Steps) != 3 || !strings.Contains(l.Message, "Nothing was installed") {
				t.Errorf("hint = %+v", l)
			}
		})
	}
}
