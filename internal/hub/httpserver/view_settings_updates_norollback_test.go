package httpserver

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/phabioo/nexara/internal/hub/update"
)

// Security review B-08: an update refused for lack of rollback material says
// why and shows the one command, instead of a bare "Update failed".
func TestUpdatesCardExplainsMissingRollbackMaterial(t *testing.T) {
	now := time.Now().UTC()
	s := newSettingsEnv(t)
	res := update.Result{
		Status: update.StatusError, Version: "0.2.0", Phase: update.PhaseVerify,
		Message:     update.MsgNoRollback + " (no copy of nexus_0.1.0_arm64.deb was kept by an earlier update); to update without a safety net, run it",
		RequestedBy: testOperator, StartedAt: now.Add(-time.Minute), FinishedAt: now,
	}
	writeJSON(t, filepath.Join(s.updDir, update.ResultFile), res)
	if _, err := s.upd.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	body := s.get("/settings", s.opts(false, false)...).Body.String()
	contains(t, body, "Update refused: no rollback copy", "Nothing was installed.",
		"go back to the version it runs now", "installed by hand with apt or dpkg",
		"sudo systemctl stop nexus-update.path", `id="set-norollback-cmd">sudo nexus update-apply --no-rollback</code>`,
		`data-copy="#set-norollback-cmd"`)
}
