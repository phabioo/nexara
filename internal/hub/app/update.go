package app

import (
	"context"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/phabioo/nexara/internal/hub/store"
	"github.com/phabioo/nexara/internal/hub/update"
)

// newUpdateService creates the self-update service (decisions #21 and #50).
// The hub only checks, downloads, verifies and stages; installing is the job
// of the root helper `nexus update-apply`, started by nexus-update.path when
// the service writes <data dir>/updates/request.json.
//
// Updating from the UI only works for the packaged data directory, which is
// the one the path unit watches; elsewhere the service still stages bundles.
func newUpdateService(dataDir string, st *store.Store, settings update.Settings, log *slog.Logger, now func() time.Time) (*update.Service, error) {
	return update.New(update.Options{
		Dir:      filepath.Join(dataDir, update.UpdatesDirName),
		Settings: settings,
		Audit: func(ctx context.Context, e store.AuditEntry) {
			appendAudit(ctx, st, log, e)
		},
		Logger:        log.With("component", "update"),
		Now:           now,
		HelperWatches: filepath.Clean(dataDir) == update.DefaultDataDir,
	})
}
