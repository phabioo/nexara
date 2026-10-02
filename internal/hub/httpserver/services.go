package httpserver

import (
	"context"

	"github.com/phabioo/nexara/internal/hub/backup"
	"github.com/phabioo/nexara/internal/hub/grid"
	"github.com/phabioo/nexara/internal/hub/history"
	"github.com/phabioo/nexara/internal/hub/store"
	"github.com/phabioo/nexara/internal/hub/update"
	"github.com/phabioo/nexara/internal/pki"
)

// Services are the hub services behind the v0.2 views (Settings, History,
// Audit log, setup restore). A nil field hides the parts of a view that need
// it, so tests and the demo can leave out what they do not exercise.
type Services struct {
	History *history.Service // History view (Series)
	Backup  *backup.Service  // Settings › Backup, setup restore
	Updates *update.Service  // Settings › Updates
	Certs   grid.CertRenewer // Settings › Certificates (renew an agent certificate)
	// Settings is the key-value store of values changed in Settings (#49).
	Settings SettingsStore
	// Store gives read access for the Audit log view and Settings summaries.
	Store *store.Store
	// CA is the hub's certificate authority (Settings › Certificates).
	CA *pki.CA
	// Restart stops the hub so systemd starts it again on restored data
	// (decision #55). Nil means restarting is not possible (tests, demo).
	Restart func()
}

// SettingsStore is the settings table (store.KV implements it).
type SettingsStore interface {
	Get(ctx context.Context, key string) (string, bool, error)
	Set(ctx context.Context, key, value string) error
}
