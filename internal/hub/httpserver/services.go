package httpserver

import (
	"context"
	"crypto/x509"
	"log/slog"
	"time"

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
	// (decision #55). Nil means restarting is not possible (tests, demo); the
	// Settings view then offers no restore.
	Restart func()
	// Caps switches capabilities of a host on and off (Settings › Hosts &
	// capabilities). Nil shows the capabilities read-only.
	Caps grid.CapabilityController
	// Logs is the hub's recent log (Settings › Diagnostics). Nil hides the
	// hub log button.
	Logs LogSource
	// ServerCert returns the hub's current TLS certificate (Settings ›
	// Certificates: expiry and names). Nil, or an error, shows "not available".
	ServerCert func() (*x509.Certificate, error)
	// HubHost tells whether a host is the device the hub runs on ("Hub +
	// agent"). Nil uses a host name / loopback address match.
	HubHost func(grid.HostInfo) bool
}

// LogRecord is one line of the hub log kept for the Diagnostics card. Text
// already holds the message and its attributes, formatted and cleaned.
type LogRecord struct {
	Time  time.Time
	Level slog.Level
	Text  string
}

// LogSource gives the recent hub log.
type LogSource interface {
	// Records returns the retained records, newest first.
	Records() []LogRecord
}

// SettingsStore is the settings table (store.KV implements it).
type SettingsStore interface {
	Get(ctx context.Context, key string) (string, bool, error)
	Set(ctx context.Context, key, value string) error
}
