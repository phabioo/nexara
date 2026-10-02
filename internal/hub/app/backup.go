package app

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/phabioo/nexara/internal/buildinfo"
	"github.com/phabioo/nexara/internal/config"
	"github.com/phabioo/nexara/internal/hub/backup"
	"github.com/phabioo/nexara/internal/hub/store"
)

// backupSettings is the settings store for backup.time and backup.keep. The
// settings table comes with the history work; until it is wired here the
// backup runs with its defaults (03:00, keep 7).
func backupSettings(*store.Store) backup.Settings { return nil }

// newBackupService wires the backup service of a running hub: snapshots come
// from the open store, audit entries go to the audit log.
func newBackupService(cfg config.HubConfig, configPath string, st *store.Store, log *slog.Logger, now func() time.Time) *backup.Service {
	return backup.New(backup.Options{
		Layout:   backup.LayoutFor(configPath, cfg),
		Snapshot: st.Snapshot,
		Settings: backupSettings(st),
		Audit:    func(ctx context.Context, e store.AuditEntry) { appendAudit(ctx, st, log, e) },
		// The running hub's own database is replaced by a restore, so the
		// entry goes into the restored file.
		AuditRestore: WriteRestoreAudit,
		HubName:      cfg.Hub.Name,
		HubVersion:   buildinfo.Version,
		Now:          now,
		Logger:       log.With("component", "backup"),
	})
}

// runBackupScheduler runs the nightly backup until ctx ends.
func runBackupScheduler(ctx context.Context, svc *backup.Service, cfg config.HubConfig, log *slog.Logger, now func() time.Time) {
	loc, err := time.LoadLocation(cfg.Hub.Timezone)
	if err != nil {
		loc = time.Local
	}
	backup.NewScheduler(backup.SchedulerOptions{Service: svc, Location: loc, Now: now, Logger: log.With("component", "backup")}).Run(ctx)
}

// OpenBackupService builds the backup service for the command line
// (`nexus backup ...`). It works with the hub running or stopped: it reads
// nexus.yaml and takes database snapshots from the file without migrating it.
// The command gives up root before it calls this (see cmd/nexus), so every
// file it creates belongs to the hub's user.
func OpenBackupService(configPath string, log *slog.Logger) (*backup.Service, backup.Layout, error) {
	cfg, err := config.LoadHub(configPath)
	if err != nil {
		return nil, backup.Layout{}, fmt.Errorf("cannot load configuration: %w", err)
	}
	lay := backup.LayoutFor(configPath, cfg)
	svc := backup.New(backup.Options{
		Layout: lay,
		Snapshot: func(ctx context.Context, dest string) error {
			return store.SnapshotFile(ctx, lay.Database, dest)
		},
		AuditRestore: WriteRestoreAudit,
		HubName:      cfg.Hub.Name,
		HubVersion:   buildinfo.Version,
		Logger:       log,
	})
	return svc, lay, nil
}

// WriteRestoreAudit appends the backup.restore entry to the database file that
// a restore has just put in place. It opens the file like the hub does
// (migrating it if the backup is older), so the entry is the first thing the
// restored hub shows in its audit log.
func WriteRestoreAudit(ctx context.Context, dbPath string, e store.AuditEntry) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	st, err := store.Open(dbPath)
	if err != nil {
		return err
	}
	defer st.Close()
	_, err = st.AppendAudit(ctx, e)
	return err
}
