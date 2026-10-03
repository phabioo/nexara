package app

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/phabioo/nexara/internal/config"
	"github.com/phabioo/nexara/internal/hub/auth"
	"github.com/phabioo/nexara/internal/hub/backup"
	"github.com/phabioo/nexara/internal/hub/store"
	"github.com/phabioo/nexara/internal/pki"
)

func backupFixture(t *testing.T) (config.HubConfig, string, *store.Store) {
	t.Helper()
	root := t.TempDir()
	cfgPath := filepath.Join(root, "nexus.yaml")
	cfg := config.DefaultHub()
	cfg.Hub.Name = "frpi5"
	cfg.Storage.Database = filepath.Join(root, "data", "nexus.db")
	cfg.TLS.Dir = filepath.Join(root, "data", "pki")
	if err := os.MkdirAll(filepath.Dir(cfg.Storage.Database), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := config.SaveHub(cfgPath, cfg); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(cfg.Storage.Database)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if _, err := auth.LoadOrCreateSecretKey(filepath.Join(root, "data", "secret.key")); err != nil {
		t.Fatal(err)
	}
	if _, err := pki.LoadOrCreateCA(cfg.TLS.Dir, "localhost"); err != nil {
		t.Fatal(err)
	}
	return cfg, cfgPath, st
}

func TestHubBackupServiceWritesAuditAndBackup(t *testing.T) {
	cfg, cfgPath, st := backupFixture(t)
	svc := newBackupService(cfg, cfgPath, st, slog.New(slog.DiscardHandler), time.Now)
	ctx := backup.WithActor(context.Background(), "alice")

	info, err := svc.CreateLocal(ctx, backup.ReasonManual)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Readable || info.Size == 0 {
		t.Errorf("info = %+v", info)
	}
	entries, err := st.ListAudit(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Action != backup.ActionCreate || entries[0].User != "alice" || entries[0].Result != store.AuditOK {
		t.Fatalf("audit = %+v", entries)
	}
	if sc := svc.Schedule(ctx); sc.Time != "03:00" || sc.Keep != 7 {
		t.Errorf("default schedule = %+v", sc)
	}
}

func TestOpenBackupServiceAndRestoreAudit(t *testing.T) {
	cfg, cfgPath, st := backupFixture(t)
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	svc, lay, err := OpenBackupService(cfgPath, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if lay.Database != cfg.Storage.Database || lay.BackupDir != filepath.Join(filepath.Dir(cfg.Storage.Database), "backups") {
		t.Errorf("layout = %+v", lay)
	}
	info, err := svc.CreateLocal(context.Background(), backup.ReasonPreUpdate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RestoreLocal(context.Background(), info.Name); err != nil {
		t.Fatal(err)
	}
	st, err = store.Open(cfg.Storage.Database)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	entries, _ := st.ListAudit(context.Background(), 10)
	if len(entries) != 1 || entries[0].Action != backup.ActionRestore {
		t.Fatalf("audit after restore = %+v", entries)
	}
	if _, _, err := OpenBackupService(filepath.Join(t.TempDir(), "missing.yaml"), nil); err == nil {
		t.Error("missing config accepted")
	}
}

// Security review B-03: backups made on the command line, including the update
// helper's pre-update backup, and failed restores reach the audit log.
func TestOpenBackupServiceAuditsIntoTheDatabase(t *testing.T) {
	cfg, cfgPath, st := backupFixture(t)
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	svc, _, err := OpenBackupService(cfgPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := backup.WithActor(context.Background(), "cli")
	if _, err := svc.CreateLocal(ctx, backup.ReasonPreUpdate); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RestoreLocal(ctx, "nexus-20260101T000000Z-manual.nxbk"); err == nil {
		t.Fatal("restore of a missing backup succeeded")
	}
	st, err = store.Open(cfg.Storage.Database)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	entries, err := st.ListAudit(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("audit = %+v", entries)
	}
	// Newest first.
	if f := entries[0]; f.Action != backup.ActionRestore || f.Result != store.AuditError || f.User != "cli" {
		t.Errorf("failed restore entry = %+v", f)
	}
	if c := entries[1]; c.Action != backup.ActionCreate || c.Result != store.AuditOK || c.User != "cli" {
		t.Errorf("create entry = %+v", c)
	}
}

func TestOpenBackupServiceDoesNotCreateADatabaseForAnAudit(t *testing.T) {
	cfg, cfgPath, st := backupFixture(t)
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	svc, _, err := OpenBackupService(cfgPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{cfg.Storage.Database, cfg.Storage.Database + "-wal", cfg.Storage.Database + "-shm"} {
		_ = os.Remove(f)
	}
	if _, err := svc.RestoreLocal(context.Background(), "nexus-20260101T000000Z-manual.nxbk"); err == nil {
		t.Fatal("restore of a missing backup succeeded")
	}
	if _, err := os.Stat(cfg.Storage.Database); err == nil {
		t.Error("the audit of a failed restore created a database")
	}
}

// Security review B-07: the running hub closes its database before a restore
// swaps the files.
func TestHubBackupServiceClosesTheStoreBeforeARestore(t *testing.T) {
	cfg, cfgPath, st := backupFixture(t)
	svc := newBackupService(cfg, cfgPath, st, slog.New(slog.DiscardHandler), time.Now)
	ctx := context.Background()
	info, err := svc.CreateLocal(ctx, backup.ReasonManual)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.ListAudit(ctx, 1); err != nil {
		t.Fatalf("the store is closed before the restore: %v", err)
	}
	if _, err := svc.RestoreLocal(ctx, info.Name); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ListAudit(ctx, 1); err == nil {
		t.Error("the old process can still use the replaced database")
	}
}
