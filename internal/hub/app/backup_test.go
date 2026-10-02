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
