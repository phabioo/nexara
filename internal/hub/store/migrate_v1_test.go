package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

// TestMigrateFromV01 builds a database exactly as v0.1 left it (schema 1, with
// data) and opens it with the current binary: the data must survive and the
// v0.2 tables must appear.
func TestMigrateFromV01(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "nexus.db")

	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	ms, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	if ms[0].version != 1 || len(ms) < 2 {
		t.Fatalf("expected the v0.1 migration plus newer ones, got %d", len(ms))
	}
	for _, stmt := range []string{
		ms[0].sql,
		"PRAGMA user_version = 1",
		`INSERT INTO users (operator_id, pass_hash, created_at, updated_at) VALUES ('alice', 'h', 1, 1)`,
		`INSERT INTO hosts (id, name, created_at) VALUES ('a1c5e0d2b7f34961', 'pi5-media', 1)`,
		`INSERT INTO audit_log (ts, "user", host, action, detail, result) VALUES (5, 'alice', 'pi5-media', 'login', '', 'ok')`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	s, err := Open(path)
	if err != nil {
		t.Fatalf("open v0.1 database: %v", err)
	}
	defer s.Close()
	if v, _ := s.SchemaVersion(ctx); v != LatestSchemaVersion() || v < 2 {
		t.Fatalf("schema version %d, want %d", v, LatestSchemaVersion())
	}
	if _, err := s.GetUserByOperatorID(ctx, "alice"); err != nil {
		t.Errorf("user lost: %v", err)
	}
	if h, err := s.GetHostByName(ctx, "pi5-media"); err != nil || h.ID != "a1c5e0d2b7f34961" {
		t.Errorf("host lost: %+v %v", h, err)
	}
	if a, err := s.ListAudit(ctx, 10); err != nil || len(a) != 1 || a[0].Action != "login" {
		t.Errorf("audit lost: %+v %v", a, err)
	}
	if err := s.SetSetting(ctx, SettingHistoryRetentionDays, "90"); err != nil {
		t.Errorf("settings table: %v", err)
	}
	row := testRow("a1c5e0d2b7f34961", t0.Truncate(time.Minute), 3)
	if err := s.MergeMetrics1m(ctx, []MetricRow{row}); err != nil {
		t.Errorf("metrics table: %v", err)
	}
}
