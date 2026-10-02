package store

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSnapshotIsConsistentAndStandalone(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "nexus.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	mustUser(t, s, "alice")
	mustUser(t, s, "bob")

	dest := filepath.Join(dir, "snap.db")
	if err := s.Snapshot(ctx, dest); err != nil {
		t.Fatal(err)
	}
	// Writes after the snapshot must not show up in it.
	mustUser(t, s, "carol")

	if _, err := os.Stat(dest + "-wal"); err == nil {
		t.Error("snapshot has a -wal companion")
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(dest); fi.Mode().Perm() != 0o600 {
			t.Errorf("mode %v, want 0600", fi.Mode().Perm())
		}
	}
	snap, err := Open(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer snap.Close()
	var n int
	if err := snap.db.QueryRowContext(ctx, "SELECT count(*) FROM users").Scan(&n); err != nil || n != 2 {
		t.Fatalf("users in snapshot = %d, %v; want 2", n, err)
	}
}

func TestSnapshotRefusesExistingTarget(t *testing.T) {
	s := openTest(t)
	dest := filepath.Join(t.TempDir(), "snap.db")
	if err := os.WriteFile(dest, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := s.Snapshot(context.Background(), dest)
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("err = %v, want already exists", err)
	}
	if b, _ := os.ReadFile(dest); string(b) != "x" {
		t.Error("existing target was modified")
	}
}

func TestSnapshotFileWhileOpen(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "nexus.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	mustUser(t, s, "alice")

	dest := filepath.Join(dir, "snap.db")
	if err := SnapshotFile(ctx, path, dest); err != nil {
		t.Fatal(err)
	}
	v, err := CheckFile(ctx, dest)
	if err != nil || v != LatestSchemaVersion() {
		t.Fatalf("CheckFile = %d, %v; want %d", v, err, LatestSchemaVersion())
	}
	if err := SnapshotFile(ctx, filepath.Join(dir, "missing.db"), filepath.Join(dir, "x.db")); err == nil {
		t.Error("snapshot of a missing database must fail")
	}
}

func TestCheckFile(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	good := filepath.Join(dir, "good.db")
	s, err := Open(good)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	garbage := filepath.Join(dir, "garbage.db")
	if err := os.WriteFile(garbage, []byte(strings.Repeat("not a database ", 500)), 0o600); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(dir, "empty.db")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		path    string
		want    int
		wantErr bool
	}{
		{"valid", good, LatestSchemaVersion(), false},
		{"garbage", garbage, 0, true},
		{"missing", filepath.Join(dir, "none.db"), 0, true},
		{"empty file reports schema 0", empty, 0, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v, err := CheckFile(ctx, tc.path)
			if (err != nil) != tc.wantErr || (!tc.wantErr && v != tc.want) {
				t.Fatalf("CheckFile = %d, %v", v, err)
			}
		})
	}
	// The check must not leave journal files or change the file.
	if _, err := os.Stat(good + "-wal"); err == nil {
		t.Error("CheckFile created a -wal file")
	}
}
