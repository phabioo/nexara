//go:build !windows

package store

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestOpenRestrictsDBFilePermissions(t *testing.T) {
	for _, tc := range []struct {
		name string
		pre  bool // existing database with a permissive mode
	}{{"new", false}, {"existing", true}} {
		t.Run(tc.name, func(t *testing.T) {
			old := syscall.Umask(0o022)
			defer syscall.Umask(old)
			path := filepath.Join(t.TempDir(), "nexus.db")
			if tc.pre {
				if err := os.WriteFile(path, nil, 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(path, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			s, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if _, err := s.AppendAudit(context.Background(), AuditEntry{Action: "x", Result: AuditOK}); err != nil {
				t.Fatal(err)
			}
			for _, p := range []string{path, path + "-wal", path + "-shm"} {
				fi, err := os.Stat(p)
				if err != nil {
					if os.IsNotExist(err) {
						continue
					}
					t.Fatal(err)
				}
				if fi.Mode().Perm() != 0o600 {
					t.Errorf("%s mode = %o, want 600", filepath.Base(p), fi.Mode().Perm())
				}
			}
			if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
				t.Fatalf("main db missing or wrong mode: %v", err)
			}
		})
	}
}
