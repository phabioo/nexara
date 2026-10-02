package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
)

// Snapshot writes a consistent copy of the database to dest (VACUUM INTO). The
// copy is a plain database file without -wal/-shm companions, taken in one
// read transaction, so it is safe while the hub keeps running. dest must not
// exist. The store has a single connection, so other callers wait until the
// copy is done; for a hub database (megabytes) that is well under a second.
func (s *Store) Snapshot(ctx context.Context, dest string) error {
	return vacuumInto(ctx, s.db, dest)
}

// SnapshotFile does the same for a database file that another process (the
// running hub) may have open: `nexus backup create` uses it. It never applies
// migrations and never writes to the source; with a WAL database SQLite may
// have to create the -shm/-wal files, so a root caller should hand them back
// to the database's owner (see the backup package).
func SnapshotFile(ctx context.Context, dbPath, dest string) error {
	if _, err := os.Stat(dbPath); err != nil {
		return fmt.Errorf("store: snapshot %s: %w", dbPath, err)
	}
	db, err := openReadOnly(dbPath, false)
	if err != nil {
		return fmt.Errorf("store: snapshot %s: %w", dbPath, err)
	}
	defer db.Close()
	return vacuumInto(ctx, db, dest)
}

func vacuumInto(ctx context.Context, db *sql.DB, dest string) error {
	if _, err := os.Lstat(dest); err == nil {
		return fmt.Errorf("store: snapshot target %s already exists", dest)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("store: snapshot target %s: %w", dest, err)
	}
	// The file name is a bound parameter: no quoting problems, no injection.
	if _, err := db.ExecContext(ctx, "VACUUM INTO ?", dest); err != nil {
		_ = os.Remove(dest)
		return fmt.Errorf("store: snapshot: %w", err)
	}
	// SQLite creates the file with the process umask; the snapshot holds the
	// sealed secrets and the audit log.
	if err := os.Chmod(dest, 0o600); err != nil && runtime.GOOS != "windows" {
		return fmt.Errorf("store: snapshot: %w", err)
	}
	return nil
}

// CheckFile opens a database file read-only and without touching it (no
// migrations, no journal files), runs SQLite's quick integrity check and
// returns the schema version (PRAGMA user_version). The backup restore uses
// it to vet a database before it replaces the live one.
func CheckFile(ctx context.Context, path string) (schema int, err error) {
	db, err := openReadOnly(path, true)
	if err != nil {
		return 0, fmt.Errorf("store: check %s: %w", path, err)
	}
	defer db.Close()
	var res string
	if err := db.QueryRowContext(ctx, "PRAGMA quick_check(1)").Scan(&res); err != nil {
		return 0, fmt.Errorf("store: check %s: %w", path, err)
	}
	if res != "ok" {
		return 0, fmt.Errorf("store: check %s: database is damaged (%s)", path, res)
	}
	if err := db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&schema); err != nil {
		return 0, fmt.Errorf("store: check %s: %w", path, err)
	}
	return schema, nil
}

// openReadOnly opens an existing file with mode=ro. immutable additionally
// tells SQLite that nothing else changes the file (a staged copy), so it
// creates no -wal/-shm files.
func openReadOnly(path string, immutable bool) (*sql.DB, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	u := url.URL{Scheme: "file", Path: filepath.ToSlash(abs)}
	if runtime.GOOS == "windows" {
		u.Path = "/" + u.Path
	}
	q := url.Values{}
	q.Set("mode", "ro")
	if immutable {
		q.Set("immutable", "1")
	}
	q.Add("_pragma", "busy_timeout(5000)")
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}
