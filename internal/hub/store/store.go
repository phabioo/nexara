// Package store is the hub's SQLite persistence layer (modernc.org/sqlite, no CGO).
//
// Conventions every caller must know:
//   - All timestamps are stored as INTEGER unix seconds in UTC and returned as
//     time.Time in UTC. Sub-second precision is dropped. The zero time.Time
//     means "unset" and is stored as NULL where the column is nullable.
//   - IDs: users have an auto-increment int64 ID; hosts have an opaque
//     16-character lower-case hex string ID (see NewID). Session and token
//     identifiers are lower-case hex SHA-256 hashes computed by the caller;
//     the store treats them as opaque strings and never sees the secret.
//   - The database has a single connection (single writer). Methods are safe
//     for concurrent use; they serialize on that connection. Do not hold a
//     transaction open across calls into other packages.
//   - Not-found and uniqueness problems are reported with the sentinel errors
//     ErrNotFound and ErrExists (use errors.Is).
//   - The schema version is tracked in PRAGMA user_version. Migrations are
//     embedded files migrations/NNNN_name.sql, applied in order, one
//     transaction each. New tables/columns need a new migration file; never
//     edit an applied one.
package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite" // registers the "sqlite" driver
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// Sentinel errors.
var (
	// ErrNotFound means the requested row does not exist.
	ErrNotFound = errors.New("store: not found")
	// ErrExists means a unique constraint was violated (operator ID, host name, ...).
	ErrExists = errors.New("store: already exists")
	// ErrTokenInvalid means an enrollment token is unknown, expired or already used.
	// The three cases are deliberately indistinguishable.
	ErrTokenInvalid = errors.New("store: enrollment token invalid, expired or used")
	// ErrSchemaTooNew means the database was written by a newer Nexus than this binary.
	ErrSchemaTooNew = errors.New("store: database schema is newer than this binary")
)

// Store is the hub database handle.
type Store struct {
	db  *sql.DB
	now func() time.Time // replaced in tests
}

// Open opens (creating if needed) the SQLite database at path with WAL,
// foreign keys and a busy timeout, then applies all pending migrations.
func Open(path string) (*Store, error) {
	dsn := path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	// Single writer; also keeps the per-connection pragmas effective.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	s := &Store{db: db, now: time.Now}
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	if err := s.migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// SchemaVersion returns the applied schema version (PRAGMA user_version).
func (s *Store) SchemaVersion(ctx context.Context) (int, error) {
	var v int
	if err := s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&v); err != nil {
		return 0, fmt.Errorf("store: read schema version: %w", err)
	}
	return v, nil
}

// LatestSchemaVersion is the schema version this binary expects.
func LatestSchemaVersion() int {
	ms, err := loadMigrations()
	if err != nil || len(ms) == 0 {
		return 0
	}
	return ms[len(ms)-1].version
}

type migration struct {
	version int
	name    string
	sql     string
}

func loadMigrations() ([]migration, error) {
	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		return nil, err
	}
	var ms []migration
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".sql") {
			continue
		}
		prefix, _, ok := strings.Cut(name, "_")
		n, err := strconv.Atoi(prefix)
		if !ok || err != nil || n < 1 {
			return nil, fmt.Errorf("store: migration %q must be named NNNN_name.sql", name)
		}
		b, err := migrationFS.ReadFile("migrations/" + name)
		if err != nil {
			return nil, err
		}
		ms = append(ms, migration{version: n, name: name, sql: string(b)})
	}
	sort.Slice(ms, func(i, j int) bool { return ms[i].version < ms[j].version })
	for i, m := range ms {
		if m.version != i+1 {
			return nil, fmt.Errorf("store: migration numbering has a gap before %s", m.name)
		}
	}
	return ms, nil
}

func (s *Store) migrate(ctx context.Context) error {
	ms, err := loadMigrations()
	if err != nil {
		return err
	}
	cur, err := s.SchemaVersion(ctx)
	if err != nil {
		return err
	}
	if cur > len(ms) {
		return fmt.Errorf("%w (database v%d, binary v%d)", ErrSchemaTooNew, cur, len(ms))
	}
	for _, m := range ms[cur:] {
		if err := s.applyMigration(ctx, m); err != nil {
			return fmt.Errorf("store: apply %s: %w", m.name, err)
		}
	}
	return nil
}

func (s *Store) applyMigration(ctx context.Context, m migration) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, m.sql); err != nil {
		return err
	}
	// PRAGMA does not accept bound parameters; m.version is an int we parsed.
	if _, err := tx.ExecContext(ctx, "PRAGMA user_version = "+strconv.Itoa(m.version)); err != nil {
		return err
	}
	return tx.Commit()
}

// NewID returns a fresh opaque host ID: 16 lower-case hex characters.
func NewID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("store: crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}

// --- helpers ---------------------------------------------------------------

func unix(t time.Time) int64 { return t.UTC().Unix() }

func fromUnix(n int64) time.Time { return time.Unix(n, 0).UTC() }

// nullUnix maps the zero time to NULL.
func nullUnix(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return unix(t)
}

func fromNull(n sql.NullInt64) time.Time {
	if !n.Valid {
		return time.Time{}
	}
	return fromUnix(n.Int64)
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// isUnique reports whether err is a SQLite UNIQUE or PRIMARY KEY violation.
func isUnique(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "UNIQUE constraint failed") || strings.Contains(msg, "PRIMARY KEY")
}

// affected turns "0 rows changed" into ErrNotFound.
func affected(res sql.Result, err error) error {
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}
