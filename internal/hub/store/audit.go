package store

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Audit results.
const (
	AuditOK     = "ok"
	AuditError  = "error"
	AuditDenied = "denied"
)

// AuditEntry is a row of the audit_log table. Never put secrets in Detail.
type AuditEntry struct {
	ID     int64
	Time   time.Time
	User   string // operator ID, or "system" for hub-initiated actions
	Host   string // host name; free text, may be empty for hub-level actions
	Action string // e.g. "login", "job.apt_upgrade", "shell.open"
	Detail string
	Result string // AuditOK, AuditError or AuditDenied
}

// Default and maximum page size of ListAudit.
const (
	defaultAuditLimit = 100
	maxAuditLimit     = 10000
)

// AppendAudit writes one audit entry. Time defaults to now. Returns the row ID.
func (s *Store) AppendAudit(ctx context.Context, e AuditEntry) (int64, error) {
	if e.Action == "" || e.Result == "" {
		return 0, errors.New("store: audit entry needs action and result")
	}
	if e.Time.IsZero() {
		e.Time = s.now()
	}
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO audit_log (ts, "user", host, action, detail, result) VALUES (?, ?, ?, ?, ?, ?)`,
		unix(e.Time), e.User, e.Host, e.Action, e.Detail, e.Result)
	if err != nil {
		return 0, fmt.Errorf("store: append audit: %w", err)
	}
	return res.LastInsertId()
}

// ListAudit returns the latest entries, newest first. limit <= 0 means 100;
// values above 10000 are capped.
func (s *Store) ListAudit(ctx context.Context, limit int) ([]AuditEntry, error) {
	if limit <= 0 {
		limit = defaultAuditLimit
	}
	if limit > maxAuditLimit {
		limit = maxAuditLimit
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, ts, "user", host, action, detail, result FROM audit_log ORDER BY ts DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("store: list audit: %w", err)
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var (
			e  AuditEntry
			ts int64
		)
		if err := rows.Scan(&e.ID, &ts, &e.User, &e.Host, &e.Action, &e.Detail, &e.Result); err != nil {
			return nil, fmt.Errorf("store: list audit: %w", err)
		}
		e.Time = fromUnix(ts)
		out = append(out, e)
	}
	return out, rows.Err()
}

// AuditKeepNewest is the number of newest audit entries PruneAudit never
// deletes, however old they are (a quiet hub keeps its last trace).
const AuditKeepNewest = 1000

// PruneAudit deletes audit entries older than before, except the newest keep
// entries (ordered like ListAudit). It returns the number of deleted rows.
func (s *Store) PruneAudit(ctx context.Context, before time.Time, keep int) (int64, error) {
	if keep < 0 {
		keep = 0
	}
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM audit_log WHERE ts < ?
		 AND id NOT IN (SELECT id FROM audit_log ORDER BY ts DESC, id DESC LIMIT ?)`,
		unix(before), keep)
	if err != nil {
		return 0, fmt.Errorf("store: prune audit: %w", err)
	}
	return res.RowsAffected()
}
