package store

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Page size limits of QueryAudit.
const (
	defaultAuditPage = 100
	maxAuditPage     = 1000
)

// ErrBadAuditCursor is returned by QueryAudit for a cursor it did not issue.
var ErrBadAuditCursor = errors.New("store: invalid audit cursor")

// AuditFilter selects audit entries. The zero value matches everything. All
// set fields must match (AND); within Actions/ActionPrefixes any match counts.
type AuditFilter struct {
	Host           string   // exact host name
	User           string   // exact operator ID
	Actions        []string // exact action names
	ActionPrefixes []string // action name prefixes, for example "job."
	Result         string   // AuditOK, AuditError or AuditDenied
	Since          time.Time
	Search         string // case-insensitive substring of Detail; LIKE wildcards are literal
	Cursor         string // the next cursor of the previous page
	Limit          int    // page size, default 100, at most 1000
}

// likeEscape makes s a literal inside LIKE ... ESCAPE '\'.
func likeEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

// auditWhere builds the WHERE clause (without the cursor) and its arguments.
func auditWhere(f AuditFilter) (string, []any) {
	var conds []string
	var args []any
	if f.Host != "" {
		conds = append(conds, "host = ?")
		args = append(args, f.Host)
	}
	if f.User != "" {
		conds = append(conds, `"user" = ?`)
		args = append(args, f.User)
	}
	if f.Result != "" {
		conds = append(conds, "result = ?")
		args = append(args, f.Result)
	}
	if !f.Since.IsZero() {
		conds = append(conds, "ts >= ?")
		args = append(args, unix(f.Since))
	}
	if len(f.Actions) > 0 || len(f.ActionPrefixes) > 0 {
		var or []string
		if len(f.Actions) > 0 {
			or = append(or, "action IN ("+strings.TrimSuffix(strings.Repeat("?,", len(f.Actions)), ",")+")")
			for _, a := range f.Actions {
				args = append(args, a)
			}
		}
		for _, p := range f.ActionPrefixes {
			or = append(or, `action LIKE ? ESCAPE '\'`)
			args = append(args, likeEscape(p)+"%")
		}
		conds = append(conds, "("+strings.Join(or, " OR ")+")")
	}
	if f.Search != "" {
		conds = append(conds, `detail LIKE ? ESCAPE '\'`)
		args = append(args, "%"+likeEscape(f.Search)+"%")
	}
	if len(conds) == 0 {
		return "", nil
	}
	return strings.Join(conds, " AND "), args
}

func encodeAuditCursor(ts, id int64) string {
	return strconv.FormatInt(ts, 10) + "." + strconv.FormatInt(id, 10)
}

func decodeAuditCursor(c string) (ts, id int64, err error) {
	a, b, ok := strings.Cut(c, ".")
	if !ok {
		return 0, 0, ErrBadAuditCursor
	}
	if ts, err = strconv.ParseInt(a, 10, 64); err != nil {
		return 0, 0, ErrBadAuditCursor
	}
	if id, err = strconv.ParseInt(b, 10, 64); err != nil {
		return 0, 0, ErrBadAuditCursor
	}
	return ts, id, nil
}

// QueryAudit returns one page of audit entries, newest first (ts, then id),
// and the cursor of the next page ("" on the last page). The cursor is a
// keyset position, so entries inserted meanwhile never shift or repeat a page.
func (s *Store) QueryAudit(ctx context.Context, f AuditFilter) ([]AuditEntry, string, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = defaultAuditPage
	}
	if limit > maxAuditPage {
		limit = maxAuditPage
	}
	where, args := auditWhere(f)
	if f.Cursor != "" {
		ts, id, err := decodeAuditCursor(f.Cursor)
		if err != nil {
			return nil, "", err
		}
		c := "(ts < ? OR (ts = ? AND id < ?))"
		if where != "" {
			where += " AND " + c
		} else {
			where = c
		}
		args = append(args, ts, ts, id)
	}
	q := `SELECT id, ts, "user", host, action, detail, result FROM audit_log`
	if where != "" {
		q += " WHERE " + where
	}
	q += " ORDER BY ts DESC, id DESC LIMIT ?"
	args = append(args, limit+1)

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, "", fmt.Errorf("store: query audit: %w", err)
	}
	defer rows.Close()
	out := make([]AuditEntry, 0, limit)
	for rows.Next() {
		var (
			e  AuditEntry
			ts int64
		)
		if err := rows.Scan(&e.ID, &ts, &e.User, &e.Host, &e.Action, &e.Detail, &e.Result); err != nil {
			return nil, "", fmt.Errorf("store: query audit: %w", err)
		}
		e.Time = fromUnix(ts)
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, "", fmt.Errorf("store: query audit: %w", err)
	}
	next := ""
	if len(out) > limit {
		out = out[:limit]
		last := out[limit-1]
		next = encodeAuditCursor(unix(last.Time), last.ID)
	}
	return out, next, nil
}

// AuditFacets lists the distinct hosts and users that appear in the audit
// log (at most max each, sorted), for the filter drop-downs.
func (s *Store) AuditFacets(ctx context.Context, max int) (hosts, users []string, err error) {
	if max <= 0 {
		max = 200
	}
	get := func(col string) ([]string, error) {
		rows, err := s.db.QueryContext(ctx,
			`SELECT DISTINCT `+col+` FROM audit_log WHERE `+col+` <> '' ORDER BY `+col+` LIMIT ?`, max)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var v string
			if err := rows.Scan(&v); err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, rows.Err()
	}
	if hosts, err = get("host"); err != nil {
		return nil, nil, fmt.Errorf("store: audit facets: %w", err)
	}
	if users, err = get(`"user"`); err != nil {
		return nil, nil, fmt.Errorf("store: audit facets: %w", err)
	}
	return hosts, users, nil
}
