package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// EnrollToken is a row of the enroll_tokens table.
type EnrollToken struct {
	TokenHash string // hex SHA-256 of the one-time code
	CreatedAt time.Time
	ExpiresAt time.Time
	UsedAt    time.Time // zero = unused
	HostID    string    // empty until SetEnrollTokenHost
	// Capabilities chosen by the operator for the new agent; nil = agent defaults.
	Capabilities []string
}

// CreateEnrollToken stores a new one-time token by hash. capabilities are the
// capability names the operator chose for the new agent; nil means agent
// defaults (stored as NULL). ErrExists on collision.
func (s *Store) CreateEnrollToken(ctx context.Context, tokenHash string, expiresAt time.Time, capabilities []string) error {
	if tokenHash == "" || expiresAt.IsZero() {
		return errors.New("store: enroll token needs hash and expiry")
	}
	var caps any
	if capabilities != nil {
		enc, err := encodeCaps(capabilities)
		if err != nil {
			return err
		}
		caps = enc
	}
	_, err := s.db.ExecContext(ctx,
		"INSERT INTO enroll_tokens (token_hash, created_at, expires_at, capabilities) VALUES (?, ?, ?, ?)",
		tokenHash, unix(s.now()), unix(expiresAt), caps)
	if isUnique(err) {
		return ErrExists
	}
	if err != nil {
		return fmt.Errorf("store: create enroll token: %w", err)
	}
	return nil
}

// ConsumeEnrollToken atomically marks the token used if it exists, is unused
// and expires after now, and returns the capabilities chosen for it (nil =
// agent defaults). A single UPDATE guarantees that concurrent callers cannot
// both succeed. Returns ErrTokenInvalid otherwise (unknown, expired and used
// are indistinguishable on purpose).
func (s *Store) ConsumeEnrollToken(ctx context.Context, tokenHash string, now time.Time) ([]string, error) {
	var caps sql.NullString
	err := s.db.QueryRowContext(ctx,
		`UPDATE enroll_tokens SET used_at = ? WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?
		 RETURNING capabilities`,
		unix(now), tokenHash, unix(now)).Scan(&caps)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrTokenInvalid
	}
	if err != nil {
		return nil, fmt.Errorf("store: consume enroll token: %w", err)
	}
	return decodeCaps(caps)
}

func decodeCaps(ns sql.NullString) ([]string, error) {
	if !ns.Valid {
		return nil, nil
	}
	var out []string
	if err := json.Unmarshal([]byte(ns.String), &out); err != nil {
		return nil, fmt.Errorf("store: corrupt capabilities: %w", err)
	}
	if out == nil {
		out = []string{}
	}
	return out, nil
}

// SetEnrollTokenHost links a consumed token to the host created with it.
func (s *Store) SetEnrollTokenHost(ctx context.Context, tokenHash, hostID string) error {
	return affected(s.db.ExecContext(ctx,
		"UPDATE enroll_tokens SET host_id = ? WHERE token_hash = ?", hostID, tokenHash))
}

// GetEnrollToken returns a token row. ErrNotFound if unknown.
func (s *Store) GetEnrollToken(ctx context.Context, tokenHash string) (EnrollToken, error) {
	var (
		t       EnrollToken
		created int64
		expires int64
		used    sql.NullInt64
		host    sql.NullString
		caps    sql.NullString
	)
	err := s.db.QueryRowContext(ctx,
		"SELECT token_hash, created_at, expires_at, used_at, host_id, capabilities FROM enroll_tokens WHERE token_hash = ?", tokenHash).
		Scan(&t.TokenHash, &created, &expires, &used, &host, &caps)
	if errors.Is(err, sql.ErrNoRows) {
		return EnrollToken{}, ErrNotFound
	}
	if err != nil {
		return EnrollToken{}, fmt.Errorf("store: get enroll token: %w", err)
	}
	t.CreatedAt, t.ExpiresAt, t.UsedAt = fromUnix(created), fromUnix(expires), fromNull(used)
	t.HostID = host.String
	if t.Capabilities, err = decodeCaps(caps); err != nil {
		return EnrollToken{}, err
	}
	return t, nil
}

// DeleteExpiredEnrollTokens removes tokens whose expiry has passed (used or
// not) and returns how many were removed.
func (s *Store) DeleteExpiredEnrollTokens(ctx context.Context, now time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, "DELETE FROM enroll_tokens WHERE expires_at <= ?", unix(now))
	if err != nil {
		return 0, fmt.Errorf("store: delete expired enroll tokens: %w", err)
	}
	return res.RowsAffected()
}
