package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Session is a row of the sessions table.
type Session struct {
	IDHash     string // hex SHA-256 of the session ID
	UserID     int64
	CreatedAt  time.Time
	LastSeenAt time.Time // idle timeout is measured from here
	ExpiresAt  time.Time // absolute limit
	Persistent bool      // "keep me signed in"
	IP         string
	UserAgent  string
}

// CreateSession inserts a session. IDHash, UserID and ExpiresAt are required;
// CreatedAt and LastSeenAt default to now. ErrExists if the hash is taken.
func (s *Store) CreateSession(ctx context.Context, sess Session) error {
	if sess.IDHash == "" || sess.UserID == 0 || sess.ExpiresAt.IsZero() {
		return errors.New("store: session needs id hash, user and expiry")
	}
	now := s.now()
	if sess.CreatedAt.IsZero() {
		sess.CreatedAt = now
	}
	if sess.LastSeenAt.IsZero() {
		sess.LastSeenAt = sess.CreatedAt
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO sessions (id_hash, user_id, created_at, last_seen_at, expires_at, persistent, ip, user_agent)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		sess.IDHash, sess.UserID, unix(sess.CreatedAt), unix(sess.LastSeenAt), unix(sess.ExpiresAt),
		boolInt(sess.Persistent), sess.IP, sess.UserAgent)
	if isUnique(err) {
		return ErrExists
	}
	if err != nil {
		return fmt.Errorf("store: create session: %w", err)
	}
	return nil
}

// GetSession returns the session with the given ID hash. ErrNotFound if unknown.
// It does not check expiry; the auth package applies idle and absolute limits.
func (s *Store) GetSession(ctx context.Context, idHash string) (Session, error) {
	var (
		sess                      Session
		created, lastSeen, expiry int64
		persistent                int
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT id_hash, user_id, created_at, last_seen_at, expires_at, persistent, ip, user_agent
		 FROM sessions WHERE id_hash = ?`, idHash).
		Scan(&sess.IDHash, &sess.UserID, &created, &lastSeen, &expiry, &persistent, &sess.IP, &sess.UserAgent)
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, ErrNotFound
	}
	if err != nil {
		return Session{}, fmt.Errorf("store: get session: %w", err)
	}
	sess.CreatedAt, sess.LastSeenAt, sess.ExpiresAt = fromUnix(created), fromUnix(lastSeen), fromUnix(expiry)
	sess.Persistent = persistent != 0
	return sess, nil
}

// TouchSession sets last_seen_at (never moves it backwards). ErrNotFound if unknown.
func (s *Store) TouchSession(ctx context.Context, idHash string, seen time.Time) error {
	return affected(s.db.ExecContext(ctx,
		"UPDATE sessions SET last_seen_at = MAX(last_seen_at, ?) WHERE id_hash = ?", unix(seen), idHash))
}

// DeleteSession removes one session (logout). Deleting an unknown session is not an error.
func (s *Store) DeleteSession(ctx context.Context, idHash string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM sessions WHERE id_hash = ?", idHash)
	return err
}

// DeleteExpiredSessions removes sessions past their absolute expiry or idle
// longer than idle, and returns how many were removed.
func (s *Store) DeleteExpiredSessions(ctx context.Context, now time.Time, idle time.Duration) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		"DELETE FROM sessions WHERE expires_at <= ? OR last_seen_at <= ?",
		unix(now), unix(now.Add(-idle)))
	if err != nil {
		return 0, fmt.Errorf("store: delete expired sessions: %w", err)
	}
	return res.RowsAffected()
}

// DeleteUserSessions removes all sessions of a user (password change, reset,
// "sign out everywhere") and returns how many were removed.
func (s *Store) DeleteUserSessions(ctx context.Context, userID int64) (int64, error) {
	res, err := s.db.ExecContext(ctx, "DELETE FROM sessions WHERE user_id = ?", userID)
	if err != nil {
		return 0, fmt.Errorf("store: delete user sessions: %w", err)
	}
	return res.RowsAffected()
}
