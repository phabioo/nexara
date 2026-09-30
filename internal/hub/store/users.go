package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Roles. v0.1 has a single operator role.
const RoleOperator = "operator"

// User is a row of the users table.
type User struct {
	ID         int64
	OperatorID string // unique, case-insensitive
	PassHash   string // encoded argon2id hash
	// TOTPSecretEnc is the TOTP secret encrypted by the auth package; nil if none.
	TOTPSecretEnc []byte
	TOTPEnabled   bool
	Role          string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

const userCols = "id, operator_id, pass_hash, totp_secret_enc, totp_enabled, role, created_at, updated_at"

func scanUser(row interface{ Scan(...any) error }) (User, error) {
	var (
		u                    User
		totpEnabled          int
		createdAt, updatedAt int64
	)
	err := row.Scan(&u.ID, &u.OperatorID, &u.PassHash, &u.TOTPSecretEnc, &totpEnabled, &u.Role, &createdAt, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, err
	}
	u.TOTPEnabled = totpEnabled != 0
	u.CreatedAt, u.UpdatedAt = fromUnix(createdAt), fromUnix(updatedAt)
	return u, nil
}

// CreateUser inserts a user. OperatorID and PassHash are required; Role
// defaults to RoleOperator. Returns ErrExists if the operator ID is taken.
func (s *Store) CreateUser(ctx context.Context, u User) (User, error) {
	if u.OperatorID == "" || u.PassHash == "" {
		return User{}, errors.New("store: user needs operator id and password hash")
	}
	if u.Role == "" {
		u.Role = RoleOperator
	}
	now := s.now()
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO users (operator_id, pass_hash, totp_secret_enc, totp_enabled, role, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		u.OperatorID, u.PassHash, u.TOTPSecretEnc, boolInt(u.TOTPEnabled), u.Role, unix(now), unix(now))
	if isUnique(err) {
		return User{}, ErrExists
	}
	if err != nil {
		return User{}, fmt.Errorf("store: create user: %w", err)
	}
	if u.ID, err = res.LastInsertId(); err != nil {
		return User{}, err
	}
	u.CreatedAt, u.UpdatedAt = fromUnix(unix(now)), fromUnix(unix(now))
	return u, nil
}

// GetUserByOperatorID looks a user up by operator ID (case-insensitive). ErrNotFound if unknown.
func (s *Store) GetUserByOperatorID(ctx context.Context, operatorID string) (User, error) {
	return scanUser(s.db.QueryRowContext(ctx, "SELECT "+userCols+" FROM users WHERE operator_id = ?", operatorID))
}

// GetUserByID looks a user up by ID. ErrNotFound if unknown.
func (s *Store) GetUserByID(ctx context.Context, id int64) (User, error) {
	return scanUser(s.db.QueryRowContext(ctx, "SELECT "+userCols+" FROM users WHERE id = ?", id))
}

// CountUsers returns the number of users. Zero means the hub is in setup mode.
func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var n int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM users").Scan(&n); err != nil {
		return 0, fmt.Errorf("store: count users: %w", err)
	}
	return n, nil
}

// UpdatePassword replaces the password hash. It does not touch sessions; call
// DeleteUserSessions as well when the change should log the user out.
func (s *Store) UpdatePassword(ctx context.Context, id int64, passHash string) error {
	if passHash == "" {
		return errors.New("store: empty password hash")
	}
	return affected(s.db.ExecContext(ctx,
		"UPDATE users SET pass_hash = ?, updated_at = ? WHERE id = ?", passHash, unix(s.now()), id))
}

// SetTOTP stores the encrypted TOTP secret and whether 2FA is active. Pass
// (nil, false) to remove 2FA.
func (s *Store) SetTOTP(ctx context.Context, id int64, secretEnc []byte, enabled bool) error {
	return affected(s.db.ExecContext(ctx,
		"UPDATE users SET totp_secret_enc = ?, totp_enabled = ?, updated_at = ? WHERE id = ?",
		secretEnc, boolInt(enabled), unix(s.now()), id))
}
