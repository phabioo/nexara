package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Settings are key-value state the UI changes at runtime (decision #49);
// nexus.yaml stays startup configuration. Values are plain text in the
// database file: never store secrets, passwords or tokens here.
//
// Key namespace: lower-case dotted names, "<area>.<name>". Areas in use:
//
//	history.*   metrics history      (SettingHistoryRetentionDays)
//	audit.*     audit log            (SettingAuditRetentionDays)
//	backup.*    nightly backups      (owned by the backup package)
//	update.*    self-update, update check (owned by the update package)
//	security.*  security options     (owned by the security settings)
//
// The owner of an area defines its keys as constants next to the code that
// reads them. A key is 3-64 characters: [a-z][a-z0-9_]* segments joined by dots.
const (
	// SettingHistoryRetentionDays is how long hourly history is kept (1-3650).
	// Unset means: the value the setup wizard wrote to nexus.yaml.
	SettingHistoryRetentionDays = "history.retention_days"
	// SettingAuditRetentionDays is how long audit entries are kept (30-3650,
	// default 365). The newest AuditKeepNewest entries are always kept.
	SettingAuditRetentionDays = "audit.retention_days"
)

// ErrInvalidSetting means a settings key or value is not acceptable.
var ErrInvalidSetting = errors.New("store: invalid setting")

const maxSettingValue = 4096

var settingKeyRe = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)

func checkSettingKey(key string) error {
	if len(key) < 3 || len(key) > 64 || !settingKeyRe.MatchString(key) {
		return fmt.Errorf("%w: key %q (want lower-case dotted name like history.retention_days)", ErrInvalidSetting, key)
	}
	return nil
}

// GetSetting returns the value of key; ok is false if the key is unset.
func (s *Store) GetSetting(ctx context.Context, key string) (value string, ok bool, err error) {
	if err := checkSettingKey(key); err != nil {
		return "", false, err
	}
	err = s.db.QueryRowContext(ctx, "SELECT value FROM settings WHERE key = ?", key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("store: get setting %s: %w", key, err)
	}
	return value, true, nil
}

// SetSetting creates or overwrites a setting.
func (s *Store) SetSetting(ctx context.Context, key, value string) error {
	if err := checkSettingKey(key); err != nil {
		return err
	}
	if len(value) > maxSettingValue {
		return fmt.Errorf("%w: value of %s is longer than %d bytes", ErrInvalidSetting, key, maxSettingValue)
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
		key, value, unix(s.now()))
	if err != nil {
		return fmt.Errorf("store: set setting %s: %w", key, err)
	}
	return nil
}

// DeleteSetting removes a setting so the default applies again. Deleting an
// unset key is not an error.
func (s *Store) DeleteSetting(ctx context.Context, key string) error {
	if err := checkSettingKey(key); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, "DELETE FROM settings WHERE key = ?", key); err != nil {
		return fmt.Errorf("store: delete setting %s: %w", key, err)
	}
	return nil
}

// ListSettings returns all settings whose key starts with prefix (e.g.
// "backup."), as key -> value. An empty prefix returns everything.
func (s *Store) ListSettings(ctx context.Context, prefix string) (map[string]string, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT key, value FROM settings ORDER BY key")
	if err != nil {
		return nil, fmt.Errorf("store: list settings: %w", err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, fmt.Errorf("store: list settings: %w", err)
		}
		if strings.HasPrefix(k, prefix) {
			out[k] = v
		}
	}
	return out, rows.Err()
}

// SettingKeys lists the stored keys with the prefix, sorted.
func (s *Store) SettingKeys(ctx context.Context, prefix string) ([]string, error) {
	m, err := s.ListSettings(ctx, prefix)
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys, nil
}

// GetSettingInt returns the integer value of key, or def if the key is unset.
// A stored value that is not an integer is an error (ErrInvalidSetting), so
// callers can fall back deliberately instead of silently using a default.
func (s *Store) GetSettingInt(ctx context.Context, key string, def int) (int, error) {
	v, ok, err := s.GetSetting(ctx, key)
	if err != nil || !ok {
		return def, err
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return def, fmt.Errorf("%w: %s is %q, want an integer", ErrInvalidSetting, key, v)
	}
	return n, nil
}

// SetSettingInt stores an integer.
func (s *Store) SetSettingInt(ctx context.Context, key string, n int) error {
	return s.SetSetting(ctx, key, strconv.Itoa(n))
}

// GetSettingBool returns the boolean value of key ("true"/"false"), or def if unset.
func (s *Store) GetSettingBool(ctx context.Context, key string, def bool) (bool, error) {
	v, ok, err := s.GetSetting(ctx, key)
	if err != nil || !ok {
		return def, err
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "1":
		return true, nil
	case "false", "0":
		return false, nil
	}
	return def, fmt.Errorf("%w: %s is %q, want true or false", ErrInvalidSetting, key, v)
}

// SetSettingBool stores a boolean as "true" or "false".
func (s *Store) SetSettingBool(ctx context.Context, key string, b bool) error {
	return s.SetSetting(ctx, key, strconv.FormatBool(b))
}

// KV is the small key-value view other packages code against
// (Get/Set/Delete without the Setting suffix); see Store.Settings.
type KV struct{ s *Store }

// Settings returns the key-value view of the settings table.
func (s *Store) Settings() KV { return KV{s} }

// Get implements the lookup interface other packages declare.
func (k KV) Get(ctx context.Context, key string) (string, bool, error) {
	return k.s.GetSetting(ctx, key)
}

// Set stores a value.
func (k KV) Set(ctx context.Context, key, value string) error {
	return k.s.SetSetting(ctx, key, value)
}

// Delete removes a value.
func (k KV) Delete(ctx context.Context, key string) error {
	return k.s.DeleteSetting(ctx, key)
}
