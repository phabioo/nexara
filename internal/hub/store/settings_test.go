package store

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestSettings(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)

	if v, ok, err := s.GetSetting(ctx, "history.retention_days"); err != nil || ok || v != "" {
		t.Fatalf("unset key: %q %v %v", v, ok, err)
	}
	if err := s.SetSetting(ctx, "history.retention_days", "90"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetSetting(ctx, "history.retention_days", "180"); err != nil { // overwrite
		t.Fatal(err)
	}
	if v, ok, err := s.GetSetting(ctx, "history.retention_days"); err != nil || !ok || v != "180" {
		t.Fatalf("got %q %v %v", v, ok, err)
	}
	if err := s.SetSetting(ctx, "backup.enabled", "true"); err != nil {
		t.Fatal(err)
	}
	m, err := s.ListSettings(ctx, "history.")
	if err != nil || len(m) != 1 || m["history.retention_days"] != "180" {
		t.Fatalf("list: %v %v", m, err)
	}
	if all, _ := s.ListSettings(ctx, ""); len(all) != 2 {
		t.Fatalf("all: %v", all)
	}
	if keys, _ := s.SettingKeys(ctx, ""); strings.Join(keys, ",") != "backup.enabled,history.retention_days" {
		t.Fatalf("keys: %v", keys)
	}
	if err := s.DeleteSetting(ctx, "history.retention_days"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteSetting(ctx, "history.retention_days"); err != nil {
		t.Fatalf("deleting an unset key must not fail: %v", err)
	}
	if _, ok, _ := s.GetSetting(ctx, "history.retention_days"); ok {
		t.Fatal("still set")
	}
}

func TestSettingsUpdatedAt(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	if err := s.SetSetting(ctx, "update.check", "true"); err != nil {
		t.Fatal(err)
	}
	var ts int64
	if err := s.db.QueryRow("SELECT updated_at FROM settings WHERE key = 'update.check'").Scan(&ts); err != nil || ts != t0.Unix() {
		t.Fatalf("updated_at %d %v", ts, err)
	}
}

func TestSettingKeyValidation(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	for _, key := range []string{"", "x", "nodot", "Upper.case", "a..b", ".a.b", "a.b.", "a.b c", "a.b'--", "history.", strings.Repeat("a", 60) + ".bbbbb"} {
		if err := s.SetSetting(ctx, key, "v"); !errors.Is(err, ErrInvalidSetting) {
			t.Errorf("Set(%q): want ErrInvalidSetting, got %v", key, err)
		}
		if _, _, err := s.GetSetting(ctx, key); !errors.Is(err, ErrInvalidSetting) {
			t.Errorf("Get(%q): want ErrInvalidSetting, got %v", key, err)
		}
		if err := s.DeleteSetting(ctx, key); !errors.Is(err, ErrInvalidSetting) {
			t.Errorf("Delete(%q): want ErrInvalidSetting, got %v", key, err)
		}
	}
	for _, key := range []string{"history.retention_days", "a.b", "security.totp.window", "backup.keep_n"} {
		if err := s.SetSetting(ctx, key, "v"); err != nil {
			t.Errorf("Set(%q): %v", key, err)
		}
	}
	if err := s.SetSetting(ctx, "backup.big", strings.Repeat("x", maxSettingValue+1)); !errors.Is(err, ErrInvalidSetting) {
		t.Errorf("oversized value: %v", err)
	}
}

func TestSettingsTyped(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)

	if n, err := s.GetSettingInt(ctx, "history.retention_days", 365); err != nil || n != 365 {
		t.Fatalf("default: %d %v", n, err)
	}
	if err := s.SetSettingInt(ctx, "history.retention_days", 90); err != nil {
		t.Fatal(err)
	}
	if n, err := s.GetSettingInt(ctx, "history.retention_days", 365); err != nil || n != 90 {
		t.Fatalf("int: %d %v", n, err)
	}
	_ = s.SetSetting(ctx, "history.retention_days", "ninety")
	if n, err := s.GetSettingInt(ctx, "history.retention_days", 365); !errors.Is(err, ErrInvalidSetting) || n != 365 {
		t.Fatalf("garbage int: %d %v", n, err)
	}

	tests := []struct {
		stored  string
		want    bool
		wantErr bool
	}{{"true", true, false}, {"false", false, false}, {"1", true, false}, {"0", false, false}, {" TRUE ", true, false}, {"yes", false, true}}
	for _, tc := range tests {
		_ = s.SetSetting(ctx, "update.check", tc.stored)
		got, err := s.GetSettingBool(ctx, "update.check", false)
		if got != tc.want || (err != nil) != tc.wantErr {
			t.Errorf("bool %q: got %v err %v", tc.stored, got, err)
		}
	}
	if b, err := s.GetSettingBool(ctx, "update.unset", true); err != nil || !b {
		t.Errorf("bool default: %v %v", b, err)
	}
	if err := s.SetSettingBool(ctx, "update.check", true); err != nil {
		t.Fatal(err)
	}
	if v, _, _ := s.GetSetting(ctx, "update.check"); v != "true" {
		t.Errorf("stored %q", v)
	}
}

func TestSettingsKVView(t *testing.T) {
	ctx := context.Background()
	kv := openTest(t).Settings()
	if err := kv.Set(ctx, "backup.enabled", "true"); err != nil {
		t.Fatal(err)
	}
	if v, ok, err := kv.Get(ctx, "backup.enabled"); err != nil || !ok || v != "true" {
		t.Fatalf("%q %v %v", v, ok, err)
	}
	if err := kv.Delete(ctx, "backup.enabled"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := kv.Get(ctx, "backup.enabled"); ok {
		t.Fatal("still set")
	}
	// Compile-time check of the shape other packages declare.
	var _ interface {
		Get(context.Context, string) (string, bool, error)
		Set(context.Context, string, string) error
	} = kv
}
