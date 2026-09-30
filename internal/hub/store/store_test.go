package store

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var t0 = time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)

func openTest(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "nexus.db"))
	if err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return t0 }
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func mustUser(t *testing.T, s *Store, id string) User {
	t.Helper()
	u, err := s.CreateUser(context.Background(), User{OperatorID: id, PassHash: "hash"})
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestMigrationsIdempotent(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "nexus.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := s.SchemaVersion(ctx); v != LatestSchemaVersion() || v < 1 {
		t.Fatalf("version %d, want %d", v, LatestSchemaVersion())
	}
	u := mustUser(t, s, "alice")
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	// Reopen: nothing re-applied, data intact.
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if got, err := s.GetUserByID(ctx, u.ID); err != nil || got.OperatorID != "alice" {
		t.Fatalf("data lost: %+v %v", got, err)
	}
	for _, tbl := range []string{"users", "sessions", "hosts", "enroll_tokens", "audit_log"} {
		if _, err := s.db.ExecContext(ctx, "SELECT 1 FROM "+tbl+" LIMIT 1"); err != nil {
			t.Errorf("table %s: %v", tbl, err)
		}
	}
	for _, tbl := range []string{"metrics_1m", "metrics_1h", "alerts"} {
		if _, err := s.db.ExecContext(ctx, "SELECT 1 FROM "+tbl); err == nil {
			t.Errorf("table %s must not exist in v0.1", tbl)
		}
	}
}

func TestPragmas(t *testing.T) {
	s := openTest(t)
	var mode string
	var fk int
	_ = s.db.QueryRow("PRAGMA journal_mode").Scan(&mode)
	_ = s.db.QueryRow("PRAGMA foreign_keys").Scan(&fk)
	if mode != "wal" || fk != 1 {
		t.Fatalf("journal_mode=%s foreign_keys=%d", mode, fk)
	}
}

func TestSchemaTooNew(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nexus.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("PRAGMA user_version = 999"); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	if _, err := Open(path); !errors.Is(err, ErrSchemaTooNew) {
		t.Fatalf("want ErrSchemaTooNew, got %v", err)
	}
}

func TestLoadMigrationsOrdered(t *testing.T) {
	ms, err := loadMigrations()
	if err != nil || len(ms) == 0 || ms[0].version != 1 {
		t.Fatalf("%v %v", ms, err)
	}
}

func TestUsers(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)

	if n, _ := s.CountUsers(ctx); n != 0 {
		t.Fatalf("count %d", n)
	}
	u, err := s.CreateUser(ctx, User{OperatorID: "Alice", PassHash: "h1"})
	if err != nil {
		t.Fatal(err)
	}
	if u.ID == 0 || u.Role != RoleOperator || !u.CreatedAt.Equal(t0) {
		t.Fatalf("created: %+v", u)
	}
	if _, err := s.CreateUser(ctx, User{OperatorID: "alice", PassHash: "x"}); !errors.Is(err, ErrExists) {
		t.Fatalf("case-insensitive duplicate: %v", err)
	}
	if _, err := s.CreateUser(ctx, User{OperatorID: "", PassHash: "x"}); err == nil {
		t.Fatal("empty operator id must fail")
	}
	got, err := s.GetUserByOperatorID(ctx, "ALICE")
	if err != nil || got.ID != u.ID || got.TOTPEnabled || got.TOTPSecretEnc != nil {
		t.Fatalf("by operator: %+v %v", got, err)
	}
	if _, err := s.GetUserByOperatorID(ctx, "bob"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	if _, err := s.GetUserByID(ctx, 999); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}

	s.now = func() time.Time { return t0.Add(time.Hour) }
	if err := s.UpdatePassword(ctx, u.ID, "h2"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetTOTP(ctx, u.ID, []byte{1, 2, 3}, true); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetUserByID(ctx, u.ID)
	if got.PassHash != "h2" || !got.TOTPEnabled || !reflect.DeepEqual(got.TOTPSecretEnc, []byte{1, 2, 3}) ||
		!got.UpdatedAt.Equal(t0.Add(time.Hour)) || !got.CreatedAt.Equal(t0) {
		t.Fatalf("updated: %+v", got)
	}
	if err := s.SetTOTP(ctx, u.ID, nil, false); err != nil {
		t.Fatal(err)
	}
	if got, _ = s.GetUserByID(ctx, u.ID); got.TOTPEnabled || got.TOTPSecretEnc != nil {
		t.Fatalf("totp not cleared: %+v", got)
	}
	if err := s.UpdatePassword(ctx, 999, "h"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	if err := s.UpdatePassword(ctx, u.ID, ""); err == nil {
		t.Fatal("empty hash must fail")
	}
	if n, _ := s.CountUsers(ctx); n != 1 {
		t.Fatalf("count %d", n)
	}
}

func TestSessions(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	u1, u2 := mustUser(t, s, "a"), mustUser(t, s, "b")

	sess := Session{IDHash: "h1", UserID: u1.ID, ExpiresAt: t0.Add(30 * 24 * time.Hour), Persistent: true, IP: "10.0.0.2", UserAgent: "UA"}
	if err := s.CreateSession(ctx, sess); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateSession(ctx, sess); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate: %v", err)
	}
	if err := s.CreateSession(ctx, Session{IDHash: "x", UserID: u1.ID}); err == nil {
		t.Fatal("missing expiry must fail")
	}
	if err := s.CreateSession(ctx, Session{IDHash: "orphan", UserID: 999, ExpiresAt: t0.Add(time.Hour)}); err == nil {
		t.Fatal("foreign key must be enforced")
	}
	got, err := s.GetSession(ctx, "h1")
	if err != nil {
		t.Fatal(err)
	}
	want := sess
	want.CreatedAt, want.LastSeenAt = t0, t0
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
	if _, err := s.GetSession(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}

	// Touch moves forward only.
	if err := s.TouchSession(ctx, "h1", t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	_ = s.TouchSession(ctx, "h1", t0.Add(time.Minute))
	if got, _ = s.GetSession(ctx, "h1"); !got.LastSeenAt.Equal(t0.Add(time.Hour)) {
		t.Fatalf("last seen %v", got.LastSeenAt)
	}
	if err := s.TouchSession(ctx, "nope", t0); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}

	// Expired: absolute expiry and idle timeout.
	_ = s.CreateSession(ctx, Session{IDHash: "abs", UserID: u2.ID, ExpiresAt: t0.Add(time.Minute)})
	_ = s.CreateSession(ctx, Session{IDHash: "idle", UserID: u2.ID, ExpiresAt: t0.Add(24 * time.Hour), LastSeenAt: t0.Add(-13 * time.Hour)})
	_ = s.CreateSession(ctx, Session{IDHash: "fresh", UserID: u2.ID, ExpiresAt: t0.Add(24 * time.Hour), LastSeenAt: t0.Add(-time.Hour)})
	n, err := s.DeleteExpiredSessions(ctx, t0.Add(2*time.Minute), 12*time.Hour)
	if err != nil || n != 2 {
		t.Fatalf("deleted %d, %v (want abs+idle)", n, err)
	}
	for id, exists := range map[string]bool{"abs": false, "idle": false, "fresh": true, "h1": true} {
		if _, err := s.GetSession(ctx, id); (err == nil) != exists {
			t.Errorf("session %s exists=%v want %v", id, err == nil, exists)
		}
	}

	if err := s.DeleteSession(ctx, "h1"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteSession(ctx, "h1"); err != nil {
		t.Fatalf("deleting twice must not fail: %v", err)
	}
	if n, _ := s.DeleteUserSessions(ctx, u2.ID); n != 1 {
		t.Fatalf("user sessions deleted %d", n)
	}
}

func TestSessionsCascadeOnUserDelete(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	u := mustUser(t, s, "a")
	if err := s.CreateSession(ctx, Session{IDHash: "h", UserID: u.ID, ExpiresAt: t0.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, "DELETE FROM users WHERE id = ?", u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSession(ctx, "h"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("session must be cascaded away, got %v", err)
	}
}

func TestHosts(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)

	h, err := s.CreateHost(ctx, Host{Name: "frpi5", DisplayName: "frpi5", Address: "192.168.1.5", OS: "linux", Arch: "arm64",
		Capabilities: []string{"monitoring", "shell"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(h.ID) != 16 || !h.CreatedAt.Equal(t0) {
		t.Fatalf("created: %+v", h)
	}
	if _, err := s.CreateHost(ctx, Host{Name: "frpi5"}); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate name: %v", err)
	}
	if _, err := s.CreateHost(ctx, Host{}); err == nil {
		t.Fatal("empty name must fail")
	}
	got, err := s.GetHost(ctx, h.ID)
	if err != nil || !reflect.DeepEqual(got, h) {
		t.Fatalf("get: %+v %v\nwant %+v", got, err, h)
	}
	if got, err = s.GetHostByName(ctx, "frpi5"); err != nil || got.ID != h.ID {
		t.Fatalf("by name: %+v %v", got, err)
	}
	if _, err := s.GetHost(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	// Zero-value capabilities come back as empty, not an error.
	h2, _ := s.CreateHost(ctx, Host{Name: "pi4"})
	if got, _ = s.GetHost(ctx, h2.ID); len(got.Capabilities) != 0 || !got.LastSeenAt.IsZero() || !got.CertNotAfter.IsZero() {
		t.Fatalf("zero host: %+v", got)
	}

	seen := t0.Add(time.Minute)
	err = s.UpdateHostStatus(ctx, h.ID, HostStatus{Address: "10.0.0.9", OS: "linux", Arch: "arm64", AgentVersion: "0.1.0",
		MAC: "aa:bb:cc:dd:ee:ff", Capabilities: []string{"monitoring", "packages"}, LastSeenAt: seen})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetHostCert(ctx, h.ID, "fp1", "42", t0.Add(365*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.SetHostDisplayName(ctx, h.ID, "Hub Pi"); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetHost(ctx, h.ID)
	if got.Address != "10.0.0.9" || got.AgentVersion != "0.1.0" || got.MAC != "aa:bb:cc:dd:ee:ff" ||
		!reflect.DeepEqual(got.Capabilities, []string{"monitoring", "packages"}) || !got.LastSeenAt.Equal(seen) ||
		got.CertFingerprint != "fp1" || got.CertSerial != "42" || !got.CertNotAfter.Equal(t0.Add(365*24*time.Hour)) ||
		got.DisplayName != "Hub Pi" {
		t.Fatalf("updated: %+v", got)
	}
	if err := s.TouchHost(ctx, h.ID, seen.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if got, _ = s.GetHost(ctx, h.ID); !got.LastSeenAt.Equal(seen.Add(time.Hour)) {
		t.Fatalf("touch: %v", got.LastSeenAt)
	}

	if got, err = s.GetHostByFingerprint(ctx, "fp1"); err != nil || got.ID != h.ID {
		t.Fatalf("by fingerprint: %+v %v", got, err)
	}
	if _, err := s.GetHostByFingerprint(ctx, ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty fingerprint must not match hosts without cert: %v", err)
	}

	if err := s.RevokeHost(ctx, h.ID); err != nil {
		t.Fatal(err)
	}
	if got, _ = s.GetHostByFingerprint(ctx, "fp1"); !got.Revoked {
		t.Fatal("revoked flag not set")
	}
	list, err := s.ListHosts(ctx)
	if err != nil || len(list) != 2 {
		t.Fatalf("list: %+v %v", list, err)
	}
	if err := s.DeleteHost(ctx, h.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteHost(ctx, h.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	for _, err := range []error{
		s.UpdateHostStatus(ctx, "nope", HostStatus{}), s.TouchHost(ctx, "nope", t0), s.RevokeHost(ctx, "nope"),
		s.SetHostCert(ctx, "nope", "", "", time.Time{}), s.SetHostDisplayName(ctx, "nope", "x"),
	} {
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("want ErrNotFound, got %v", err)
		}
	}
}

func TestEnrollTokens(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)

	if err := s.CreateEnrollToken(ctx, "tok", t0.Add(15*time.Minute), []string{"shell", "packages"}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateEnrollToken(ctx, "tok", t0.Add(time.Hour), nil); !errors.Is(err, ErrExists) {
		t.Fatal(err)
	}
	caps, err := s.ConsumeEnrollToken(ctx, "tok", t0.Add(time.Minute))
	if err != nil || !reflect.DeepEqual(caps, []string{"shell", "packages"}) {
		t.Fatalf("consume: %v %v", caps, err)
	}
	if _, err := s.ConsumeEnrollToken(ctx, "tok", t0.Add(2*time.Minute)); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("second consume: %v", err)
	}
	if _, err := s.ConsumeEnrollToken(ctx, "unknown", t0); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("unknown: %v", err)
	}
	_ = s.CreateEnrollToken(ctx, "old", t0.Add(time.Minute), nil)
	if _, err := s.ConsumeEnrollToken(ctx, "old", t0.Add(time.Minute)); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("expired (boundary): %v", err)
	}

	host, _ := s.CreateHost(ctx, Host{Name: "h"})
	if err := s.SetEnrollTokenHost(ctx, "tok", host.ID); err != nil {
		t.Fatal(err)
	}
	tok, err := s.GetEnrollToken(ctx, "tok")
	if err != nil || tok.HostID != host.ID || !tok.UsedAt.Equal(t0.Add(time.Minute)) || !tok.ExpiresAt.Equal(t0.Add(15*time.Minute)) ||
		!reflect.DeepEqual(tok.Capabilities, []string{"shell", "packages"}) {
		t.Fatalf("token: %+v %v", tok, err)
	}
	if _, err := s.GetEnrollToken(ctx, "zzz"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	// Deleting the host keeps the token, host_id becomes NULL.
	if err := s.DeleteHost(ctx, host.ID); err != nil {
		t.Fatal(err)
	}
	if tok, _ = s.GetEnrollToken(ctx, "tok"); tok.HostID != "" {
		t.Fatalf("host_id must be cleared: %+v", tok)
	}

	_ = s.CreateEnrollToken(ctx, "later", t0.Add(24*time.Hour), []string{})
	n, err := s.DeleteExpiredEnrollTokens(ctx, t0.Add(time.Hour))
	if err != nil || n != 2 { // "tok" and "old"
		t.Fatalf("deleted %d, %v", n, err)
	}
	if tok, err := s.GetEnrollToken(ctx, "later"); err != nil || tok.Capabilities == nil || len(tok.Capabilities) != 0 {
		t.Fatalf("unexpired token must survive with empty, non-nil capabilities: %+v %v", tok, err)
	}
}

func TestEnrollTokenNilCapabilitiesMeansDefaults(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	_ = s.CreateEnrollToken(ctx, "d", t0.Add(time.Hour), nil)
	_ = s.CreateEnrollToken(ctx, "e", t0.Add(time.Hour), []string{})
	if tok, _ := s.GetEnrollToken(ctx, "d"); tok.Capabilities != nil {
		t.Fatalf("nil must stay nil: %#v", tok.Capabilities)
	}
	if caps, err := s.ConsumeEnrollToken(ctx, "d", t0); err != nil || caps != nil {
		t.Fatalf("nil caps: %#v %v", caps, err)
	}
	if caps, err := s.ConsumeEnrollToken(ctx, "e", t0); err != nil || caps == nil || len(caps) != 0 {
		t.Fatalf("empty caps must be non-nil: %#v %v", caps, err)
	}
}

func TestEnrollTokenConsumedOnceConcurrently(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	if err := s.CreateEnrollToken(ctx, "race", t0.Add(time.Hour), nil); err != nil {
		t.Fatal(err)
	}
	var wins atomic.Int32
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.ConsumeEnrollToken(ctx, "race", t0); err == nil {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("token consumed %d times, want exactly 1", wins.Load())
	}
}

func TestAudit(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)

	for i, a := range []string{"login", "job.apt_update", "shell.open"} {
		e := AuditEntry{Time: t0.Add(time.Duration(i) * time.Second), User: "alice", Host: "frpi5", Action: a, Detail: "d", Result: AuditOK}
		if _, err := s.AppendAudit(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	id, err := s.AppendAudit(ctx, AuditEntry{Action: "logout", Result: AuditDenied}) // time defaults to now = t0
	if err != nil || id == 0 {
		t.Fatal(id, err)
	}
	if _, err := s.AppendAudit(ctx, AuditEntry{Action: "x"}); err == nil {
		t.Fatal("missing result must fail")
	}
	all, err := s.ListAudit(ctx, 0)
	if err != nil || len(all) != 4 {
		t.Fatalf("list: %+v %v", all, err)
	}
	if all[0].Action != "shell.open" || all[3].Action != "logout" && all[3].Action != "login" {
		t.Fatalf("order (newest first): %+v", all)
	}
	if all[0].User != "alice" || all[0].Host != "frpi5" || all[0].Detail != "d" || !all[0].Time.Equal(t0.Add(2*time.Second)) {
		t.Fatalf("fields: %+v", all[0])
	}
	two, _ := s.ListAudit(ctx, 2)
	if len(two) != 2 || two[0].Action != "shell.open" {
		t.Fatalf("limit: %+v", two)
	}
}
