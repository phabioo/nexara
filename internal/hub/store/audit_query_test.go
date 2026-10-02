package store

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func seedQueryAudit(t *testing.T) *Store {
	t.Helper()
	s := openTest(t)
	ctx := context.Background()
	rows := []AuditEntry{
		{Time: t0.Add(-50 * time.Hour), User: "fabio", Action: "login", Result: AuditOK, Detail: "ip=192.0.2.1"},
		{Time: t0.Add(-30 * time.Hour), User: "fabio", Host: "pi5-media", Action: "job.apt_upgrade", Result: AuditOK, Detail: "100% done"},
		{Time: t0.Add(-20 * time.Hour), User: "mallory", Action: "login", Result: AuditDenied, Detail: "ip=192.0.2.9 reason=bad_password"},
		{Time: t0.Add(-10 * time.Hour), User: "fabio", Host: "pi3-dns", Action: "job.pkg_install", Result: AuditError, Detail: "my_pkg failed"},
		{Time: t0.Add(-1 * time.Hour), User: "fabio", Host: "pi5-media", Action: "shell.open", Result: AuditOK, Detail: "session x"},
	}
	for _, e := range rows {
		if _, err := s.AppendAudit(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func TestQueryAuditFilters(t *testing.T) {
	s := seedQueryAudit(t)
	tests := []struct {
		name string
		f    AuditFilter
		want []string // details, newest first
	}{
		{"all", AuditFilter{}, []string{"session x", "my_pkg failed", "ip=192.0.2.9 reason=bad_password", "100% done", "ip=192.0.2.1"}},
		{"host", AuditFilter{Host: "pi5-media"}, []string{"session x", "100% done"}},
		{"user", AuditFilter{User: "mallory"}, []string{"ip=192.0.2.9 reason=bad_password"}},
		{"result", AuditFilter{Result: AuditError}, []string{"my_pkg failed"}},
		{"since", AuditFilter{Since: t0.Add(-25 * time.Hour)}, []string{"session x", "my_pkg failed", "ip=192.0.2.9 reason=bad_password"}},
		{"exact action", AuditFilter{Actions: []string{"login"}}, []string{"ip=192.0.2.9 reason=bad_password", "ip=192.0.2.1"}},
		{"prefix", AuditFilter{ActionPrefixes: []string{"job."}}, []string{"my_pkg failed", "100% done"}},
		{"exact or prefix", AuditFilter{Actions: []string{"shell.open"}, ActionPrefixes: []string{"job."}}, []string{"session x", "my_pkg failed", "100% done"}},
		{"prefix underscore is literal", AuditFilter{ActionPrefixes: []string{"job_"}}, nil},
		{"search is case-insensitive", AuditFilter{Search: "BAD_PASS"}, []string{"ip=192.0.2.9 reason=bad_password"}},
		{"search percent is literal", AuditFilter{Search: "%"}, []string{"100% done"}},
		{"search underscore is literal", AuditFilter{Search: "y_p"}, []string{"my_pkg failed"}},
		{"search underscore does not match any char", AuditFilter{Search: "m_pkg"}, nil},
		{"search backslash", AuditFilter{Search: `\`}, nil},
		{"combined", AuditFilter{Host: "pi5-media", User: "fabio", Result: AuditOK, Since: t0.Add(-2 * time.Hour), Actions: []string{"shell.open"}, Search: "sess"}, []string{"session x"}},
		{"combined without match", AuditFilter{Host: "pi3-dns", Result: AuditOK}, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, next, err := s.QueryAudit(context.Background(), tc.f)
			if err != nil {
				t.Fatal(err)
			}
			if next != "" {
				t.Errorf("next = %q on a single page", next)
			}
			var details []string
			for _, e := range got {
				details = append(details, e.Detail)
			}
			if fmt.Sprint(details) != fmt.Sprint(tc.want) {
				t.Errorf("got %q, want %q", details, tc.want)
			}
		})
	}
}

func TestQueryAuditPagingStableUnderInserts(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	// Many entries share one second, so the id tie-break matters.
	for i := 0; i < 25; i++ {
		ts := t0.Add(-time.Duration(i/5) * time.Minute)
		if _, err := s.AppendAudit(ctx, AuditEntry{Time: ts, User: "u", Action: "a", Result: AuditOK, Detail: fmt.Sprint(i)}); err != nil {
			t.Fatal(err)
		}
	}
	seen := map[int64]bool{}
	var cursor string
	pages := 0
	for {
		got, next, err := s.QueryAudit(ctx, AuditFilter{Limit: 7, Cursor: cursor})
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range got {
			if seen[e.ID] {
				t.Fatalf("entry %d repeated", e.ID)
			}
			seen[e.ID] = true
		}
		pages++
		if pages == 1 {
			// New entries arrive between the pages; they sort before the cursor and must not shift it.
			for i := 0; i < 4; i++ {
				if _, err := s.AppendAudit(ctx, AuditEntry{Time: t0.Add(time.Hour), User: "u", Action: "a", Result: AuditOK, Detail: "new"}); err != nil {
					t.Fatal(err)
				}
			}
		}
		if next == "" {
			break
		}
		cursor = next
	}
	if len(seen) != 25 || pages != 4 {
		t.Errorf("saw %d entries in %d pages, want 25 in 4", len(seen), pages)
	}
}

func TestQueryAuditPageSizeAndCursor(t *testing.T) {
	s := seedQueryAudit(t)
	ctx := context.Background()
	got, next, err := s.QueryAudit(ctx, AuditFilter{Limit: 5})
	if err != nil || len(got) != 5 || next != "" {
		t.Fatalf("exact page: %d entries, next %q, err %v", len(got), next, err)
	}
	got, next, _ = s.QueryAudit(ctx, AuditFilter{Limit: 2})
	if len(got) != 2 || next == "" {
		t.Fatalf("first page: %d entries, next %q", len(got), next)
	}
	for _, bad := range []string{"x", "1", "a.b", "1.b", "."} {
		if _, _, err := s.QueryAudit(ctx, AuditFilter{Cursor: bad}); !errors.Is(err, ErrBadAuditCursor) {
			t.Errorf("cursor %q: err = %v", bad, err)
		}
	}
}

func TestAuditFacets(t *testing.T) {
	s := seedQueryAudit(t)
	hosts, users, err := s.AuditFacets(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(hosts) != "[pi3-dns pi5-media]" || fmt.Sprint(users) != "[fabio mallory]" {
		t.Errorf("hosts %v users %v", hosts, users)
	}
}

// TestQueryAuditLarge checks that a filtered, paged query on 100k rows stays
// fast with the existing index on ts alone.
func TestQueryAuditLarge(t *testing.T) {
	if testing.Short() {
		t.Skip("large table")
	}
	s := openTest(t)
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO audit_log (ts, "user", host, action, detail, result) VALUES (?, ?, ?, ?, ?, ?)`)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100_000; i++ {
		if _, err := stmt.ExecContext(ctx, unix(t0)-int64(i)*30, "u"+fmt.Sprint(i%3), "host"+fmt.Sprint(i%10), "job.apt_update", "detail "+fmt.Sprint(i), AuditOK); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	for name, f := range map[string]AuditFilter{
		"newest page":  {},
		"host":         {Host: "host3"},
		"rare search":  {Search: "detail 99999"},
		"deep cursor":  {Cursor: encodeAuditCursor(unix(t0)-90_000*30, 10_000)},
		"no match":     {Host: "host3", Result: AuditDenied},
		"action group": {ActionPrefixes: []string{"job."}, Since: t0.Add(-24 * time.Hour)},
	} {
		start := time.Now()
		if _, _, err := s.QueryAudit(ctx, f); err != nil {
			t.Fatal(err)
		}
		d := time.Since(start)
		t.Logf("%-13s %v", name, d)
		if d > 2*time.Second {
			t.Errorf("%s took %v", name, d)
		}
	}
	if _, _, err := s.AuditFacets(ctx, 0); err != nil {
		t.Fatal(err)
	}
}
