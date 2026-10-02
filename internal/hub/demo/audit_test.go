package demo

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/phabioo/nexara/internal/hub/store"
)

func TestSeedAudit(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(filepath.Join(t.TempDir(), "nexus.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	if err := SeedAudit(ctx, st, now); err != nil {
		t.Fatal(err)
	}
	all, next, err := st.QueryAudit(ctx, store.AuditFilter{Limit: 1000})
	if err != nil || len(all) != 1000 || next == "" {
		t.Fatalf("got %d entries, next %q, err %v", len(all), next, err)
	}
	if all[0].Time.After(now) {
		t.Errorf("newest entry %v is in the future", all[0].Time)
	}
	denied, _, _ := st.QueryAudit(ctx, store.AuditFilter{Result: store.AuditDenied, Limit: 5})
	errs, _, _ := st.QueryAudit(ctx, store.AuditFilter{Result: store.AuditError, Limit: 5})
	if len(denied) == 0 || len(errs) == 0 {
		t.Errorf("want denied and failed entries, got %d and %d", len(denied), len(errs))
	}
	// A second call leaves the log alone.
	if err := SeedAudit(ctx, st, now); err != nil {
		t.Fatal(err)
	}
	again, _, _ := st.QueryAudit(ctx, store.AuditFilter{Limit: 1000, Cursor: next})
	if len(again) != 1920-1000 {
		t.Errorf("after a second seed %d entries remain beyond the first 1000, want %d", len(again), 1920-1000)
	}
}
