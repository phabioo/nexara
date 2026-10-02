package store

import (
	"context"
	"testing"
	"time"
)

func TestPruneAudit(t *testing.T) {
	ctx := context.Background()
	day := 24 * time.Hour

	// 10 entries, one per day: entry i is i days old at t0.
	seed := func(t *testing.T) *Store {
		s := openTest(t)
		for i := 9; i >= 0; i-- {
			if _, err := s.AppendAudit(ctx, AuditEntry{Time: t0.Add(-time.Duration(i) * day), User: "u", Action: "a", Result: AuditOK}); err != nil {
				t.Fatal(err)
			}
		}
		return s
	}
	tests := []struct {
		name       string
		olderThan  time.Duration // cutoff = t0 - olderThan
		keep       int
		wantLeft   int
		wantPruned int64
	}{
		{"only old entries go", 5 * day, 0, 6, 4}, // ages 6..9 are older than 5 days... ages > 5: 6,7,8,9
		{"keep newest protects old entries", 5 * day, 8, 8, 2},
		{"keep more than exist deletes nothing", 5 * day, 100, 10, 0},
		{"nothing old enough", 30 * day, 0, 10, 0},
		{"everything old, keep 3", 0, 3, 3, 7},
		{"negative keep behaves like zero", 5 * day, -1, 6, 4},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := seed(t)
			n, err := s.PruneAudit(ctx, t0.Add(-tc.olderThan), tc.keep)
			if err != nil || n != tc.wantPruned {
				t.Fatalf("pruned %d, want %d (%v)", n, tc.wantPruned, err)
			}
			left, _ := s.ListAudit(ctx, 100)
			if len(left) != tc.wantLeft {
				t.Fatalf("left %d, want %d", len(left), tc.wantLeft)
			}
			// What remains must be the newest entries.
			for i, e := range left {
				if want := t0.Add(-time.Duration(i) * day); !e.Time.Equal(want) {
					t.Fatalf("entry %d at %v, want %v", i, e.Time, want)
				}
			}
		})
	}
}

func TestPruneAuditSameTimestamp(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	// Many entries in the same second: "newest" is decided by ID.
	for i := 0; i < 5; i++ {
		if _, err := s.AppendAudit(ctx, AuditEntry{Time: t0.Add(-48 * time.Hour), Action: "a", Result: AuditOK}); err != nil {
			t.Fatal(err)
		}
	}
	n, err := s.PruneAudit(ctx, t0, 2)
	if err != nil || n != 3 {
		t.Fatalf("pruned %d %v", n, err)
	}
	left, _ := s.ListAudit(ctx, 10)
	if len(left) != 2 || left[0].ID != 5 || left[1].ID != 4 {
		t.Fatalf("left %+v", left)
	}
}
