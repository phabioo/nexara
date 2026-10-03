package store

import (
	"context"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestAppendAuditCleansAndCapsDetail(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"short text unchanged", "session abc, duration 3s", "session abc, duration 3s"},
		{"exactly at the cap", strings.Repeat("a", MaxAuditDetail), strings.Repeat("a", MaxAuditDetail)},
		{"cut at the cap", strings.Repeat("a", 5000), strings.Repeat("a", MaxAuditDetail)},
		{"multi-byte characters count once", strings.Repeat("ä", 600), strings.Repeat("ä", MaxAuditDetail)},
		{"control characters", "line1\nline2\x1b[31m\x00", "line1?line2?[31m?"},
		{"invalid UTF-8", "a\xffb", "a?b"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := openTest(t)
			ctx := context.Background()
			if _, err := s.AppendAudit(ctx, AuditEntry{User: "op", Action: "x", Result: AuditOK, Detail: tc.in}); err != nil {
				t.Fatal(err)
			}
			got, err := s.ListAudit(ctx, 1)
			if err != nil || len(got) != 1 {
				t.Fatalf("%v %v", got, err)
			}
			if got[0].Detail != tc.want {
				t.Errorf("detail = %q, want %q", got[0].Detail, tc.want)
			}
			if !utf8.ValidString(got[0].Detail) {
				t.Error("stored detail is not valid UTF-8")
			}
		})
	}
}
