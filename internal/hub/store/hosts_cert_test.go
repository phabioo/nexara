package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestReplaceHostCert(t *testing.T) {
	ctx := context.Background()
	notAfter := time.Date(2027, 9, 30, 12, 0, 0, 0, time.UTC)
	later := notAfter.Add(365 * 24 * time.Hour)

	tests := []struct {
		name    string
		prepare func(*Store, Host)
		oldFP   string
		newFP   string
		wantErr error
		wantFP  string
	}{
		{name: "swaps all three fields", oldFP: "fp-old", newFP: "fp-new", wantFP: "fp-new"},
		{name: "stale old fingerprint (concurrent renewal)", oldFP: "fp-other", newFP: "fp-new", wantErr: ErrNotFound, wantFP: "fp-old"},
		{name: "revoked host", oldFP: "fp-old", newFP: "fp-new", wantErr: ErrNotFound, wantFP: "fp-old",
			prepare: func(s *Store, h Host) {
				if err := s.RevokeHost(ctx, h.ID); err != nil {
					t.Fatal(err)
				}
			}},
		{name: "empty new fingerprint", oldFP: "fp-old", newFP: "", wantErr: errors.New("any"), wantFP: "fp-old"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := openTest(t)
			h, err := s.CreateHost(ctx, Host{Name: "pi4", CertFingerprint: "fp-old", CertSerial: "1", CertNotAfter: notAfter})
			if err != nil {
				t.Fatal(err)
			}
			if tc.prepare != nil {
				tc.prepare(s, h)
			}
			err = s.ReplaceHostCert(ctx, h.ID, tc.oldFP, tc.newFP, "2", later)
			switch {
			case tc.wantErr == nil && err != nil:
				t.Fatalf("ReplaceHostCert: %v", err)
			case tc.wantErr != nil && err == nil:
				t.Fatal("ReplaceHostCert succeeded, want an error")
			case errors.Is(tc.wantErr, ErrNotFound) && !errors.Is(err, ErrNotFound):
				t.Fatalf("error = %v, want ErrNotFound", err)
			}
			got, _ := s.GetHost(ctx, h.ID)
			if got.CertFingerprint != tc.wantFP {
				t.Fatalf("fingerprint = %q, want %q", got.CertFingerprint, tc.wantFP)
			}
			wantSerial, wantAfter := "1", notAfter
			if tc.wantErr == nil {
				wantSerial, wantAfter = "2", later
			}
			if got.CertSerial != wantSerial || !got.CertNotAfter.Equal(wantAfter) {
				t.Fatalf("serial/not_after = %q/%v, want %q/%v (fields must change together)", got.CertSerial, got.CertNotAfter, wantSerial, wantAfter)
			}
		})
	}
}
