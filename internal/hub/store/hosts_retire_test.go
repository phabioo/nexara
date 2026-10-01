package store

import (
	"context"
	"errors"
	"testing"
)

func TestRetireHost(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	h, err := s.CreateHost(ctx, Host{Name: "pi4", CertFingerprint: "fp-1"})
	if err != nil {
		t.Fatal(err)
	}

	if err := s.RetireHost(ctx, h.ID); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetHostByFingerprint(ctx, "fp-1")
	if err != nil || !got.Revoked || got.ID != h.ID {
		t.Fatalf("after retire: %+v, %v (the old certificate must still map to a revoked row)", got, err)
	}
	if got.Name == "pi4" || got.Name != "pi4~"+h.ID {
		t.Errorf("name = %q", got.Name)
	}
	if _, err := s.CreateHost(ctx, Host{Name: "pi4"}); err != nil {
		t.Errorf("name not free after retire: %v", err)
	}

	// Idempotent: a second retire must not stack suffixes.
	if err := s.RetireHost(ctx, h.ID); err != nil {
		t.Fatal(err)
	}
	if again, _ := s.GetHost(ctx, h.ID); again.Name != got.Name || !again.Revoked {
		t.Errorf("second retire changed the row: %+v", again)
	}
	if err := s.RetireHost(ctx, "0000000000000000"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown id: %v", err)
	}
}
