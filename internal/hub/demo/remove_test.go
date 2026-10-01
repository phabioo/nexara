package demo

import (
	"context"
	"errors"
	"testing"

	"github.com/phabioo/nexara/internal/hub/grid"
)

func TestRemoveHost(t *testing.T) {
	tests := []struct {
		name string // host to remove
	}{
		{"pi5-media"}, // online
		{"pi4"},       // offline
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h, _ := newHub(t, 0.001)
			events := sub(t, h)
			info := byName(t, h, tc.name)
			if err := h.RemoveHost(context.Background(), grid.Actor{Operator: "op"}, info.ID); err != nil {
				t.Fatal(err)
			}
			ev, _ := waitFor(t, events, kind(grid.EventHostRemoved))
			if ev.Host != info.ID || ev.Payload.(grid.HostInfo).Name != tc.name {
				t.Fatalf("event %+v", ev)
			}
			if _, ok := h.Host(info.ID); ok {
				t.Error("host still known")
			}
			if _, ok := h.Snapshot(info.ID); ok {
				t.Error("snapshot still available")
			}
			if len(h.Hosts()) != 2 {
				t.Errorf("hosts = %d, want 2", len(h.Hosts()))
			}
			for _, i := range h.Hosts() {
				if i.ID == info.ID {
					t.Error("removed host listed")
				}
			}
			if err := h.RemoveHost(context.Background(), grid.Actor{}, info.ID); !errors.Is(err, grid.ErrHostNotFound) {
				t.Errorf("second removal: %v", err)
			}
		})
	}
	h, _ := newHub(t, 0.001)
	if err := h.RemoveHost(context.Background(), grid.Actor{}, "nope"); !errors.Is(err, grid.ErrHostNotFound) {
		t.Errorf("unknown host: %v", err)
	}
}
