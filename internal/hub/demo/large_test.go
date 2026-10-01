package demo

import (
	"testing"

	"github.com/phabioo/nexara/internal/protocol"
)

func TestLargeDataSet(t *testing.T) {
	pkgs := largePackages()
	if len(pkgs) != largePackageTarget {
		t.Fatalf("%d packages, want %d", len(pkgs), largePackageTarget)
	}
	names := map[string]bool{}
	states := map[protocol.PackageState]int{}
	for _, p := range pkgs {
		if names[p.Name] {
			t.Fatalf("duplicate package %q", p.Name)
		}
		names[p.Name] = true
		states[p.State]++
	}
	if states[protocol.PackageUpdate] < 10 || states[protocol.PackageOrphaned] < 5 || states[protocol.PackageInstalled] < 700 {
		t.Errorf("state mix %v", states)
	}

	units := largeUnits()
	var failed, inactive int
	for _, u := range units {
		switch u.ActiveState {
		case "failed":
			failed++
		case "inactive":
			inactive++
		}
	}
	if len(units) != 31 || failed != 1 || inactive < 5 {
		t.Errorf("%d units, %d failed, %d inactive", len(units), failed, inactive)
	}
	if n := len(largeDisks()); n != 5 {
		t.Errorf("%d disks, want 5", n)
	}
}

func TestLargeOption(t *testing.T) {
	tests := []struct {
		name      string
		large     bool
		wantPkgs  int
		wantUnits int
		wantDisks int
	}{
		{"default keeps the design sample", false, 12, 6, 2},
		{"large", true, largePackageTarget, 31, 5},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := New(Options{Large: tc.large})
			defer h.Close()
			snap, ok := h.Snapshot(hostPi5)
			if !ok {
				t.Fatal("pi5-media missing")
			}
			if n := len(snap.Packages.Items); n != tc.wantPkgs {
				t.Errorf("%d packages, want %d", n, tc.wantPkgs)
			}
			if n := len(snap.Services.Units); n != tc.wantUnits {
				t.Errorf("%d units, want %d", n, tc.wantUnits)
			}
			if n := len(snap.Metrics.Disks); n != tc.wantDisks {
				t.Errorf("%d disks, want %d", n, tc.wantDisks)
			}
		})
	}
}
