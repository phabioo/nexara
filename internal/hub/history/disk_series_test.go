package history

import (
	"context"
	"fmt"
	"reflect"
	"slices"
	"sort"
	"testing"
	"time"

	"github.com/phabioo/nexara/internal/hub/store"
)

func TestDiskSeriesMatchesSeriesPerMount(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	m := minuteOf(t0).Add(-10 * time.Minute)
	for i := 0; i < 3; i++ {
		r, _ := sampleRow(hostA, sample(m, float64(10*(i+1))))
		r.Time = m.Add(time.Duration(i) * time.Minute)
		r.Disks[1].Used = uint64(500 + 10*i)
		if err := e.st.MergeMetrics1m(ctx, []store.MetricRow{r}); err != nil {
			t.Fatal(err)
		}
	}
	from, to, step := m.Add(-5*time.Minute), m.Add(10*time.Minute), 5*time.Minute

	got, err := e.svc.DiskSeries(ctx, hostA, from, to, step)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Metric != MetricDisk("/") || got[1].Metric != MetricDisk("/mnt/data") {
		t.Fatalf("series: %+v", got)
	}
	for _, s := range got {
		want, err := e.svc.Series(ctx, hostA, s.Metric, from, to, step)
		if err != nil {
			t.Fatal(err)
		}
		if s.Total != want.Total || s.Unit != want.Unit || !s.From.Equal(want.From) || s.Step != want.Step || s.Source != want.Source {
			t.Errorf("%s: header %+v, want %+v", s.Metric, s, want)
		}
		if len(s.Points) != len(want.Points) {
			t.Fatalf("%s: %d points, want %d", s.Metric, len(s.Points), len(want.Points))
		}
		for i := range s.Points {
			a, b := s.Points[i], want.Points[i]
			if a.HasData() != b.HasData() || (a.HasData() && (a.Avg != b.Avg || a.Max != b.Max)) {
				t.Errorf("%s point %d: %+v, want %+v", s.Metric, i, a, b)
			}
		}
	}
	if p := got[1].Points[1]; p.Avg != 510 || got[1].Total != 1000 {
		t.Errorf("/mnt/data bucket: %+v total %v", p, got[1].Total)
	}
	// The mounts do not share their points.
	if &got[0].Points[0] == &got[1].Points[0] {
		t.Error("series share one points slice")
	}
}

func TestDiskSeriesErrorsAndEmpty(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if got, err := e.svc.DiskSeries(ctx, "unknown", t0.Add(-time.Hour), t0, 5*time.Minute); err != nil || len(got) != 0 {
		t.Errorf("unknown host: %v %v", got, err)
	}
	if _, err := e.svc.DiskSeries(ctx, "", t0.Add(-time.Hour), t0, 5*time.Minute); err == nil {
		t.Error("empty host must be rejected")
	}
	if _, err := e.svc.DiskSeries(ctx, hostA, t0, t0.Add(-time.Hour), 5*time.Minute); err == nil {
		t.Error("reversed range must be rejected")
	}
}

func TestLocation(t *testing.T) {
	berlin, err := time.LoadLocation("Europe/Berlin")
	if err != nil {
		t.Skip("no tz database")
	}
	tests := []struct {
		name string
		mod  func(*Options)
		want *time.Location
	}{
		{"default", func(*Options) {}, time.Local},
		{"configured", func(o *Options) { o.Location = berlin }, berlin},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, tc.mod)
			if got := e.svc.Location(); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("Location() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDiskSeriesBoundsMounts(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	m := minuteOf(t0).Add(-60 * time.Minute)
	// Mount churn: every minute brings 30 mounts nobody had before, the newest
	// sample only a few.
	for i := 0; i < 40; i++ {
		r, _ := sampleRow(hostA, sample(m, 10))
		r.Time = m.Add(time.Duration(i) * time.Minute)
		r.Disks = nil
		n := 30
		if i == 39 {
			n = 3
		}
		for j := 0; j < n; j++ {
			r.Disks = append(r.Disks, store.DiskUsage{Mount: fmt.Sprintf("/m%02d-%02d", i, j), Used: 1, Total: 2})
		}
		if err := e.st.MergeMetrics1m(ctx, []store.MetricRow{r}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := e.svc.DiskSeries(ctx, hostA, m.Add(-5*time.Minute), m.Add(50*time.Minute), 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != MaxDiskSeries {
		t.Fatalf("%d series, want %d", len(got), MaxDiskSeries)
	}
	var names []string
	for _, s := range got {
		names = append(names, string(s.Metric))
	}
	if !sort.StringsAreSorted(names) {
		t.Errorf("series not ordered: %v", names)
	}
	for j := 0; j < 3; j++ {
		want := string(MetricDisk(fmt.Sprintf("/m39-%02d", j)))
		if !slices.Contains(names, want) {
			t.Errorf("mount %s of the newest sample missing in %v", want, names)
		}
	}
	// The rest comes from the next newest sample (i = 38), in path order.
	if !slices.Contains(names, string(MetricDisk("/m38-00"))) || slices.Contains(names, string(MetricDisk("/m10-00"))) {
		t.Errorf("fill-up should prefer recent mounts: %v", names)
	}
}

func TestPickMounts(t *testing.T) {
	row := func(mounts ...string) store.DiskRow {
		r := store.DiskRow{}
		for _, m := range mounts {
			r.Disks = append(r.Disks, store.DiskUsage{Mount: m})
		}
		return r
	}
	tests := []struct {
		name  string
		rows  []store.DiskRow
		limit int
		want  []string
	}{
		{"none", nil, 3, nil},
		{"newest first", []store.DiskRow{row("/old"), row("/b", "/a")}, 3, []string{"/a", "/b", "/old"}},
		{"newest alone exceeds the limit", []store.DiskRow{row("/old"), row("/c", "/b", "/a")}, 2, []string{"/a", "/b"}},
		{"invalid names are skipped", []store.DiskRow{row("/ok", "", "/bad\x00")}, 5, []string{"/ok"}},
		{"duplicates once", []store.DiskRow{row("/a"), row("/a", "/b")}, 5, []string{"/a", "/b"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := pickMounts(tc.rows, tc.limit); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("pickMounts = %v, want %v", got, tc.want)
			}
		})
	}
}
