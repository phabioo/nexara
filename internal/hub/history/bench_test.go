package history

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/phabioo/nexara/internal/hub/store"
)

// seedLarge fills a store like a hub a year after install: up to 5 hosts, a year of
// hourly rows with two mounts each, and 7 days of minute rows.
func seedLarge(tb testing.TB, hostCount int) (*Service, time.Time) {
	tb.Helper()
	st, err := store.Open(filepath.Join(tb.TempDir(), "nexus.db"))
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = st.Close() })
	now := time.Date(2026, 10, 2, 12, 30, 20, 0, time.UTC)
	ctx := context.Background()

	mk := func(host string, at time.Time, n int, samples int) store.MetricRow {
		f := float64(n % 97)
		temp, tmax := 40+f/4, 45+f/4
		return store.MetricRow{
			HostID: host, Time: at, Samples: samples,
			CPUAvg: f, CPUMax: f + 3, MemUsedAvg: 1e9 + f*1e6, MemUsedMax: 1.1e9 + f*1e6, MemTotal: 8 << 30,
			TempAvg: &temp, TempMax: &tmax,
			NetRxAvg: f * 1e3, NetRxMax: f * 2e3, NetTxAvg: f * 1e2, NetTxMax: f * 3e2,
			Disks: []store.DiskUsage{{Mount: "/", Used: uint64(40e9 + f*1e6), Total: 117e9}, {Mount: "/mnt/data", Used: uint64(2.9e12), Total: 4e12}},
		}
	}
	hosts := []string{"h3", "h1", "h2", "h4", "h5"}[:hostCount]
	hourStart := now.Truncate(time.Hour)
	var hours, mins []store.MetricRow
	for hi, h := range hosts {
		for i := 0; i < 365*24; i++ {
			hours = append(hours, mk(h, hourStart.Add(-time.Duration(i+1)*time.Hour), i+hi, 1800))
		}
		for i := 0; i < 7*24*60; i++ {
			mins = append(mins, mk(h, now.Truncate(time.Minute).Add(-time.Duration(i+1)*time.Minute), i+hi, 30))
		}
	}
	if err := st.ReplaceMetrics(ctx, store.Metrics1h, hours); err != nil {
		tb.Fatal(err)
	}
	if err := st.MergeMetrics1m(ctx, mins); err != nil {
		tb.Fatal(err)
	}
	return New(Options{Store: st, Now: func() time.Time { return now }}), now
}

func TestSeriesLargeDataset(t *testing.T) {
	if testing.Short() {
		t.Skip("seeds a year of data")
	}
	svc, now := seedLarge(t, 1)
	ctx := context.Background()

	start := time.Now()
	for _, r := range Ranges {
		s, err := svc.SeriesRange(ctx, "h3", MetricCPU, r)
		if err != nil {
			t.Fatal(err)
		}
		gaps := 0
		for _, p := range s.Points {
			if !p.HasData() {
				gaps++
			}
		}
		// Only the not yet existing newest bucket and the leading edge may be empty.
		if gaps > 2 {
			t.Errorf("%s: %d empty points of %d", r.Key, gaps, len(s.Points))
		}
	}
	year, err := svc.Series(ctx, "h3", MetricDisk("/mnt/data"), now.Add(-365*24*time.Hour), now, time.Hour)
	if err != nil || len(year.Points) != 365*24+1 || year.Total != 4e12 {
		t.Fatalf("year of disk usage: %v points=%d total=%v", err, len(year.Points), year.Total)
	}
	t.Logf("three standard ranges and a year of disk usage: %v", time.Since(start))
}

func BenchmarkSeries(b *testing.B) {
	svc, now := seedLarge(b, 5)
	ctx := context.Background()
	cases := []struct {
		name   string
		metric Metric
		span   time.Duration
		step   time.Duration
	}{
		{"cpu_24h_5m", MetricCPU, 24 * time.Hour, 5 * time.Minute},
		{"cpu_7d_30m", MetricCPU, 7 * 24 * time.Hour, 30 * time.Minute},
		{"cpu_30d_1h", MetricCPU, 30 * 24 * time.Hour, time.Hour},
		{"cpu_365d_1h", MetricCPU, 365 * 24 * time.Hour, time.Hour},
		{"temp_365d_6h", MetricTemp, 365 * 24 * time.Hour, 6 * time.Hour},
		{"disk_7d_30m", MetricDisk("/mnt/data"), 7 * 24 * time.Hour, 30 * time.Minute},
		{"disk_365d_1h", MetricDisk("/mnt/data"), 365 * 24 * time.Hour, time.Hour},
	}
	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := svc.Series(ctx, "h3", c.metric, now.Add(-c.span), now, c.step); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
