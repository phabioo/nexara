package demo

import (
	"context"
	"math"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/phabioo/nexara/internal/hub/history"
	"github.com/phabioo/nexara/internal/hub/store"
)

var historyNow = time.Date(2026, 10, 2, 14, 17, 42, 0, time.UTC)

// backfilled writes the history into a real database (slow under -race: use sparingly).
func backfilled(t *testing.T, now time.Time) (*Hub, *store.Store) {
	t.Helper()
	h, _ := newHub(t, 0.001)
	st, err := store.Open(filepath.Join(t.TempDir(), "nexus.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := h.BackfillHistory(context.Background(), st, now); err != nil {
		t.Fatal(err)
	}
	return h, st
}

// generated returns the rows BackfillHistory would write, per host, without
// touching a database (SQLite is slow under the race detector).
func generated(t *testing.T, now time.Time) (minutes, hours map[string][]store.MetricRow) {
	t.Helper()
	h, _ := newHub(t, 0.001)
	m, hr, err := h.historyRows(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	group := func(rows []store.MetricRow) map[string][]store.MetricRow {
		out := map[string][]store.MetricRow{}
		for _, r := range rows {
			out[r.HostID] = append(out[r.HostID], r)
		}
		return out
	}
	return group(m), group(hr)
}

func TestBackfillHistoryShape(t *testing.T) {
	last := historyNow.Truncate(time.Minute)
	mins, hrs := generated(t, historyNow)

	pi5, pi3, pi4 := mins[string(hostPi5)], mins[string(hostPi3)], mins[string(hostPi4)]
	// 7 days of minutes minus the 25 minute reboot gap; nothing from the running minute on.
	if want := 7*24*60 - 25; len(pi5) != want {
		t.Errorf("pi5 minutes %d, want %d", len(pi5), want)
	}
	if want := 7*24*60 - 8; len(pi3) != want {
		t.Errorf("pi3 minutes %d, want %d", len(pi3), want)
	}
	if got := pi5[len(pi5)-1].Time; !got.Equal(last.Add(-time.Minute)) {
		t.Errorf("pi5 newest minute %v, want %v", got, last.Add(-time.Minute))
	}
	// pi4 is offline: its history ends 52 hours ago.
	if len(pi4) == 0 || !pi4[len(pi4)-1].Time.Before(last.Add(-52*time.Hour)) {
		t.Errorf("pi4 history must end 52 h ago: %d rows", len(pi4))
	}
	if n := len(hrs[string(hostPi5)]); n < 34*24 || n > 35*24 {
		t.Errorf("pi5 hours %d", n)
	}
	if n := len(hrs[string(hostPi4)]); n == 0 || n >= len(hrs[string(hostPi5)]) {
		t.Errorf("pi4 hours %d", n)
	}
	for _, r := range hrs[string(hostPi5)] {
		if !r.Time.Equal(r.Time.Truncate(time.Hour)) || r.Time.Add(time.Hour).After(last) {
			t.Fatalf("hour row %v is not a closed whole hour", r.Time)
		}
	}

	// Plausible values and the gap.
	gapStart := last.Add(-20*time.Hour - 25*time.Minute)
	for _, r := range pi5 {
		if !r.Time.Before(gapStart) && r.Time.Before(gapStart.Add(25*time.Minute)) {
			t.Fatalf("row inside the reboot gap: %v", r.Time)
		}
		if r.CPUAvg < 0 || r.CPUMax > 100 || r.CPUMax < r.CPUAvg || r.TempAvg == nil || *r.TempAvg < 25 || *r.TempAvg > 84 ||
			r.MemUsedAvg <= 0 || r.MemUsedAvg > float64(r.MemTotal) || r.NetRxAvg < 0 || len(r.Disks) != 2 || r.Samples != 30 {
			t.Fatalf("implausible row: %+v", r)
		}
	}
	// Disk usage ends at the profile's value.
	end := pi5[len(pi5)-1].Disks[1]
	if end.Mount != "/mnt/data" || math.Abs(float64(end.Used)-2_900_000_000_000) > 0.001*float64(end.Total) {
		t.Errorf("pi5 /mnt/data now: %+v", end)
	}
	// A daily rhythm: the afternoon is busier than the night on average.
	var day, night, dn, nn float64
	for _, r := range hrs[string(hostPi3)] {
		switch r.Time.Hour() {
		case 15:
			day, dn = day+r.CPUAvg, dn+1
		case 3:
			night, nn = night+r.CPUAvg, nn+1
		}
	}
	if day/dn <= night/nn {
		t.Errorf("no daily rhythm: day %.1f night %.1f", day/dn, night/nn)
	}
}

func TestBackfillHistoryIsDeterministic(t *testing.T) {
	am, ah := generated(t, historyNow)
	bm, bh := generated(t, historyNow.Add(10*time.Second)) // same minute
	if len(am) == 0 || !reflect.DeepEqual(am, bm) || !reflect.DeepEqual(ah, bh) {
		t.Fatal("the generated history differs between runs")
	}
	// A different minute shifts the data (it is not a constant).
	cm, _ := generated(t, historyNow.Add(7*time.Minute))
	if reflect.DeepEqual(am, cm) {
		t.Fatal("history does not depend on the time")
	}
}

func TestBackfillHistoryServesTheHistoryView(t *testing.T) {
	_, st := backfilled(t, historyNow)
	svc := history.New(history.Options{Store: st, Now: func() time.Time { return historyNow }})
	ctx := context.Background()

	for _, r := range history.Ranges {
		for _, m := range []history.Metric{history.MetricCPU, history.MetricMem, history.MetricTemp, history.MetricNetRx, history.MetricNetTx, history.MetricDisk("/mnt/data")} {
			s, err := svc.SeriesRange(ctx, string(hostPi5), m, r)
			if err != nil || !s.HasData() {
				t.Fatalf("%s %s: err=%v data=%v", r.Key, m, err, s.HasData())
			}
		}
	}
	// The 24 h chart of pi5-media shows the reboot gap, the one of pi4 its long outage.
	s, _ := svc.SeriesRange(ctx, string(hostPi5), history.MetricCPU, history.Ranges[0])
	run, longest := 0, 0
	for _, p := range s.Points[:len(s.Points)-3] { // the newest buckets are naturally open
		if p.HasData() {
			run = 0
			continue
		}
		run++
		longest = max(longest, run)
	}
	if longest < 4 {
		t.Errorf("pi5 24 h: reboot gap not visible (longest gap %d points)", longest)
	}
	off, _ := svc.SeriesRange(ctx, string(hostPi4), history.MetricCPU, history.Ranges[0])
	data := 0
	for _, p := range off.Points {
		if p.HasData() {
			data++
		}
	}
	if data != 0 {
		t.Errorf("pi4 has %d points in its last 24 h, it has been offline for 52 h", data)
	}
	if mounts, err := svc.Mounts(ctx, string(hostPi5)); err != nil || len(mounts) != 2 {
		t.Errorf("mounts %v %v", mounts, err)
	}
}

func TestBackfillHistoryStopsWithContext(t *testing.T) {
	h, _ := newHub(t, 0.001)
	st, err := store.Open(filepath.Join(t.TempDir(), "nexus.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := h.BackfillHistory(ctx, st, historyNow); err == nil {
		t.Fatal("want the context error")
	}
}
