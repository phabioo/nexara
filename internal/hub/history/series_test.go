package history

import (
	"context"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/phabioo/nexara/internal/hub/store"
)

// put stores one bucket with cpu = value (avg) and value+1 (max).
func (e *env) put(table store.MetricsTable, host string, at time.Time, value float64, samples int) {
	e.t.Helper()
	r, _ := sampleRow(host, sample(at, 0))
	r.Time, r.Samples = at, samples
	r.CPUAvg, r.CPUMax = value, value+1
	r.MemUsedAvg, r.MemUsedMax = value*1000, value*1000+500
	var err error
	if table == store.Metrics1m {
		err = e.st.MergeMetrics1m(context.Background(), []store.MetricRow{r})
	} else {
		err = e.st.ReplaceMetrics(context.Background(), table, []store.MetricRow{r})
	}
	if err != nil {
		e.t.Fatal(err)
	}
}

func TestSeries24h(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	m0 := minuteOf(t0) // 12:30

	// Minutes 12:00..12:09 have data (value = minute), 12:10..12:19 are a gap, 12:20 has data.
	base := m0.Add(-30 * time.Minute)
	for i := 0; i < 10; i++ {
		e.put(store.Metrics1m, hostA, base.Add(time.Duration(i)*time.Minute), float64(i), 1)
	}
	e.put(store.Metrics1m, hostA, base.Add(20*time.Minute), 100, 1)
	e.put(store.Metrics1m, hostB, base, 999, 1) // another host never leaks in

	s, err := e.svc.SeriesRange(ctx, hostA, MetricCPU, Ranges[0])
	if err != nil {
		t.Fatal(err)
	}
	if s.Source != store.Metrics1m || s.Step != 5*time.Minute || s.Unit != UnitPercent || s.Host != hostA {
		t.Fatalf("meta: %+v", s)
	}
	// 12:30:20 yesterday rounds down to 12:30, now (12:30:20) up to 12:35: 24 h + one bucket.
	if len(s.Points) != 289 || !s.From.Equal(m0.Add(-24*time.Hour)) {
		t.Fatalf("points=%d from=%v", len(s.Points), s.From)
	}
	for i, p := range s.Points {
		if want := s.From.Add(time.Duration(i) * 5 * time.Minute); !p.Time.Equal(want) {
			t.Fatalf("point %d at %v, want %v", i, p.Time, want)
		}
	}
	at := func(tm time.Time) Point { return s.Points[int(tm.Sub(s.From)/(5*time.Minute))] }
	if p := at(base); !p.HasData() || p.Avg != 2 || p.Max != 5 { // minutes 0-4: avg 2, max 4+1
		t.Errorf("bucket 12:00: %+v", p)
	}
	if p := at(base.Add(5 * time.Minute)); p.Avg != 7 || p.Max != 10 {
		t.Errorf("bucket 12:05: %+v", p)
	}
	for _, off := range []time.Duration{10 * time.Minute, 15 * time.Minute} {
		if p := at(base.Add(off)); p.HasData() || !math.IsNaN(p.Avg) || !math.IsNaN(p.Max) {
			t.Errorf("gap at +%v is not NaN: %+v", off, p)
		}
	}
	if p := at(base.Add(20 * time.Minute)); p.Avg != 100 {
		t.Errorf("bucket 12:20: %+v", p)
	}
	if !s.HasData() {
		t.Error("HasData")
	}
	// Nothing at all is not "zero" either.
	empty, err := e.svc.SeriesRange(ctx, "no-such-host", MetricCPU, Ranges[0])
	if err != nil || empty.HasData() {
		t.Fatalf("empty series: %v %+v", err, empty.HasData())
	}
}

func TestSeriesSourceAndStep(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	day := 24 * time.Hour
	tests := []struct {
		name       string
		from       time.Time
		span       time.Duration
		step       time.Duration
		wantSource store.MetricsTable
		wantStep   time.Duration
	}{
		{"24h at 5 min", t0.Add(-day), day, 5 * time.Minute, store.Metrics1m, 5 * time.Minute},
		{"7d at 30 min", t0.Add(-7 * day), 7 * day, 30 * time.Minute, store.Metrics1m, 30 * time.Minute},
		{"30d at 1 h", t0.Add(-30 * day), 30 * day, time.Hour, store.Metrics1h, time.Hour},
		{"30d at 5 min asks too much: hours, 1 h", t0.Add(-30 * day), 30 * day, 5 * time.Minute, store.Metrics1h, time.Hour},
		{"24h at 1 h is answered from hours", t0.Add(-day), day, time.Hour, store.Metrics1h, time.Hour},
		{"24h at 2 h", t0.Add(-day), day, 2 * time.Hour, store.Metrics1h, 2 * time.Hour},
		{"step below a minute is raised", t0.Add(-time.Hour), time.Hour, 10 * time.Second, store.Metrics1m, time.Minute},
		{"old window falls back to hours", t0.Add(-20 * day), 2 * day, 10 * time.Minute, store.Metrics1h, time.Hour},
		{"window just inside minute retention", t0.Add(-7 * day), day, 10 * time.Minute, store.Metrics1m, 10 * time.Minute},
		{"fractional seconds in step are dropped", t0.Add(-day), day, 5*time.Minute + 700*time.Millisecond, store.Metrics1m, 5 * time.Minute},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, err := e.svc.Series(ctx, hostA, MetricCPU, tc.from, tc.from.Add(tc.span), tc.step)
			if err != nil {
				t.Fatal(err)
			}
			if s.Source != tc.wantSource || s.Step != tc.wantStep {
				t.Fatalf("source=%s step=%v, want %s %v", s.Source, s.Step, tc.wantSource, tc.wantStep)
			}
			first, last := s.Points[0].Time, s.Points[len(s.Points)-1].Time.Add(s.Step)
			if first.After(tc.from) || last.Before(tc.from.Add(tc.span)) || tc.from.Sub(first) >= s.Step {
				t.Errorf("points [%v, %v) do not cover [%v, +%v)", first, last, tc.from, tc.span)
			}
			if first.Unix()%int64(s.Step/time.Second) != 0 {
				t.Errorf("first point %v is not step-aligned", first)
			}
		})
	}
}

func TestSeries30dFromHoursWithUnrolledTail(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	h := t0.Truncate(time.Hour) // 12:00, the current hour

	// Three closed hours (09:00, 10:00, 11:00) as hour rows, a gap hour 08:00, and
	// two minutes of the current, not yet rolled-up hour.
	e.put(store.Metrics1h, hostA, h.Add(-3*time.Hour), 10, 1800)
	e.put(store.Metrics1h, hostA, h.Add(-2*time.Hour), 20, 1800)
	e.put(store.Metrics1h, hostA, h.Add(-time.Hour), 30, 1800)
	e.put(store.Metrics1m, hostA, h.Add(5*time.Minute), 50, 1)
	e.put(store.Metrics1m, hostA, h.Add(10*time.Minute), 70, 1)
	// Minutes of an already rolled hour must not be counted twice.
	e.put(store.Metrics1m, hostA, h.Add(-2*time.Hour+time.Minute), 999, 1)

	s, err := e.svc.SeriesRange(ctx, hostA, MetricCPU, Ranges[2])
	if err != nil {
		t.Fatal(err)
	}
	if s.Source != store.Metrics1h || s.Step != time.Hour {
		t.Fatalf("%+v", s)
	}
	byHour := func(tm time.Time) Point { return s.Points[int(tm.Sub(s.From)/time.Hour)] }
	checks := []struct {
		at   time.Time
		want float64 // NaN = gap
	}{
		{h.Add(-4 * time.Hour), math.NaN()},
		{h.Add(-3 * time.Hour), 10},
		{h.Add(-2 * time.Hour), 20},
		{h.Add(-time.Hour), 30},
		{h, 60}, // from the two minutes
	}
	for _, c := range checks {
		p := byHour(c.at)
		if math.IsNaN(c.want) != math.IsNaN(p.Avg) || (!math.IsNaN(c.want) && p.Avg != c.want) {
			t.Errorf("hour %v: avg %v, want %v", c.at, p.Avg, c.want)
		}
	}
	if p := byHour(h); p.Max != 71 {
		t.Errorf("current hour max %v", p.Max)
	}
}

func TestSeriesCoarseStepWeights(t *testing.T) {
	e := newEnv(t)
	h := t0.Truncate(time.Hour).Add(-6 * time.Hour)
	e.put(store.Metrics1h, hostA, h, 10, 3000)
	e.put(store.Metrics1h, hostA, h.Add(time.Hour), 40, 1000)
	s, err := e.svc.Series(context.Background(), hostA, MetricCPU, h, h.Add(2*time.Hour), 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Points) != 1 || math.Abs(s.Points[0].Avg-17.5) > 1e-9 { // (10*3000 + 40*1000) / 4000
		t.Fatalf("%+v", s.Points)
	}
}

func TestSeriesMetrics(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	m := minuteOf(t0).Add(-10 * time.Minute)
	for i := 0; i < 3; i++ {
		r, _ := sampleRow(hostA, sample(m, float64(10*(i+1))))
		r.Time = m.Add(time.Duration(i) * time.Minute)
		if err := e.st.MergeMetrics1m(ctx, []store.MetricRow{r}); err != nil {
			t.Fatal(err)
		}
	}
	// A host without sensor and with different mounts.
	noSensor := sample(m, 5)
	noSensor.TempC = nil
	noSensor.Disks = noSensor.Disks[:1]
	r, _ := sampleRow(hostB, noSensor)
	r.Time = m
	if err := e.st.MergeMetrics1m(ctx, []store.MetricRow{r}); err != nil {
		t.Fatal(err)
	}

	q := func(host string, metric Metric) Series {
		s, err := e.svc.Series(ctx, host, metric, m.Add(-5*time.Minute), m.Add(10*time.Minute), 5*time.Minute)
		if err != nil {
			t.Fatalf("%s: %v", metric, err)
		}
		return s
	}
	// Buckets: [m-5, m) empty, [m, m+5) minutes 0-2, [m+5, ...) empty.
	val := func(s Series) Point { return s.Points[1] }

	if p := val(q(hostA, MetricCPU)); p.Avg != 20 || p.Max != 30 {
		t.Errorf("cpu %+v", p)
	}
	mem := q(hostA, MetricMem)
	if p := val(mem); p.Avg != float64(2<<30) || mem.Total != float64(8<<30) || mem.Unit != UnitBytes {
		t.Errorf("mem %+v total=%v", p, mem.Total)
	}
	if p := val(q(hostA, MetricTemp)); math.Abs(p.Avg-42) > 1e-9 || math.Abs(p.Max-43) > 1e-9 {
		t.Errorf("temp %+v", p)
	}
	if p := val(q(hostA, MetricNetRx)); p.Avg != 2000 || p.Max != 3000 {
		t.Errorf("net rx %+v", p)
	}
	if s := q(hostA, MetricNetTx); val(s).Avg != 200 || s.Unit != UnitBytesPerSecond {
		t.Errorf("net tx %+v", s)
	}
	if s := q(hostB, MetricTemp); s.HasData() {
		t.Errorf("sensorless host must yield only gaps: %+v", s.Points)
	}
	if s := q(hostB, MetricCPU); !s.HasData() {
		t.Error("cpu of the sensorless host")
	}

	disk := q(hostA, MetricDisk("/mnt/data"))
	if p := val(disk); p.Avg != 500 || p.Max != 500 || disk.Total != 1000 || disk.Unit != UnitBytes {
		t.Errorf("disk %+v total=%v", p, disk.Total)
	}
	if s := q(hostA, MetricDisk("/nope")); s.HasData() || s.Total != 0 {
		t.Errorf("unknown mount: %+v", s)
	}
	if s := q(hostB, MetricDisk("/mnt/data")); s.HasData() {
		t.Errorf("mount missing on this host: %+v", s)
	}

	mounts, err := e.svc.Mounts(ctx, hostA)
	if err != nil || len(mounts) != 2 || mounts[0] != "/" || mounts[1] != "/mnt/data" {
		t.Errorf("mounts %v %v", mounts, err)
	}
	if mounts, err := e.svc.Mounts(ctx, "unknown"); err != nil || mounts != nil {
		t.Errorf("unknown host mounts %v %v", mounts, err)
	}
}

func TestSeriesErrors(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	from, to := t0.Add(-time.Hour), t0
	tests := []struct {
		name   string
		host   string
		metric Metric
		from   time.Time
		to     time.Time
		step   time.Duration
		want   error
	}{
		{"unknown metric", hostA, "load", from, to, time.Minute, ErrInvalidQuery},
		{"empty disk mount", hostA, "disk:", from, to, time.Minute, ErrInvalidQuery},
		{"control char in mount", hostA, "disk:/a\nb", from, to, time.Minute, ErrInvalidQuery},
		{"no host", "", MetricCPU, from, to, time.Minute, ErrInvalidQuery},
		{"empty range", hostA, MetricCPU, to, to, time.Minute, ErrInvalidQuery},
		{"reversed range", hostA, MetricCPU, to, from, time.Minute, ErrInvalidQuery},
		{"zero step", hostA, MetricCPU, from, to, 0, ErrInvalidQuery},
		{"ten years at 1 h", hostA, MetricCPU, t0.Add(-3650 * 24 * time.Hour), to, time.Hour, ErrTooManyPoints},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := e.svc.Series(ctx, tc.host, tc.metric, tc.from, tc.to, tc.step)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestParseMetricAndRange(t *testing.T) {
	for _, s := range []string{"cpu", "mem", "temp", "net_rx", "net_tx", "disk:/", "disk:/mnt/data", "disk:C:\\"} {
		if m, err := ParseMetric(s); err != nil || string(m) != s {
			t.Errorf("ParseMetric(%q) = %q, %v", s, m, err)
		}
	}
	for _, s := range []string{"", "CPU", "disk", "disk:", "net", "cpu;drop"} {
		if _, err := ParseMetric(s); !errors.Is(err, ErrInvalidQuery) {
			t.Errorf("ParseMetric(%q): %v", s, err)
		}
	}
	if m, ok := MetricDisk("/mnt/x").Mount(); !ok || m != "/mnt/x" {
		t.Errorf("Mount: %q %v", m, ok)
	}
	if _, ok := MetricCPU.Mount(); ok {
		t.Error("cpu is not a disk")
	}
	for _, r := range Ranges {
		if got, ok := ParseRange(r.Key); !ok || got != r {
			t.Errorf("ParseRange(%q)", r.Key)
		}
	}
	if _, ok := ParseRange("1y"); ok {
		t.Error("unknown range")
	}
}

func TestSeriesStableGridAcrossPolls(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, _ := e.svc.SeriesRange(ctx, hostA, MetricCPU, Ranges[0])
	e.clk.Add(90 * time.Second) // a later poll
	b, _ := e.svc.SeriesRange(ctx, hostA, MetricCPU, Ranges[0])
	shift := b.From.Sub(a.From)
	if shift%(5*time.Minute) != 0 {
		t.Errorf("grids differ by %v", shift)
	}
}
