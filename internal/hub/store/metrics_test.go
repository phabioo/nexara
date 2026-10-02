package store

import (
	"context"
	"errors"
	"math"
	"strings"
	"testing"
	"time"
)

const hostA, hostB = "a1c5e0d2b7f34961", "b3d7f1a4c8e25072"

func fp(v float64) *float64 { return &v }

// testRow builds a bucket with easily recognizable values: cpu avg = n, max = 2n.
func testRow(host string, at time.Time, n int) MetricRow {
	f := float64(n)
	return MetricRow{
		HostID: host, Time: at, Samples: n,
		CPUAvg: f, CPUMax: 2 * f,
		MemUsedAvg: 1000 * f, MemUsedMax: 1500 * f, MemTotal: 8000,
		TempAvg: fp(40 + f), TempMax: fp(50 + f),
		NetRxAvg: 10 * f, NetRxMax: 20 * f, NetTxAvg: 5 * f, NetTxMax: 6 * f,
		Disks: []DiskUsage{{Mount: "/", Used: 100 * uint64(n), Total: 1000}},
	}
}

func near(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

func TestMergeMetrics1m(t *testing.T) {
	ctx := context.Background()
	at := t0.Truncate(time.Minute)

	first := testRow(hostA, at, 10)
	second := testRow(hostA, at, 30)
	second.CPUMax = 7 // lower than the first piece: max stays
	second.MemTotal = 9000
	second.Disks = []DiskUsage{{Mount: "/", Used: 555, Total: 1000}}

	tests := []struct {
		name   string
		a, b   MetricRow
		assert func(t *testing.T, got MetricRow)
	}{
		{"weighted by samples", first, second, func(t *testing.T, g MetricRow) {
			if g.Samples != 40 {
				t.Errorf("samples %d", g.Samples)
			}
			if want := (10.0*10 + 30.0*30) / 40; !near(g.CPUAvg, want) {
				t.Errorf("cpu avg %v, want %v", g.CPUAvg, want)
			}
			if g.CPUMax != 20 {
				t.Errorf("cpu max %v, want 20 (max of 20 and 7)", g.CPUMax)
			}
			if g.MemTotal != 9000 || g.Disks[0].Used != 555 {
				t.Errorf("newer piece must win for total/disks: %+v", g)
			}
			if g.TempAvg == nil || !near(*g.TempAvg, (50.0*10+70.0*30)/40) {
				t.Errorf("temp avg %v", g.TempAvg)
			}
		}},
		{"temperature missing in the second piece", first, func() MetricRow { r := second; r.TempAvg, r.TempMax = nil, nil; return r }(),
			func(t *testing.T, g MetricRow) {
				if g.TempAvg == nil || *g.TempAvg != 50 || *g.TempMax != 60 {
					t.Errorf("temp must stay from the first piece: %v %v", g.TempAvg, g.TempMax)
				}
			}},
		{"temperature missing in the first piece", func() MetricRow { r := first; r.TempAvg, r.TempMax = nil, nil; return r }(), second,
			func(t *testing.T, g MetricRow) {
				if g.TempAvg == nil || *g.TempAvg != 70 || *g.TempMax != 80 {
					t.Errorf("temp must come from the second piece: %v %v", g.TempAvg, g.TempMax)
				}
			}},
		{"no sensor at all", func() MetricRow { r := first; r.TempAvg, r.TempMax = nil, nil; return r }(),
			func() MetricRow { r := second; r.TempAvg, r.TempMax = nil, nil; return r }(),
			func(t *testing.T, g MetricRow) {
				if g.TempAvg != nil || g.TempMax != nil {
					t.Errorf("temp must stay NULL: %v %v", g.TempAvg, g.TempMax)
				}
			}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := openTest(t)
			if err := s.MergeMetrics1m(ctx, []MetricRow{tc.a}); err != nil {
				t.Fatal(err)
			}
			if err := s.MergeMetrics1m(ctx, []MetricRow{tc.b}); err != nil {
				t.Fatal(err)
			}
			rows, err := s.ListMetrics(ctx, Metrics1m, hostA, at.Add(-time.Hour), at.Add(time.Hour))
			if err != nil || len(rows) != 1 {
				t.Fatalf("%v rows=%d", err, len(rows))
			}
			tc.assert(t, rows[0])
		})
	}
}

func TestMetricRowValidation(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	good := testRow(hostA, t0, 1)
	for name, mod := range map[string]func(*MetricRow){
		"no host":    func(r *MetricRow) { r.HostID = "" },
		"no samples": func(r *MetricRow) { r.Samples = 0 },
		"no time":    func(r *MetricRow) { r.Time = time.Time{} },
	} {
		r := good
		mod(&r)
		if err := s.MergeMetrics1m(ctx, []MetricRow{r}); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
	// A rejected row rolls back the whole batch.
	bad := good
	bad.Samples = 0
	if err := s.MergeMetrics1m(ctx, []MetricRow{good, bad}); err == nil {
		t.Fatal("want error")
	}
	if rows, _ := s.ListMetrics(ctx, Metrics1m, hostA, t0.Add(-time.Hour), t0.Add(time.Hour)); len(rows) != 0 {
		t.Errorf("batch must be atomic, found %d rows", len(rows))
	}
	if err := s.ReplaceMetrics(ctx, "metrics_x", nil); err == nil {
		t.Error("unknown table must fail")
	}
}

func TestDisksCapped(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	r := testRow(hostA, t0.Truncate(time.Minute), 1)
	r.Disks = nil
	for i := 0; i < 50; i++ {
		r.Disks = append(r.Disks, DiskUsage{Mount: "/m" + string(rune('A'+i%26)) + string(rune('a'+i/26)), Used: 1, Total: 2})
	}
	if err := s.MergeMetrics1m(ctx, []MetricRow{r}); err != nil {
		t.Fatal(err)
	}
	got, _ := s.LatestMetric(ctx, hostA)
	if len(got.Disks) != maxDisksPerRow {
		t.Errorf("disks %d, want %d", len(got.Disks), maxDisksPerRow)
	}
	if _, err := s.LatestMetric(ctx, "nobody"); !errors.Is(err, ErrNotFound) {
		t.Errorf("want ErrNotFound, got %v", err)
	}
}

func TestReplaceMetricsIsIdempotent(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	hour := t0.Truncate(time.Hour)
	for _, n := range []int{5, 9} {
		if err := s.ReplaceMetrics(ctx, Metrics1h, []MetricRow{testRow(hostA, hour, n)}); err != nil {
			t.Fatal(err)
		}
	}
	rows, _ := s.ListMetrics(ctx, Metrics1h, hostA, hour, hour.Add(time.Hour))
	if len(rows) != 1 || rows[0].Samples != 9 {
		t.Fatalf("replace must overwrite: %+v", rows)
	}
}

func TestQueryMetricBuckets(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	base := time.Date(2026, 9, 30, 10, 0, 0, 0, time.UTC)

	var rows []MetricRow
	// 10:00-10:09 minutes with data except 10:03..10:04 (a gap); cpu = minute number.
	for m := 0; m < 10; m++ {
		if m == 3 || m == 4 {
			continue
		}
		r := testRow(hostA, base.Add(time.Duration(m)*time.Minute), 1)
		r.CPUAvg, r.CPUMax = float64(m), float64(m)+0.5
		if m >= 5 { // no sensor reading from minute 5 on
			r.TempAvg, r.TempMax = nil, nil
		}
		rows = append(rows, r)
	}
	// Another host must never leak in.
	rows = append(rows, testRow(hostB, base, 1))
	if err := s.MergeMetrics1m(ctx, rows); err != nil {
		t.Fatal(err)
	}

	q := MetricQuery{Table: Metrics1m, Host: hostA, From: base, To: base.Add(10 * time.Minute), Step: 5 * time.Minute}
	got, err := s.QueryMetricBuckets(ctx, q, ColCPU)
	if err != nil {
		t.Fatal(err)
	}
	// Bucket 0: minutes 0,1,2 (3,4 missing): avg 1, max 2.5. Bucket 1: minutes 5..9: avg 7, max 9.5.
	if len(got) != 2 || got[0].Index != 0 || !near(got[0].Avg, 1) || got[0].Max != 2.5 ||
		got[1].Index != 1 || !near(got[1].Avg, 7) || got[1].Max != 9.5 {
		t.Fatalf("cpu buckets: %+v", got)
	}

	// Temperature: bucket 1 has only sensorless minutes and is absent, not 0.
	temp, err := s.QueryMetricBuckets(ctx, q, ColTemp)
	if err != nil || len(temp) != 1 || temp[0].Index != 0 {
		t.Fatalf("temp buckets: %+v %v", temp, err)
	}

	// Samples weight the average.
	if err := s.MergeMetrics1m(ctx, []MetricRow{func() MetricRow {
		r := testRow(hostA, base.Add(20*time.Minute), 3)
		r.CPUAvg = 10
		return r
	}(), func() MetricRow {
		r := testRow(hostA, base.Add(21*time.Minute), 1)
		r.CPUAvg = 2
		return r
	}()}); err != nil {
		t.Fatal(err)
	}
	q2 := MetricQuery{Table: Metrics1m, Host: hostA, From: base.Add(20 * time.Minute), To: base.Add(25 * time.Minute), Step: 5 * time.Minute}
	w, _ := s.QueryMetricBuckets(ctx, q2, ColCPU)
	if len(w) != 1 || !near(w[0].Avg, (10*3+2*1)/4.0) {
		t.Fatalf("weighted: %+v", w)
	}

	mem, _ := s.QueryMetricBuckets(ctx, q2, ColMem)
	if len(mem) != 1 || mem[0].Total != 8000 {
		t.Fatalf("mem total: %+v", mem)
	}

	for _, bad := range []MetricQuery{
		{Table: "x", Host: hostA, From: base, To: base.Add(time.Hour), Step: time.Minute},
		{Table: Metrics1m, Host: hostA, From: base, To: base, Step: time.Minute},
		{Table: Metrics1m, Host: hostA, From: base.Add(time.Minute), To: base.Add(time.Hour), Step: 5 * time.Minute},
		{Table: Metrics1m, Host: hostA, From: base, To: base.Add(time.Hour), Step: 0},
	} {
		if _, err := s.QueryMetricBuckets(ctx, bad, ColCPU); err == nil {
			t.Errorf("want an error for %+v", bad)
		}
	}
	if _, err := s.QueryMetricBuckets(ctx, q, "disk; DROP TABLE hosts"); err == nil {
		t.Error("unknown column must fail")
	}
}

func TestHourQueryIncludesUnrolledTail(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	h0 := time.Date(2026, 9, 30, 8, 0, 0, 0, time.UTC)

	hourRow := func(h time.Time, cpu float64) MetricRow {
		r := testRow(hostA, h, 1)
		r.Samples, r.CPUAvg, r.CPUMax = 1800, cpu, cpu
		return r
	}
	minuteRow := func(at time.Time, cpu float64) MetricRow {
		r := testRow(hostA, at, 1)
		r.CPUAvg, r.CPUMax = cpu, cpu
		return r
	}
	// 08:00 rolled (hour row and its minutes), 09:00 not rolled (only minutes).
	if err := s.ReplaceMetrics(ctx, Metrics1h, []MetricRow{hourRow(h0, 10)}); err != nil {
		t.Fatal(err)
	}
	if err := s.MergeMetrics1m(ctx, []MetricRow{
		minuteRow(h0.Add(10*time.Minute), 99), // already counted by its hour row: must be ignored
		minuteRow(h0.Add(time.Hour), 50),
		minuteRow(h0.Add(time.Hour+time.Minute), 70),
	}); err != nil {
		t.Fatal(err)
	}
	q := MetricQuery{Table: Metrics1h, Host: hostA, From: h0, To: h0.Add(2 * time.Hour), Step: time.Hour}

	without, _ := s.QueryMetricBuckets(ctx, q, ColCPU)
	if len(without) != 1 || without[0].Avg != 10 {
		t.Fatalf("without tail: %+v", without)
	}
	q.TailFrom = h0.Add(-time.Hour)
	with, err := s.QueryMetricBuckets(ctx, q, ColCPU)
	if err != nil {
		t.Fatal(err)
	}
	if len(with) != 2 || with[0].Avg != 10 || with[1].Index != 1 || !near(with[1].Avg, 60) {
		t.Fatalf("with tail: %+v", with)
	}
	disks, err := s.QueryDiskRows(ctx, q)
	if err != nil || len(disks) != 3 { // hour 08:00 + two unrolled minutes of 09:00
		t.Fatalf("disk rows %d %v", len(disks), err)
	}
}

func TestUnrolledHoursAndPrune(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	h := time.Date(2026, 9, 30, 8, 0, 0, 0, time.UTC)
	if err := s.MergeMetrics1m(ctx, []MetricRow{
		testRow(hostA, h.Add(5*time.Minute), 1), testRow(hostA, h.Add(6*time.Minute), 1),
		testRow(hostA, h.Add(time.Hour), 1),
		testRow(hostB, h.Add(time.Hour+time.Minute), 1),
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.ReplaceMetrics(ctx, Metrics1h, []MetricRow{testRow(hostA, h.Add(time.Hour), 1)}); err != nil {
		t.Fatal(err)
	}
	got, err := s.UnrolledHours(ctx, h.Add(-time.Hour), h.Add(3*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	want := []HostHour{{hostA, h}, {hostB, h.Add(time.Hour)}}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("unrolled %+v, want %+v", got, want)
	}

	// Zero cutoff leaves a table alone.
	if m, hh, err := s.PruneMetrics(ctx, time.Time{}, time.Time{}); err != nil || m != 0 || hh != 0 {
		t.Fatalf("zero cutoffs: %d %d %v", m, hh, err)
	}
	m, hh, err := s.PruneMetrics(ctx, h.Add(time.Hour), h.Add(2*time.Hour))
	if err != nil || m != 2 || hh != 1 {
		t.Fatalf("prune: minutes=%d hours=%d err=%v", m, hh, err)
	}

	if err := s.DeleteHostMetrics(ctx, hostB); err != nil {
		t.Fatal(err)
	}
	left, _ := s.ListMetrics(ctx, Metrics1m, hostB, h.Add(-time.Hour), h.Add(5*time.Hour))
	other, _ := s.ListMetrics(ctx, Metrics1m, hostA, h.Add(-time.Hour), h.Add(5*time.Hour))
	if len(left) != 0 || len(other) != 1 {
		t.Fatalf("delete host metrics: b=%d a=%d", len(left), len(other))
	}
	if err := s.DeleteHostMetrics(ctx, "unknown"); err != nil {
		t.Errorf("unknown host must not fail: %v", err)
	}
}

// TestQueriesUseThePrimaryKey guards the read path on small hardware: the
// range queries must seek (host_id, ts) and never scan a whole history table.
func TestQueriesUseThePrimaryKey(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	base := time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC)
	for _, tbl := range []MetricsTable{Metrics1m, Metrics1h} {
		q := MetricQuery{Table: tbl, Host: hostA, From: base, To: base.Add(24 * time.Hour), Step: time.Hour, TailFrom: base}
		stmts := []string{q.bucketSQL(metricColumnSQL[ColCPU])}
		stmts = append(stmts, `WITH src(ts, samples, d) AS (`+q.sourceSQL("disks")+`) SELECT ts, samples, d FROM src`)
		for _, stmt := range stmts {
			args := []any{hostA, unix(q.From), unix(q.To), unix(q.TailFrom), int64(3600)}
			if !strings.Contains(stmt, "?5") {
				args = args[:4]
			}
			if tbl == Metrics1m && !strings.Contains(stmt, "?4") && !strings.Contains(stmt, "?5") {
				args = args[:3]
			}
			rows, err := s.db.QueryContext(ctx, "EXPLAIN QUERY PLAN "+stmt, args...)
			if err != nil {
				t.Fatalf("%s: %v", tbl, err)
			}
			for rows.Next() {
				var id, parent, unused int
				var detail string
				if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
					t.Fatal(err)
				}
				if strings.HasPrefix(detail, "SCAN ") && detail != "SCAN src" { // src is the CTE result
					t.Errorf("%s: full table scan: %s", tbl, detail)
				}
			}
			rows.Close()
		}
	}
}
