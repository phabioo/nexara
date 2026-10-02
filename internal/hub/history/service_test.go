package history

import (
	"context"
	"math"
	"testing"
	"time"

	"github.com/phabioo/nexara/internal/hub/grid"
	"github.com/phabioo/nexara/internal/hub/store"
)

func minuteOf(t time.Time) time.Time { return t.Truncate(time.Minute) }

func TestFlushWritesOnlyClosedMinutes(t *testing.T) {
	e := newEnv(t)
	m0 := minuteOf(t0) // 12:30

	// 12:30:20 .. 12:30:58 -> minute 12:30; 12:31:00 and 12:31:10 -> minute 12:31.
	for i, at := range []time.Time{t0, t0.Add(20 * time.Second), t0.Add(38 * time.Second), t0.Add(40 * time.Second), t0.Add(50 * time.Second)} {
		e.svc.Observe(hostA, sample(at, float64(10*(i+1))))
	}

	// Minute 12:30 ends at 12:31:00; with the 5 s grace it closes at 12:31:05.
	e.clk.Set(m0.Add(60*time.Second + 4*time.Second))
	e.flush()
	if got := e.minutes(hostA, m0, m0.Add(time.Hour)); len(got) != 0 {
		t.Fatalf("minute written before its grace ended: %+v", got)
	}

	e.clk.Set(m0.Add(65 * time.Second))
	e.flush()
	got := e.minutes(hostA, m0, m0.Add(time.Hour))
	if len(got) != 1 || !got[0].Time.Equal(m0) {
		t.Fatalf("rows: %+v", got)
	}
	r := got[0]
	if r.Samples != 3 || r.CPUAvg != 20 || r.CPUMax != 30 {
		t.Errorf("12:30 minute: samples=%d avg=%v max=%v", r.Samples, r.CPUAvg, r.CPUMax)
	}
	if r.TempAvg == nil || math.Abs(*r.TempAvg-42) > 1e-9 || len(r.Disks) != 2 || r.MemTotal != 8<<30 {
		t.Errorf("12:30 minute details: %+v", r)
	}

	// The open minute 12:31 is written once it has closed, not before, and
	// nothing is written twice.
	e.clk.Set(m0.Add(2*time.Minute + 6*time.Second))
	e.flush()
	e.flush()
	got = e.minutes(hostA, m0, m0.Add(time.Hour))
	if len(got) != 2 || got[1].Samples != 2 || got[0].Samples != 3 {
		t.Fatalf("after second flush: %+v", got)
	}
}

func TestSampleTimestampHandling(t *testing.T) {
	m0 := minuteOf(t0)
	tests := []struct {
		name string
		at   time.Time
		want time.Time // minute the sample lands in
	}{
		{"own timestamp", t0.Add(-3 * time.Minute), m0.Add(-3 * time.Minute)},
		{"replayed sample, 10 min old", t0.Add(-10 * time.Minute), m0.Add(-10 * time.Minute)},
		{"slightly in the future", t0.Add(90 * time.Second), m0.Add(time.Minute)},
		{"older than the agent buffer", t0.Add(-2 * time.Hour), m0},
		{"far future (agent clock wrong)", t0.Add(24 * time.Hour), m0},
		{"no timestamp", time.Time{}, m0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			e.svc.Observe(hostA, sample(tc.at, 10))
			e.clk.Set(t0.Add(time.Hour))
			e.flush()
			got := e.minutes(hostA, m0.Add(-3*time.Hour), m0.Add(3*time.Hour))
			if len(got) != 1 || !got[0].Time.Equal(tc.want) {
				t.Fatalf("landed in %+v, want %v", got, tc.want)
			}
		})
	}
}

func TestLateSamplesAreMerged(t *testing.T) {
	e := newEnv(t)
	m0 := minuteOf(t0)
	e.svc.Observe(hostA, sample(t0, 10))
	e.clk.Set(m0.Add(2 * time.Minute))
	e.flush()

	// The agent was disconnected and replays a sample of the already flushed minute.
	e.svc.Observe(hostA, sample(t0.Add(10*time.Second), 30))
	e.flush()
	got := e.minutes(hostA, m0, m0.Add(time.Minute))
	if len(got) != 1 || got[0].Samples != 2 || got[0].CPUAvg != 20 || got[0].CPUMax != 30 {
		t.Fatalf("merged minute: %+v", got)
	}
}

func TestNoRowsWithoutSamples(t *testing.T) {
	e := newEnv(t)
	m0 := minuteOf(t0)
	// hostA delivers in minutes 0 and 3; minutes 1 and 2 (agent offline) stay absent.
	e.svc.Observe(hostA, sample(t0, 10))
	e.clk.Add(3 * time.Minute)
	e.svc.Observe(hostA, sample(e.clk.Now(), 10))
	e.clk.Set(m0.Add(10 * time.Minute))
	e.flush()
	got := e.minutes(hostA, m0, m0.Add(10*time.Minute))
	if len(got) != 2 || !got[0].Time.Equal(m0) || !got[1].Time.Equal(m0.Add(3*time.Minute)) {
		t.Fatalf("rows: %+v", got)
	}
	if other := e.minutes(hostB, m0, m0.Add(time.Hour)); len(other) != 0 {
		t.Errorf("a host without samples got rows: %+v", other)
	}
	// Dropped garbage and empty host IDs create nothing either.
	bad := sample(t0, math.NaN())
	e.svc.Observe(hostB, bad)
	e.svc.Observe("", sample(t0, 5))
	e.flush()
	if n := len(e.minutes(hostB, m0, m0.Add(time.Hour))); n != 0 {
		t.Errorf("garbage sample created %d rows", n)
	}
}

func TestHourRollup(t *testing.T) {
	e := newEnv(t)
	h := time.Date(2026, 10, 2, 11, 0, 0, 0, time.UTC)

	// 11:58, 11:59 (2 samples), plus a sensorless host B; the clock is at 11:59:40.
	e.clk.Set(h.Add(59*time.Minute + 40*time.Second))
	e.svc.Observe(hostA, sample(h.Add(58*time.Minute), 10))
	e.svc.Observe(hostA, sample(h.Add(59*time.Minute), 20))
	e.svc.Observe(hostA, sample(h.Add(59*time.Minute+30*time.Second), 40))
	noTemp := sample(h.Add(59*time.Minute), 70)
	noTemp.TempC = nil
	e.svc.Observe(hostB, noTemp)

	// Hour not over yet: minutes of 11:58 are flushed but no hour row exists.
	e.clk.Set(h.Add(59*time.Minute + 59*time.Second))
	e.flush()
	if got := e.hours(hostA, h, h.Add(time.Hour)); len(got) != 0 {
		t.Fatalf("hour rolled before it ended: %+v", got)
	}

	// 12:00:06: the last minute (11:59) has closed -> flush rolls the hour.
	e.clk.Set(h.Add(time.Hour + 6*time.Second))
	e.flush()
	got := e.hours(hostA, h, h.Add(time.Hour))
	if len(got) != 1 || !got[0].Time.Equal(h) {
		t.Fatalf("hour rows: %+v", got)
	}
	r := got[0]
	if r.Samples != 3 || math.Abs(r.CPUAvg-(10+20+40)/3.0) > 1e-9 || r.CPUMax != 40 {
		t.Errorf("hour A: samples=%d avg=%v max=%v", r.Samples, r.CPUAvg, r.CPUMax)
	}
	b := e.hours(hostB, h, h.Add(time.Hour))
	if len(b) != 1 || b[0].TempAvg != nil {
		t.Errorf("hour B must have no temperature: %+v", b)
	}

	// A late replayed sample re-rolls the finished hour.
	e.svc.Observe(hostA, sample(h.Add(58*time.Minute+10*time.Second), 70))
	e.flush()
	r = e.hours(hostA, h, h.Add(time.Hour))[0]
	if r.Samples != 4 || r.CPUMax != 70 || math.Abs(r.CPUAvg-(10+20+40+70)/4.0) > 1e-9 {
		t.Errorf("re-rolled hour: samples=%d avg=%v max=%v", r.Samples, r.CPUAvg, r.CPUMax)
	}
}

func TestSweepRollsMissedHours(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	h := time.Date(2026, 10, 2, 8, 0, 0, 0, time.UTC)
	// Minutes of 08:00 and 09:00 exist, but the hub was down at both hour ends
	// (or the host went offline in the last minutes of the hour).
	var rows []store.MetricRow
	for _, at := range []time.Time{h.Add(5 * time.Minute), h.Add(6 * time.Minute), h.Add(time.Hour + time.Minute)} {
		r, _ := sampleRow(hostA, sample(at, 20))
		r.Time = at
		rows = append(rows, r)
	}
	if err := e.st.MergeMetrics1m(ctx, rows); err != nil {
		t.Fatal(err)
	}
	e.clk.Set(h.Add(4*time.Hour + 10*time.Minute))
	e.svc.maintain(ctx, e.clk.Now())
	got := e.hours(hostA, h, h.Add(3*time.Hour))
	if len(got) != 2 || got[0].Samples != 2 || got[1].Samples != 1 {
		t.Fatalf("swept hours: %+v", got)
	}
}

func TestRetentionPruning(t *testing.T) {
	tests := []struct {
		name        string
		setting     string // "" = unset
		cfgDays     int
		wantHourAge time.Duration // oldest surviving hour must be younger than this
		wantGone    time.Duration // an hour of this age must be pruned
		wantKept    time.Duration
	}{
		{"yaml default 365", "", 365, 0, 366 * 24 * time.Hour, 364 * 24 * time.Hour},
		{"yaml default 90", "", 90, 0, 91 * 24 * time.Hour, 89 * 24 * time.Hour},
		{"setting overrides yaml", "30", 365, 0, 31 * 24 * time.Hour, 29 * 24 * time.Hour},
		{"invalid setting falls back to yaml", "banana", 90, 0, 91 * 24 * time.Hour, 89 * 24 * time.Hour},
		{"out of range setting falls back", "99999", 90, 0, 91 * 24 * time.Hour, 89 * 24 * time.Hour},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, func(o *Options) { o.DefaultRetentionDays = tc.cfgDays })
			ctx := context.Background()
			if tc.setting != "" {
				if err := e.st.SetSetting(ctx, store.SettingHistoryRetentionDays, tc.setting); err != nil {
					t.Fatal(err)
				}
			}
			now := e.clk.Now()
			row := func(age time.Duration) store.MetricRow {
				r, _ := sampleRow(hostA, sample(now, 10))
				r.Time = now.Add(-age).Truncate(time.Hour)
				return r
			}
			rowMin := func(age time.Duration) store.MetricRow {
				r := row(age)
				r.Time = now.Add(-age).Truncate(time.Minute)
				return r
			}
			if err := e.st.ReplaceMetrics(ctx, store.Metrics1h, []store.MetricRow{row(tc.wantGone), row(tc.wantKept)}); err != nil {
				t.Fatal(err)
			}
			// Minutes: 6 days old stays, 8 days old goes, independent of the hour retention.
			if err := e.st.MergeMetrics1m(ctx, []store.MetricRow{rowMin(8 * 24 * time.Hour), rowMin(6 * 24 * time.Hour)}); err != nil {
				t.Fatal(err)
			}
			e.svc.maintain(ctx, now)

			far := now.Add(-2000 * 24 * time.Hour)
			hs := e.hours(hostA, far, now)
			// The kept hour survives; the gone hour is pruned. (Rolling the 6 day old minute
			// adds one more hour row, which is younger than the retention only if it fits.)
			var haveGone, haveKept bool
			for _, r := range hs {
				age := now.Sub(r.Time)
				if age > tc.wantGone-time.Hour {
					haveGone = true
				}
				if age >= tc.wantKept-time.Hour && age <= tc.wantKept+time.Hour {
					haveKept = true
				}
			}
			if haveGone || !haveKept {
				t.Errorf("hours after pruning: gone=%v kept=%v rows=%d", haveGone, haveKept, len(hs))
			}
			ms := e.minutes(hostA, far, now)
			if len(ms) != 1 || now.Sub(ms[0].Time) > 7*24*time.Hour {
				t.Errorf("minutes after pruning: %+v", ms)
			}
		})
	}
}

func TestRetentionSettings(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.DefaultRetentionDays = 180 })
	ctx := context.Background()
	if got := e.svc.RetentionDays(ctx); got != 180 {
		t.Fatalf("default from nexus.yaml: %d", got)
	}
	for _, bad := range []int{0, -1, 3651} {
		if err := e.svc.SetRetentionDays(ctx, bad); err == nil {
			t.Errorf("SetRetentionDays(%d) must fail", bad)
		}
	}
	if err := e.svc.SetRetentionDays(ctx, 90); err != nil {
		t.Fatal(err)
	}
	if got := e.svc.RetentionDays(ctx); got != 90 {
		t.Fatalf("after set: %d", got)
	}
	if got := e.svc.AuditRetentionDays(ctx); got != 365 {
		t.Fatalf("audit default: %d", got)
	}
	if err := e.svc.SetAuditRetentionDays(ctx, 10); err == nil {
		t.Error("audit retention below 30 days must fail")
	}
	if err := e.svc.SetAuditRetentionDays(ctx, 60); err != nil {
		t.Fatal(err)
	}
	if got := e.svc.AuditRetentionDays(ctx); got != 60 {
		t.Fatalf("audit after set: %d", got)
	}
	// Out-of-range options default.
	if got := New(Options{Store: e.st, DefaultRetentionDays: 99999}).defaultDays; got != DefaultRetentionDays {
		t.Errorf("bad option default: %d", got)
	}
}

func TestAuditPruningDaily(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if err := e.svc.SetAuditRetentionDays(ctx, 30); err != nil {
		t.Fatal(err)
	}
	add := func(n int, age time.Duration) {
		for i := 0; i < n; i++ {
			if _, err := e.st.AppendAudit(ctx, store.AuditEntry{Time: e.clk.Now().Add(-age), User: "u", Action: "a", Result: store.AuditOK}); err != nil {
				t.Fatal(err)
			}
		}
	}
	count := func() int {
		l, err := e.st.ListAudit(ctx, 10000)
		if err != nil {
			t.Fatal(err)
		}
		return len(l)
	}
	day := 24 * time.Hour

	// 1500 old entries and 50 recent ones: the old ones beyond the newest 1000 go.
	add(1500, 60*day)
	add(50, time.Hour)
	e.svc.maintain(ctx, e.clk.Now())
	// 1550 total; keep newest 1000 = 50 recent + 950 old; 550 removed + 1 prune record.
	if got := count(); got != 1001 {
		t.Fatalf("after first prune: %d entries, want 1001", got)
	}
	last, _ := e.st.ListAudit(ctx, 1)
	if last[0].Action != AuditActionPrune || last[0].User != "system" || last[0].Detail != "removed 550 entries older than 30 days" {
		t.Fatalf("prune record: %+v", last[0])
	}

	// Within 24 h nothing runs again, even though the entries are still old.
	add(10, 90*day)
	e.clk.Add(23 * time.Hour)
	e.svc.maintain(ctx, e.clk.Now())
	if got := count(); got != 1011 {
		t.Fatalf("pruned again within a day: %d", got)
	}
	e.clk.Add(2 * time.Hour)
	e.svc.maintain(ctx, e.clk.Now())
	if got := count(); got > 1002 { // the 10 old ones are beyond the newest 1000 -> removed, plus a record
		t.Fatalf("not pruned after a day: %d", got)
	}
}

func TestFlushFailureKeepsRowsForRetry(t *testing.T) {
	e := newEnv(t)
	m0 := minuteOf(t0)
	e.svc.Observe(hostA, sample(t0, 10))
	e.clk.Set(m0.Add(2 * time.Minute))

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := e.svc.Flush(cancelled); err == nil {
		t.Fatal("flush with a dead context must fail")
	}
	if got := e.minutes(hostA, m0, m0.Add(time.Hour)); len(got) != 0 {
		t.Fatalf("rows written despite the failure: %+v", got)
	}
	e.flush() // the database is fine again
	if got := e.minutes(hostA, m0, m0.Add(time.Hour)); len(got) != 1 || got[0].Samples != 1 {
		t.Fatalf("retry lost the minute: %+v", got)
	}
	e.flush()
	if got := e.minutes(hostA, m0, m0.Add(time.Hour)); got[0].Samples != 1 {
		t.Fatalf("minute written twice: %+v", got)
	}
}

func TestPendingBacklogIsBounded(t *testing.T) {
	e := newEnv(t)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	base := minuteOf(t0).Add(-10 * time.Minute)
	for i := 0; i < pendingLimit+100; i++ {
		// Distinct hosts so every sample is its own bucket in the same minute.
		e.svc.Observe("host"+time.Duration(i).String(), sample(base, 1))
	}
	e.clk.Set(t0.Add(time.Hour))
	_ = e.svc.Flush(cancelled)
	e.svc.mu.Lock()
	n := len(e.svc.pending)
	e.svc.mu.Unlock()
	if n != pendingLimit {
		t.Fatalf("pending %d, want %d", n, pendingLimit)
	}
}

func TestRunAggregatesAndFlushesOnShutdown(t *testing.T) {
	hub := newFakeHub()
	ticks := make(chan time.Time)
	e := newEnv(t, func(o *Options) { o.Hub, o.Ticks = hub, ticks })
	m0 := minuteOf(t0)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		e.svc.Run(ctx)
		close(done)
	}()

	hub.send(ctx, grid.Event{Kind: grid.EventMetrics, Host: hostA, Payload: sample(t0, 10)})
	hub.send(ctx, grid.Event{Kind: grid.EventMetrics, Host: hostA, Payload: sample(t0.Add(10*time.Second), 30)})
	hub.send(ctx, grid.Event{Kind: grid.EventMetrics, Host: hostB, Payload: sample(t0, 50)})
	// Other events and wrong payloads are ignored.
	hub.send(ctx, grid.Event{Kind: grid.EventHostOnline, Host: hostA, Payload: grid.HostInfo{}})
	hub.send(ctx, grid.Event{Kind: grid.EventMetrics, Host: hostA, Payload: "not metrics"})

	// The minute closes: a tick writes it. (An unbuffered tick is only
	// received after all events above were handled.)
	e.clk.Set(m0.Add(70 * time.Second))
	ticks <- e.clk.Now()
	ticks <- e.clk.Now() // second tick returns only after the first was fully processed
	a := e.minutes(hostA, m0, m0.Add(time.Hour))
	if len(a) != 1 || a[0].Samples != 2 || a[0].CPUAvg != 20 {
		t.Fatalf("host A after tick: %+v", a)
	}
	if b := e.minutes(hostB, m0, m0.Add(time.Hour)); len(b) != 1 {
		t.Fatalf("host B after tick: %+v", b)
	}

	// A sample of the new, still open minute is flushed on shutdown.
	hub.send(ctx, grid.Event{Kind: grid.EventMetrics, Host: hostA, Payload: sample(m0.Add(75*time.Second), 90)})
	ticks <- e.clk.Now()
	if got := e.minutes(hostA, m0.Add(time.Minute), m0.Add(time.Hour)); len(got) != 0 {
		t.Fatalf("open minute written early: %+v", got)
	}
	cancel()
	<-done
	got := e.minutes(hostA, m0.Add(time.Minute), m0.Add(time.Hour))
	if len(got) != 1 || got[0].CPUAvg != 90 {
		t.Fatalf("open minute lost at shutdown: %+v", got)
	}
}

func TestHostRemovedDeletesHistory(t *testing.T) {
	hub := newFakeHub()
	ticks := make(chan time.Time)
	e := newEnv(t, func(o *Options) { o.Hub, o.Ticks = hub, ticks })
	m0 := minuteOf(t0)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		e.svc.Run(ctx)
		close(done)
	}()

	e.svc.Observe(hostA, sample(t0.Add(-5*time.Minute), 10))
	e.svc.Observe(hostB, sample(t0.Add(-5*time.Minute), 10))
	e.clk.Set(m0.Add(2 * time.Minute))
	ticks <- e.clk.Now()
	ticks <- e.clk.Now()
	e.svc.Observe(hostA, sample(t0, 10)) // still open when the host is removed
	hub.send(ctx, grid.Event{Kind: grid.EventHostRemoved, Host: hostA})
	ticks <- e.clk.Now()
	cancel()
	<-done

	far := m0.Add(-time.Hour)
	if got := e.minutes(hostA, far, m0.Add(time.Hour)); len(got) != 0 {
		t.Errorf("removed host keeps history: %+v", got)
	}
	if got := e.minutes(hostB, far, m0.Add(time.Hour)); len(got) != 1 {
		t.Errorf("other host lost its history: %+v", got)
	}
}

func TestRunWithoutHub(t *testing.T) {
	ticks := make(chan time.Time)
	e := newEnv(t, func(o *Options) { o.Ticks = ticks })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		e.svc.Run(ctx)
		close(done)
	}()
	ticks <- t0
	cancel()
	<-done
}

func TestRunDrainsQueuedEventsAtShutdown(t *testing.T) {
	hub := newFakeHub(8)
	e := newEnv(t, func(o *Options) { o.Hub, o.Ticks = hub, make(chan time.Time) })
	for i := 0; i < 3; i++ {
		hub.ch <- grid.Event{Kind: grid.EventMetrics, Host: hostA, Payload: sample(t0, float64(10*(i+1)))}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already over when Run starts: only the drain can pick the events up
	e.svc.Run(ctx)
	got := e.minutes(hostA, minuteOf(t0), minuteOf(t0).Add(time.Minute))
	if len(got) != 1 || got[0].Samples != 3 || got[0].CPUAvg != 20 {
		t.Fatalf("queued events lost at shutdown: %+v", got)
	}
}
