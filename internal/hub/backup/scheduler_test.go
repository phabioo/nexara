package backup

import (
	"context"
	"testing"
	"time"
)

func mustLoc(t *testing.T, name string) *time.Location {
	t.Helper()
	l, err := time.LoadLocation(name)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestNextAndPrevRun(t *testing.T) {
	berlin := mustLoc(t, "Europe/Berlin")
	utc := time.UTC
	at := func(loc *time.Location, y int, mo time.Month, d, h, m int) time.Time {
		return time.Date(y, mo, d, h, m, 0, 0, loc)
	}
	tests := []struct {
		name       string
		now        time.Time
		hhmm       string
		loc        *time.Location
		next, prev time.Time
	}{
		{"before the time today", at(utc, 2026, 10, 2, 1, 0), "03:00", utc, at(utc, 2026, 10, 2, 3, 0), at(utc, 2026, 10, 1, 3, 0)},
		{"exactly at the time", at(utc, 2026, 10, 2, 3, 0), "03:00", utc, at(utc, 2026, 10, 3, 3, 0), at(utc, 2026, 10, 2, 3, 0)},
		{"after the time", at(utc, 2026, 10, 2, 3, 0).Add(time.Second), "03:00", utc, at(utc, 2026, 10, 3, 3, 0), at(utc, 2026, 10, 2, 3, 0)},
		{"end of month", at(utc, 2026, 10, 31, 23, 59), "03:00", utc, at(utc, 2026, 11, 1, 3, 0), at(utc, 2026, 10, 31, 3, 0)},
		{"hub time zone, not UTC", at(utc, 2026, 10, 2, 0, 30), "03:00", berlin, at(berlin, 2026, 10, 2, 3, 0), at(berlin, 2026, 10, 1, 3, 0)},
		{"hub zone date differs from UTC date", at(utc, 2026, 10, 1, 23, 30), "03:00", berlin, at(berlin, 2026, 10, 2, 3, 0), at(berlin, 2026, 10, 1, 3, 0)},
		{"day DST ends (25 hours)", at(berlin, 2026, 10, 25, 4, 0), "03:00", berlin, at(berlin, 2026, 10, 26, 3, 0), at(berlin, 2026, 10, 25, 3, 0)},
		{"custom time", at(utc, 2026, 10, 2, 12, 0), "23:45", utc, at(utc, 2026, 10, 2, 23, 45), at(utc, 2026, 10, 1, 23, 45)},
		{"invalid time falls back to 03:00", at(utc, 2026, 10, 2, 1, 0), "oops", utc, at(utc, 2026, 10, 2, 3, 0), at(utc, 2026, 10, 1, 3, 0)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := NextRun(tc.now, tc.hhmm, tc.loc); !got.Equal(tc.next) {
				t.Errorf("NextRun = %v, want %v", got, tc.next)
			}
			if got := PrevRun(tc.now, tc.hhmm, tc.loc); !got.Equal(tc.prev) {
				t.Errorf("PrevRun = %v, want %v", got, tc.prev)
			}
		})
	}
	// The wall-clock time stays 03:00 across the DST change.
	next := NextRun(at(berlin, 2026, 10, 23, 12, 0), "03:00", berlin)
	next2 := NextRun(next, "03:00", berlin)
	if next.Hour() != 3 || next2.Hour() != 3 || next2.Sub(next) != 25*time.Hour {
		t.Errorf("DST: %v then %v", next, next2)
	}
}

// schedHarness runs a Scheduler on the fake clock: Sleep advances the clock
// and stops the run after maxSleeps calls.
type schedHarness struct {
	h      *testHub
	sched  *Scheduler
	sleeps []time.Duration
	// onSleep, if set, runs before the clock advances (settings changes).
	onSleep func(n int)
	max     int
	cancel  context.CancelFunc
}

func newSched(t *testing.T, h *testHub, loc *time.Location, maxSleeps int) *schedHarness {
	s := &schedHarness{h: h, max: maxSleeps}
	s.sched = NewScheduler(SchedulerOptions{
		Service: h.svc, Location: loc, Now: h.clock.Now,
		Sleep: func(ctx context.Context, d time.Duration) error {
			s.sleeps = append(s.sleeps, d)
			if len(s.sleeps) > s.max {
				s.cancel()
				return ctx.Err()
			}
			if s.onSleep != nil {
				s.onSleep(len(s.sleeps))
			}
			h.clock.Add(d)
			return ctx.Err()
		},
	})
	return s
}

func (s *schedHarness) run() {
	ctx, cancel := context.WithCancel(bg)
	s.cancel = cancel
	defer cancel()
	s.sched.Run(ctx)
}

func TestSchedulerRunsAtLocalTime(t *testing.T) {
	h := newHub(t)
	berlin := mustLoc(t, "Europe/Berlin")
	// 14:00 local (CEST). No backup exists yet: the start-up check makes one.
	h.clock.t = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	// Sleeps: catch-up delay, then 1 h chunks up to 03:00, run, ...
	s := newSched(t, h, berlin, 40)
	s.run()

	list, err := h.svc.List(bg)
	must(t, err)
	if len(list) != 3 { // catch-up + two nightly runs
		t.Fatalf("backups = %+v", list)
	}
	if s.sleeps[0] != catchUpDelay {
		t.Errorf("first sleep = %v, want the catch-up delay", s.sleeps[0])
	}
	for _, d := range s.sleeps {
		if d > maxSleep || d <= 0 {
			t.Fatalf("sleep of %v", d)
		}
	}
	// Oldest is the catch-up backup, the following ones are the nightly runs
	// at exactly 03:00 hub time.
	var nightly []Info
	for i := len(list) - 2; i >= 0; i-- { // skip the catch-up one at the end of the slice
		nightly = append(nightly, list[i])
	}
	for _, in := range nightly {
		l := in.CreatedAt.In(berlin)
		if l.Hour() != 3 || l.Minute() != 0 {
			t.Errorf("nightly backup at %v local, want 03:00", l)
		}
		if in.Reason != ReasonNightly {
			t.Errorf("reason %q", in.Reason)
		}
	}
	// Consecutive nightly runs are one calendar day apart (not twice per night).
	for i := 1; i < len(nightly); i++ {
		if d := nightly[i].CreatedAt.Sub(nightly[i-1].CreatedAt); d < 23*time.Hour || d > 25*time.Hour {
			t.Errorf("runs %v apart", d)
		}
	}
}

func TestSchedulerCatchUp(t *testing.T) {
	berlin := mustLoc(t, "Europe/Berlin")
	tests := []struct {
		name string
		// last backup relative to the start (negative = before); nil: none.
		last      *time.Duration
		wantFirst bool // catch-up backup right after the delay
	}{
		{"no backup at all", nil, true},
		{"last backup is older than the last 03:00", ptr(-30 * time.Hour), true},
		{"last backup after the last 03:00", ptr(-2 * time.Hour), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHub(t)
			h.clock.t = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC) // 14:00 Berlin; last 03:00 was 01:00Z
			if tc.last != nil {
				h.clock.t = h.clock.t.Add(*tc.last)
				_, err := h.svc.CreateLocal(bg, ReasonManual)
				must(t, err)
				h.clock.t = h.clock.t.Add(-*tc.last)
			}
			before, _ := h.svc.List(bg)
			s := newSched(t, h, berlin, 1) // the delay, then a single chunk sleep
			s.run()
			after, _ := h.svc.List(bg)
			if got := len(after) - len(before); (got == 1) != tc.wantFirst || got > 1 {
				t.Errorf("catch-up created %d backups, want %v", got, tc.wantFirst)
			}
			if tc.wantFirst && after[0].Reason != ReasonNightly {
				t.Errorf("reason %q", after[0].Reason)
			}
		})
	}
}

func ptr[T any](v T) *T { return &v }

func TestSchedulerFollowsSettingsAndPrunes(t *testing.T) {
	h := newHub(t)
	utc := time.UTC
	h.clock.t = time.Date(2026, 10, 2, 12, 0, 0, 0, utc)
	must(t, h.svc.SetSchedule(bg, Schedule{Time: "05:00", Keep: 2}))
	s := newSched(t, h, utc, 120)
	s.run()

	list, err := h.svc.List(bg)
	must(t, err)
	if len(list) != 2 {
		t.Fatalf("keep 2, but %d backups remain", len(list))
	}
	for _, in := range list {
		if in.CreatedAt.Hour() != 5 || in.CreatedAt.Minute() != 0 {
			// The first (catch-up) backup is pruned by then; all left are nightly.
			t.Errorf("backup at %v, want 05:00", in.CreatedAt)
		}
	}
	// Changing the time takes effect within the hour.
	h2 := newHub(t)
	h2.clock.t = time.Date(2026, 10, 2, 12, 0, 0, 0, utc)
	s2 := newSched(t, h2, utc, 30)
	s2.onSleep = func(n int) {
		if n == 3 {
			must(t, h2.svc.SetSchedule(bg, Schedule{Time: "20:00", Keep: 7}))
		}
	}
	s2.run()
	list, _ = h2.svc.List(bg)
	var at20 bool
	for _, in := range list {
		if in.CreatedAt.Hour() == 20 {
			at20 = true
		}
	}
	if !at20 {
		t.Errorf("no backup at the changed time 20:00: %+v", list)
	}
}

func TestSchedulerSurvivesFailureAndStops(t *testing.T) {
	h := newHub(t)
	h.clock.t = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	o := h.svc.o
	calls := 0
	o.Snapshot = func(ctx context.Context, dest string) error {
		calls++
		if calls == 1 {
			return context.DeadlineExceeded
		}
		return h.st.Snapshot(ctx, dest)
	}
	h.svc = New(o)
	s := newSched(t, h, time.UTC, 40)
	s.run() // must return when the context is cancelled, after a failed first run
	if calls < 2 {
		t.Errorf("snapshot called %d times; the scheduler gave up after a failure", calls)
	}
	list, _ := h.svc.List(bg)
	if len(list) == 0 {
		t.Error("no backup after the failed one")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	failed := 0
	for _, e := range h.audits {
		if e.Action == ActionCreate && e.Result == "error" {
			failed++
		}
		if e.User != "system" {
			t.Errorf("audit user %q, want system", e.User)
		}
	}
	if failed != 1 {
		t.Errorf("%d failed-create audit entries, want 1", failed)
	}
}
