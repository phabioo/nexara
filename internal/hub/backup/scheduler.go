package backup

import (
	"context"
	"log/slog"
	"strconv"
	"time"
)

const (
	// catchUpDelay postpones the start-up check so that a hub that is still
	// settling (setup, restart loops) does not back up on every start.
	catchUpDelay = 2 * time.Minute
	// maxSleep bounds one sleep so that clock changes and a changed
	// backup.time are noticed within the hour.
	maxSleep = time.Hour
)

// SchedulerOptions configure a Scheduler. Service is required.
type SchedulerOptions struct {
	Service *Service
	// Location is the hub's time zone (hub.timezone); nil means time.Local.
	Location *time.Location
	Now      func() time.Time
	// Sleep waits for d or until ctx ends (then it returns ctx.Err()). Nil
	// uses a real timer; tests inject a fake clock.
	Sleep  func(ctx context.Context, d time.Duration) error
	Logger *slog.Logger
}

// Scheduler runs the nightly backup at backup.time and catches up once after
// a start when the last backup is older than the most recent scheduled time
// (the Pi was off at 03:00).
type Scheduler struct{ o SchedulerOptions }

// NewScheduler returns a Scheduler.
func NewScheduler(o SchedulerOptions) *Scheduler {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Location == nil {
		o.Location = time.Local
	}
	if o.Sleep == nil {
		o.Sleep = realSleep
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	return &Scheduler{o: o}
}

func realSleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Run blocks until ctx ends.
func (s *Scheduler) Run(ctx context.Context) {
	ctx = WithActor(ctx, "system")
	if s.o.Sleep(ctx, catchUpDelay) != nil {
		return
	}
	s.catchUp(ctx)
	for {
		sch := s.o.Service.Schedule(ctx)
		now := s.o.Now()
		next := NextRun(now, sch.Time, s.o.Location)
		if err := s.o.Sleep(ctx, min(next.Sub(now), maxSleep)); err != nil {
			return
		}
		// A chunked sleep (or a clock that stepped back) lands here early.
		if s.o.Now().Before(next) {
			continue
		}
		s.run(ctx)
	}
}

func (s *Scheduler) catchUp(ctx context.Context) {
	infos, err := s.o.Service.listNames()
	if err != nil {
		s.o.Logger.Warn("backup catch-up check failed", "err", err)
		return
	}
	now := s.o.Now()
	prev := PrevRun(now, s.o.Service.Schedule(ctx).Time, s.o.Location)
	if len(infos) > 0 && !infos[0].CreatedAt.Before(prev) {
		return
	}
	s.o.Logger.Info("last backup is older than the scheduled time; backing up now", "scheduled", prev)
	s.run(ctx)
}

func (s *Scheduler) run(ctx context.Context) {
	info, err := s.o.Service.CreateAndPrune(ctx, ReasonNightly)
	if err != nil {
		// CreateLocal already wrote the audit entry. The next try is the
		// next scheduled time.
		s.o.Logger.Error("nightly backup failed", "err", err)
		return
	}
	s.o.Logger.Info("backup created", "file", info.Name, "bytes", strconv.FormatInt(info.Size, 10))
}

// NextRun returns the first occurrence of hhmm ("03:00") in loc strictly after now.
func NextRun(now time.Time, hhmm string, loc *time.Location) time.Time {
	h, m := splitTime(hhmm)
	n := now.In(loc)
	t := time.Date(n.Year(), n.Month(), n.Day(), h, m, 0, 0, loc)
	if !t.After(now) {
		t = time.Date(n.Year(), n.Month(), n.Day()+1, h, m, 0, 0, loc)
	}
	return t
}

// PrevRun returns the latest occurrence of hhmm in loc at or before now.
func PrevRun(now time.Time, hhmm string, loc *time.Location) time.Time {
	h, m := splitTime(hhmm)
	n := now.In(loc)
	t := time.Date(n.Year(), n.Month(), n.Day(), h, m, 0, 0, loc)
	if t.After(now) {
		t = time.Date(n.Year(), n.Month(), n.Day()-1, h, m, 0, 0, loc)
	}
	return t
}

func splitTime(hhmm string) (h, m int) {
	if mm := timeRe.FindStringSubmatch(hhmm); mm != nil {
		h, _ = strconv.Atoi(mm[1])
		m, _ = strconv.Atoi(mm[2])
		return h, m
	}
	return 3, 0
}
