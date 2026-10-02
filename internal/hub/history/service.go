package history

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/phabioo/nexara/internal/hub/grid"
	"github.com/phabioo/nexara/internal/hub/store"
	"github.com/phabioo/nexara/internal/protocol"
)

// Defaults of Options.
const (
	DefaultMinuteRetention = 7 * 24 * time.Hour
	DefaultRetentionDays   = 365
	DefaultFlushGrace      = 5 * time.Second
	defaultCheckEvery      = 5 * time.Second

	// A sample's own timestamp is used when it is at most maxSampleAge old
	// (agents replay up to 10 minutes after a reconnect) and at most
	// maxSampleSkew in the future; otherwise the hub's receive time is used.
	maxSampleAge  = 15 * time.Minute
	maxSampleSkew = 2 * time.Minute

	// pendingLimit bounds the rows kept for retry while the database is failing.
	pendingLimit = 5000

	auditPruneEvery = 24 * time.Hour
)

// Subscriber is the part of grid.Hub the aggregator needs.
type Subscriber interface {
	Subscribe(ctx context.Context) <-chan grid.Event
}

// Options configure a Service. Only Store is required.
type Options struct {
	Store *store.Store
	// Hub delivers the live samples; nil means the Service only serves queries.
	Hub    Subscriber
	Logger *slog.Logger

	// Now is the clock (tests); defaults to time.Now.
	Now func() time.Time
	// Ticks replaces the internal ticker that checks for closed minutes (tests).
	Ticks <-chan time.Time
	// FlushGrace is how long after a minute's end late samples are still
	// collected before the minute is written; defaults to 5 s.
	FlushGrace time.Duration
	// MinuteRetention defaults to 7 days.
	MinuteRetention time.Duration
	// DefaultRetentionDays is the hour retention while the setting
	// history.retention_days is unset: storage.history.hour_days of nexus.yaml.
	DefaultRetentionDays int
	// Location is the hub's time zone (hub.timezone); the History view labels
	// its time axis with it. Nil means time.Local.
	Location *time.Location
}

// Service aggregates, stores and serves the metrics history.
type Service struct {
	st   *store.Store
	hub  Subscriber
	log  *slog.Logger
	now  func() time.Time
	tick <-chan time.Time

	grace           time.Duration
	minuteRetention time.Duration
	defaultDays     int
	loc             *time.Location

	flushMu sync.Mutex // serializes flushes and forget (writes happen outside mu)
	mu      sync.Mutex // guards open, pending, maintHour, lastAuditPrune
	open    map[bucketKey]*bucket
	pending []store.MetricRow // closed minutes that failed to write

	maintHour      time.Time // hour of the last successful maintenance run
	lastAuditPrune time.Time
}

type bucketKey struct {
	host   string
	minute int64 // unix seconds, multiple of 60
}

// New creates a Service; call Run to start the aggregation.
func New(o Options) *Service {
	s := &Service{
		st: o.Store, hub: o.Hub, log: o.Logger, now: o.Now, tick: o.Ticks,
		grace: o.FlushGrace, minuteRetention: o.MinuteRetention, defaultDays: o.DefaultRetentionDays,
		loc:  o.Location,
		open: make(map[bucketKey]*bucket),
	}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.loc == nil {
		s.loc = time.Local
	}
	if s.grace <= 0 {
		s.grace = DefaultFlushGrace
	}
	if s.minuteRetention <= 0 {
		s.minuteRetention = DefaultMinuteRetention
	}
	if s.defaultDays < MinRetentionDays || s.defaultDays > MaxRetentionDays {
		s.defaultDays = DefaultRetentionDays
	}
	return s
}

// Location is the time zone to show timestamps of the history in.
func (s *Service) Location() *time.Location { return s.loc }

// Now is the service's clock. Callers that issue several queries for one page
// take it once, so all series share the same time grid.
func (s *Service) Now() time.Time { return s.now() }

// Run aggregates events until ctx ends, then flushes the open minute and
// returns. Database problems are logged and retried at the next check.
func (s *Service) Run(ctx context.Context) {
	var events <-chan grid.Event
	if s.hub != nil {
		events = s.hub.Subscribe(ctx)
	}
	ticks := s.tick
	if ticks == nil {
		t := time.NewTicker(defaultCheckEvery)
		defer t.Stop()
		ticks = t.C
	}
loop:
	for {
		if ctx.Err() != nil { // a ready event must not win the select over shutdown
			break
		}
		select {
		case <-ctx.Done():
			break loop
		case ev, ok := <-events:
			if !ok {
				events = nil // closed with ctx; wait for ctx.Done
				continue
			}
			s.handle(ctx, ev)
		case <-ticks:
			s.check(ctx)
		}
	}
	// The run context is cancelled; the last writes get their own deadline.
	fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	// Events that were already queued when the context ended still count.
	for drained := false; !drained && events != nil; {
		select {
		case ev, ok := <-events:
			if !ok {
				drained = true
				break
			}
			s.handle(fctx, ev)
		default:
			drained = true
		}
	}
	if err := s.flush(fctx, s.now(), true); err != nil {
		s.log.Error("flushing the open history minute failed; it is lost", "err", err)
	}
}

func (s *Service) handle(ctx context.Context, ev grid.Event) {
	switch ev.Kind {
	case grid.EventMetrics:
		if m, ok := ev.Payload.(protocol.Metrics); ok {
			s.Observe(string(ev.Host), m)
		}
	case grid.EventHostRemoved:
		s.forget(ctx, string(ev.Host))
	}
}

// Observe adds one live sample of a host. Samples are bucketed by their own
// timestamp when it is plausible (see maxSampleAge), else by arrival time.
func (s *Service) Observe(host string, m protocol.Metrics) {
	if host == "" {
		return
	}
	r, ok := sampleRow(host, m)
	if !ok {
		return
	}
	now := s.now()
	at := m.Timestamp
	if at.IsZero() || at.After(now.Add(maxSampleSkew)) || at.Before(now.Add(-maxSampleAge)) {
		at = now
	}
	k := bucketKey{host: host, minute: at.Unix() - at.Unix()%60}
	r.Time = time.Unix(k.minute, 0).UTC()

	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.open[k]
	if b == nil {
		b = &bucket{}
		s.open[k] = b
	}
	b.add(r)
}

// forget drops everything of a removed host, including its stored history.
func (s *Service) forget(ctx context.Context, host string) {
	s.flushMu.Lock()
	defer s.flushMu.Unlock()
	s.mu.Lock()
	for k := range s.open {
		if k.host == host {
			delete(s.open, k)
		}
	}
	kept := s.pending[:0]
	for _, r := range s.pending {
		if r.HostID != host {
			kept = append(kept, r)
		}
	}
	s.pending = kept
	s.mu.Unlock()
	if err := s.st.DeleteHostMetrics(ctx, host); err != nil && ctx.Err() == nil {
		s.log.Warn("deleting the history of a removed host failed", "host", host, "err", err)
	}
}

// Flush writes all minutes that have closed (plus grace) and rolls finished
// hours up. Run calls it periodically; it is exported for tests and for
// callers that want data on disk now (a backup).
func (s *Service) Flush(ctx context.Context) error { return s.flush(ctx, s.now(), false) }

// check is one periodic pass: flush closed minutes, then the hourly and daily maintenance.
func (s *Service) check(ctx context.Context) {
	now := s.now()
	if err := s.flush(ctx, now, false); err != nil {
		if ctx.Err() == nil {
			s.log.Warn("writing the metrics history failed; will retry", "err", err)
		}
		return
	}
	s.maintain(ctx, now)
}

// flush writes closed minutes in one transaction. With all set, also the open
// ones (shutdown). Rows that fail to write stay pending for the next call.
func (s *Service) flush(ctx context.Context, now time.Time, all bool) error {
	s.flushMu.Lock()
	defer s.flushMu.Unlock()

	cutoff := now.Add(-s.grace).Unix()
	s.mu.Lock()
	for k, b := range s.open {
		if all || k.minute+60 <= cutoff {
			s.pending = append(s.pending, b.row(k.host, time.Unix(k.minute, 0).UTC()))
			delete(s.open, k)
		}
	}
	if over := len(s.pending) - pendingLimit; over > 0 {
		s.log.Warn("history backlog too large, dropping the oldest minutes", "dropped", over)
		s.pending = append([]store.MetricRow(nil), s.pending[over:]...)
	}
	rows := append([]store.MetricRow(nil), s.pending...)
	s.mu.Unlock()
	if len(rows) == 0 {
		return nil
	}
	if err := s.st.MergeMetrics1m(ctx, rows); err != nil {
		return err
	}
	s.mu.Lock()
	s.pending = nil // only flush and forget touch it, both under flushMu
	s.mu.Unlock()

	// Hours that are over now and got minutes in this flush (the last minute
	// of an hour, or minutes an agent replayed late) are rolled up again.
	seen := map[store.HostHour]bool{}
	var keys []store.HostHour
	for _, r := range rows {
		h := store.HostHour{HostID: r.HostID, Hour: r.Time.Truncate(time.Hour)}
		if !h.Hour.Add(time.Hour).After(now) && !seen[h] {
			seen[h] = true
			keys = append(keys, h)
		}
	}
	if err := s.roll(ctx, keys); err != nil {
		s.setMaintHour(time.Time{}) // let the next check sweep again
		return fmt.Errorf("rolling up hours: %w", err)
	}
	return nil
}

// roll recomputes the hour rows of the given host hours from their minutes.
func (s *Service) roll(ctx context.Context, keys []store.HostHour) error {
	var out []store.MetricRow
	for _, k := range keys {
		mins, err := s.st.ListMetrics(ctx, store.Metrics1m, k.HostID, k.Hour, k.Hour.Add(time.Hour))
		if err != nil {
			return err
		}
		if row, ok := Combine(k.HostID, k.Hour, mins); ok {
			out = append(out, row)
		}
	}
	return s.st.ReplaceMetrics(ctx, store.Metrics1h, out)
}

// maintain runs the hourly retention work and, once a day, the audit pruning.
func (s *Service) maintain(ctx context.Context, now time.Time) {
	hour := now.Truncate(time.Hour)
	s.mu.Lock()
	hourDone := hour.Equal(s.maintHour)
	auditDone := !s.lastAuditPrune.IsZero() && now.Sub(s.lastAuditPrune) < auditPruneEvery
	s.mu.Unlock()
	if !hourDone {
		if err := s.sweepAndPrune(ctx, now); err != nil {
			if ctx.Err() == nil {
				s.log.Warn("history maintenance failed; will retry", "err", err)
			}
		} else {
			s.setMaintHour(hour)
		}
	}
	if !auditDone {
		if err := s.PruneAudit(ctx); err != nil {
			if ctx.Err() == nil {
				s.log.Warn("audit pruning failed; will retry", "err", err)
			}
		} else {
			s.mu.Lock()
			s.lastAuditPrune = now
			s.mu.Unlock()
		}
	}
}

func (s *Service) setMaintHour(h time.Time) {
	s.mu.Lock()
	s.maintHour = h
	s.mu.Unlock()
}

func (s *Service) sweepAndPrune(ctx context.Context, now time.Time) error {
	days := s.RetentionDays(ctx)
	hourCutoff := now.Add(-time.Duration(days) * 24 * time.Hour)
	minuteCutoff := now.Add(-s.minuteRetention)

	// Roll closed hours that have minutes but no hour row (hub was down at the
	// hour boundary, host went offline in the last minutes of an hour, upgrade).
	// Hours older than either retention would be pruned again at once.
	from := minuteCutoff
	if hourCutoff.After(from) {
		from = hourCutoff
	}
	keys, err := s.st.UnrolledHours(ctx, from.Truncate(time.Hour), now.Truncate(time.Hour))
	if err != nil {
		return err
	}
	if err := s.roll(ctx, keys); err != nil {
		return err
	}
	m, h, err := s.st.PruneMetrics(ctx, minuteCutoff, hourCutoff)
	if err != nil {
		return err
	}
	if m+h > 0 {
		s.log.Info("pruned metrics history", "minutes", m, "hours", h, "hour_retention_days", days)
	}
	return nil
}
