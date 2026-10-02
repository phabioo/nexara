package demo

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/phabioo/nexara/internal/hub/history"
	"github.com/phabioo/nexara/internal/hub/store"
)

// Synthetic history for `nexus dev --demo`, so the History view has something
// to show from the first second. Every value is a pure function of the host,
// the minute and `now` (no random state): the same call gives the same data.
const (
	backfillMinuteDays = 7  // minute rows, like the real retention
	backfillHourDays   = 35 // enough for the 30 day range
	minuteSamples      = 30 // 60 s at the 2 s live interval
)

// historySpan is a stretch of time without data (agent down, hub rebooting).
type historySpan struct{ from, to time.Time }

func (s historySpan) contains(t time.Time) bool { return !t.Before(s.from) && t.Before(s.to) }

// BackfillHistory writes plausible minute and hour history for the demo hosts
// into st: a daily rhythm in CPU, temperature and network, a nightly job on
// pi5-media, slowly growing disks, a reboot gap on pi5-media (20 hours ago),
// a short outage on pi3-dns (3 days ago) and an offline pi4 whose history ends
// 52 hours ago. It writes everything up to the last closed minute before now
// (hours first, then minutes) and returns early if ctx ends.
func (h *Hub) BackfillHistory(ctx context.Context, st *store.Store, now time.Time) error {
	minutes, hours, err := h.historyRows(ctx, now)
	if err != nil {
		return err
	}
	if err := st.ReplaceMetrics(ctx, store.Metrics1h, hours); err != nil {
		return fmt.Errorf("demo history: %w", err)
	}
	if err := st.ReplaceMetrics(ctx, store.Metrics1m, minutes); err != nil {
		return fmt.Errorf("demo history: %w", err)
	}
	return nil
}

// historyRows generates the minute and hour rows BackfillHistory writes.
func (h *Hub) historyRows(ctx context.Context, now time.Time) (minutes, hours []store.MetricRow, err error) {
	type target struct {
		id    string
		prof  profile
		seed  uint64
		end   time.Time
		gaps  []historySpan
		spike bool // nightly job
	}
	now = now.UTC()
	last := now.Truncate(time.Minute) // exclusive: the running minute belongs to the live aggregator

	h.mu.Lock()
	var targets []target
	for i, hst := range h.hosts {
		t := target{id: string(hst.info.ID), prof: hst.prof, seed: uint64(i+1) * 0x9e3779b97f4a7c15, end: last}
		if len(t.prof.cpuBase) == 0 {
			t.prof = genericProfile()
		}
		switch hst.info.ID {
		case hostPi5:
			t.gaps = []historySpan{{last.Add(-20*time.Hour - 25*time.Minute), last.Add(-20 * time.Hour)}}
			t.spike = true
		case hostPi3:
			t.gaps = []historySpan{{last.Add(-72*time.Hour - 8*time.Minute), last.Add(-72 * time.Hour)}}
		case hostPi4:
			t.end = last.Add(-52 * time.Hour)
		}
		targets = append(targets, t)
	}
	h.mu.Unlock()

	for _, t := range targets {
		first := last.Add(-backfillHourDays * 24 * time.Hour).Truncate(time.Hour)
		minuteFrom := last.Add(-backfillMinuteDays * 24 * time.Hour)
		for hour := first; hour.Before(t.end); hour = hour.Add(time.Hour) {
			if err := ctx.Err(); err != nil {
				return nil, nil, err
			}
			// The first hour of the span may start before the data and the
			// current hour is still open: only whole, closed hours get a row.
			if hour.Add(time.Hour).After(last) {
				break
			}
			rows := make([]store.MetricRow, 0, 60)
			for m := 0; m < 60; m++ {
				at := hour.Add(time.Duration(m) * time.Minute)
				if !at.Before(t.end) || skipped(t.gaps, at) {
					continue
				}
				r := synthMinute(t.id, t.prof, t.seed, t.spike, at, last)
				rows = append(rows, r)
				if !at.Before(minuteFrom) {
					minutes = append(minutes, r)
				}
			}
			if row, ok := history.Combine(t.id, hour, rows); ok {
				hours = append(hours, row)
			}
		}
		// Minutes of the last, partial hour (not rolled up yet) still belong to the minute table.
		for at := last.Truncate(time.Hour); at.Before(t.end) && at.Before(last); at = at.Add(time.Minute) {
			if skipped(t.gaps, at) {
				continue
			}
			minutes = append(minutes, synthMinute(t.id, t.prof, t.seed, t.spike, at, last))
		}
	}
	return minutes, hours, ctx.Err()
}

func skipped(gaps []historySpan, t time.Time) bool {
	for _, g := range gaps {
		if g.contains(t) {
			return true
		}
	}
	return false
}

// noise is a deterministic value in [-1, 1] for (seed, minute, channel).
func noise(seed uint64, at time.Time, channel uint64) float64 {
	x := seed ^ uint64(at.Unix()/60)*0xbf58476d1ce4e5b9 ^ channel*0x94d049bb133111eb
	x ^= x >> 30
	x *= 0xbf58476d1ce4e5b9
	x ^= x >> 27
	x *= 0x94d049bb133111eb
	x ^= x >> 31
	return float64(x>>11)/float64(1<<52) - 1
}

// synthMinute is the demo host's state during the minute starting at at.
// ref is the end of the history (disk usage grows towards the profile's value
// there).
func synthMinute(host string, p profile, seed uint64, spike bool, at, ref time.Time) store.MetricRow {
	tod := float64(at.Hour()) + float64(at.Minute())/60
	daily := math.Sin(2 * math.Pi * (tod - 9) / 24) // peaks mid afternoon, low at night
	evening := math.Max(0, math.Sin(2*math.Pi*(tod-14)/24))
	days := ref.Sub(at).Hours() / 24

	avg := p.cpuAvg()
	cpu := avg*(1+0.45*daily) + noise(seed, at, 1)*p.cpuAmp
	if spike && tod >= 3 && tod < 3.67 { // nightly transcode/backup job
		cpu += 42 + noise(seed, at, 2)*6
	}
	cpu = clamp(cpu, 0.5, 100)
	cpuMax := clamp(cpu+math.Abs(noise(seed, at, 3))*p.cpuAmp*2.5+1, cpu, 100)

	temp := clamp(p.tempBase+(cpu-avg)*0.2+1.5*daily+noise(seed, at, 4)*0.4, 25, 84)

	// Memory: slow cache growth over three days, then freed, plus noise.
	cycle := math.Mod(float64(at.Unix())/3600/72, 1)
	mem := float64(p.memBase)*(0.9+0.18*cycle) + noise(seed, at, 5)*0.03*gib
	mem = clamp(mem, 0.1*gib, float64(p.memTotal))
	memMax := math.Min(mem+0.04*gib, float64(p.memTotal))

	rx := p.rx * (0.45 + 1.1*evening) * (1 + 0.4*noise(seed, at, 6))
	tx := p.tx * (0.45 + 1.1*evening) * (1 + 0.4*noise(seed, at, 7))
	rx, tx = math.Max(rx, 0), math.Max(tx, 0)

	disks := make([]store.DiskUsage, 0, len(p.disks))
	for i, d := range p.disks {
		// Roughly +0.03 % of the disk per day, with the profile's value as "now".
		used := float64(d.Used) - days*0.0003*float64(d.Total) + noise(seed, at, 20+uint64(i))*0.00002*float64(d.Total)
		disks = append(disks, store.DiskUsage{Mount: d.Mount, Used: uint64(clamp(used, 0, float64(d.Total))), Total: d.Total})
	}
	return store.MetricRow{
		HostID: host, Time: at, Samples: minuteSamples,
		CPUAvg: cpu, CPUMax: cpuMax,
		MemUsedAvg: mem, MemUsedMax: memMax, MemTotal: p.memTotal,
		TempAvg: &temp, TempMax: ptr(temp + 0.3 + math.Abs(noise(seed, at, 8))*0.5),
		NetRxAvg: rx, NetRxMax: rx * (1.5 + math.Abs(noise(seed, at, 9))),
		NetTxAvg: tx, NetTxMax: tx * (1.5 + math.Abs(noise(seed, at, 10))),
		Disks: disks,
	}
}

func ptr(v float64) *float64 { return &v }
