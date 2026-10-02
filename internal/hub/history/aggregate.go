package history

import (
	"math"
	"sort"
	"time"

	"github.com/phabioo/nexara/internal/hub/store"
	"github.com/phabioo/nexara/internal/protocol"
)

// Limits on agent-controlled data, so one misbehaving agent cannot bloat rows.
const (
	maxMounts   = 32
	maxMountLen = 256
)

// bucket accumulates store.MetricRows into one bigger row. Everything is
// weighted by Samples, so minutes can be rolled into hours without bias.
type bucket struct {
	n int // samples

	cpuSum, cpuMax float64
	memSum, memMax float64
	memTotal       uint64

	tempN            int
	tempSum, tempMax float64

	rxSum, rxMax float64
	txSum, txMax float64

	disks map[string]*diskAcc
}

type diskAcc struct {
	n       int
	usedSum float64
	total   uint64
}

// add folds r into the bucket. Rows must be added oldest first: the newest
// row decides memory total and disk size.
func (b *bucket) add(r store.MetricRow) {
	w := float64(r.Samples)
	first := b.n == 0
	b.n += r.Samples

	b.cpuSum += r.CPUAvg * w
	b.memSum += r.MemUsedAvg * w
	b.rxSum += r.NetRxAvg * w
	b.txSum += r.NetTxAvg * w
	if first {
		b.cpuMax, b.memMax, b.rxMax, b.txMax = r.CPUMax, r.MemUsedMax, r.NetRxMax, r.NetTxMax
	} else {
		b.cpuMax = math.Max(b.cpuMax, r.CPUMax)
		b.memMax = math.Max(b.memMax, r.MemUsedMax)
		b.rxMax = math.Max(b.rxMax, r.NetRxMax)
		b.txMax = math.Max(b.txMax, r.NetTxMax)
	}
	if r.MemTotal > 0 {
		b.memTotal = r.MemTotal
	}
	if r.TempAvg != nil && r.TempMax != nil {
		if b.tempN == 0 {
			b.tempMax = *r.TempMax
		} else {
			b.tempMax = math.Max(b.tempMax, *r.TempMax)
		}
		b.tempN += r.Samples
		b.tempSum += *r.TempAvg * w
	}
	for _, d := range r.Disks {
		if b.disks == nil {
			b.disks = make(map[string]*diskAcc)
		}
		a := b.disks[d.Mount]
		if a == nil {
			if len(b.disks) >= maxMounts {
				continue
			}
			a = &diskAcc{}
			b.disks[d.Mount] = a
		}
		a.n += r.Samples
		a.usedSum += float64(d.Used) * w
		a.total = d.Total
	}
}

// row returns the accumulated bucket starting at at. b.n must be > 0.
func (b *bucket) row(host string, at time.Time) store.MetricRow {
	n := float64(b.n)
	r := store.MetricRow{
		HostID: host, Time: at, Samples: b.n,
		CPUAvg: b.cpuSum / n, CPUMax: b.cpuMax,
		MemUsedAvg: b.memSum / n, MemUsedMax: b.memMax, MemTotal: b.memTotal,
		NetRxAvg: b.rxSum / n, NetRxMax: b.rxMax,
		NetTxAvg: b.txSum / n, NetTxMax: b.txMax,
	}
	if b.tempN > 0 {
		avg, mx := b.tempSum/float64(b.tempN), b.tempMax
		r.TempAvg, r.TempMax = &avg, &mx
	}
	if len(b.disks) > 0 {
		mounts := make([]string, 0, len(b.disks))
		for m := range b.disks {
			mounts = append(mounts, m)
		}
		sort.Strings(mounts)
		for _, m := range mounts {
			a := b.disks[m]
			r.Disks = append(r.Disks, store.DiskUsage{Mount: m, Used: uint64(math.Round(a.usedSum / float64(a.n))), Total: a.total})
		}
	}
	return r
}

// Combine merges rows (oldest first) into one row at the given time, weighted
// by their samples: the hour roll-up, also used to build the demo history. It
// reports false when there are no rows.
func Combine(host string, at time.Time, rows []store.MetricRow) (store.MetricRow, bool) {
	var b bucket
	for _, r := range rows {
		b.add(r)
	}
	if b.n == 0 {
		return store.MetricRow{}, false
	}
	return b.row(host, at), true
}

// sampleRow turns a live sample into a one-sample row. It reports false for a
// sample that cannot be trusted (non-finite CPU), which is then dropped
// rather than turned into a plausible-looking number.
func sampleRow(host string, m protocol.Metrics) (store.MetricRow, bool) {
	if !finite(m.CPUPercent) {
		return store.MetricRow{}, false
	}
	r := store.MetricRow{
		HostID: host, Samples: 1,
		CPUAvg: clamp(m.CPUPercent, 0, 100), MemTotal: m.MemTotal,
		MemUsedAvg: float64(m.MemUsed),
		NetRxAvg:   nonNeg(m.Net.RxBytesPerSec), NetTxAvg: nonNeg(m.Net.TxBytesPerSec),
	}
	r.CPUMax, r.MemUsedMax, r.NetRxMax, r.NetTxMax = r.CPUAvg, r.MemUsedAvg, r.NetRxAvg, r.NetTxAvg
	if t := m.TempC; t != nil && finite(*t) && *t > -50 && *t < 250 {
		a, x := *t, *t
		r.TempAvg, r.TempMax = &a, &x
	}
	seen := make(map[string]bool, len(m.Disks))
	for _, d := range m.Disks {
		if d.Mount == "" || len(d.Mount) > maxMountLen || len(r.Disks) >= maxMounts || seen[d.Mount] {
			continue
		}
		seen[d.Mount] = true
		used := d.Used
		if d.Total > 0 && used > d.Total {
			used = d.Total
		}
		r.Disks = append(r.Disks, store.DiskUsage{Mount: d.Mount, Used: used, Total: d.Total})
	}
	return r, true
}

func finite(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v, 0) }

func clamp(v, lo, hi float64) float64 { return math.Min(math.Max(v, lo), hi) }

func nonNeg(v float64) float64 {
	if !finite(v) || v < 0 {
		return 0
	}
	return v
}
