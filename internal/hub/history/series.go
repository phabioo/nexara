package history

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
	"unicode"

	"github.com/phabioo/nexara/internal/hub/store"
)

// Metric names a chart series.
type Metric string

// Series metrics. Disk series are built with MetricDisk.
const (
	MetricCPU   Metric = "cpu"
	MetricMem   Metric = "mem"
	MetricTemp  Metric = "temp"
	MetricNetRx Metric = "net_rx"
	MetricNetTx Metric = "net_tx"
)

const diskPrefix = "disk:"

// MetricDisk is the series of one mount point, e.g. MetricDisk("/mnt/data").
func MetricDisk(mount string) Metric { return Metric(diskPrefix + mount) }

// Mount returns the mount of a disk metric.
func (m Metric) Mount() (string, bool) {
	mount, ok := strings.CutPrefix(string(m), diskPrefix)
	return mount, ok
}

// Unit says how to label a series.
type Unit string

// Units of Series values.
const (
	UnitPercent        Unit = "percent"
	UnitBytes          Unit = "bytes"
	UnitCelsius        Unit = "celsius"
	UnitBytesPerSecond Unit = "bytes_per_second"
)

// Errors of Series.
var (
	ErrInvalidQuery  = errors.New("history: invalid query")
	ErrTooManyPoints = errors.New("history: range and step give too many points")
)

// ParseMetric validates a metric name from a URL ("cpu", "disk:/mnt/data").
func ParseMetric(s string) (Metric, error) {
	m := Metric(s)
	switch m {
	case MetricCPU, MetricMem, MetricTemp, MetricNetRx, MetricNetTx:
		return m, nil
	}
	if mount, ok := m.Mount(); ok && validMount(mount) {
		return m, nil
	}
	return "", fmt.Errorf("%w: unknown metric %q", ErrInvalidQuery, s)
}

func validMount(mount string) bool {
	if mount == "" || len(mount) > maxMountLen {
		return false
	}
	for _, r := range mount {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func (m Metric) unit() Unit {
	switch m {
	case MetricCPU:
		return UnitPercent
	case MetricTemp:
		return UnitCelsius
	case MetricNetRx, MetricNetTx:
		return UnitBytesPerSecond
	}
	return UnitBytes // mem and disks
}

// Point is one chart point. Avg and Max are NaN when the bucket has no data
// (host offline, no sensor): draw a gap, not zero. For disk series Max equals
// Avg (usage is stored as an average only).
type Point struct {
	Time time.Time // start of the bucket, UTC
	Avg  float64
	Max  float64
}

// HasData reports whether the point carries a value.
func (p Point) HasData() bool { return !math.IsNaN(p.Avg) }

// Series is the answer to a Series query.
type Series struct {
	Host   string
	Metric Metric
	Unit   Unit
	// From is the start of the first bucket (the requested start rounded down
	// to a multiple of Step); Points[i].Time == From + i*Step.
	From time.Time
	// Step is the effective bucket width: the request, raised to the
	// resolution of the table that answered (1 min or 1 h).
	Step time.Duration
	// Source says which table answered: store.Metrics1m or store.Metrics1h.
	Source store.MetricsTable
	// Total is the largest installed memory (mem) or mount size (disk) seen in
	// the range, to turn bytes into percent; 0 for other metrics or no data.
	Total  float64
	Points []Point
}

// HasData reports whether any point carries a value.
func (s Series) HasData() bool {
	for _, p := range s.Points {
		if p.HasData() {
			return true
		}
	}
	return false
}

// maxSeriesPoints bounds one answer (a year at 1 h is 8760 points).
const maxSeriesPoints = 10000

// minuteSlack covers the hourly pruning of minute rows: minutes up to an hour
// older than the retention can still exist.
const minuteSlack = time.Hour

// Range is one of the History view's range buttons.
type Range struct {
	Key   string // "24h", "7d", "30d": used in URLs
	Label string
	Span  time.Duration
	Step  time.Duration
}

// Ranges are the ranges of the History view (24 h from minutes at 5 min, 7 d
// from minutes at 30 min, 30 d from hours at 1 h).
var Ranges = []Range{
	{Key: "24h", Label: "24 hours", Span: 24 * time.Hour, Step: 5 * time.Minute},
	{Key: "7d", Label: "7 days", Span: 7 * 24 * time.Hour, Step: 30 * time.Minute},
	{Key: "30d", Label: "30 days", Span: 30 * 24 * time.Hour, Step: time.Hour},
}

// ParseRange finds a range by key.
func ParseRange(key string) (Range, bool) {
	for _, r := range Ranges {
		if r.Key == key {
			return r, true
		}
	}
	return Range{}, false
}

// SeriesRange is Series for the last r.Span up to now.
func (s *Service) SeriesRange(ctx context.Context, host string, metric Metric, r Range) (Series, error) {
	now := s.now()
	return s.Series(ctx, host, metric, now.Add(-r.Span), now, r.Step)
}

// Series returns the points of one metric of one host in [from, to) in
// buckets of step. The grid is anchored at the unix epoch: from is rounded
// down and to up to a multiple of step, so repeated polls produce the same
// bucket boundaries. Ranges that begin within the minute retention and ask for
// a step below one hour are answered from minutes; everything else from hours
// (with the current, not yet rolled-up hour taken from minutes), and then the
// step is at least one hour. Buckets without data have NaN values.
func (s *Service) Series(ctx context.Context, host string, metric Metric, from, to time.Time, step time.Duration) (Series, error) {
	metric, err := ParseMetric(string(metric))
	if err != nil {
		return Series{}, err
	}
	if host == "" || step < time.Second || !to.After(from) {
		return Series{}, fmt.Errorf("%w: host, step and range are required", ErrInvalidQuery)
	}
	now := s.now()
	table := store.Metrics1h
	if step < time.Hour && !from.Before(now.Add(-s.minuteRetention-minuteSlack)) {
		table = store.Metrics1m
	}
	step = step.Truncate(time.Second)
	if floor := time.Duration(table.Width()) * time.Second; step < floor {
		step = floor
	}
	stepS := int64(step / time.Second)
	fromU := floorDiv(from.Unix(), stepS) * stepS
	toU := (to.Unix() + stepS - 1) / stepS * stepS
	n := (toU - fromU) / stepS
	if n > maxSeriesPoints {
		return Series{}, fmt.Errorf("%w: %d points (max %d)", ErrTooManyPoints, n, maxSeriesPoints)
	}

	out := Series{
		Host: host, Metric: metric, Unit: metric.unit(), From: time.Unix(fromU, 0).UTC(),
		Step: step, Source: table, Points: make([]Point, n),
	}
	for i := range out.Points {
		out.Points[i] = Point{Time: out.From.Add(time.Duration(i) * step), Avg: math.NaN(), Max: math.NaN()}
	}
	q := store.MetricQuery{
		Table: table, Host: host, From: out.From, To: time.Unix(toU, 0).UTC(), Step: step,
	}
	if table == store.Metrics1h {
		// Minutes of hours that are not rolled up yet: the current hour and,
		// briefly after a restart, the previous one.
		q.TailFrom = now.Truncate(time.Hour).Add(-time.Hour)
	}

	if mount, ok := metric.Mount(); ok {
		return s.diskSeries(ctx, q, mount, out)
	}
	col := map[Metric]store.MetricColumn{
		MetricCPU: store.ColCPU, MetricMem: store.ColMem, MetricTemp: store.ColTemp,
		MetricNetRx: store.ColNetRx, MetricNetTx: store.ColNetTx,
	}[metric]
	buckets, err := s.st.QueryMetricBuckets(ctx, q, col)
	if err != nil {
		return Series{}, err
	}
	for _, b := range buckets {
		if b.Index < 0 || b.Index >= len(out.Points) {
			continue
		}
		out.Points[b.Index].Avg, out.Points[b.Index].Max = b.Avg, b.Max
		if metric == MetricMem {
			out.Total = math.Max(out.Total, float64(b.Total))
		}
	}
	return out, nil
}

func (s *Service) diskSeries(ctx context.Context, q store.MetricQuery, mount string, out Series) (Series, error) {
	rows, err := s.st.QueryDiskRows(ctx, q)
	if err != nil {
		return Series{}, err
	}
	type acc struct {
		w, sum float64
	}
	accs := make([]acc, len(out.Points))
	stepS := int64(out.Step / time.Second)
	for _, r := range rows {
		i := int((r.Time.Unix() - out.From.Unix()) / stepS)
		if i < 0 || i >= len(accs) {
			continue
		}
		for _, d := range r.Disks {
			if d.Mount != mount {
				continue
			}
			a := &accs[i]
			a.w += float64(r.Samples)
			a.sum += float64(d.Used) * float64(r.Samples)
			out.Total = math.Max(out.Total, float64(d.Total))
		}
	}
	for i, a := range accs {
		if a.w > 0 {
			// Usage is stored as an average only: Max equals Avg.
			out.Points[i].Avg = a.sum / a.w
			out.Points[i].Max = out.Points[i].Avg
		}
	}
	return out, nil
}

// Mounts lists the mount points of a host that appear in its latest history
// row (empty if the host has no history). Use it to offer the disk series.
func (s *Service) Mounts(ctx context.Context, host string) ([]string, error) {
	r, err := s.st.LatestMetric(ctx, host)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	mounts := make([]string, len(r.Disks))
	for i, d := range r.Disks {
		mounts[i] = d.Mount
	}
	return mounts, nil
}

func floorDiv(a, b int64) int64 {
	q := a / b
	if a%b != 0 && (a < 0) != (b < 0) {
		q--
	}
	return q
}
