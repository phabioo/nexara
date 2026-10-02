package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// MetricsTable selects the resolution of a history table.
type MetricsTable string

// The two history tables (see migration 0002).
const (
	Metrics1m MetricsTable = "metrics_1m" // one row per host and minute, kept 7 days
	Metrics1h MetricsTable = "metrics_1h" // one row per host and hour, kept per history.retention_days
)

// Width is the bucket size of the table in seconds.
func (t MetricsTable) Width() int64 {
	if t == Metrics1h {
		return 3600
	}
	return 60
}

func (t MetricsTable) valid() bool { return t == Metrics1m || t == Metrics1h }

// maxDisksPerRow bounds the JSON column; mount lists come from agents.
const maxDisksPerRow = 32

// DiskUsage is the usage of one mount inside a MetricRow.
type DiskUsage struct {
	Mount string `json:"m"`
	Used  uint64 `json:"u"` // bytes, bucket average
	Total uint64 `json:"t"` // bytes
}

// MetricRow is one history bucket of one host. Time is the bucket start (a
// multiple of the table's width, UTC). Samples is the weight used when rows are
// averaged again and is at least 1. Net rates are bytes per second. TempAvg and
// TempMax are nil when the host has no temperature sensor.
type MetricRow struct {
	HostID  string
	Time    time.Time
	Samples int

	CPUAvg, CPUMax         float64 // percent
	MemUsedAvg, MemUsedMax float64 // bytes
	MemTotal               uint64  // bytes
	TempAvg, TempMax       *float64
	NetRxAvg, NetRxMax     float64 // bytes per second
	NetTxAvg, NetTxMax     float64 // bytes per second
	Disks                  []DiskUsage
}

const metricCols = `host_id, ts, samples, cpu_avg, cpu_max, mem_used_avg, mem_used_max, mem_total,
	temp_avg, temp_max, net_rx_bps_avg, net_rx_bps_max, net_tx_bps_avg, net_tx_bps_max, disks`

func (r MetricRow) validate() error {
	switch {
	case r.HostID == "":
		return errors.New("store: metric row needs a host ID")
	case r.Samples < 1:
		return errors.New("store: metric row needs at least one sample")
	case r.Time.IsZero():
		return errors.New("store: metric row needs a time")
	}
	return nil
}

func (r MetricRow) args() ([]any, error) {
	if err := r.validate(); err != nil {
		return nil, err
	}
	disks := r.Disks
	if len(disks) > maxDisksPerRow {
		disks = disks[:maxDisksPerRow]
	}
	if disks == nil {
		disks = []DiskUsage{}
	}
	js, err := json.Marshal(disks)
	if err != nil {
		return nil, err
	}
	return []any{r.HostID, unix(r.Time), r.Samples, r.CPUAvg, r.CPUMax, r.MemUsedAvg, r.MemUsedMax,
		int64(r.MemTotal), nullFloat(r.TempAvg), nullFloat(r.TempMax),
		r.NetRxAvg, r.NetRxMax, r.NetTxAvg, r.NetTxMax, string(js)}, nil
}

func nullFloat(p *float64) any {
	if p == nil {
		return nil
	}
	return *p
}

func scanMetricRow(row interface{ Scan(...any) error }) (MetricRow, error) {
	var (
		r          MetricRow
		ts, total  int64
		tAvg, tMax sql.NullFloat64
		disks      string
	)
	if err := row.Scan(&r.HostID, &ts, &r.Samples, &r.CPUAvg, &r.CPUMax, &r.MemUsedAvg, &r.MemUsedMax, &total,
		&tAvg, &tMax, &r.NetRxAvg, &r.NetRxMax, &r.NetTxAvg, &r.NetTxMax, &disks); err != nil {
		return MetricRow{}, err
	}
	r.Time = fromUnix(ts)
	r.MemTotal = uint64(max(total, 0))
	if tAvg.Valid {
		v := tAvg.Float64
		r.TempAvg = &v
	}
	if tMax.Valid {
		v := tMax.Float64
		r.TempMax = &v
	}
	if err := json.Unmarshal([]byte(disks), &r.Disks); err != nil {
		return MetricRow{}, fmt.Errorf("corrupt disks of %s at %d: %w", r.HostID, ts, err)
	}
	return r, nil
}

// mergeUpsert adds the incoming bucket to an existing one of the same minute:
// the live path can deliver a minute in two pieces (shutdown and restart in
// the same minute, or buffered samples an agent replays after a gap). Averages
// are weighted by samples; a missing temperature on either side keeps the
// other. Disks and memory total come from the newer piece.
const mergeUpsert = ` ON CONFLICT(host_id, ts) DO UPDATE SET
	cpu_avg        = (cpu_avg * samples + excluded.cpu_avg * excluded.samples) / (samples + excluded.samples),
	cpu_max        = max(cpu_max, excluded.cpu_max),
	mem_used_avg   = (mem_used_avg * samples + excluded.mem_used_avg * excluded.samples) / (samples + excluded.samples),
	mem_used_max   = max(mem_used_max, excluded.mem_used_max),
	mem_total      = excluded.mem_total,
	temp_avg       = CASE WHEN temp_avg IS NULL THEN excluded.temp_avg
	                      WHEN excluded.temp_avg IS NULL THEN temp_avg
	                      ELSE (temp_avg * samples + excluded.temp_avg * excluded.samples) / (samples + excluded.samples) END,
	temp_max       = CASE WHEN temp_max IS NULL THEN excluded.temp_max
	                      WHEN excluded.temp_max IS NULL THEN temp_max
	                      ELSE max(temp_max, excluded.temp_max) END,
	net_rx_bps_avg = (net_rx_bps_avg * samples + excluded.net_rx_bps_avg * excluded.samples) / (samples + excluded.samples),
	net_rx_bps_max = max(net_rx_bps_max, excluded.net_rx_bps_max),
	net_tx_bps_avg = (net_tx_bps_avg * samples + excluded.net_tx_bps_avg * excluded.samples) / (samples + excluded.samples),
	net_tx_bps_max = max(net_tx_bps_max, excluded.net_tx_bps_max),
	disks          = excluded.disks,
	samples        = samples + excluded.samples`

func placeholders(n int) string { return strings.TrimSuffix(strings.Repeat("?, ", n), ", ") }

func (s *Store) writeMetrics(ctx context.Context, insert string, table MetricsTable, rows []MetricRow, suffix string, verb string) error {
	if len(rows) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: %s: %w", verb, err)
	}
	defer func() { _ = tx.Rollback() }()
	stmt, err := tx.PrepareContext(ctx, insert+" INTO "+string(table)+" ("+metricCols+") VALUES ("+placeholders(15)+")"+suffix)
	if err != nil {
		return fmt.Errorf("store: %s: %w", verb, err)
	}
	defer stmt.Close()
	for _, r := range rows {
		args, err := r.args()
		if err != nil {
			return fmt.Errorf("store: %s: %w", verb, err)
		}
		if _, err := stmt.ExecContext(ctx, args...); err != nil {
			return fmt.Errorf("store: %s: %w", verb, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: %s: %w", verb, err)
	}
	return nil
}

// MergeMetrics1m writes minute buckets in one transaction. A bucket that
// already exists is merged with the incoming one (see mergeUpsert), so a
// minute can be written in pieces. Rows must already be aligned to the minute.
func (s *Store) MergeMetrics1m(ctx context.Context, rows []MetricRow) error {
	return s.writeMetrics(ctx, "INSERT", Metrics1m, rows, mergeUpsert, "merge minute metrics")
}

// ReplaceMetrics replaces buckets of the given table (idempotent re-writes:
// the hour roll-up, the demo backfill). One transaction.
func (s *Store) ReplaceMetrics(ctx context.Context, table MetricsTable, rows []MetricRow) error {
	if !table.valid() {
		return fmt.Errorf("store: unknown metrics table %q", table)
	}
	return s.writeMetrics(ctx, "INSERT OR REPLACE", table, rows, "", "replace metrics")
}

// ListMetrics returns the buckets of one host with from <= Time < to, oldest first.
func (s *Store) ListMetrics(ctx context.Context, table MetricsTable, host string, from, to time.Time) ([]MetricRow, error) {
	if !table.valid() {
		return nil, fmt.Errorf("store: unknown metrics table %q", table)
	}
	rows, err := s.db.QueryContext(ctx,
		"SELECT "+metricCols+" FROM "+string(table)+" WHERE host_id = ? AND ts >= ? AND ts < ? ORDER BY ts",
		host, unix(from), unix(to))
	if err != nil {
		return nil, fmt.Errorf("store: list metrics: %w", err)
	}
	defer rows.Close()
	var out []MetricRow
	for rows.Next() {
		r, err := scanMetricRow(rows)
		if err != nil {
			return nil, fmt.Errorf("store: list metrics: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// LatestMetric returns the newest minute bucket of a host (ErrNotFound if none).
func (s *Store) LatestMetric(ctx context.Context, host string) (MetricRow, error) {
	r, err := scanMetricRow(s.db.QueryRowContext(ctx,
		"SELECT "+metricCols+" FROM metrics_1m WHERE host_id = ? ORDER BY ts DESC LIMIT 1", host))
	if errors.Is(err, sql.ErrNoRows) {
		return MetricRow{}, ErrNotFound
	}
	if err != nil {
		return MetricRow{}, fmt.Errorf("store: latest metric: %w", err)
	}
	return r, nil
}

// HostHour names the hour of a host.
type HostHour struct {
	HostID string
	Hour   time.Time // start of the hour
}

// UnrolledHours lists hours with minute data but no hour row, for hours that
// start in [from, before). The history service rolls them up.
func (s *Store) UnrolledHours(ctx context.Context, from, before time.Time) ([]HostHour, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT DISTINCT m.host_id, m.ts - m.ts % 3600 AS hr FROM metrics_1m m
		 WHERE m.ts >= ? AND m.ts < ?
		   AND NOT EXISTS (SELECT 1 FROM metrics_1h h WHERE h.host_id = m.host_id AND h.ts = m.ts - m.ts % 3600)
		 ORDER BY hr, m.host_id`, unix(from), unix(before))
	if err != nil {
		return nil, fmt.Errorf("store: unrolled hours: %w", err)
	}
	defer rows.Close()
	var out []HostHour
	for rows.Next() {
		var (
			h  HostHour
			hr int64
		)
		if err := rows.Scan(&h.HostID, &hr); err != nil {
			return nil, fmt.Errorf("store: unrolled hours: %w", err)
		}
		h.Hour = fromUnix(hr)
		out = append(out, h)
	}
	return out, rows.Err()
}

// PruneMetrics deletes minute buckets older than minutesBefore and hour
// buckets older than hoursBefore (bucket start strictly before the cutoff).
// A zero cutoff keeps that table untouched.
func (s *Store) PruneMetrics(ctx context.Context, minutesBefore, hoursBefore time.Time) (minutes, hours int64, err error) {
	del := func(table string, before time.Time) (int64, error) {
		if before.IsZero() {
			return 0, nil
		}
		res, err := s.db.ExecContext(ctx, "DELETE FROM "+table+" WHERE ts < ?", unix(before))
		if err != nil {
			return 0, fmt.Errorf("store: prune %s: %w", table, err)
		}
		return res.RowsAffected()
	}
	if minutes, err = del("metrics_1m", minutesBefore); err != nil {
		return 0, 0, err
	}
	if hours, err = del("metrics_1h", hoursBefore); err != nil {
		return minutes, 0, err
	}
	return minutes, hours, nil
}

// DeleteHostMetrics removes all history of a host (host removal). Unknown hosts are not an error.
func (s *Store) DeleteHostMetrics(ctx context.Context, host string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: delete host metrics: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	for _, t := range []MetricsTable{Metrics1m, Metrics1h} {
		if _, err := tx.ExecContext(ctx, "DELETE FROM "+string(t)+" WHERE host_id = ?", host); err != nil {
			return fmt.Errorf("store: delete host metrics: %w", err)
		}
	}
	return tx.Commit()
}

// MetricColumn selects the series QueryMetricBuckets aggregates.
type MetricColumn string

// Aggregatable series.
const (
	ColCPU   MetricColumn = "cpu"
	ColMem   MetricColumn = "mem"
	ColTemp  MetricColumn = "temp"
	ColNetRx MetricColumn = "net_rx"
	ColNetTx MetricColumn = "net_tx"
)

// columns are fixed strings; callers never influence the SQL text.
var metricColumnSQL = map[MetricColumn][2]string{
	ColCPU:   {"cpu_avg", "cpu_max"},
	ColMem:   {"mem_used_avg", "mem_used_max"},
	ColTemp:  {"temp_avg", "temp_max"},
	ColNetRx: {"net_rx_bps_avg", "net_rx_bps_max"},
	ColNetTx: {"net_tx_bps_avg", "net_tx_bps_max"},
}

// MetricQuery describes a bucketed range read. Buckets are Step seconds wide,
// counted from From; From must be a multiple of Step so the bucket grid is
// stable between calls.
type MetricQuery struct {
	Table MetricsTable
	Host  string
	From  time.Time
	To    time.Time // exclusive
	Step  time.Duration
	// TailFrom (hour table only, optional): minute buckets with Time >= TailFrom
	// whose hour has no hour row yet are read too, so a 30 day chart includes
	// the current, not yet rolled-up hour.
	TailFrom time.Time
}

// MetricBucket is one aggregated chart bucket. Index counts Step-wide buckets
// from the query's From. Avg is weighted by samples, Max is the largest
// maximum, Total the largest installed memory in the bucket.
type MetricBucket struct {
	Index int
	Avg   float64
	Max   float64
	Total uint64
}

// sourceSQL is the row source of a query: the table itself, plus the unrolled
// tail of the minute table for hour queries. cols is the select list after
// "ts, samples".
func (q MetricQuery) sourceSQL(cols string) string {
	base := fmt.Sprintf("SELECT ts, samples, %s FROM %s WHERE host_id = ?1 AND ts >= ?2 AND ts < ?3", cols, q.Table)
	if q.Table != Metrics1h || q.TailFrom.IsZero() {
		return base
	}
	return base + fmt.Sprintf(` UNION ALL SELECT m.ts, m.samples, %s FROM metrics_1m m
		WHERE m.host_id = ?1 AND m.ts >= max(?2, ?4) AND m.ts < ?3
		  AND NOT EXISTS (SELECT 1 FROM metrics_1h h WHERE h.host_id = m.host_id AND h.ts = m.ts - m.ts %% 3600)`,
		prefixCols(cols, "m."))
}

// prefixCols prefixes each identifier of a simple column list.
func prefixCols(cols, prefix string) string {
	parts := strings.Split(cols, ",")
	for i, p := range parts {
		parts[i] = prefix + strings.TrimSpace(p)
	}
	return strings.Join(parts, ", ")
}

func (q MetricQuery) check() error {
	switch {
	case !q.Table.valid():
		return fmt.Errorf("store: unknown metrics table %q", q.Table)
	case q.Step < time.Second || q.Step%time.Second != 0:
		return errors.New("store: metric query step must be whole seconds")
	case !q.To.After(q.From):
		return errors.New("store: metric query range is empty")
	case unix(q.From)%int64(q.Step/time.Second) != 0:
		return errors.New("store: metric query From must be a multiple of Step")
	}
	return nil
}

func (q MetricQuery) bucketSQL(c [2]string) string {
	return `WITH src(ts, samples, a, m, tot) AS (` + q.sourceSQL(c[0]+", "+c[1]+", mem_total") + `)
		SELECT (ts - ?2) / ?5 AS b, SUM(a * samples) * 1.0 / SUM(samples), MAX(m), MAX(tot)
		FROM src WHERE a IS NOT NULL GROUP BY b ORDER BY b`
}

// QueryMetricBuckets aggregates one series into Step-wide buckets in SQL; only
// buckets that contain data are returned (gaps are absent), ordered by index.
func (s *Store) QueryMetricBuckets(ctx context.Context, q MetricQuery, col MetricColumn) ([]MetricBucket, error) {
	if err := q.check(); err != nil {
		return nil, err
	}
	c, ok := metricColumnSQL[col]
	if !ok {
		return nil, fmt.Errorf("store: unknown metric column %q", col)
	}
	rows, err := s.db.QueryContext(ctx, q.bucketSQL(c),
		q.Host, unix(q.From), unix(q.To), unix(q.TailFrom), int64(q.Step/time.Second))
	if err != nil {
		return nil, fmt.Errorf("store: query metrics: %w", err)
	}
	defer rows.Close()
	var out []MetricBucket
	for rows.Next() {
		var (
			b   MetricBucket
			tot sql.NullInt64
		)
		if err := rows.Scan(&b.Index, &b.Avg, &b.Max, &tot); err != nil {
			return nil, fmt.Errorf("store: query metrics: %w", err)
		}
		b.Total = uint64(max(tot.Int64, 0))
		out = append(out, b)
	}
	return out, rows.Err()
}

// DiskRow is the disk part of a bucket.
type DiskRow struct {
	Time    time.Time
	Samples int
	Disks   []DiskUsage
}

// QueryDiskRows reads the per-mount usage of the buckets in the query range
// (same row source as QueryMetricBuckets), oldest first. Step is ignored but
// must still be valid.
func (s *Store) QueryDiskRows(ctx context.Context, q MetricQuery) ([]DiskRow, error) {
	if err := q.check(); err != nil {
		return nil, err
	}
	query := `WITH src(ts, samples, d) AS (` + q.sourceSQL("disks") + `) SELECT ts, samples, d FROM src ORDER BY ts`
	args := []any{q.Host, unix(q.From), unix(q.To)}
	if q.Table == Metrics1h && !q.TailFrom.IsZero() {
		args = append(args, unix(q.TailFrom)) // ?4 only exists in the SQL then
	}
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: query disks: %w", err)
	}
	defer rows.Close()
	var out []DiskRow
	for rows.Next() {
		var (
			r  DiskRow
			ts int64
			js string
		)
		if err := rows.Scan(&ts, &r.Samples, &js); err != nil {
			return nil, fmt.Errorf("store: query disks: %w", err)
		}
		r.Time = fromUnix(ts)
		if err := json.Unmarshal([]byte(js), &r.Disks); err != nil {
			return nil, fmt.Errorf("store: query disks: corrupt row at %d: %w", ts, err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
