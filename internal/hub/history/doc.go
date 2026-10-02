// Package history keeps the metrics history of the hub: it turns the live
// samples of the agents (grid.EventMetrics, every 2 s) into minute and hour
// buckets in SQLite (tables metrics_1m and metrics_1h, decisions #33/#49) and
// answers the chart queries of the History view.
//
// # Write path
//
// Service.Run subscribes to the grid, aggregates samples per host and minute
// in memory (average and maximum) and writes a minute only after it has closed,
// all closed minutes of all hosts in ONE transaction per flush, so an SD card
// sees roughly one write burst per minute instead of one per sample. When an
// hour closes the minutes are rolled into an hour row (sample-weighted
// averages, maximum of the maxima). Retention runs hourly: minutes are kept
// MinuteRetention (7 days), hours for the history retention (below). Once a day
// old audit entries are pruned (never the newest store.AuditKeepNewest).
//
// A host that is offline delivers no samples, so it gets no rows: gaps in the
// history are real gaps, never zeros. Buffered samples an agent replays after a
// reconnect carry their original timestamp and are merged into the right
// minute. Run flushes the open minute when its context ends, so a clean
// shutdown loses no data; wait for Run to return before closing the store.
//
// # Retention: one source of truth
//
// The setup wizard writes storage.history.hour_days to nexus.yaml; that value
// is only the default. The settings key history.retention_days (written by the
// Settings view through SetRetentionDays) overrides it as soon as it exists.
// RetentionDays returns the effective value. Shortening the period deletes the
// older hours at the next hourly run; the Settings view should warn about it.
// Audit retention is the settings key audit.retention_days (default 365,
// 30-3650), see AuditRetentionDays / SetAuditRetentionDays.
//
// # Read path (History view)
//
// Service.Series(ctx, host, metric, from, to, step) returns evenly spaced
// points. Use Ranges for the three standard ranges (24 h at 5 min, 7 d at
// 30 min, 30 d at 1 h) and Service.SeriesRange for "the last 24 h". Points
// without data have NaN in Avg and Max (use math.IsNaN; NaN cannot be
// JSON-encoded, so the view must turn it into a gap itself). Metric values:
//
//	cpu      percent, 0-100
//	mem      used bytes; Series.Total is the installed memory (percent = avg/total)
//	temp     degrees Celsius; hosts without a sensor yield only gaps
//	net_rx   bytes per second
//	net_tx   bytes per second
//	disk:<mount>  used bytes of that mount (Max equals Avg); Series.Total is its size
//
// Service.Mounts lists the mounts of a host for the disk selector.
package history
