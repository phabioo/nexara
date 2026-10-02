-- Nexara Nexus schema v2 (v0.2 foundations): metrics history and settings
-- (decisions #33, #49). Forward-only: this file is never edited once released.
--
-- metrics_1m / metrics_1h hold one row per host and time bucket. ts is the
-- bucket start (unix seconds, UTC; a multiple of 60 resp. 3600). The two
-- tables have the same columns:
--   samples       number of live samples (2 s apart) behind the bucket; the
--                 weight when buckets are averaged again (minutes -> hours ->
--                 chart steps). Always >= 1: a bucket exists only when the
--                 agent delivered data, a gap is a missing row, never zeros.
--   cpu_*         total CPU percent, 0-100.
--   mem_*         used memory in bytes (REAL: an average of integers);
--                 mem_total is the installed memory at the end of the bucket.
--   temp_*        SoC temperature in Celsius; NULL when the host has no sensor.
--   net_*_bps_*   throughput of the primary interface in BYTES per second
--                 (the name follows decision #49's "bps"; the unit is B/s).
--   disks         JSON array of per-mount usage, e.g.
--                   [{"m":"/","u":41000000000,"t":117000000000}]
--                 m = mount point, u = used bytes (bucket average, rounded),
--                 t = total bytes. A JSON column instead of a child table:
--                 usage changes slowly, the mount set differs per host, and a
--                 child table would multiply rows (a year of hours x 5 mounts
--                 x hosts) for data that is always read together with its
--                 bucket. The writer keeps at most 32 mounts per row.
--
-- No foreign key to hosts: history is deleted explicitly when a host is
-- removed (Store.DeleteHostMetrics), and the demo hub has no host rows.
-- WITHOUT ROWID makes the primary key (host_id, ts) the table itself: range
-- queries for one host are a single b-tree scan, and a row costs no extra
-- index entry (SD-card friendly).

CREATE TABLE metrics_1m (
    host_id         TEXT    NOT NULL,
    ts              INTEGER NOT NULL,
    samples         INTEGER NOT NULL CHECK (samples > 0),
    cpu_avg         REAL    NOT NULL,
    cpu_max         REAL    NOT NULL,
    mem_used_avg    REAL    NOT NULL,
    mem_used_max    REAL    NOT NULL,
    mem_total       INTEGER NOT NULL,
    temp_avg        REAL,
    temp_max        REAL,
    net_rx_bps_avg  REAL    NOT NULL,
    net_rx_bps_max  REAL    NOT NULL,
    net_tx_bps_avg  REAL    NOT NULL,
    net_tx_bps_max  REAL    NOT NULL,
    disks           TEXT    NOT NULL DEFAULT '[]',
    PRIMARY KEY (host_id, ts)
) WITHOUT ROWID;
-- Retention pruning deletes by age across all hosts.
CREATE INDEX metrics_1m_ts ON metrics_1m(ts);

CREATE TABLE metrics_1h (
    host_id         TEXT    NOT NULL,
    ts              INTEGER NOT NULL,
    samples         INTEGER NOT NULL CHECK (samples > 0),
    cpu_avg         REAL    NOT NULL,
    cpu_max         REAL    NOT NULL,
    mem_used_avg    REAL    NOT NULL,
    mem_used_max    REAL    NOT NULL,
    mem_total       INTEGER NOT NULL,
    temp_avg        REAL,
    temp_max        REAL,
    net_rx_bps_avg  REAL    NOT NULL,
    net_rx_bps_max  REAL    NOT NULL,
    net_tx_bps_avg  REAL    NOT NULL,
    net_tx_bps_max  REAL    NOT NULL,
    disks           TEXT    NOT NULL DEFAULT '[]',
    PRIMARY KEY (host_id, ts)
) WITHOUT ROWID;
CREATE INDEX metrics_1h_ts ON metrics_1h(ts);

-- Key-value state that the UI changes (history retention, update check,
-- backup options, ...). nexus.yaml stays startup configuration (decision #9).
-- Values are plain text: never store secrets here.
CREATE TABLE settings (
    key        TEXT    PRIMARY KEY,
    value      TEXT    NOT NULL,
    updated_at INTEGER NOT NULL
) WITHOUT ROWID;
