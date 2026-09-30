-- Nexara Nexus schema v1 (v0.1 subset).
--
-- Conventions: all timestamps are INTEGER unix seconds, UTC. Booleans are
-- INTEGER 0/1. Nullable columns are NULL when unset. Text identifiers that are
-- hashes (token_hash, id_hash) are lower-case hex SHA-256 computed by the caller.
--
-- Not created yet on purpose (later versions add them as new migrations):
--   metrics_1m, metrics_1h  (v0.2, history)
--   alerts                  (v0.3)

CREATE TABLE users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    operator_id     TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    pass_hash       TEXT    NOT NULL,               -- argon2id, encoded
    totp_secret_enc BLOB,                           -- encrypted with secret.key; NULL = none
    totp_enabled    INTEGER NOT NULL DEFAULT 0,
    role            TEXT    NOT NULL DEFAULT 'operator',
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL
);

CREATE TABLE sessions (
    id_hash      TEXT    PRIMARY KEY,               -- SHA-256 of the session ID, never the ID itself
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at   INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,                  -- idle timeout is measured from here
    expires_at   INTEGER NOT NULL,                  -- absolute limit (30 days)
    persistent   INTEGER NOT NULL DEFAULT 0,        -- "keep me signed in"
    ip           TEXT    NOT NULL DEFAULT '',
    user_agent   TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX sessions_user_id ON sessions(user_id);
CREATE INDEX sessions_expires_at ON sessions(expires_at);

CREATE TABLE hosts (
    id               TEXT    PRIMARY KEY,           -- opaque, 16 hex chars (store.NewID)
    name             TEXT    NOT NULL UNIQUE,       -- short unique name, used in URLs
    display_name     TEXT    NOT NULL DEFAULT '',
    address          TEXT    NOT NULL DEFAULT '',
    os               TEXT    NOT NULL DEFAULT '',
    arch             TEXT    NOT NULL DEFAULT '',
    agent_version    TEXT    NOT NULL DEFAULT '',
    cert_fingerprint TEXT    NOT NULL DEFAULT '',   -- SHA-256 of the client certificate, hex
    cert_serial      TEXT    NOT NULL DEFAULT '',
    cert_not_after   INTEGER,
    mac              TEXT    NOT NULL DEFAULT '',   -- for Wake-on-LAN
    capabilities     TEXT    NOT NULL DEFAULT '[]', -- JSON array of capability names
    revoked          INTEGER NOT NULL DEFAULT 0,
    created_at       INTEGER NOT NULL,
    last_seen_at     INTEGER
);
CREATE INDEX hosts_cert_fingerprint ON hosts(cert_fingerprint);

CREATE TABLE enroll_tokens (
    token_hash TEXT    PRIMARY KEY,                 -- SHA-256 of the one-time code
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at    INTEGER,                             -- NULL = unused
    host_id    TEXT    REFERENCES hosts(id) ON DELETE SET NULL
);
CREATE INDEX enroll_tokens_expires_at ON enroll_tokens(expires_at);

CREATE TABLE audit_log (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    ts     INTEGER NOT NULL,
    "user" TEXT    NOT NULL DEFAULT '',             -- operator id, or "system"
    host   TEXT    NOT NULL DEFAULT '',             -- host name or ID; free text, no FK so entries outlive hosts
    action TEXT    NOT NULL,                        -- e.g. "login", "job.apt_upgrade", "shell.open"
    detail TEXT    NOT NULL DEFAULT '',
    result TEXT    NOT NULL                         -- "ok", "error" or "denied"
);
CREATE INDEX audit_log_ts ON audit_log(ts);
