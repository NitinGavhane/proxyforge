-- ProxyForge schema v1 (Phase 1, M1)
-- One engagement = one SQLite file (WAL). Bodies live in flow_blobs as
-- zstd-compressed BLOBs; flows holds queryable metadata.

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS flows (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    started     INTEGER NOT NULL,          -- unix millis
    finished    INTEGER,
    duration_ms INTEGER,
    client_addr TEXT,
    server_addr TEXT,
    scheme      TEXT,
    http_version TEXT,
    method      TEXT,
    host        TEXT,
    port        INTEGER,
    path        TEXT,
    query       TEXT,
    status      INTEGER,
    resp_version TEXT,
    err         TEXT,
    origin      TEXT NOT NULL DEFAULT 'proxy',
    mitm        INTEGER NOT NULL DEFAULT 0,
    in_scope    INTEGER NOT NULL DEFAULT 1,
    truncated   INTEGER NOT NULL DEFAULT 0,
    req_size    INTEGER,
    resp_size   INTEGER,
    ws_count    INTEGER NOT NULL DEFAULT 0,
    comment     TEXT NOT NULL DEFAULT '',
    highlight   TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_flows_started ON flows(started DESC);
CREATE INDEX IF NOT EXISTS idx_flows_host    ON flows(host);
CREATE TABLE IF NOT EXISTS flow_blobs (
    flow_id  INTEGER NOT NULL REFERENCES flows(id) ON DELETE CASCADE,
    kind     TEXT    NOT NULL,  -- req_headers|req_body|req_trailer|resp_headers|resp_body|resp_trailer
    encoding TEXT    NOT NULL,  -- zstd|raw
    size     INTEGER NOT NULL,  -- uncompressed size
    sha256   TEXT    NOT NULL,
    content  BLOB    NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_blobs_flow_kind ON flow_blobs(flow_id, kind);

CREATE TABLE IF NOT EXISTS audit_log (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    ts     INTEGER NOT NULL,
    actor  TEXT NOT NULL,   -- ui|api|mcp:<client>|cli
    action TEXT NOT NULL,
    target TEXT,
    detail TEXT
);

-- FTS5 over decoded text; rowid == flows.id, maintained by the store layer.
CREATE VIRTUAL TABLE IF NOT EXISTS flows_fts USING fts5(
    method, host, path, headers, body,
    content=''
);
