-- Phase 3 P1/P2: site-map endpoints + repeater tabs
CREATE TABLE IF NOT EXISTS endpoints (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    source    TEXT NOT NULL,   -- capture | import | discovery
    scheme    TEXT NOT NULL,
    host      TEXT NOT NULL,
    port      INTEGER NOT NULL,
    method    TEXT NOT NULL DEFAULT 'GET',
    path      TEXT NOT NULL,   -- path only (no query) for tree aggregation
    status    INTEGER,
    count     INTEGER NOT NULL DEFAULT 1,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    UNIQUE(scheme, host, port, method, path)
);
CREATE INDEX IF NOT EXISTS idx_endpoints_host ON endpoints(host);

CREATE TABLE IF NOT EXISTS repeater_tabs (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    name    TEXT NOT NULL,
    raw     TEXT NOT NULL,
    created INTEGER NOT NULL,
    updated INTEGER NOT NULL
);

ALTER TABLE flows ADD COLUMN tool_ref INTEGER NOT NULL DEFAULT 0;
CREATE INDEX IF NOT EXISTS idx_flows_origin_ref ON flows(origin, tool_ref);
