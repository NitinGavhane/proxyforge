-- Phase 3 P5: scanner issues
CREATE TABLE IF NOT EXISTS issues (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    check_id   TEXT NOT NULL,
    title      TEXT NOT NULL,
    severity   TEXT NOT NULL,   -- info | low | medium | high | critical
    confidence TEXT NOT NULL,   -- certain | firm | tentative
    host       TEXT NOT NULL,
    port       INTEGER NOT NULL DEFAULT 0,
    path       TEXT NOT NULL DEFAULT '',
    detail     TEXT NOT NULL DEFAULT '',
    evidence_flow_id INTEGER,
    scan_id    INTEGER NOT NULL DEFAULT 0,
    created    INTEGER NOT NULL,
    UNIQUE(check_id, host, port, path, scan_id)
);
CREATE INDEX IF NOT EXISTS idx_issues_host ON issues(host);
