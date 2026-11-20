-- M5: intercept queue + rules
CREATE TABLE IF NOT EXISTS intercept_rules (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    name    TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    spec    TEXT NOT NULL -- JSON predicate
);

CREATE TABLE IF NOT EXISTS intercept_queue (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         INTEGER NOT NULL,
    state      TEXT NOT NULL, -- pending_req | pending_resp | forwarded | completed | dropped | restarted
    is_response INTEGER NOT NULL DEFAULT 0,
    snapshot   TEXT NOT NULL -- JSON flow snapshot at park time
);
CREATE INDEX IF NOT EXISTS idx_intercept_state ON intercept_queue(state);
