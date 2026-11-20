-- M7: target scope
CREATE TABLE IF NOT EXISTS scope_rules (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    kind    TEXT NOT NULL,    -- include | exclude
    pattern TEXT NOT NULL,    -- regex over scheme://host:port/path
    enabled INTEGER NOT NULL DEFAULT 1
);
