-- M6: match & replace rules
CREATE TABLE IF NOT EXISTS match_replace_rules (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    name      TEXT NOT NULL,
    enabled   INTEGER NOT NULL DEFAULT 1,
    direction TEXT NOT NULL,          -- request | response
    spec      TEXT NOT NULL,          -- JSON predicate (intercept.Spec)
    action    TEXT NOT NULL,          -- JSON action
    hits      INTEGER NOT NULL DEFAULT 0
);
