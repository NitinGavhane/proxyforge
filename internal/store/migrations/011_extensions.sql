-- Phase 3 P9: JS extensions
CREATE TABLE IF NOT EXISTS extensions (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    name    TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    code    TEXT NOT NULL,
    runs    INTEGER NOT NULL DEFAULT 0,
    errors  INTEGER NOT NULL DEFAULT 0,
    last_error TEXT NOT NULL DEFAULT '',
    created INTEGER NOT NULL,
    updated INTEGER NOT NULL
);
