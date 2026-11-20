-- Phase 3 P7: cookie jar, macros, organizer
CREATE TABLE IF NOT EXISTS cookies (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    host     TEXT NOT NULL,
    port     INTEGER NOT NULL DEFAULT 0,
    name     TEXT NOT NULL,
    value    TEXT NOT NULL,
    path     TEXT NOT NULL DEFAULT '/',
    secure   INTEGER NOT NULL DEFAULT 0,
    httponly INTEGER NOT NULL DEFAULT 0,
    samesite TEXT NOT NULL DEFAULT '',
    updated  INTEGER NOT NULL,
    UNIQUE(host, port, name, path)
);

CREATE TABLE IF NOT EXISTS macros (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    name    TEXT NOT NULL,
    flow_id INTEGER NOT NULL,
    created INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS organizer_items (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    flow_id INTEGER NOT NULL UNIQUE,
    note    TEXT NOT NULL DEFAULT '',
    tags    TEXT NOT NULL DEFAULT '',  -- comma-separated
    created INTEGER NOT NULL
);
