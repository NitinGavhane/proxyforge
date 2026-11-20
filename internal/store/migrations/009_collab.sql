-- Phase 3 P6: OOB collaborator
CREATE TABLE IF NOT EXISTS collab_canaries (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    canary  TEXT NOT NULL UNIQUE,
    label   TEXT NOT NULL DEFAULT '',
    created INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS collab_interactions (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    ts      INTEGER NOT NULL,
    canary  TEXT NOT NULL DEFAULT '',
    label   TEXT NOT NULL DEFAULT '',
    proto   TEXT NOT NULL,           -- http | dns
    src     TEXT NOT NULL DEFAULT '',
    method  TEXT NOT NULL DEFAULT '',
    host    TEXT NOT NULL DEFAULT '',
    path    TEXT NOT NULL DEFAULT '',
    detail  TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_collab_interactions_canary ON collab_interactions(canary);
