-- M4: WebSocket message capture
CREATE TABLE IF NOT EXISTS ws_messages (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    flow_id    INTEGER NOT NULL REFERENCES flows(id) ON DELETE CASCADE,
    ts         INTEGER NOT NULL,       -- unix millis
    direction  TEXT NOT NULL,          -- c2s | s2c
    opcode     INTEGER NOT NULL,       -- RFC 6455: 0 continuation, 1 text, 2 binary, 8 close, 9 ping, 10 pong
    fin        INTEGER NOT NULL DEFAULT 1,
    compressed INTEGER NOT NULL DEFAULT 0, -- RSV1 permessage-deflate marker
    size       INTEGER NOT NULL,
    encoding   TEXT NOT NULL,          -- raw | zstd (blob compression)
    payload    BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ws_flow ON ws_messages(flow_id, id);
