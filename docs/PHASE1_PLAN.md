# Phase 1 Plan — Proxy core + Intercept

Status: **Draft v1 — for approval before implementation**

Goal: a working intercepting proxy you can point a browser at, with HTTPS
MITM, HTTP/2, WebSocket capture, interception with edit/forward/drop, match &
replace, scope, searchable history, and the local UI — tested end to end
against OWASP Juice Shop.

Sequencing is milestone-based; each milestone ends green (tests + CI) before
the next starts. Rough effort order is M1 → M8; M0 is scaffolding.

---

## M0 — Scaffolding & CI

- Go module, `cmd/proxyforge`, package skeletons, MIT LICENSE, README stub,
  CONTRIBUTING stub, `.gitignore`.
- GitHub Actions: `go vet`, `go test -race ./...`, `gofmt` check; UI job
  placeholder. Release workflow skeleton (cross-compile matrix, embedded UI).
- Vite React+TS+Tailwind hello-world embedded via `go:embed`, served at
  `127.0.0.1:8765` behind token auth.

**Exit criteria:** `go test ./...` green; `proxyforge` binary serves the UI
locally; CI runs on push.

## M1 — Plain HTTP proxy + history + store

- `internal/store`: SQLite (modernc, WAL), embedded migrations, `flows` +
  `flow_blobs` + FTS5, zstd body blobs, truncation flag.
- `internal/proxy` listener: absolute-form and origin-form HTTP/1.1 proxying
  via `http.Transport`; CONNECT handled in M2 (error clearly for now).
- Pipeline skeleton: parse → store → event; flow model (ordered headers,
  pseudo-headers, trailers, http_version) with golden round-trip tests
  (h1 and h2 fixtures).
- REST: `GET /flows` (filter/sort/page), `GET /flows/{id}` (paged bodies),
  `WS /events`. Token auth (config 0600, `proxyforge token`).
- Audit log table + writer (wired to every mutating endpoint).
- UI: HTTP history table (filter/search/sort), request/response viewer
  (text-only rendering), comment + highlight.

**Tests:** httptest h1 upstream; client (net/http configured with ProxyURL)
through engine → assert captured flow equality vs server-seen request; FTS
search hits; body truncation marker; auth 401 without token.
**Exit:** browse Juice Shop over plain HTTP through ProxyForge; history fills
and is searchable.

## M2 — HTTPS MITM

- `internal/ca`: per-install root CA (ECDSA P-256; RSA option), leaf minting
  (13-month, SANs from CONNECT/SNI), in-memory + disk cache; `ca export /
  remove` CLI; key perms 0600 (chmod enforced at startup).
- CONNECT handling → MITM path: terminate TLS with leaf, serve h1 downstream
  (ALPN h2 comes in M3), upstream via TLS-capable Transport.
- TLS pass-through list (host/wildcard) → raw splice + tunnel-metadata-only
  logging.
- Upstream proxy chaining (HTTP CONNECT) + SOCKS5 egress; per-project setting.
- Client certificates for upstream mTLS (per-scope pairs).

**Tests:** engine CA mint → openssl verify chain; HTTPS httptest upstream;
client with ProxyURL + custom RootCAs → end-to-end GET/POST captured (headers,
body, TLS version/SNI recorded); pass-through host yields zero decrypted
flows but a tunnel entry; chained-proxy test via second local proxy.
**Exit:** browser pointed at ProxyForge (CA manually trusted) browses HTTPS
sites; history shows decrypted flows.

## M3 — HTTP/2

- Downstream: ALPN `h2` on MITM conns → `http2.Server.ServeConn`; upstream:
  `ForceAttemptHTTP2`. Version mismatch legs supported both directions.
- Flow records negotiated versions; UI shows protocol badge.
- Per-host downstream-downgrade flag (h2 → h1) for misbehaving clients.

**Tests:** httptest h2 upstream via `http2.Transport`; client h2 through MITM
(GET, POST body, trailers); h2→h1 and h1→h2 leg-mismatch cases; concurrent
stream stress (e.g. 100 parallel requests) with `-race`.
**Exit:** Chrome (h2) through proxy to an h2 origin; flows marked `HTTP/2`.

## M4 — WebSocket proxying & capture

- h1 `Upgrade` hijack → bidirectional pipe; frame capture (direction, opcode,
  payload, ts, compressed-frame note) into `ws_messages`; close/reconnect
  metadata on the flow.
- WS messages visible in UI (per-flow WebSocket tab) and via REST paging.
- Match & replace applied to text frames (M6 wires the rules; hook lands here).

**Tests:** local WS echo server (gorilla or x/net); client through proxy:
send/receive/close asserted on both legs + captured messages equal; large
fragmented frames; binary frames stored intact.
**Exit:** Juice Shop / ws-echo demo traffic captured frame-by-frame in UI.

## M5 — Intercept

- Intercept gate in pipeline: enabled rules → flow parks (state machine:
  `pending_req → forwarded → pending_resp → completed | dropped`), persisted,
  survives restart.
- Rules: scope-match, method, URL regex, header, content-type, body regex
  (Phase 1 predicate set); enable/disable master toggle.
- Actions: edit raw request/headers/body, **Forward**, **Drop**,
  **Forward all**; response interception toggle (Burp parity).
- UI: Intercept tab — queue list, editor panes, action buttons, keyboard
  shortcuts (⌘F forward, ⌘D drop).
- REST + events: `GET/POST /intercept/*` (list, get, modify, forward, drop,
  forward-all) — same endpoints MCP will reuse in Phase 4.

**Tests:** rule match → flow parks (upstream receives nothing until forward);
edit-then-forward mutates upstream-seen request; drop → no upstream conn;
response interception parks before delivery to client; restart-mid-intercept
recovery; forward-all drains queue in order.
**Exit:** live demo — pause a Juice Shop login request, edit credentials,
forward, observe modified auth response.

## M6 — Match & Replace

- Rule engine shared with intercept predicates; actions: replace/add/remove
  header, body regex replace, raw byte replace; direction: request/response;
  ordering + enable flags; per-rule hit counter.
- UI: rules table with live "recent matches" preview.
- REST CRUD + audit entries.

**Tests:** header rewrite observed upstream; regex body rewrite (capture
groups); response rule modifies client-seen body; disabled rule inert; hit
counters accurate; ordering stable.
**Exit:** demo — auto-add header / rewrite host on the fly.

## M7 — Scope enforcement & safety baseline

- `internal/scope`: include/exclude regex rules, enabled set, live-match
  preview against recent history in UI.
- Pipeline behavior: out-of-scope proxy traffic passes through but is **not
  logged** (counter only); intercept rules can't match out-of-scope traffic.
- Outbound gate lands now (origin tags on all flows; tool-origin enforcement
  activates in Phase 3, but the gate + refusal logging exist and are tested
  with a synthetic tool origin).
- Audit export (`GET /audit.jsonl`), token rotation CLI.

**Tests:** out-of-scope request → pass-through, zero rows, counter+1;
scope-change retroactivity explicit (no silent re-filtering of stored flows);
synthetic tool-origin out-of-scope request → gate refusal + audit row; regex
preview matches engine truth on sampled history.
**Exit:** scope tab usable; out-of-scope noise gone from history.

## M8 — Polish, demo, docs

- History diff view (two flows, word/byte level — shared with Phase 3
  Comparer), keyboard navigation, column chooser, export selection to HAR
  (single-flow and filtered-set; HAR schema-validated — feeds REA round-trip
  test).
- `demos/juice-shop/docker-compose.yml` + `demos/run-demo.sh`: scripted
  end-to-end (browse → intercept+edit → M&R → scope filtering → HAR export).
- Docs: README quick start (build, run, browser proxy + CA trust steps for
  Firefox/Chrome), docs/FEATURE_PARITY.md updated, Phase 1 retro +
  Phase 2 plan drafted.
- Playwright smoke in CI: launch UI, verify history render + intercept
  forward.

**Exit (Phase 1 definition of done):** all milestones green in CI; demo script
passes from clean checkout with only Docker + Go + Node required; every
feature above demonstrable against Juice Shop; FEATURE_PARITY.md current.

---

## Non-goals for Phase 1 (explicit)

Browser launcher (P2), site map/issues/scanner/repeater/intruder (P3),
MCP (P4), HTTP/3, h2 extended-CONNECT WebSocket, extension API. Data model
reserves for P3/P4 (origin tags, tool_ref, sitemap table) so no migrations
break later.

## Key packages & ownership

| Package | Owns |
|---|---|
| `internal/proxy` | conns, TLS, h1/h2 legs, WS pipe, upstream/SOCKS, pass-through |
| `internal/flows` | Flow model, pipeline, rules engine, intercept queue, events |
| `internal/store` | schema, migrations, queries, FTS, blobs |
| `internal/api` | REST/WS, auth, audit wiring |
| `internal/ca` | root/leaf certs, cache, export/remove |
| `internal/scope` | scope evaluation (single source of truth for pipeline + gate + UI) |

## Test matrix summary

| Area | Style |
|---|---|
| Flow parse/serialize | golden round-trip (h1/h2/weird-header fixtures) |
| Engine | integration vs httptest (h1/h2/TLS/WS/chained proxy), `-race` |
| Intercept | behavioral (park/edit/forward/drop/restart) |
| Rules & scope | table-driven unit + engine-level |
| Store | CRUD/FTS/paging + truncation |
| API | handler tests with token auth + audit assertions |
| E2E | Juice Shop demo script, Playwright smoke |
