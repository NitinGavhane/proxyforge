# ProxyForge Architecture

Status: **Draft v1 — for approval before implementation**

ProxyForge is an open-source, Burp Suite–style intercepting web proxy for
**authorized** security testing, with first-class Claude Code MCP support.
Single Go binary: proxy engine + tools + local web UI + MCP server.

> For authorized security testing only. See README and LICENSE.

---

## 1. Principles

1. **Safety is engine-level, not UI-level.** Scope enforcement, rate limits,
   and confirmation gates live in the outbound path of the proxy engine. No
   tool (UI, REST, MCP) can bypass them because none of them open their own
   sockets — everything goes through the engine's outbound gate.
2. **Captured traffic is untrusted data.** It is never rendered as HTML in the
   UI, never interpolated into prompts without labeling, and always marked as
   untrusted in MCP results (pattern adopted from REA, see §12).
3. **One engagement, one file.** All state for an engagement lives in a single
   SQLite database (WAL). Copy the file, back up the engagement.
4. **Localhost by default.** Proxy listener, API, UI, and MCP HTTP endpoint
   bind to 127.0.0.1 unless explicitly changed; the API requires token auth.
5. **Stdlib-first.** net/http, crypto/tls, x/net/http2. Libraries only where
   they buy real leverage (SQLite, MCP SDK, UI stack).

## 2. System overview

```
                         ┌─────────────────────────────────────────────────────────────┐
   browser / app ───────►│                        ProxyForge (Go)                       │
   (proxy or SOCKS)      │                                                             │
                         │  Listener ──► Engine ──► Pipeline ──► Outbound Gate ──► net │
                         │   h1/h2/WS     MITM      scope ▸ M&R ▸        (scope,      │
                         │   CONNECT     CA/leaf    intercept ▸         rate limit,   │
                         │   pass-thru   certs      store ▸ events      origin tags)  │
                         │      │                                                     │
                         │      ▼                                                     │
                         │  SQLite (project file, WAL) ◄── Tools: Repeater, Intruder, │
                         │      │                        Scanner, Decoder, Comparer,  │
                         │      ▼                        Sequencer, Organizer         │
                         │  Control plane: REST + WebSocket (127.0.0.1, token auth)   │
                         │      ├──► embedded React UI (go:embed)                     │
                         │      └──► MCP server (stdio bridge + streamable HTTP)      │
                         └─────────────────────────────────────────────────────────────┘
                                Claude Code ──── MCP ────┘        User ── browser UI
```

Components:

| Component | Responsibility |
|---|---|
| **Engine** (`internal/proxy`) | Listeners, CONNECT, TLS MITM, HTTP/1.1 + HTTP/2, WebSocket proxying, upstream proxy/SOCKS, pass-through |
| **Pipeline** (`internal/flows`) | Per-message processing: scope → match&replace → intercept gate → upstream → response path → persistence → events |
| **Store** (`internal/store`) | SQLite schema, migrations, queries, FTS search, body blob compression |
| **Control plane** (`internal/api`) | REST + WebSocket for UI and programmatic clients; token auth; audit logging |
| **Tools** (`internal/tools`, Phase 3) | Repeater, Intruder, Scanner, Sequencer, session handling, import/export |
| **MCP** (`internal/mcp`, Phase 4) | stdio + streamable HTTP MCP server exposing proxy, history, tools, issues |
| **UI** (`ui/`, React+TS+Tailwind) | Intercept, history, target map, tools, settings; served from the binary |

## 3. Technology choices

| Decision | Choice | Rationale / alternatives rejected |
|---|---|---|
| Language | Go | Single static binary, cross-platform, stdlib HTTP/TLS, great concurrency model for a proxy |
| MITM engine | **Custom on `net/http` + `crypto/tls` + `x/net/http2`**, patterned after goproxy/martian | We need HTTP/2 on both legs, first-class pause/resume interception, and raw-level match&replace — none of which elazarl/goproxy (h1-only, callback model) or martian (maintenance mode, h1 downstream) provide natively. We borrow their proven ideas (CONNECT handling, modifier chain) without their constraints. |
| SQLite driver | `modernc.org/sqlite` (pure Go) | CGO-free → trivial cross-compile (linux/macOS/windows, amd64/arm64). FTS5 included for history search. `mattn/go-sqlite3` rejected: CGO cross-compile pain. |
| Body storage | BLOBs, zstd-compressed (`klauspost/compress`) | Engagements capture tens of thousands of flows; bodies dominate size. Cap per-body (configurable, default 8 MB) with truncation marker. |
| UI | React 19 + TypeScript + Tailwind + Vite, embedded via `go:embed` | Per brief. No runtime dependency on Node; `dist/` is committed at release time or built in CI. |
| MCP SDK | Official `modelcontextprotocol/go-sdk`, fallback `mark3labs/mcp-go` | Decide at Phase 4 start; contract designed to be SDK-independent. |
| Config | `~/.proxyforge/config.toml` (0600) + per-project DB | Global: ports, CA location, token. Project: everything else. |
| Defaults | Proxy `127.0.0.1:8080`, API/UI `127.0.0.1:8765`, MCP HTTP `127.0.0.1:8766` | All configurable; API picks a free port if bound. |

## 4. Proxy engine

### 4.1 Connection lifecycle

```
client conn
  ├─ plain HTTP request (absolute-form or origin-form) ──► pipeline (no MITM)
  └─ CONNECT host:port
       ├─ host in pass-through list ──► raw TCP splice (TLS untouched)
       ├─ TLS (ClientHello SNI) ──► MITM:
       │     1. leaf cert for SNI from cache, else mint (ECDSA P-256, 13-month,
       │        SANs from ClientHello/CONNECT), signed by install-local root CA
       │     2. ALPN negotiate: h2 ──► http2.Server.ServeConn(tlsConn)
       │                  http/1.1 ──► http.Server.ServeConn-with-hijack
       │     3. each request enters the pipeline as a Flow
       └─ CONNECT to non-TLS (rare) ──► raw tunnel, no parsing
```

- **Root CA**: generated per install on first run (`~/.proxyforge/ca/root.key`
  0600, `root.pem` public). `proxyforge ca export|remove` commands; removal
  documented one-liner per OS. Leaf cache in-memory + on-disk, keyed by
  (host, SAN set). RSA root option for legacy clients.
- **Upstream**: engine can chain through an HTTP proxy (CONNECT) or SOCKS5
  (`x/net/proxy`) for egress. Per-scope upstream selection (Phase 3).
- **Client certs**: per-scope client cert/key pairs for upstream mTLS.
- **TLS pass-through list**: exact host or wildcard; covers pinned apps where
  MITM would break the app (traffic still logged as tunnel metadata).

### 4.2 HTTP/2 strategy

Proxying is **request-level, not byte-level**: both legs decode to the same
internal `Flow` model (method, target, headers as ordered list, body, trailers,
HTTP version, pseudo-headers preserved). Downstream h2 (browser ↔ us) is
terminated by our TLS + `http2.Server`; upstream h2 (us ↔ server) via
`http.Transport{ForceAttemptHTTP2: true}`. Version mismatch is fine — we can
speak h1 to the client and h2 upstream and vice versa. HTTP/2-only
peculiarities (CONNECT for tunnels, extended CONNECT for WS, trailers) are
modeled in `Flow` from day one so later phases don't reshape storage.

WebSocket: h1 `Upgrade` → bidirectional byte pipe with frame-boundary capture
(opcode, payload, direction, timestamp) into `ws_messages`; messages also pass
through match&replace. h2 extended-CONNECT WS is a stretch goal (tracked, not
promised for Phase 1).

### 4.3 Flow pipeline

Every exchange (proxy traffic and tool traffic alike) is a **Flow**:

```
parse ──► scope check ──► match&replace (auto rules, req) ──► intercept gate (req)
      ──► outbound gate (origin tag, scope enforcement for tools, rate limit)
      ──► upstream send ──► match&replace (resp) ──► intercept gate (resp)
      ──► store (history/ws) ──► events (WS broadcast)
```

- **Intercept gate**: if any enabled rule matches, the flow parks in a queue
  (memory + persisted state). Holders: UI panel, REST, MCP. Actions: edit
  (raw/headers/body), **Forward**, **Drop**, **Forward all**. Queue survives
  daemon restart (state in SQLite).
- **Rules engine** shared by intercept and match&replace: predicates on scope
  match, method, URL regex, header, content-type, body regex, status code
  (responses); actions replace/remove/add header, body regex replace, raw
  byte replace. Boolean AND/OR composition.
- **Events**: append-only bus → WebSocket fan-out (new flow, intercept queue
  change, tool progress, scan findings).

## 5. Data model (SQLite, per project)

Core tables (outline; full DDL in migrations):

- `flows` — id, started/finished ts, client↔server addr, scheme, http_version,
  method, host, port, path, query, status, duration, size_req/resp, origin
  (`proxy|repeater|intruder|scanner|mcp|import`), tool_ref, comment, highlight,
  flags (in_scope, mitm'd, truncated)
- `flow_blobs` — flow_id, kind (req_headers/req_body/resp_headers/resp_body/
  trailers), zstd blob, sha256, encoding notes
- `ws_messages` — flow_id, direction, opcode, payload blob, ts
- `scope_rules` — include/exclude, regex, enabled
- `intercept_rules`, `match_replace_rules` — JSON predicate/action, enabled
- `sitemap` — host/path tree nodes aggregated from flows + imports (rea, HAR,
  OpenAPI)
- Phase 3+: `repeater_tabs`, `intruder_*`, `issues`, `organizer`, `sessions`,
  `macros`, `extensions`, `audit_log` (present from Phase 1)
- `flows_fts` — FTS5 over method/host/path/headers/decoded body text

Out-of-scope proxy traffic: **not stored**, counted only in a metrics counter
(so users can see the proxy is alive without polluting the engagement file).

## 6. Control plane

- REST under `/api/v1/*`: projects, flows (list/get/search with filters +
  paging), intercept queue, rules, scope, CA export, import/export, tools
  (Phase 3), audit. JSON only; bodies over a size budget are paged/truncated
  with explicit markers.
- WebSocket `/api/v1/events`: event stream for live UI.
- **Auth**: bearer token (32 random bytes, hex) generated on first run,
  stored in config (0600, created atomically — concurrent daemon/CLI
  first-starts converge on one token), printable via `proxyforge token`,
  rotatable with `proxyforge token rotate`. Every `/api/v1/*` route requires
  it; the UI *shell* loads without a token (it carries no data) so the token
  gate can render, then exchanges the token for a `SameSite=Strict`
  localhost session cookie. MCP (stdio) authenticates to the daemon with
  the same token read from config.
- **Audit log**: every state-changing call (API and MCP) records actor
  (`ui|api|mcp:<client>`), action, target, timestamp — append-only table +
  JSONL export. Present from Phase 1.

## 7. UI (React + TS + Tailwind)

Tabs mirror Burp's mental model: **Proxy** (Intercept, HTTP history, WebSockets
history), **Target** (site map, scope), **Repeater**, **Intruder**, **Decoder**,
**Comparer**, **Sequencer**, **Scanner**, **Organizer**, **Extensions**,
**Settings** — phased per plan. Phase 1 ships Proxy + Target-scope + Settings.

Rendering rule: request/response bodies render as **text** in a monospace
editor (hex/image preview optional) — never as HTML. Comments, highlights,
per-row diff (Phase 1: request/response diff between two flows).

## 8. Safety architecture (all phases)

| Control | Mechanism |
|---|---|
| Scope enforcement | Engine-level **outbound gate**. Proxy-origin traffic may leave scope (it's just a pass-through proxy) but is then not logged; **tool-origin traffic** (repeater/intruder/scanner/mcp) must target in-scope hosts or the gate refuses the connection — before any bytes leave. Refusals logged to audit. |
| Active-tool confirmation | First active request per engagement session per tool requires an explicit confirm (UI button / MCP `confirm` call with scope echo). Opt-out per session, never per config-file default. |
| Rate limits | Default: global 10 req/s, 2 concurrent per target host for scanner/intruder; configurable, shown live in UI. |
| Prompt-injection defense | Every MCP result containing captured content carries `_meta.provenance.untrusted_content: true` (REA pattern); tool descriptions instruct treating it as data. API responses carry an equivalent header (`X-Untrusted-Content: captured`). Captured bodies are never auto-executed, never rendered as HTML, and MCP body results are size-budgeted. |
| Network posture | 127.0.0.1 bind for API/UI/MCP; token auth; proxy listener is the only optionally non-local bind, defaulting to 127.0.0.1. |
| CA hygiene | Key 0600, never leaves the machine except explicit export; `proxyforge ca remove` documented for all three OSes; UI banner when CA is installed into a system trust store. |
| Audit | Append-only `audit_log`; JSONL export; MCP actions attributed. |
| Secrets hygiene | Optional redaction pass on exports (authorization/cookie headers, URL userinfo — REA's redaction list). |

## 9. Extension system (Phase 3 sketch)

Go plugins (`plugin` package) don't work cross-platform — rejected. Plan:
**WASM components via wazero** (pure-Go runtime) for payload generators /
checks / handlers with capability-based host functions (no ambient socket
access — a plugin sends requests only through the engine's outbound gate,
inheriting all safety controls), plus a **JS hook** (`goja`) for lightweight
request/response scripting (Burp "montoya-in-JS" analog). Details and API
freeze in Phase 3 design doc.

## 10. MCP server (Phase 4 sketch)

- **Transports**: streamable HTTP on `127.0.0.1:8766` (token auth) and stdio
  (`proxyforge mcp` child process bridging to the daemon over localhost).
- **Tools** (as briefed): `proxy_status`, `list_history`, `get_request`,
  `search_traffic`, `intercept_enable/disable`, `list_intercepted`,
  `forward/drop/modify_intercepted`, `repeater_send`, `repeater_history`,
  `intruder_create/start/stop/results`, `scanner_start`, `list_issues`,
  `get_issue`, `scope_get/set`, `match_replace_add/list/remove`,
  `decode/encode`, `compare`, `jwt_inspect`, `sitemap_get`, `export_report`.
- **Resources**: history pages, issues; **prompts**: analyze-auth-flow,
  find-idor-candidates, summarize-attack-surface.
- Every tool result is size-budgeted with paging; captured content always
  provenance-marked; active tools flow through the outbound gate (scope,
  confirmation, rate limit) and the audit log.
- Ships `.mcp.json` example + `CLAUDE.md` workflow.

## 11. REA reference project — where it fits

[morluto/rea](https://github.com/morluto/rea) (MIT) is an MCP server + CLI
giving agents reverse-engineering tools: native binaries (via Hopper/Ghidra/
IDA/Kuna), JS/Electron apps, .NET, APKs, Android devices (ADB), Frida, pcaps,
and **offline analysis of saved network captures (HAR/Fiddler SAZ/mitmproxy
flows)** with credential redaction and provenance markers.

**Relationship — complementary, not embedded:**

| ProxyForge | REA |
|---|---|
| Sees the **wire**: live traffic, intercept, active tools | Sees the **client**: binary/app internals, embedded endpoints, pinning logic |

Concrete integration points (all optional, no hard dependency):

1. **Side-by-side MCP servers** — Claude Code runs both; no code required.
2. **HAR interchange** — ProxyForge exports HAR; REA's
   `inspect_web_network_capture` already ingests HAR offline (works today).
3. **Endpoint import → site map** (Phase 3/4) — `sitemap_import` API/MCP tool
   accepts endpoint lists; Claude extracts endpoints with REA from an APK/
   Electron bundle, imports into ProxyForge's Target map, and diffs against
   observed traffic → **shadow-API discovery** (endpoints that exist in the
   client but were never exercised).
4. **Design patterns adopted** (credited): untrusted-content provenance
   markers, capture redaction list, decoder resource budgets.

Explicitly **not** adopted: REA's Node/TS stack, its binary-analysis providers
(out of scope for a proxy), or any coupling that forces users to install REA.

## 12. Repository layout

```
proxyforge/
  cmd/proxyforge/          # main: daemon, UI, CLI subcommands (ca, token, mcp, import)
  internal/
    config/                # global config, project resolution
    ca/                    # root CA, leaf minting, cache, export/remove
    proxy/                 # engine: listeners, CONNECT, MITM, h1/h2, ws, upstream, socks
    flows/                 # Flow model, pipeline, rules, intercept queue, events bus
    scope/                 # scope rule evaluation (shared by pipeline + gate + UI)
    store/                 # sqlite, migrations (embed), queries, fts, blobs
    api/                   # REST + WS, auth, audit
    tools/                 # phase 3: repeater, intruder, scanner, sequencer, sessions
    ext/                   # phase 3: wasm + js extension host
    mcp/                   # phase 4: MCP server + stdio bridge
    audit/                 # audit log writer + JSONL export
  ui/                      # React app (vite), embedded at build
  docs/                    # ARCHITECTURE, PHASE1_PLAN, FEATURE_PARITY, plugin guide
  demos/juice-shop/        # docker-compose + demo script
  scripts/                 # build, release, cross-compile
  .github/workflows/       # CI: go test, ui build/test, e2e, release matrix
```

## 13. Testing strategy

- **Unit**: rules engine, scope matcher, cert minting, flow parse/serialize
  round-trips (golden bytes), storage, redaction.
- **Integration** (Go): spin engine against `httptest` servers — h1, h2,
  TLS-with-test-CA, WS echo, upstream-proxy chains; drive with real client
  transports; assert captures, intercept semantics, M&R effects, scope gate
  refusals.
- **E2E**: Juice Shop (docker-compose) demo script — curl/browser through
  proxy, intercept-and-edit flow, MITM HTTPS, export HAR — scripted
  assertions; also the user-facing demo.
- **UI**: vitest component tests; Playwright smoke against the served UI in CI
  (Phase 1 exit: history list renders, intercept forward works).
- **CI**: GitHub Actions — `go vet/test/race`, UI build+test, e2e job, release
  matrix cross-compiling linux/macOS/windows (amd64/arm64) with embedded UI.

## 14. Risks & open questions

| Risk | Mitigation |
|---|---|
| HTTP/2 edge cases (trailers, extended-CONNECT, priorities) | Model in Flow early; h2 downstream via x/net/http2 is well-trodden (h2 proxies exist in Go); fall back to h1 downstream per-host if a client breaks (config flag per host) |
| modernc SQLite throughput under load | WAL + prepared statements + batch inserts; benchmark in M1; escape hatch: swap driver behind store interface (mattn) without schema change |
| Cert trust UX (Firefox vs Chromium vs system store) | Phase 2: `http://proxy.local` CA page with per-browser instructions + automated trust for launched browser profile |
| MCP SDK maturity at Phase 4 | Contract designed SDK-agnostic; two candidate SDKs; decide on streamable-HTTP maturity then |
| Body truncation breaking analyst workflows | Explicit truncated flag + full-body fetch from blob by id; configurable cap |
| Scope regex footguns (overbroad include) | Scope editor shows live match preview against recent history before save |

## 15. Phase map

| Phase | Delivers |
|---|---|
| **1** | Engine (h1, h2, MITM, WS, upstream/SOCKS, pass-through), intercept + rules, history + FTS + diff, M&R, scope, audit, token auth, UI (Proxy/Settings), CI, Juice Shop demo |
| **2** | Launched browser (CDP, throwaway profile, trusted CA), `http://proxy.local` CA page, manual proxy docs, optional tagging extension |
| **3** | Target site map + content discovery, Repeater, Intruder (4 modes, payload sets, grep), Decoder, Comparer, Sequencer, passive + opt-in active Scanner, self-hosted OOB collaborator, session handling/macros, logger + HAR/Burp import/export, Organizer, extensions (WASM/JS), OpenAPI/Postman/cURL import, reporting |
| **4** | MCP server (stdio + streamable HTTP), resources, prompts, `.mcp.json`, `CLAUDE.md`, audit review UI |
