# Burp Suite Feature Parity Checklist

Status legend: ✅ shipped · 🚧 in progress · 📅 planned (phase) · ⬜ not scheduled

Updated at: **ALL PHASES COMPLETE (1–4)** (2026-11-21). This table
is maintained every milestone. Phase 3 plan: `PHASE3_PLAN.md`; client setup:
`CLIENTS.md`.

| Feature | Burp equivalent | Status | Notes |
|---|---|---|---|
| HTTP/1.1 proxying | Proxy listener | ✅ M1 | absolute + origin form |
| HTTPS MITM (local CA) | Proxy listener / CA | ✅ M2 | per-install root, per-host leaves, openssl-verified chain |
| HTTP/2 (both legs) | HTTP/2 support | ✅ M3 | h2↔h1 mismatch legs supported; per-host downgrade list; trailers both directions |
| WebSocket proxying + capture | WebSockets history | ✅ M4 | frame-level capture (text/binary/fragmented/control), ws + wss, WS tab in UI, paged API |
| Upstream proxy / SOCKS | Upstream proxy servers | ✅ M2 | http(s) CONNECT chain + socks5 egress |
| TLS pass-through list | TLS pass through | ✅ M2 | wildcard hosts, opaque splice + tunnel records |
| Client certificates | Client TLS certs | ✅ M2 | per-host-pattern upstream mTLS |
| Intercept (pause/edit/forward/drop) | Proxy > Intercept | ✅ M5 | requests + responses, edits (method/path/headers/body/status), forward-all, queue survives restart as recovered rows |
| Intercept rules | Intercept rules | ✅ M5 | method/host/URL/content-type/header/body/status regex predicates, phase-aware |
| HTTP history (filter/search/sort) | HTTP history | ✅ M1 | FTS5 search |
| Highlight + comment | Annotations | ✅ M1 | |
| Request/response diff | Message editor diff | ✅ M8 | word + byte modes, 4 parts (req/resp × headers/body); full Comparer in P3 |
| HAR export | Export | ✅ M8 | HAR 1.2, single flow or filtered set, base64 for binary bodies |
| Match & Replace | Match and replace | ✅ M6 | header set/add/remove, body regex w/ capture groups, raw byte replace; shared predicates, stable order, hit counters + recent matches, audited CRUD |
| Target scope (in/out) | Target > Scope | ✅ M7 | engine-level: out-of-scope proxied but never logged/intercepted/modified; outbound gate refuses tool origins; live preview; `token rotate` |
| Audit log of actions | (Team/extension) | ✅ M1 | JSONL export |
| Token-auth localhost API | (none) | ✅ M1 | bearer + session cookie |
| Launch browser (isolated profile) | Burp's Chromium | ✅ P2 | `proxyforge browse` — chromium>chrome>edge detection, throwaway profile, optional session CA trust (`-trust-ca`) with automatic revert, `-dump` for scripting |
| CA download page | CA download | ✅ P2 | `http://proxy.local` virtual host served by the engine (never forwarded/logged/intercepted), UA-aware instructions, `/ca.pem` download |
| Browser tagging extension | (extension) | ✅ P2 | MV3 extension (`extension/`): context-menu "tag this site" → flows highlighted in history; audited `POST /api/v1/annotate-tab` |
| Site map tree | Target > Site map | ✅ P3/P1 | aggregated from every captured/tool flow; **REA endpoint import** with shadow detection (imported-but-never-observed flagged) |
| Content discovery | Content discovery | ✅ P3/P1 | wordlist jobs (built-in ~100 paths or custom), 404-baseline differencing, rate-limited (1–20 rps), stoppable, audited, scope-gated per request |
| Issues / scanner (passive) | Passive scanner | 📅 P3 | headers, CORS, CSP, secrets |
| Scanner (active, opt-in) | Active scanner | ✅ P3/P5+P6 | reflected XSS, SQLi error-based, open redirect, path traversal, **SSRF via OOB canary (high/certain)**, time-based command injection (tentative) — explicit confirm gate, per-check selection, rate-limited, scope-gated; IDOR heuristics deferred to P7 session handling |
| Repeater | Repeater | ✅ P3/P2 | tabs with persisted raw, per-tab history, follow-redirects (each hop its own flow, 30x→GET, auth/cookie dropped cross-origin), raw request editing (origin-form/absolute-form + X-Scheme hint); sends are scope-gated + audited |
| Intruder (4 modes + payloads) | Intruder | ✅ P3/P3 | sniper / battering ram / pitchfork / cluster bomb (exact request sets, sniper keeps unfilled markers); payloads: list, numbers, null, brute-forcer (capped); grep match + extract (group 1); 1–20 rps rate limit; stoppable; scope-gated per request; results table |
| Decoder | Decoder | ✅ P3/P4 | URL/HTML/Base64 (std+urlsafe, unpadded)/Hex/Gzip/JWT (pretty-printed, signature explicitly NOT verified)/smart chained decode with step trace |
| Comparer | Comparer | ✅ P3/P4 | word + byte diff on pasted text or two history flows (4 parts each) |
| Sequencer | Sequencer | ✅ P3/P4 | Shannon entropy (overall + per-position), χ² uniformity, duplicates, gzip structure ratio, FIPS-style monobit for hex, verdict (poor/weak/acceptable/good) + notes |
| OOB collaborator (self-hosted) | Collaborator | ✅ P3/P6 | HTTP interaction listener + minimal DNS A-responder (`-collab-addr`, `-collab-dns`); per-job canaries with URL/host/domain forms; every callback attributed (label, src, method, path); persisted interaction log + API; powers the scanner's `ssrf-canary` check |
| Session handling / macros | Session handling rules | ✅ P3/P7 | auto cookie jar (Set-Cookie captured from all flows, deletion honored), jar-backed Cookie header on Repeater sends (`use_jar`), macro-lite: replay a captured login on 401/403 then retry once (`macro_flow_id`) |
| Logger & exports (HAR/Burp XML) | Logger++ / export | ✅ P3/P7 | HAR 1.2 (M8), CSV, JSON, Burp XML export + Burp XML import (recorded as import-origin flows) |
| Organizer | Organizer | ✅ P3/P7 | save/annotate flows with notes + tags, list/delete, audited |
| Extensions (JS) | Extender (Java/Python) | ✅ P3/P9 | goja-sandboxed JS hooks (`onRequest`/`onResponse`) — pure ECMAScript (no I/O/network/fs by construction), 2s interrupt cap, compile-checked on save, per-script run/error stats, dry-run test against captured flows, in-scope only, failures never block traffic. WASM (wazero) deferred |
| OpenAPI/Postman/cURL import | (extensions) | 📅 P3 | |
| Reporting (MD/HTML) | Reporting | ✅ P3/P8 | Markdown + self-contained HTML from issues with severity summary and request/response evidence (truncated, escaped); PDF via print-to-PDF |
| MCP server (tools/resources/prompts) | (none) | ✅ P4 | 26 tools (status/history/search/intercept/repeater/intruder/scanner/issues/scope/M&R/decode/compare/jwt/sitemap/report), 3 resources (history/issues/scope), 3 workflow prompts; stdio relay (`proxyforge mcp`) + streamable HTTP (`POST /api/v1/mcp`, token-authed, audited); untrusted-content provenance on every captured-content result; `authorized`/`confirm_active` gates on active tools |
