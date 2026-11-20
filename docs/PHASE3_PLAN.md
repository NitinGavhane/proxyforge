# Phase 3 Plan — Burp feature parity

Status: **COMPLETE (P1–P9)** — 2026-11-21. P9 shipped the JS extension
system (goja sandbox, JSON-bridged flow mutation, interrupt-capped, dry-run
testing); the WASM/wazero component ABI is deferred to a future phase — the
JS hooks cover the scripting use cases and the sandbox properties it
promised (no ambient sockets) hold for both.

Sequencing note: every active tool sends exclusively through
`Engine.SendToolFlow` (scope-gated, audited, captured). Repeater lands early
because Phase 4's MCP wraps it directly.

| Milestone | Scope | Exit criteria |
|---|---|---|
| **P1** | Target: site map (hosts → endpoints, aggregated from captures), endpoint import (the REA bridge), shadow detection (imported-but-never-observed), content discovery (wordlist job, baseline-diff detection, rate-limited) | site map reflects every captured flow; discovery finds planted paths against a test origin; imports flagged when unobserved |
| **P2** | Repeater: tabs, raw request editing (h1 raw mode; upstream h2 automatic), per-tab history, follow-redirects (per-hop flows), send | raw round-trip (render↔parse) exact; redirects recorded hop-by-hop; out-of-scope send refused by the gate |
| **P3** | Intruder: sniper / battering ram / pitchfork / cluster bomb; payload sets (list, numbers, null, brute-forcer); grep match + extract; rate limiting; results table | all four modes produce exact request sets; rate cap enforced; results greppable |
| **P4** | Decoder (URL/HTML/Base64/Hex/Gzip/JWT/smart), Comparer UI (diff engine exists), Sequencer (entropy + FIPS-style tests on token samples) | decoder round-trips; sequencer reports entropy/chi-square/repetition on known-good and known-bad sequences |
| **P5** | Scanner: issue model (severity/confidence), passive checks (security headers, cookie flags, CORS, CSP, info disclosure, secret patterns), opt-in active checks (SQLi error/time, reflected XSS, SSRF via OOB, path traversal, open redirect, command-injection canaries, IDOR heuristics) | passive findings on a deliberately misconfigured origin; active checks gated behind explicit confirm; every issue carries request/response evidence |
| **P6** | Self-hosted OOB collaborator: HTTP listener + interaction log + per-job canary domains (`x.oob.local` style virtual hosts) | blind SSRF/blind XXE demo fires and is attributed to the job that planted it |
| **P7** | Sessions: cookie jar + macro-lite (replay a login flow on 401); Logger exports (JSON/CSV, Burp XML import+export); Organizer (save/annotate) | macro refreshes an expired session in a live test |
| **P8** | Import/export: OpenAPI/Swagger, Postman, cURL (`proxyforge import curl '…'`); Reporting: Markdown/HTML evidence reports | OpenAPI import populates the site map; report renders issues with evidence |
| **P9** | Extension system: WASM (wazero) components with capability-scoped host functions + JS hooks (goja) for request/response scripting | a sample extension rewrites a header end-to-end; no ambient socket access from plugins |

Out of scope here: HTTP/3, h2 extended-CONNECT WS (unchanged from Phase 1).
