# Phase 1 Retrospective

Completed 2026-11-19. M0–M8 delivered: proxy core, HTTPS MITM, HTTP/2 both
legs, WebSocket capture, intercept, match & replace, scope + safety baseline,
diff/HAR/demo/Playwright.

## What shipped

| Milestone | Highlights |
|---|---|
| M0 | Scaffold, CI (go/ui/e2e), embedded UI, token auth |
| M1 | HTTP/1.1 proxying, SQLite store (WAL, zstd bodies, FTS5), REST+WS API, history UI |
| M2 | Per-install CA + per-host leaves (openssl-verified), CONNECT→MITM, TLS pass-through, upstream proxy/SOCKS, upstream client certs |
| M3 | HTTP/2 both legs, mixed h2↔h1, trailers, per-host downgrade list |
| M4 | ws/wss proxying with frame-level capture, plaintext-tunnel parsing, WS UI tab |
| M5 | Intercept (park/edit/forward/drop/forward-all), phase-aware rules, restart recovery, audit |
| M6 | Match & Replace (headers, body regex with capture groups, raw), hit counters, previews |
| M7 | Scope (include/exclude, non-retroactive), out-of-scope never logged/intercepted, outbound gate + `SendToolFlow`, token rotation |
| M8 | HAR 1.2 export (REA-compatible), word/byte diff UI, Juice Shop demo, Playwright smoke, j/k navigation |

## Bugs found and what they taught us

1. **One-shot listener lifecycle** (M2): `http.Server.Serve` closes its
   listener when Accept ends, and returns before the connection goroutine
   finishes — two separate kills of live MITM connections. Lesson: when
   composing stdlib servers, own the conn lifecycle explicitly
   (`trackedConn`).
2. **CONNECT ≠ TLS** (M4): gorilla (and other ws clients) CONNECT even for
   plaintext `ws://`. The engine now peeks the first byte (0x16 → MITM TLS,
   else plaintext HTTP tunnel). Lesson: never assume what's inside a tunnel.
3. **Rule semantics must be phase-explicit** (M5/M6): "which predicates
   apply to which phase" needed a precise model (conversation-level URL,
   per-phase content-type/header/body, status responses-only) — discovered
   through tests disagreeing with the code.
4. **Config cold-start race** (M8): the daemon and `token` CLI creating
   config concurrently could mint different tokens; an empty-file read made
   the loser overwrite the winner. Fixed with O_EXCL create + settle-retry
   + atomic (temp+rename) writes; regression-tested. This was latent since
   M1 and only surfaced under the Playwright smoke — **smoke tests in real
   browsers earn their keep**.
5. **UI behind the auth wall** (M8): `/` required a token before the token
   gate could render — shipped broken-by-design since M1 and only caught by
   the Playwright smoke. The shell is public; every `/api/*` route stays
   token-gated.
6. **Controlled checkboxes vs polling** (M8): 1s poll refresh raced toggle
   clicks; fixed with optimistic local state.

## Carried into Phase 2+

- Raw header ordering is normalized (stdlib map) — documented non-goal.
- h2 extended-CONNECT WebSocket and HTTP/3 remain out of scope.
- `SendToolFlow` is the single outbound path for Phase 3 tools (Repeater,
  Intruder, Scanner) — scope-gated and audited by construction.
- The demo's `SKIP_DOCKER=1` fallback app keeps local dev cheap; CI runs
  the real Juice Shop.
- Deliberate deviations from the plan: none material; disk leaf cache +
  tunnel records landed as specified.
