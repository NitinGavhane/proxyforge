# Phase 2 Plan — Browser integration

Status: **Complete (2026-11-19)** — delivered as N1–N4 below. Deviations:
`-dump` was added for scripting/smoke use; CDP/Playwright deep integration
moved to Phase 3+ (launch-time flags cover Phase 2 needs).

Goal: make "point a browser at ProxyForge" a one-click experience and
document the manual paths for every client type.

## N1 — `proxyforge browse` (launched browser)

- Locate a Chrome/Chromium binary (chromium > chrome > edge > none).
- Throwaway profile under a temp dir (never the user's profile).
- Launch with:
  `--proxy-server=http://127.0.0.1:8080 --user-data-dir=<tmp>`
  `--proxy-bypass-list=<-loopback>` (let localhost through the proxy so the
  CA page is reachable),
  `--no-first-run --no-default-browser-check --disable-fre`.
- CA trust options (in order of preference):
  a. macOS: `security add-trusted-cert -d -r trustRoot -k <login keychain>`
     + revert command on exit (flag-gated, default off);
  b. Linux: copy to `~/.pki/nssdb` via `certutil` when available;
  c. fallback: launch untrusted + open `http://proxy.local` instructions.
- `--proxyforge-browse <url>` opens a target after startup.
- Tests: binary detection matrix, launch args (unit-test the arg builder
  against expected flags), CA trust command construction (no execution),
  revert cleanup. Manual e2e documented for macOS/Linux/Windows.

## N2 — CA page at `http://proxy.local`

- API handler (localhost-only) serving:
  `/` instructions per OS/browser (with detected-browser hint),
  `/ca.pem` the root cert download,
  `/health` used by the browser extension later.
- The proxy resolves `proxy.local` internally (host rewrite in the engine,
  loopback-only; documented).
- Tests: handler serves PEM + instructions; requests from non-loopback
  refused (they can't arrive — the listener is loopback anyway).

## N3 — Manual proxy docs

- `docs/CLIENTS.md`: Firefox (per-connection proxy + CA import via
  Authority), Chrome/Chromium flags, Safari (system proxy + Keychain),
  Android (WiFi proxy + cert as CA install caveat), iOS (WiFi proxy +
  profile install), curl `--proxy` + `--cacert`, Python/Node/Go clients.
- Each with "remove afterwards" instructions.

## N4 — Optional browser extension

- Manifest V3, minimal: a badge + context-menu "send to ProxyForge" that
  tags the current tab origin via `POST /api/v1/annotate-tab` (engine-side
  tag on subsequent flows for that origin for N minutes).
- Ships in `extension/`, loadable unpacked; not a store release.
- Tests: API contract; extension tested manually (documented steps).

## Exit criteria

- `proxyforge browse` opens a working proxied browser on macOS, Linux,
  Windows (CI: arg-matrix tests; manual: per-OS checklist in
  `docs/CLIENTS.md`).
- `http://proxy.local` reachable from the launched browser with download +
  per-OS trust instructions.
- FEATURE_PARITY.md updated; Phase 2 retro appended to PHASE1_RETRO-style
  notes.
