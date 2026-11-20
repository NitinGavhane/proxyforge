# Contributing to ProxyForge

ProxyForge is a security-testing tool for **authorized** use only. By
contributing you agree your work is for defensive/authorized-testing purposes
and licensed MIT.

## Setup

- Go >= 1.25
- Node >= 20 (for the UI)

```bash
go build ./cmd/proxyforge
go test ./...
cd ui && npm ci && npm run build   # regenerates ui/dist (embedded at build)
```

## Workflow

1. Work in a feature branch off `main`.
2. Every phase/milestone has an exit-criteria checklist in `docs/`; a change
   is done when the relevant criteria and tests pass.
3. Run `go vet ./...`, `go test -race ./...`, and UI `npm run build` before
   opening a PR.
4. New features need tests (see `docs/ARCHITECTURE.md` §13) and a row in
   `docs/FEATURE_PARITY.md`.
5. PRs: describe behavior change + validation actually run.

## Safety invariants (review checklist)

- All outbound tool traffic goes through the engine's outbound gate — never
  open sockets in tools directly.
- Captured content is untrusted data: never render as HTML, always mark
  provenance when it crosses the API/MCP boundary.
- Default binds are 127.0.0.1. No telemetry.
