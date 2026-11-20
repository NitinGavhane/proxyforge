# Phase 4 Retrospective — MCP server

Completed 2026-11-21. With this, all four phases of the original brief are
done.

## What shipped

- **`internal/mcp`** — JSON-RPC 2.0 dispatcher implementing the MCP surface:
  `initialize` (capabilities + serverInfo), `ping`, `tools/list`,
  `tools/call`, `resources/list|read`, `prompts/list|get`.
- **26 tools** matching the brief's catalog (plus small renames for
  clarity: `intercept_forward/drop`, `intruder_start/stop/results`).
- **3 resources**: `proxyforge://history`, `://issues`, `://scope`.
- **3 prompts**: analyze-auth-flow, find-idor-candidates,
  summarize-attack-surface — each embedding the untrusted-data ground rule.
- **Two transports**: streamable HTTP on `POST /api/v1/mcp` (token-authed,
  audited as `mcp.request`) and a stdio relay (`proxyforge mcp`) that
  forwards line-delimited JSON-RPC to the daemon with the config token —
  the shape Claude Code launches.
- **Safety**: every tool result embedding captured traffic carries
  `_meta.provenance.untrusted_content: true` (the REA convention from the
  reference analysis); active tools gate on `authorized` /
  `confirm_active`; mutating calls append audit rows with actor `mcp`;
  all sends flow through the engine's scope-gated `SendToolFlow`.
- **Docs**: `CLAUDE.md` (ground rules, workflow, session recipes) and a
  `.mcp.json` example.

## Notes for the next iteration

- Streamable HTTP is the stateless JSON mode (no SSE push, no sessions) —
  sufficient for request/response tool use; SSE notifications can be added
  on the existing event bus when a client needs them.
- The stdio relay is deliberately thin: all logic lives behind the daemon
  endpoint, so both transports share one dispatcher and one audit trail.
- Tool schemas are hand-written objects; they validate loosely. If the
  official Go SDK stabilizes, migrating the envelope types while keeping
  the Backend interface is mechanical.

## Bugs caught in P4

- goja's nested-slice copy semantics (fixed via a JSON bridge — recorded in
  the P9 notes; surfaced again here because the MCP demo reused it).
- The live stdio smoke initially "failed" because a stray Python process
  was squatting on the default API port 8765 — a good reminder that the
  relay's error messages name the port it dialed.
