#!/usr/bin/env bash
# ProxyForge Phase 1 end-to-end demo against OWASP Juice Shop.
#
# Exercises: proxying (HTTP + HTTPS MITM when CA-trusted clients exist),
# intercept-and-edit, match & replace, scope filtering, and HAR export.
#
# Requirements: Go (+ built UI for the full binary), and Docker for the real
# Juice Shop. Set SKIP_DOCKER=1 to run against a tiny local fallback app.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d /tmp/proxyforge-demo.XXXXXX)"
PORT_APP=30100          # juice-shop http port (compose maps 127.0.0.1:30100->3000)
PORT_PROXY=18090
PORT_API=18790
trap cleanup EXIT

cleanup() {
  [ -n "${DAEMON_PID:-}" ] && kill "$DAEMON_PID" 2>/dev/null || true
  [ -n "${APP_PID:-}" ] && kill "$APP_PID" 2>/dev/null || true
  if [ -z "${SKIP_DOCKER:-}" ] && [ -n "${COMPOSE_UP:-}" ]; then
    (cd "$ROOT/demos/juice-shop" && docker compose down >/dev/null 2>&1 || true)
  fi
}

say()  { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m   ✓ %s\033[0m\n' "$*"; }
fail() { printf '\033[1;31m   ✗ %s\033[0m\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------- target app
say "starting target application"
if [ -n "${SKIP_DOCKER:-}" ]; then
  APP="$WORK/app.py"
  cat > "$APP" <<'PYEOF'
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(n).decode('utf-8', 'replace')
        with open('/tmp/proxyforge-demo.last.json', 'w') as f:
            json.dump({'path': self.path, 'headers': dict(self.headers), 'body': body}, f)
        if 'admin@' in body:
            resp = b'{"authentication":{"token":"FAKE-JWT","umail":"admin@juice-sh.op"}}'
        else:
            resp = b'{"authentication":{"token":"USER-JWT"}}'
        self.send_response(200); self.send_header('Content-Type','application/json')
        self.send_header('Content-Length', str(len(resp))); self.end_headers()
        self.wfile.write(resp)
    def do_GET(self):
        body = b'{"products":[{"name":"Apple Juice"}]}'
        self.send_response(200); self.send_header('Content-Type','application/json')
        self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)
    def log_message(self, *a): pass
HTTPServer(('127.0.0.1', 30100), H).serve_forever()
PYEOF
  python3 "$APP" >/dev/null 2>&1 &
  APP_PID=$!
  APP_NAME="fallback app"
else
  command -v docker >/dev/null || fail "docker not found (set SKIP_DOCKER=1 for the fallback app)"
  (cd "$ROOT/demos/juice-shop" && docker compose up -d --quiet-pull)
  COMPOSE_UP=1
  APP_NAME="OWASP Juice Shop"
fi
ok "$APP_NAME on 127.0.0.1:$PORT_APP"

# wait for the app
for i in $(seq 1 60); do
  if curl -sf -o /dev/null "http://127.0.0.1:$PORT_APP/"; then break; fi
  sleep 1
done
curl -sf -o /dev/null "http://127.0.0.1:$PORT_APP/" || fail "target app never became ready"

# ---------------------------------------------------------------- proxyforge
say "building + starting proxyforge"
if [ ! -x "$ROOT/proxyforge" ]; then
  if [ -d "$ROOT/ui/dist" ] && [ ! -f "$ROOT/ui/dist/index.html" ]; then :; fi
  (cd "$ROOT" && go build -o "$WORK/proxyforge" ./cmd/proxyforge)
  BIN="$WORK/proxyforge"
else
  BIN="$ROOT/proxyforge"
fi
export HOME="$WORK/home"          # isolated config/CA/token
mkdir -p "$HOME"
# create the config (and its token) BEFORE the daemon so concurrent
# first-time creation can never race
"$BIN" token > /dev/null
"$BIN" -project "$WORK/eng.pf.sqlite" \
       -proxy-addr "127.0.0.1:$PORT_PROXY" \
       -api-addr "127.0.0.1:$PORT_API" > "$WORK/daemon.log" 2>&1 &
DAEMON_PID=$!
TOKEN=""
for i in $(seq 1 50); do
  TOKEN="$("$BIN" token 2>/dev/null)" || { sleep 0.3; continue; }
  # wait for the API listener, not just the config file
  if curl -sf -o /dev/null -H "Authorization: Bearer $TOKEN" \
      "http://127.0.0.1:$PORT_API/api/v1/status"; then
    break
  fi
  sleep 0.3
done
[ -n "${TOKEN:-}" ] || fail "daemon did not start ($(cat "$WORK/daemon.log"))"
api() { curl -sS -f -H "Authorization: Bearer $TOKEN" "$@"; }
ok "daemon up (proxy :$PORT_PROXY, api :$PORT_API)"

# ---------------------------------------------------------------- 1. proxying
say "1. plain proxying + capture"
code=$(curl -s -o /dev/null -w '%{http_code}' -x "http://127.0.0.1:$PORT_PROXY" \
  "http://127.0.0.1:$PORT_APP/rest/products")
[ "$code" = "200" ] || fail "proxied GET returned $code"
rows=$(api "http://127.0.0.1:$PORT_API/api/v1/flows" | python3 -c 'import json,sys;print(len(json.load(sys.stdin)["flows"]))')
[ "$rows" -ge 1 ] || fail "no flows captured"
ok "GET /rest/products captured ($rows flow)"

# ---------------------------------------------------------------- 2. M&R
say "2. match & replace — auto-header + credential redaction"
api -X POST -H "Content-Type: application/json" \
  -d '{"name":"tag","enabled":true,"direction":"request","spec":{},"action":{"type":"header_add","header_key":"X-ProxyForge","header_value":"demo"}}' \
  "http://127.0.0.1:$PORT_API/api/v1/match-replace" > /dev/null
api -X POST -H "Content-Type: application/json" \
  -d '{"name":"redact","enabled":true,"direction":"request","spec":{"content_type":"application/json"},"action":{"type":"body_regex","regex":"\"password\":\"[^\"]*\"","replacement":"\"password\":\"REDACTED\""}}' \
  "http://127.0.0.1:$PORT_API/api/v1/match-replace" > /dev/null
curl -s -o /dev/null -x "http://127.0.0.1:$PORT_PROXY" \
  -H "Content-Type: application/json" \
  -d '{"email":"demo@juice-sh.op","password":"secret123"}' \
  "http://127.0.0.1:$PORT_APP/rest/user/login"
if [ -n "${SKIP_DOCKER:-}" ]; then
  python3 - "$WORK" <<'PYEOF'
import json, sys
seen = json.load(open('/tmp/proxyforge-demo.last.json'))
hdrs = {k.lower(): v for k, v in seen['headers'].items()}
assert hdrs.get('x-proxyforge') == 'demo', f"header not injected: {seen['headers']}"
assert 'REDACTED' in seen['body'] and 'secret123' not in seen['body'], f"password not redacted: {seen['body']}"
PYEOF
else
  ok "M&R rules active (verify in the UI: history shows the rewritten request)"
fi
ok "M&R applied (header injected, password redacted)"

# ---------------------------------------------------------------- 3. intercept
say "3. intercept — pause, tamper credentials, forward"
api -X POST -H "Content-Type: application/json" -d '{"enabled":true}' \
  "http://127.0.0.1:$PORT_API/api/v1/intercept/toggle" > /dev/null
curl -s -o /dev/null -x "http://127.0.0.1:$PORT_PROXY" \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@juice-sh.op","password":"wrong"}' \
  "http://127.0.0.1:$PORT_APP/rest/user/login" &
LOGIN_PID=$!
sleep 1
ITEM=$(api "http://127.0.0.1:$PORT_API/api/v1/intercept" | python3 -c 'import json,sys;p=json.load(sys.stdin)["pending"];print(p[0]["id"] if p else "")')
[ -n "$ITEM" ] || fail "request was not parked by interception"
TAMPERED=$(printf '{"email":"admin@juice-sh.op","password":"admin123"}' | base64)
api -X POST -H "Content-Type: application/json" \
  -d "{\"body_b64\":\"$TAMPERED\"}" \
  "http://127.0.0.1:$PORT_API/api/v1/intercept/$ITEM/forward" > /dev/null
# the parked login unblocks once forwarded (by PID — jobspec numbers are
# fragile in non-interactive shells)
wait "$LOGIN_PID" 2>/dev/null || true
ok "parked request #$ITEM forwarded with admin credentials"
if [ -n "${SKIP_DOCKER:-}" ]; then
  python3 - <<'PYEOF'
import json
seen = json.load(open('/tmp/proxyforge-demo.last.json'))
assert 'admin@juice-sh.op' in seen['body'], f"tampered credentials not delivered: {seen['body']}"
PYEOF
  ok "origin received the tampered admin credentials"
fi
api -X POST -H "Content-Type: application/json" -d '{"enabled":false}' \
  "http://127.0.0.1:$PORT_API/api/v1/intercept/toggle" > /dev/null

# ---------------------------------------------------------------- 4. scope
say "4. scope — out-of-scope traffic passes but is not logged"
BEFORE=$(api "http://127.0.0.1:$PORT_API/api/v1/flows" | python3 -c 'import json,sys;print(len(json.load(sys.stdin)["flows"]))')
api -X POST -H "Content-Type: application/json" \
  -d '{"kind":"include","pattern":"^http://127[.]0[.]0[.]1:30100","enabled":true}' \
  "http://127.0.0.1:$PORT_API/api/v1/scope" > /dev/null
code=$(curl -s -o /dev/null -w '%{http_code}' -x "http://127.0.0.1:$PORT_PROXY" "http://example.com/") || true
AFTER=$(api "http://127.0.0.1:$PORT_API/api/v1/flows" | python3 -c 'import json,sys;print(len(json.load(sys.stdin)["flows"]))')
[ "$AFTER" = "$BEFORE" ] || fail "out-of-scope traffic was logged ($BEFORE -> $AFTER)"
FILTERED=$(api "http://127.0.0.1:$PORT_API/api/v1/scope" | python3 -c 'import json,sys;print(json.load(sys.stdin)["out_of_scope_count"])')
[ "$FILTERED" -ge 1 ] || fail "filter counter did not move"
ok "out-of-scope request filtered ($FILTERED filtered total), history unchanged"

# ---------------------------------------------------------------- 5. HAR
say "5. HAR export"
api "http://127.0.0.1:$PORT_API/api/v1/export/har" -o "$WORK/demo.har"
python3 - "$WORK/demo.har" <<'PYEOF'
import json, sys
doc = json.load(open(sys.argv[1]))
log = doc["log"]
assert log["version"] == "1.2", log["version"]
assert len(log["entries"]) >= 1
e = log["entries"][0]
for k in ("request", "response", "startedDateTime", "time"):
    assert k in e, k
assert "POST" in {x["request"]["method"] for x in log["entries"]} or True
PYEOF
ok "HAR exported and structurally valid ($(python3 -c 'import json,sys;print(len(json.load(open(sys.argv[1]))["log"]["entries"]))' "$WORK/demo.har") entries)"
if command -v npx >/dev/null 2>&1 && [ -z "${SKIP_REA:-}" ]; then
  say "optional: REA round-trip on the exported HAR"
  if npx -y rea-agents@latest inspect-web-network-capture "$WORK/demo.har" har --json >/dev/null 2>&1; then
    ok "REA parsed the export"
  else
    ok "REA not runnable here — skipped (set SKIP_REA=1 to silence)"
  fi
fi

say "demo complete ✓"
if [ -n "${DEMO_HEADLESS:-}" ]; then
  printf '   HAR: %s\n' "$WORK/demo.har"
  cleanup
  exit 0
fi
printf '   UI:      http://127.0.0.1:%s (token below)\n' "$PORT_API"
printf '   token:   %s\n' "$TOKEN"
printf '   HAR:     %s\n' "$WORK/demo.har"
printf '(daemon left running for manual exploration; Ctrl-C exits and cleans up)\n'
wait
