// Playwright smoke: token gate → history renders → intercept parks and
// forwards from the UI. Run from ui/ after the daemon is built:
//   node e2e/smoke.mjs <binary> <workdir>
import { chromium } from "playwright";
import { spawn, execSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const [, , binArg] = process.argv;
const BIN = binArg ?? join(process.cwd(), "..", "proxyforge");
// always a fresh workdir — leftover state from earlier runs (partial config,
// stale CA) must never leak into a smoke run
const WORK = mkdtempSync(join(tmpdir(), "pf-smoke-"));
mkdirSync(join(WORK, "home"), { recursive: true });
const PORT_PROXY = 18095;
const PORT_API = 18795;
const PORT_APP = 19095;

const log = (...a) => console.log("[smoke]", ...a);
const fail = (msg) => {
  console.error("[smoke] FAIL:", msg);
  process.exitCode = 1;
};

// upstream target: tiny fixed app
const APP = join(WORK, "app.py");
writeFileSync(
  APP,
  `from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        b = b'{"ok":true}'
        self.send_response(200); self.send_header('Content-Length', str(len(b))); self.end_headers(); self.wfile.write(b)
    def log_message(self, *a): pass
HTTPServer(('127.0.0.1', ${PORT_APP}), H).serve_forever()
`,
);
const app = spawn("python3", [APP], { stdio: "ignore" });

const daemon = spawn(
  BIN,
  [
    "-project", join(WORK, "eng.pf.sqlite"),
    "-proxy-addr", `127.0.0.1:${PORT_PROXY}`,
    "-api-addr", `127.0.0.1:${PORT_API}`,
  ],
  { env: { ...process.env, HOME: join(WORK, "home") }, stdio: ["ignore", "pipe", "pipe"] },
);
let daemonErr = "";
daemon.stderr.on("data", (d) => (daemonErr += d));
daemon.on("error", (e) => {
  daemonErr += "spawn error: " + e.message + "\n";
});

const cleanup = () => {
  daemon.kill();
  app.kill();
};
process.on("exit", cleanup);

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function main() {
  // wait for API
  const token = execSync(`HOME=${join(WORK, "home")} ${BIN} token`, {
    encoding: "utf8",
  }).trim();
  let lastErr = "";
  for (let i = 0; i < 50; i++) {
    try {
      const r = await fetch(`http://127.0.0.1:${PORT_API}/api/v1/status`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (r.ok) break;
      lastErr = "HTTP " + r.status;
      if (r.status === 401)
        throw new Error("token rejected (401) — daemon/token mismatch");
    } catch (e) {
      lastErr = e.cause?.code ?? e.message;
    }
    await sleep(300);
    if (i === 49)
      throw new Error(
        "daemon API never came up: " + lastErr + "; stderr: " + daemonErr.slice(-500),
      );
  }

  // seed traffic through the proxy
  execSync(
    `curl -s -o /dev/null -x http://127.0.0.1:${PORT_PROXY} http://127.0.0.1:${PORT_APP}/seed`,
  );

  const browser = await chromium.launch();
  const page = await browser.newPage();

  // 1. token gate
  await page.goto(`http://127.0.0.1:${PORT_API}/`);
  await page.getByPlaceholder("API token").fill(token);
  await page.getByRole("button", { name: "unlock" }).click();
  await page.waitForSelector("text=HTTP history", { timeout: 5000 });
  log("token gate + layout ok");

  // 2. history renders seeded flow
  await page.waitForSelector("text=/seed", { timeout: 5000 });
  log("history renders captured flow");

  // 3. intercept: park, forward from the UI
  await page.getByRole("button", { name: "Intercept" }).click();
  await page
    .locator("input[type=checkbox]")
    .first()
    .check(); // master toggle
  const parked = execSync(
    `curl -s -o /dev/null -w '%{http_code}' -x http://127.0.0.1:${PORT_PROXY} --max-time 20 http://127.0.0.1:${PORT_APP}/parked & sleep 1; curl -s -H "Authorization: Bearer ${token}" http://127.0.0.1:${PORT_API}/api/v1/intercept`,
    { shell: "/bin/bash", encoding: "utf8" },
  );
  if (!parked.includes(`"pending":[{`)) {
    throw new Error("request did not park: " + parked);
  }
  await page.waitForSelector("text=/parked", { timeout: 5000 });
  log("intercept queue shows parked request");
  await page.getByRole("button", { name: "forward" }).click();
  await sleep(1000);
  const after = await (
    await fetch(`http://127.0.0.1:${PORT_API}/api/v1/intercept`, {
      headers: { Authorization: `Bearer ${token}` },
    })
  ).json();
  if (after.pending.length !== 0) {
    throw new Error("queue did not drain after forward");
  }
  log("forward drained the queue");

  await browser.close();
  log("PASS");
}

main()
  .catch((e) => fail(e.message))
  .finally(() => process.exit(process.exitCode ?? 0));
