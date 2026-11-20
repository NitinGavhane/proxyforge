// Thin API client. Uses session cookie auth (set via POST /auth); falls back
// to surfacing 401 so the app can show the token gate.
import type { FlowRow, FullFlow, Status, WSMessage } from "./types";

export class UnauthorizedError extends Error {}

async function req(path: string, init?: RequestInit): Promise<Response> {
  const resp = await fetch(path, { credentials: "include", ...init });
  if (resp.status === 401) throw new UnauthorizedError();
  if (!resp.ok) throw new Error(`${resp.status} ${await resp.text()}`);
  return resp;
}

export async function getStatus(): Promise<Status> {
  const r = await req("/api/v1/status");
  return r.json();
}

export async function login(token: string): Promise<void> {
  const resp = await fetch("/api/v1/auth", {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token }),
  });
  if (!resp.ok) throw new UnauthorizedError();
}

export interface ListParams {
  q?: string;
  host?: string;
  method?: string;
  status?: string;
  sort?: string;
  limit?: number;
  offset?: number;
}

export async function listFlows(p: ListParams = {}): Promise<FlowRow[]> {
  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(p)) {
    if (v !== undefined && v !== "") qs.set(k, String(v));
  }
  const r = await req(`/api/v1/flows?${qs}`);
  const out = await r.json();
  return out.flows ?? [];
}

export async function getFlow(id: number): Promise<FullFlow> {
  const r = await req(`/api/v1/flows/${id}`);
  return r.json();
}

export async function listWSMessages(
  flowId: number,
  limit = 200,
  offset = 0,
): Promise<WSMessage[]> {
  const r = await req(`/api/v1/flows/${flowId}/ws?limit=${limit}&offset=${offset}`);
  const out = await r.json();
  return out.messages ?? [];
}

export interface InterceptRule {
  id: number;
  name: string;
  enabled: boolean;
  spec: Record<string, string>;
}

export interface InterceptPending {
  id: number;
  is_response: boolean;
  flow: {
    id?: number;
    request: {
      method: string;
      scheme: string;
      host: string;
      port: number;
      path: string;
      version: string;
      headers: { k: string; v: string }[];
    };
    response?: {
      status: number;
      status_text: string;
      headers: { k: string; v: string }[];
    };
    req_body_b64?: string;
    resp_body_b64?: string;
  };
}

export interface InterceptOverview {
  enabled: boolean;
  intercept_responses: boolean;
  rules: InterceptRule[];
  pending: InterceptPending[];
}

export async function interceptOverview(): Promise<InterceptOverview> {
  const r = await req("/api/v1/intercept");
  return r.json();
}

export async function interceptToggle(patch: {
  enabled?: boolean;
  intercept_responses?: boolean;
}): Promise<void> {
  await req("/api/v1/intercept/toggle", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(patch),
  });
}

export async function interceptForward(
  id: number,
  edit?: { method?: string; path?: string; body_b64?: string; status?: number },
): Promise<void> {
  await req(`/api/v1/intercept/${id}/forward`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(edit ?? {}),
  });
}

export async function interceptDrop(id: number): Promise<void> {
  await req(`/api/v1/intercept/${id}/drop`, { method: "POST" });
}

export async function interceptForwardAll(): Promise<number> {
  const r = await req("/api/v1/intercept/forward-all", { method: "POST" });
  const out = await r.json();
  return out.forwarded ?? 0;
}

export interface MRMatchPreview {
  ts: number;
  where: string;
  note: string;
}

export interface MRRule {
  id: number;
  name: string;
  enabled: boolean;
  direction: "request" | "response";
  spec: Record<string, string>;
  action: {
    type: string;
    header_key?: string;
    header_value?: string;
    regex?: string;
    replacement?: string;
    find?: string;
    replace?: string;
  };
  hits: number;
  recent?: MRMatchPreview[];
}

export async function mrList(): Promise<MRRule[]> {
  const r = await req("/api/v1/match-replace");
  const out = await r.json();
  return out.rules ?? [];
}

export async function mrAdd(rule: {
  name: string;
  enabled: boolean;
  direction: string;
  spec: Record<string, string>;
  action: Record<string, string>;
}): Promise<number> {
  const r = await req("/api/v1/match-replace", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(rule),
  });
  const out = await r.json();
  return out.id;
}

export async function mrToggle(id: number, enabled: boolean): Promise<void> {
  await req(`/api/v1/match-replace/${id}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ enabled }),
  });
}

export async function mrDelete(id: number): Promise<void> {
  await req(`/api/v1/match-replace/${id}`, { method: "DELETE" });
}

export interface ScopeRule {
  id: number;
  kind: "include" | "exclude";
  pattern: string;
  enabled: boolean;
}

export interface ScopeOverview {
  rules: ScopeRule[];
  out_of_scope_count: number;
}

export interface ScopePreviewRow {
  host: string;
  path: string;
  url: string;
  in_scope: boolean;
}

export async function scopeGet(): Promise<ScopeOverview> {
  const r = await req("/api/v1/scope");
  return r.json();
}

export async function scopeAdd(rule: {
  kind: string;
  pattern: string;
  enabled: boolean;
}): Promise<number> {
  const r = await req("/api/v1/scope", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(rule),
  });
  const out = await r.json();
  return out.id;
}

export async function scopeToggle(id: number, enabled: boolean): Promise<void> {
  await req(`/api/v1/scope/${id}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ enabled }),
  });
}

export async function scopeDelete(id: number): Promise<void> {
  await req(`/api/v1/scope/${id}`, { method: "DELETE" });
}

export async function scopePreview(): Promise<{ preview: ScopePreviewRow[] }> {
  const r = await req("/api/v1/scope/preview");
  return r.json();
}

export interface DiffSegment {
  type: "equal" | "insert" | "delete";
  text: string;
}

export interface DiffResult {
  mode: string;
  a: string;
  b: string;
  segments: DiffSegment[];
}

export async function flowDiff(
  a: number,
  b: number,
  part: string,
  mode = "word",
): Promise<DiffResult> {
  const r = await req(`/api/v1/flows/${a}/diff/${b}?part=${part}&mode=${mode}`);
  return r.json();
}

// Download the current filtered history (or explicit ids) as a HAR file.
export async function exportHAR(params: ListParams, ids?: number[]): Promise<void> {
  const qs = new URLSearchParams();
  if (ids?.length) {
    qs.set("ids", ids.join(","));
  } else {
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== "") qs.set(k, String(v));
    }
  }
  const r = await req(`/api/v1/export/har?${qs}`);
  const blob = await r.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "proxyforge.har";
  a.click();
  URL.revokeObjectURL(url);
}

export async function annotate(
  id: number,
  patch: { comment?: string; highlight?: string },
): Promise<void> {
  await req(`/api/v1/flows/${id}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(patch),
  });
}

export function decodeBody(b64?: string): string {
  if (!b64) return "";
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  // Render as text; bodies are never executed or rendered as HTML.
  return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
}

// --- target / sitemap ---

export interface SitePath {
  path: string;
  scheme: string;
  port: number;
  methods: string[];
  status?: number;
  count: number;
  source: string;
  observed: boolean;
  shadow?: boolean;
  last_seen: number;
}

export interface SiteHost {
  host: string;
  endpoints: number;
  paths: SitePath[];
}

export async function sitemapGet(): Promise<{ hosts: SiteHost[] }> {
  const r = await req("/api/v1/sitemap");
  return r.json();
}

export interface ImportEndpoint {
  host: string;
  path: string;
  scheme?: string;
  port?: number;
  method?: string;
}

export async function sitemapImport(
  endpoints: ImportEndpoint[],
): Promise<{ imported: number }> {
  const r = await req("/api/v1/sitemap/import", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ endpoints }),
  });
  return r.json();
}

// --- discovery ---

export interface DiscoveryResult {
  path: string;
  url: string;
  status: number;
  size: number;
  interesting: boolean;
  err?: string;
}

export interface DiscoveryJob {
  id: number;
  base_url: string;
  state: "running" | "done" | "stopped" | "error";
  probed: number;
  total: number;
  results: DiscoveryResult[];
  err?: string;
}

export async function discoveryStart(body: {
  base_url: string;
  wordlist?: string[];
  rate_per_sec?: number;
}): Promise<{ job: DiscoveryJob }> {
  const r = await req("/api/v1/discovery/start", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return r.json();
}

export async function discoveryGet(id: number): Promise<{ job: DiscoveryJob }> {
  const r = await req(`/api/v1/discovery/${id}`);
  return r.json();
}

export async function discoveryStop(id: number): Promise<void> {
  await req(`/api/v1/discovery/${id}/stop`, { method: "POST" });
}

// --- repeater ---

export interface RepeaterTab {
  id: number;
  name: string;
  raw: string;
}

export interface RepeaterHistoryRow {
  id: number;
  method: string;
  host: string;
  port: number;
  path: string;
  status: number;
  err?: string;
  duration_ms: number;
}

export interface SendResult {
  final: {
    id: number;
    err?: string;
    duration_ms: number;
    tls_server?: string;
    response?: {
      status: number;
      headers: { k: string; v: string }[];
    };
    resp_body_b64?: string;
  } | null;
  hops: unknown[];
}

export async function repeaterTabs(): Promise<RepeaterTab[]> {
  const r = await req("/api/v1/repeater");
  const out = await r.json();
  return out.tabs ?? [];
}

export async function repeaterNew(
  name?: string,
  raw?: string,
): Promise<{ id: number }> {
  const r = await req("/api/v1/repeater", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name, raw }),
  });
  return r.json();
}

export async function repeaterUpdate(
  id: number,
  raw: string,
): Promise<void> {
  await req(`/api/v1/repeater/${id}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ raw }),
  });
}

export async function repeaterDelete(id: number): Promise<void> {
  await req(`/api/v1/repeater/${id}`, { method: "DELETE" });
}

export async function repeaterSend(
  id: number,
  body: { raw: string; follow_redirects: boolean },
): Promise<{ result: SendResult }> {
  const r = await req(`/api/v1/repeater/${id}/send`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return r.json();
}

export async function repeaterHistory(
  id: number,
): Promise<{ history: RepeaterHistoryRow[] }> {
  const r = await req(`/api/v1/repeater/${id}/history`);
  return r.json();
}

// --- intruder ---

export interface IntruderResult {
  index: number;
  payloads: string[];
  rendered: string;
  flow_id?: number;
  status: number;
  size: number;
  ms: number;
  err?: string;
  matches?: Record<string, string>;
  extracts?: Record<string, string>;
}

export interface IntruderJob {
  id: number;
  attack_type: string;
  state: "running" | "done" | "stopped" | "error";
  total: number;
  sent: number;
  results: IntruderResult[];
  err?: string;
}

export async function intruderStart(body: {
  attack_type: string;
  raw: string;
  payload_sets: { type: string; items: string[] }[];
  match?: { name: string; regex: string }[];
  extract?: { name: string; regex: string }[];
  rate_per_sec?: number;
}): Promise<{ job: IntruderJob }> {
  const r = await req("/api/v1/intruder/start", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return r.json();
}

export async function intruderGet(id: number): Promise<{ job: IntruderJob }> {
  const r = await req(`/api/v1/intruder/${id}`);
  return r.json();
}

export async function intruderStop(id: number): Promise<void> {
  await req(`/api/v1/intruder/${id}/stop`, { method: "POST" });
}

// --- decoder / comparer / sequencer ---

export interface DecodeResult {
  input: string;
  format: string;
  mode: string;
  output: string;
  steps?: string[];
  is_text: boolean;
  err?: string;
}

export async function decodeTransform(
  input: string,
  format: string,
  mode: string,
): Promise<DecodeResult> {
  const r = await req("/api/v1/decode", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ input, format, mode }),
  });
  const out = await r.json();
  return out.result;
}

export async function rawCompare(
  a: string,
  b: string,
  mode: string,
): Promise<DiffResult> {
  const r = await req("/api/v1/compare", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ a, b, mode }),
  });
  return r.json();
}

export interface MonobitResult {
  total_bits: number;
  ones: number;
  ones_ratio: number;
  pass: boolean;
}

export interface SequencerAnalysis {
  samples: number;
  unique: number;
  duplicates: number;
  min_len: number;
  max_len: number;
  avg_len: number;
  charset_size: number;
  entropy_bits_per_char: number;
  chi_square: number;
  degrees_of_freedom: number;
  per_position_entropy?: number[];
  monobit?: MonobitResult;
  compression_ratio: number;
  verdict: string;
  notes?: string[];
}

export async function sequencerAnalyze(
  tokens: string,
): Promise<SequencerAnalysis> {
  const r = await req("/api/v1/sequencer/analyze", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ tokens }),
  });
  const out = await r.json();
  return out.analysis;
}

// --- scanner ---

export interface ScanJob {
  id: number;
  state: "running" | "done" | "stopped" | "error";
  target: string;
  passive: boolean;
  active: boolean;
  probed: number;
  issues: number;
  err?: string;
}

export interface Issue {
  id: number;
  check_id: string;
  title: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  confidence: "certain" | "firm" | "tentative";
  host: string;
  port: number;
  path: string;
  detail: string;
  evidence_flow_id?: number;
  scan_id: number;
}

export async function scanStart(body: {
  base_url?: string;
  flow_id?: number;
  passive?: boolean;
  active?: boolean;
  active_checks?: string[];
  confirm_active?: boolean;
  rate_per_sec?: number;
}): Promise<{ job: ScanJob }> {
  const r = await req("/api/v1/scanner/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return r.json();
}

export async function scanGet(id: number): Promise<{ job: ScanJob }> {
  const r = await req(`/api/v1/scanner/${id}`);
  return r.json();
}

export async function issuesList(
  host?: string,
  severity?: string,
): Promise<{ issues: Issue[] }> {
  const qs = new URLSearchParams();
  if (host) qs.set("host", host);
  if (severity) qs.set("severity", severity);
  const r = await req(`/api/v1/issues?${qs}`);
  return r.json();
}

// --- extensions ---

export interface PFExtension {
  id: number;
  name: string;
  enabled: boolean;
  code: string;
  runs: number;
  errors: number;
  last_error?: string;
}

export interface ExtTestView {
  before: Record<string, unknown>;
  after: Record<string, unknown>;
  error?: string;
  error_response?: string;
}

export async function extList(): Promise<{ extensions: PFExtension[] }> {
  const r = await req("/api/v1/extensions");
  return r.json();
}

export async function extAdd(
  name: string,
  code: string,
  enabled: boolean,
): Promise<number> {
  const r = await req("/api/v1/extensions", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name, code, enabled }),
  });
  const out = await r.json();
  return out.id;
}

export async function extUpdate(
  id: number,
  patch: { name?: string; code?: string; enabled?: boolean },
): Promise<void> {
  await req(`/api/v1/extensions/${id}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(patch),
  });
}

export async function extDelete(id: number): Promise<void> {
  await req(`/api/v1/extensions/${id}`, { method: "DELETE" });
}

export async function extTest(
  id: number,
  flowId: number,
): Promise<ExtTestView> {
  const r = await req(`/api/v1/extensions/${id}/test`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ flow_id: flowId }),
  });
  return r.json();
}
