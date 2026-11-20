import { useCallback, useEffect, useState } from "react";
import {
  decodeBody,
  interceptDrop,
  interceptForward,
  interceptForwardAll,
  interceptOverview,
  interceptToggle,
  type InterceptOverview,
  type InterceptPending,
} from "../api";

function headersToText(hdrs: { k: string; v: string }[] | undefined): string {
  return (hdrs ?? []).map((h) => `${h.k}: ${h.v}`).join("\n");
}

function b64encode(s: string): string {
  const bytes = new TextEncoder().encode(s);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

export default function InterceptTab({ onChanged }: { onChanged?: () => void }) {
  const [ov, setOv] = useState<InterceptOverview | null>(null);
  // optimistic overrides for the toggles (poll refresh can race a click)
  const [enabledOv, setEnabledOv] = useState<boolean | null>(null);
  const [responsesOv, setResponsesOv] = useState<boolean | null>(null);
  const [selected, setSelected] = useState<number | null>(null);
  const [method, setMethod] = useState("");
  const [path, setPath] = useState("");
  const [headers, setHeaders] = useState("");
  const [body, setBody] = useState("");
  const [status, setStatus] = useState("");

  const refresh = useCallback(() => {
    interceptOverview()
      .then((o) => {
        setOv(o);
        setEnabledOv(null);
        setResponsesOv(null);
      })
      .catch(() => {});
  }, []);

  useEffect(() => {
    refresh();
    const t = setInterval(refresh, 1000); // polling fallback; ws events also trigger
    return () => clearInterval(t);
  }, [refresh]);

  useEffect(() => {
    const item = ov?.pending.find((p) => p.id === selected) ?? null;
    if (item) {
      setMethod(item.flow.request.method);
      setPath(item.flow.request.path);
      setHeaders(headersToText(item.flow.request.headers));
      setBody(
        item.is_response
          ? decodeBody(item.flow.resp_body_b64)
          : decodeBody(item.flow.req_body_b64),
      );
      setStatus(item.flow.response ? String(item.flow.response.status) : "");
    }
  }, [selected, ov]);

  const item: InterceptPending | null =
    ov?.pending.find((p) => p.id === selected) ?? null;

  const doForward = useCallback(async () => {
    if (item == null) return;
    const edit: Record<string, unknown> = {};
    if (!item.is_response) {
      if (method && method !== item.flow.request.method) edit.method = method;
      if (path && path !== item.flow.request.path) edit.path = path;
      // header edits ride as raw text; only send when changed
      if (headers !== headersToText(item.flow.request.headers)) {
        edit.headers = headers
          .split("\n")
          .map((l) => l.trim())
          .filter(Boolean)
          .map((l) => {
            const i = l.indexOf(":");
            return i < 0
              ? { k: l, v: "" }
              : { k: l.slice(0, i).trim(), v: l.slice(i + 1).trim() };
          });
      }
      const orig = decodeBody(item.flow.req_body_b64);
      if (body !== orig) edit.body_b64 = b64encode(body);
    } else {
      const orig = decodeBody(item.flow.resp_body_b64);
      if (body !== orig) edit.body_b64 = b64encode(body);
      if (status && Number(status) !== item.flow.response?.status)
        edit.status = Number(status);
    }
    await interceptForward(item.id, edit);
    setSelected(null);
    refresh();
    onChanged?.();
  }, [item, method, path, headers, body, status, refresh, onChanged]);

  const doDrop = useCallback(async () => {
    if (item == null) return;
    await interceptDrop(item.id);
    setSelected(null);
    refresh();
    onChanged?.();
  }, [item, refresh, onChanged]);

  // keyboard: ⌘F / Ctrl+F forward, ⌘D / Ctrl+D drop
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (!(e.metaKey || e.ctrlKey)) return;
      if (e.key === "f" || e.key === "F") {
        e.preventDefault();
        void doForward();
      } else if (e.key === "d" || e.key === "D") {
        e.preventDefault();
        void doDrop();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [doForward, doDrop]);

  if (!ov)
    return <div className="p-4 text-xs text-slate-600">loading intercept…</div>;

  const enabled = enabledOv ?? ov.enabled;
  const interceptResponses = responsesOv ?? ov.intercept_responses;

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex items-center gap-4 border-b border-slate-800 px-4 py-2 text-xs">
        <label className="flex items-center gap-2">
          <input
            type="checkbox"
            checked={enabled}
            onChange={(e) => {
              setEnabledOv(e.target.checked);
              interceptToggle({ enabled: e.target.checked }).then(refresh);
            }}
          />
          <span className={enabled ? "font-semibold text-emerald-400" : "text-slate-500"}>
            intercept is {enabled ? "on" : "off"}
          </span>
        </label>
        <label className="flex items-center gap-2">
          <input
            type="checkbox"
            checked={interceptResponses}
            onChange={(e) => {
              setResponsesOv(e.target.checked);
              interceptToggle({ intercept_responses: e.target.checked }).then(refresh);
            }}
          />
          <span className="text-slate-400">intercept responses</span>
        </label>
        <span className="text-slate-500">
          {ov.rules.length} rule{ov.rules.length === 1 ? "" : "s"}
        </span>
        <span className="flex-1" />
        <button
          onClick={() => interceptForwardAll().then(refresh)}
          className="rounded border border-slate-700 bg-slate-900 px-2 py-1 hover:border-emerald-600"
        >
          forward all
        </button>
      </div>

      <div className="flex min-h-0 flex-1">
        <div className="w-72 shrink-0 overflow-auto border-r border-slate-800">
          {ov.pending.length === 0 && (
            <p className="p-3 text-xs text-slate-600">
              queue empty — matching traffic will pause here
            </p>
          )}
          {ov.pending.map((p) => (
            <button
              key={p.id}
              onClick={() => setSelected(p.id)}
              className={`block w-full px-3 py-2 text-left text-xs hover:bg-slate-800/60 ${
                selected === p.id ? "bg-sky-950/60" : ""
              }`}
            >
              <div className="mono truncate text-slate-300">
                {p.is_response ? "← " : ""}
                {p.flow.request.method} {p.flow.request.host}
              </div>
              <div className="mono truncate text-slate-500">
                {p.flow.request.path}
                {p.is_response && p.flow.response
                  ? ` · ${p.flow.response.status}`
                  : ""}
              </div>
            </button>
          ))}
        </div>

        <div className="flex min-w-0 flex-1 flex-col">
          {item ? (
            <>
              <div className="flex items-center gap-2 border-b border-slate-800 px-3 py-1.5 text-xs">
                <span className="rounded bg-slate-800 px-1.5 py-0.5 text-slate-300">
                  {item.is_response ? "response" : "request"} #{item.id}
                </span>
                <span className="flex-1" />
                <button
                  onClick={doForward}
                  className="rounded bg-emerald-700 px-3 py-1 font-medium text-white hover:bg-emerald-600"
                  title="⌘F"
                >
                  forward
                </button>
                <button
                  onClick={doDrop}
                  className="rounded bg-red-800 px-3 py-1 font-medium text-white hover:bg-red-700"
                  title="⌘D"
                >
                  drop
                </button>
              </div>
              <div className="flex gap-1 border-b border-slate-800 px-3 py-1">
                <input
                  value={method}
                  onChange={(e) => setMethod(e.target.value)}
                  disabled={item.is_response}
                  className="mono w-20 rounded border border-slate-700 bg-slate-900 px-2 py-1 text-xs disabled:opacity-40"
                />
                <input
                  value={path}
                  onChange={(e) => setPath(e.target.value)}
                  disabled={item.is_response}
                  className="mono min-w-0 flex-1 rounded border border-slate-700 bg-slate-900 px-2 py-1 text-xs disabled:opacity-40"
                />
                {item.is_response && (
                  <input
                    value={status}
                    onChange={(e) => setStatus(e.target.value)}
                    className="mono w-16 rounded border border-slate-700 bg-slate-900 px-2 py-1 text-xs"
                    placeholder="status"
                  />
                )}
              </div>
              <textarea
                value={headers}
                onChange={(e) => setHeaders(e.target.value)}
                disabled={item.is_response}
                spellCheck={false}
                className="mono h-32 resize-none border-b border-slate-800 bg-slate-950 px-3 py-2 text-xs text-slate-300 outline-none disabled:opacity-40"
              />
              <textarea
                value={body}
                onChange={(e) => setBody(e.target.value)}
                spellCheck={false}
                placeholder="body (text)"
                className="mono min-h-0 flex-1 resize-none bg-slate-950 px-3 py-2 text-xs text-slate-300 outline-none"
              />
            </>
          ) : (
            <p className="p-4 text-xs text-slate-600">
              select a parked item to edit · ⌘F forward · ⌘D drop
            </p>
          )}
        </div>
      </div>
    </div>
  );
}
