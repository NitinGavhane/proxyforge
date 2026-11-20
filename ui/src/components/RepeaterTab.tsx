import { useCallback, useEffect, useState } from "react";
import {
  repeaterDelete,
  repeaterHistory,
  repeaterNew,
  repeaterSend,
  repeaterTabs,
  repeaterUpdate,
  type RepeaterTab,
  type RepeaterHistoryRow,
  type SendResult,
} from "../api";

export default function RepeaterTab() {
  const [tabs, setTabs] = useState<RepeaterTab[]>([]);
  const [active, setActive] = useState<number | null>(null);
  const [raw, setRaw] = useState("");
  const [follow, setFollow] = useState(false);
  const [result, setResult] = useState<SendResult | null>(null);
  const [history, setHistory] = useState<RepeaterHistoryRow[]>([]);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  const refreshTabs = useCallback(() => {
    repeaterTabs()
      .then((t) => {
        setTabs(t);
        setActive((cur) => cur ?? t[0]?.id ?? null);
      })
      .catch(() => {});
  }, []);

  useEffect(() => {
    refreshTabs();
  }, [refreshTabs]);

  useEffect(() => {
    const tab = tabs.find((t) => t.id === active);
    if (tab) setRaw(tab.raw);
  }, [active, tabs]);

  const send = async () => {
    if (active == null) return;
    setBusy(true);
    setErr("");
    setResult(null);
    try {
      // save the raw first so the send uses exactly what's on screen
      await repeaterUpdate(active, raw);
      const { result } = await repeaterSend(active, {
        raw,
        follow_redirects: follow,
      });
      setResult(result);
      repeaterHistory(active).then((h) => setHistory(h.history ?? []));
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  };

  const newTab = async () => {
    const { id } = await repeaterNew();
    refreshTabs();
    setActive(id);
    setRaw("GET / HTTP/1.1\nHost: example.com\n");
  };

  const removeTab = async (id: number) => {
    await repeaterDelete(id);
    if (active === id) {
      setActive(null);
      setRaw("");
    }
    refreshTabs();
  };

  const activeTab = tabs.find((t) => t.id === active);

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex items-center gap-1 border-b border-slate-800 px-4 py-2 text-xs">
        {tabs.map((t) => (
          <span
            key={t.id}
            className={`group flex items-center gap-1 rounded px-2 py-1 ${
              active === t.id ? "bg-sky-800 text-white" : "text-slate-400 hover:bg-slate-800"
            }`}
          >
            <button onClick={() => setActive(t.id)}>{t.name}</button>
            <button
              onClick={() => removeTab(t.id)}
              className="opacity-0 transition-opacity group-hover:opacity-100"
              title="close tab"
            >
              ✕
            </button>
          </span>
        ))}
        <button
          onClick={newTab}
          className="rounded px-2 py-1 text-slate-400 hover:bg-slate-800"
          title="new tab"
        >
          +
        </button>
        <span className="flex-1" />
        <label className="flex items-center gap-1 text-slate-400">
          <input
            type="checkbox"
            checked={follow}
            onChange={(e) => setFollow(e.target.checked)}
          />
          follow redirects
        </label>
        <button
          onClick={send}
          disabled={busy || active == null}
          className="rounded bg-emerald-700 px-4 py-1 font-medium text-white hover:bg-emerald-600 disabled:opacity-40"
        >
          {busy ? "sending…" : "send"}
        </button>
      </div>

      <div className="flex min-h-0 flex-1">
        <div className="flex min-w-0 flex-1 flex-col">
          <textarea
            value={raw}
            onChange={(e) => setRaw(e.target.value)}
            spellCheck={false}
            placeholder={"GET /path HTTP/1.1\nHost: target.example\nX-Scheme: https (optional hint)"}
            className="mono min-h-0 flex-1 resize-none bg-slate-950 px-3 py-2 text-xs text-slate-200 outline-none"
          />
          {err && (
            <div className="border-t border-red-900 bg-red-950/50 px-3 py-1 text-xs text-red-300">
              {err}
            </div>
          )}
          {result && (
            <div className="flex h-2/5 min-h-0 flex-col border-t border-slate-800">
              <div className="flex items-center gap-2 border-b border-slate-800 px-3 py-1 text-xs">
                <span className="mono text-emerald-400">
                  {result.final?.response?.status ?? result.final?.err ?? "—"}
                </span>
                {result.hops?.length > 1 && (
                  <span className="rounded bg-slate-800 px-1.5 text-slate-300">
                    {result.hops.length} hops
                  </span>
                )}
                {result.final?.tls_server && (
                  <span className="text-slate-500">
                    🔒 {result.final.tls_server}
                  </span>
                )}
                <span className="text-slate-600">
                  {result.final?.duration_ms}ms
                </span>
              </div>
              <pre className="mono min-h-0 flex-1 overflow-auto whitespace-pre-wrap break-all px-3 py-2 text-xs text-slate-300">
                {result.final?.response?.headers
                  ?.map((h) => `${h.k}: ${h.v}`)
                  .join("\n") ?? ""}
                {"\n\n"}
                {result.final?.resp_body_b64
                  ? atob(result.final.resp_body_b64)
                  : ""}
              </pre>
            </div>
          )}
        </div>

        <div className="w-64 shrink-0 overflow-auto border-l border-slate-800">
          <div className="border-b border-slate-800 px-3 py-2 text-xs text-slate-400">
            history {activeTab ? `· tab ${activeTab.id}` : ""}
          </div>
          {(history ?? []).length === 0 && (
            <p className="p-3 text-xs text-slate-600">no sends yet</p>
          )}
          {(history ?? []).map((h) => (
            <button
              key={h.id}
              onClick={() => {
                // clicking history loads that send's raw back into the editor
                setRaw(
                  `${h.method} ${h.path} HTTP/1.1\nHost: ${h.host}${h.port && h.port !== 80 && h.port !== 443 ? ":" + h.port : ""}\n`,
                );
              }}
              className="block w-full px-3 py-1.5 text-left text-xs hover:bg-slate-800/60"
            >
              <span className="mono text-slate-300">
                {h.status || "ERR"} {h.method}
              </span>
              <span className="mono block truncate text-slate-500">
                {h.host}
                {h.path}
              </span>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
