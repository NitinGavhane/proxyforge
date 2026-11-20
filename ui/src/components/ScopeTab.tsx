import { useCallback, useEffect, useState } from "react";
import {
  scopeAdd,
  scopeDelete,
  scopeGet,
  scopePreview,
  scopeToggle,
  type ScopeRule,
  type ScopePreviewRow,
} from "../api";

export default function ScopeTab() {
  const [rules, setRules] = useState<ScopeRule[]>([]);
  const [count, setCount] = useState(0);
  const [preview, setPreview] = useState<ScopePreviewRow[]>([]);
  const [kind, setKind] = useState("include");
  const [pattern, setPattern] = useState("");
  const [error, setError] = useState("");

  const refresh = useCallback(() => {
    scopeGet()
      .then((o) => {
        setRules(o.rules);
        setCount(o.out_of_scope_count);
      })
      .catch(() => {});
    scopePreview()
      .then((p) => setPreview(p.preview))
      .catch(() => {});
  }, []);

  useEffect(() => {
    refresh();
    const t = setInterval(refresh, 2000);
    return () => clearInterval(t);
  }, [refresh]);

  const add = async () => {
    setError("");
    try {
      await scopeAdd({ kind, pattern, enabled: true });
      setPattern("");
      refresh();
    } catch (e) {
      setError(String(e));
    }
  };

  return (
    <div className="flex h-full min-h-0">
      <div className="flex w-96 shrink-0 flex-col border-r border-slate-800">
        <div className="border-b border-slate-800 px-4 py-2 text-xs text-slate-400">
          target scope — out-of-scope traffic is proxied but never logged,
          intercepted, or modified
          <div className="mt-1 text-slate-500">
            filtered exchanges: <span className="text-amber-400">{count}</span>
          </div>
        </div>
        <div className="flex gap-2 border-b border-slate-800 px-4 py-2 text-xs">
          <select
            value={kind}
            onChange={(e) => setKind(e.target.value)}
            className="rounded border border-slate-700 bg-slate-900 px-2 py-1"
          >
            <option value="include">include</option>
            <option value="exclude">exclude</option>
          </select>
          <input
            value={pattern}
            onChange={(e) => setPattern(e.target.value)}
            placeholder="regex, e.g. ^https://app\.example\.com(/|$)"
            className="mono min-w-0 flex-1 rounded border border-slate-700 bg-slate-900 px-2 py-1"
          />
          <button
            onClick={add}
            disabled={!pattern}
            className="rounded bg-sky-700 px-2 py-1 text-white hover:bg-sky-600 disabled:opacity-40"
          >
            add
          </button>
        </div>
        {error && (
          <div className="px-4 py-1 text-xs text-red-400">{error}</div>
        )}
        <div className="min-h-0 flex-1 overflow-auto">
          {rules.length === 0 && (
            <p className="p-4 text-xs text-slate-600">
              no scope rules — everything is in scope and logged
            </p>
          )}
          {rules.map((r) => (
            <div
              key={r.id}
              className="flex items-center gap-2 border-b border-slate-900 px-4 py-2 text-xs"
            >
              <input
                type="checkbox"
                checked={r.enabled}
                onChange={(e) => scopeToggle(r.id, e.target.checked).then(refresh)}
              />
              <span
                className={`rounded px-1.5 py-0.5 ${
                  r.kind === "include"
                    ? "bg-emerald-950 text-emerald-300"
                    : "bg-red-950 text-red-300"
                }`}
              >
                {r.kind}
              </span>
              <span className="mono min-w-0 flex-1 truncate text-slate-300" title={r.pattern}>
                {r.pattern}
              </span>
              <button
                onClick={() => scopeDelete(r.id).then(refresh)}
                className="text-red-500 hover:text-red-300"
              >
                ✕
              </button>
            </div>
          ))}
        </div>
      </div>

      <div className="flex min-w-0 flex-1 flex-col">
        <div className="border-b border-slate-800 px-4 py-2 text-xs text-slate-400">
          live preview — what the CURRENT rules would do to recent history
          (saved flows keep their capture-time verdict)
        </div>
        <div className="min-h-0 flex-1 overflow-auto">
          {preview.length === 0 && (
            <p className="p-4 text-xs text-slate-600">no history yet</p>
          )}
          {preview.map((p, i) => (
            <div
              key={i}
              className="flex items-center gap-3 border-b border-slate-900 px-4 py-1.5 text-xs"
            >
              <span
                className={`rounded px-1.5 py-0.5 ${
                  p.in_scope
                    ? "bg-emerald-950 text-emerald-300"
                    : "bg-slate-800 text-slate-500"
                }`}
              >
                {p.in_scope ? "in scope" : "filtered"}
              </span>
              <span className="mono min-w-0 flex-1 truncate text-slate-400">
                {p.host}
                <span className="text-slate-600">{p.path}</span>
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
