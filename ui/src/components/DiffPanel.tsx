import { useEffect, useState } from "react";
import { flowDiff, type DiffResult } from "../api";

const PARTS = [
  ["req_body", "request body"],
  ["resp_body", "response body"],
  ["req_headers", "request headers"],
  ["resp_headers", "response headers"],
] as const;

export default function DiffPanel({
  a,
  b,
  onClose,
}: {
  a: number;
  b: number;
  onClose: () => void;
}) {
  const [part, setPart] = useState<string>("req_body");
  const [mode, setMode] = useState<string>("word");
  const [res, setRes] = useState<DiffResult | null>(null);

  useEffect(() => {
    let cancelled = false;
    flowDiff(a, b, part, mode).then((d) => {
      if (!cancelled) setRes(d);
    });
    return () => {
      cancelled = true;
    };
  }, [a, b, part, mode]);

  return (
    <aside className="flex w-1/2 min-w-0 flex-col border-l border-slate-800">
      <div className="flex items-center gap-2 border-b border-slate-800 px-3 py-1.5 text-xs">
        <span className="rounded bg-violet-950 px-1.5 py-0.5 text-violet-300">
          diff {a} ↔ {b}
        </span>
        <select
          value={part}
          onChange={(e) => setPart(e.target.value)}
          className="rounded border border-slate-700 bg-slate-900 px-1.5 py-0.5"
        >
          {PARTS.map(([v, label]) => (
            <option key={v} value={v}>
              {label}
            </option>
          ))}
        </select>
        <select
          value={mode}
          onChange={(e) => setMode(e.target.value)}
          className="rounded border border-slate-700 bg-slate-900 px-1.5 py-0.5"
        >
          <option value="word">word</option>
          <option value="byte">byte</option>
        </select>
        <span className="flex-1" />
        <button
          onClick={onClose}
          className="rounded border border-slate-700 px-2 py-0.5 hover:border-sky-600"
        >
          close
        </button>
      </div>
      <div className="min-h-0 flex-1 overflow-auto">
        {!res ? (
          <p className="p-4 text-xs text-slate-600">computing diff…</p>
        ) : (
          <pre className="mono whitespace-pre-wrap break-all px-3 py-2 text-xs leading-5">
            {res.segments.map((seg, i) => (
              <span
                key={i}
                className={
                  seg.type === "insert"
                    ? "bg-emerald-950/70 text-emerald-200"
                    : seg.type === "delete"
                      ? "bg-red-950/70 text-red-200 line-through"
                      : "text-slate-300"
                }
              >
                {seg.text}
              </span>
            ))}
          </pre>
        )}
      </div>
    </aside>
  );
}
