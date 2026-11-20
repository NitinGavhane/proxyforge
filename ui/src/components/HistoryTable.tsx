import { useEffect } from "react";
import type { FlowRow } from "../types";

function methodClass(m: string): string {
  switch (m) {
    case "GET":
      return "text-emerald-400";
    case "POST":
      return "text-sky-400";
    case "PUT":
      return "text-amber-400";
    case "PATCH":
      return "text-violet-400";
    case "DELETE":
      return "text-red-400";
    default:
      return "text-slate-400";
  }
}

function statusClass(s: number): string {
  if (s === 0) return "text-red-500";
  if (s < 300) return "text-emerald-400";
  if (s < 400) return "text-amber-400";
  return "text-red-400";
}

function fmtTime(ms: number): string {
  const d = new Date(ms);
  return d.toLocaleTimeString([], { hour12: false });
}

function fmtSize(n: number): string {
  if (n < 1024) return `${n}`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)}k`;
  return `${(n / 1024 / 1024).toFixed(1)}M`;
}

export default function HistoryTable({
  flows,
  selected,
  onSelect,
  colors,
}: {
  flows: FlowRow[];
  selected: number | null;
  onSelect: (id: number, compare?: boolean) => void;
  colors: Record<string, string>;
}) {
  // keyboard navigation: j/k or arrows move selection
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.metaKey || e.ctrlKey || e.altKey) return;
      const tag = (e.target as HTMLElement)?.tagName;
      if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return;
      const idx = flows.findIndex((f) => f.id === selected);
      let next = -1;
      if (e.key === "j" || e.key === "ArrowDown") next = idx < 0 ? 0 : Math.min(idx + 1, flows.length - 1);
      else if (e.key === "k" || e.key === "ArrowUp") next = idx < 0 ? flows.length - 1 : Math.max(idx - 1, 0);
      if (next >= 0 && flows[next]) {
        e.preventDefault();
        onSelect(flows[next].id);
        document
          .getElementById(`flow-row-${flows[next].id}`)
          ?.scrollIntoView({ block: "nearest" });
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [flows, selected, onSelect]);

  return (
    <div className="min-w-0 flex-1 overflow-auto">
      <table className="w-full text-left text-xs">
        <thead className="sticky top-0 z-10 bg-slate-900/95 text-slate-500 backdrop-blur">
          <tr>
            <th className="px-2 py-1.5 font-medium">#</th>
            <th className="px-2 py-1.5 font-medium">time</th>
            <th className="px-2 py-1.5 font-medium">method</th>
            <th className="px-2 py-1.5 font-medium">host</th>
            <th className="px-2 py-1.5 font-medium">path</th>
            <th className="px-2 py-1.5 font-medium">status</th>
            <th className="px-2 py-1.5 font-medium">len</th>
            <th className="px-2 py-1.5 font-medium">ms</th>
            <th className="px-2 py-1.5 font-medium">proto</th>
          </tr>
        </thead>
        <tbody className="mono">
          {flows.map((f) => (
            <tr
              key={f.id}
              id={`flow-row-${f.id}`}
              onClick={(e) => onSelect(f.id, e.metaKey || e.ctrlKey)}
              className={`cursor-pointer border-b border-slate-900 hover:bg-slate-800/60 ${
                selected === f.id ? "bg-sky-950/60" : ""
              }`}
              style={colors[f.highlight] ? { boxShadow: `inset 3px 0 0 ${colors[f.highlight]}` } : undefined}
            >
              <td className="px-2 py-1 text-slate-600">{f.id}</td>
              <td className="px-2 py-1 text-slate-500">{fmtTime(f.started)}</td>
              <td className={`px-2 py-1 font-semibold ${methodClass(f.method)}`}>
                {f.method}
              </td>
              <td className="max-w-40 truncate px-2 py-1 text-sky-300">
                {f.host}
              </td>
              <td className="max-w-96 truncate px-2 py-1 text-slate-300">
                {f.path}
                {f.comment && <span title={f.comment}> 💬</span>}
                {f.truncated && <span title="body truncated"> ✂</span>}
              </td>
              <td className={`px-2 py-1 font-semibold ${statusClass(f.status)}`}>
                {f.status === 0 ? (f.err ? "ERR" : "—") : f.status}
              </td>
              <td className="px-2 py-1 text-slate-500">
                {fmtSize(f.resp_size || f.req_size)}
              </td>
              <td className="px-2 py-1 text-slate-500">{f.duration_ms}</td>
              <td className="px-2 py-1 text-slate-600">
                {f.http_version || "—"}
                {f.tunnel ? (
                  <span title="pass-through tunnel (opaque)" className="ml-1 text-slate-400">
                    ⏩
                  </span>
                ) : f.mitm ? (
                  <span title={`MITM TLS${f.tls_client ? " · client " + f.tls_client : ""}`} className="ml-1 text-emerald-500">
                    🔒
                  </span>
                ) : null}
                {f.origin !== "proxy" && (
                  <span className="ml-1 rounded bg-violet-950 px-1 text-[10px] text-violet-300">
                    {f.origin}
                  </span>
                )}
              </td>
            </tr>
          ))}
          {flows.length === 0 && (
            <tr>
              <td colSpan={9} className="px-4 py-8 text-center text-slate-600">
                no flows captured — point a client at the proxy
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
