import { useEffect, useState } from "react";
import { annotate, decodeBody, getFlow, listWSMessages } from "../api";
import type { FullFlow, Header, WSMessage } from "../types";

function Headers({ headers }: { headers: Header[] }) {
  if (!headers.length)
    return <p className="px-3 py-2 text-xs text-slate-600">(no headers)</p>;
  return (
    <table className="w-full text-xs">
      <tbody className="mono">
        {headers.map((h, i) => (
          <tr key={i} className="border-b border-slate-900">
            <td className="w-48 truncate px-3 py-0.5 text-sky-300" title={h.k}>
              {h.k}
            </td>
            <td className="px-3 py-0.5 break-all text-slate-300">{h.v}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function Body({ b64, truncated }: { b64?: string; truncated?: boolean }) {  const text = decodeBody(b64);
  if (!text)
    return (
      <p className="px-3 py-2 text-xs text-slate-600">
        {truncated ? "(body truncated — fetch by id)" : "(empty body)"}
      </p>
    );
  return (
    <div>
      {truncated && (
        <p className="bg-amber-950/50 px-3 py-0.5 text-[10px] text-amber-300">
          truncated preview
        </p>
      )}
      {/* captured content is rendered as TEXT only — never executed */}
      <pre className="mono max-h-72 overflow-auto whitespace-pre-wrap break-all px-3 py-2 text-xs text-slate-300">
        {text}
      </pre>
    </div>
  );
}

export default function FlowDetail({
  id,
  onAnnotated,
  colors,
}: {
  id: number | null;
  onAnnotated: () => void;
  colors: Record<string, string>;
}) {
  const [flow, setFlow] = useState<FullFlow | null>(null);
  const [comment, setComment] = useState("");
  const [highlight, setHighlight] = useState("");
  const [tab, setTab] = useState<"req" | "resp" | "ws">("req");
  const [wsMsgs, setWsMsgs] = useState<WSMessage[]>([]);

  useEffect(() => {
    setFlow(null);
    setWsMsgs([]);
    if (id === null) return;
    let cancelled = false;
    getFlow(id).then((f) => {
      if (cancelled) return;
      setFlow(f);
      setComment(f.comment);
      setHighlight(f.highlight);
      if (f.ws_count) {
        setTab("ws");
        listWSMessages(f.id).then((m) => {
          if (!cancelled) setWsMsgs(m);
        });
      } else {
        setTab("req");
      }
    });
    return () => {
      cancelled = true;
    };
  }, [id]);

  if (id === null)
    return (
      <aside className="hidden w-1/2 border-l border-slate-800 lg:block">
        <p className="p-4 text-xs text-slate-600">select a flow to inspect</p>
      </aside>
    );

  const save = async () => {
    if (!flow) return;
    await annotate(flow.id, { comment, highlight });
    onAnnotated();
  };

  return (
    <aside className="flex w-1/2 min-w-0 flex-col border-l border-slate-800">
      {flow ? (
        <>
          <div className="flex items-center gap-2 border-b border-slate-800 px-3 py-1.5 text-xs">
            <span className="mono rounded bg-slate-800 px-1.5 py-0.5 text-sky-300">
              {flow.request.method} {flow.request.host}
              {flow.request.path}
            </span>
            {flow.response && (
              <span className="mono text-slate-400">{flow.response.status}</span>
            )}
            {flow.tunnel && (
              <span className="rounded bg-slate-800 px-1.5 py-0.5 text-slate-300" title="opaque pass-through tunnel">
                tunnel
              </span>
            )}
            {flow.tls_client && (
              <span className="rounded bg-emerald-950 px-1.5 py-0.5 text-emerald-300" title="TLS versions (client ↔ proxy ↔ origin)">
                🔒 {flow.tls_client} ↔ {flow.tls_server || "—"}
              </span>
            )}
            {flow.err && (
              <span className="mono rounded bg-red-950 px-1.5 py-0.5 text-red-300">
                {flow.err}
              </span>
            )}
          </div>

          <div className="flex gap-1 border-b border-slate-800 px-3 py-1">
            {(["req", "resp", ...(flow.ws_count ? (["ws"] as const) : [])] as const).map(
              (t) => (
                <button
                  key={t}
                  onClick={() => setTab(t)}
                  className={`rounded px-2 py-0.5 text-xs ${
                    tab === t
                      ? "bg-sky-800 text-white"
                      : "text-slate-400 hover:bg-slate-800"
                  }`}
                >
                  {t === "req" ? "request" : t === "resp" ? "response" : `websocket (${flow.ws_count})`}
                </button>
              ),
            )}
          </div>

          <div className="min-h-0 flex-1 overflow-auto">
            {tab === "req" && (
              <>
                <p className="mono px-3 pt-2 text-xs text-slate-400">
                  {flow.request.method} {flow.request.path}{" "}
                  {flow.request.version}
                </p>
                <p className="mono px-3 pb-1 text-[10px] text-slate-600">
                  {flow.request.scheme}://{flow.request.host}:
                  {flow.request.port} · {flow.request.headers.length} headers
                </p>
                <Headers headers={flow.request.headers} />
                <Body b64={flow.req_body_b64} truncated={flow.request.body_truncated} />
              </>
            )}
            {tab === "resp" &&
              (flow.response ? (
                <>
                  <p className="mono px-3 pt-2 text-xs text-slate-400">
                    {flow.response.version} {flow.response.status}{" "}
                    {flow.response.status_text}
                  </p>
                  <Headers headers={flow.response.headers} />
                  <Body b64={flow.resp_body_b64} truncated={flow.response.body_truncated} />
                </>
              ) : (
                <p className="p-4 text-xs text-slate-600">no response captured</p>
              ))}
            {tab === "ws" && <WSTab msgs={wsMsgs} />}
          </div>

          <div className="flex items-center gap-2 border-t border-slate-800 px-3 py-2">
            <input
              value={comment}
              onChange={(e) => setComment(e.target.value)}
              placeholder="comment…"
              className="min-w-0 flex-1 rounded border border-slate-700 bg-slate-900 px-2 py-1 text-xs outline-none focus:border-sky-600"
            />
            <select
              value={highlight}
              onChange={(e) => setHighlight(e.target.value)}
              className="rounded border border-slate-700 bg-slate-900 px-1.5 py-1 text-xs"
              style={colors[highlight] ? { color: colors[highlight] } : undefined}
            >
              <option value="">color</option>
              {Object.keys(colors)
                .filter((c) => c)
                .map((c) => (
                  <option key={c} value={c}>
                    {c}
                  </option>
                ))}
            </select>
            <button
              onClick={save}
              className="rounded bg-sky-700 px-2.5 py-1 text-xs text-white hover:bg-sky-600"
            >
              save
            </button>
          </div>
        </>
      ) : (
        <p className="p-4 text-xs text-slate-600">loading flow #{id}…</p>
      )}
    </aside>
  );
}

// WSTab lists captured WebSocket frames. Payloads render as text only —
// captured content is never executed or rendered as HTML.
function WSTab({ msgs }: { msgs: WSMessage[] }) {
  const [expanded, setExpanded] = useState<Set<number>>(new Set());
  if (!msgs.length)
    return <p className="p-4 text-xs text-slate-600">no frames captured</p>;
  const toggle = (id: number) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };
  return (
    <div className="py-1">
      {msgs.map((m) => {
        const open = expanded.has(m.id);
        const text = decodeBody(m.payload_b64);
        return (
          <div key={m.id} className="border-b border-slate-900">
            <button
              onClick={() => toggle(m.id)}
              className="flex w-full items-center gap-2 px-3 py-1 text-left text-xs hover:bg-slate-800/60"
            >
              <span
                className={
                  m.direction === "c2s" ? "text-sky-400" : "text-emerald-400"
                }
                title={m.direction === "c2s" ? "client → server" : "server → client"}
              >
                {m.direction === "c2s" ? "→" : "←"}
              </span>
              <span className="mono text-slate-400">{m.opcode_name}</span>
              {!m.fin && <span className="text-[10px] text-slate-600">cont</span>}
              {m.compressed && <span className="text-[10px] text-amber-500">rsv1</span>}
              <span className="text-slate-600">{m.size} B</span>
              <span className="flex-1" />
              <span className="mono max-w-96 truncate text-slate-500">
                {open ? "" : text.slice(0, 120)}
              </span>
            </button>
            {open && text && (
              <pre className="mono max-h-64 overflow-auto whitespace-pre-wrap break-all bg-slate-950/50 px-3 py-2 text-xs text-slate-300">
                {text}
              </pre>
            )}
          </div>
        );
      })}
    </div>
  );
}
