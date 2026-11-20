import { useCallback, useEffect, useRef, useState } from "react";
import {
  UnauthorizedError,
  exportHAR,
  getStatus,
  listFlows,
  login,
  type ListParams,
} from "./api";
import type { FlowRow, Status } from "./types";
import TokenGate from "./components/TokenGate";
import HistoryTable from "./components/HistoryTable";
import FlowDetail from "./components/FlowDetail";
import InterceptTab from "./components/InterceptTab";
import MatchReplaceTab from "./components/MatchReplaceTab";
import ScopeTab from "./components/ScopeTab";
import TargetTab from "./components/TargetTab";
import RepeaterTab from "./components/RepeaterTab";
import IntruderTab from "./components/IntruderTab";
import UtilitiesTab from "./components/UtilitiesTab";
import ScannerTab from "./components/ScannerTab";
import ExtensionsTab from "./components/ExtensionsTab";
import DiffPanel from "./components/DiffPanel";

const HIGHLIGHT_COLORS: Record<string, string> = {
  "": "",
  red: "#7f1d1d",
  orange: "#7c2d12",
  yellow: "#713f12",
  green: "#14532d",
  cyan: "#164e63",
  magenta: "#701a75",
};

export default function App() {
  const [authed, setAuthed] = useState<boolean | null>(null);
  const [status, setStatus] = useState<Status | null>(null);
  const [flows, setFlows] = useState<FlowRow[]>([]);
  const [selected, setSelected] = useState<number | null>(null);
  const [live, setLive] = useState(false);
  const [error, setError] = useState("");
  const [view, setView] = useState<
    | "history"
    | "intercept"
    | "matchreplace"
    | "scope"
    | "target"
    | "repeater"
    | "intruder"
    | "utilities"
    | "scanner"
    | "extensions"
  >("history");
  const [diffPair, setDiffPair] = useState<[number, number] | null>(null);

  const [search, setSearch] = useState("");
  const [method, setMethod] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [sort, setSort] = useState("");
  const params: ListParams = { q: search, method, status: statusFilter, sort, limit: 200 };
  const paramsRef = useRef(params);
  paramsRef.current = params;

  const refresh = useCallback(() => {
    listFlows(paramsRef.current)
      .then(setFlows)
      .catch((e) => {
        if (e instanceof UnauthorizedError) setAuthed(false);
        else setError(String(e));
      });
  }, []);

  useEffect(() => {
    getStatus()
      .then((s) => {
        setAuthed(true);
        setStatus(s);
      })
      .catch((e) => {
        if (e instanceof UnauthorizedError) setAuthed(false);
        else setError(String(e));
      });
  }, []);

  useEffect(() => {
    if (!authed) return;
    refresh();
    const t = setInterval(refresh, 2000); // polling fallback
    return () => clearInterval(t);
  }, [authed, refresh, search, method, statusFilter, sort]);

  // live events
  useEffect(() => {
    if (!authed) return;
    const proto = location.protocol === "https:" ? "wss" : "ws";
    const ws = new WebSocket(`${proto}://${location.host}/api/v1/events`);
    ws.onopen = () => setLive(true);
    ws.onclose = () => setLive(false);
    ws.onerror = () => setLive(false);
    ws.onmessage = (ev) => {
      try {
        const msg = JSON.parse(ev.data as string);
        if (msg.type === "flow.new" || msg.type === "flow.updated") refresh();
        // intercept.changed: InterceptTab refreshes via its own 1s poll
      } catch {
        /* ignore malformed */
      }
    };
    return () => ws.close();
  }, [authed, refresh]);

  if (authed === null) {
    return (
      <div className="flex h-full items-center justify-center text-slate-500">
        connecting…
      </div>
    );
  }
  if (!authed) {
    return (
      <TokenGate
        onLogin={async (token) => {
          await login(token);
          setAuthed(true);
        }}
      />
    );
  }

  const selectedRow = flows.find((f) => f.id === selected) ?? null;

  return (
    <div className="flex h-full flex-col">
      <header className="flex items-center gap-4 border-b border-slate-800 px-4 py-2">
        <span className="text-sm font-bold tracking-wide text-sky-400">
          ⚒ ProxyForge
        </span>
        <nav className="flex gap-1 text-xs">
          {(
            [
              "history",
              "intercept",
              "matchreplace",
              "scope",
              "target",
              "repeater",
              "intruder",
              "utilities",
              "scanner",
              "extensions",
            ] as const
          ).map((v) => (
            <button
              key={v}
              onClick={() => setView(v)}
              className={`rounded px-2 py-1 ${
                view === v
                  ? "bg-sky-800 text-white"
                  : "text-slate-400 hover:bg-slate-800"
              }`}
            >
              {v === "history"
                ? "HTTP history"
                : v === "intercept"
                  ? "Intercept"
                  : v === "matchreplace"
                    ? "Match & Replace"
                    : v === "scope"
                      ? "Scope"
                      : v === "target"
                        ? "Target"
                        : v === "repeater"
                          ? "Repeater"
                          : v === "intruder"
                            ? "Intruder"
                            : "Decoder · Comparer · Sequencer"}
            </button>
          ))}
        </nav>
        <span className="mono text-xs text-slate-500">
          {status ? `v${status.version} · ${status.flows} flows` : ""}
        </span>
        <span className="flex-1" />
        <span
          className={`text-xs ${live ? "text-emerald-400" : "text-slate-600"}`}
          title={live ? "live event stream" : "polling (2s)"}
        >
          {live ? "● live" : "○ polling"}
        </span>
      </header>

      {error && (
        <div className="border-b border-red-900 bg-red-950/50 px-4 py-1 text-xs text-red-300">
          {error}
        </div>
      )}

      {view === "intercept" ? (
        <InterceptTab />
      ) : view === "matchreplace" ? (
        <MatchReplaceTab />
      ) : view === "scope" ? (
        <ScopeTab />
      ) : view === "target" ? (
        <TargetTab />
      ) : view === "repeater" ? (
        <RepeaterTab />
      ) : view === "intruder" ? (
        <IntruderTab />
      ) : view === "utilities" ? (
        <UtilitiesTab />
      ) : view === "scanner" ? (
        <ScannerTab />
      ) : view === "extensions" ? (
        <ExtensionsTab />
      ) : (
        <>
          <div className="flex items-center gap-2 border-b border-slate-800 px-4 py-2">
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="search method · host · path · headers · body…"
              className="mono w-96 rounded border border-slate-700 bg-slate-900 px-2 py-1 text-xs outline-none focus:border-sky-600"
            />
        <select
          value={method}
          onChange={(e) => setMethod(e.target.value)}
          className="rounded border border-slate-700 bg-slate-900 px-2 py-1 text-xs"
        >
          <option value="">any method</option>
          {["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"].map(
            (m) => (
              <option key={m}>{m}</option>
            ),
          )}
        </select>
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="rounded border border-slate-700 bg-slate-900 px-2 py-1 text-xs"
        >
          <option value="">any status</option>
          {["2xx", "3xx", "4xx", "5xx"].map((s) => (
            <option key={s}>{s}</option>
          ))}
        </select>
        <select
          value={sort}
          onChange={(e) => setSort(e.target.value)}
          className="rounded border border-slate-700 bg-slate-900 px-2 py-1 text-xs"
        >
          <option value="">newest first</option>
          <option value="started_asc">oldest first</option>
          <option value="host">host</option>
          <option value="status">status</option>
          <option value="duration">slowest</option>
        </select>
        <button
          onClick={refresh}
          className="rounded border border-slate-700 bg-slate-900 px-2 py-1 text-xs hover:border-sky-600"
        >
          refresh
        </button>
        <button
          onClick={() => exportHAR(params)}
          title="export the current filter as HAR 1.2"
          className="rounded border border-slate-700 bg-slate-900 px-2 py-1 text-xs hover:border-sky-600"
        >
          ⬇ HAR
        </button>
        <span className="text-slate-600">
          {selected != null && "⌘/ctrl-click a second row to diff"}
        </span>
          </div>

          <div className="flex min-h-0 flex-1">
            <HistoryTable
              flows={flows}
              selected={selected}
              onSelect={(id, compare) => {
                if (compare && selected != null && selected !== id) {
                  setDiffPair([selected, id]);
                } else {
                  setSelected(id);
                  setDiffPair(null);
                }
              }}
              colors={HIGHLIGHT_COLORS}
            />
            {diffPair ? (
              <DiffPanel
                a={diffPair[0]}
                b={diffPair[1]}
                onClose={() => setDiffPair(null)}
              />
            ) : (
              <FlowDetail
                id={selectedRow?.id ?? null}
                onAnnotated={refresh}
                colors={HIGHLIGHT_COLORS}
              />
            )}
          </div>
        </>
      )}
    </div>
  );
}
