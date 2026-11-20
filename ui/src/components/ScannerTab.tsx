import { useCallback, useEffect, useState } from "react";
import {
  issuesList,
  scanGet,
  scanStart,
  type Issue,
  type ScanJob,
} from "../api";

const SEV_COLOR: Record<string, string> = {
  critical: "bg-red-950 text-red-300",
  high: "bg-red-950/70 text-red-300",
  medium: "bg-amber-950 text-amber-300",
  low: "bg-sky-950 text-sky-300",
  info: "bg-slate-800 text-slate-400",
};

const ACTIVE_CHECKS = [
  "xss-reflect",
  "sqli-error",
  "open-redirect",
  "path-traversal",
] as const;

export default function ScannerTab() {
  const [baseUrl, setBaseUrl] = useState("");
  const [passive, setPassive] = useState(true);
  const [active, setActive] = useState(false);
  const [checks, setChecks] = useState<string[]>([...ACTIVE_CHECKS]);
  const [confirm, setConfirm] = useState(false);
  const [job, setJob] = useState<ScanJob | null>(null);
  const [issues, setIssues] = useState<Issue[]>([]);
  const [selected, setSelected] = useState<Issue | null>(null);
  const [err, setErr] = useState("");

  const refreshIssues = useCallback(() => {
    issuesList()
      .then((l) => setIssues(l.issues ?? []))
      .catch(() => {});
  }, []);

  const refreshJob = useCallback(() => {
    if (job && job.state === "running" && job.id != null) {
      scanGet(job.id)
        .then((d) => setJob(d.job))
        .then(refreshIssues)
        .catch(() => {});
    }
  }, [job, refreshIssues]);

  useEffect(() => {
    refreshIssues();
  }, [refreshIssues]);

  useEffect(() => {
    refreshJob();
    const t = setInterval(refreshJob, 1000);
    return () => clearInterval(t);
  }, [refreshJob]);

  const start = async () => {
    setErr("");
    setJob(null);
    try {
      const { job: j } = await scanStart({
        base_url: baseUrl,
        passive,
        active,
        active_checks: active ? checks : [],
        confirm_active: confirm,
      });
      setJob(j);
    } catch (e) {
      setErr(String(e));
    }
  };

  const sevCount = (sev: string) => issues.filter((i) => i.severity === sev).length;

  return (
    <div className="flex h-full min-h-0">
      <div className="flex w-80 shrink-0 flex-col border-r border-slate-800">
        <div className="border-b border-slate-800 px-4 py-2 text-xs text-slate-400">
          scanner — passive is safe; active sends modified requests
          (in-scope only, rate-limited)
        </div>
        <div className="flex flex-col gap-2 px-4 py-3 text-xs">
          <input
            value={baseUrl}
            onChange={(e) => setBaseUrl(e.target.value)}
            placeholder="http://target.example/ or flow id"
            className="mono rounded border border-slate-700 bg-slate-900 px-2 py-1"
          />
          <label className="flex items-center gap-2">
            <input
              type="checkbox"
              checked={passive}
              onChange={(e) => setPassive(e.target.checked)}
            />
            <span className="text-slate-300">passive checks</span>
          </label>
          <label className="flex items-center gap-2">
            <input
              type="checkbox"
              checked={active}
              onChange={(e) => setActive(e.target.checked)}
            />
            <span className="text-slate-300">active checks (opt-in)</span>
          </label>
          {active && (
            <div className="ml-6 flex flex-col gap-1">
              {ACTIVE_CHECKS.map((c) => (
                <label key={c} className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    checked={checks.includes(c)}
                    onChange={(e) =>
                      setChecks((prev) =>
                        e.target.checked
                          ? [...prev, c]
                          : prev.filter((x) => x !== c),
                      )
                    }
                  />
                  <span className="mono text-slate-400">{c}</span>
                </label>
              ))}
              <label className="mt-1 flex items-center gap-2 rounded border border-amber-900 bg-amber-950/40 px-2 py-1">
                <input
                  type="checkbox"
                  checked={confirm}
                  onChange={(e) => setConfirm(e.target.checked)}
                />
                <span className="text-amber-300">
                  I am authorized to test this target
                </span>
              </label>
            </div>
          )}
          <button
            onClick={start}
            disabled={!baseUrl || (active && !confirm)}
            className="rounded bg-emerald-700 px-3 py-1.5 font-medium text-white hover:bg-emerald-600 disabled:opacity-40"
          >
            start scan
          </button>
          {err && <div className="text-red-400">{err}</div>}
          {job && (
            <div className="text-slate-400">
              #{job.id} {job.state} · {job.probed} probes ·{" "}
              <span className="text-amber-300">{job.issues} issues</span>
            </div>
          )}
        </div>
        <div className="mt-2 border-t border-slate-800 px-4 py-2 text-xs text-slate-500">
          {sevCount("critical")} critical · {sevCount("high")} high ·{" "}
          {sevCount("medium")} medium · {sevCount("low")} low ·{" "}
          {sevCount("info")} info
        </div>
      </div>

      <div className="flex min-w-0 flex-1 flex-col">
        <div className="min-h-0 flex-1 overflow-auto">
          {issues.length === 0 && (
            <p className="p-4 text-xs text-slate-600">
              no issues yet — run a scan
            </p>
          )}
          {issues.map((i) => (
            <button
              key={i.id}
              onClick={() => setSelected(i)}
              className={`flex w-full items-center gap-2 border-b border-slate-900 px-3 py-1.5 text-left text-xs hover:bg-slate-800/60 ${
                selected?.id === i.id ? "bg-sky-950/60" : ""
              }`}
            >
              <span
                className={`w-16 shrink-0 rounded px-1.5 py-0.5 text-center ${SEV_COLOR[i.severity] ?? ""}`}
              >
                {i.severity}
              </span>
              <span className="min-w-0 flex-1 truncate text-slate-200">
                {i.title}
              </span>
              <span className="mono shrink-0 text-slate-500">
                {i.host}
                {i.path.slice(0, 24)}
              </span>
              <span className="shrink-0 text-slate-600">{i.confidence}</span>
            </button>
          ))}
        </div>
        {selected && (
          <div className="h-44 shrink-0 overflow-auto border-t border-slate-800 bg-slate-950/60 px-4 py-2 text-xs">
            <div className="mb-1 flex items-center gap-2">
              <span className={`rounded px-1.5 py-0.5 ${SEV_COLOR[selected.severity]}`}>
                {selected.severity} / {selected.confidence}
              </span>
              <span className="mono text-slate-500">{selected.check_id}</span>
              {selected.evidence_flow_id ? (
                <span className="text-sky-400">
                  evidence: flow #{selected.evidence_flow_id}
                </span>
              ) : null}
            </div>
            <div className="mb-1 text-slate-200">{selected.title}</div>
            <div className="text-slate-400">{selected.detail}</div>
          </div>
        )}
      </div>
    </div>
  );
}
