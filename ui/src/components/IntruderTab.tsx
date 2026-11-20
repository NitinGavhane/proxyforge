import { useCallback, useEffect, useState } from "react";
import {
  intruderGet,
  intruderStart,
  intruderStop,
  type IntruderJob,
  type IntruderResult,
} from "../api";

const ATTACK_TYPES = [
  ["sniper", "Sniper"],
  ["battering_ram", "Battering ram"],
  ["pitchfork", "Pitchfork"],
  ["cluster_bomb", "Cluster bomb"],
] as const;

export default function IntruderTab() {
  const [raw, setRaw] = useState(
    "GET /§id§ HTTP/1.1\nHost: example.com\nX-Scheme: https\n",
  );
  const [attackType, setAttackType] = useState<string>("sniper");
  const [sets, setSets] = useState<string[]>(["a\nb"]);
  const [matchRe, setMatchRe] = useState("");
  const [extractRe, setExtractRe] = useState("");
  const [rate, setRate] = useState(5);
  const [job, setJob] = useState<IntruderJob | null>(null);
  const [err, setErr] = useState("");

  const refresh = useCallback(() => {
    if (job && job.state === "running" && job.id != null) {
      intruderGet(job.id)
        .then((d) => setJob(d.job))
        .catch(() => {});
    }
  }, [job]);

  useEffect(() => {
    refresh();
    const t = setInterval(refresh, 1000);
    return () => clearInterval(t);
  }, [refresh]);

  const start = async () => {
    setErr("");
    setJob(null);
    try {
      const payload_sets = sets.map((text) => ({
        type: "list",
        items: text.split("\n").filter((l) => l !== ""),
      }));
      const { job: j } = await intruderStart({
        attack_type: attackType,
        raw,
        payload_sets,
        match: matchRe ? [{ name: "match", regex: matchRe }] : [],
        extract: extractRe ? [{ name: "extract", regex: extractRe }] : [],
        rate_per_sec: rate,
      });
      setJob(j);
    } catch (e) {
      setErr(String(e));
    }
  };

  const grepKeys = (r: IntruderResult) =>
    Object.keys(r.matches ?? {}).concat(Object.keys(r.extracts ?? {}));

  return (
    <div className="flex h-full min-h-0">
      <div className="flex w-2/5 min-w-0 flex-col border-r border-slate-800">
        <div className="border-b border-slate-800 px-4 py-2 text-xs text-slate-400">
          intruder — mark positions with §name§, scope-gated + rate-limited
        </div>
        <textarea
          value={raw}
          onChange={(e) => setRaw(e.target.value)}
          spellCheck={false}
          className="mono h-44 resize-none border-b border-slate-800 bg-slate-950 px-3 py-2 text-xs text-slate-200 outline-none"
        />
        <div className="flex flex-col gap-2 px-4 py-2 text-xs">
          <select
            value={attackType}
            onChange={(e) => setAttackType(e.target.value)}
            className="rounded border border-slate-700 bg-slate-900 px-2 py-1"
          >
            {ATTACK_TYPES.map(([v, label]) => (
              <option key={v} value={v}>
                {label}
              </option>
            ))}
          </select>
          {sets.map((text, i) => (
            <div key={i} className="flex items-center gap-2">
              <span className="w-16 text-slate-500">set {i + 1}</span>
              <textarea
                value={text}
                onChange={(e) =>
                  setSets((prev) =>
                    prev.map((p, j) => (j === i ? e.target.value : p)),
                  )
                }
                placeholder="one payload per line"
                className="mono h-16 flex-1 resize-none rounded border border-slate-700 bg-slate-900 px-2 py-1"
              />
              {sets.length > 1 && (
                <button
                  onClick={() =>
                    setSets((prev) => prev.filter((_, j) => j !== i))
                  }
                  className="text-red-500"
                >
                  ✕
                </button>
              )}
            </div>
          ))}
          <button
            onClick={() => setSets((prev) => [...prev, ""])}
            className="self-start rounded border border-slate-700 px-2 py-0.5 text-slate-400"
          >
            + set
          </button>
          <div className="flex gap-2">
            <input
              value={matchRe}
              onChange={(e) => setMatchRe(e.target.value)}
              placeholder="grep match regex"
              className="mono min-w-0 flex-1 rounded border border-slate-700 bg-slate-900 px-2 py-1"
            />
            <input
              value={extractRe}
              onChange={(e) => setExtractRe(e.target.value)}
              placeholder="extract (group 1)"
              className="mono min-w-0 flex-1 rounded border border-slate-700 bg-slate-900 px-2 py-1"
            />
          </div>
          <div className="flex items-center gap-2">
            <span className="text-slate-500">rate</span>
            <input
              type="number"
              min={1}
              max={20}
              value={rate}
              onChange={(e) => setRate(Number(e.target.value))}
              className="w-16 rounded border border-slate-700 bg-slate-900 px-2 py-1"
            />
            <span className="text-slate-500">req/s</span>
            <span className="flex-1" />
            <button
              onClick={start}
              className="rounded bg-emerald-700 px-4 py-1 font-medium text-white hover:bg-emerald-600"
            >
              start attack
            </button>
          </div>
          {err && <div className="text-red-400">{err}</div>}
          {job && (
            <div className="flex items-center gap-2">
              <span
                className={
                  job.state === "running"
                    ? "text-emerald-400"
                    : job.state === "error"
                      ? "text-red-400"
                      : "text-slate-500"
                }
              >
                #{job.id} {job.state}
              </span>
              <span className="text-slate-500">
                {job.sent}/{job.total}
              </span>
              {job.state === "running" && (
                <button
                  onClick={() => intruderStop(job.id)}
                  className="rounded border border-slate-700 px-2 py-0.5"
                >
                  stop
                </button>
              )}
            </div>
          )}
        </div>
      </div>

      <div className="min-w-0 flex-1 overflow-auto">
        <div className="border-b border-slate-800 px-4 py-2 text-xs text-slate-400">
          results{" "}
          {job ? `· ${job.results?.length ?? 0} rows (attack ${job.attack_type})` : ""}
        </div>
        {!job?.results?.length && (
          <p className="p-4 text-xs text-slate-600">
            no results yet — configure and start an attack
          </p>
        )}
        {job?.results?.length ? (
          <table className="w-full text-left text-xs">
            <thead className="sticky top-0 bg-slate-900/95 text-slate-500">
              <tr>
                <th className="px-2 py-1">#</th>
                <th className="px-2 py-1">payloads</th>
                <th className="px-2 py-1">status</th>
                <th className="px-2 py-1">size</th>
                <th className="px-2 py-1">ms</th>
                <th className="px-2 py-1">grep</th>
                <th className="px-2 py-1">err</th>
              </tr>
            </thead>
            <tbody className="mono">
              {job.results.map((r) => (
                <tr
                  key={r.index}
                  className={`border-b border-slate-900 ${
                    grepKeys(r).length ? "bg-emerald-950/40" : ""
                  }`}
                >
                  <td className="px-2 py-0.5 text-slate-600">{r.index}</td>
                  <td className="max-w-64 truncate px-2 py-0.5 text-amber-300">
                    {r.payloads.join(" ⋅ ")}
                  </td>
                  <td
                    className={`px-2 py-0.5 font-semibold ${
                      r.status >= 500
                        ? "text-red-400"
                        : r.status >= 400
                          ? "text-amber-400"
                          : r.status > 0
                            ? "text-emerald-400"
                            : "text-slate-600"
                    }`}
                  >
                    {r.status || "—"}
                  </td>
                  <td className="px-2 py-0.5 text-slate-500">{r.size}</td>
                  <td className="px-2 py-0.5 text-slate-500">{r.ms}</td>
                  <td className="max-w-72 truncate px-2 py-0.5 text-sky-300">
                    {Object.entries(r.matches ?? {})
                      .map(([k, v]) => `${k}:${v}`)
                      .join(" ")}
                    {Object.entries(r.extracts ?? {})
                      .map(([k, v]) => `${k}=${v}`)
                      .join(" ")}
                  </td>
                  <td className="max-w-48 truncate px-2 py-0.5 text-red-400">
                    {r.err || ""}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : null}
      </div>
    </div>
  );
}
