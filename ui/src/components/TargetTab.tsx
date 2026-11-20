import { useCallback, useEffect, useState } from "react";
import {
  discoveryStart,
  discoveryGet,
  discoveryStop,
  sitemapGet,
  sitemapImport,
  type DiscoveryJob,
  type SiteHost,
} from "../api";

export default function TargetTab() {
  const [hosts, setHosts] = useState<SiteHost[]>([]);
  const [open, setOpen] = useState<string | null>(null);
  const [jobs, setJobs] = useState<DiscoveryJob[]>([]);
  const [baseUrl, setBaseUrl] = useState("");
  const [rate, setRate] = useState(5);
  const [importText, setImportText] = useState("");
  const [msg, setMsg] = useState("");

  const refresh = useCallback(() => {
    sitemapGet()
      .then((s) => setHosts(s.hosts ?? []))
      .catch(() => {});
    jobs.forEach((j) => {
      if (j.state === "running") {
        discoveryGet(j.id)
          .then((d) =>
            setJobs((prev) => prev.map((p) => (p.id === d.job.id ? d.job : p))),
          )
          .catch(() => {});
      }
    });
  }, [jobs]);

  useEffect(() => {
    refresh();
    const t = setInterval(refresh, 1500);
    return () => clearInterval(t);
  }, [refresh]);

  const startDiscovery = async () => {
    setMsg("");
    try {
      const { job } = await discoveryStart({
        base_url: baseUrl,
        rate_per_sec: rate,
      });
      setJobs((prev) => [job, ...prev]);
      setMsg(`discovery job #${job.id} running`);
    } catch (e) {
      setMsg(String(e));
    }
  };

  const doImport = async () => {
    setMsg("");
    try {
      const parsed = JSON.parse(importText) as {
        host: string;
        path: string;
        scheme?: string;
        port?: number;
        method?: string;
      }[];
      const { imported } = await sitemapImport(parsed);
      setMsg(`imported ${imported} endpoints (shadow until observed)`);
      setImportText("");
      refresh();
    } catch (e) {
      setMsg(String(e));
    }
  };

  const shadowCount = (h: SiteHost) =>
    h.paths.filter((p) => p.shadow).length;

  return (
    <div className="flex h-full min-h-0">
      <div className="w-2/3 min-w-0 border-r border-slate-800">
        <div className="border-b border-slate-800 px-4 py-2 text-xs text-slate-400">
          target site map — every captured endpoint, aggregated{" "}
          <span className="text-amber-400">
            ⚑ shadow = imported but never observed
          </span>
        </div>
        <div className="min-h-0 flex-1 overflow-auto">
          {hosts.length === 0 && (
            <p className="p-4 text-xs text-slate-600">
              no endpoints yet — browse through the proxy or run discovery
            </p>
          )}
          {hosts.map((h) => (
            <div key={h.host} className="border-b border-slate-900">
              <button
                onClick={() => setOpen(open === h.host ? null : h.host)}
                className="flex w-full items-center gap-2 px-4 py-2 text-left text-xs hover:bg-slate-800/60"
              >
                <span className="text-slate-500">
                  {open === h.host ? "▾" : "▸"}
                </span>
                <span className="font-medium text-sky-300">{h.host}</span>
                <span className="text-slate-500">{h.endpoints} endpoints</span>
                {shadowCount(h) > 0 && (
                  <span className="rounded bg-amber-950 px-1.5 py-0.5 text-amber-300">
                    {shadowCount(h)} shadow
                  </span>
                )}
              </button>
              {open === h.host && (
                <div className="bg-slate-950/40">
                  {h.paths.map((p, i) => (
                    <div
                      key={i}
                      className={`flex items-center gap-3 px-10 py-1 text-xs ${
                        p.shadow ? "bg-amber-950/30" : ""
                      }`}
                    >
                      <span className="mono w-40 shrink-0 truncate text-slate-400">
                        {p.methods.join(",")}
                      </span>
                      <span className="mono min-w-0 flex-1 truncate text-slate-300">
                        {p.path}
                        {p.shadow && (
                          <span className="ml-2 text-amber-400">⚑ never observed</span>
                        )}
                      </span>
                      <span className="text-slate-500">{p.status || "—"}</span>
                      <span className="text-slate-600">×{p.count}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      <div className="flex w-1/3 min-w-0 flex-col">
        <div className="border-b border-slate-800 px-4 py-2 text-xs text-slate-400">
          content discovery — active tool, in-scope only, rate-limited
        </div>
        <div className="flex flex-col gap-2 border-b border-slate-800 px-4 py-3 text-xs">
          <input
            value={baseUrl}
            onChange={(e) => setBaseUrl(e.target.value)}
            placeholder="https://target.example/"
            className="mono rounded border border-slate-700 bg-slate-900 px-2 py-1"
          />
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
              onClick={startDiscovery}
              disabled={!baseUrl}
              className="rounded bg-sky-700 px-3 py-1 text-white hover:bg-sky-600 disabled:opacity-40"
            >
              start
            </button>
          </div>
          {msg && <div className="text-slate-400">{msg}</div>}
          {jobs.map((j) => (
            <div key={j.id} className="rounded border border-slate-800 p-2">
              <div className="flex items-center gap-2">
                <span className="text-slate-300">#{j.id}</span>
                <span
                  className={
                    j.state === "running"
                      ? "text-emerald-400"
                      : j.state === "error"
                        ? "text-red-400"
                        : "text-slate-500"
                  }
                >
                  {j.state}
                </span>
                <span className="text-slate-500">
                  {j.probed}/{j.total}
                </span>
                <span className="flex-1" />
                {j.state === "running" && (
                  <button
                    onClick={() => discoveryStop(j.id)}
                    className="rounded border border-slate-700 px-2 py-0.5"
                  >
                    stop
                  </button>
                )}
              </div>
              {j.results
                .filter((r) => r.interesting)
                .slice(0, 8)
                .map((r, i) => (
                  <div key={i} className="mono py-0.5 text-xs text-amber-300">
                    {r.status} {r.path} ({r.size}B)
                  </div>
                ))}
            </div>
          ))}
        </div>

        <div className="px-4 py-2 text-xs text-slate-400">
          import endpoints (JSON list) — the REA bridge
        </div>
        <textarea
          value={importText}
          onChange={(e) => setImportText(e.target.value)}
          spellCheck={false}
          placeholder={`[{"host":"api.example.com","path":"/v2/admin"}]`}
          className="mono h-32 resize-none border-y border-slate-800 bg-slate-950 px-3 py-2 text-xs text-slate-300 outline-none"
        />
        <div className="px-4 py-2">
          <button
            onClick={doImport}
            disabled={!importText.trim()}
            className="rounded bg-sky-700 px-3 py-1 text-xs text-white hover:bg-sky-600 disabled:opacity-40"
          >
            import
          </button>
        </div>
      </div>
    </div>
  );
}
