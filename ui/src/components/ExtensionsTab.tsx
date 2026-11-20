import { useCallback, useEffect, useState } from "react";
import {
  extAdd,
  extDelete,
  extList,
  extTest,
  extUpdate,
  type PFExtension,
  type ExtTestView,
} from "../api";

export default function ExtensionsTab() {
  const [exts, setExts] = useState<PFExtension[]>([]);
  const [sel, setSel] = useState<number | null>(null);
  const [name, setName] = useState("");
  const [code, setCode] = useState(
    "function onRequest(flow) {\n  // mutate flow.request: method, path, headers [{name,value}], body\n}\nfunction onResponse(flow) {\n  // mutate flow.response: status, headers, body\n}\n",
  );
  const [testFlow, setTestFlow] = useState("");
  const [view, setView] = useState<ExtTestView | null>(null);
  const [err, setErr] = useState("");
  const [msg, setMsg] = useState("");

  const refresh = useCallback(() => {
    extList()
      .then((l) => setExts(l.extensions ?? []))
      .catch(() => {});
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const selected = exts.find((e) => e.id === sel) ?? null;
  useEffect(() => {
    if (selected) {
      setName(selected.name);
      setCode(selected.code);
    }
  }, [sel, exts]);

  const add = async () => {
    setErr("");
    try {
      await extAdd(name, code, true);
      setName("");
      refresh();
      setMsg("added");
      setTimeout(() => setMsg(""), 1500);
    } catch (e) {
      setErr(String(e));
    }
  };

  const save = async () => {
    setErr("");
    try {
      await extUpdate(selected!.id, { name, code });
      refresh();
      setMsg("saved");
      setTimeout(() => setMsg(""), 1500);
    } catch (e) {
      setErr(String(e));
    }
  };

  const toggle = async (id: number, enabled: boolean) => {
    await extUpdate(id, { enabled });
    refresh();
  };

  const runTest = async () => {
    setErr("");
    setView(null);
    try {
      const v = await extTest(selected!.id, Number(testFlow));
      setView(v);
    } catch (e) {
      setErr(String(e));
    }
  };

  return (
    <div className="flex h-full min-h-0">
      <div className="w-64 shrink-0 overflow-auto border-r border-slate-800">
        <div className="border-b border-slate-800 px-3 py-2 text-xs text-slate-400">
          extensions (JS) — pure sandbox, no I/O
        </div>
        {exts.map((e) => (
          <div
            key={e.id}
            className={`flex items-center gap-2 border-b border-slate-900 px-3 py-1.5 text-xs ${
              sel === e.id ? "bg-sky-950/60" : ""
            } hover:bg-slate-800/60`}
          >
            <input
              type="checkbox"
              checked={e.enabled}
              onChange={(ev) => toggle(e.id, ev.target.checked)}
            />
            <button className="min-w-0 flex-1 text-left" onClick={() => setSel(e.id)}>
              <div className="truncate text-slate-200">{e.name}</div>
              <div className="text-slate-600">
                ✓{e.runs} {e.errors > 0 && <span className="text-red-400">✗{e.errors}</span>}
              </div>
            </button>
            {e.last_error && <span title={e.last_error}>⚠</span>}
            <button
              onClick={() => extDelete(e.id).then(refresh)}
              className="text-red-500 hover:text-red-300"
            >
              ✕
            </button>
          </div>
        ))}
        <button
          onClick={add}
          disabled={!name.trim()}
          className="m-3 rounded bg-sky-700 px-3 py-1 text-xs text-white hover:bg-sky-600 disabled:opacity-40"
        >
          + new extension
        </button>
      </div>

      <div className="flex min-w-0 flex-1 flex-col">
        <div className="flex items-center gap-2 border-b border-slate-800 px-3 py-1.5 text-xs">
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="name"
            className="w-40 rounded border border-slate-700 bg-slate-900 px-2 py-1"
          />
          {selected && (
            <>
              <button
                onClick={save}
                className="rounded bg-emerald-700 px-3 py-1 text-white hover:bg-emerald-600"
              >
                save
              </button>
              <input
                value={testFlow}
                onChange={(e) => setTestFlow(e.target.value)}
                placeholder="flow id to test"
                className="mono w-28 rounded border border-slate-700 bg-slate-900 px-2 py-1"
              />
              <button
                onClick={runTest}
                disabled={!testFlow}
                className="rounded border border-slate-700 px-2 py-1 hover:border-sky-600 disabled:opacity-40"
              >
                dry run
              </button>
            </>
          )}
          {msg && <span className="text-emerald-400">{msg}</span>}
          {err && <span className="truncate text-red-400">{err}</span>}
        </div>
        <textarea
          value={code}
          onChange={(e) => setCode(e.target.value)}
          spellCheck={false}
          className="mono min-h-0 flex-1 resize-none bg-slate-950 px-3 py-2 text-xs text-slate-200 outline-none"
        />
        {view && (
          <div className="h-40 shrink-0 overflow-auto border-t border-slate-800 bg-slate-950/60 px-3 py-2 text-xs">
            {view.error && <div className="text-red-400">error: {view.error}</div>}
            <div className="grid grid-cols-2 gap-2">
              <div>
                <div className="mb-1 text-slate-500">before</div>
                <pre className="mono whitespace-pre-wrap break-all text-slate-400">
                  {JSON.stringify(view.before, null, 1)}
                </pre>
              </div>
              <div>
                <div className="mb-1 text-slate-500">after</div>
                <pre className="mono whitespace-pre-wrap break-all text-emerald-300">
                  {JSON.stringify(view.after, null, 1)}
                </pre>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
