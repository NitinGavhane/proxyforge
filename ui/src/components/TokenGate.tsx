import { useState } from "react";

export default function TokenGate({
  onLogin,
}: {
  onLogin: (token: string) => Promise<void>;
}) {
  const [token, setToken] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  return (
    <div className="flex h-full items-center justify-center">
      <form
        className="w-96 rounded-lg border border-slate-800 bg-slate-900/60 p-6"
        onSubmit={async (e) => {
          e.preventDefault();
          setBusy(true);
          setErr("");
          try {
            await onLogin(token.trim());
          } catch {
            setErr("invalid token — get it with: proxyforge token");
          } finally {
            setBusy(false);
          }
        }}
      >
        <h1 className="mb-1 text-lg font-semibold">ProxyForge</h1>
        <p className="mb-4 text-xs text-slate-500">
          Local control plane authentication. The API token was generated on
          first run and lives in <code className="mono">~/.proxyforge/config.toml</code>.
        </p>
        <input
          autoFocus
          type="password"
          value={token}
          onChange={(e) => setToken(e.target.value)}
          placeholder="API token"
          className="mono w-full rounded border border-slate-700 bg-slate-900 px-3 py-2 text-sm outline-none focus:border-sky-600"
        />
        {err && <p className="mt-2 text-xs text-red-400">{err}</p>}
        <button
          disabled={busy || !token.trim()}
          className="mt-4 w-full rounded bg-sky-700 px-3 py-2 text-sm font-medium text-white hover:bg-sky-600 disabled:opacity-40"
        >
          {busy ? "checking…" : "unlock"}
        </button>
      </form>
    </div>
  );
}
