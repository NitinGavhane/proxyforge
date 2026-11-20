import { useCallback, useEffect, useState } from "react";
import {
  mrAdd,
  mrDelete,
  mrList,
  mrToggle,
  type MRRule,
} from "../api";

function actionSummary(r: MRRule): string {
  const a = r.action;
  switch (a.type) {
    case "header_set":
      return `set ${a.header_key}: ${a.header_value}`;
    case "header_add":
      return `add ${a.header_key}: ${a.header_value}`;
    case "header_remove":
      return `remove ${a.header_key}`;
    case "body_regex":
      return `body s/${a.regex}/${a.replacement}/`;
    case "body_raw":
      return `body "${a.find}" → "${a.replace}"`;
    default:
      return a.type;
  }
}

function specSummary(r: MRRule): string {
  const s = r.spec;
  const parts: string[] = [];
  if (s.method) parts.push(s.method);
  if (s.host) parts.push(`~${s.host}`);
  if (s.url_regex) parts.push(`url~${s.url_regex}`);
  if (s.content_type) parts.push(`ct:${s.content_type}`);
  if (s.header_regex) parts.push(`hdr~${s.header_regex}`);
  if (s.body_regex) parts.push(`body~${s.body_regex}`);
  if (s.status_regex) parts.push(`status~${s.status_regex}`);
  return parts.join(" ") || "everything";
}

export default function MatchReplaceTab() {
  const [rules, setRules] = useState<MRRule[]>([]);
  const [expanded, setExpanded] = useState<number | null>(null);
  const [showForm, setShowForm] = useState(false);
  // form state
  const [name, setName] = useState("");
  const [direction, setDirection] = useState("request");
  const [type, setType] = useState("header_add");
  const [headerKey, setHeaderKey] = useState("");
  const [headerValue, setHeaderValue] = useState("");
  const [regex, setRegex] = useState("");
  const [replacement, setReplacement] = useState("");
  const [find, setFind] = useState("");
  const [replace, setReplace] = useState("");
  const [error, setError] = useState("");

  const refresh = useCallback(() => {
    mrList()
      .then((r) => setRules(r))
      .catch(() => {});
  }, []);

  useEffect(() => {
    refresh();
    const t = setInterval(refresh, 2000);
    return () => clearInterval(t);
  }, [refresh]);

  const submit = async () => {
    setError("");
    const action: Record<string, string> = { type };
    if (type === "header_set" || type === "header_add" || type === "header_remove") {
      action.header_key = headerKey;
      action.header_value = headerValue;
    } else if (type === "body_regex") {
      action.regex = regex;
      action.replacement = replacement;
    } else if (type === "body_raw") {
      action.find = find;
      action.replace = replace;
    }
    try {
      await mrAdd({ name, enabled: true, direction, spec: {}, action });
      setName("");
      setHeaderKey("");
      setHeaderValue("");
      setRegex("");
      setReplacement("");
      setFind("");
      setReplace("");
      setShowForm(false);
      refresh();
    } catch (e) {
      setError(String(e));
    }
  };

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex items-center gap-3 border-b border-slate-800 px-4 py-2 text-xs">
        <span className="text-slate-400">
          automatic modifications — applied in rule order before interception
        </span>
        <span className="flex-1" />
        <button
          onClick={() => setShowForm((v) => !v)}
          className="rounded bg-sky-700 px-2 py-1 text-white hover:bg-sky-600"
        >
          {showForm ? "cancel" : "add rule"}
        </button>
      </div>

      {showForm && (
        <div className="grid grid-cols-4 gap-2 border-b border-slate-800 bg-slate-900/40 px-4 py-3 text-xs">
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="rule name"
            className="col-span-2 rounded border border-slate-700 bg-slate-900 px-2 py-1"
          />
          <select
            value={direction}
            onChange={(e) => setDirection(e.target.value)}
            className="rounded border border-slate-700 bg-slate-900 px-2 py-1"
          >
            <option value="request">request</option>
            <option value="response">response</option>
          </select>
          <select
            value={type}
            onChange={(e) => setType(e.target.value)}
            className="rounded border border-slate-700 bg-slate-900 px-2 py-1"
          >
            <option value="header_add">add header</option>
            <option value="header_set">set header</option>
            <option value="header_remove">remove header</option>
            <option value="body_regex">body regex</option>
            <option value="body_raw">body raw replace</option>
          </select>
          {(type === "header_set" || type === "header_add" || type === "header_remove") && (
            <>
              <input
                value={headerKey}
                onChange={(e) => setHeaderKey(e.target.value)}
                placeholder="header name"
                className="mono rounded border border-slate-700 bg-slate-900 px-2 py-1"
              />
              {type !== "header_remove" && (
                <input
                  value={headerValue}
                  onChange={(e) => setHeaderValue(e.target.value)}
                  placeholder="value"
                  className="mono col-span-3 rounded border border-slate-700 bg-slate-900 px-2 py-1"
                />
              )}
            </>
          )}
          {type === "body_regex" && (
            <>
              <input
                value={regex}
                onChange={(e) => setRegex(e.target.value)}
                placeholder='regex, e.g. "password":"[^"]*"'
                className="mono col-span-2 rounded border border-slate-700 bg-slate-900 px-2 py-1"
              />
              <input
                value={replacement}
                onChange={(e) => setReplacement(e.target.value)}
                placeholder="replacement ($1 groups)"
                className="mono col-span-2 rounded border border-slate-700 bg-slate-900 px-2 py-1"
              />
            </>
          )}
          {type === "body_raw" && (
            <>
              <input
                value={find}
                onChange={(e) => setFind(e.target.value)}
                placeholder="find (literal)"
                className="mono col-span-2 rounded border border-slate-700 bg-slate-900 px-2 py-1"
              />
              <input
                value={replace}
                onChange={(e) => setReplace(e.target.value)}
                placeholder="replace with"
                className="mono col-span-2 rounded border border-slate-700 bg-slate-900 px-2 py-1"
              />
            </>
          )}
          <div className="col-span-4 flex items-center gap-2">
            {error && <span className="text-red-400">{error}</span>}
            <span className="flex-1" />
            <button
              onClick={submit}
              disabled={!name}
              className="rounded bg-emerald-700 px-3 py-1 text-white hover:bg-emerald-600 disabled:opacity-40"
            >
              save rule
            </button>
          </div>
        </div>
      )}

      <div className="min-h-0 flex-1 overflow-auto">
        {rules.length === 0 && (
          <p className="p-4 text-xs text-slate-600">
            no match & replace rules — add one to modify traffic automatically
          </p>
        )}
        {rules.map((r) => (
          <div key={r.id} className="border-b border-slate-900">
            <div className="flex items-center gap-3 px-4 py-2 text-xs">
              <input
                type="checkbox"
                checked={r.enabled}
                onChange={(e) =>
                  mrToggle(r.id, e.target.checked).then(refresh)
                }
              />
              <span className="w-28 truncate text-slate-200" title={r.name}>
                {r.name}
              </span>
              <span
                className={`rounded px-1.5 py-0.5 ${
                  r.direction === "request"
                    ? "bg-sky-950 text-sky-300"
                    : "bg-emerald-950 text-emerald-300"
                }`}
              >
                {r.direction}
              </span>
              <span className="mono min-w-0 flex-1 truncate text-slate-500" title={specSummary(r)}>
                if [{specSummary(r)}]
              </span>
              <span className="mono min-w-0 flex-1 truncate text-amber-300" title={actionSummary(r)}>
                {actionSummary(r)}
              </span>
              <span className="text-slate-400" title="hits">
                ✓{r.hits}
              </span>
              <button
                onClick={() => setExpanded(expanded === r.id ? null : r.id)}
                className="text-slate-500 hover:text-slate-300"
                title="recent matches"
              >
                {expanded === r.id ? "▾" : "▸"}
              </button>
              <button
                onClick={() => mrDelete(r.id).then(refresh)}
                className="text-red-500 hover:text-red-300"
                title="delete"
              >
                ✕
              </button>
            </div>
            {expanded === r.id && (
              <div className="bg-slate-950/40 px-8 py-2 text-xs">
                {r.recent?.length ? (
                  r.recent.map((m, i) => (
                    <div key={i} className="mono flex gap-3 py-0.5 text-slate-400">
                      <span className="text-slate-600">
                        {new Date(m.ts).toLocaleTimeString([], { hour12: false })}
                      </span>
                      <span className="min-w-0 flex-1 truncate" title={m.where}>
                        {m.where}
                      </span>
                      <span className="text-slate-500">{m.note}</span>
                    </div>
                  ))
                ) : (
                  <span className="text-slate-600">no matches yet</span>
                )}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
