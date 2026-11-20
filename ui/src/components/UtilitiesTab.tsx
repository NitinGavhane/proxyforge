import { useState } from "react";
import {
  decodeTransform,
  rawCompare,
  sequencerAnalyze,
  type DecodeResult,
  type DiffResult,
  type SequencerAnalysis,
} from "../api";

const FORMATS = [
  ["url", "URL"],
  ["html", "HTML"],
  ["base64", "Base64"],
  ["hex", "Hex"],
  ["gzip", "Gzip"],
  ["jwt", "JWT"],
  ["smart", "Smart"],
] as const;

function DecoderPane() {
  const [input, setInput] = useState("");
  const [format, setFormat] = useState("base64");
  const [mode, setMode] = useState("decode");
  const [res, setRes] = useState<DecodeResult | null>(null);

  const run = async () => {
    setRes(await decodeTransform(input, format, mode));
  };

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="flex items-center gap-2 border-b border-slate-800 px-4 py-2 text-xs">
        <select
          value={format}
          onChange={(e) => setFormat(e.target.value)}
          className="rounded border border-slate-700 bg-slate-900 px-2 py-1"
        >
          {FORMATS.map(([v, label]) => (
            <option key={v} value={v}>
              {label}
            </option>
          ))}
        </select>
        <select
          value={mode}
          onChange={(e) => setMode(e.target.value)}
          className="rounded border border-slate-700 bg-slate-900 px-2 py-1"
        >
          <option value="decode">decode</option>
          <option value="encode">encode</option>
        </select>
        <span className="flex-1" />
        <button
          onClick={run}
          disabled={!input}
          className="rounded bg-sky-700 px-3 py-1 text-white hover:bg-sky-600 disabled:opacity-40"
        >
          run
        </button>
      </div>
      <textarea
        value={input}
        onChange={(e) => setInput(e.target.value)}
        spellCheck={false}
        placeholder="input…"
        className="mono h-28 resize-none border-b border-slate-800 bg-slate-950 px-3 py-2 text-xs text-slate-200 outline-none"
      />
      {res && (
        <div className="flex min-h-0 flex-1 flex-col">
          {res.steps?.length ? (
            <div className="border-b border-slate-800 px-3 py-1 text-xs text-sky-300">
              chain: {res.steps.join(" → ")}
            </div>
          ) : null}
          {res.err ? (
            <div className="px-3 py-2 text-xs text-red-400">{res.err}</div>
          ) : (
            <pre className="mono min-h-0 flex-1 overflow-auto whitespace-pre-wrap break-all px-3 py-2 text-xs text-emerald-200">
              {res.output}
            </pre>
          )}
        </div>
      )}
    </div>
  );
}

function ComparerPane() {
  const [a, setA] = useState("");
  const [b, setB] = useState("");
  const [mode, setMode] = useState("word");
  const [res, setRes] = useState<DiffResult | null>(null);

  const run = async () => setRes(await rawCompare(a, b, mode));

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="flex items-center gap-2 border-b border-slate-800 px-4 py-2 text-xs">
        <span className="text-slate-400">raw compare (or ⌘-click two rows in history)</span>
        <span className="flex-1" />
        <select
          value={mode}
          onChange={(e) => setMode(e.target.value)}
          className="rounded border border-slate-700 bg-slate-900 px-2 py-1"
        >
          <option value="word">word</option>
          <option value="byte">byte</option>
        </select>
        <button
          onClick={run}
          className="rounded bg-sky-700 px-3 py-1 text-white hover:bg-sky-600"
        >
          compare
        </button>
      </div>
      <div className="flex h-32 shrink-0">
        <textarea
          value={a}
          onChange={(e) => setA(e.target.value)}
          spellCheck={false}
          placeholder="first…"
          className="mono min-w-0 flex-1 resize-none border-r border-slate-800 bg-slate-950 px-3 py-2 text-xs text-slate-200 outline-none"
        />
        <textarea
          value={b}
          onChange={(e) => setB(e.target.value)}
          spellCheck={false}
          placeholder="second…"
          className="mono min-w-0 flex-1 resize-none bg-slate-950 px-3 py-2 text-xs text-slate-200 outline-none"
        />
      </div>
      <div className="min-h-0 flex-1 overflow-auto">
        {res && (
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
    </div>
  );
}

function SequencerPane() {
  const [tokens, setTokens] = useState("");
  const [res, setRes] = useState<SequencerAnalysis | null>(null);
  const [err, setErr] = useState("");

  const run = async () => {
    setErr("");
    try {
      setRes(await sequencerAnalyze(tokens));
    } catch (e) {
      setErr(String(e));
    }
  };

  const verdictColor =
    res?.verdict === "good"
      ? "text-emerald-400"
      : res?.verdict === "acceptable"
        ? "text-amber-400"
        : "text-red-400";

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="flex items-center gap-2 border-b border-slate-800 px-4 py-2 text-xs">
        <span className="text-slate-400">paste session tokens (one per line, ≥ 8)</span>
        <span className="flex-1" />
        <button
          onClick={run}
          disabled={!tokens.trim()}
          className="rounded bg-sky-700 px-3 py-1 text-white hover:bg-sky-600 disabled:opacity-40"
        >
          analyze
        </button>
      </div>
      <textarea
        value={tokens}
        onChange={(e) => setTokens(e.target.value)}
        spellCheck={false}
        placeholder="token1\ntoken2\n…"
        className="mono h-36 resize-none border-b border-slate-800 bg-slate-950 px-3 py-2 text-xs text-slate-200 outline-none"
      />
      {err && <div className="px-3 py-1 text-xs text-red-400">{err}</div>}
      {res && (
        <div className="min-h-0 flex-1 overflow-auto px-4 py-2 text-xs">
          <div className="mb-2 flex items-center gap-3">
            <span className="text-slate-400">verdict</span>
            <span className={`text-base font-bold ${verdictColor}`}>
              {res.verdict}
            </span>
            <span className="text-slate-500">
              {res.samples} samples · {res.unique} unique
            </span>
          </div>
          <div className="grid grid-cols-2 gap-x-6 gap-y-1 text-slate-300">
            <span>
              entropy <b className="text-slate-100">{res.entropy_bits_per_char}</b> bits/char
            </span>
            <span>
              charset <b className="text-slate-100">{res.charset_size}</b> symbols
            </span>
            <span>
              duplicates <b className="text-slate-100">{res.duplicates}</b>
            </span>
            <span>
              lengths <b className="text-slate-100">{res.min_len}–{res.max_len}</b> (avg {res.avg_len})
            </span>
            <span>
              χ² <b className="text-slate-100">{res.chi_square.toFixed?.(1) ?? res.chi_square}</b> (df {res.degrees_of_freedom})
            </span>
            <span>
              compression <b className="text-slate-100">{res.compression_ratio}</b>
            </span>
            {res.monobit && (
              <span>
                monobit{" "}
                <b className={res.monobit.pass ? "text-emerald-400" : "text-red-400"}>
                  {res.monobit.ones_ratio} {res.monobit.pass ? "pass" : "FAIL"}
                </b>
              </span>
            )}
            {res.per_position_entropy && (
              <span>
                per-position entropy [{res.per_position_entropy.slice(0, 8).join(", ")}
                {res.per_position_entropy.length > 8 ? ", …" : ""}]
              </span>
            )}
          </div>
          {res.notes?.length ? (
            <div className="mt-3">
              {res.notes.map((n, i) => (
                <div key={i} className="py-0.5 text-amber-300">
                  ⚠ {n}
                </div>
              ))}
            </div>
          ) : null}
        </div>
      )}
    </div>
  );
}

export default function UtilitiesTab() {
  const [pane, setPane] = useState<"decoder" | "comparer" | "sequencer">("decoder");
  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex gap-1 border-b border-slate-800 px-4 py-2 text-xs">
        {(["decoder", "comparer", "sequencer"] as const).map((p) => (
          <button
            key={p}
            onClick={() => setPane(p)}
            className={`rounded px-2 py-1 capitalize ${
              pane === p ? "bg-sky-800 text-white" : "text-slate-400 hover:bg-slate-800"
            }`}
          >
            {p}
          </button>
        ))}
      </div>
      {pane === "decoder" ? (
        <DecoderPane />
      ) : pane === "comparer" ? (
        <ComparerPane />
      ) : (
        <SequencerPane />
      )}
    </div>
  );
}
