import { useQuery } from "@tanstack/react-query";
import clsx from "clsx";
import { AlertTriangle, Check, CheckCircle2, ChevronDown, Copy, Loader2, Minus, Play, Upload, XCircle } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { ApiError, api } from "../api";
import type { DraftReplay, DraftReplayDataset, ReplayResult } from "../types";
import { ErrorBox, btnSecondary } from "./ui";
import { locale, t, tn } from "../i18n";

const EXAMPLE = `{"Image": "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe", "CommandLine": "powershell.exe -enc SQBFAFgA"}
{"Image": "C:\\\\Windows\\\\explorer.exe", "CommandLine": "explorer.exe"}`;

const AUTO_KEY = "vitrix.replay.auto";
const readAuto = () => {
  try {
    return localStorage.getItem(AUTO_KEY) === "1";
  } catch {
    return false;
  }
};

const expectText = (d: DraftReplayDataset) => {
  const e = d.expectation;
  if (!e) return "";
  return e.max === e.min ? `exactly ${e.min}` : `${e.min}–${e.max ?? "∞"}`;
};

function Verdict({ d }: { d: DraftReplayDataset }) {
  if (d.error)
    return (
      <span className="inline-flex items-center gap-1.5 text-warn">
        <AlertTriangle size={14} aria-hidden /> {t("not_evaluated")}
      </span>
    );
  if (d.passed === null)
    return (
      <span className="inline-flex items-center gap-1.5 text-muted">
        <Minus size={14} aria-hidden /> {t("no_expectation_for_this_rule")}
      </span>
    );
  return d.passed ? (
    <span className="inline-flex items-center gap-1.5 text-good">
      <CheckCircle2 size={14} aria-hidden /> {t("meets")}{expectText(d)})
    </span>
  ) : (
    <span className="inline-flex items-center gap-1.5 text-bad">
      <XCircle size={14} aria-hidden /> {t("breaks")}{expectText(d)})
    </span>
  );
}

function EventViewer({ d, start }: { d: DraftReplayDataset; start: number }) {
  const [pos, setPos] = useState(start);
  const [copied, setCopied] = useState(false);
  const m = d.sample[Math.min(pos, d.sample.length - 1)];
  if (!m) return null;
  const json = JSON.stringify(m.event, null, 2);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(json);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* no clipboard permission */
    }
  };
  return (
    <div className="mt-2 space-y-2">
      <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-muted">
        <span>
          {t("matched_event")} <span className="font-mono text-text">{d.dataset} · #{m.index}</span>
        </span>
        <span className="flex gap-1">
          <button type="button" disabled={pos === 0} onClick={() => setPos(pos - 1)} className="rounded-md px-2 py-1 hover:bg-surface-2 disabled:opacity-40">
            {t("prev")}
          </button>
          <button type="button" disabled={pos >= d.sample.length - 1} onClick={() => setPos(pos + 1)} className="rounded-md px-2 py-1 hover:bg-surface-2 disabled:opacity-40">
            {t("next")}
          </button>
          <button type="button" onClick={copy} className="inline-flex items-center gap-1 rounded-md px-2 py-1 hover:bg-surface-2">
            {copied ? <Check size={13} aria-hidden /> : <Copy size={13} aria-hidden />} {copied ? t("l_copied") : t("l_copy_json")}
          </button>
        </span>
      </div>
      <pre className="max-h-64 overflow-auto rounded-[10px] border border-line bg-code p-3 font-mono text-xs text-code-text">{json}</pre>
    </div>
  );
}

function ResultTable({ res }: { res: DraftReplay }) {
  const [open, setOpen] = useState<string | null>(null);
  const [chip, setChip] = useState(0);
  const events = res.datasets.reduce((s, d) => s + d.events, 0);
  const withExpect = res.datasets.filter((d) => d.passed !== null);
  const meeting = withExpect.filter((d) => d.passed).length;
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2 text-[13px] text-muted">
        <span>
          <b className="text-strong tabular-nums">{events.toLocaleString(locale())}</b> {t("events")} {tn("rp_datasets", res.datasets.length)} · <span className="tabular-nums">{res.duration_ms}</span> ms
        </span>
        {withExpect.length > 0 && (
          <span className={clsx("inline-flex items-center gap-1.5 font-medium", res.passed ? "text-good" : "text-bad")}>
            {res.passed ? <CheckCircle2 size={14} aria-hidden /> : <XCircle size={14} aria-hidden />}
            {t("rp_meet", { a: meeting, b: withExpect.length })}
          </span>
        )}
      </div>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[480px] text-left text-[13px]">
          <caption className="sr-only">{t("draft_replay_per_dataset")}</caption>
          <thead className="text-[11px] uppercase tracking-wide text-subtle">
            <tr>
              <th className="py-2 pr-3 font-medium">{t("dataset")}</th>
              <th className="py-2 pr-3 text-right font-medium">{t("events_2")}</th>
              <th className="py-2 pr-3 text-right font-medium">{t("matches")}</th>
              <th className="py-2 pr-3 font-medium">{t("expectation")}</th>
              <th className="py-2 text-right font-medium">{t("time")}</th>
            </tr>
          </thead>
          <tbody>
            {res.datasets.map((d) => {
              const isOpen = open === d.dataset;
              return (
                <tr key={d.dataset} className="border-t border-line align-top">
                  <td className="py-2 pr-3">
                    <button
                      type="button"
                      aria-expanded={isOpen}
                      disabled={d.sample.length === 0}
                      onClick={() => {
                        setOpen(isOpen ? null : d.dataset);
                        setChip(0);
                      }}
                      className="inline-flex items-center gap-1.5 text-left font-mono text-xs text-text disabled:cursor-default"
                    >
                      <ChevronDown size={13} className={clsx("shrink-0 transition-transform", !isOpen && "-rotate-90", d.sample.length === 0 && "opacity-30")} aria-hidden />
                      <span className="break-all">{d.dataset}</span>
                    </button>
                    {isOpen && (
                      <div className="pl-5">
                        <div className="mt-1.5 flex flex-wrap gap-1">
                          {d.sample.map((m, i) => (
                            <button
                              key={m.index}
                              type="button"
                              aria-pressed={chip === i}
                              onClick={() => setChip(i)}
                              className={clsx("rounded-md px-1.5 py-0.5 font-mono text-[11px]", chip === i ? "bg-accent-soft text-strong" : "bg-surface-2 text-muted hover:text-text")}
                            >
                              #{m.index}
                            </button>
                          ))}
                        </div>
                        {d.truncated && <p className="mt-1 text-xs text-subtle">{t("rp_showing", { n: d.sample.length, more: d.matches - d.sample.length })}</p>}
                        <EventViewer key={`${d.dataset}-${chip}`} d={d} start={chip} />
                      </div>
                    )}
                  </td>
                  <td className="py-2 pr-3 text-right tabular-nums">{d.error ? "—" : d.events.toLocaleString(locale())}</td>
                  <td className="py-2 pr-3 text-right font-semibold text-strong tabular-nums">{d.error ? "—" : d.matches}</td>
                  <td className="py-2 pr-3">
                    <Verdict d={d} />
                    {d.passed === false && !d.error && d.message && <span className="block text-xs text-bad">{d.message}</span>}
                    {d.error && <span className="block text-xs text-warn [overflow-wrap:anywhere]">{d.error}</span>}
                  </td>
                  <td className="py-2 text-right text-xs text-subtle tabular-nums">{d.duration_ms} ms</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function PastedEvents({ rule }: { rule: string }) {
  const [text, setText] = useState("");
  const [res, setRes] = useState<ReplayResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const run = () => {
    setBusy(true);
    api
      .replay(text, rule)
      .then((r) => {
        setRes(r);
        setError(null);
      })
      .catch((e: Error) => setError(e.message))
      .finally(() => setBusy(false));
  };
  const mine = res?.rules.find((r) => r.rule === "<editor>") ?? res?.rules[0];
  return (
    <details className="rounded-[10px] border border-line bg-surface">
      <summary className="cursor-pointer px-3 py-2 text-[13px] font-medium text-text">{t("paste_events")}</summary>
      <div className="space-y-2 border-t border-line p-3">
        <label className="block">
          <span className="sr-only">{t("events_as_json_json_lines_or_yaml")}</span>
          <textarea
            value={text}
            onChange={(e) => setText(e.target.value)}
            rows={6}
            placeholder={t("paste_events_as_json_json_lines_or_yam")}
            className="w-full rounded-[10px] border border-line bg-code p-3 font-mono text-xs text-code-text placeholder:text-subtle focus:border-accent/50"
          />
        </label>
        <div className="flex flex-wrap gap-2">
          <button type="button" disabled={!text.trim() || busy} aria-busy={busy} onClick={run} className={btnSecondary}>
            {busy ? <Loader2 size={14} className="animate-spin" aria-hidden /> : <Play size={14} aria-hidden />} {t("rp_run_pasted")}
          </button>
          <label className={clsx(btnSecondary, "cursor-pointer")}>
            <Upload size={14} aria-hidden /> {t("file")}
            <input
              type="file"
              accept=".json,.jsonl,.ndjson,.yml,.yaml"
              className="sr-only"
              onChange={async (e) => {
                const f = e.target.files?.[0];
                if (f) setText(await f.text());
              }}
            />
          </label>
          <button type="button" onClick={() => setText(EXAMPLE)} className="rounded-[10px] px-3 py-2 text-[13px] text-muted hover:text-text">
            {t("example")}
          </button>
        </div>
        {error && <ErrorBox message={error} />}
        {res && (
          <div className="text-[13px] text-muted" aria-live="polite">
            {mine?.error ? (
              <span className="inline-flex items-center gap-1.5 text-warn">
                <AlertTriangle size={14} aria-hidden /> {t("not_evaluated_2")} {mine.error}
              </span>
            ) : (
              <>
                <b className="text-strong tabular-nums">{mine?.matches ?? 0}</b> {t("rp_of_events_match", { n: res.events })}
                {mine && mine.sample.length > 0 && <span className="font-mono text-xs"> · #{mine.sample.join(", #")}</span>}
              </>
            )}
          </div>
        )}
      </div>
    </details>
  );
}

/**
 * Replays the unsaved draft on the local datasets (pure compute, nothing leaves the machine) and
 * compares the matches with `<dataset>.expect.yml`. Reports to the Editor whether an expectation broke.
 */
export function ReplayPanel(props: { rule: string; ruleId: string | null; invalid: boolean; onBroken: (broken: boolean | null) => void }) {
  const { rule, ruleId, invalid, onBroken } = props;
  const list = useQuery({ queryKey: ["replay-datasets"], queryFn: api.replayDatasets, retry: false });
  const [pick, setPick] = useState("");
  const [auto, setAuto] = useState(readAuto);
  const [res, setRes] = useState<DraftReplay | null>(null);
  const [ranRule, setRanRule] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const ctrl = useRef<AbortController | null>(null);

  const run = () => {
    ctrl.current?.abort();
    const c = new AbortController();
    ctrl.current = c;
    setBusy(true);
    api
      .replayDraft({ rule, path: ruleId, ...(pick ? { datasets: [pick] } : {}) }, c.signal)
      .then((r) => {
        setRes(r);
        setRanRule(rule);
        setError(null);
        setBusy(false);
        onBroken(r.datasets.some((d) => d.passed === false));
      })
      .catch((e: Error) => {
        if (e.name === "AbortError") return;
        setError(e.message);
        setBusy(false);
      });
  };

  // "Run on edit": debounced like Impact. Manual by default so large datasets do not re-run on each keystroke.
  useEffect(() => {
    if (!auto || invalid) return;
    const t = setTimeout(run, 600);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [auto, rule, pick, invalid]);
  useEffect(() => () => ctrl.current?.abort(), []);

  const toggleAuto = (v: boolean) => {
    setAuto(v);
    try {
      localStorage.setItem(AUTO_KEY, v ? "1" : "0");
    } catch {
      /* storage unavailable */
    }
  };

  const datasets = list.data ?? [];
  const forbidden = list.error instanceof ApiError && list.error.status === 403 ? t("l_your_role_cannot_run_replay") : null;
  const stale = res !== null && ranRule !== rule;

  return (
    <div className="space-y-4">
      <p className="text-[13px] text-muted">{t("replay_this_draft_on_local_logs_nothin")}</p>
      {list.isLoading && <p className="text-sm text-muted">{t("reading_datasets")}</p>}
      {list.error && (forbidden ? <p className="text-sm text-muted">{forbidden}</p> : <ErrorBox message={(list.error as Error).message} />)}
      {list.data && datasets.length === 0 && (
        <p className="text-sm text-muted">
          {t("no_dataset_in")} <span className="font-mono">datasets/</span>{t("add_json_jsonl_or_yaml_logs_there_and_")} <span className="font-mono">name.expect.yml</span> {t("with_the_expected_counts")}
        </p>
      )}
      {datasets.length > 0 && (
        <div className="flex flex-wrap items-center gap-3">
          <label className="flex items-center gap-2 text-[13px] text-muted">
            {t("dataset")}
            <select value={pick} onChange={(e) => setPick(e.target.value)} className="rounded-[10px] border border-line bg-surface px-2.5 py-2 text-[13px] text-text">
              <option value="">{t("all_datasets")}{datasets.length})</option>
              {datasets.map((d) => (
                <option key={d.name} value={d.name}>
                  {d.name}
                  {d.has_expectations ? "" : " (no expectations)"}
                </option>
              ))}
            </select>
          </label>
          <button type="button" onClick={run} disabled={busy || invalid} aria-busy={busy} className={btnSecondary}>
            {busy ? <Loader2 size={14} className="animate-spin" aria-hidden /> : <Play size={14} aria-hidden />} {t("rp_run_replay")}
          </button>
          <label className="flex items-center gap-1.5 text-[13px] text-muted">
            <input type="checkbox" checked={auto} onChange={(e) => toggleAuto(e.target.checked)} className="accent-accent" /> {t("run_on_edit")}
          </label>
          {invalid && <span className="text-xs text-warn">{t("fix_validation_errors_first")}</span>}
        </div>
      )}
      {datasets.some((d) => d.error) && (
        <ul className="space-y-0.5 text-xs text-warn">
          {datasets
            .filter((d) => d.error)
            .map((d) => (
              <li key={d.name} className="flex gap-1.5">
                <AlertTriangle size={13} className="mt-0.5 shrink-0" aria-hidden />
                <span>
                  <span className="font-mono">{d.name}</span>: {d.error}
                </span>
              </li>
            ))}
        </ul>
      )}
      {error && <ErrorBox message={error} />}
      {stale && (
        <p className="flex flex-wrap items-center gap-2 text-xs text-warn">
          <AlertTriangle size={13} aria-hidden /> {t("results_are_from_an_older_version_of_t")}
          <button type="button" onClick={run} disabled={busy || invalid} className="font-medium text-accent hover:underline">
            {t("re_run")}
          </button>
        </p>
      )}
      {res && <ResultTable res={res} />}
      <PastedEvents rule={rule} />
    </div>
  );
}
