import { useQuery } from "@tanstack/react-query";
import clsx from "clsx";
import { AlertTriangle, Check, CheckCircle2, ChevronDown, Copy, Loader2, Minus, Play, Upload, XCircle } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { ApiError, api } from "../api";
import { Link } from "react-router-dom";
import type { DraftReplay, DraftReplayDataset, ReplayCase, ReplayError, ReplayResult } from "../types";
import { ErrorBox, btnSecondary } from "./ui";
import { locale, t } from "../i18n";

const EXAMPLE = `{"Image": "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe", "CommandLine": "powershell.exe -enc SQBFAFgA"}
{"Image": "C:\\\\Windows\\\\explorer.exe", "CommandLine": "explorer.exe"}`;

const AUTO_KEY = "vitrix.replay.auto";
const readAuto = () => {
  try {
    return localStorage.getItem(AUTO_KEY) !== "0";
  } catch {
    return true;
  }
};

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

const ERR_TITLE: Record<string, "rp_e_unsupported" | "rp_e_regex_timeout" | "rp_e_invalid_regex" | "rp_e_bad_dataset" | "rp_e_bad_expectation" | "rp_e_invalid_rule"> = {
  unsupported: "rp_e_unsupported",
  "regex-timeout": "rp_e_regex_timeout",
  "invalid-regex": "rp_e_invalid_regex",
  "bad-dataset": "rp_e_bad_dataset",
  "bad-expectation": "rp_e_bad_expectation",
  "invalid-rule": "rp_e_invalid_rule",
};

/** A replay error in plain language: icon + title + message + hint + fix actions (never a raw exception). */
export function ErrorCard({ err, onJump }: { err: ReplayError; onJump?: () => void }) {
  const [copied, setCopied] = useState(false);
  const title = ERR_TITLE[err.code] ? t(ERR_TITLE[err.code]) : t("rp_e_generic");
  const regex = err.code === "regex-timeout" || err.code === "invalid-regex";
  return (
    <div role="alert" className="rounded-[10px] border border-warn/30 bg-warn-soft p-3 text-[13px] text-text">
      <p className="flex items-center gap-2 font-semibold text-warn">
        <AlertTriangle size={15} aria-hidden /> {title}
      </p>
      <p className="mt-1 [overflow-wrap:anywhere]">{err.message}</p>
      {err.hint && <p className="mt-1 text-muted">{t("rp_hint")} {err.hint}</p>}
      <div className="mt-2 flex flex-wrap items-center gap-3 text-xs">
        {onJump && (
          <button type="button" className="font-medium text-accent hover:underline" onClick={onJump}>
            {t("rp_open_line")}
          </button>
        )}
        {regex && (
          <Link to="/regex" className="font-medium text-accent hover:underline">
            {t("rp_open_regex")}
          </Link>
        )}
        <button
          type="button"
          className="text-muted hover:text-text"
          onClick={async () => {
            try {
              await navigator.clipboard.writeText(JSON.stringify(err, null, 2));
              setCopied(true);
              setTimeout(() => setCopied(false), 1500);
            } catch {
              /* no clipboard permission */
            }
          }}
        >
          {copied ? t("l_copied") : t("rp_copy_details")}
        </button>
      </div>
    </div>
  );
}

/** A dataset is not pass or fail: it only says whether the rule matched (neutral colours, not status). */
const matchCell = (d: DraftReplayDataset) =>
  d.error ? (
    <span className="inline-flex items-center gap-1.5 font-medium text-warn">
      <AlertTriangle size={14} aria-hidden /> {t("rp_error")}
    </span>
  ) : d.matches > 0 ? (
    <span className="inline-flex items-center gap-1.5 font-medium text-strong">
      <Check size={14} aria-hidden /> {t("rp_match")}
    </span>
  ) : (
    <span className="inline-flex items-center gap-1.5 text-muted">
      <Minus size={14} aria-hidden /> {t("rp_no_match")}
    </span>
  );

const statusCell = (ok: boolean, errored: boolean) =>
  errored ? (
    <span className="inline-flex items-center gap-1.5 font-medium text-warn">
      <AlertTriangle size={14} aria-hidden /> {t("rp_error")}
    </span>
  ) : ok ? (
    <span className="inline-flex items-center gap-1.5 font-medium text-good">
      <CheckCircle2 size={14} aria-hidden /> {t("rp_pass")}
    </span>
  ) : (
    <span className="inline-flex items-center gap-1.5 font-medium text-bad">
      <XCircle size={14} aria-hidden /> {t("rp_fail")}
    </span>
  );

function CaseDetail({ c }: { c: ReplayCase }) {
  return (
    <div className="space-y-2">
      {c.error && <ErrorCard err={c.error} />}
      {c.hint && !c.passed && <p className="text-muted">{c.hint}</p>}
      {c.selections && c.selections.length > 0 && (
        <ul className="space-y-1.5">
          {c.selections.map((s) => (
            <li key={s.name}>
              <p className="flex items-center gap-1.5 font-medium text-text">
                {s.matched ? <CheckCircle2 size={13} className="text-good" aria-hidden /> : <XCircle size={13} className="text-bad" aria-hidden />}
                {s.name}
                {s.exclusion && <span className="text-xs font-normal text-subtle">({t("rp_exclusion")})</span>}
                <span className="text-xs font-normal text-muted">{s.matched ? t("rp_sel_matched") : t("rp_sel_not")}</span>
              </p>
              <ul className="ml-5 mt-0.5 space-y-0.5 font-mono text-[12px]">
                {s.fields.map((f, i) => (
                  <li key={i} className="flex flex-wrap items-baseline gap-x-2">
                    {f.matched ? <CheckCircle2 size={12} className="text-good" aria-hidden /> : <XCircle size={12} className="text-bad" aria-hidden />}
                    <span className="text-accent">{f.field}</span>
                    <span className="text-muted">{t("rp_wants")} {JSON.stringify(f.expected)}</span>
                    <span className="text-muted">{f.present ? `${t("rp_has")} ${JSON.stringify(f.actual)}` : t("rp_absent")}</span>
                  </li>
                ))}
              </ul>
            </li>
          ))}
        </ul>
      )}
      {c.event && (
        <details className="text-xs">
          <summary className="cursor-pointer text-muted">{t("ts_event")}</summary>
          <pre className="mt-1 max-h-48 overflow-auto rounded-lg border border-line bg-code p-2 font-mono text-[12px] text-code-text">{JSON.stringify(c.event, null, 2)}</pre>
        </details>
      )}
    </div>
  );
}

function ResultTable({ res, compare }: { res: DraftReplay; compare: boolean }) {
  const cases = res.cases ?? [];
  const failingKeys = [...cases.filter((c) => !c.passed).map((c) => `c:${c.name}`), ...res.datasets.filter((d) => d.error).map((d) => `d:${d.dataset}`)];
  const [open, setOpen] = useState<Set<string>>(() => new Set(failingKeys.slice(0, 3)));
  const [chip, setChip] = useState<Record<string, number>>({});
  const [filter, setFilter] = useState<"all" | "fail" | "pass">("all");
  const toggle = (k: string) => {
    const n = new Set(open);
    if (n.has(k)) n.delete(k);
    else n.add(k);
    setOpen(n);
  };
  const casesFailed = cases.filter((c) => !c.passed).length;
  const dsFailed = res.datasets.filter((d) => d.error).length;
  const show = (ok: boolean) => filter === "all" || (filter === "pass") === ok;
  const events = res.datasets.reduce((s, d) => s + d.events, 0);
  const allGood = casesFailed === 0 && dsFailed === 0;

  const rows: React.ReactNode[] = [];
  const head = (k: string, text: string) => (
    <tr key={k} className="bg-surface-2">
      <th colSpan={5} scope="colgroup" className="px-2 py-1.5 text-left text-[11px] font-semibold uppercase tracking-wider text-subtle">
        {text}
      </th>
    </tr>
  );
  if (cases.length > 0) {
    rows.push(head("hc", t("ed_cases_head")));
    [...cases].sort((a, b) => Number(a.passed) - Number(b.passed)).forEach((c) => {
      if (!show(c.passed)) return;
      const k = `c:${c.name}`;
      const on = open.has(k);
      rows.push(
        <tr key={k} className="border-t border-line align-top">
          <td className="px-2 py-2">{statusCell(c.passed, Boolean(c.error))}</td>
          <td className="py-2 pr-3">
            <button type="button" aria-expanded={on} onClick={() => toggle(k)} className="inline-flex items-start gap-1.5 text-left text-text">
              <ChevronDown size={13} className={clsx("mt-1 shrink-0 transition-transform", !on && "-rotate-90")} aria-hidden />
              <span>
                {c.name} <span className="ml-1 text-xs text-subtle">{c.kind}</span>
              </span>
            </button>
            {on && (
              <div className="pl-5 pt-2">
                <CaseDetail c={c} />
              </div>
            )}
          </td>
          <td className="py-2 pr-3 text-xs text-muted">
            {t("expected")} <b className="font-mono text-text">{c.expected}</b>
          </td>
          <td className="py-2 pr-3 text-xs text-muted">
            {t("got")} <b className="font-mono text-text">{c.matched === null ? "-" : c.matched ? "match" : "no_match"}</b>
          </td>
          <td />
        </tr>,
      );
    });
  }
  if (res.datasets.length > 0) {
    rows.push(head("hd", t("ed_datasets_head")));
    res.datasets.forEach((d) => {
      if (!show(!d.error)) return;
      const k = `d:${d.dataset}`;
      const on = open.has(k);
      const pos = chip[k] ?? 0;
      const expandable = d.sample.length > 0 || Boolean(d.error) || (compare && ((d.added?.length ?? 0) > 0 || (d.removed?.length ?? 0) > 0));
      rows.push(
        <tr key={k} className="border-t border-line align-top">
          <td className="px-2 py-2">{matchCell(d)}</td>
          <td className="py-2 pr-3">
            <button type="button" aria-expanded={on} disabled={!expandable} onClick={() => toggle(k)} className="inline-flex items-center gap-1.5 text-left font-mono text-xs text-text disabled:cursor-default">
              <ChevronDown size={13} className={clsx("shrink-0 transition-transform", !on && "-rotate-90", !expandable && "opacity-30")} aria-hidden />
              <span className="break-all">{d.dataset}</span>
            </button>
            {on && (
              <div className="space-y-2 pl-5 pt-2">
                {d.error && <ErrorCard err={d.error} />}
                {compare && ((d.added?.length ?? 0) > 0 || (d.removed?.length ?? 0) > 0) && (
                  <p className="text-xs text-muted">
                    {t("rp_added")} {(d.added ?? []).map((e) => `#${e.index}`).join(" ") || "-"} · {t("rp_removed")} {(d.removed ?? []).map((e) => `#${e.index}`).join(" ") || "-"}
                  </p>
                )}
                {d.sample.length > 0 && (
                  <>
                    <div className="flex flex-wrap gap-1">
                      {d.sample.map((m, i) => (
                        <button key={m.index} type="button" aria-pressed={pos === i} onClick={() => setChip({ ...chip, [k]: i })} className={clsx("rounded-md px-1.5 py-0.5 font-mono text-[11px]", pos === i ? "bg-accent-soft text-strong" : "bg-surface-2 text-muted hover:text-text")}>
                          #{m.index}
                        </button>
                      ))}
                    </div>
                    {d.truncated && <p className="text-xs text-subtle">{t("rp_showing", { n: d.sample.length, more: d.matches - d.sample.length })}</p>}
                    <EventViewer key={`${k}-${pos}`} d={d} start={pos} />
                  </>
                )}
              </div>
            )}
          </td>
          <td />
          <td className="py-2 pr-3 text-xs tabular-nums text-muted">
            {d.error ? "-" : `${d.matches} / ${d.events.toLocaleString(locale())}`}
            {compare && d.before !== null && d.before !== undefined && <span className="block text-subtle">{t("rp_before")} {d.before}</span>}
          </td>
          <td className="py-2 text-right text-xs tabular-nums text-subtle">{d.duration_ms} ms</td>
        </tr>,
      );
    });
  }
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2 text-[13px]">
        <span className={clsx("inline-flex items-center gap-1.5 font-medium", allGood ? "text-good" : "text-bad")}>
          {allGood ? <CheckCircle2 size={14} aria-hidden /> : <XCircle size={14} aria-hidden />}
          {allGood ? t("rp_all_pass") : t("rp_summary", { c: casesFailed, d: dsFailed })}
        </span>
        <span className="text-xs text-muted">
          {events.toLocaleString(locale())} {t("events")} · {res.duration_ms} ms
        </span>
        <span className="flex gap-1" role="group" aria-label={t("rp_filter")}>
          {(["all", "fail", "pass"] as const).map((f) => (
            <button key={f} type="button" aria-pressed={filter === f} onClick={() => setFilter(f)} className={clsx("rounded-full px-2.5 py-0.5 text-xs", filter === f ? "bg-accent-soft font-semibold text-strong" : "text-muted hover:text-text")}>
              {t(`rp_f_${f}` as "rp_f_all")}
            </button>
          ))}
        </span>
      </div>
      {res.case_problems && res.case_problems.length > 0 && (
        <ul className="space-y-0.5 text-xs text-warn">
          {res.case_problems.map((p, i) => (
            <li key={i} className="flex gap-1.5">
              <AlertTriangle size={13} className="mt-0.5 shrink-0" aria-hidden /> {p.message}
              {p.hint && <span className="text-muted"> {p.hint}</span>}
            </li>
          ))}
        </ul>
      )}
      <div className="overflow-x-auto">
        <table className="w-full min-w-[480px] text-left text-[13px]">
          <caption className="sr-only">{t("draft_replay_per_dataset")}</caption>
          <tbody>{rows}</tbody>
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
 * Replays the unsaved draft on the local datasets (pure compute, nothing leaves the machine) and shows
 * which events match. Datasets are information only; `onBroken` reports failing test cases to the Editor.
 */
export function ReplayPanel(props: { rule: string; cases: string; ruleId: string | null; invalid: boolean; onBroken: (broken: boolean | null) => void }) {
  const { rule, cases, ruleId, invalid, onBroken } = props;
  const list = useQuery({ queryKey: ["replay-datasets"], queryFn: api.replayDatasets, retry: false });
  const [pick, setPick] = useState("");
  const [auto, setAuto] = useState(readAuto);
  const [res, setRes] = useState<DraftReplay | null>(null);
  const [ranRule, setRanRule] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ReplayError | null>(null);
  const [compare, setCompare] = useState(Boolean(ruleId)); // a saved rule compares with its saved version by default
  const ctrl = useRef<AbortController | null>(null);

  const run = () => {
    ctrl.current?.abort();
    const c = new AbortController();
    ctrl.current = c;
    setBusy(true);
    api
      .replayDraft({ rule, path: ruleId, ...(cases.trim() ? { cases } : {}), ...(compare && ruleId ? { compare: true } : {}), ...(pick ? { datasets: [pick] } : {}) }, c.signal)
      .then((r) => {
        setRes(r);
        setRanRule(rule);
        setError(null);
        setBusy(false);
        onBroken((r.cases ?? []).some((x) => !x.passed));
      })
      .catch((e: Error) => {
        if (e.name === "AbortError") return;
        const detail = e instanceof ApiError ? (e.body?.detail as unknown) : null;
        setError(detail && typeof detail === "object" && "message" in detail ? (detail as ReplayError) : { code: "server", message: e.message, hint: null });
        setBusy(false);
      });
  };

  // "Run on edit": debounced like Impact. Manual by default so large datasets do not re-run on each keystroke.
  useEffect(() => {
    if (!auto || invalid) return;
    const t = setTimeout(run, 600);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [auto, rule, cases, pick, invalid, compare]);
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
          {t("no_dataset_in")} <span className="font-mono">datasets/</span>{t("add_json_jsonl_or_yaml_logs_there_and_")}
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
                </option>
              ))}
            </select>
          </label>
          <button type="button" onClick={run} disabled={busy || invalid} aria-busy={busy} className={btnSecondary}>
            {busy ? <Loader2 size={14} className="animate-spin" aria-hidden /> : <Play size={14} aria-hidden />} {t("rp_run_replay")}
          </button>
          <label className="flex items-center gap-1.5 text-[13px] text-muted" title={ruleId ? undefined : t("rp_no_saved")}>
            <input type="checkbox" checked={compare} disabled={!ruleId} onChange={(e) => setCompare(e.target.checked)} className="accent-accent" /> {t("rp_compare")}
          </label>
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
      {error && <ErrorCard err={error} />}
      {stale && (
        <p className="flex flex-wrap items-center gap-2 text-xs text-warn">
          <AlertTriangle size={13} aria-hidden /> {t("results_are_from_an_older_version_of_t")}
          <button type="button" onClick={run} disabled={busy || invalid} className="font-medium text-accent hover:underline">
            {t("re_run")}
          </button>
        </p>
      )}
      {res && <ResultTable res={res} compare={compare && res.saved !== undefined} />}
      <PastedEvents rule={rule} />
    </div>
  );
}
