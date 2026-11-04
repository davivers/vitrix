import { useQuery } from "@tanstack/react-query";
import clsx from "clsx";
import { AlertTriangle, CheckCircle2, ChevronRight, Minus, Play, Search, XCircle } from "lucide-react";
import { Fragment, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api } from "../api";
import { IssueList } from "../components/Issues";
import { timeAgo } from "../components/dash";
import { KindTag } from "../components/flow";
import { Card, ErrorBox, LevelTag, PageHeader, btnPrimary, btnSecondary, inputCls } from "../components/ui";
import type { CaseKind, CaseResult, SuiteRule } from "../types";
import { t, tn } from "../i18n";

type RuleState = "failing" | "weak" | "none" | "healthy";
const ORDER: Record<RuleState, number> = { failing: 0, weak: 1, none: 2, healthy: 3 };
const KINDS: CaseKind[] = ["positive", "negative", "false_positive", "edge"];

const failedCases = (r: SuiteRule) => r.results.filter((c) => !c.passed);
const hasErrors = (r: SuiteRule) => r.problems.some((p) => p.severity === "error");

/** Failing = a case fails; Weak = all pass but no false-positive case; Healthy = all pass; None = no cases. */
function stateOf(r: SuiteRule): RuleState {
  if (r.results.length === 0) return "none";
  if (failedCases(r).length > 0 || hasErrors(r)) return "failing";
  return r.results.some((c) => c.kind === "false_positive") ? "healthy" : "weak";
}

const frac = (r: SuiteRule, kinds: CaseKind[]) => {
  const rows = r.results.filter((c) => kinds.includes(c.kind));
  return rows.length ? `${rows.filter((c) => c.passed).length}/${rows.length}` : "-";
};

function StateCell({ r, s }: { r: SuiteRule; s: RuleState }) {
  if (s === "failing")
    return (
      <span className="inline-flex items-center gap-1.5 font-medium text-bad">
        <XCircle size={14} aria-hidden /> {t("ts_st_failing", { n: failedCases(r).length || r.problems.length })}
      </span>
    );
  if (s === "weak")
    return (
      <span className="inline-flex items-center gap-1.5 font-medium text-warn">
        <AlertTriangle size={14} aria-hidden /> {t("ts_st_weak")}
      </span>
    );
  if (s === "none")
    return (
      <span className="inline-flex items-center gap-1.5 text-muted">
        <Minus size={14} aria-hidden /> {t("ts_st_none")}
      </span>
    );
  return (
    <span className="inline-flex items-center gap-1.5 font-medium text-good">
      <CheckCircle2 size={14} aria-hidden /> {t("ts_st_healthy")}
    </span>
  );
};

function CaseDetail({ c }: { c: CaseResult & { hint?: string | null } }) {
  return (
    <li className="space-y-1 py-2 text-[13px]">
      <p className="flex flex-wrap items-center gap-2">
        {c.passed ? <CheckCircle2 size={14} className="text-good" aria-hidden /> : <XCircle size={14} className="text-bad" aria-hidden />}
        <span className="font-medium text-text">{c.name}</span> <KindTag kind={c.kind} />
        <span className="text-muted">
          {t("expected")} <b className="font-mono">{c.expect}</b>, {t("got")} <b className="font-mono">{c.got}</b>
        </span>
      </p>
      {c.error && <p className="text-bad [overflow-wrap:anywhere]">{c.error}</p>}
      {c.hint && <p className="text-muted">{c.hint}</p>}
      {c.event && (
        <details className="text-xs">
          <summary className="cursor-pointer text-muted">{t("ts_event")}</summary>
          <pre className="mt-1 max-h-48 overflow-auto rounded-lg border border-line bg-code p-2 font-mono text-[12px] text-code-text">{JSON.stringify(c.event, null, 2)}</pre>
        </details>
      )}
    </li>
  );
}

export default function TestSuitesPage() {
  const { data, error, isFetching, refetch, dataUpdatedAt } = useQuery({ queryKey: ["tests"], queryFn: api.tests });
  const [params, setParams] = useSearchParams();
  const state = params.get("state") as RuleState | null;
  const q = params.get("q") ?? "";
  const level = params.get("level") ?? "";
  const [open, setOpen] = useState<Set<string>>(new Set());
  const set = (k: string, v: string | null) => {
    const n = new URLSearchParams(params);
    if (v) n.set(k, v);
    else n.delete(k);
    setParams(n, { replace: true });
  };

  const all = data?.rules ?? [];
  const counts = useMemo(() => {
    const c: Record<RuleState, number> = { healthy: 0, failing: 0, weak: 0, none: 0 };
    for (const r of all) c[stateOf(r)]++;
    return c;
  }, [all]);
  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return all
      .filter((r) => (!needle || `${r.title} ${r.id}`.toLowerCase().includes(needle)) && (!level || r.level === level) && (!state || stateOf(r) === state))
      .sort((a, b) => ORDER[stateOf(a)] - ORDER[stateOf(b)] || (a.title || a.id).localeCompare(b.title || b.id));
  }, [all, q, level, state]);
  const levels = [...new Set(all.map((r) => r.level).filter(Boolean))] as string[];
  // Auto-expand when exactly one rule fails.
  const onlyFailing = counts.failing === 1 ? all.find((r) => stateOf(r) === "failing")?.id : null;
  const isOpen = (id: string) => open.has(id) || id === onlyFailing;
  const toggle = (id: string) => {
    const n = new Set(open);
    if (n.has(id)) n.delete(id);
    else n.add(id);
    setOpen(n);
  };
  const tiles: [RuleState, string][] = [
    ["healthy", t("ts_st_healthy")],
    ["failing", t("ts_tile_failing")],
    ["weak", t("ts_tile_weak")],
    ["none", t("ts_st_none")],
  ];

  return (
    <div className="mx-auto max-w-7xl px-4 py-8 sm:px-8">
      <PageHeader
        title={t("test_suites")}
        subtitle={data ? t("ts_last_run", { ago: timeAgo(new Date(dataUpdatedAt).toISOString()), n: tn("n_cases", data.total), ms: data.duration_ms }) : t("ts_sub")}
        actions={
          <button type="button" onClick={() => refetch()} aria-busy={isFetching} className={btnPrimary}>
            <Play size={15} className={isFetching ? "animate-pulse" : undefined} aria-hidden /> {isFetching ? t("ts_running") : t("ts_run")}
          </button>
        }
      />
      {error && (
        <div className="space-y-2">
          <ErrorBox message={(error as Error).message} />
          <button type="button" className={btnSecondary} onClick={() => refetch()}>
            {t("try_again")}
          </button>
        </div>
      )}
      {data && (
        <>
          <div className="mb-4 grid grid-cols-2 gap-3 lg:grid-cols-4">
            {tiles.map(([k, label]) => (
              <button
                key={k}
                type="button"
                aria-pressed={state === k}
                onClick={() => set("state", state === k ? null : k)}
                className={clsx("rounded-[12px] border p-4 text-left", state === k ? "border-accent bg-accent-soft" : "border-line bg-surface hover:bg-surface-2")}
              >
                <span className="block text-xs font-medium uppercase tracking-wide text-subtle">{label}</span>
                <span className="mt-1 block text-[22px] font-bold tabular-nums text-strong">{counts[k]}</span>
                <span className="text-xs text-muted">{tn("n_rules", counts[k])}</span>
              </button>
            ))}
          </div>
          {all.length > 0 && counts.failing === 0 && counts.weak === 0 && counts.none === 0 && (
            <p className="mb-4 flex items-center gap-2 rounded-lg bg-good-soft p-3 text-sm text-good" role="status">
              <CheckCircle2 size={15} aria-hidden /> {t("ts_all_healthy", { n: all.length })}
            </p>
          )}
          <div className="mb-3 flex flex-wrap items-center gap-3">
            <label className="relative block w-full max-w-xs">
              <span className="sr-only">{t("search_rules")}</span>
              <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-subtle" aria-hidden />
              <input value={q} onChange={(e) => set("q", e.target.value || null)} placeholder={t("search_rules")} className={`${inputCls} pl-9`} />
            </label>
            <label className="flex items-center gap-2 text-sm text-muted">
              {t("severity")}
              <select value={level} onChange={(e) => set("level", e.target.value || null)} className={clsx(inputCls, "w-auto py-1.5")}>
                <option value="">{t("ts_all")}</option>
                {levels.map((l) => (
                  <option key={l} value={l}>
                    {l}
                  </option>
                ))}
              </select>
            </label>
            {(state || q || level) && (
              <button type="button" className="text-sm font-medium text-accent hover:underline" onClick={() => setParams({}, { replace: true })}>
                {t("ts_clear")}
              </button>
            )}
            <span className="ml-auto text-xs text-muted" role="status" aria-live="polite">
              {t("ts_shown", { n: rows.length })}
            </span>
          </div>
          <Card className="overflow-hidden">
            {all.length === 0 ? (
              <p className="p-8 text-center text-sm text-muted">
                {t("ts_no_rules")}{" "}
                <Link to="/editor" className="font-medium text-accent hover:underline">
                  {t("new_rule")}
                </Link>
              </p>
            ) : rows.length === 0 ? (
              <p className="p-8 text-center text-sm text-muted">{t("no_rule_matches")}</p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full min-w-[44rem] text-left text-[13px]">
                  <caption className="sr-only">{t("test_suites")}</caption>
                  <thead className="border-b border-line bg-surface-2 text-[11.5px] uppercase tracking-wide text-subtle">
                    <tr>
                      <th className="w-8 py-2" />
                      <th className="py-2 pr-3 font-medium">{t("rule")}</th>
                      <th className="px-3 py-2 font-medium">{t("pk_cases")}</th>
                      <th className="px-3 py-2 font-medium" title={t("ts_tp_tip")}>TP</th>
                      <th className="px-3 py-2 font-medium" title={t("proves_the_exclusion_2")}>FP</th>
                      <th className="px-3 py-2 font-medium">{t("ts_edge")}</th>
                      <th className="py-2 pl-3 pr-4 font-medium">{t("state")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {rows.map((r) => {
                      const s = stateOf(r);
                      const on = isOpen(r.id);
                      return (
                        <Fragment key={r.id}>
                          <tr className="border-b border-line">
                            <td className="py-2 pl-2">
                              <button type="button" aria-expanded={on} aria-label={r.title || r.id} onClick={() => toggle(r.id)} className="rounded p-1 text-subtle hover:bg-surface-2">
                                <ChevronRight size={15} className={clsx("transition-transform", on && "rotate-90")} aria-hidden />
                              </button>
                            </td>
                            <td className="py-2 pr-3">
                              <span className="block font-medium text-strong">{r.title || r.id}</span>
                              <span className="block font-mono text-[11px] text-subtle">{r.id}</span>
                            </td>
                            <td className="px-3 py-2 tabular-nums">{frac(r, KINDS)}</td>
                            <td className="px-3 py-2 tabular-nums">{frac(r, ["positive"])}</td>
                            <td className="px-3 py-2 tabular-nums">{frac(r, ["false_positive"])}</td>
                            <td className="px-3 py-2 tabular-nums">{frac(r, ["edge", "negative"])}</td>
                            <td className="py-2 pl-3 pr-4">
                              <StateCell r={r} s={s} />
                            </td>
                          </tr>
                          {on && (
                            <tr key={`${r.id}-d`} className="border-b border-line bg-surface-2">
                              <td />
                              <td colSpan={6} className="px-3 py-3">
                                <div className="mb-2 flex flex-wrap items-center gap-3">
                                  <LevelTag level={r.level} />
                                  <Link to={`/editor/${r.id}`} className="text-xs font-medium text-accent hover:underline">
                                    {t("open_in_the_editor")}
                                  </Link>
                                </div>
                                {s === "none" ? (
                                  <p className="text-muted">{t("ts_add_cases")}</p>
                                ) : (
                                  <ul className="divide-y divide-line">
                                    {[...failedCases(r), ...r.results.filter((c) => c.passed)].map((c, i) => (
                                      <CaseDetail key={`${c.name}-${i}`} c={c} />
                                    ))}
                                  </ul>
                                )}
                                {s === "weak" && <p className="mt-2 text-xs text-warn">{t("ts_weak_why")}</p>}
                                {r.problems.length > 0 && (
                                  <div className="mt-2 text-[12.5px]">
                                    <IssueList issues={r.problems} />
                                  </div>
                                )}
                              </td>
                            </tr>
                          )}
                        </Fragment>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </Card>
          {data.broken.map((b) => (
            <div key={b.file} className="mt-3">
              <ErrorBox message={`${b.file}: ${b.error}`} />
            </div>
          ))}
        </>
      )}
    </div>
  );
}
