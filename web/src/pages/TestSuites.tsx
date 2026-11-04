import { IssueList } from "../components/Issues";
import { useQuery } from "@tanstack/react-query";
import clsx from "clsx";
import { AlertTriangle, CheckCircle2, ChevronRight, Play, Search, XCircle } from "lucide-react";
import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { DonutChart, SERIES_COLORS } from "../components/charts";
import { Section, pct } from "../components/dash";
import { KIND_LABEL, KindTag } from "../components/flow";
import { Card, ErrorBox, LevelTag, PageHeader, btnPrimary } from "../components/ui";
import type { CaseKind, CaseResult, SuiteRule } from "../types";
import { t, tn } from "../i18n";

const KINDS: CaseKind[] = ["positive", "negative", "false_positive", "edge"];

const passed = (r: SuiteRule) => r.results.filter((c) => c.passed).length;
const failing = (r: SuiteRule) => r.results.some((c) => !c.passed) || r.problems.some((p) => p.severity === "error");

/** One test case: a compact row that expands to the event that was tested. */
function CaseRow({ c }: { c: CaseResult }) {
  const [open, setOpen] = useState(!c.passed);
  const expectedLabel = c.expect === "match" ? t("l_should_match") : t("l_should_not_match");
  return (
    <li>
      <button type="button" onClick={() => setOpen(!open)} aria-expanded={open} className="flex w-full items-center gap-3 px-4 py-2.5 text-left hover:bg-surface">
        {c.passed ? <CheckCircle2 size={16} className="shrink-0 text-good" aria-label={t("passed")} /> : <XCircle size={16} className="shrink-0 text-bad" aria-label={t("failed")} />}
        <span className="min-w-0 flex-1 truncate text-[13.5px] text-text">{c.name}</span>
        <KindTag kind={c.kind} />
        <ChevronRight size={15} className={clsx("shrink-0 text-subtle transition-transform", open && "rotate-90")} aria-hidden />
      </button>
      {open && (
        <div className="space-y-3 border-t border-line bg-surface-2 px-4 py-3 text-[12.5px]">
          <div className="flex flex-wrap items-center gap-x-5 gap-y-1">
            <span className="text-muted">
              {t("expected")} <b className="font-mono text-text">{c.expect}</b> <span className="text-subtle">({expectedLabel})</span>
            </span>
            <span className="text-muted">
              {t("got")} <b className={clsx("font-mono", c.passed ? "text-text" : "text-bad")}>{c.got}</b>
            </span>
            {c.exercises_filter && <span className="text-xs text-accent">{t("proves_the_exclusion_2")}</span>}
          </div>
          {c.error && <p className="text-bad [overflow-wrap:anywhere]">{c.error}</p>}
          {c.event && (
            <dl className="grid grid-cols-[minmax(6rem,11rem)_1fr] gap-x-4 gap-y-1 rounded-lg border border-line bg-code p-3 font-mono text-[12px]">
              {Object.entries(c.event).map(([k, v]) => (
                <div key={k} className="contents">
                  <dt className="truncate text-accent" title={k}>
                    {k}
                  </dt>
                  <dd className="text-code-text [overflow-wrap:anywhere]">{typeof v === "string" ? v : JSON.stringify(v)}</dd>
                </div>
              ))}
            </dl>
          )}
        </div>
      )}
    </li>
  );
}

function RulePanel({ rule }: { rule: SuiteRule }) {
  const [kind, setKind] = useState<"all" | CaseKind>("all");
  const counts = useMemo(() => Object.fromEntries(KINDS.map((k) => [k, rule.results.filter((c) => c.kind === k).length])) as Record<CaseKind, number>, [rule]);
  const shown = rule.results.filter((c) => kind === "all" || c.kind === kind);
  const missing = KINDS.filter((k) => counts[k] === 0 && (k === "false_positive" || k === "edge"));
  return (
    <Card className="overflow-hidden">
      <div className="flex flex-wrap items-start justify-between gap-3 border-b border-line px-4 py-3">
        <div className="min-w-0">
          <h2 className="truncate text-[15px] font-semibold text-strong">{rule.title || rule.id}</h2>
          <p className="font-mono text-xs text-subtle">{rule.id}</p>
        </div>
        <div className="flex items-center gap-3">
          <LevelTag level={rule.level} />
          <Link to={`/editor/${rule.id}`} className="text-xs font-medium text-accent hover:underline">
            {t("open_in_the_editor")}
          </Link>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-1.5 border-b border-line px-4 py-2.5" role="group" aria-label={t("case_kind")}>
        {(["all", ...KINDS] as const).map((k) => {
          const n = k === "all" ? rule.results.length : counts[k];
          return (
            <button
              key={k}
              type="button"
              aria-pressed={kind === k}
              disabled={n === 0}
              onClick={() => setKind(k)}
              className={clsx(
                "rounded-full px-3 py-1 text-xs transition-colors disabled:cursor-default disabled:opacity-40",
                kind === k ? "bg-accent-soft font-semibold text-strong" : "text-muted hover:bg-surface-2 hover:text-text",
              )}
            >
              {k === "all" ? t("l_all") : KIND_LABEL[k]} <span className="tabular-nums text-subtle">{n}</span>
            </button>
          );
        })}
        <span className="ml-auto text-xs tabular-nums text-muted">
          {t("ts_n_passing", { a: passed(rule), b: rule.results.length })}
        </span>
      </div>

      {missing.length > 0 && (
        <p className="flex items-center gap-2 border-b border-line bg-warn-soft px-4 py-2 text-xs text-text">
          <AlertTriangle size={14} className="shrink-0 text-warn" aria-hidden />
          {t("ts_missing", { kinds: missing.map((k) => KIND_LABEL[k].toLowerCase()).join(t("ts_or")), req: missing.includes("false_positive") ? t("ts_req") : "" })}
        </p>
      )}

      <ul className="divide-y divide-line">
        {shown.map((c, i) => (
          <CaseRow key={`${c.name}-${i}`} c={c} />
        ))}
        {shown.length === 0 && <li className="px-4 py-8 text-center text-sm text-muted">{t("no_case_of_this_kind")}</li>}
      </ul>

      {rule.problems.length > 0 && (
        <div className="border-t border-line px-4 py-3 text-[12.5px]">
          <IssueList issues={rule.problems} />
        </div>
      )}
    </Card>
  );
}

export default function TestSuitesPage() {
  const { data, error, isFetching, refetch } = useQuery({ queryKey: ["tests"], queryFn: api.tests });
  const [selected, setSelected] = useState<string | null>(null);
  const [q, setQ] = useState("");
  const [onlyFailing, setOnlyFailing] = useState(false);

  const rules = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return [...(data?.rules ?? [])]
      .filter((r) => (!needle || `${r.title} ${r.id}`.toLowerCase().includes(needle)) && (!onlyFailing || failing(r)))
      .sort((a, b) => Number(failing(b)) - Number(failing(a)) || a.id.localeCompare(b.id));
  }, [data, q, onlyFailing]);

  const current = (data?.rules ?? []).find((r) => r.id === selected) ?? rules[0] ?? null;
  const failingRules = (data?.rules ?? []).filter(failing).length;

  return (
    <div className="mx-auto max-w-7xl px-4 py-8 sm:px-8">
      <PageHeader
        title={t("test_suites")}
        subtitle={t("ts_sub")}
        actions={
          <button type="button" onClick={() => refetch()} className={btnPrimary}>
            <Play size={15} className={isFetching ? "animate-pulse" : undefined} aria-hidden /> {isFetching ? t("ts_running") : t("ts_run")}
          </button>
        }
      />
      {error && <ErrorBox message={(error as Error).message} />}
      {data && (
        <>
          <div className="mb-5 grid gap-4 lg:grid-cols-[minmax(0,1.3fr)_minmax(0,1fr)]">
            <Section title={t("cases_by_kind")} aside={`${tn("n_cases", data.total)} · ${data.duration_ms} ms`}>
              <DonutChart
                ariaLabel={t("test_cases_by_kind")}
                unit={" " + t("ts_cases_unit")}
                centerValue={`${pct(data.passed, data.total)}%`}
                centerLabel={t("ts_n_passing", { a: data.passed, b: data.total })}
                slices={KINDS.map((k, i) => ({ key: k, label: KIND_LABEL[k], value: data.by_kind[k].total, color: SERIES_COLORS[i] }))}
              />
            </Section>
            <Section title={t("health_of_the_suites")}>
              <ul className="space-y-3 text-[13px]">
                <li className="flex items-center justify-between gap-3">
                  <span className="flex items-center gap-2 text-muted">
                    {failingRules ? <XCircle size={15} className="text-bad" aria-hidden /> : <CheckCircle2 size={15} className="text-good" aria-hidden />}
                    {t("ts_rules_failing")}
                  </span>
                  <b className="tabular-nums text-strong">{failingRules}</b>
                </li>
                {KINDS.slice(2).map((k) => {
                  const withKind = data.rules.filter((r) => r.results.some((c) => c.kind === k)).length;
                  return (
                    <li key={k} className="flex items-center justify-between gap-3">
                      <span className="flex items-center gap-2 text-muted">
                        {withKind === data.rules.length ? <CheckCircle2 size={15} className="text-good" aria-hidden /> : <AlertTriangle size={15} className="text-warn" aria-hidden />}
                        {t("ts_rules_with_kind", { k: KIND_LABEL[k].toLowerCase() })}
                      </span>
                      <b className="tabular-nums text-strong">
                        {withKind}/{data.rules.length}
                      </b>
                    </li>
                  );
                })}
                <li className="flex items-center justify-between gap-3">
                  <span className="flex items-center gap-2 text-muted">
                    <CheckCircle2 size={15} className="text-good" aria-hidden /> {t("exclusions_proven_by_a_case")}
                  </span>
                  <b className="tabular-nums text-strong">{data.rules.flatMap((r) => r.results).filter((c) => c.exercises_filter).length}</b>
                </li>
              </ul>
            </Section>
          </div>

          <div className="grid items-start gap-5 lg:grid-cols-[21rem_minmax(0,1fr)]">
            <Card className="overflow-hidden lg:sticky lg:top-4">
              <div className="space-y-2 border-b border-line p-3">
                <label className="relative block">
                  <span className="sr-only">{t("search_rules")}</span>
                  <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-subtle" aria-hidden />
                  <input
                    value={q}
                    onChange={(e) => setQ(e.target.value)}
                    placeholder={t("search_rules")}
                    className="w-full rounded-[10px] border border-line bg-surface py-1.5 pl-9 pr-3 text-sm text-text placeholder:text-subtle focus:border-accent/50"
                  />
                </label>
                <label className="flex items-center gap-2 text-xs text-muted">
                  <input type="checkbox" checked={onlyFailing} onChange={(e) => setOnlyFailing(e.target.checked)} className="accent-accent" /> {t("failing_only")}
                </label>
              </div>
              <ul className="max-h-[560px] divide-y divide-line overflow-auto">
                {rules.map((r) => {
                  const bad = failing(r);
                  const on = current?.id === r.id;
                  return (
                    <li key={r.id}>
                      <button
                        type="button"
                        onClick={() => setSelected(r.id)}
                        aria-current={on}
                        className={clsx("flex w-full items-center gap-3 px-3 py-2.5 text-left", on ? "bg-accent-soft" : "hover:bg-surface")}
                      >
                        {bad ? <XCircle size={16} className="shrink-0 text-bad" aria-label={t("failing")} /> : <CheckCircle2 size={16} className="shrink-0 text-good" aria-label={t("passing")} />}
                        <span className="min-w-0 flex-1">
                          <span className="block truncate text-[13px] font-medium text-strong">{r.title || r.id}</span>
                          <span className="block truncate font-mono text-[11px] text-subtle">{r.id}</span>
                        </span>
                        <span className="text-xs tabular-nums text-muted">
                          {passed(r)}/{r.results.length}
                        </span>
                      </button>
                    </li>
                  );
                })}
                {rules.length === 0 && <li className="px-3 py-6 text-center text-sm text-muted">{t("no_rule_matches")}</li>}
              </ul>
            </Card>

            <div className="min-w-0 space-y-4">
              {current ? <RulePanel key={current.id} rule={current} /> : <p className="text-sm text-muted">{t("select_a_rule")}</p>}
              {data.broken.map((b) => (
                <ErrorBox key={b.file} message={`${b.file}: ${b.error}`} />
              ))}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
