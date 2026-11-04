import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api } from "../api";
import { BarList, ConnectorNotice, LineChart, Section, StatTile, StateBar, formatDate, formatHours, pct } from "../components/dash";
import ExportMenu from "../components/ExportMenu";
import { ErrorBox, PageHeader, TARGET_CODE, TargetSwatch } from "../components/ui";
import type { State } from "../types";
import { t, tn } from "../i18n";

const LEVELS: [string, string][] = [
  ["critical", t("l_critical")],
  ["high", t("l_high")],
  ["medium", t("l_medium")],
  ["low", t("l_low")],
  ["informational", t("l_info")],
];
const STATUSES = ["stable", "test", "experimental", "deprecated", "unsupported"];

/** Colours the tile icon: green from `good`, yellow from `warn`. Targets are simple thresholds, not benchmarks. */
const level = (value: number, good: number, warn: number): State => (value >= good ? "ok" : value >= warn ? "warn" : "fail");

export default function ExecutivePage() {
  const stats = useQuery({ queryKey: ["stats"], queryFn: api.stats });
  const activity = useQuery({ queryKey: ["activity"], queryFn: () => api.activity() });
  const targets = useQuery({ queryKey: ["targets"], queryFn: api.targets });
  const quality = useQuery({ queryKey: ["quality"], queryFn: api.quality });
  const history = useQuery({ queryKey: ["history"], queryFn: api.history });
  const coverage = useQuery({ queryKey: ["coverage"], queryFn: api.coverage });

  const s = stats.data;
  const act = activity.data;
  const labels = Object.fromEntries((targets.data ?? []).map((t) => [t.name, t.label]));
  const timeline = history.data?.available ? history.data.timeline : [];

  if (stats.error) {
    return (
      <div className="p-8">
        <ErrorBox message={(stats.error as Error).message} />
      </div>
    );
  }

  const ready = quality.data ? pct(quality.data.summary.ready, quality.data.summary.total) : 0;
  const testPct = s ? pct(s.tests.passed, s.tests.total) : 0;
  const tested = s ? pct(s.rules.total - s.tests.rules_without_cases, s.rules.total) : 0;
  const techSpark = timeline.map((t) => t.techniques);

  return (
    <div className="mx-auto max-w-7xl px-4 py-8 sm:px-8">
      <PageHeader
        title={t("executive")}
        subtitle={t("threat_coverage_detection_quality_and_")}
        actions={
          <ExportMenu
            page="executive"
            title={t("executive")}
            disabled={!s}
            facts={s ? [["ATT&CK coverage", `${s.mitre.coverage_pct}%`], ["Rules", s.rules.total], ["Tests passed", `${s.tests.passed}/${s.tests.total}`], ["Ready to publish", quality.data ? `${quality.data.summary.ready}/${quality.data.summary.total}` : "-"]] : []}
            tables={[
              { name: "risk-by-tactic", label: t("ex_tbl_tactic"), columns: ["tactic_id", "tactic", "rules"], rows: (s?.mitre.tactics ?? []).map((x) => [x.id, x.name, x.count]) },
              { name: "rules-by-level", label: t("rules_by_severity"), columns: ["level", "rules"], rows: Object.entries(s?.rules.by_level ?? {}) },
              { name: "rules-by-status", label: t("rules_by_maturity_status"), columns: ["status", "rules"], rows: Object.entries(s?.rules.by_status ?? {}) },
              { name: "rules-by-language", label: t("rules_by_final_language"), columns: ["language", "rules"], rows: Object.entries(s?.by_target ?? {}) },
            ]}
          />
        }
      />
      {!s && <p className="text-sm text-muted">{t("reading_the_repository")}</p>}

      {s && (
        <>
          <div className="mb-5 grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
            <StatTile
              label={t("att_ck_coverage")}
              value={`${s.mitre.coverage_pct}%`}
              sub={t("ex_tactics_techs", { a: s.mitre.covered, b: s.mitre.total, n: tn("n_techniques", s.mitre.techniques) })}
              status={level(s.mitre.coverage_pct, 70, 40)}
              spark={techSpark}
            />
            <StatTile
              label={t("ready_to_publish")}
              value={quality.data ? `${ready}%` : "—"}
              sub={quality.data ? t("ex_pass_gate", { a: quality.data.summary.ready, b: quality.data.summary.total }) : t("ex_running_gate")}
              status={quality.data ? level(ready, 95, 80) : "none"}
            />
            <StatTile
              label={t("average_health")}
              value={quality.data?.summary.health != null ? `${quality.data.summary.health}/100` : "—"}
              sub={quality.data ? (quality.data.summary.stale ? t("ex_due_review", { n: quality.data.summary.stale }) : t("ex_no_overdue")) : undefined}
              status={quality.data?.summary.health != null ? level(quality.data.summary.health, 90, 70) : "none"}
            />
            <StatTile
              label={t("time_to_merge")}
              value={act?.available ? formatHours(act.merge.median_hours) : "—"}
              sub={act?.available ? (act.merge.sample ? t("ex_median_of", { n: act.merge.sample, v: formatHours(act.merge.p90_hours) }) : t("ex_no_merged")) : t("ex_needs_gh")}
              source={act?.available ? "GitHub" : undefined}
            />
          </div>

          <div className="grid gap-5 lg:grid-cols-2">
            <Section title={t("detection_coverage_over_time")} aside={history.data?.available ? tn("n_commits", history.data.commits) : undefined}>
              {!history.data && <p className="text-sm text-muted">{t("reading_git_history")}</p>}
              {history.data && !history.data.available && <p className="text-sm text-subtle">{history.data.message ?? `${t("no_git_history")}${history.data.reason}). Coverage over time needs a Git repository.`}</p>}
              {history.data?.available && (
                <LineChart
                  ariaLabel={t("att_ck_techniques_covered_after_each_c")}
                  unit={" " + t("ex_techniques_unit")}
                  points={timeline.map((t) => ({ label: formatDate(t.date), value: t.techniques, note: `${tn("n_rules", t.rules)} · ${tn("n_tactics", t.tactics)} · ${t.sha}` }))}
                />
              )}
            </Section>

            <Section title={t("rule_set_health")} aside={tn("n_rules", s.rules.total)}>
              <StateBar counts={s.pipeline.validation} />
              <dl className="mt-5 grid grid-cols-2 gap-x-6 gap-y-2 text-[13px]">
                <dt className="text-muted">{t("lint_errors")}</dt>
                <dd className="text-right font-semibold text-strong tabular-nums">{s.lint.errors}</dd>
                <dt className="text-muted">{t("lint_warnings")}</dt>
                <dd className="text-right font-semibold text-strong tabular-nums">{s.lint.warnings}</dd>
                <dt className="text-muted">{t("conversion_failures")}</dt>
                <dd className="text-right font-semibold text-strong tabular-nums">{s.conversion_failures}</dd>
                <dt className="text-muted">{t("rules_without_test_cases")}</dt>
                <dd className="text-right font-semibold text-strong tabular-nums">{s.tests.rules_without_cases}</dd>
                <dt className="text-muted">{t("test_cases_passing")}</dt>
                <dd className="text-right font-semibold text-strong tabular-nums">
                  {s.tests.total ? `${testPct}%` : "—"} <span className="font-normal text-subtle">{t("ex_pct_tested", { n: tested })}</span>
                </dd>
              </dl>
            </Section>

            <Section title={t("delivery")} aside={act?.available ? act.repo.name : undefined}>
              <ConnectorNotice activity={act} />
              {act?.available && (
                <dl className="grid grid-cols-2 gap-x-6 gap-y-2 text-[13px]">
                  <dt className="text-muted">{t("ci_passing_latest_runs")}</dt>
                  <dd className="text-right font-semibold text-strong tabular-nums">{act.ci.success_rate === null ? "—" : `${act.ci.success_rate}% of ${act.ci.sample}`}</dd>
                  <dt className="text-muted">{t("open_prs")}</dt>
                  <dd className="text-right font-semibold text-strong tabular-nums">{act.pulls.open}</dd>
                  <dt className="text-muted">{t("prs_with_failing_ci")}</dt>
                  <dd className="text-right font-semibold text-strong tabular-nums">{act.pulls.failing}</dd>
                  <dt className="text-muted">{t("prs_opened_from_the_ui")}</dt>
                  <dd className="text-right font-semibold text-strong tabular-nums">{act.pulls.from_vitrix}</dd>
                  <dt className="text-muted">{t("median_time_to_merge")}</dt>
                  <dd className="text-right font-semibold text-strong tabular-nums">{formatHours(act.merge.median_hours)}</dd>
                  <dt className="text-muted">{t("p90_time_to_merge")}</dt>
                  <dd className="text-right font-semibold text-strong tabular-nums">{formatHours(act.merge.p90_hours)}</dd>
                </dl>
              )}
            </Section>

            <Section title={t("contributors")} aside={history.data?.available ? t("l_from_git") : undefined}>
              {history.data?.available ? (
                <BarList rows={history.data.authors.slice(0, 6).map((a) => ({ key: a.name, label: a.name, value: a.commits, title: t("ex_author", { name: a.name, c: a.commits, r: a.rules_created ?? 0 }) }))} empty={t("no_commits_yet")} />
              ) : (
                <p className="text-sm text-subtle">{t("needs_a_git_repository")}</p>
              )}
            </Section>

            <Section title={t("rules_by_severity")}>
              <BarList rows={LEVELS.filter(([k]) => s.rules.by_level[k]).map(([k, label]) => ({ key: k, label, code: k, value: s.rules.by_level[k] }))} empty={t("no_rule_has_a_level")} />
            </Section>

            <Section title={t("rules_by_maturity_status")}>
              <BarList
                rows={[...STATUSES, ...Object.keys(s.rules.by_status).filter((k) => !STATUSES.includes(k))]
                  .filter((k) => s.rules.by_status[k])
                  .map((k) => ({ key: k, label: k, value: s.rules.by_status[k] }))}
              />
            </Section>

            <Section title={t("rules_by_final_language")}>
              <BarList
                rows={Object.entries(s.by_target)
                  .sort((a, b) => b[1] - a[1])
                  .map(([name, n]) => ({
                    key: name,
                    label: (
                      <span className="flex items-center gap-2">
                        <TargetSwatch target={name} />
                        {labels[name] ?? name}
                      </span>
                    ),
                    code: TARGET_CODE[name],
                    value: n,
                    title: `${labels[name] ?? name}: ${tn("n_rules", n)}`,
                  }))}
              />
            </Section>

            <Section title={t("rules_by_data_source")} aside="logsource">
              <BarList
                rows={Object.entries(s.rules.by_logsource)
                  .sort((a, b) => b[1] - a[1])
                  .slice(0, 8)
                  .map(([name, n]) => ({ key: name, label: name, value: n }))}
                empty={t("no_rules")}
              />
            </Section>

            <Section title={t("coverage_gaps")} aside={t("ex_tactics_none", { n: s.mitre.uncovered.length })} className="lg:col-span-2">
              {s.mitre.uncovered.length === 0 ? (
                <p className="text-sm text-muted">Every ATT&amp;CK tactic has at least one rule.</p>
              ) : (
                <ul className="flex flex-wrap gap-2">
                  {s.mitre.tactics
                    .filter((t) => t.count === 0)
                    .map((t) => (
                      <li key={t.slug} className="rounded-md bg-surface-2 px-2 py-1 text-[12.5px] text-text">
                        <span className="mr-1.5 font-mono text-[11.5px] text-subtle">{t.id}</span>
                        {t.name}
                      </li>
                    ))}
                </ul>
              )}
              {coverage.data && coverage.data.unmapped.length > 0 && (
                <p className="mt-3 text-xs text-warn">
                  {coverage.data.unmapped.length} rule(s) have no technique tag and do not appear in the matrix.{" "}
                  <Link to="/coverage" className="text-accent hover:underline">
                    {t("see_the_matrix")}
                  </Link>
                </p>
              )}
            </Section>
          </div>
        </>
      )}
    </div>
  );
}
