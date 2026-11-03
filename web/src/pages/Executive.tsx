import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api } from "../api";
import { BarList, ConnectorNotice, LineChart, Section, StatTile, StateBar, formatDate, formatHours, pct } from "../components/dash";
import { ErrorBox, PageHeader, TARGET_CODE, TargetSwatch } from "../components/ui";
import type { State } from "../types";

const LEVELS: [string, string][] = [
  ["critical", "Critical"],
  ["high", "High"],
  ["medium", "Medium"],
  ["low", "Low"],
  ["informational", "Info"],
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
        title="Executive"
        subtitle="Threat coverage, detection quality and delivery pace. Numbers come from the repository, its Git history and, when connected, GitHub."
      />
      {!s && <p className="text-sm text-muted">Reading the repository…</p>}

      {s && (
        <>
          <div className="mb-5 grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
            <StatTile
              label="ATT&CK coverage"
              value={`${s.mitre.coverage_pct}%`}
              sub={`${s.mitre.covered} of ${s.mitre.total} tactics · ${s.mitre.techniques} techniques`}
              status={level(s.mitre.coverage_pct, 70, 40)}
              spark={techSpark}
            />
            <StatTile
              label="Ready to publish"
              value={quality.data ? `${ready}%` : "—"}
              sub={quality.data ? `${quality.data.summary.ready} of ${quality.data.summary.total} pass the quality gate` : "running the gate…"}
              status={quality.data ? level(ready, 95, 80) : "none"}
            />
            <StatTile
              label="Average health"
              value={quality.data?.summary.health != null ? `${quality.data.summary.health}/100` : "—"}
              sub={quality.data ? (quality.data.summary.stale ? `${quality.data.summary.stale} rule(s) due for review` : "no review overdue") : undefined}
              status={quality.data?.summary.health != null ? level(quality.data.summary.health, 90, 70) : "none"}
            />
            <StatTile
              label="Time to merge"
              value={act?.available ? formatHours(act.merge.median_hours) : "—"}
              sub={act?.available ? (act.merge.sample ? `median of ${act.merge.sample} PRs · p90 ${formatHours(act.merge.p90_hours)}` : "no merged PR") : "needs the GitHub connection"}
              source={act?.available ? "GitHub" : undefined}
            />
          </div>

          <div className="grid gap-5 lg:grid-cols-2">
            <Section title="Detection coverage over time" aside={history.data?.available ? `${history.data.commits} ${history.data.commits === 1 ? "commit" : "commits"}` : undefined}>
              {!history.data && <p className="text-sm text-muted">Reading Git history…</p>}
              {history.data && !history.data.available && <p className="text-sm text-subtle">No Git history ({history.data.reason}). Coverage over time needs a Git repository.</p>}
              {history.data?.available && (
                <LineChart
                  ariaLabel="ATT&CK techniques covered after each commit"
                  unit=" techniques"
                  points={timeline.map((t) => ({ label: formatDate(t.date), value: t.techniques, note: `${t.rules} rules · ${t.tactics} tactics · ${t.sha}` }))}
                />
              )}
            </Section>

            <Section title="Rule-set health" aside={`${s.rules.total} rules`}>
              <StateBar counts={s.pipeline.validation} />
              <dl className="mt-5 grid grid-cols-2 gap-x-6 gap-y-2 text-[13px]">
                <dt className="text-muted">Lint errors</dt>
                <dd className="text-right font-semibold text-strong tabular-nums">{s.lint.errors}</dd>
                <dt className="text-muted">Lint warnings</dt>
                <dd className="text-right font-semibold text-strong tabular-nums">{s.lint.warnings}</dd>
                <dt className="text-muted">Conversion failures</dt>
                <dd className="text-right font-semibold text-strong tabular-nums">{s.conversion_failures}</dd>
                <dt className="text-muted">Rules without test cases</dt>
                <dd className="text-right font-semibold text-strong tabular-nums">{s.tests.rules_without_cases}</dd>
                <dt className="text-muted">Test cases passing</dt>
                <dd className="text-right font-semibold text-strong tabular-nums">
                  {s.tests.total ? `${testPct}%` : "—"} <span className="font-normal text-subtle">({tested}% of rules tested)</span>
                </dd>
              </dl>
            </Section>

            <Section title="Delivery" aside={act?.available ? act.repo.name : undefined}>
              <ConnectorNotice activity={act} />
              {act?.available && (
                <dl className="grid grid-cols-2 gap-x-6 gap-y-2 text-[13px]">
                  <dt className="text-muted">CI passing (latest runs)</dt>
                  <dd className="text-right font-semibold text-strong tabular-nums">{act.ci.success_rate === null ? "—" : `${act.ci.success_rate}% of ${act.ci.sample}`}</dd>
                  <dt className="text-muted">Open PRs</dt>
                  <dd className="text-right font-semibold text-strong tabular-nums">{act.pulls.open}</dd>
                  <dt className="text-muted">PRs with failing CI</dt>
                  <dd className="text-right font-semibold text-strong tabular-nums">{act.pulls.failing}</dd>
                  <dt className="text-muted">PRs opened from the UI</dt>
                  <dd className="text-right font-semibold text-strong tabular-nums">{act.pulls.from_vitrix}</dd>
                  <dt className="text-muted">Median time to merge</dt>
                  <dd className="text-right font-semibold text-strong tabular-nums">{formatHours(act.merge.median_hours)}</dd>
                  <dt className="text-muted">p90 time to merge</dt>
                  <dd className="text-right font-semibold text-strong tabular-nums">{formatHours(act.merge.p90_hours)}</dd>
                </dl>
              )}
            </Section>

            <Section title="Contributors" aside={history.data?.available ? "from Git" : undefined}>
              {history.data?.available ? (
                <BarList rows={history.data.authors.slice(0, 6).map((a) => ({ key: a.name, label: a.name, value: a.commits, title: `${a.name}: ${a.commits} commits, ${a.rules_created ?? 0} rules created` }))} empty="No commits yet." />
              ) : (
                <p className="text-sm text-subtle">Needs a Git repository.</p>
              )}
            </Section>

            <Section title="Rules by severity">
              <BarList rows={LEVELS.filter(([k]) => s.rules.by_level[k]).map(([k, label]) => ({ key: k, label, code: k, value: s.rules.by_level[k] }))} empty="No rule has a level." />
            </Section>

            <Section title="Rules by maturity (status)">
              <BarList
                rows={[...STATUSES, ...Object.keys(s.rules.by_status).filter((k) => !STATUSES.includes(k))]
                  .filter((k) => s.rules.by_status[k])
                  .map((k) => ({ key: k, label: k, value: s.rules.by_status[k] }))}
              />
            </Section>

            <Section title="Rules by final language">
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
                    title: `${labels[name] ?? name}: ${n} rules`,
                  }))}
              />
            </Section>

            <Section title="Rules by data source" aside="logsource">
              <BarList
                rows={Object.entries(s.rules.by_logsource)
                  .sort((a, b) => b[1] - a[1])
                  .slice(0, 8)
                  .map(([name, n]) => ({ key: name, label: name, value: n }))}
                empty="No rules."
              />
            </Section>

            <Section title="Coverage gaps" aside={`${s.mitre.uncovered.length} tactics without a rule`} className="lg:col-span-2">
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
                    See the matrix
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
