import { useQuery } from "@tanstack/react-query";
import clsx from "clsx";
import { AlertTriangle, CheckCircle2, Clock, ExternalLink, GitCommitHorizontal, GitPullRequest, HardDrive, Plus, RefreshCw, XCircle } from "lucide-react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { BarList, ConnectorNotice, HealthMeter, RunBadge, Section, formatDuration, formatHours, pct, safeHref, timeAgo } from "../components/dash";
import { FlowFunnel } from "../components/flow";
import ExportMenu from "../components/ExportMenu";
import { Card, ErrorBox, PageHeader, btnPrimary, btnSecondary } from "../components/ui";
import type { Activity, History, QualityRule, RuleSummary, Stats } from "../types";
import { t, tn } from "../i18n";

/** One pipeline stage: main number + a detail line with a status icon. */
function Stage({ label, value, detail, ok }: { label: string; value: string; detail: string; ok: boolean | null }) {
  const Icon = ok === null ? null : ok ? CheckCircle2 : XCircle;
  return (
    <div className="flex min-w-0 flex-col gap-1 px-4 py-3">
      <span className="text-[11px] font-semibold uppercase tracking-wider text-subtle">{label}</span>
      <span className="text-[22px] font-bold leading-tight text-strong tabular-nums">{value}</span>
      <span className="flex items-center gap-1.5 text-[12px] text-muted">
        {Icon && <Icon size={13} className={clsx("shrink-0", ok ? "text-good" : "text-bad")} aria-hidden />}
        <span className="truncate">{detail}</span>
      </span>
    </div>
  );
}

function Pipeline({ stats, activity }: { stats: Stats; activity: Activity | undefined }) {
  const { pipeline, tests } = stats;
  const total = stats.rules.total;
  const pulls = activity?.available ? activity.pulls : null;
  return (
    <Card className="mb-5">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-line px-4 py-3">
        <h2 className="text-[15px] font-semibold text-strong">{t("validation_pipeline")}</h2>
        <span className="flex items-center gap-1.5 text-xs text-subtle">
          {activity?.available ? (
            <>
              <GitCommitHorizontal size={14} aria-hidden />
              <a href={safeHref(activity.head.url)} target="_blank" rel="noreferrer" className="font-mono hover:text-text">
                {activity.head.sha.slice(0, 7)}
              </a>
              · {activity.repo.base} · {timeAgo(activity.head.date)}
            </>
          ) : (
            t("l_local_repository")
          )}
        </span>
      </div>
      <div className="grid grid-cols-2 divide-line sm:grid-cols-3 lg:grid-cols-5 lg:divide-x">
        <Stage label={t("parse")} value={String(pipeline.parse.ok)} detail={pipeline.parse.failed ? t("db_invalid_yaml", { n: pipeline.parse.failed }) : t("db_yaml_ok")} ok={pipeline.parse.failed === 0} />
        <Stage
          label={t("validation")}
          value={t("db_n_passing", { n: pipeline.validation.ok })}
          detail={t("db_warn_fail", { w: pipeline.validation.warn, f: pipeline.validation.fail })}
          ok={pipeline.validation.fail === 0}
        />
        <Stage
          label={t("conversion")}
          value={`${pipeline.conversion.ok}/${total}`}
          detail={pipeline.conversion.failed ? t("db_conv_fail", { n: pipeline.conversion.failed }) : t("db_final_ok")}
          ok={pipeline.conversion.failed === 0}
        />
        <Stage
          label={t("tests")}
          value={`${tests.passed}/${tests.total}`}
          detail={tests.total - tests.passed ? t("db_failing_cases", { n: tests.total - tests.passed }) : t("db_no_cases", { n: tests.rules_without_cases })}
          ok={tests.total === tests.passed && tests.rules_without_cases === 0}
        />
        <Stage
          label={t("pull_requests")}
          value={pulls ? `${pulls.open} open` : "—"}
          detail={pulls ? (pulls.failing ? t("db_pr_fail", { n: pulls.failing }) : t("l_none_with_failing_ci")) : t("l_github_not_connected")}
          ok={pulls ? pulls.failing === 0 : null}
        />
      </div>
    </Card>
  );
}

/** Rules that need work: failing or warning, blocked by the gate, or overdue for review. */
function NeedsAttention({ rules, gate }: { rules: RuleSummary[]; gate: QualityRule[] }) {
  const byId = new Map(gate.map((g) => [g.id, g]));
  const items = rules
    .map((r) => {
      const g = byId.get(r.id);
      const stale = g?.checks.some((c) => c.id === "review" && c.passed === false) ?? false;
      return { r, g, stale, blocked: g ? !g.ready : false };
    })
    .filter((x) => x.r.state !== "ok" || x.blocked || x.stale)
    .sort((a, b) => (a.g?.score ?? 100) - (b.g?.score ?? 100));
  return (
    <Section title={t("needs_attention")} aside={tn("n_rules", items.length)}>
      {items.length === 0 ? (
        <p className="flex items-center gap-2 text-sm text-muted">
          <CheckCircle2 size={16} className="text-good" aria-hidden /> {t("nothing_pending_every_rule_passes_lint")}
        </p>
      ) : (
        <ul className="-mx-2 divide-y divide-line">
          {items.map(({ r, g, stale, blocked }) => {
            const fail = r.state === "fail";
            const first = r.issues[0]?.message ?? g?.blockers[0] ?? (stale ? t("db_not_reviewed", { n: Math.round(g?.age_days ?? 0) }) : "—");
            return (
              <li key={r.id}>
                <Link to={`/editor/${r.id}`} className="flex gap-3 rounded-lg px-2 py-2.5 hover:bg-surface">
                  <span
                    className={clsx(
                      "mt-0.5 inline-flex h-fit shrink-0 items-center gap-1 rounded-full px-2 py-0.5 text-xs font-semibold",
                      fail || blocked ? "bg-bad-soft text-bad" : "bg-warn-soft text-warn",
                    )}
                  >
                    {fail ? <XCircle size={12} aria-hidden /> : blocked ? <XCircle size={12} aria-hidden /> : stale ? <Clock size={12} aria-hidden /> : <AlertTriangle size={12} aria-hidden />}
                    {fail ? t("l_failing") : blocked ? t("l_blocked") : stale ? t("l_review_due") : t("l_warning")}
                  </span>
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-[13.5px] font-semibold text-strong">{r.title || r.id}</span>
                    <span className="block text-[12.5px] text-muted [overflow-wrap:anywhere]">{first}</span>
                    <span className="block font-mono text-[11.5px] text-subtle">{r.file}</span>
                  </span>
                  {g && <HealthMeter score={g.score} />}
                </Link>
              </li>
            );
          })}
        </ul>
      )}
    </Section>
  );
}

function CiRuns({ activity }: { activity: Activity | undefined }) {
  return (
    <Section title={t("ci_runs")} aside={activity?.available && activity.ci.success_rate !== null ? t("db_ci_passing", { p: activity.ci.success_rate, n: activity.ci.sample }) : undefined}>
      <ConnectorNotice activity={activity} />
      {activity?.available &&
        (activity.ci.runs.length === 0 ? (
          <p className="text-sm text-subtle">{t("no_ci_run_on")} {activity.repo.base}.</p>
        ) : (
          <ul className="-mx-2 divide-y divide-line">
            {activity.ci.runs.slice(0, 8).map((run) => (
              <li key={run.id}>
                <a href={safeHref(run.url)} target="_blank" rel="noreferrer" className="flex items-center gap-3 rounded-lg px-2 py-2 text-[13px] hover:bg-surface">
                  <RunBadge state={run.state} />
                  <span className="min-w-0 flex-1 truncate text-text">
                    #{run.number} · {run.title || run.name}
                  </span>
                  <span className="hidden font-mono text-xs text-subtle sm:inline">{run.sha}</span>
                  <span className="w-16 text-right text-xs text-subtle">{formatDuration(run.duration_s)}</span>
                  <span className="w-24 text-right text-xs text-subtle">{timeAgo(run.created_at)}</span>
                </a>
              </li>
            ))}
          </ul>
        ))}
    </Section>
  );
}

function OpenPulls({ activity }: { activity: Activity | undefined }) {
  return (
    <Section title={t("open_pull_requests")} aside={activity?.available && activity.merge.sample > 0 ? t("db_median", { v: formatHours(activity.merge.median_hours) }) : t("db_median", { v: "—" })}>
      <ConnectorNotice activity={activity} />
      {activity?.available &&
        (activity.pulls.open === 0 ? (
          <p className="text-sm text-subtle">{t("no_open_pr_against")} {activity.repo.base}.</p>
        ) : (
          <ul className="-mx-2 divide-y divide-line">
            {activity.pulls.items.map((pr) => (
              <li key={pr.number}>
                <a href={safeHref(pr.url)} target="_blank" rel="noreferrer" className="flex items-center gap-3 rounded-lg px-2 py-2 text-[13px] hover:bg-surface">
                  <GitPullRequest size={15} className="shrink-0 text-subtle" aria-hidden />
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-text">
                      #{pr.number} {pr.title}
                      {pr.against_base === false && pr.base && <span className="ml-2 rounded bg-surface-2 px-1.5 py-0.5 font-mono text-[10px] text-subtle">{pr.base}</span>}
                      {pr.draft && <span className="ml-2 rounded bg-surface-2 px-1.5 py-0.5 text-[10px] uppercase text-subtle">{t("draft")}</span>}
                    </span>
                    <span className="block text-xs text-subtle">
                      {pr.author ?? "—"} · open for {formatHours(pr.age_hours)}
                      {pr.from_vitrix && t("db_from_ui")}
                    </span>
                  </span>
                  <RunBadge state={pr.ci} />
                </a>
              </li>
            ))}
          </ul>
        ))}
    </Section>
  );
}

/** Latest commits touching rules, cases or datasets (local Git; no GitHub needed). */
function RecentChanges({ history }: { history: History | undefined }) {
  return (
    <Section title={t("recent_changes")} aside={history?.available ? t("db_commits_on", { x: tn("n_commits", history.commits) }) : undefined}>
      {!history && <p className="text-sm text-muted">{t("reading_git_history")}</p>}
      {history && !history.available && <p className="text-sm text-subtle">{history.message ?? `${t("no_git_history")}${history.reason}).`}</p>}
      {history?.available && history.activity.length === 0 && <p className="text-sm text-subtle">{t("no_commit_touches_rules_yet")}</p>}
      {history?.available && (
        <ul className="-mx-2 divide-y divide-line">
          {history.activity.slice(0, 8).map((c) => (
            <li key={c.sha} className="px-2 py-2 text-[13px]">
              <span className="flex items-baseline gap-2">
                <span className="font-mono text-xs text-accent">{c.sha}</span>
                <span className="min-w-0 flex-1 truncate text-text">{c.subject}</span>
                <span className="shrink-0 text-xs text-subtle">{timeAgo(c.date)}</span>
              </span>
              <span className="block truncate text-xs text-subtle">
                {c.author} · {t("db_files", { n: c.files.length + c.more_files })}
              </span>
            </li>
          ))}
        </ul>
      )}
    </Section>
  );
}

export default function DashboardPage() {
  const stats = useQuery({ queryKey: ["stats"], queryFn: api.stats });
  const rules = useQuery({ queryKey: ["rules"], queryFn: api.rules });
  const activity = useQuery({ queryKey: ["activity"], queryFn: () => api.activity() });
  const refresh = useQuery({ queryKey: ["activity-refresh"], queryFn: () => api.activity(true), enabled: false });
  const quality = useQuery({ queryKey: ["quality"], queryFn: api.quality });
  const history = useQuery({ queryKey: ["history"], queryFn: api.history });

  const act = refresh.data ?? activity.data;
  const error = stats.error ?? rules.error;
  const tactics = (stats.data?.mitre.tactics ?? []).filter((t) => t.count > 0);

  return (
    <div className="mx-auto max-w-7xl px-4 py-8 sm:px-8">
      <PageHeader
        title={t("operational")}
        subtitle={
          act?.available
            ? t("db_health_of", { name: act.repo.name, base: act.repo.base })
            : t("l_health_of_the_local_repository_val")
        }
        actions={
          <div className="flex flex-wrap gap-2">
            <ExportMenu
              page="operational"
              title={t("operational")}
              disabled={!stats.data}
              facts={stats.data ? [["Rules", stats.data.rules.total], ["Lint errors", stats.data.lint.errors], ["Lint warnings", stats.data.lint.warnings], ["Open pull requests", act?.available ? act.pulls.open : "-"]] : []}
              tables={[
                { name: "open-pull-requests", label: t("open_pull_requests"), columns: ["number", "title", "author", "age_hours", "ci"], rows: act?.available ? act.pulls.items.map((p) => [p.number, p.title, p.author, p.age_hours, p.ci]) : [] },
                { name: "recent-runs", label: t("ci_runs"), columns: ["id", "state"], rows: act?.available ? act.ci.runs.map((r) => [r.id, r.state]) : [] },
                { name: "rules-needing-attention", label: t("ex_tbl_attention"), columns: ["rule_id", "title", "level"], rows: (rules.data ?? []).filter((r) => r.state !== "ok").map((r) => [r.id, r.title, r.level]) },
              ]}
            />
            {act?.available && (
              <button type="button" onClick={() => refresh.refetch()} className={btnSecondary}>
                <RefreshCw size={15} className={refresh.isFetching ? "animate-spin" : undefined} aria-hidden /> {t("refresh")}
              </button>
            )}
            <Link to="/editor" className={btnPrimary}>
              <Plus size={16} aria-hidden /> {t("new_rule")}
            </Link>
          </div>
        }
      />
      {error && <ErrorBox message={(error as Error).message} />}
      {stats.isLoading && <p className="text-sm text-muted">{t("reading_the_repository")}</p>}

      {(rules.data ?? []).filter((r) => r.publication?.state === "local" || r.publication?.state === "unknown").length > 0 && (
        <p className="mb-4 flex flex-wrap items-center gap-2 rounded-[10px] border border-warn/30 bg-warn-soft px-4 py-2.5 text-sm text-warn" role="status">
          <HardDrive size={15} aria-hidden /> {tn("ru_only_local", (rules.data ?? []).filter((r) => r.publication?.state === "local" || r.publication?.state === "unknown").length)}
          <Link to="/rules?publication=unmerged" className="font-semibold underline">
            {t("ru_show_them")}
          </Link>
        </p>
      )}

      {stats.data && <Pipeline stats={stats.data} activity={act} />}

      {quality.data && (
        <>
          <div className="mb-2 flex flex-wrap items-baseline justify-between gap-3 px-1">
            <h2 className="text-[15px] font-semibold text-strong">{t("path_to_publication")}</h2>
            <Link to="/rules?view=gate" className="text-xs font-medium text-accent hover:underline">
              {t("db_ready_open", { a: quality.data.summary.ready, b: quality.data.summary.total })}
            </Link>
          </div>
          <FlowFunnel q={quality.data} />
        </>
      )}

      {stats.data && rules.data && (
        <div className="grid gap-5 lg:grid-cols-[3fr_2fr]">
          <NeedsAttention rules={rules.data} gate={quality.data?.rules ?? []} />
          <Section title={t("mitre_att_ck_coverage")} aside={t("db_tactics_pct", { a: stats.data.mitre.covered, b: stats.data.mitre.total, p: pct(stats.data.mitre.covered, stats.data.mitre.total) })}>
            <BarList
              rows={tactics.map((t) => ({ key: t.slug, code: t.id, label: t.name, value: t.count, title: `${t.id} ${t.name}: ${tn("n_rules", t.count)}`, to: "/coverage" }))}
              empty={t("no_rule_with_an_attack_tactic_tag")}
            />
            {stats.data.mitre.uncovered.length > 0 && <p className="mt-4 text-xs text-subtle">{t("no_coverage_2")} {stats.data.mitre.uncovered.join(", ")}.</p>}
          </Section>
          <CiRuns activity={act} />
          <OpenPulls activity={act} />
          <RecentChanges history={history.data} />
        </div>
      )}
      {act?.available && (
        <p className="mt-5 flex items-center gap-1.5 text-xs text-subtle">
          <ExternalLink size={12} aria-hidden /> {t("github_data_from")} {timeAgo(act.fetched_at)}{t("db_rest_local")}
        </p>
      )}
    </div>
  );
}
