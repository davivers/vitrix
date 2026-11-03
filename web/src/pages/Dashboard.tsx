import { useQuery } from "@tanstack/react-query";
import clsx from "clsx";
import { AlertTriangle, CheckCircle2, Clock, ExternalLink, GitCommitHorizontal, GitPullRequest, Plus, RefreshCw, XCircle } from "lucide-react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { BarList, ConnectorNotice, HealthMeter, RunBadge, Section, formatDuration, formatHours, pct, safeHref, timeAgo } from "../components/dash";
import { Card, ErrorBox, PageHeader, btnPrimary, btnSecondary } from "../components/ui";
import type { Activity, History, QualityRule, RuleSummary, Stats } from "../types";
import { FlowFunnel } from "./QualityGate";

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
        <h2 className="text-[15px] font-semibold text-strong">Validation pipeline</h2>
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
            "local repository"
          )}
        </span>
      </div>
      <div className="grid grid-cols-2 divide-line sm:grid-cols-3 lg:grid-cols-5 lg:divide-x">
        <Stage label="Parse" value={String(pipeline.parse.ok)} detail={pipeline.parse.failed ? `${pipeline.parse.failed} with invalid YAML` : "YAML without syntax errors"} ok={pipeline.parse.failed === 0} />
        <Stage
          label="Validation"
          value={`${pipeline.validation.ok} passing`}
          detail={`${pipeline.validation.warn} with warnings · ${pipeline.validation.fail} failing`}
          ok={pipeline.validation.fail === 0}
        />
        <Stage
          label="Conversion"
          value={`${pipeline.conversion.ok}/${total}`}
          detail={pipeline.conversion.failed ? `${pipeline.conversion.failed} conversion failures` : "final language ok"}
          ok={pipeline.conversion.failed === 0}
        />
        <Stage
          label="Tests"
          value={`${tests.passed}/${tests.total}`}
          detail={tests.total - tests.passed ? `${tests.total - tests.passed} failing cases` : `${tests.rules_without_cases} rules without cases`}
          ok={tests.total === tests.passed && tests.rules_without_cases === 0}
        />
        <Stage
          label="Pull requests"
          value={pulls ? `${pulls.open} open` : "—"}
          detail={pulls ? (pulls.failing ? `${pulls.failing} with failing CI` : "none with failing CI") : "GitHub not connected"}
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
    <Section title="Needs attention" aside={`${items.length} ${items.length === 1 ? "rule" : "rules"}`}>
      {items.length === 0 ? (
        <p className="flex items-center gap-2 text-sm text-muted">
          <CheckCircle2 size={16} className="text-good" aria-hidden /> Nothing pending: every rule passes lint, conversion, tests and the quality gate.
        </p>
      ) : (
        <ul className="-mx-2 divide-y divide-line">
          {items.map(({ r, g, stale, blocked }) => {
            const fail = r.state === "fail";
            const first = r.issues[0]?.message ?? g?.blockers[0] ?? (stale ? `Not reviewed for ${Math.round(g?.age_days ?? 0)} days` : "—");
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
                    {fail ? "Failing" : blocked ? "Blocked" : stale ? "Review due" : "Warning"}
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
    <Section title="CI runs" aside={activity?.available && activity.ci.success_rate !== null ? `${activity.ci.success_rate}% passing (${activity.ci.sample})` : undefined}>
      <ConnectorNotice activity={activity} />
      {activity?.available &&
        (activity.ci.runs.length === 0 ? (
          <p className="text-sm text-subtle">No CI run on {activity.repo.base}.</p>
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
    <Section title="Open pull requests" aside={activity?.available && activity.merge.median_hours !== null ? `median time to merge: ${formatHours(activity.merge.median_hours)}` : undefined}>
      <ConnectorNotice activity={activity} />
      {activity?.available &&
        (activity.pulls.items.length === 0 ? (
          <p className="text-sm text-subtle">No open PR against {activity.repo.base}.</p>
        ) : (
          <ul className="-mx-2 divide-y divide-line">
            {activity.pulls.items.map((pr) => (
              <li key={pr.number}>
                <a href={safeHref(pr.url)} target="_blank" rel="noreferrer" className="flex items-center gap-3 rounded-lg px-2 py-2 text-[13px] hover:bg-surface">
                  <GitPullRequest size={15} className="shrink-0 text-subtle" aria-hidden />
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-text">
                      #{pr.number} {pr.title}
                      {pr.draft && <span className="ml-2 rounded bg-surface-2 px-1.5 py-0.5 text-[10px] uppercase text-subtle">draft</span>}
                    </span>
                    <span className="block text-xs text-subtle">
                      {pr.author ?? "—"} · open for {formatHours(pr.age_hours)}
                      {pr.from_vitrix && " · from the UI"}
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
    <Section title="Recent changes" aside={history?.available ? `${history.commits} ${history.commits === 1 ? "commit" : "commits"} on detections` : undefined}>
      {!history && <p className="text-sm text-muted">Reading Git history…</p>}
      {history && !history.available && <p className="text-sm text-subtle">No Git history ({history.reason}).</p>}
      {history?.available && history.activity.length === 0 && <p className="text-sm text-subtle">No commit touches rules yet.</p>}
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
                {c.author} · {c.files.length + c.more_files} file(s)
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
        title="Operational"
        subtitle={
          act?.available
            ? `Health of ${act.repo.name}: validation, conversion, tests and ATT&CK coverage on ${act.repo.base}.`
            : "Health of the local repository: validation, conversion, tests and ATT&CK coverage."
        }
        actions={
          <div className="flex flex-wrap gap-2">
            {act?.available && (
              <button type="button" onClick={() => refresh.refetch()} className={btnSecondary}>
                <RefreshCw size={15} className={refresh.isFetching ? "animate-spin" : undefined} aria-hidden /> Refresh
              </button>
            )}
            <Link to="/editor" className={btnPrimary}>
              <Plus size={16} aria-hidden /> New rule
            </Link>
          </div>
        }
      />
      {error && <ErrorBox message={(error as Error).message} />}
      {stats.isLoading && <p className="text-sm text-muted">Reading the repository…</p>}

      {stats.data && <Pipeline stats={stats.data} activity={act} />}

      {quality.data && (
        <>
          <div className="mb-2 flex flex-wrap items-baseline justify-between gap-3 px-1">
            <h2 className="text-[15px] font-semibold text-strong">Path to publication</h2>
            <Link to="/gate" className="text-xs font-medium text-accent hover:underline">
              {quality.data.summary.ready}/{quality.data.summary.total} ready · open the Quality Gate
            </Link>
          </div>
          <FlowFunnel q={quality.data} />
        </>
      )}

      {stats.data && rules.data && (
        <div className="grid gap-5 lg:grid-cols-[3fr_2fr]">
          <NeedsAttention rules={rules.data} gate={quality.data?.rules ?? []} />
          <Section title="MITRE ATT&CK coverage" aside={`${stats.data.mitre.covered}/${stats.data.mitre.total} tactics · ${pct(stats.data.mitre.covered, stats.data.mitre.total)}%`}>
            <BarList
              rows={tactics.map((t) => ({ key: t.slug, code: t.id, label: t.name, value: t.count, title: `${t.id} ${t.name}: ${t.count} rules`, to: "/coverage" }))}
              empty="No rule with an attack.<tactic> tag."
            />
            {stats.data.mitre.uncovered.length > 0 && <p className="mt-4 text-xs text-subtle">No coverage: {stats.data.mitre.uncovered.join(", ")}.</p>}
          </Section>
          <CiRuns activity={act} />
          <OpenPulls activity={act} />
          <RecentChanges history={history.data} />
        </div>
      )}
      {act?.available && (
        <p className="mt-5 flex items-center gap-1.5 text-xs text-subtle">
          <ExternalLink size={12} aria-hidden /> GitHub data from {timeAgo(act.fetched_at)}; the rest comes from the local repository.
        </p>
      )}
    </div>
  );
}
