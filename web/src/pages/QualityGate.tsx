import { useQuery } from "@tanstack/react-query";
import clsx from "clsx";
import { CheckCircle2, ChevronDown, ShieldCheck, XCircle } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { HealthMeter, Section, StatTile, pct } from "../components/dash";
import { CheckList, FlowStepper, QUESTIONS, STAGES, STAGE_META } from "../components/flow";
import { Card, ErrorBox, PageHeader } from "../components/ui";
import type { QualityReport, QualityRule, StageState } from "../types";

const GATE_LABELS: Record<string, string> = {
  min_positive: "Minimum positive cases",
  min_negative: "Minimum negative cases",
  false_positive_levels: "Levels requiring a false-positive case",
  require_filter_test: "Exclusions must be tested",
  require_mitre: "ATT&CK technique required",
  allow_warnings: "Lint warnings allowed",
  blocked_status: "Blocking statuses",
  require_replay: "Replay expectation required",
  review_days: "Review window (days)",
  min_score: "Minimum health score to approve",
};

function fmt(v: unknown): string {
  if (typeof v === "boolean") return v ? "yes" : "no";
  if (Array.isArray(v)) return v.length ? v.join(", ") : "—";
  return String(v);
}

export function FlowFunnel({ q }: { q: QualityReport }) {
  return (
    <Card className="mb-5 overflow-x-auto">
      <ol className="flex min-w-[760px] divide-x divide-line">
        {q.stages.map((s) => {
          const passed = (s.counts.ok ?? 0) + (s.counts.warn ?? 0) + (s.counts.pending ?? 0);
          const failed = s.counts.fail ?? 0;
          const meta = STAGES.find((x) => x.id === s.id)!;
          return (
            <li key={s.id} className="flex-1 px-4 py-3" title={meta.hint}>
              <span className="text-[11px] font-semibold uppercase tracking-wider text-subtle">{s.label}</span>
              <span className="mt-1 block text-[22px] font-bold leading-tight text-strong tabular-nums">
                {s.id === "deploy" ? (s.counts.pending ?? 0) : passed}
                <span className="text-sm font-medium text-subtle">/{q.summary.total}</span>
              </span>
              <span className="mt-0.5 flex items-center gap-1 text-xs text-muted">
                {s.id === "deploy" ? (
                  "ready, awaiting CI and merge"
                ) : failed ? (
                  <>
                    <XCircle size={12} className="text-bad" aria-hidden /> {failed} blocked
                  </>
                ) : (s.counts.skip ?? 0) === q.summary.total ? (
                  "not applicable"
                ) : (
                  <>
                    <CheckCircle2 size={12} className="text-good" aria-hidden /> no blockers
                  </>
                )}
              </span>
            </li>
          );
        })}
      </ol>
    </Card>
  );
}

function RuleRow({ r }: { r: QualityRule }) {
  const [open, setOpen] = useState(!r.ready);
  return (
    <li className="border-b border-line last:border-0">
      <button type="button" onClick={() => setOpen(!open)} aria-expanded={open} className="flex w-full flex-wrap items-center gap-3 px-4 py-3 text-left hover:bg-surface">
        <span className={clsx("inline-flex shrink-0 items-center gap-1 rounded-full px-2 py-0.5 text-xs font-semibold", r.ready ? "bg-good-soft text-good" : "bg-bad-soft text-bad")}>
          {r.ready ? <CheckCircle2 size={12} aria-hidden /> : <XCircle size={12} aria-hidden />}
          {r.ready ? "Ready" : "Blocked"}
        </span>
        <span className="min-w-[14rem] flex-1">
          <span className="block truncate text-[13.5px] font-semibold text-strong">{r.title || r.id}</span>
          <span className="block font-mono text-[11.5px] text-subtle">{r.id}</span>
        </span>
        <HealthMeter score={r.score} />
        <FlowStepper stages={r.stages} compact />
        <ChevronDown size={16} className={clsx("text-subtle transition-transform", open && "rotate-180")} aria-hidden />
      </button>
      {open && (
        <div className="grid gap-5 px-4 pb-4 md:grid-cols-[1fr_16rem]">
          <CheckList checks={r.checks} />
          <div className="space-y-2">
            <h3 className="text-[11px] font-semibold uppercase tracking-wider text-subtle">The five questions</h3>
            <ul className="space-y-1.5 text-[12.5px]">
              {Object.entries(QUESTIONS).map(([id, text]) => {
                const state = r.answers[id] as StageState;
                const { Icon, cls, label } = STAGE_META[state];
                return (
                  <li key={id} className="flex gap-2">
                    <Icon size={14} className={clsx("mt-0.5 shrink-0", cls)} aria-label={label} />
                    <span className="text-text">{text}</span>
                  </li>
                );
              })}
            </ul>
            <Link to={`/editor/${r.id}`} className="inline-block pt-1 text-xs font-medium text-accent hover:underline">
              Open in the Editor
            </Link>
          </div>
        </div>
      )}
    </li>
  );
}

export default function QualityGatePage() {
  const { data: q, error, isLoading } = useQuery({ queryKey: ["quality"], queryFn: api.quality });
  const [filter, setFilter] = useState<"all" | "blocked" | "ready">("all");
  const rules = (q?.rules ?? []).filter((r) => filter === "all" || (filter === "ready") === r.ready);

  return (
    <div className="mx-auto max-w-7xl px-4 py-8 sm:px-8">
      <PageHeader
        title="Quality gate"
        subtitle="Write → Validate → Test → Replay → Analyze → Quality gate → Deploy. A rule is publishable only when every blocking check passes and the real CI validates the change."
      />
      {error && <ErrorBox message={(error as Error).message} />}
      {isLoading && <p className="text-sm text-muted">Running the lifecycle on every rule…</p>}
      {q && (
        <>
          <div className="mb-5 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
            <StatTile label="Ready to publish" value={`${q.summary.ready}/${q.summary.total}`} sub={`${pct(q.summary.ready, q.summary.total)}% of the rule set`} status={q.summary.blocked ? "warn" : "ok"} />
            <StatTile label="Blocked" value={q.summary.blocked} sub={q.summary.blocked ? "see the blockers below" : "none"} status={q.summary.blocked ? "fail" : "ok"} />
            <StatTile
              label="Average health"
              value={q.summary.health === null ? "—" : `${q.summary.health}/100`}
              sub={q.summary.stale ? `${q.summary.stale} rule(s) due for review` : "no review overdue"}
              status={q.summary.health === null ? "none" : q.summary.health >= 90 ? "ok" : q.summary.health >= 70 ? "warn" : "fail"}
            />
            <StatTile
              label="Replay datasets"
              value={q.datasets.length}
              sub={q.datasets.length ? `${q.datasets.filter((d) => d.passed).length} without regression` : "none in datasets/"}
              status={q.datasets.some((d) => !d.passed) ? "fail" : q.datasets.length ? "ok" : "none"}
            />
          </div>

          <FlowFunnel q={q} />

          <div className="grid gap-5 xl:grid-cols-[1fr_20rem]">
            <Card className="overflow-hidden">
              <div className="flex flex-wrap items-center justify-between gap-3 border-b border-line px-4 py-3">
                <h2 className="text-[15px] font-semibold text-strong">Rules</h2>
                <div className="flex gap-1 rounded-[10px] border border-line bg-surface p-1" role="group" aria-label="Filter">
                  {(
                    [
                      ["all", "All"],
                      ["blocked", "Blocked"],
                      ["ready", "Ready"],
                    ] as const
                  ).map(([k, label]) => (
                    <button
                      key={k}
                      type="button"
                      aria-pressed={filter === k}
                      onClick={() => setFilter(k)}
                      className={clsx("rounded-md px-3 py-1 text-[13px]", filter === k ? "bg-accent-soft font-medium text-strong" : "text-muted hover:text-text")}
                    >
                      {label}
                    </button>
                  ))}
                </div>
              </div>
              <ul>
                {rules.map((r) => (
                  <RuleRow key={r.id} r={r} />
                ))}
                {rules.length === 0 && <li className="px-4 py-8 text-center text-sm text-muted">No rule in this filter.</li>}
              </ul>
            </Card>

            <div className="flex flex-col gap-5">
              <Section title="Questions answered">
                <ul className="space-y-2.5 text-[13px]">
                  {q.questions.map((x) => (
                    <li key={x.id}>
                      <span className="text-text">
                        {x.id}. {x.text}
                      </span>
                      <span className="mt-0.5 flex gap-3 text-xs text-muted">
                        <span className="flex items-center gap-1">
                          <CheckCircle2 size={12} className="text-good" aria-hidden /> {(x.counts.ok ?? 0) + (x.counts.warn ?? 0)} yes
                        </span>
                        <span className="flex items-center gap-1">
                          <XCircle size={12} className="text-bad" aria-hidden /> {x.counts.fail ?? 0} no
                        </span>
                      </span>
                    </li>
                  ))}
                </ul>
              </Section>
              <Section title="Criteria" aside={<ShieldCheck size={15} className="text-subtle" aria-hidden />}>
                <dl className="space-y-1.5 text-[12.5px]">
                  {Object.entries(q.gate).map(([k, v]) => (
                    <div key={k} className="flex justify-between gap-3">
                      <dt className="text-muted">{GATE_LABELS[k] ?? k}</dt>
                      <dd className="text-right font-mono text-text">{fmt(v)}</dd>
                    </div>
                  ))}
                </dl>
                <p className="mt-3 text-xs text-subtle">
                  Tune <span className="font-mono">quality_gate</span> in vitrix.yml (see{" "}
                  <Link to="/settings" className="text-accent hover:underline">
                    Settings
                  </Link>
                  ). In CI: <span className="font-mono">vitrix check --gate</span>.
                </p>
              </Section>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
