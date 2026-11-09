import clsx from "clsx";
import { AlertTriangle, CheckCircle2, ChevronRight, Clock, Minus, XCircle } from "lucide-react";
import type { GateCheck, QualityReport, StageId, StageState } from "../types";
import { Card } from "./ui";
import { t } from "../i18n";

export const STAGES: { id: StageId; label: string; hint: string }[] = [
  { id: "write", label: t("l_write"), hint: t("l_yaml_parses_without_errors") },
  { id: "validate", label: t("l_validate"), hint: t("l_schema_lint_and_conversion_to_the_") },
  { id: "test", label: t("l_test"), hint: t("l_positive_negative_and_edge_cases") },
  { id: "replay", label: t("l_replay"), hint: t("l_datasets_logs_with_the_expected_ma") },
  { id: "analyze", label: t("l_analyze"), hint: t("l_false_positives_exclusions_att_ck_") },
  { id: "gate", label: t("l_quality_gate"), hint: t("l_every_blocking_check_passes") },
  { id: "deploy", label: t("l_deploy"), hint: t("l_validated_by_the_real_ci_then_merg") },
];

export const QUESTIONS: Record<number, string> = {
  1: t("l_is_the_rule_syntactically_correct"),
  2: t("l_does_the_detection_logic_work"),
  3: t("l_are_there_known_false_positives"),
  4: t("l_does_the_rule_detect_the_expected_"),
  5: t("l_is_the_rule_ready_to_be_published"),
};

export const STAGE_META: Record<StageState, { label: string; cls: string; ring: string; Icon: typeof CheckCircle2 }> = {
  ok: { label: "ok", cls: "text-good", ring: "bg-good-soft", Icon: CheckCircle2 },
  warn: { label: t("fl_recs"), cls: "text-warn", ring: "bg-warn-soft", Icon: AlertTriangle },
  fail: { label: t("blocked"), cls: "text-bad", ring: "bg-bad-soft", Icon: XCircle },
  skip: { label: t("fl_na"), cls: "text-subtle", ring: "bg-surface-2", Icon: Minus },
  pending: { label: t("fl_waiting"), cls: "text-muted", ring: "bg-surface-2", Icon: Clock },
};

export function StageIcon({ state, size = 14 }: { state: StageState; size?: number }) {
  const { cls, Icon } = STAGE_META[state];
  return <Icon size={size} className={clsx("shrink-0", cls)} aria-label={STAGE_META[state].label} />;
}

/** The Write → … → Deploy track. Every stage has icon + text, never colour alone. */
export function FlowStepper({ stages, compact = false }: { stages: Record<StageId, StageState>; compact?: boolean }) {
  return (
    <ol className={clsx("flex flex-wrap items-center", compact ? "gap-1" : "gap-1.5")} aria-label={t("rule_lifecycle")}>
      {STAGES.map((s, i) => {
        const state = stages[s.id];
        const { ring, cls, Icon, label } = STAGE_META[state];
        return (
          <li key={s.id} className="flex items-center gap-1.5">
            <span
              title={`${s.label}: ${label} · ${s.hint}`}
              className={clsx("inline-flex items-center gap-1.5 rounded-full font-medium", ring, compact ? "px-1.5 py-1" : "px-2.5 py-1 text-[12.5px]")}
            >
              <Icon size={compact ? 13 : 14} className={cls} aria-hidden />
              {compact ? <span className="sr-only">{`${s.label}: ${label}`}</span> : <span className="text-text">{s.label}</span>}
            </span>
            {i < STAGES.length - 1 && <ChevronRight size={compact ? 12 : 14} className="text-subtle" aria-hidden />}
          </li>
        );
      })}
    </ol>
  );
}

/** Gate checks grouped by stage. */
export function CheckList({ checks }: { checks: GateCheck[] }) {
  return (
    <div className="space-y-3">
      {STAGES.filter((s) => checks.some((c) => c.stage === s.id)).map((s) => (
        <div key={s.id}>
          <h3 className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-subtle">{s.label}</h3>
          <ul className="space-y-1">
            {checks
              .filter((c) => c.stage === s.id)
              .map((c) => {
                const state: StageState = c.passed === null ? "skip" : c.passed ? "ok" : c.blocking ? "fail" : "warn";
                return (
                  <li key={c.id} className="flex items-start gap-2 text-[13px]">
                    <span className="mt-0.5">
                      <StageIcon state={state} />
                    </span>
                    <span className="min-w-0">
                      <span className="text-text">{c.label}</span>
                      {!c.blocking && c.passed === false && <span className="ml-1.5 text-xs text-subtle">(recommendation)</span>}
                      {c.detail && <span className="block text-xs text-subtle [overflow-wrap:anywhere]">{c.detail}</span>}
                    </span>
                  </li>
                );
              })}
          </ul>
        </div>
      ))}
    </div>
  );
}

const KIND_META: Record<string, string> = {
  positive: t("l_positive_2"),
  negative: t("l_negative_2"),
  false_positive: t("l_false_positive_2"),
  edge: t("l_edge_2"),
};

export function KindTag({ kind }: { kind: string }) {
  return <span className="rounded bg-surface-2 px-1.5 py-0.5 font-mono text-[10.5px] uppercase tracking-wide text-text">{KIND_META[kind] ?? kind}</span>;
}

export const KIND_LABEL: Record<string, string> = {
  positive: t("l_positive"),
  negative: t("l_negative"),
  false_positive: t("l_false_positive"),
  edge: t("l_edge"),
};

export const GATE_LABELS: Record<string, string> = {
  min_positive: t("l_minimum_positive_cases"),
  min_negative: t("l_minimum_negative_cases"),
  false_positive_levels: t("l_levels_requiring_a_false_positive_"),
  require_filter_test: t("l_exclusions_must_be_tested"),
  require_mitre: t("l_att_ck_technique_required"),
  allow_warnings: t("l_lint_warnings_allowed"),
  blocked_status: t("l_blocking_statuses"),
  review_days: t("l_review_window_days"),
  min_score: t("l_minimum_health_score_to_approve"),
};

export function fmt(v: unknown, key?: string): string {
  if (typeof v === "boolean") return v ? "yes" : "no";
  if (Array.isArray(v)) return v.length ? v.join(", ") : key === "false_positive_levels" ? t("gc_not_required") : "—"; // opt-in check
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
              <span className="text-[11px] font-semibold uppercase tracking-wider text-subtle">{s.id === "deploy" ? t("l_deploy") : s.label}</span>
              <span className="mt-1 block text-[22px] font-bold leading-tight text-strong tabular-nums">
                {s.id === "deploy" ? (s.counts.pending ?? 0) : passed}
                <span className="text-sm font-medium text-subtle">/{q.summary.total}</span>
              </span>
              <span className="mt-0.5 flex items-center gap-1 text-xs text-muted">
                {s.id === "deploy" ? (
                  t("fl_ready_wait")
                ) : failed ? (
                  <>
                    <XCircle size={12} className="text-bad" aria-hidden /> {t("fl_n_blocked", { n: failed })}
                  </>
                ) : (s.counts.skip ?? 0) === q.summary.total ? (
                  t("fl_na")
                ) : (
                  <>
                    <CheckCircle2 size={12} className="text-good" aria-hidden /> {t("no_blockers")}
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
