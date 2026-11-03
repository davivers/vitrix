import clsx from "clsx";
import { AlertTriangle, CheckCircle2, ChevronRight, CircleDashed, Clock, XCircle } from "lucide-react";
import type { GateCheck, StageId, StageState } from "../types";

export const STAGES: { id: StageId; label: string; hint: string }[] = [
  { id: "write", label: "Write", hint: "YAML parses without errors" },
  { id: "validate", label: "Validate", hint: "schema, lint and conversion to the final query language" },
  { id: "test", label: "Test", hint: "positive, negative and edge cases" },
  { id: "replay", label: "Replay", hint: "datasets/ logs with the expected match counts" },
  { id: "analyze", label: "Analyze", hint: "false positives, exclusions, ATT&CK and test data quality" },
  { id: "gate", label: "Quality gate", hint: "every blocking check passes" },
  { id: "deploy", label: "Deploy", hint: "validated by the real CI, then merged. Vitrix does not push to SIEMs yet." },
];

export const QUESTIONS: Record<number, string> = {
  1: "Is the rule syntactically correct?",
  2: "Does the detection logic work?",
  3: "Are there known false positives?",
  4: "Does the rule detect the expected behaviour?",
  5: "Is the rule ready to be published?",
};

export const STAGE_META: Record<StageState, { label: string; cls: string; ring: string; Icon: typeof CheckCircle2 }> = {
  ok: { label: "ok", cls: "text-good", ring: "bg-good-soft", Icon: CheckCircle2 },
  warn: { label: "has recommendations", cls: "text-warn", ring: "bg-warn-soft", Icon: AlertTriangle },
  fail: { label: "blocked", cls: "text-bad", ring: "bg-bad-soft", Icon: XCircle },
  skip: { label: "not applicable", cls: "text-subtle", ring: "bg-surface-2", Icon: CircleDashed },
  pending: { label: "waiting for CI and merge", cls: "text-muted", ring: "bg-surface-2", Icon: Clock },
};

export function StageIcon({ state, size = 14 }: { state: StageState; size?: number }) {
  const { cls, Icon } = STAGE_META[state];
  return <Icon size={size} className={clsx("shrink-0", cls)} aria-label={STAGE_META[state].label} />;
}

/** The Write → … → Deploy track. Every stage has icon + text, never colour alone. */
export function FlowStepper({ stages, compact = false }: { stages: Record<StageId, StageState>; compact?: boolean }) {
  return (
    <ol className={clsx("flex flex-wrap items-center", compact ? "gap-1" : "gap-1.5")} aria-label="Rule lifecycle">
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
  positive: "positive",
  negative: "negative",
  false_positive: "false positive",
  edge: "edge",
};

export function KindTag({ kind }: { kind: string }) {
  return <span className="rounded bg-surface-2 px-1.5 py-0.5 font-mono text-[10.5px] uppercase tracking-wide text-text">{KIND_META[kind] ?? kind}</span>;
}

export const KIND_LABEL: Record<string, string> = {
  positive: "Positive",
  negative: "Negative",
  false_positive: "False positive",
  edge: "Edge",
};
