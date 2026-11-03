import clsx from "clsx";
import { AlertTriangle, CheckCircle2, ChevronRight, CircleDashed, Clock, XCircle } from "lucide-react";
import type { GateCheck, StageId, StageState } from "../types";

export const STAGES: { id: StageId; label: string; hint: string }[] = [
  { id: "write", label: "Escrever", hint: "YAML lido sem erro" },
  { id: "validate", label: "Validar", hint: "schema, lint e conversão para a linguagem final" },
  { id: "test", label: "Testar", hint: "casos positivos, negativos e de borda" },
  { id: "replay", label: "Replay", hint: "logs de datasets/ com as contagens esperadas" },
  { id: "analyze", label: "Analisar", hint: "falsos positivos, exclusões, ATT&CK e qualidade dos casos" },
  { id: "gate", label: "Quality gate", hint: "todas as verificações bloqueantes passam" },
  { id: "deploy", label: "Deploy", hint: "merge do PR; o CI gera o dist/. Envio direto ao SIEM ainda não existe." },
];

export const QUESTIONS: Record<number, string> = {
  1: "A regra está sintaticamente correta?",
  2: "A lógica de detecção funciona?",
  3: "Existem falsos positivos conhecidos?",
  4: "A regra detecta os comportamentos esperados?",
  5: "A regra está pronta para ser publicada?",
};

export const STAGE_META: Record<StageState, { label: string; cls: string; ring: string; Icon: typeof CheckCircle2 }> = {
  ok: { label: "ok", cls: "text-good", ring: "bg-good-soft", Icon: CheckCircle2 },
  warn: { label: "com recomendações", cls: "text-warn", ring: "bg-warn-soft", Icon: AlertTriangle },
  fail: { label: "bloqueado", cls: "text-bad", ring: "bg-bad-soft", Icon: XCircle },
  skip: { label: "não se aplica", cls: "text-subtle", ring: "bg-surface-2", Icon: CircleDashed },
  pending: { label: "aguardando merge", cls: "text-muted", ring: "bg-surface-2", Icon: Clock },
};

export function StageIcon({ state, size = 14 }: { state: StageState; size?: number }) {
  const { cls, Icon } = STAGE_META[state];
  return <Icon size={size} className={clsx("shrink-0", cls)} aria-label={STAGE_META[state].label} />;
}

/** A trilha Escrever → … → Deploy. Cada etapa tem ícone + texto, nunca só cor. */
export function FlowStepper({ stages, compact = false }: { stages: Record<StageId, StageState>; compact?: boolean }) {
  return (
    <ol className={clsx("flex flex-wrap items-center", compact ? "gap-1" : "gap-1.5")} aria-label="Fluxo da regra">
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

/** Verificações do gate agrupadas por etapa. */
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
                      {!c.blocking && c.passed === false && <span className="ml-1.5 text-xs text-subtle">(recomendação)</span>}
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

const KIND_META: Record<string, { label: string; cls: string }> = {
  positive: { label: "positivo", cls: "bg-surface-2 text-text" },
  negative: { label: "negativo", cls: "bg-surface-2 text-text" },
  false_positive: { label: "falso positivo", cls: "bg-surface-2 text-text" },
  edge: { label: "borda", cls: "bg-surface-2 text-text" },
};

export function KindTag({ kind }: { kind: string }) {
  const meta = KIND_META[kind] ?? { label: kind, cls: "bg-surface-2 text-text" };
  return <span className={clsx("rounded px-1.5 py-0.5 font-mono text-[10.5px] uppercase tracking-wide", meta.cls)}>{meta.label}</span>;
}

export const KIND_LABEL: Record<string, string> = {
  positive: "Positivos",
  negative: "Negativos",
  false_positive: "Falsos positivos",
  edge: "Borda",
};
