import clsx from "clsx";
import { AlertTriangle, CheckCircle2, XCircle } from "lucide-react";
import type { ReactNode } from "react";
import type { State } from "../types";

const STATE = {
  ok: { label: "Válida", cls: "bg-good-soft text-good", Icon: CheckCircle2 },
  warn: { label: "Com avisos", cls: "bg-warn-soft text-warn", Icon: AlertTriangle },
  fail: { label: "Com falha", cls: "bg-bad-soft text-bad", Icon: XCircle },
} as const;

/** Estado sempre com ícone e texto, nunca só cor. */
export function StateBadge({ state }: { state: State }) {
  const { label, cls, Icon } = STATE[state];
  return (
    <span className={clsx("inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-medium", cls)}>
      <Icon size={14} aria-hidden /> {label}
    </span>
  );
}

const LEVEL: Record<string, string> = {
  critical: "Crítica",
  high: "Alta",
  medium: "Média",
  low: "Baixa",
  informational: "Info",
};

export function LevelTag({ level }: { level: string | null }) {
  if (!level) return <span className="text-muted">—</span>;
  const dot = level === "critical" ? "bg-bad" : level === "high" ? "bg-warn" : "bg-subtle";
  return (
    <span className="inline-flex items-center gap-1.5 text-sm">
      <span className={clsx("size-2 rounded-full", dot)} aria-hidden />
      {LEVEL[level] ?? level}
    </span>
  );
}

const TARGET_CODE: Record<string, string> = { splunk: "SPL", kql: "KQL", "elastic-eql": "EQL", "elastic-lucene": "LUCENE" };

/** Cor de série de cada SIEM; sempre ao lado do rótulo, nunca sozinha. */
const TARGET_SWATCH: Record<string, string> = {
  splunk: "bg-siem-splunk",
  kql: "bg-siem-microsoft",
  "elastic-eql": "bg-siem-elastic",
  "elastic-lucene": "bg-siem-elastic",
};

export function TargetSwatch({ target }: { target: string }) {
  return <span className={clsx("size-2 shrink-0 rounded-[2px]", TARGET_SWATCH[target] ?? "bg-subtle")} aria-hidden />;
}
const SOURCE_LABEL: Record<string, string> = {
  rule: "definida na regra (vitrix.target)",
  route: "definida por uma rota do vitrix.yml",
  default: "padrão do projeto (default_target)",
  all: "sem escolha: todos os alvos ativos",
  override: "forçada pela linha de comando",
};

/** Linguagem final da regra, com o resultado da conversão (ícone + texto, nunca só cor). */
export function TargetChip({ target, ok, source }: { target: string; ok?: boolean; source?: string | null }) {
  const code = TARGET_CODE[target] ?? target.toUpperCase();
  const failed = ok === false;
  return (
    <span
      title={`${target}${source ? ` · ${SOURCE_LABEL[source] ?? source}` : ""}${failed ? " · conversão falhou" : ""}`}
      className={clsx("inline-flex items-center gap-1.5 rounded-md px-2 py-1 font-mono text-xs font-semibold", failed ? "bg-bad-soft text-bad" : "bg-surface-2 text-text")}
    >
      <TargetSwatch target={target} />
      {code}
      {ok !== undefined && (failed ? <XCircle size={12} aria-label="conversão falhou" /> : <CheckCircle2 size={12} className="text-good" aria-label="conversão ok" />)}
    </span>
  );
}

export function Card({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={clsx("glass rounded-2xl", className)}>{children}</div>;
}

export function PageHeader({ title, subtitle, actions }: { title: string; subtitle?: string; actions?: ReactNode }) {
  return (
    <header className="mb-6 flex items-start justify-between gap-4">
      <div>
        <h1 className="text-[26px] font-bold tracking-[-0.02em] text-strong">{title}</h1>
        {subtitle && <p className="mt-1 text-sm text-muted">{subtitle}</p>}
      </div>
      {actions}
    </header>
  );
}

export function ErrorBox({ message }: { message: string }) {
  return (
    <div role="alert" className="flex items-start gap-2 rounded-lg border border-bad/30 bg-bad-soft p-3 text-sm text-bad [overflow-wrap:anywhere]">
      <XCircle size={16} className="mt-0.5 shrink-0" aria-hidden /> {message}
    </div>
  );
}
