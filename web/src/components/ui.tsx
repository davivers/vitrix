import clsx from "clsx";
import { AlertTriangle, CheckCircle2, XCircle } from "lucide-react";
import type { ReactNode } from "react";
import type { State } from "../types";
import { t } from "../i18n";

const STATE = {
  ok: { label: t("l_valid"), cls: "bg-good-soft text-good", Icon: CheckCircle2 },
  warn: { label: t("l_warnings"), cls: "bg-warn-soft text-warn", Icon: AlertTriangle },
  fail: { label: t("l_failing"), cls: "bg-bad-soft text-bad", Icon: XCircle },
} as const;

/** State is always icon + text, never colour alone. */
export function StateBadge({ state }: { state: State }) {
  const { label, cls, Icon } = STATE[state];
  return (
    <span className={clsx("inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-medium", cls)}>
      <Icon size={14} aria-hidden /> {label}
    </span>
  );
}

const LEVEL: Record<string, string> = {
  critical: t("l_critical"),
  high: t("l_high"),
  medium: t("l_medium"),
  low: t("l_low"),
  informational: t("l_info"),
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

export const TARGET_CODE: Record<string, string> = { splunk: "SPL", kql: "KQL", "elastic-eql": "EQL", "elastic-lucene": "LUCENE" };

/** Series colour of each SIEM; always next to the label, never alone. */
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
  rule: t("fl_src_rule"),
  folder: t("fl_src_folder"),
  workspace: t("fl_src_default"),
  "legacy-config": t("fl_src_legacy"),
  route: t("fl_src_legacy"),
  default: t("fl_src_default"),
  all: t("l_no_choice_every_active_target"),
  override: t("l_forced_on_the_command_line"),
};

/** Final query language of the rule, with the conversion result (icon + text, never colour alone). */
export function TargetChip({ target, ok, source }: { target: string; ok?: boolean; source?: string | null }) {
  const code = TARGET_CODE[target] ?? target.toUpperCase();
  const failed = ok === false;
  return (
    <span
      title={`${target}${source ? ` · ${SOURCE_LABEL[source] ?? source}` : ""}${failed ? " · " + t("conversion_failed") : ""}`}
      className={clsx("inline-flex items-center gap-1.5 rounded-md px-2 py-1 font-mono text-xs font-semibold", failed ? "bg-bad-soft text-bad" : "bg-surface-2 text-text")}
    >
      <TargetSwatch target={target} />
      {code}
      {ok !== undefined && (failed ? <XCircle size={12} aria-label={t("conversion_failed")} /> : <CheckCircle2 size={12} className="text-good" aria-label={t("conversion_ok")} />)}
    </span>
  );
}

export function Card({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={clsx("glass rounded-2xl", className)}>{children}</div>;
}

export function PageHeader({ title, subtitle, actions }: { title: string; subtitle?: string; actions?: ReactNode }) {
  return (
    <header className="mb-6 flex flex-wrap items-start justify-between gap-4">
      <div className="min-w-0">
        <h1 className="text-[26px] font-bold tracking-[-0.02em] text-strong">{title}</h1>
        {subtitle && <p className="mt-1 max-w-3xl text-sm text-muted">{subtitle}</p>}
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

export const btnPrimary =
  "inline-flex items-center justify-center gap-2 rounded-[10px] bg-brand px-4 py-2 text-[13.5px] font-semibold text-on-brand hover:brightness-90 disabled:cursor-not-allowed disabled:opacity-55 disabled:hover:brightness-100";
export const btnSecondary =
  "inline-flex items-center justify-center gap-2 rounded-[10px] border border-line bg-surface-2 px-3 py-2 text-[13.5px] font-semibold text-text hover:bg-surface-3 disabled:cursor-not-allowed disabled:opacity-55";
export const inputCls =
  "w-full rounded-[10px] border border-line bg-surface px-3 py-2 text-sm text-text placeholder:text-subtle focus:border-accent/50";
