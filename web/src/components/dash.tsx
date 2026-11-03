import clsx from "clsx";
import { AlertTriangle, CheckCircle2, CircleDashed, Loader2, PlugZap, XCircle } from "lucide-react";
import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import type { Activity, RunState, State } from "../types";
import { Card } from "./ui";

// --------------------------------------------------------------------------- formatação

const rtf = new Intl.RelativeTimeFormat("pt-BR", { numeric: "auto" });

/** "há 5 minutos", "ontem"… */
export function timeAgo(iso: string | null | undefined): string {
  if (!iso) return "—";
  const diff = (new Date(iso).getTime() - Date.now()) / 1000;
  const steps: [Intl.RelativeTimeFormatUnit, number][] = [
    ["second", 60],
    ["minute", 60],
    ["hour", 24],
    ["day", 30],
    ["month", 12],
    ["year", Infinity],
  ];
  let value = diff;
  for (const [unit, size] of steps) {
    if (Math.abs(value) < size) return rtf.format(Math.round(value), unit);
    value /= size;
  }
  return "—";
}

/** Horas em texto curto: 45 min, 3,5 h, 2,1 d. */
export function formatHours(h: number | null | undefined): string {
  if (h === null || h === undefined) return "—";
  if (h < 1) return `${Math.round(h * 60)} min`;
  if (h < 48) return `${h.toLocaleString("pt-BR", { maximumFractionDigits: 1 })} h`;
  return `${(h / 24).toLocaleString("pt-BR", { maximumFractionDigits: 1 })} d`;
}

export function formatDuration(s: number | null | undefined): string {
  if (s === null || s === undefined) return "—";
  return s < 60 ? `${s} s` : `${Math.floor(s / 60)} min ${String(s % 60).padStart(2, "0")} s`;
}

export const pct = (n: number, d: number) => (d ? Math.round((100 * n) / d) : 0);

// --------------------------------------------------------------------------- blocos

export function Section({ title, aside, children, className }: { title: string; aside?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <Card className={clsx("flex flex-col p-5", className)}>
      <div className="mb-4 flex items-baseline justify-between gap-3">
        <h2 className="text-[15px] font-semibold text-strong">{title}</h2>
        {aside && <div className="text-xs text-subtle">{aside}</div>}
      </div>
      {children}
    </Card>
  );
}

/** Número de destaque. O texto nunca usa cor de série; o tom só aparece no ícone de status. */
export function StatTile(props: { label: string; value: ReactNode; sub?: ReactNode; status?: State | "none"; source?: string }) {
  const { label, value, sub, status, source } = props;
  const Icon = status === "ok" ? CheckCircle2 : status === "warn" ? AlertTriangle : status === "fail" ? XCircle : null;
  const tone = status === "ok" ? "text-good" : status === "warn" ? "text-warn" : "text-bad";
  return (
    <Card className="flex flex-col gap-1.5 p-4">
      <span className="text-[11.5px] font-medium uppercase tracking-wide text-subtle">{label}</span>
      <span className="text-[28px] font-bold leading-none tracking-tight text-strong tabular-nums">{value}</span>
      {sub && (
        <span className="flex items-center gap-1.5 text-[12.5px] text-muted">
          {Icon && <Icon size={14} className={clsx("shrink-0", tone)} aria-hidden />}
          {sub}
        </span>
      )}
      {source && <span className="mt-auto pt-1 text-[11px] text-subtle">{source}</span>}
    </Card>
  );
}

export interface BarRow {
  key: string;
  label: ReactNode;
  code?: string; // id curto em mono (TA0002, SPL)
  value: number;
  title?: string; // tooltip
}

/** Barras horizontais de uma série só (um tom), valor na ponta. Sem legenda: o título nomeia a série. */
export function BarList({ rows, max, unit = "", empty }: { rows: BarRow[]; max?: number; unit?: string; empty?: string }) {
  const top = max ?? Math.max(1, ...rows.map((r) => r.value));
  if (rows.length === 0) return <p className="text-sm text-subtle">{empty ?? "Sem dados."}</p>;
  return (
    <ul className="space-y-2.5">
      {rows.map((r) => (
        <li key={r.key} className="grid grid-cols-[minmax(0,15rem)_1fr_2.5rem] items-center gap-3 text-[13px]" title={r.title ?? `${r.value}${unit}`}>
          <span className="flex min-w-0 items-center gap-2">
            {r.code && <span className="shrink-0 font-mono text-[11.5px] text-subtle">{r.code}</span>}
            <span className="truncate text-text">{r.label}</span>
          </span>
          <span className="h-2 rounded-r-[4px] bg-surface-2" aria-hidden>
            <span className="block h-2 rounded-r-[4px] bg-accent" style={{ width: `${Math.max(r.value ? 2 : 0, (100 * r.value) / top)}%` }} />
          </span>
          <span className="text-right font-semibold text-strong tabular-nums">
            {r.value}
            {unit}
          </span>
        </li>
      ))}
    </ul>
  );
}

const STATE_META: Record<State, { label: string; bar: string; text: string; Icon: typeof CheckCircle2 }> = {
  ok: { label: "Aprovadas", bar: "bg-good", text: "text-good", Icon: CheckCircle2 },
  warn: { label: "Com avisos", bar: "bg-warn", text: "text-warn", Icon: AlertTriangle },
  fail: { label: "Reprovadas", bar: "bg-bad", text: "text-bad", Icon: XCircle },
};

/** Barra empilhada de estado, com legenda (ícone + texto + número): nunca só cor. */
export function StateBar({ counts }: { counts: Record<State, number> }) {
  const total = counts.ok + counts.warn + counts.fail;
  const order: State[] = ["ok", "warn", "fail"];
  return (
    <div className="space-y-3">
      <div className="flex h-3 gap-[2px] overflow-hidden rounded-[4px] bg-surface-2" role="img" aria-label={order.map((s) => `${STATE_META[s].label}: ${counts[s]}`).join(", ")}>
        {order.map((s) => (counts[s] ? <span key={s} className={STATE_META[s].bar} style={{ width: `${(100 * counts[s]) / total}%` }} title={`${STATE_META[s].label}: ${counts[s]}`} /> : null))}
      </div>
      <ul className="flex flex-wrap gap-x-5 gap-y-1.5 text-[13px]">
        {order.map((s) => {
          const { label, text, Icon } = STATE_META[s];
          return (
            <li key={s} className="flex items-center gap-1.5 text-muted">
              <Icon size={14} className={text} aria-hidden />
              {label}
              <span className="font-semibold text-strong tabular-nums">{counts[s]}</span>
              <span className="text-subtle">({pct(counts[s], total)}%)</span>
            </li>
          );
        })}
      </ul>
    </div>
  );
}

export function RunBadge({ state }: { state: RunState | null }) {
  if (state === null)
    return (
      <span className="inline-flex items-center gap-1 text-xs text-subtle">
        <CircleDashed size={13} aria-hidden /> sem CI
      </span>
    );
  const meta = {
    success: { label: "aprovado", cls: "bg-good-soft text-good", Icon: CheckCircle2 },
    failure: { label: "reprovado", cls: "bg-bad-soft text-bad", Icon: XCircle },
    pending: { label: "rodando", cls: "bg-surface-2 text-muted", Icon: Loader2 },
  }[state];
  return (
    <span className={clsx("inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium", meta.cls)}>
      <meta.Icon size={12} className={state === "pending" ? "animate-spin" : undefined} aria-hidden /> {meta.label}
    </span>
  );
}

const REASON: Record<string, string> = {
  not_configured: "Configure a seção github no vitrix.yml para ver PRs, CI e tempo até o merge.",
  no_token: "Defina VITRIX_GITHUB_TOKEN no ambiente do vitrix serve para ler PRs e CI.",
  error: "Não consegui ler o GitHub agora.",
};

/** Aviso no lugar dos números do GitHub quando o conector não está disponível. Nunca inventa número. */
export function ConnectorNotice({ activity, compact }: { activity: Activity | undefined; compact?: boolean }) {
  if (!activity || activity.available) return null;
  return (
    <div className={clsx("flex items-start gap-2 rounded-[10px] border border-line bg-surface text-[13px] text-muted", compact ? "p-2.5" : "p-3")}>
      <PlugZap size={16} className="mt-0.5 shrink-0 text-subtle" aria-hidden />
      <span>
        {REASON[activity.reason]}
        {activity.reason === "error" && <span className="block text-xs text-subtle [overflow-wrap:anywhere]">{activity.message}</span>}{" "}
        <Link to="/connections" className="font-medium text-accent hover:underline">
          Conexões
        </Link>
      </span>
    </div>
  );
}

/** Link vindo de dados externos (API do GitHub): só https://github.com/, nunca javascript: ou outro host. */
export function safeHref(url: string | null | undefined): string | undefined {
  return typeof url === "string" && url.startsWith("https://github.com/") ? url : undefined;
}
