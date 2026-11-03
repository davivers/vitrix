import clsx from "clsx";
import { AlertTriangle, CheckCircle2, CircleDashed, Loader2, PlugZap, XCircle } from "lucide-react";
import { useId, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import type { Activity, RunState, State } from "../types";
import { Card } from "./ui";

// --------------------------------------------------------------------------- formatting

const rtf = new Intl.RelativeTimeFormat("en", { numeric: "auto" });

/** "5 minutes ago", "yesterday"… */
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

/** Short hours: 45 min, 3.5 h, 2.1 d. */
export function formatHours(h: number | null | undefined): string {
  if (h === null || h === undefined) return "—";
  if (h < 1) return `${Math.round(h * 60)} min`;
  if (h < 48) return `${h.toLocaleString("en", { maximumFractionDigits: 1 })} h`;
  return `${(h / 24).toLocaleString("en", { maximumFractionDigits: 1 })} d`;
}

export function formatDuration(s: number | null | undefined): string {
  if (s === null || s === undefined) return "—";
  return s < 60 ? `${s}s` : `${Math.floor(s / 60)}m ${String(s % 60).padStart(2, "0")}s`;
}

export const formatDate = (iso: string) => new Date(iso).toLocaleDateString("en", { month: "short", day: "numeric", year: "numeric" });

export const pct = (n: number, d: number) => (d ? Math.round((100 * n) / d) : 0);

/** Link from external data (GitHub API): only https://github.com/, never javascript: or another host. */
export function safeHref(url: string | null | undefined): string | undefined {
  return typeof url === "string" && url.startsWith("https://github.com/") ? url : undefined;
}

// --------------------------------------------------------------------------- blocks

export function Section({ title, aside, children, className }: { title: string; aside?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <Card className={clsx("flex min-w-0 flex-col p-5", className)}>
      <div className="mb-4 flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1">
        <h2 className="text-[15px] font-semibold text-strong">{title}</h2>
        {aside && <div className="text-xs text-subtle">{aside}</div>}
      </div>
      {children}
    </Card>
  );
}

/** Headline number. Text never uses series colours; the tone only shows on the status icon. */
export function StatTile(props: { label: string; value: ReactNode; sub?: ReactNode; status?: State | "none"; source?: string; spark?: number[] }) {
  const { label, value, sub, status, source, spark } = props;
  const Icon = status === "ok" ? CheckCircle2 : status === "warn" ? AlertTriangle : status === "fail" ? XCircle : null;
  const tone = status === "ok" ? "text-good" : status === "warn" ? "text-warn" : "text-bad";
  return (
    <Card className="flex flex-col gap-1.5 p-4">
      <span className="text-[11.5px] font-medium uppercase tracking-wide text-subtle">{label}</span>
      <span className="flex items-end justify-between gap-3">
        <span className="text-[28px] font-bold leading-none tracking-tight text-strong tabular-nums">{value}</span>
        {spark && spark.length > 1 && <Sparkline values={spark} />}
      </span>
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

/** Tiny trend line for a tile: 2px stroke, last point marked. Decorative (the value is written). */
export function Sparkline({ values, width = 84, height = 28 }: { values: number[]; width?: number; height?: number }) {
  const max = Math.max(...values);
  const min = Math.min(...values);
  const x = (i: number) => (i / (values.length - 1)) * (width - 6) + 3;
  const y = (v: number) => height - 4 - ((v - min) / Math.max(1, max - min)) * (height - 8);
  const d = values.map((v, i) => `${i ? "L" : "M"}${x(i).toFixed(1)},${y(v).toFixed(1)}`).join(" ");
  return (
    <svg width={width} height={height} aria-hidden className="shrink-0 overflow-visible">
      <path d={d} fill="none" stroke="var(--color-accent)" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" />
      <circle cx={x(values.length - 1)} cy={y(values[values.length - 1])} r={3} fill="var(--color-accent)" stroke="var(--color-bg)" strokeWidth={2} />
    </svg>
  );
}

export interface Point {
  label: string; // x label (date)
  value: number;
  note?: string; // extra tooltip line
}

/**
 * Single-series step/line chart with a crosshair tooltip. One series, so no legend: the section
 * title names it. A visually hidden table carries every value for screen readers.
 */
export function LineChart({ points, height = 180, unit = "", ariaLabel }: { points: Point[]; height?: number; unit?: string; ariaLabel: string }) {
  const [hover, setHover] = useState<number | null>(null);
  const gid = useId();
  const width = 640;
  const pad = { l: 34, r: 12, t: 12, b: 24 };
  if (points.length === 0) return <p className="text-sm text-subtle">No data yet.</p>;
  const max = Math.max(1, ...points.map((p) => p.value));
  const ticks = niceTicks(max);
  const top = ticks[ticks.length - 1];
  const n = points.length;
  const x = (i: number) => pad.l + (n === 1 ? (width - pad.l - pad.r) / 2 : (i / (n - 1)) * (width - pad.l - pad.r));
  const y = (v: number) => pad.t + (1 - v / top) * (height - pad.t - pad.b);
  // step line: the value holds until the next change (a rule count is a level, not a slope)
  const line = points.map((p, i) => (i === 0 ? `M${x(0)},${y(p.value)}` : `H${x(i)}V${y(p.value)}`)).join("");
  const area = `${line}V${y(0)}H${x(0)}Z`;
  const active = hover !== null ? points[hover] : null;

  return (
    <div className="relative">
      <svg
        viewBox={`0 0 ${width} ${height}`}
        className="h-auto w-full touch-none"
        role="img"
        aria-label={ariaLabel}
        onPointerMove={(e) => {
          const box = (e.currentTarget as SVGSVGElement).getBoundingClientRect();
          const px = ((e.clientX - box.left) / box.width) * width;
          const i = n === 1 ? 0 : Math.round(((px - pad.l) / (width - pad.l - pad.r)) * (n - 1));
          setHover(Math.max(0, Math.min(n - 1, i)));
        }}
        onPointerLeave={() => setHover(null)}
      >
        <defs>
          <linearGradient id={gid} x1="0" x2="0" y1="0" y2="1">
            <stop offset="0" stopColor="var(--color-accent)" stopOpacity="0.16" />
            <stop offset="1" stopColor="var(--color-accent)" stopOpacity="0.02" />
          </linearGradient>
        </defs>
        {ticks.map((t) => (
          <g key={t}>
            <line x1={pad.l} x2={width - pad.r} y1={y(t)} y2={y(t)} stroke="var(--color-line)" strokeWidth={1} />
            <text x={pad.l - 8} y={y(t) + 4} textAnchor="end" fontSize={11} fill="var(--color-subtle)">
              {t}
            </text>
          </g>
        ))}
        <path d={area} fill={`url(#${gid})`} />
        <path d={line} fill="none" stroke="var(--color-accent)" strokeWidth={2} strokeLinejoin="round" strokeLinecap="round" />
        {[0, n - 1].filter((i, k, a) => a.indexOf(i) === k).map((i) => (
          <text key={i} x={x(i)} y={height - 6} textAnchor={i === 0 && n > 1 ? "start" : "end"} fontSize={11} fill="var(--color-subtle)">
            {points[i].label}
          </text>
        ))}
        <circle cx={x(n - 1)} cy={y(points[n - 1].value)} r={4} fill="var(--color-accent)" stroke="var(--color-bg)" strokeWidth={2} />
        {active && hover !== null && (
          <g>
            <line x1={x(hover)} x2={x(hover)} y1={pad.t} y2={y(0)} stroke="var(--color-muted)" strokeWidth={1} />
            <circle cx={x(hover)} cy={y(active.value)} r={5} fill="var(--color-accent)" stroke="var(--color-bg)" strokeWidth={2} />
          </g>
        )}
      </svg>
      {active && hover !== null && (
        <div
          className="pointer-events-none absolute top-1 z-10 rounded-lg border border-line bg-ink px-2.5 py-1.5 text-xs shadow-lg"
          style={{ left: `${(x(hover) / width) * 100}%`, transform: `translateX(${hover > n / 2 ? "-105%" : "5%"})` }}
        >
          <span className="block text-subtle">{active.label}</span>
          <span className="block font-semibold text-strong tabular-nums">
            {active.value}
            {unit}
          </span>
          {active.note && <span className="block text-muted">{active.note}</span>}
        </div>
      )}
      <table className="sr-only">
        <caption>{ariaLabel}</caption>
        <tbody>
          {points.map((p, i) => (
            <tr key={i}>
              <th scope="row">{p.label}</th>
              <td>
                {p.value}
                {unit}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function niceTicks(max: number): number[] {
  const step = max <= 4 ? 1 : max <= 10 ? 2 : max <= 25 ? 5 : max <= 50 ? 10 : Math.ceil(max / 5 / 10) * 10;
  const out = [];
  for (let v = 0; v <= max + step - 1 && out.length < 7; v += step) out.push(v);
  if (out[out.length - 1] < max) out.push(out[out.length - 1] + step);
  return out;
}

export interface BarRow {
  key: string;
  label: ReactNode;
  code?: string; // short mono id (TA0002, SPL)
  value: number;
  title?: string; // tooltip
  to?: string; // optional link
}

/** Horizontal bars of a single series (one hue), value at the tip. No legend: the title names it. */
export function BarList({ rows, max, unit = "", empty }: { rows: BarRow[]; max?: number; unit?: string; empty?: string }) {
  const top = max ?? Math.max(1, ...rows.map((r) => r.value));
  if (rows.length === 0) return <p className="text-sm text-subtle">{empty ?? "No data."}</p>;
  return (
    <ul className="space-y-2.5">
      {rows.map((r) => {
        const label = (
          <span className="flex min-w-0 items-center gap-2">
            {r.code && <span className="shrink-0 font-mono text-[11.5px] text-subtle">{r.code}</span>}
            <span className="truncate text-text">{r.label}</span>
          </span>
        );
        return (
          <li key={r.key} className="grid grid-cols-[minmax(0,15rem)_1fr_2.5rem] items-center gap-3 text-[13px]" title={r.title ?? `${r.value}${unit}`}>
            {r.to ? (
              <Link to={r.to} className="min-w-0 hover:text-accent">
                {label}
              </Link>
            ) : (
              label
            )}
            <span className="h-2 rounded-r-[4px] bg-surface-2" aria-hidden>
              <span className="block h-2 rounded-r-[4px] bg-accent" style={{ width: `${Math.max(r.value ? 2 : 0, (100 * r.value) / top)}%` }} />
            </span>
            <span className="text-right font-semibold text-strong tabular-nums">
              {r.value}
              {unit}
            </span>
          </li>
        );
      })}
    </ul>
  );
}

const STATE_META: Record<State, { label: string; bar: string; text: string; Icon: typeof CheckCircle2 }> = {
  ok: { label: "Passing", bar: "bg-good", text: "text-good", Icon: CheckCircle2 },
  warn: { label: "Warnings", bar: "bg-warn", text: "text-warn", Icon: AlertTriangle },
  fail: { label: "Failing", bar: "bg-bad", text: "text-bad", Icon: XCircle },
};

/** Stacked state bar with a legend (icon + text + number): never colour alone. */
export function StateBar({ counts }: { counts: Record<State, number> }) {
  const total = counts.ok + counts.warn + counts.fail;
  const order: State[] = ["ok", "warn", "fail"];
  return (
    <div className="space-y-3">
      <div
        className="flex h-3 gap-[2px] overflow-hidden rounded-[4px] bg-surface-2"
        role="img"
        aria-label={order.map((s) => `${STATE_META[s].label}: ${counts[s]}`).join(", ")}
      >
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

/** Health score 0–100 as a meter: status tone + the number written next to it. */
export function HealthMeter({ score }: { score: number }) {
  const tone = score >= 90 ? "bg-good" : score >= 70 ? "bg-warn" : "bg-bad";
  return (
    <span className="inline-flex items-center gap-2" title={`Health ${score}/100`}>
      <span className="h-1.5 w-14 overflow-hidden rounded-full bg-surface-2" aria-hidden>
        <span className={clsx("block h-1.5 rounded-full", tone)} style={{ width: `${score}%` }} />
      </span>
      <span className="font-mono text-xs font-semibold text-strong tabular-nums">{score}</span>
    </span>
  );
}

export function RunBadge({ state }: { state: RunState | null }) {
  if (state === null)
    return (
      <span className="inline-flex items-center gap-1 text-xs text-subtle">
        <CircleDashed size={13} aria-hidden /> no CI
      </span>
    );
  const meta = {
    success: { label: "passed", cls: "bg-good-soft text-good", Icon: CheckCircle2 },
    failure: { label: "failed", cls: "bg-bad-soft text-bad", Icon: XCircle },
    pending: { label: "running", cls: "bg-surface-2 text-muted", Icon: Loader2 },
  }[state];
  return (
    <span className={clsx("inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium", meta.cls)}>
      <meta.Icon size={12} className={state === "pending" ? "animate-spin" : undefined} aria-hidden /> {meta.label}
    </span>
  );
}

const REASON: Record<string, string> = {
  not_configured: "Configure the github section in vitrix.yml to see PRs, CI and time to merge.",
  no_token: "Set VITRIX_GITHUB_TOKEN in the environment of vitrix serve to read PRs and CI.",
  error: "Could not read GitHub right now.",
};

/** Shown instead of GitHub numbers when the connector is unavailable. Never invents numbers. */
export function ConnectorNotice({ activity, compact }: { activity: Activity | undefined; compact?: boolean }) {
  if (!activity || activity.available) return null;
  return (
    <div className={clsx("flex items-start gap-2 rounded-[10px] border border-line bg-surface text-[13px] text-muted", compact ? "p-2.5" : "p-3")}>
      <PlugZap size={16} className="mt-0.5 shrink-0 text-subtle" aria-hidden />
      <span>
        {REASON[activity.reason]}
        {activity.reason === "error" && <span className="block text-xs text-subtle [overflow-wrap:anywhere]">{activity.message}</span>}{" "}
        <Link to="/connections" className="font-medium text-accent hover:underline">
          Connections
        </Link>
      </span>
    </div>
  );
}
