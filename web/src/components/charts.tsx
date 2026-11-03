import clsx from "clsx";
import { useState, type ReactNode } from "react";
import { pct } from "./dash";

/** Categorical palette validated for the dark surface (OKLCH lightness band, CVD and contrast checks). */
export const SERIES_COLORS = ["#7C6DF0", "#1FA2BD", "#D2693A", "#C84B92", "#3E86E0"];
/** The "Other" bucket and empty remainders: a muted gray, always labelled. */
export const OTHER_COLOR = "#59627F";
/** One-hue ramp (strong to light violet) for ordinal data such as severity. */
export const VIOLET_RAMP = ["#7C6DF0", "#9A8EF4", "#B7AEF7", "#D2CCFA", "#E6E3FC"];

export interface Slice {
  key: string;
  label: string;
  value: number;
  color: string;
}

/** Top `n` entries as slices (fixed colour order), the rest folded into "Other". */
export function topSlices(entries: [string, number][], n = 5, colors: string[] = SERIES_COLORS): Slice[] {
  const sorted = [...entries].filter(([, v]) => v > 0).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  const head = sorted.slice(0, n).map(([label, value], i) => ({ key: label, label, value, color: colors[i % colors.length] }));
  const rest = sorted.slice(n).reduce((sum, [, v]) => sum + v, 0);
  return rest > 0 ? [...head, { key: "__other", label: "Other", value: rest, color: OTHER_COLOR }] : head;
}

function niceTicks(max: number): number[] {
  const step = max <= 4 ? 1 : max <= 10 ? 2 : max <= 25 ? 5 : max <= 50 ? 10 : Math.ceil(max / 5 / 10) * 10;
  const out: number[] = [];
  for (let v = 0; v <= max + step - 1 && out.length < 7; v += step) out.push(v);
  if (out[out.length - 1] < max) out.push(out[out.length - 1] + step);
  return out;
}

/**
 * Donut ("pie") chart with a 2px surface gap between slices, a centre total, a legend that carries
 * the numbers (identity is never colour alone) and a hidden table for screen readers.
 */
export function DonutChart(props: { slices: Slice[]; centerValue: ReactNode; centerLabel: string; ariaLabel: string; unit?: string }) {
  const { slices, centerValue, centerLabel, ariaLabel, unit = "" } = props;
  const [hover, setHover] = useState<string | null>(null);
  const total = slices.reduce((s, x) => s + x.value, 0);
  const r = 44;
  const C = 2 * Math.PI * r;
  const gap = slices.length > 1 ? 2 : 0;
  let offset = 0;
  const arcs = slices.map((s) => {
    const len = total ? (s.value / total) * C : 0;
    const arc = { ...s, dash: Math.max(0, len - gap), offset };
    offset += len;
    return arc;
  });
  const active = slices.find((s) => s.key === hover);

  if (total === 0) return <p className="text-sm text-subtle">No data yet.</p>;
  return (
    <div className="flex flex-wrap items-center gap-x-6 gap-y-4">
      <div className="relative size-[148px] shrink-0">
        <svg viewBox="0 0 120 120" className="size-full -rotate-90" role="img" aria-label={ariaLabel} onPointerLeave={() => setHover(null)}>
          <circle cx={60} cy={60} r={r} fill="none" stroke="var(--color-surface-2)" strokeWidth={16} />
          {arcs.map((a) => (
            <circle
              key={a.key}
              cx={60}
              cy={60}
              r={r}
              fill="none"
              stroke={a.color}
              strokeWidth={hover === a.key ? 19 : 16}
              strokeDasharray={`${a.dash} ${C - a.dash}`}
              strokeDashoffset={-a.offset}
              onPointerEnter={() => setHover(a.key)}
              className="transition-[stroke-width]"
            >
              <title>{`${a.label}: ${a.value}${unit} (${pct(a.value, total)}%)`}</title>
            </circle>
          ))}
        </svg>
        <div className="pointer-events-none absolute inset-0 grid place-content-center text-center">
          <span className="text-[22px] font-bold leading-none text-strong tabular-nums">{active ? active.value : centerValue}</span>
          <span className="mt-1 max-w-[84px] text-[10.5px] leading-tight text-subtle">{active ? `${pct(active.value, total)}% · ${active.label}` : centerLabel}</span>
        </div>
      </div>
      <ul className="min-w-[10rem] flex-1 space-y-1.5 text-[13px]">
        {slices.map((s) => (
          <li
            key={s.key}
            onPointerEnter={() => setHover(s.key)}
            onPointerLeave={() => setHover(null)}
            className={clsx("flex items-center gap-2 rounded-md px-1.5 py-0.5", hover === s.key && "bg-surface-2")}
          >
            <span className="size-2.5 shrink-0 rounded-[3px]" style={{ background: s.color }} aria-hidden />
            <span className="min-w-0 flex-1 truncate text-text" title={s.label}>
              {s.label}
            </span>
            <span className="font-semibold text-strong tabular-nums">{s.value}</span>
            <span className="w-9 text-right text-xs text-subtle tabular-nums">{pct(s.value, total)}%</span>
          </li>
        ))}
      </ul>
      <table className="sr-only">
        <caption>{ariaLabel}</caption>
        <tbody>
          {slices.map((s) => (
            <tr key={s.key}>
              <th scope="row">{s.label}</th>
              <td>
                {s.value}
                {unit}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export interface Column {
  key: string;
  label: string; // x axis (short)
  title: string; // tooltip heading
  value: number;
  note?: string;
}

/** Column chart of a single series: bars up to 24px, 4px rounded tops, square base, value above the bar. */
export function ColumnChart({ columns, height = 190, ariaLabel, unit = "" }: { columns: Column[]; height?: number; ariaLabel: string; unit?: string }) {
  const [hover, setHover] = useState<number | null>(null);
  const width = 760;
  const pad = { l: 30, r: 8, t: 22, b: 30 };
  const n = columns.length;
  if (n === 0) return <p className="text-sm text-subtle">No data yet.</p>;
  const max = Math.max(1, ...columns.map((c) => c.value));
  const ticks = niceTicks(max);
  const top = ticks[ticks.length - 1];
  const slot = (width - pad.l - pad.r) / n;
  const bar = Math.min(24, slot * 0.6);
  const y = (v: number) => pad.t + (1 - v / top) * (height - pad.t - pad.b);
  const base = y(0);
  const active = hover !== null ? columns[hover] : null;

  return (
    <div className="relative">
      <svg viewBox={`0 0 ${width} ${height}`} className="h-auto w-full" role="img" aria-label={ariaLabel} onPointerLeave={() => setHover(null)}>
        {ticks.map((t) => (
          <g key={t}>
            <line x1={pad.l} x2={width - pad.r} y1={y(t)} y2={y(t)} stroke="var(--color-line)" strokeWidth={1} />
            <text x={pad.l - 6} y={y(t) + 4} textAnchor="end" fontSize={11} fill="var(--color-subtle)">
              {t}
            </text>
          </g>
        ))}
        {columns.map((c, i) => {
          const cx = pad.l + slot * i + slot / 2;
          const h = base - y(c.value);
          const r = Math.min(4, h);
          const yv = y(c.value);
          return (
            <g key={c.key} onPointerEnter={() => setHover(i)}>
              <rect x={pad.l + slot * i} y={pad.t} width={slot} height={base - pad.t} fill="transparent" />
              {c.value > 0 && (
                <path
                  d={`M${cx - bar / 2},${base}V${yv + r}Q${cx - bar / 2},${yv} ${cx - bar / 2 + r},${yv}H${cx + bar / 2 - r}Q${cx + bar / 2},${yv} ${cx + bar / 2},${yv + r}V${base}Z`}
                  fill="var(--color-accent)"
                  opacity={hover === null || hover === i ? 1 : 0.55}
                />
              )}
              {c.value > 0 && (
                <text x={cx} y={yv - 6} textAnchor="middle" fontSize={11} fontWeight={600} fill="var(--color-text)">
                  {c.value}
                </text>
              )}
              <text x={cx} y={height - 10} textAnchor="middle" fontSize={10} fill={hover === i ? "var(--color-text)" : "var(--color-subtle)"}>
                {c.label}
              </text>
            </g>
          );
        })}
      </svg>
      {active && hover !== null && (
        <div
          className="pointer-events-none absolute top-0 z-10 rounded-lg border border-line bg-ink px-2.5 py-1.5 text-xs shadow-lg"
          style={{ left: `${((pad.l + slot * hover + slot / 2) / width) * 100}%`, transform: `translateX(${hover > n / 2 ? "-105%" : "5%"})` }}
        >
          <span className="block font-semibold text-strong">{active.title}</span>
          <span className="block text-muted tabular-nums">
            {active.value}
            {unit}
          </span>
          {active.note && <span className="block text-subtle">{active.note}</span>}
        </div>
      )}
      <table className="sr-only">
        <caption>{ariaLabel}</caption>
        <tbody>
          {columns.map((c) => (
            <tr key={c.key}>
              <th scope="row">{c.title}</th>
              <td>
                {c.value}
                {unit}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
