import clsx from "clsx";
import { ChevronDown } from "lucide-react";
import { useState } from "react";
import type { CoverageTactic, State } from "../types";
import { t, tn } from "../i18n";

export interface MatrixRule {
  id: string;
  title: string;
  state: State;
  level: string | null;
}

/** One cell of the matrix: a technique (or a parent technique with its sub-techniques folded in). */
export interface Cell {
  key: string; // unique per tactic + id
  id: string;
  rules: MatrixRule[]; // distinct
  subs: number; // folded sub-techniques (depth "Techniques")
}

export const LEVEL_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, informational: 0 };

/** Fixed bands so colours compare across tactics; with few rules per technique the count itself is the step. */
export function heatStep(n: number, max: number): 0 | 1 | 2 | 3 | 4 {
  if (n <= 0) return 0;
  if (max <= 3) return Math.min(n, 3) as 1 | 2 | 3;
  return n >= 7 ? 4 : n >= 4 ? 3 : n >= 2 ? 2 : 1;
}

export const HEAT_CLASS = ["bg-heat-0 text-heat-text", "bg-heat-1 text-heat-text", "bg-heat-2 text-heat-text", "bg-heat-3 text-heat-text", "bg-heat-4 text-heat-text-4"] as const;

export const LEGEND = [
  { step: 0, text: "0" },
  { step: 1, text: "1" },
  { step: 2, text: "2-3" },
  { step: 3, text: "4-6" },
  { step: 4, text: "7+" },
] as const;

export function buildCells(t: CoverageTactic, deep: boolean): Cell[] {
  const techs = t.techniques.filter((x) => x.id !== "—");
  if (deep) return techs.map((x) => ({ key: `${t.slug}:${x.id}`, id: x.id, rules: x.rules, subs: 0 }));
  const parents = new Map<string, { rules: Map<string, MatrixRule>; subs: number }>();
  for (const x of techs) {
    const pid = x.id.split(".")[0];
    const p = parents.get(pid) ?? { rules: new Map(), subs: 0 };
    for (const r of x.rules) p.rules.set(r.id, r);
    if (x.id.includes(".")) p.subs += 1;
    parents.set(pid, p);
  }
  return [...parents].map(([id, p]) => ({ key: `${t.slug}:${id}`, id, rules: [...p.rules.values()], subs: p.subs }));
}

function CellButton(props: { cell: Cell; max: number; selected: boolean; dim: boolean; hit: boolean; deep: boolean; onSelect: (c: Cell, el: HTMLButtonElement) => void }) {
  const { cell, max, selected, dim, hit, deep, onSelect } = props;
  const n = cell.rules.length;
  const top = cell.rules.reduce<string | null>((best, r) => (r.level && (best === null || (LEVEL_RANK[r.level] ?? -1) > (LEVEL_RANK[best] ?? -1)) ? r.level : best), null);
  const label = `${cell.id}, ${tn("n_rules", n)}${cell.subs ? `, ${tn("n_techniques", cell.subs)}` : ""}`;
  return (
    <button
      type="button"
      aria-label={label}
      aria-haspopup="dialog"
      title={`${cell.id} · ${tn("n_rules", n)}${top ? ` · ${t("am_highest", { l: top })}` : ""}`}
      onClick={(e) => onSelect(cell, e.currentTarget)}
      className={clsx(
        "flex h-9 w-full items-center justify-between gap-2 rounded-lg border px-2.5 text-left",
        HEAT_CLASS[heatStep(n, max)],
        selected ? "outline-2 outline-accent" : hit ? "ring-2 ring-accent" : "",
        "border-line",
        dim && "opacity-35",
        deep && cell.id.includes(".") && "ml-2 w-[calc(100%-0.5rem)] border-l-2 border-l-accent/50",
      )}
    >
      <span className="font-mono text-[11.5px] font-semibold">{cell.id}</span>
      <span className="flex items-baseline gap-1.5">
        {cell.subs > 0 && <span className="text-[10.5px] opacity-80">{t("am_sub", { n: cell.subs })}</span>}
        <span className="text-xs font-bold tabular-nums">{n}</span>
      </span>
    </button>
  );
}

export function AttackMatrix(props: {
  tactics: CoverageTactic[];
  deep: boolean;
  hits: Set<string> | null; // cell keys matching the search; null = no search
  selected: string | null;
  onSelect: (cell: Cell, el: HTMLButtonElement) => void;
}) {
  const { tactics, deep, hits, selected, onSelect } = props;
  const [open, setOpen] = useState<Record<string, boolean>>({});
  const maxRules = Math.max(1, ...tactics.map((t) => t.rules));
  const all = tactics.map((t) => ({ t, cells: buildCells(t, deep) }));
  const maxCell = Math.max(0, ...all.flatMap((x) => x.cells.map((c) => c.rules.length)));

  return (
    <ol className="flex flex-col gap-2 md:flex-row md:gap-1.5 md:overflow-x-auto md:pb-2" tabIndex={0} aria-label={t("att_ck_matrix_scrolls_horizontally")}>
      {all.map(({ t: tac, cells }) => {
        const isOpen = open[tac.slug] ?? false;
        return (
          <li key={tac.slug} className="md:w-[168px] md:shrink-0">
            <h3 className="m-0">
              <button
                type="button"
                aria-expanded={isOpen}
                onClick={() => setOpen({ ...open, [tac.slug]: !isOpen })}
                className="w-full rounded-[10px] border border-line bg-surface-2 px-2.5 py-2 text-left md:cursor-default md:sticky md:top-0"
              >
                <span className="flex items-start justify-between gap-2">
                  <span>
                    <span className="block font-mono text-[10.5px] text-subtle">{tac.id}</span>
                    <span className="block text-[12.5px] font-semibold leading-tight text-strong">{tac.name}</span>
                  </span>
                  <ChevronDown size={15} className={clsx("mt-1 shrink-0 text-subtle transition-transform md:hidden", isOpen && "rotate-180")} aria-hidden />
                </span>
                <span className="mt-1 block text-[11.5px] text-muted tabular-nums">
                  {tn("n_techniques", tac.techniques.filter((x) => x.id !== "—").length)} · {tn("n_rules", tac.rules)}
                </span>
                <span className="mt-1.5 flex items-center gap-2">
                  <span className="h-1.5 flex-1 rounded-full bg-surface-3">
                    <span className="block h-full rounded-full bg-accent" style={{ width: `${(100 * tac.rules) / maxRules}%` }} />
                  </span>
                  <span className="text-[11px] tabular-nums text-muted">{tac.rules > 0 ? tac.rules : t("no_coverage")}</span>
                </span>
              </button>
            </h3>
            <ul className={clsx("mt-1.5 grid-cols-2 gap-1.5 md:flex md:flex-col", isOpen ? "grid" : "hidden md:flex")}>
              {cells.map((c) => (
                <li key={c.key} className={clsx("min-w-0", deep && c.id.includes(".") && "col-span-2")}>
                  <CellButton cell={c} max={maxCell} selected={selected === c.key} dim={hits !== null && !hits.has(c.key)} hit={hits !== null && hits.has(c.key)} deep={deep} onSelect={onSelect} />
                </li>
              ))}
              {cells.length === 0 && <li className="col-span-2 rounded-lg border border-dashed border-line px-2.5 py-3 text-center text-[11.5px] text-subtle">{t("no_coverage")}</li>}
            </ul>
          </li>
        );
      })}
    </ol>
  );
}
