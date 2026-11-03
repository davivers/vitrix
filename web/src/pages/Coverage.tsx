import { useQuery } from "@tanstack/react-query";
import clsx from "clsx";
import { AlertTriangle, Download, Grid3x3, Search } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api } from "../api";
import { AttackMatrix, HEAT_CLASS, LEGEND, buildCells, type Cell } from "../components/AttackMatrix";
import { Section, StatTile, pct } from "../components/dash";
import { TechniqueDrawer } from "../components/TechniqueDrawer";
import { Card, ErrorBox, PageHeader, btnPrimary, btnSecondary, inputCls } from "../components/ui";
import { t, tn } from "../i18n";

const GAPS_HINT = t("l_technique_gaps_need_the_att_ck_cat");

function Skeleton() {
  return (
    <div aria-busy="true">
      <span className="sr-only">{t("loading_coverage")}</span>
      <div className="mb-5 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {[0, 1, 2, 3].map((i) => (
          <div key={i} className="h-28 animate-pulse rounded-2xl bg-surface motion-reduce:animate-none" />
        ))}
      </div>
      <div className="flex gap-2">
        {[0, 1, 2, 3, 4, 5].map((i) => (
          <div key={i} className="h-64 flex-1 animate-pulse rounded-2xl bg-surface motion-reduce:animate-none" />
        ))}
      </div>
    </div>
  );
}

export default function CoveragePage() {
  const { data, error, isLoading, refetch } = useQuery({ queryKey: ["coverage"], queryFn: api.coverage });
  const [params, setParams] = useSearchParams();
  const tactic = params.get("tactic") ?? "";
  const q = params.get("q") ?? "";
  const showEmpty = params.get("empty") === "1"; // tactics without a technique are hidden by default
  const deep = params.get("depth") === "sub";
  const set = (patch: Record<string, string>) => {
    const next = new URLSearchParams(params);
    for (const [k, v] of Object.entries(patch)) v ? next.set(k, v) : next.delete(k);
    setParams(next, { replace: true });
  };

  const [sel, setSel] = useState<Cell | null>(null);
  const lastCell = useRef<HTMLButtonElement | null>(null);
  const searchRef = useRef<HTMLInputElement>(null);
  const unmappedRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const el = document.activeElement;
      if (e.key === "/" && !(el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement || el instanceof HTMLSelectElement)) {
        e.preventDefault();
        searchRef.current?.focus();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const tactics = useMemo(
    () => (data?.tactics ?? []).filter((t) => (!tactic || t.slug === tactic) && (showEmpty || t.techniques.some((x) => x.id !== "—"))),
    [data, tactic, showEmpty],
  );

  const needle = q.trim().toLowerCase();
  const hits = useMemo(() => {
    if (!needle) return null;
    const keys = new Set<string>();
    for (const t of tactics)
      for (const c of buildCells(t, deep))
        if (c.id.toLowerCase().includes(needle) || c.rules.some((r) => r.title.toLowerCase().includes(needle) || r.id.toLowerCase().includes(needle))) keys.add(c.key);
    return keys;
  }, [tactics, needle, deep]);

  const closeDrawer = useCallback(() => {
    setSel(null);
    lastCell.current?.focus();
  }, []);

  const stats = useMemo(() => {
    if (!data) return null;
    const mapped = new Set(data.tactics.flatMap((t) => t.techniques.flatMap((x) => x.rules.map((r) => r.id))));
    return { mapped: mapped.size, total: mapped.size + data.unmapped.length };
  }, [data]);

  const drawerTactics = sel && data ? data.tactics.filter((t) => t.techniques.some((x) => x.id === sel.id || x.id.startsWith(`${sel.id}.`))).map((t) => t.name) : [];

  return (
    <div className="mx-auto max-w-[1600px] px-4 py-8 sm:px-8">
      <PageHeader
        title={t("mitre_att_ck_coverage")}
        subtitle={t("techniques_cited_by_your_rules_grouped")}
        actions={
          <a href="/api/coverage/navigator" download="vitrix-attack-layer.json" className={btnSecondary}>
            <Download size={15} aria-hidden /> {t("cv_navigator")}
          </a>
        }
      />
      {error && (
        <div className="space-y-3">
          <ErrorBox message={(error as Error).message} />
          <button type="button" className={btnSecondary} onClick={() => refetch()}>
            {t("retry")}
          </button>
        </div>
      )}
      {isLoading && <Skeleton />}
      {data && stats && (
        <>
          <div className="mb-5 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
            <StatTile
              label={t("tactics_covered")}
              value={`${data.covered}/${data.total}`}
              sub={t("cv_pct", { p: pct(data.covered, data.total) })}
              status={data.covered / data.total >= 0.7 ? "ok" : data.covered / data.total >= 0.4 ? "warn" : "fail"}
            />
            <StatTile label={t("techniques")} value={data.techniques} sub={t("distinct_techniques_and_sub_techniques")} />
            <StatTile label={t("rules_mapped")} value={t("cv_x_of_y", { a: stats.mapped, b: stats.total })} sub={t("cv_have_tech", { p: pct(stats.mapped, stats.total) })} />
            <div className="relative">
              <StatTile
                label={t("rules_without_a_technique")}
                value={data.unmapped.length}
                sub={data.unmapped.length ? t("cv_missing") : t("l_all_mapped")}
                status={data.unmapped.length ? "warn" : "ok"}
              />
              {data.unmapped.length > 0 && (
                <button
                  type="button"
                  onClick={() => unmappedRef.current?.scrollIntoView({ behavior: "smooth", block: "start" })}
                  className="absolute right-4 top-4 text-xs font-medium text-accent hover:underline"
                >
                  View
                </button>
              )}
            </div>
          </div>

          {data.techniques === 0 && data.unmapped.length === 0 ? (
            <Card className="flex flex-col items-center gap-3 p-10 text-center">
              <Grid3x3 size={28} className="text-subtle" aria-hidden />
              <p className="max-w-md text-sm text-muted">
                No rules yet. Coverage is built from the ATT&amp;CK tags of your rules (<span className="font-mono">attack.t1059.001</span>).
              </p>
              <Link to="/editor" className={btnPrimary}>
                {t("create_a_rule")}
              </Link>
            </Card>
          ) : (
            <>
              <div className="mb-3 flex flex-wrap items-end gap-x-4 gap-y-3">
                <label className="relative">
                  <span className="sr-only">{t("search_technique_or_rule_press_to_focu")}</span>
                  <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-subtle" aria-hidden />
                  <input
                    ref={searchRef}
                    value={q}
                    onChange={(e) => set({ q: e.target.value })}
                    placeholder={t("search_technique_or_rule")}
                    className={clsx(inputCls, "w-72 max-w-full pl-9")}
                  />
                </label>
                <label className="flex items-center gap-2 text-[13px] text-muted">
                  {t("tactic")}
                  <select value={tactic} onChange={(e) => set({ tactic: e.target.value })} className="rounded-[10px] border border-line bg-surface px-2.5 py-2 text-[13px] text-text">
                    <option value="">{t("all")}</option>
                    {data.tactics.map((t) => (
                      <option key={t.slug} value={t.slug}>
                        {t.name}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="flex items-center gap-2 text-[13px] text-muted">
                  <input type="checkbox" checked={showEmpty} onChange={(e) => set({ empty: e.target.checked ? "1" : "" })} className="accent-accent" /> {t("show_empty_tactics")}
                </label>
                <button type="button" disabled aria-disabled title={GAPS_HINT} aria-describedby="gaps-hint" className="cursor-not-allowed rounded-[10px] border border-line px-3 py-1.5 text-[13px] text-subtle opacity-60">
                  {t("gaps")}
                </button>
                <div role="group" aria-label={t("depth")} className="flex items-center gap-1 rounded-[10px] border border-line bg-surface p-1">
                  <span className="px-2 text-[13px] text-muted">{t("depth")}</span>
                  {(
                    [
                      [false, t("l_techniques")],
                      [true, "+Sub"],
                    ] as const
                  ).map(([v, label]) => (
                    <button key={label} type="button" aria-pressed={deep === v} onClick={() => set({ depth: v ? "sub" : "" })} className={clsx("rounded-md px-3 py-1 text-[13px]", deep === v ? "bg-accent-soft font-medium text-strong" : "text-muted hover:text-text")}>
                      {label}
                    </button>
                  ))}
                </div>
              </div>
              <p id="gaps-hint" className="mb-3 text-xs text-subtle">
                {GAPS_HINT}
              </p>

              <div className="mb-3 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted" aria-label={t("legend_rules_per_technique")}>
                <span>{t("rules_per_technique")}</span>
                {LEGEND.map((l) => (
                  <span key={l.step} className="inline-flex items-center gap-1.5">
                    <span className={clsx("inline-block size-4 rounded border border-line", HEAT_CLASS[l.step])} aria-hidden />
                    {l.text}
                  </span>
                ))}
              </div>

              {data.techniques === 0 ? (
                <Card className="p-6 text-sm text-muted">
                  <p className="flex items-center gap-2">
                    <AlertTriangle size={15} className="text-warn" aria-hidden /> {t("none_of_your")} {data.unmapped.length} rules has an ATT&amp;CK technique tag. See the list below.
                  </p>
                </Card>
              ) : hits && hits.size === 0 ? (
                <Card className="flex flex-wrap items-center gap-3 p-6 text-sm text-muted">
                  {t("no_technique_matches")}{q}”.
                  <button type="button" className="font-medium text-accent hover:underline" onClick={() => setParams({}, { replace: true })}>
                    {t("clear_filters")}
                  </button>
                </Card>
              ) : (
                <Card className="p-3 md:overflow-x-auto">
                  <AttackMatrix
                    tactics={tactics}
                    deep={deep}
                    hits={hits}
                    selected={sel?.key ?? null}
                    onSelect={(cell, el) => {
                      lastCell.current = el;
                      setSel(cell);
                    }}
                  />
                </Card>
              )}
            </>
          )}

          <div className="mt-5 grid gap-5 lg:grid-cols-2">
            <Section title={t("data_sources")} aside={t("cv_logsource_each")}>
              <ul className="divide-y divide-line">
                {data.logsources.map((g) => (
                  <li key={g.logsource} className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1 py-2.5 text-[13px]">
                    <span className="font-mono text-text">{g.logsource}</span>
                    <span className="text-xs text-muted tabular-nums">
                      {tn("n_rules", g.rules)} · {tn("n_techniques", g.techniques.length)}
                    </span>
                    {g.techniques.length > 0 && <span className="w-full font-mono text-[11.5px] text-subtle">{g.techniques.join(", ")}</span>}
                  </li>
                ))}
                {data.logsources.length === 0 && <li className="py-2 text-sm text-subtle">{t("no_rules")}</li>}
              </ul>
              <p className="mt-3 text-xs text-subtle">{t("a_data_source_that_stops_sending_logs_")}</p>
            </Section>

            <div ref={unmappedRef}>
              {data.unmapped.length > 0 && (
                <Section title={t("rules_without_an_att_ck_technique")}>
                  <ul className="space-y-1 text-[13px]">
                    {data.unmapped.map((r) => (
                      <li key={r.id}>
                        <Link to={`/editor/${r.id}`} className="text-text hover:text-accent">
                          {r.title || r.id}
                        </Link>
                        <span className="ml-2 font-mono text-[11.5px] text-subtle">{r.id}</span>
                      </li>
                    ))}
                  </ul>
                </Section>
              )}
            </div>
          </div>
        </>
      )}
      {sel && <TechniqueDrawer cell={sel} tactics={drawerTactics} onClose={closeDrawer} />}
    </div>
  );
}
