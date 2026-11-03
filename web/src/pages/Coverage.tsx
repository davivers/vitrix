import { useQuery } from "@tanstack/react-query";
import clsx from "clsx";
import { Download } from "lucide-react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { ColumnChart, DonutChart, OTHER_COLOR, SERIES_COLORS, topSlices } from "../components/charts";
import { Section, StatTile, pct } from "../components/dash";
import { Card, ErrorBox, PageHeader, btnSecondary } from "../components/ui";
import type { CoverageTactic } from "../types";

const ABBR: Record<string, string> = {
  reconnaissance: "Recon",
  resource_development: "ResDev",
  initial_access: "Initial",
  execution: "Exec",
  persistence: "Persist",
  privilege_escalation: "PrivEsc",
  defense_evasion: "Evasion",
  credential_access: "Creds",
  discovery: "Discov",
  lateral_movement: "Lateral",
  collection: "Collect",
  command_and_control: "C2",
  exfiltration: "Exfil",
  impact: "Impact",
};

/** Cell intensity: one hue (violet), light to strong by rule count. The number is always written. */
function heat(n: number, max: number): string {
  if (n === 0) return "bg-surface";
  const r = n / Math.max(1, max);
  return r > 0.66 ? "bg-accent/45" : r > 0.33 ? "bg-accent/30" : "bg-accent/18";
}

function Column({ t, max }: { t: CoverageTactic; max: number }) {
  return (
    <div className="flex w-44 shrink-0 flex-col gap-1.5">
      <div className={clsx("rounded-[10px] border border-line px-2.5 py-2", heat(t.rules, max))} title={`${t.id} ${t.name}: ${t.rules} rules`}>
        <span className="block font-mono text-[10.5px] text-subtle">{t.id}</span>
        <span className="block text-[12.5px] font-semibold leading-tight text-strong">{t.name}</span>
        <span className="mt-1 block text-[11.5px] text-muted tabular-nums">
          {t.rules} {t.rules === 1 ? "rule" : "rules"} · {t.techniques.length} tech.
        </span>
      </div>
      {t.techniques.map((tech) => (
        <div key={tech.id} className="rounded-lg border border-line bg-surface-2 px-2.5 py-1.5">
          <span className="flex items-center justify-between gap-2">
            <a
              href={tech.id.startsWith("T") ? `https://attack.mitre.org/techniques/${tech.id.replace(".", "/")}/` : undefined}
              target="_blank"
              rel="noreferrer"
              className="font-mono text-[11.5px] font-semibold text-text hover:text-accent"
            >
              {tech.id}
            </a>
            <span className="text-[11px] text-subtle tabular-nums">{tech.rules.length}</span>
          </span>
          <ul className="mt-1 space-y-0.5">
            {tech.rules.map((r) => (
              <li key={r.id}>
                <Link to={`/editor/${r.id}`} className="block truncate text-[11.5px] text-muted hover:text-accent" title={r.title}>
                  {r.title || r.id}
                </Link>
              </li>
            ))}
          </ul>
        </div>
      ))}
      {t.techniques.length === 0 && <div className="rounded-lg border border-dashed border-line px-2.5 py-3 text-center text-[11.5px] text-subtle">no coverage</div>}
    </div>
  );
}

export default function CoveragePage() {
  const { data, error } = useQuery({ queryKey: ["coverage"], queryFn: api.coverage });
  const max = Math.max(1, ...(data?.tactics ?? []).map((t) => t.rules));
  return (
    <div className="mx-auto max-w-[1600px] px-4 py-8 sm:px-8">
      <PageHeader
        title="MITRE ATT&CK coverage"
        subtitle="Enterprise matrix: tactics in ATT&CK order, the techniques cited in rule tags (attack.tXXXX) and the rules behind each one."
        actions={
          <a href="/api/coverage/navigator" download="vitrix-attack-layer.json" className={btnSecondary}>
            <Download size={15} aria-hidden /> ATT&amp;CK Navigator layer
          </a>
        }
      />
      {error && <ErrorBox message={(error as Error).message} />}
      {data && (
        <>
          <div className="mb-5 grid gap-4 sm:grid-cols-3">
            <StatTile
              label="Tactics covered"
              value={`${data.covered}/${data.total}`}
              sub={`${pct(data.covered, data.total)}% of the matrix`}
              status={data.covered / data.total >= 0.7 ? "ok" : data.covered / data.total >= 0.4 ? "warn" : "fail"}
            />
            <StatTile label="Techniques" value={data.techniques} sub="distinct techniques and sub-techniques" />
            <StatTile
              label="Rules without a technique"
              value={data.unmapped.length}
              sub={data.unmapped.length ? "missing from the matrix" : "all mapped"}
              status={data.unmapped.length ? "warn" : "ok"}
            />
          </div>
          <div className="mb-5 grid gap-5 lg:grid-cols-2">
            <Section title="Rules per tactic" aside="ATT&CK order">
              <ColumnChart
                ariaLabel="Number of rules per ATT&CK tactic"
                unit=" rules"
                columns={data.tactics.map((t) => ({ key: t.slug, label: ABBR[t.slug] ?? t.id, title: `${t.id} ${t.name}`, value: t.rules, note: `${t.techniques.length} technique(s)` }))}
              />
              <p className="mt-2 text-xs text-subtle">Hover a column for the full tactic name and id.</p>
            </Section>
            <Section title="Techniques per tactic" aside="distinct techniques cited">
              <ColumnChart
                ariaLabel="Number of distinct techniques per ATT&CK tactic"
                unit=" techniques"
                columns={data.tactics.map((t) => ({ key: t.slug, label: ABBR[t.slug] ?? t.id, title: `${t.id} ${t.name}`, value: t.techniques.filter((x) => x.id !== "—").length }))}
              />
            </Section>
          </div>

          <div className="mb-5 grid gap-5 xl:grid-cols-3">
            <Section title="Tactic coverage" aside="tactics with at least one rule">
              <DonutChart
                ariaLabel="Tactics covered versus tactics without a rule"
                centerValue={`${data.covered}/${data.total}`}
                centerLabel="tactics covered"
                unit=" tactics"
                slices={[
                  { key: "covered", label: "Covered", value: data.covered, color: SERIES_COLORS[0] },
                  { key: "gap", label: "No rule yet", value: data.total - data.covered, color: OTHER_COLOR },
                ]}
              />
            </Section>
            <Section title="Rules by tactic" aside="top 5 + other">
              <DonutChart
                ariaLabel="Share of rules by ATT&CK tactic"
                centerValue={data.tactics.reduce((n, t) => n + t.rules, 0)}
                centerLabel="rule–tactic links"
                slices={topSlices(data.tactics.filter((t) => t.rules > 0).map((t) => [t.name, t.rules]))}
              />
            </Section>
            <Section title="Rules by data source" aside="top 5 + other">
              <DonutChart
                ariaLabel="Share of rules by data source"
                centerValue={data.logsources.reduce((n, g) => n + g.rules, 0)}
                centerLabel="rules"
                slices={topSlices(data.logsources.map((g) => [g.logsource, g.rules]))}
              />
            </Section>
          </div>

          <Card className="overflow-x-auto p-4">
            <div className="flex gap-2">
              {data.tactics.map((t) => (
                <Column key={t.slug} t={t} max={max} />
              ))}
            </div>
          </Card>
          <p className="mt-3 text-xs text-subtle">Violet intensity = number of rules in the tactic (a single series colour; the number is always written in the cell).</p>

          <div className="mt-5 grid gap-5 lg:grid-cols-2">
            <Section title="Data sources" aside="logsource of each rule">
              <ul className="divide-y divide-line">
                {data.logsources.map((g) => (
                  <li key={g.logsource} className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1 py-2.5 text-[13px]">
                    <span className="font-mono text-text">{g.logsource}</span>
                    <span className="text-xs text-muted tabular-nums">
                      {g.rules} {g.rules === 1 ? "rule" : "rules"} · {g.techniques.length} technique(s)
                    </span>
                    {g.techniques.length > 0 && <span className="w-full font-mono text-[11.5px] text-subtle">{g.techniques.join(", ")}</span>}
                  </li>
                ))}
                {data.logsources.length === 0 && <li className="py-2 text-sm text-subtle">No rules.</li>}
              </ul>
              <p className="mt-3 text-xs text-subtle">A data source that stops sending logs silently disables every rule listed here.</p>
            </Section>

            {data.unmapped.length > 0 && (
              <Section title="Rules without an ATT&CK technique">
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
        </>
      )}
    </div>
  );
}
