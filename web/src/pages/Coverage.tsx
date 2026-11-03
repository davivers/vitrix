import { useQuery } from "@tanstack/react-query";
import clsx from "clsx";
import { Link } from "react-router-dom";
import { api } from "../api";
import { StatTile, pct } from "../components/dash";
import { Card, ErrorBox, PageHeader } from "../components/ui";
import type { CoverageTactic } from "../types";

/** Intensidade de uma célula: um tom (violeta) do claro ao forte conforme o nº de regras. */
function heat(n: number, max: number): string {
  if (n === 0) return "bg-surface";
  const r = n / Math.max(1, max);
  return r > 0.66 ? "bg-accent/45" : r > 0.33 ? "bg-accent/30" : "bg-accent/18";
}

function Column({ t, max }: { t: CoverageTactic; max: number }) {
  return (
    <div className="flex w-44 shrink-0 flex-col gap-1.5">
      <div className={clsx("rounded-[10px] border border-line px-2.5 py-2", heat(t.rules, max))} title={`${t.id} ${t.name}: ${t.rules} regras`}>
        <span className="block font-mono text-[10.5px] text-subtle">{t.id}</span>
        <span className="block text-[12.5px] font-semibold leading-tight text-strong">{t.name}</span>
        <span className="mt-1 block text-[11.5px] text-muted tabular-nums">
          {t.rules} {t.rules === 1 ? "regra" : "regras"} · {t.techniques.length} técn.
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
      {t.techniques.length === 0 && <div className="rounded-lg border border-dashed border-line px-2.5 py-3 text-center text-[11.5px] text-subtle">sem cobertura</div>}
    </div>
  );
}

export default function CoveragePage() {
  const { data, error } = useQuery({ queryKey: ["coverage"], queryFn: api.coverage });
  const max = Math.max(1, ...(data?.tactics ?? []).map((t) => t.rules));
  return (
    <div className="mx-auto max-w-[1600px] px-4 py-8 sm:px-8">
      <PageHeader
        title="Cobertura MITRE ATT&CK"
        subtitle="Matriz Enterprise: táticas na ordem do ATT&CK, técnicas citadas nas tags das regras (attack.tXXXX) e as regras de cada uma."
      />
      {error && <ErrorBox message={(error as Error).message} />}
      {data && (
        <>
          <div className="mb-5 grid gap-4 sm:grid-cols-3">
            <StatTile label="Táticas cobertas" value={`${data.covered}/${data.total}`} sub={`${pct(data.covered, data.total)}% da matriz`} status={data.covered / data.total >= 0.7 ? "ok" : data.covered / data.total >= 0.4 ? "warn" : "fail"} />
            <StatTile label="Técnicas" value={data.techniques} sub="técnicas e subtécnicas distintas" />
            <StatTile
              label="Regras sem técnica"
              value={data.unmapped.length}
              sub={data.unmapped.length ? "não aparecem na matriz" : "todas mapeadas"}
              status={data.unmapped.length ? "warn" : "ok"}
            />
          </div>
          <Card className="overflow-x-auto p-4">
            <div className="flex gap-2">
              {data.tactics.map((t) => (
                <Column key={t.slug} t={t} max={max} />
              ))}
            </div>
          </Card>
          <p className="mt-3 text-xs text-subtle">Intensidade do violeta = número de regras na tática (cor de série única; o número está sempre escrito na célula).</p>
          {data.unmapped.length > 0 && (
            <Card className="mt-5 p-4">
              <h2 className="mb-2 text-[15px] font-semibold text-strong">Regras sem técnica ATT&amp;CK</h2>
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
            </Card>
          )}
        </>
      )}
    </div>
  );
}
