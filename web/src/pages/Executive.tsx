import { useQuery } from "@tanstack/react-query";
import { api } from "../api";
import { BarList, ConnectorNotice, Section, StatTile, StateBar, formatHours, pct } from "../components/dash";
import { ErrorBox, PageHeader, TargetSwatch } from "../components/ui";
import type { State } from "../types";

const LEVELS: [string, string][] = [
  ["critical", "Crítica"],
  ["high", "Alta"],
  ["medium", "Média"],
  ["low", "Baixa"],
  ["informational", "Info"],
];
const STATUSES = ["stable", "test", "experimental", "deprecated", "unsupported"];
const TARGET_CODE: Record<string, string> = { splunk: "SPL", kql: "KQL", "elastic-eql": "EQL", "elastic-lucene": "LUCENE" };

/** Meta simples para colorir o ícone do indicador: verde a partir de `good`, amarelo a partir de `warn`. */
const level = (value: number, good: number, warn: number): State => (value >= good ? "ok" : value >= warn ? "warn" : "fail");

export default function ExecutivePage() {
  const stats = useQuery({ queryKey: ["stats"], queryFn: api.stats });
  const activity = useQuery({ queryKey: ["activity"], queryFn: () => api.activity() });
  const targets = useQuery({ queryKey: ["targets"], queryFn: api.targets });

  const s = stats.data;
  const act = activity.data;
  const labels = Object.fromEntries((targets.data ?? []).map((t) => [t.name, t.label]));

  if (stats.error) {
    return (
      <div className="p-8">
        <ErrorBox message={(stats.error as Error).message} />
      </div>
    );
  }

  const ready = s ? pct(s.pipeline.validation.ok + s.pipeline.validation.warn, s.rules.total) : 0;
  const testPct = s ? pct(s.tests.passed, s.tests.total) : 0;
  const tested = s ? pct(s.rules.total - s.tests.rules_without_cases, s.rules.total) : 0;

  return (
    <div className="mx-auto max-w-7xl px-4 py-8 sm:px-8">
      <PageHeader
        title="Executivo"
        subtitle="Cobertura de ameaças, qualidade do acervo de detecções e ritmo de entrega. Números derivados do repositório e, quando conectado, do GitHub."
      />
      {!s && <p className="text-sm text-muted">Lendo o repositório…</p>}

      {s && (
        <>
          <div className="mb-5 grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
            <StatTile
              label="Cobertura ATT&CK"
              value={`${s.mitre.coverage_pct}%`}
              sub={`${s.mitre.covered} de ${s.mitre.total} táticas · ${s.mitre.techniques} técnicas`}
              status={level(s.mitre.coverage_pct, 70, 40)}
            />
            <StatTile
              label="Regras publicáveis"
              value={`${ready}%`}
              sub={`${s.pipeline.validation.ok + s.pipeline.validation.warn} de ${s.rules.total} sem reprovação`}
              status={level(ready, 95, 80)}
            />
            <StatTile
              label="Testes aprovados"
              value={s.tests.total ? `${testPct}%` : "—"}
              sub={s.tests.total ? `${s.tests.passed}/${s.tests.total} casos · ${tested}% das regras com casos` : "nenhum caso de teste"}
              status={s.tests.total ? level(Math.min(testPct, tested), 100, 90) : "fail"}
            />
            <StatTile
              label="Tempo até o merge"
              value={act?.available ? formatHours(act.merge.median_hours) : "—"}
              sub={act?.available ? (act.merge.sample ? `mediana de ${act.merge.sample} PRs · p90 ${formatHours(act.merge.p90_hours)}` : "nenhum PR mesclado") : "requer conexão com o GitHub"}
              source={act?.available ? "GitHub" : undefined}
            />
          </div>

          <div className="grid gap-5 lg:grid-cols-2">
            <Section title="Saúde do acervo" aside={`${s.rules.total} regras`}>
              <StateBar counts={s.pipeline.validation} />
              <dl className="mt-5 grid grid-cols-2 gap-x-6 gap-y-2 text-[13px]">
                <dt className="text-muted">Erros de lint</dt>
                <dd className="text-right font-semibold text-strong tabular-nums">{s.lint.errors}</dd>
                <dt className="text-muted">Avisos de lint</dt>
                <dd className="text-right font-semibold text-strong tabular-nums">{s.lint.warnings}</dd>
                <dt className="text-muted">Falhas de conversão</dt>
                <dd className="text-right font-semibold text-strong tabular-nums">{s.conversion_failures}</dd>
                <dt className="text-muted">Regras sem casos de teste</dt>
                <dd className="text-right font-semibold text-strong tabular-nums">{s.tests.rules_without_cases}</dd>
              </dl>
            </Section>

            <Section title="Entrega" aside={act?.available ? act.repo.name : undefined}>
              <ConnectorNotice activity={act} />
              {act?.available && (
                <dl className="grid grid-cols-2 gap-x-6 gap-y-2 text-[13px]">
                  <dt className="text-muted">CI aprovado (últimas execuções)</dt>
                  <dd className="text-right font-semibold text-strong tabular-nums">{act.ci.success_rate === null ? "—" : `${act.ci.success_rate}% de ${act.ci.sample}`}</dd>
                  <dt className="text-muted">PRs abertos</dt>
                  <dd className="text-right font-semibold text-strong tabular-nums">{act.pulls.open}</dd>
                  <dt className="text-muted">PRs com CI reprovado</dt>
                  <dd className="text-right font-semibold text-strong tabular-nums">{act.pulls.failing}</dd>
                  <dt className="text-muted">PRs abertos pela interface</dt>
                  <dd className="text-right font-semibold text-strong tabular-nums">{act.pulls.from_vitrix}</dd>
                  <dt className="text-muted">Mediana até o merge</dt>
                  <dd className="text-right font-semibold text-strong tabular-nums">{formatHours(act.merge.median_hours)}</dd>
                  <dt className="text-muted">p90 até o merge</dt>
                  <dd className="text-right font-semibold text-strong tabular-nums">{formatHours(act.merge.p90_hours)}</dd>
                </dl>
              )}
            </Section>

            <Section title="Regras por severidade">
              <BarList rows={LEVELS.filter(([k]) => s.rules.by_level[k]).map(([k, label]) => ({ key: k, label, code: k, value: s.rules.by_level[k] }))} empty="Nenhuma regra com level." />
            </Section>

            <Section title="Regras por maturidade (status)">
              <BarList
                rows={[...STATUSES, ...Object.keys(s.rules.by_status).filter((k) => !STATUSES.includes(k))]
                  .filter((k) => s.rules.by_status[k])
                  .map((k) => ({ key: k, label: k, value: s.rules.by_status[k] }))}
              />
            </Section>

            <Section title="Regras por linguagem final">
              <BarList
                rows={Object.entries(s.by_target)
                  .sort((a, b) => b[1] - a[1])
                  .map(([name, n]) => ({
                    key: name,
                    label: (
                      <span className="flex items-center gap-2">
                        <TargetSwatch target={name} />
                        {labels[name] ?? name}
                      </span>
                    ),
                    code: TARGET_CODE[name],
                    value: n,
                    title: `${labels[name] ?? name}: ${n} regras`,
                  }))}
              />
            </Section>

            <Section title="Lacunas de cobertura" aside={`${s.mitre.uncovered.length} táticas sem regra`}>
              {s.mitre.uncovered.length === 0 ? (
                <p className="text-sm text-muted">Todas as táticas do ATT&amp;CK têm ao menos uma regra.</p>
              ) : (
                <ul className="flex flex-wrap gap-2">
                  {s.mitre.tactics
                    .filter((t) => t.count === 0)
                    .map((t) => (
                      <li key={t.slug} className="rounded-md bg-surface-2 px-2 py-1 text-[12.5px] text-text">
                        <span className="mr-1.5 font-mono text-[11.5px] text-subtle">{t.id}</span>
                        {t.name}
                      </li>
                    ))}
                </ul>
              )}
            </Section>
          </div>
        </>
      )}
    </div>
  );
}
