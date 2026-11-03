import { useQuery } from "@tanstack/react-query";
import clsx from "clsx";
import { AlertTriangle, CheckCircle2, ExternalLink, GitCommitHorizontal, GitPullRequest, Plus, RefreshCw, XCircle } from "lucide-react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { BarList, ConnectorNotice, RunBadge, Section, formatDuration, formatHours, pct, safeHref, timeAgo } from "../components/dash";
import { Card, ErrorBox, PageHeader } from "../components/ui";
import type { Activity, RuleSummary, Stats } from "../types";
import { FlowFunnel } from "./QualityGate";

/** Uma etapa do pipeline: número principal + linha de detalhe com ícone de status. */
function Stage({ label, value, detail, ok }: { label: string; value: string; detail: string; ok: boolean | null }) {
  const Icon = ok === null ? null : ok ? CheckCircle2 : XCircle;
  return (
    <div className="flex min-w-0 flex-col gap-1 px-4 py-3">
      <span className="text-[11px] font-semibold uppercase tracking-wider text-subtle">{label}</span>
      <span className="text-[22px] font-bold leading-tight text-strong tabular-nums">{value}</span>
      <span className="flex items-center gap-1.5 text-[12px] text-muted">
        {Icon && <Icon size={13} className={clsx("shrink-0", ok ? "text-good" : "text-bad")} aria-hidden />}
        <span className="truncate">{detail}</span>
      </span>
    </div>
  );
}

function Pipeline({ stats, activity }: { stats: Stats; activity: Activity | undefined }) {
  const { pipeline, tests } = stats;
  const total = stats.rules.total;
  const pulls = activity?.available ? activity.pulls : null;
  return (
    <Card className="mb-5">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-line px-4 py-3">
        <h2 className="text-[15px] font-semibold text-strong">Pipeline de validação</h2>
        <span className="flex items-center gap-1.5 text-xs text-subtle">
          {activity?.available ? (
            <>
              <GitCommitHorizontal size={14} aria-hidden />
              <a href={safeHref(activity.head.url)} target="_blank" rel="noreferrer" className="font-mono hover:text-text">
                {activity.head.sha.slice(0, 7)}
              </a>
              · {activity.repo.base} · {timeAgo(activity.head.date)}
            </>
          ) : (
            "repositório local"
          )}
        </span>
      </div>
      <div className="grid grid-cols-2 divide-line sm:grid-cols-3 lg:grid-cols-5 lg:divide-x">
        <Stage
          label="Parse"
          value={String(pipeline.parse.ok)}
          detail={pipeline.parse.failed ? `${pipeline.parse.failed} com YAML inválido` : "YAML sem erros de sintaxe"}
          ok={pipeline.parse.failed === 0}
        />
        <Stage
          label="Validação"
          value={`${pipeline.validation.ok} aprovadas`}
          detail={`${pipeline.validation.warn} com avisos · ${pipeline.validation.fail} reprovadas`}
          ok={pipeline.validation.fail === 0}
        />
        <Stage
          label="Conversão"
          value={`${pipeline.conversion.ok}/${total}`}
          detail={pipeline.conversion.failed ? `${pipeline.conversion.failed} falhas de conversão` : "linguagem final ok"}
          ok={pipeline.conversion.failed === 0}
        />
        <Stage
          label="Testes"
          value={`${tests.passed}/${tests.total}`}
          detail={tests.total - tests.passed ? `${tests.total - tests.passed} casos reprovados` : `${tests.rules_without_cases} regras sem casos`}
          ok={tests.total === tests.passed && tests.rules_without_cases === 0}
        />
        <Stage
          label="Pull requests"
          value={pulls ? `${pulls.open} abertos` : "—"}
          detail={pulls ? (pulls.failing ? `${pulls.failing} com CI reprovado` : "nenhum com CI reprovado") : "sem conexão com o GitHub"}
          ok={pulls ? pulls.failing === 0 : null}
        />
      </div>
    </Card>
  );
}

function Pending({ rules }: { rules: RuleSummary[] }) {
  const items = rules.filter((r) => r.state !== "ok").sort((a, b) => (a.state === b.state ? a.id.localeCompare(b.id) : a.state === "fail" ? -1 : 1));
  return (
    <Section title="Pendências de qualidade" aside={`${items.length} ${items.length === 1 ? "regra" : "regras"}`}>
      {items.length === 0 ? (
        <p className="flex items-center gap-2 text-sm text-muted">
          <CheckCircle2 size={16} className="text-good" aria-hidden /> Nenhuma pendência: todas as regras passam no lint, na conversão e nos testes.
        </p>
      ) : (
        <ul className="-mx-2 divide-y divide-line">
          {items.map((r) => {
            const fail = r.state === "fail";
            return (
              <li key={r.id}>
                <Link to={`/editor/${r.id}`} className="flex gap-3 rounded-lg px-2 py-2.5 hover:bg-surface">
                  <span className={clsx("mt-0.5 inline-flex h-fit shrink-0 items-center gap-1 rounded-full px-2 py-0.5 text-xs font-semibold", fail ? "bg-bad-soft text-bad" : "bg-warn-soft text-warn")}>
                    {fail ? <XCircle size={12} aria-hidden /> : <AlertTriangle size={12} aria-hidden />}
                    {fail ? "Reprovada" : "Aviso"}
                  </span>
                  <span className="min-w-0">
                    <span className="block truncate text-[13.5px] font-semibold text-strong">{r.title || r.id}</span>
                    <span className="block text-[12.5px] text-muted [overflow-wrap:anywhere]">{r.issues[0]?.message ?? "—"}</span>
                    <span className="block font-mono text-[11.5px] text-subtle">{r.file}</span>
                  </span>
                </Link>
              </li>
            );
          })}
        </ul>
      )}
    </Section>
  );
}

function CiRuns({ activity }: { activity: Activity | undefined }) {
  return (
    <Section title="Execuções do CI" aside={activity?.available && activity.ci.success_rate !== null ? `${activity.ci.success_rate}% aprovadas (${activity.ci.sample})` : undefined}>
      <ConnectorNotice activity={activity} />
      {activity?.available &&
        (activity.ci.runs.length === 0 ? (
          <p className="text-sm text-subtle">Nenhuma execução de CI em {activity.repo.base}.</p>
        ) : (
          <ul className="-mx-2 divide-y divide-line">
            {activity.ci.runs.slice(0, 8).map((run) => (
              <li key={run.id}>
                <a href={safeHref(run.url)} target="_blank" rel="noreferrer" className="flex items-center gap-3 rounded-lg px-2 py-2 text-[13px] hover:bg-surface">
                  <RunBadge state={run.state} />
                  <span className="min-w-0 flex-1 truncate text-text">
                    #{run.number} · {run.title || run.name}
                  </span>
                  <span className="hidden font-mono text-xs text-subtle sm:inline">{run.sha}</span>
                  <span className="w-20 text-right text-xs text-subtle">{formatDuration(run.duration_s)}</span>
                  <span className="w-24 text-right text-xs text-subtle">{timeAgo(run.created_at)}</span>
                </a>
              </li>
            ))}
          </ul>
        ))}
    </Section>
  );
}

function OpenPulls({ activity }: { activity: Activity | undefined }) {
  return (
    <Section
      title="Pull requests abertos"
      aside={activity?.available && activity.merge.median_hours !== null ? `mediana até o merge: ${formatHours(activity.merge.median_hours)}` : undefined}
    >
      <ConnectorNotice activity={activity} />
      {activity?.available &&
        (activity.pulls.items.length === 0 ? (
          <p className="text-sm text-subtle">Nenhum PR aberto contra {activity.repo.base}.</p>
        ) : (
          <ul className="-mx-2 divide-y divide-line">
            {activity.pulls.items.map((pr) => (
              <li key={pr.number}>
                <a href={safeHref(pr.url)} target="_blank" rel="noreferrer" className="flex items-center gap-3 rounded-lg px-2 py-2 text-[13px] hover:bg-surface">
                  <GitPullRequest size={15} className="shrink-0 text-subtle" aria-hidden />
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-text">
                      #{pr.number} {pr.title}
                      {pr.draft && <span className="ml-2 rounded bg-surface-2 px-1.5 py-0.5 text-[10px] uppercase text-subtle">rascunho</span>}
                    </span>
                    <span className="block text-xs text-subtle">
                      {pr.author ?? "—"} · aberto há {formatHours(pr.age_hours)}
                      {pr.from_vitrix && " · pela interface"}
                    </span>
                  </span>
                  <RunBadge state={pr.ci} />
                </a>
              </li>
            ))}
          </ul>
        ))}
    </Section>
  );
}

export default function DashboardPage() {
  const stats = useQuery({ queryKey: ["stats"], queryFn: api.stats });
  const rules = useQuery({ queryKey: ["rules"], queryFn: api.rules });
  const activity = useQuery({ queryKey: ["activity"], queryFn: () => api.activity() });
  const refresh = useQuery({ queryKey: ["activity-refresh"], queryFn: () => api.activity(true), enabled: false });
  const quality = useQuery({ queryKey: ["quality"], queryFn: api.quality });

  const act = refresh.data ?? activity.data;
  const error = stats.error ?? rules.error;
  const tactics = (stats.data?.mitre.tactics ?? []).filter((t) => t.count > 0);

  return (
    <div className="mx-auto max-w-7xl px-4 py-8 sm:px-8">
      <PageHeader
        title="Operacional"
        subtitle={
          act?.available
            ? `Integridade de ${act.repo.name}: validação, conversão, testes e cobertura ATT&CK no ${act.repo.base}.`
            : "Integridade do repositório local: validação, conversão, testes e cobertura ATT&CK."
        }
        actions={
          <div className="flex flex-wrap gap-2">
            {act?.available && (
              <button
                type="button"
                onClick={() => refresh.refetch()}
                className="inline-flex items-center gap-2 rounded-[10px] border border-line bg-surface-2 px-3 py-2 text-[13.5px] font-semibold text-text hover:bg-surface-3"
              >
                <RefreshCw size={15} className={refresh.isFetching ? "animate-spin" : undefined} aria-hidden /> Atualizar
              </button>
            )}
            <Link to="/editor" className="inline-flex items-center gap-2 rounded-[10px] bg-brand px-4 py-2 text-[13.5px] font-semibold text-strong hover:brightness-110">
              <Plus size={16} aria-hidden /> Nova regra
            </Link>
          </div>
        }
      />
      {error && <ErrorBox message={(error as Error).message} />}
      {stats.isLoading && <p className="text-sm text-muted">Lendo o repositório…</p>}

      {stats.data && <Pipeline stats={stats.data} activity={act} />}

      {quality.data && (
        <>
          <div className="mb-2 flex items-baseline justify-between gap-3 px-1">
            <h2 className="text-[15px] font-semibold text-strong">Fluxo até a publicação</h2>
            <Link to="/gate" className="text-xs font-medium text-accent hover:underline">
              {quality.data.summary.ready}/{quality.data.summary.total} prontas · ver Quality Gate
            </Link>
          </div>
          <FlowFunnel q={quality.data} />
        </>
      )}

      {stats.data && rules.data && (
        <div className="grid gap-5 lg:grid-cols-[3fr_2fr]">
          <Pending rules={rules.data} />
          <Section
            title="Cobertura MITRE ATT&CK"
            aside={`${stats.data.mitre.covered}/${stats.data.mitre.total} táticas · ${pct(stats.data.mitre.covered, stats.data.mitre.total)}%`}
          >
            <BarList
              rows={tactics.map((t) => ({ key: t.slug, code: t.id, label: t.name, value: t.count, title: `${t.id} ${t.name}: ${t.count} regras` }))}
              empty="Nenhuma regra com tag attack.<tática>."
            />
            {stats.data.mitre.uncovered.length > 0 && (
              <p className="mt-4 text-xs text-subtle">Sem cobertura: {stats.data.mitre.uncovered.join(", ")}.</p>
            )}
          </Section>
          <CiRuns activity={act} />
          <OpenPulls activity={act} />
        </div>
      )}
      {act?.available && (
        <p className="mt-5 flex items-center gap-1.5 text-xs text-subtle">
          <ExternalLink size={12} aria-hidden /> Dados do GitHub de {timeAgo(act.fetched_at)}; o restante vem do repositório local.
        </p>
      )}
    </div>
  );
}
