import { useQuery } from "@tanstack/react-query";
import clsx from "clsx";
import { CheckCircle2, ChevronDown, ShieldCheck, XCircle } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { Section, StatTile, pct } from "../components/dash";
import { CheckList, FlowStepper, QUESTIONS, STAGES, STAGE_META } from "../components/flow";
import { Card, ErrorBox, PageHeader } from "../components/ui";
import type { QualityReport, QualityRule, StageState } from "../types";

const GATE_LABELS: Record<string, string> = {
  min_positive: "Casos positivos mínimos",
  min_negative: "Casos negativos mínimos",
  false_positive_levels: "Exigem caso de falso positivo",
  require_filter_test: "Exclusão precisa de teste",
  require_mitre: "Técnica ATT&CK obrigatória",
  allow_warnings: "Avisos de lint permitidos",
  blocked_status: "Status que bloqueiam",
  require_replay: "Replay obrigatório",
};

function fmt(v: unknown): string {
  if (typeof v === "boolean") return v ? "sim" : "não";
  if (Array.isArray(v)) return v.length ? v.join(", ") : "—";
  return String(v);
}

export function FlowFunnel({ q }: { q: QualityReport }) {
  return (
    <Card className="mb-5 overflow-x-auto">
      <ol className="flex min-w-[760px] divide-x divide-line">
        {q.stages.map((s) => {
          const passed = (s.counts.ok ?? 0) + (s.counts.warn ?? 0) + (s.counts.pending ?? 0);
          const failed = s.counts.fail ?? 0;
          const meta = STAGES.find((x) => x.id === s.id)!;
          return (
            <li key={s.id} className="flex-1 px-4 py-3" title={meta.hint}>
              <span className="text-[11px] font-semibold uppercase tracking-wider text-subtle">{s.label}</span>
              <span className="mt-1 block text-[22px] font-bold leading-tight text-strong tabular-nums">
                {s.id === "deploy" ? (s.counts.pending ?? 0) : passed}
                <span className="text-sm font-medium text-subtle">/{q.summary.total}</span>
              </span>
              <span className="mt-0.5 flex items-center gap-1 text-xs text-muted">
                {s.id === "deploy" ? (
                  "prontas, aguardando merge"
                ) : failed ? (
                  <>
                    <XCircle size={12} className="text-bad" aria-hidden /> {failed} bloqueadas
                  </>
                ) : (s.counts.skip ?? 0) === q.summary.total ? (
                  "não se aplica"
                ) : (
                  <>
                    <CheckCircle2 size={12} className="text-good" aria-hidden /> sem bloqueio
                  </>
                )}
              </span>
            </li>
          );
        })}
      </ol>
    </Card>
  );
}

function RuleRow({ r }: { r: QualityRule }) {
  const [open, setOpen] = useState(!r.ready);
  return (
    <li className="border-b border-line last:border-0">
      <button type="button" onClick={() => setOpen(!open)} aria-expanded={open} className="flex w-full flex-wrap items-center gap-3 px-4 py-3 text-left hover:bg-surface">
        <span className={clsx("inline-flex shrink-0 items-center gap-1 rounded-full px-2 py-0.5 text-xs font-semibold", r.ready ? "bg-good-soft text-good" : "bg-bad-soft text-bad")}>
          {r.ready ? <CheckCircle2 size={12} aria-hidden /> : <XCircle size={12} aria-hidden />}
          {r.ready ? "Pronta" : "Bloqueada"}
        </span>
        <span className="min-w-[14rem] flex-1">
          <span className="block truncate text-[13.5px] font-semibold text-strong">{r.title || r.id}</span>
          <span className="block font-mono text-[11.5px] text-subtle">{r.id}</span>
        </span>
        <FlowStepper stages={r.stages} compact />
        <ChevronDown size={16} className={clsx("text-subtle transition-transform", open && "rotate-180")} aria-hidden />
      </button>
      {open && (
        <div className="grid gap-5 px-4 pb-4 md:grid-cols-[1fr_16rem]">
          <CheckList checks={r.checks} />
          <div className="space-y-2">
            <h3 className="text-[11px] font-semibold uppercase tracking-wider text-subtle">As cinco perguntas</h3>
            <ul className="space-y-1.5 text-[12.5px]">
              {Object.entries(QUESTIONS).map(([id, text]) => {
                const state = r.answers[id] as StageState;
                const { Icon, cls, label } = STAGE_META[state];
                return (
                  <li key={id} className="flex gap-2">
                    <Icon size={14} className={clsx("mt-0.5 shrink-0", cls)} aria-label={label} />
                    <span className="text-text">{text}</span>
                  </li>
                );
              })}
            </ul>
            <Link to={`/editor/${r.id}`} className="inline-block pt-1 text-xs font-medium text-accent hover:underline">
              Abrir no Editor
            </Link>
          </div>
        </div>
      )}
    </li>
  );
}

export default function QualityGatePage() {
  const { data: q, error, isLoading } = useQuery({ queryKey: ["quality"], queryFn: api.quality });
  const [filter, setFilter] = useState<"all" | "blocked" | "ready">("all");
  const rules = (q?.rules ?? []).filter((r) => filter === "all" || (filter === "ready") === r.ready);

  return (
    <div className="mx-auto max-w-7xl px-4 py-8 sm:px-8">
      <PageHeader
        title="Quality gate"
        subtitle="Escrever → Validar → Testar → Replay → Analisar → Quality gate → Deploy. Uma regra só é publicável quando todas as verificações bloqueantes passam."
      />
      {error && <ErrorBox message={(error as Error).message} />}
      {isLoading && <p className="text-sm text-muted">Rodando o fluxo em todas as regras…</p>}
      {q && (
        <>
          <div className="mb-5 grid gap-4 sm:grid-cols-3">
            <StatTile label="Prontas para publicar" value={`${q.summary.ready}/${q.summary.total}`} sub={`${pct(q.summary.ready, q.summary.total)}% do acervo`} status={q.summary.blocked ? "warn" : "ok"} />
            <StatTile label="Bloqueadas" value={q.summary.blocked} sub={q.summary.blocked ? "veja os bloqueios abaixo" : "nenhuma"} status={q.summary.blocked ? "fail" : "ok"} />
            <StatTile
              label="Datasets de replay"
              value={q.datasets.length}
              sub={q.datasets.length ? `${q.datasets.filter((d) => d.passed).length} sem regressão` : "nenhum em datasets/"}
              status={q.datasets.some((d) => !d.passed) ? "fail" : q.datasets.length ? "ok" : "none"}
            />
          </div>

          <FlowFunnel q={q} />

          <div className="grid gap-5 xl:grid-cols-[1fr_20rem]">
            <Card className="overflow-hidden">
              <div className="flex flex-wrap items-center justify-between gap-3 border-b border-line px-4 py-3">
                <h2 className="text-[15px] font-semibold text-strong">Regras</h2>
                <div className="flex gap-1 rounded-[10px] border border-line bg-surface p-1" role="group" aria-label="Filtrar">
                  {(
                    [
                      ["all", "Todas"],
                      ["blocked", "Bloqueadas"],
                      ["ready", "Prontas"],
                    ] as const
                  ).map(([k, label]) => (
                    <button
                      key={k}
                      type="button"
                      aria-pressed={filter === k}
                      onClick={() => setFilter(k)}
                      className={clsx("rounded-md px-3 py-1 text-[13px]", filter === k ? "bg-accent-soft font-medium text-strong" : "text-muted hover:text-text")}
                    >
                      {label}
                    </button>
                  ))}
                </div>
              </div>
              <ul>
                {rules.map((r) => (
                  <RuleRow key={r.id} r={r} />
                ))}
                {rules.length === 0 && <li className="px-4 py-8 text-center text-sm text-muted">Nenhuma regra neste filtro.</li>}
              </ul>
            </Card>

            <div className="flex flex-col gap-5">
              <Section title="Perguntas respondidas">
                <ul className="space-y-2.5 text-[13px]">
                  {q.questions.map((x) => (
                    <li key={x.id}>
                      <span className="text-text">
                        {x.id}. {x.text}
                      </span>
                      <span className="mt-0.5 flex gap-3 text-xs text-muted">
                        <span className="flex items-center gap-1">
                          <CheckCircle2 size={12} className="text-good" aria-hidden /> {(x.counts.ok ?? 0) + (x.counts.warn ?? 0)} sim
                        </span>
                        <span className="flex items-center gap-1">
                          <XCircle size={12} className="text-bad" aria-hidden /> {x.counts.fail ?? 0} não
                        </span>
                      </span>
                    </li>
                  ))}
                </ul>
              </Section>
              <Section title="Critérios" aside={<ShieldCheck size={15} className="text-subtle" aria-hidden />}>
                <dl className="space-y-1.5 text-[12.5px]">
                  {Object.entries(q.gate).map(([k, v]) => (
                    <div key={k} className="flex justify-between gap-3">
                      <dt className="text-muted">{GATE_LABELS[k] ?? k}</dt>
                      <dd className="text-right font-mono text-text">{fmt(v)}</dd>
                    </div>
                  ))}
                </dl>
                <p className="mt-3 text-xs text-subtle">
                  Ajuste em <span className="font-mono">quality_gate</span> no vitrix.yml (tela{" "}
                  <Link to="/settings" className="text-accent hover:underline">
                    Configurações
                  </Link>
                  ). No CI: <span className="font-mono">vitrix check --gate</span>.
                </p>
              </Section>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
