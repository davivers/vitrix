import { useQuery } from "@tanstack/react-query";
import clsx from "clsx";
import { AlertTriangle, CheckCircle2, Filter, Play, XCircle } from "lucide-react";
import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { StatTile, pct } from "../components/dash";
import { KIND_LABEL, KindTag } from "../components/flow";
import { Card, ErrorBox, PageHeader } from "../components/ui";
import type { CaseKind } from "../types";

const KINDS: CaseKind[] = ["positive", "negative", "false_positive", "edge"];

export default function TestSuitesPage() {
  const { data, error, isFetching, refetch } = useQuery({ queryKey: ["tests"], queryFn: api.tests });
  const [kind, setKind] = useState<"all" | CaseKind>("all");
  const [onlyFailed, setOnlyFailed] = useState(false);

  const rules = useMemo(
    () =>
      (data?.rules ?? [])
        .map((r) => ({ ...r, shown: r.results.filter((c) => (kind === "all" || c.kind === kind) && (!onlyFailed || !c.passed)) }))
        .filter((r) => r.shown.length > 0 || (onlyFailed && r.problems.some((p) => p.severity === "error"))),
    [data, kind, onlyFailed],
  );

  return (
    <div className="mx-auto max-w-7xl px-4 py-8 sm:px-8">
      <PageHeader
        title="Test suites"
        subtitle="Todos os casos de teste do repositório, rodados no avaliador local. Cada caso tem um tipo: positivo, negativo, falso positivo ou borda."
        actions={
          <button
            type="button"
            onClick={() => refetch()}
            className="inline-flex items-center gap-2 rounded-[10px] bg-brand px-4 py-2 text-[13.5px] font-semibold text-strong hover:brightness-110"
          >
            <Play size={15} className={isFetching ? "animate-pulse" : undefined} aria-hidden /> {isFetching ? "Executando…" : "Executar suites"}
          </button>
        }
      />
      {error && <ErrorBox message={(error as Error).message} />}
      {data && (
        <>
          <div className="mb-5 grid gap-4 sm:grid-cols-2 xl:grid-cols-5">
            <StatTile
              label="Todos os casos"
              value={`${data.passed}/${data.total}`}
              sub={`${pct(data.passed, data.total)}% aprovados · ${data.duration_ms} ms`}
              status={data.passed === data.total ? "ok" : "fail"}
            />
            {KINDS.map((k) => (
              <StatTile
                key={k}
                label={KIND_LABEL[k]}
                value={`${data.by_kind[k].passed}/${data.by_kind[k].total}`}
                sub={data.by_kind[k].total ? (data.by_kind[k].passed === data.by_kind[k].total ? "todos aprovados" : "há reprovados") : "nenhum caso"}
                status={data.by_kind[k].total === 0 ? "warn" : data.by_kind[k].passed === data.by_kind[k].total ? "ok" : "fail"}
              />
            ))}
          </div>

          <div className="mb-4 flex flex-wrap items-center gap-3">
            <div className="flex gap-1 rounded-[10px] border border-line bg-surface p-1" role="group" aria-label="Tipo de caso">
              {(["all", ...KINDS] as const).map((k) => (
                <button
                  key={k}
                  type="button"
                  aria-pressed={kind === k}
                  onClick={() => setKind(k)}
                  className={clsx("rounded-md px-3 py-1 text-[13px]", kind === k ? "bg-accent-soft font-medium text-strong" : "text-muted hover:text-text")}
                >
                  {k === "all" ? "Todos" : KIND_LABEL[k]}
                </button>
              ))}
            </div>
            <label className="flex items-center gap-2 text-[13px] text-muted">
              <input type="checkbox" checked={onlyFailed} onChange={(e) => setOnlyFailed(e.target.checked)} className="accent-[#8b7cf6]" />
              <Filter size={14} aria-hidden /> Só reprovados
            </label>
          </div>

          <div className="space-y-4">
            {rules.map((r) => (
              <Card key={r.id} className="overflow-hidden">
                <div className="flex flex-wrap items-center justify-between gap-2 border-b border-line px-4 py-3">
                  <span>
                    <Link to={`/editor/${r.id}`} className="text-[13.5px] font-semibold text-strong hover:text-accent">
                      {r.title || r.id}
                    </Link>
                    <span className="ml-2 font-mono text-[11.5px] text-subtle">{r.id}</span>
                  </span>
                  <span className="text-xs text-muted tabular-nums">
                    {r.results.filter((c) => c.passed).length}/{r.results.length} casos
                  </span>
                </div>
                <table className="w-full text-left text-[13px]">
                  <caption className="sr-only">Casos de {r.id}</caption>
                  <thead className="text-[11px] uppercase tracking-wide text-subtle">
                    <tr>
                      <th className="px-4 py-2 font-medium">Resultado</th>
                      <th className="px-4 py-2 font-medium">Caso</th>
                      <th className="px-4 py-2 font-medium">Tipo</th>
                      <th className="px-4 py-2 font-medium">Esperado</th>
                      <th className="px-4 py-2 font-medium">Obtido</th>
                    </tr>
                  </thead>
                  <tbody>
                    {r.shown.map((c, i) => (
                      <tr key={i} className="border-t border-line">
                        <td className="px-4 py-2">
                          <span className={clsx("inline-flex items-center gap-1 text-xs font-semibold", c.passed ? "text-good" : "text-bad")}>
                            {c.passed ? <CheckCircle2 size={14} aria-hidden /> : <XCircle size={14} aria-hidden />}
                            {c.passed ? "passou" : "falhou"}
                          </span>
                        </td>
                        <td className="px-4 py-2 text-text">
                          {c.name}
                          {c.exercises_filter && <span className="ml-2 text-xs text-subtle">· prova a exclusão</span>}
                          {c.error && <span className="block text-xs text-bad">{c.error}</span>}
                        </td>
                        <td className="px-4 py-2">
                          <KindTag kind={c.kind} />
                        </td>
                        <td className="px-4 py-2 font-mono text-xs text-muted">{c.expect}</td>
                        <td className="px-4 py-2 font-mono text-xs text-muted">{c.got}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {r.problems.length > 0 && (
                  <ul className="space-y-1 border-t border-line px-4 py-2.5 text-[12.5px]">
                    {r.problems.map((p, i) => (
                      <li key={i} className="flex gap-2">
                        {p.severity === "error" ? <XCircle size={14} className="mt-0.5 shrink-0 text-bad" aria-hidden /> : <AlertTriangle size={14} className="mt-0.5 shrink-0 text-warn" aria-hidden />}
                        <span className="text-text">{p.message}</span>
                      </li>
                    ))}
                  </ul>
                )}
              </Card>
            ))}
            {rules.length === 0 && <p className="text-sm text-muted">Nenhum caso com esse filtro.</p>}
            {data.broken.map((b) => (
              <ErrorBox key={b.file} message={`${b.file}: ${b.error}`} />
            ))}
          </div>
        </>
      )}
    </div>
  );
}
