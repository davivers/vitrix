import { useQuery } from "@tanstack/react-query";
import { Plus, Search } from "lucide-react";
import { useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api } from "../api";
import { Card, ErrorBox, LevelTag, PageHeader, StateBadge, TargetChip } from "../components/ui";
import type { State } from "../types";

const FILTERS: { value: "all" | State; label: string }[] = [
  { value: "all", label: "Todas" },
  { value: "ok", label: "Válidas" },
  { value: "warn", label: "Com avisos" },
  { value: "fail", label: "Com falha" },
];

export default function RulesPage() {
  const navigate = useNavigate();
  const { data, error, isLoading } = useQuery({ queryKey: ["rules"], queryFn: api.rules });
  const [q, setQ] = useState("");
  const [filter, setFilter] = useState<"all" | State>("all");

  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return (data ?? []).filter(
      (r) =>
        (filter === "all" || r.state === filter) &&
        (!needle || [r.title, r.id, ...r.techniques, ...r.tactics].some((s) => s.toLowerCase().includes(needle))),
    );
  }, [data, q, filter]);

  return (
    <div className="mx-auto max-w-6xl px-8 py-8">
      <PageHeader
        title="Regras"
        subtitle={data ? `${data.length} regras no repositório` : "Lendo o repositório…"}
        actions={
          <Link to="/editor" className="inline-flex items-center gap-2 rounded-[10px] bg-brand px-4 py-2 text-[13.5px] font-semibold text-strong shadow-[0_8px_24px_-10px_rgb(109_91_240/0.8)] hover:brightness-110">
            <Plus size={16} aria-hidden /> Nova regra
          </Link>
        }
      />

      <div className="mb-4 flex flex-wrap items-center gap-3">
        <label className="relative">
          <span className="sr-only">Buscar regra</span>
          <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-subtle" aria-hidden />
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Buscar por título, arquivo ou técnica"
            className="w-80 rounded-[10px] border border-line bg-surface py-2 pl-9 pr-3 text-sm text-text placeholder:text-subtle focus:border-accent/50"
          />
        </label>
        <div className="flex gap-1 rounded-[10px] border border-line bg-surface p-1" role="group" aria-label="Filtrar por estado">
          {FILTERS.map((f) => (
            <button
              key={f.value}
              type="button"
              aria-pressed={filter === f.value}
              onClick={() => setFilter(f.value)}
              className={`rounded-md px-3 py-1.5 text-sm ${filter === f.value ? "bg-accent-soft font-medium text-strong" : "text-muted hover:text-text"}`}
            >
              {f.label}
            </button>
          ))}
        </div>
      </div>

      {error && <ErrorBox message={(error as Error).message} />}

      <Card className="overflow-hidden">
        <table className="w-full text-left text-sm">
          <thead className="border-b border-line bg-surface text-[11.5px] uppercase tracking-wide text-subtle">
            <tr>
              <th className="px-4 py-3 font-medium">Regra</th>
              <th className="px-4 py-3 font-medium">Severidade</th>
              <th className="px-4 py-3 font-medium">MITRE</th>
              <th className="px-4 py-3 font-medium">Linguagem final</th>
              <th className="px-4 py-3 font-medium">Testes</th>
              <th className="px-4 py-3 font-medium">Estado</th>
            </tr>
          </thead>
          <tbody>
            {isLoading && (
              <tr>
                <td colSpan={6} className="px-4 py-10 text-center text-muted">
                  Carregando…
                </td>
              </tr>
            )}
            {!isLoading && rows.length === 0 && !error && (
              <tr>
                <td colSpan={6} className="px-4 py-10 text-center text-muted">
                  {data?.length ? "Nenhuma regra com esse filtro." : "Nenhuma regra em rules/. Crie a primeira em “Nova regra”."}
                </td>
              </tr>
            )}
            {rows.map((r) => (
              <tr
                key={r.id}
                onClick={() => navigate(`/editor/${r.id}`)}
                className="cursor-pointer border-b border-line last:border-0 hover:bg-accent/[0.07]"
              >
                <td className="px-4 py-3">
                  <Link to={`/editor/${r.id}`} className="font-semibold text-strong hover:text-accent" onClick={(e) => e.stopPropagation()}>
                    {r.title || r.id}
                  </Link>
                  <div className="font-mono text-xs text-subtle">{r.id}</div>
                </td>
                <td className="px-4 py-3">
                  <LevelTag level={r.level} />
                </td>
                <td className="px-4 py-3 font-mono text-xs text-subtle">{r.techniques.join(", ") || "—"}</td>
                <td className="px-4 py-3">
                  <span className="flex flex-wrap gap-1">
                    {r.targets.map((t) => (
                      <TargetChip key={t} target={t} ok={r.conversion[t]} source={r.target_source} />
                    ))}
                  </span>
                </td>
                <td className="px-4 py-3 tabular-nums">{r.tests.total ? `${r.tests.passed}/${r.tests.total}` : <span className="text-warn">sem casos</span>}</td>
                <td className="px-4 py-3">
                  <StateBadge state={r.state} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
    </div>
  );
}
