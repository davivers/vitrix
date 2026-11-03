import { useQuery } from "@tanstack/react-query";
import { Plus, Search } from "lucide-react";
import { useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api } from "../api";
import { HealthMeter, timeAgo } from "../components/dash";
import { Card, ErrorBox, LevelTag, PageHeader, StateBadge, TargetChip, btnPrimary } from "../components/ui";
import type { State } from "../types";

const FILTERS: { value: "all" | State; label: string }[] = [
  { value: "all", label: "All" },
  { value: "ok", label: "Valid" },
  { value: "warn", label: "Warnings" },
  { value: "fail", label: "Failing" },
];

export default function RulesPage() {
  const navigate = useNavigate();
  const { data, error, isLoading } = useQuery({ queryKey: ["rules"], queryFn: api.rules });
  const quality = useQuery({ queryKey: ["quality"], queryFn: api.quality });
  const [q, setQ] = useState("");
  const [filter, setFilter] = useState<"all" | State>("all");

  const gate = useMemo(() => new Map((quality.data?.rules ?? []).map((r) => [r.id, r])), [quality.data]);

  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return (data ?? []).filter(
      (r) =>
        (filter === "all" || r.state === filter) &&
        (!needle || [r.title, r.id, r.logsource ?? "", ...r.techniques, ...r.tactics].some((s) => s.toLowerCase().includes(needle))),
    );
  }, [data, q, filter]);

  return (
    <div className="mx-auto max-w-7xl px-4 py-8 sm:px-8">
      <PageHeader
        title="Rules"
        subtitle={data ? `${data.length} rules in the repository` : "Reading the repository…"}
        actions={
          <Link to="/editor" className={btnPrimary}>
            <Plus size={16} aria-hidden /> New rule
          </Link>
        }
      />

      <div className="mb-4 flex flex-wrap items-center gap-3">
        <label className="relative">
          <span className="sr-only">Search rules</span>
          <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-subtle" aria-hidden />
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Search by title, file, data source or technique"
            className="w-80 max-w-full rounded-[10px] border border-line bg-surface py-2 pl-9 pr-3 text-sm text-text placeholder:text-subtle focus:border-accent/50"
          />
        </label>
        <div className="flex gap-1 rounded-[10px] border border-line bg-surface p-1" role="group" aria-label="Filter by state">
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

      <Card className="overflow-x-auto">
        <table className="w-full min-w-[900px] text-left text-sm">
          <thead className="border-b border-line bg-surface text-[11.5px] uppercase tracking-wide text-subtle">
            <tr>
              <th className="px-4 py-3 font-medium">Rule</th>
              <th className="px-4 py-3 font-medium">Severity</th>
              <th className="px-4 py-3 font-medium">ATT&amp;CK</th>
              <th className="px-4 py-3 font-medium">Final language</th>
              <th className="px-4 py-3 font-medium">Tests</th>
              <th className="px-4 py-3 font-medium">Health</th>
              <th className="px-4 py-3 font-medium">Changed</th>
              <th className="px-4 py-3 font-medium">State</th>
            </tr>
          </thead>
          <tbody>
            {isLoading && (
              <tr>
                <td colSpan={8} className="px-4 py-10 text-center text-muted">
                  Loading…
                </td>
              </tr>
            )}
            {!isLoading && rows.length === 0 && !error && (
              <tr>
                <td colSpan={8} className="px-4 py-10 text-center text-muted">
                  {data?.length ? "No rule matches this filter." : "No rules in rules/. Create the first one with “New rule”."}
                </td>
              </tr>
            )}
            {rows.map((r) => {
              const g = gate.get(r.id);
              return (
                <tr key={r.id} onClick={() => navigate(`/editor/${r.id}`)} className="cursor-pointer border-b border-line last:border-0 hover:bg-accent/[0.07]">
                  <td className="px-4 py-3">
                    <Link to={`/editor/${r.id}`} className="font-semibold text-strong hover:text-accent" onClick={(e) => e.stopPropagation()}>
                      {r.title || r.id}
                    </Link>
                    <div className="font-mono text-xs text-subtle">{r.id}</div>
                    {r.logsource && <div className="text-xs text-subtle">{r.logsource}</div>}
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
                  <td className="px-4 py-3 tabular-nums">{r.tests.total ? `${r.tests.passed}/${r.tests.total}` : <span className="text-warn">no cases</span>}</td>
                  <td className="px-4 py-3">{g ? <HealthMeter score={g.score} /> : <span className="text-subtle">—</span>}</td>
                  <td className="px-4 py-3 text-xs text-muted">{g?.age_days !== null && g?.age_days !== undefined ? timeAgo(new Date(Date.now() - g.age_days * 86400000).toISOString()) : "—"}</td>
                  <td className="px-4 py-3">
                    <StateBadge state={r.state} />
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </Card>
    </div>
  );
}
