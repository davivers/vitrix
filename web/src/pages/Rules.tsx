import { useQuery } from "@tanstack/react-query";
import { CheckCircle2, ChevronDown, Download, GitCompare, HardDrive, Plus, Rocket, Search, XCircle } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { DEMO, api } from "../api";
import { HintText } from "../components/Issues";
import { DriftBadge, count, driftErrorMessage } from "../components/Drift";
import { HealthMeter, StatTile, pct, timeAgo } from "../components/dash";
import { FlowFunnel } from "../components/flow";
import { PublicationBadge } from "./Editor";
import { PublishBatch } from "./Packs";
import { RulePublish } from "../components/RulePublish";
import { Card, ErrorBox, LevelTag, PageHeader, StateBadge, TargetChip, btnPrimary, btnSecondary, inputCls } from "../components/ui";
import type { QualityReport, RuleSummary, State } from "../types";
import { t, tn } from "../i18n";

const FILTERS: { value: "all" | State; label: string }[] = [
  { value: "all", label: t("l_all") },
  { value: "ok", label: t("l_valid") },
  { value: "warn", label: t("l_warnings") },
  { value: "fail", label: t("l_failing") },
];

const STRIP_KEY = "vitrix.rules.gate-strip";
const readStrip = () => {
  try {
    return localStorage.getItem(STRIP_KEY) !== "closed";
  } catch {
    return true;
  }
};

/** Workspace-wide gate summary (moved here from the old Quality Gate page). */
function GateStrip({ q, onBlocked, forceOpen }: { q: QualityReport; onBlocked: () => void; forceOpen: boolean }) {
  const [open, setOpen] = useState(() => forceOpen || readStrip());
  const toggle = () => {
    setOpen(!open);
    try {
      localStorage.setItem(STRIP_KEY, open ? "closed" : "open");
    } catch {
      /* storage unavailable */
    }
  };
  return (
    <section aria-label={t("quality_gate_summary")} className="mb-5">
      <button type="button" onClick={toggle} aria-expanded={open} className="mb-2 inline-flex items-center gap-1.5 text-[13px] font-semibold text-muted hover:text-text">
        <ChevronDown size={14} className={open ? "" : "-rotate-90"} aria-hidden /> {t("quality_gate_summary")}
      </button>
      {open && (
        <>
          <div className="mb-4 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
            <StatTile label={t("ready_to_publish")} value={`${q.summary.ready}/${q.summary.total}`} sub={t("ru_pct_set", { p: pct(q.summary.ready, q.summary.total) })} status={q.summary.blocked ? "warn" : "ok"} />
            <button type="button" onClick={onBlocked} disabled={!q.summary.blocked} className="text-left disabled:cursor-default" aria-label={t("ru_show_blocked", { n: q.summary.blocked })}>
              <StatTile label={t("blocked_2")} value={q.summary.blocked} sub={q.summary.blocked ? t("l_click_to_filter_the_table") : t("l_none_word")} status={q.summary.blocked ? "fail" : "ok"} />
            </button>
            <StatTile
              label={t("average_health")}
              value={q.summary.health === null ? "—" : `${q.summary.health}/100`}
              sub={q.summary.stale ? t("ex_due_review", { n: q.summary.stale }) : t("ex_no_overdue")}
              status={q.summary.health === null ? "none" : q.summary.health >= 90 ? "ok" : q.summary.health >= 70 ? "warn" : "fail"}
            />
            <StatTile
              label={t("replay_datasets")}
              value={q.datasets.length}
              sub={q.datasets.length ? t("ru_ds_info") : t("ru_none_ds")}
              status="none"
            />
          </div>
          <FlowFunnel q={q} />
        </>
      )}
    </section>
  );
}

const isUnmerged = (r: RuleSummary) => Boolean(r.publication && r.publication.state !== "published");

export default function RulesPage() {
  const navigate = useNavigate();
  const { data, error, isLoading } = useQuery({ queryKey: ["rules"], queryFn: api.rules });
  const quality = useQuery({ queryKey: ["quality"], queryFn: api.quality });
  const [q, setQ] = useState("");
  const [filter, setFilter] = useState<"all" | State>("all");
  const [gateFilter, setGateFilter] = useState<"all" | "blocked" | "ready">("all");
  // "Not in Git yet": local, unknown (no Git), pushed or in a PR (anything not merged).
  const [notInGit, setNotInGit] = useState(() => new URLSearchParams(window.location.search).get("publication") === "unmerged");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [publishId, setPublishId] = useState<string | null>(null);
  const [batchOpen, setBatchOpen] = useState(false);
  // Drift needs a replay of every rule at a Git ref (seconds on big repos), so it only runs when asked.
  const [driftOn, setDriftOn] = useState(false);
  const [driftRef, setDriftRef] = useState("");
  const [driftApplied, setDriftApplied] = useState<string | null>(null);
  const [driftOnly, setDriftOnly] = useState(false);
  const drift = useQuery({ queryKey: ["drift", driftApplied, null], queryFn: () => api.drift(driftApplied), enabled: driftOn, retry: false });
  const driftRows = useMemo(() => new Map((drift.data?.rules ?? []).map((r) => [r.rule, r])), [drift.data]);
  const [params] = useSearchParams();
  const stripRef = useRef<HTMLDivElement>(null);

  // /rules?view=gate (old /gate bookmarks): scroll to the summary and show the blocked rules, if any.
  const viewGate = params.get("view") === "gate";
  useEffect(() => {
    if (!viewGate || !quality.data) return;
    stripRef.current?.scrollIntoView({ block: "start" });
    if (quality.data.summary.blocked) setGateFilter("blocked");
  }, [viewGate, quality.data]);

  const gate = useMemo(() => new Map((quality.data?.rules ?? []).map((r) => [r.id, r])), [quality.data]);

  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase();
    const list = (data ?? []).filter(
      (r) =>
        (filter === "all" || r.state === filter) &&
        (!notInGit || isUnmerged(r)) &&
        (gateFilter === "all" || (gateFilter === "ready") === Boolean(gate.get(r.id)?.ready)) &&
        (!driftOn || !driftOnly || driftRows.get(r.id)?.state !== "same" || driftRows.get(r.id)?.modified) &&
        (!needle || [r.title, r.id, r.logsource ?? "", ...r.techniques, ...r.tactics].some((s) => s.toLowerCase().includes(needle))),
    );
    // Gate view: blocked rules first, lowest health first.
    return viewGate ? [...list].sort((a, b) => Number(gate.get(a.id)?.ready ?? true) - Number(gate.get(b.id)?.ready ?? true) || (gate.get(a.id)?.score ?? 100) - (gate.get(b.id)?.score ?? 100)) : list;
  }, [data, q, filter, gateFilter, notInGit, gate, viewGate, driftOn, driftOnly, driftRows]);
  const unmerged = (data ?? []).filter(isUnmerged);
  const onlyLocal = (data ?? []).filter((r) => r.publication?.state === "local" || r.publication?.state === "unknown").length;
  const toggleSel = (id: string) => {
    const n = new Set(selected);
    if (n.has(id)) n.delete(id);
    else n.add(id);
    setSelected(n);
  };

  return (
    <div className="mx-auto max-w-7xl px-4 py-8 sm:px-8">
      <PageHeader
        title={viewGate ? t("l_quality_gate") : t("l_rules")}
        subtitle={viewGate ? t("l_which_rules_can_be_published_block") : data ? t("ru_n_rules", { n: data.length }) : t("reading_the_repository")}
        actions={
          <div className="flex flex-wrap gap-2">
            <Link to="/packs" className={btnSecondary} {...(DEMO ? { "aria-disabled": true, title: t("demo_disabled"), onClick: (e) => e.preventDefault() } : {})}>
              <Download size={16} aria-hidden /> {t("pk_import_cta")}
            </Link>
            <Link to="/editor" className={btnPrimary}>
              <Plus size={16} aria-hidden /> {t("new_rule")}
            </Link>
          </div>
        }
      />

      {onlyLocal > 0 && (
        <p className="mb-4 flex flex-wrap items-center gap-2 rounded-[10px] border border-warn/30 bg-warn-soft px-4 py-2.5 text-sm text-warn" role="status">
          <HardDrive size={15} aria-hidden /> {tn("ru_only_local", onlyLocal)}
          <button type="button" className="font-semibold underline" onClick={() => setNotInGit(true)}>
            {t("ru_show_them")}
          </button>
        </p>
      )}

      <div ref={stripRef}>
        {quality.isLoading && <p className="mb-5 text-sm text-muted">{t("running_the_lifecycle_on_every_rule")}</p>}
        {quality.error && (
          <div className="mb-5">
            <ErrorBox message={(quality.error as Error).message} />
          </div>
        )}
        {quality.data && <GateStrip q={quality.data} forceOpen={viewGate} onBlocked={() => setGateFilter("blocked")} />}
      </div>

      <div className="mb-4 flex flex-wrap items-center gap-3">
        <label className="relative">
          <span className="sr-only">{t("search_rules")}</span>
          <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-subtle" aria-hidden />
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder={t("search_by_title_file_data_source_or_te")}
            className="w-80 max-w-full rounded-[10px] border border-line bg-surface py-2 pl-9 pr-3 text-sm text-text placeholder:text-subtle focus:border-accent/50"
          />
        </label>
        <div className="flex gap-1 rounded-[10px] border border-line bg-surface p-1" role="group" aria-label={t("filter_by_state")}>
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
        {unmerged.length > 0 && (
          <button type="button" aria-pressed={notInGit} onClick={() => setNotInGit(!notInGit)} className={`inline-flex items-center gap-1.5 rounded-[10px] border border-line px-3 py-2 text-sm ${notInGit ? "bg-accent-soft font-medium text-strong" : "bg-surface text-muted hover:text-text"}`}>
            <HardDrive size={14} aria-hidden /> {t("ru_not_in_git")} ({unmerged.length})
          </button>
        )}
        {quality.data && (
          <div className="flex gap-1 rounded-[10px] border border-line bg-surface p-1" role="group" aria-label={t("filter_by_gate")}>
            {(
              [
                ["all", t("l_all")],
                ["blocked", t("ru_f_blocked")],
                ["ready", t("ru_f_ready")],
              ] as const
            ).map(([k, label]) => (
              <button
                key={k}
                type="button"
                aria-pressed={gateFilter === k}
                onClick={() => setGateFilter(k)}
                className={`rounded-md px-3 py-1.5 text-sm ${gateFilter === k ? "bg-accent-soft font-medium text-strong" : "text-muted hover:text-text"}`}
              >
                {label}
              </button>
            ))}
          </div>
        )}
        <div className="flex items-center gap-2">
          <button type="button" aria-pressed={driftOn} onClick={() => setDriftOn(!driftOn)} className={`inline-flex items-center gap-1.5 rounded-[10px] border border-line px-3 py-2 text-sm ${driftOn ? "bg-accent-soft font-medium text-strong" : "bg-surface text-muted hover:text-text"}`}>
            <GitCompare size={14} aria-hidden /> {t("dr_column")}
          </button>
          {driftOn && (
            <>
              <form
                className="flex gap-1"
                onSubmit={(e) => {
                  e.preventDefault();
                  setDriftApplied(driftRef.trim() || null);
                }}
              >
                <label>
                  <span className="sr-only">{t("dr_ref")}</span>
                  <input value={driftRef} onChange={(e) => setDriftRef(e.target.value)} placeholder={t("dr_ref_ph")} className={`${inputCls} w-44`} maxLength={200} spellCheck={false} />
                </label>
                <button type="submit" className={btnSecondary}>
                  {t("dr_compare")}
                </button>
              </form>
              <label className="flex items-center gap-2 text-[13px] text-muted">
                <input type="checkbox" checked={driftOnly} onChange={(e) => setDriftOnly(e.target.checked)} className="accent-accent" /> {t("dr_only")}
              </label>
            </>
          )}
        </div>
      </div>

      {error && <ErrorBox message={(error as Error).message} />}
      {driftOn && drift.isFetching && <p className="mb-3 text-sm text-muted">{t("dr_running")}</p>}
      {driftOn && drift.error && (
        <div className="mb-3">
          <ErrorBox message={driftErrorMessage(drift.error)} />
        </div>
      )}
      {driftOn && drift.data && (
        <p className="mb-3 text-[13px] text-muted">
          {t("dr_vs")} <span className="font-mono text-text">{drift.data.ref}</span> · {t("dr_summary", { n: drift.data.summary.drifted, m: drift.data.summary.modified })}
        </p>
      )}

      {notInGit && selected.size > 0 && (
        <Card className="mb-4 space-y-3 p-4">
          <div className="flex flex-wrap items-center gap-3">
            <span className="text-sm text-text">{tn("ru_selected", selected.size)}</span>
            <button type="button" className={btnPrimary} onClick={() => setBatchOpen(!batchOpen)}>
              <Rocket size={15} aria-hidden /> {t("ru_publish_selected", { n: selected.size })}
            </button>
            <button type="button" className="text-sm text-muted hover:text-text" onClick={() => setSelected(new Set())}>
              {t("cancel")}
            </button>
          </div>
          {batchOpen && <PublishBatch ids={[...selected]} titles={Object.fromEntries((data ?? []).map((r) => [r.id, r.title]))} />}
        </Card>
      )}
      {publishId && <RulePublish id={publishId} onClose={() => setPublishId(null)} />}

      <Card className="overflow-x-auto">
        <table className="w-full min-w-[760px] text-left text-sm">
          <thead className="border-b border-line bg-surface text-[11.5px] uppercase tracking-wide text-subtle">
            <tr>
              <th className="px-3 py-3 font-medium">{t("rule")}</th>
              <th className="px-3 py-3 font-medium">{t("severity")}</th>
              <th className="px-3 py-3 font-medium">ATT&amp;CK</th>
              <th className="px-3 py-3 font-medium">{t("final_language")}</th>
              <th className="px-3 py-3 font-medium">{t("tests")}</th>
              <th className="whitespace-nowrap px-3 py-3 font-medium">{t("gate")}</th>
              <th className="hidden px-3 py-3 font-medium min-[1440px]:table-cell">{t("changed")}</th>
              <th className="px-3 py-3 font-medium">{t("state")}</th>
              {driftOn && <th className="px-3 py-3 font-medium">{t("dr_column")}</th>}
            </tr>
          </thead>
          <tbody>
            {isLoading && (
              <tr>
                <td colSpan={9} className="px-4 py-10 text-center text-muted">
                  {t("loading")}
                </td>
              </tr>
            )}
            {!isLoading && rows.length === 0 && !error && (
              <tr>
                <td colSpan={9} className="px-4 py-10 text-center text-muted">
                  {data?.length ? t("l_no_rule_matches_this_filter") : t("ru_empty")}
                </td>
              </tr>
            )}
            {rows.map((r) => {
              const g = gate.get(r.id);
              return (
                <tr key={r.id} onClick={() => navigate(`/editor/${r.id}`)} className="cursor-pointer border-b border-line last:border-0 hover:bg-surface-2">
                  <td className="px-3 py-3">
                    {notInGit && isUnmerged(r) && (
                      <input
                        type="checkbox"
                        className="mr-2 accent-accent"
                        aria-label={t("ru_select", { t: r.title || r.id })}
                        checked={selected.has(r.id)}
                        onClick={(e) => e.stopPropagation()}
                        onChange={() => toggleSel(r.id)}
                      />
                    )}
                    <Link to={`/editor/${r.id}`} className="font-semibold text-strong hover:text-accent" onClick={(e) => e.stopPropagation()}>
                      {r.title || r.id}
                    </Link>
                    <div className="font-mono text-xs text-subtle">{r.id}</div>
                    {r.publication && r.publication.state !== "published" && (
                      <div className="mt-1 flex flex-wrap items-center gap-2">
                        <PublicationBadge pub={r.publication} isNew={false} />
                        {!DEMO && r.publication.state !== "in_pr" && (
                          <button type="button" className="rounded-md border border-line px-2 py-0.5 text-xs font-medium text-accent hover:bg-surface-2" aria-label={t("ru_publish_rule", { t: r.title || r.id })} onClick={(e) => { e.stopPropagation(); setPublishId(r.id); }}>
                            {t("publish")}
                          </button>
                        )}
                      </div>
                    )}
                    {r.logsource && <div className="text-xs text-subtle">{r.logsource}</div>}
                  </td>
                  <td className="px-3 py-3">
                    <LevelTag level={r.level} />
                  </td>
                  <td className="px-3 py-3 font-mono text-xs text-subtle">{r.techniques.join(", ") || "—"}</td>
                  <td className="px-3 py-3">
                    <span className="flex flex-wrap gap-1">
                      {r.targets.map((t) => (
                        <TargetChip key={t} target={t} ok={r.conversion[t]} source={r.target_source} />
                      ))}
                    </span>
                  </td>
                  <td className="px-3 py-3 tabular-nums">{r.tests.total ? `${r.tests.passed}/${r.tests.total}` : <span className="text-warn">{t("no_cases")}</span>}</td>
                  <td className="whitespace-nowrap px-3 py-3">
                    {g ? (
                      <span className="flex flex-nowrap items-center gap-2">
                        <span className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-semibold ${g.ready ? "bg-good-soft text-good" : "bg-bad-soft text-bad"}`}>
                          {g.ready ? <CheckCircle2 size={12} aria-hidden /> : <XCircle size={12} aria-hidden />}
                          {g.ready ? t("ru_row_ready") : t("ru_row_blocked")}
                        </span>
                        <span className="hidden min-[1440px]:inline"><HealthMeter score={g.score} /></span>
                        <span className="tabular-nums text-xs text-muted min-[1440px]:hidden">{g.score}</span>
                      </span>
                    ) : (
                      <span className="text-subtle">—</span>
                    )}
                  </td>
                  <td className="hidden px-3 py-3 text-xs text-muted min-[1440px]:table-cell">{g?.age_days !== null && g?.age_days !== undefined ? timeAgo(new Date(Date.now() - g.age_days * 86400000).toISOString()) : "—"}</td>
                  <td className="px-3 py-3">
                    <span className="whitespace-nowrap"><StateBadge state={r.state} /></span>
                    {r.state !== "ok" && r.issues[0] && (
                      <span className="mt-1 block max-w-[110px] truncate text-xs text-muted" title={r.issues.map((i) => `${i.message}${i.hint ? ` — ${i.hint}` : ""}`).join(" | ")}>
                        {r.issues[0].hint ? <HintText text={r.issues[0].hint} /> : r.issues[0].message}
                      </span>
                    )}
                  </td>
                  {driftOn && (
                    <td className="whitespace-nowrap px-3 py-3">
                      {(() => {
                        const d = driftRows.get(r.id);
                        return d ? (
                          <span className="flex flex-col gap-1">
                            <DriftBadge state={d.state} modified={d.modified} />
                            <span className="text-xs tabular-nums text-muted">
                              {count(d.before)} → {count(d.after)}
                            </span>
                          </span>
                        ) : (
                          <span className="text-subtle">—</span>
                        );
                      })()}
                    </td>
                  )}
                </tr>
              );
            })}
          </tbody>
        </table>
      </Card>
    </div>
  );
}
