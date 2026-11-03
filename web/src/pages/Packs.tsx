import { useMutation, useQuery } from "@tanstack/react-query";
import { AlertTriangle, CheckCircle2, Download, ExternalLink, Loader2, PackageOpen, Rocket, Search, XCircle } from "lucide-react";
import { useEffect, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { ApiError, DEMO, api } from "../api";
import { can, useMe } from "../components/auth";
import { Card, ErrorBox, LevelTag, PageHeader, btnPrimary, btnSecondary, inputCls } from "../components/ui";
import { safeHref } from "../components/dash";
import type { BlockedDraft, PackFilters, PackItem, PackJob, Submission } from "../types";
import { t } from "../i18n";

const ACTIVE = new Set(["queued", "downloading", "scanning", "importing"]);
const STATUSES = ["stable", "test", "experimental"] as const;
const mb = (n: number) => `${(n / 1048576).toFixed(1)} MB`;

/** Polls a job every second while it runs. */
function useJob(id: string | null) {
  return useQuery({
    queryKey: ["pack-job", id],
    queryFn: () => api.packJob(id!),
    enabled: id !== null,
    retry: false,
    refetchInterval: (q) => (q.state.data && !ACTIVE.has(q.state.data.state) ? false : 1000),
  });
}

function Progress({ job }: { job: PackJob }) {
  const p = job.progress;
  const done = !ACTIVE.has(job.state);
  return (
    <div role="status" aria-live="polite" className="flex flex-wrap items-center gap-x-4 gap-y-1 text-sm text-muted">
      {done ? job.state === "failed" ? <XCircle size={15} className="text-bad" aria-hidden /> : <CheckCircle2 size={15} className="text-good" aria-hidden /> : <Loader2 size={15} className="animate-spin" aria-hidden />}
      <span className="font-medium text-text">{t(`pk_state_${job.state}` as "pk_state_queued")}</span>
      {job.state === "downloading" && <span className="tabular-nums">{p.total ? `${mb(p.bytes)} / ${mb(p.total)}` : mb(p.bytes)}</span>}
      {(job.state === "scanning" || job.state === "importing" || done) && (
        <span className="tabular-nums">{t("pk_counts", { s: p.scanned, m: p.matched, i: p.imported })}</span>
      )}
    </div>
  );
}

export default function PacksPage() {
  const me = useMe();
  const editor = can(me, "editor") && !DEMO;
  const sources = useQuery({ queryKey: ["pack-sources"], queryFn: api.packSources, retry: false, enabled: !DEMO });
  const src = sources.data?.sources[0];
  const max = sources.data?.limits.max_rules ?? 50;

  const [ref, setRef] = useState("");
  const [f, setF] = useState({ product: "", category: "", service: "", text: "" });
  const [statuses, setStatuses] = useState<string[]>(["stable", "test"]);
  const [limit, setLimit] = useState(20);
  const [untested, setUntested] = useState(false);
  const [previewId, setPreviewId] = useState<string | null>(null);
  const [importId, setImportId] = useState<string | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());

  const filters: PackFilters = {
    product: f.product.trim() || null,
    category: f.category.trim() || null,
    service: f.service.trim() || null,
    statuses,
    text: f.text.trim() || null,
  };
  const body = { source: src?.id ?? "sigmahq", ref: ref || (src?.refs[0] ?? "master"), filters, into: "sigmahq", include_untested: untested };

  const preview = useJob(previewId);
  const imported = useJob(importId);
  const startPreview = useMutation({
    mutationFn: () => api.startPackJob({ ...body, mode: "preview", paths: null }),
    onSuccess: (job) => {
      setPreviewId(job.id);
      setImportId(null);
      setSelected(new Set());
    },
  });
  const startImport = useMutation({
    mutationFn: () => api.startPackJob({ ...body, mode: "import", paths: [...selected] }),
    onSuccess: (job) => setImportId(job.id),
  });

  const items = preview.data?.result?.items ?? [];
  const pickable = (i: PackItem) => i.state === "ready" || untested;
  // Seed the selection once a preview finishes: the first `limit` importable rules that are not in the repo yet.
  const previewDone = preview.data?.state === "done" ? preview.data.id : null;
  useEffect(() => {
    if (previewDone) setSelected(new Set(items.filter((i) => pickable(i) && !i.exists).slice(0, Math.min(limit, max)).map((i) => i.path)));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [previewDone]);

  const toggle = (path: string) => {
    const next = new Set(selected);
    if (next.has(path)) next.delete(path);
    else if (next.size < Math.min(limit, max)) next.add(path);
    setSelected(next);
  };

  const created = (imported.data?.result?.items ?? []).filter((i) => i.draft_id);
  const onPreview = (e: FormEvent) => {
    e.preventDefault();
    if (!startPreview.isPending) startPreview.mutate();
  };
  const running = Boolean((preview.data && ACTIVE.has(preview.data.state)) || (imported.data && ACTIVE.has(imported.data.state)) || startPreview.isPending || startImport.isPending);

  return (
    <div className="mx-auto max-w-5xl px-4 py-8 sm:px-8">
      <PageHeader title={t("pk_title")} subtitle={t("pk_sub")} />
      {DEMO ? (
        <Card className="p-8 text-center text-sm text-muted">{t("demo_disabled")}</Card>
      ) : sources.error ? (
        <ErrorBox message={(sources.error as Error).message} />
      ) : sources.data && !sources.data.enabled ? (
        <Card className="flex flex-col items-center gap-3 p-10 text-center">
          <PackageOpen size={28} className="text-subtle" aria-hidden />
          <p className="font-medium text-text">{t("pk_off")}</p>
          <p className="max-w-md text-sm text-muted">{sources.data.reason}</p>
        </Card>
      ) : (
        <>
          <Card className="mb-5 p-5">
            <form onSubmit={onPreview} className="space-y-4">
              <div className="grid gap-4 sm:grid-cols-3">
                <label className="block space-y-1">
                  <span className="text-[13px] font-medium text-strong">{t("pk_source")}</span>
                  <select className={inputCls} disabled aria-label={t("pk_source")} value={src?.id ?? "sigmahq"} onChange={() => undefined}>
                    <option value={src?.id ?? "sigmahq"}>{src ? `${src.name} (${src.license})` : "SigmaHQ"}</option>
                  </select>
                </label>
                <label className="block space-y-1">
                  <span className="text-[13px] font-medium text-strong">{t("pk_ref")}</span>
                  <select className={inputCls} value={ref} onChange={(e) => setRef(e.target.value)}>
                    {(src?.refs ?? ["master"]).map((r) => (
                      <option key={r} value={r}>
                        {r}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="block space-y-1">
                  <span className="text-[13px] font-medium text-strong">{t("pk_limit")}</span>
                  <input type="number" min={1} max={max} value={limit} onChange={(e) => setLimit(Math.max(1, Math.min(max, Number(e.target.value) || 1)))} className={inputCls} />
                  <span className="block text-xs text-subtle">{t("pk_limit_hint", { n: max })}</span>
                </label>
              </div>
              <div className="grid gap-4 sm:grid-cols-4">
                {(
                  [
                    ["product", t("pk_product"), "windows"],
                    ["category", t("pk_category"), "process_creation"],
                    ["service", t("pk_service"), "sysmon"],
                    ["text", t("pk_text"), ""],
                  ] as const
                ).map(([k, label, ph]) => (
                  <label key={k} className="block space-y-1">
                    <span className="text-[13px] font-medium text-strong">{label}</span>
                    <input value={f[k]} onChange={(e) => setF({ ...f, [k]: e.target.value })} placeholder={ph} maxLength={k === "text" ? 200 : 100} className={inputCls} spellCheck={false} />
                  </label>
                ))}
              </div>
              <fieldset className="flex flex-wrap items-center gap-x-4 gap-y-2 text-[13px] text-muted">
                <legend className="sr-only">{t("pk_status")}</legend>
                <span className="font-medium text-strong">{t("pk_status")}</span>
                {STATUSES.map((s) => (
                  <label key={s} className="flex items-center gap-1.5">
                    <input type="checkbox" className="accent-accent" checked={statuses.includes(s)} onChange={(e) => setStatuses(e.target.checked ? [...statuses, s] : statuses.filter((x) => x !== s))} /> {s}
                  </label>
                ))}
                <label className="flex items-center gap-1.5">
                  <input type="checkbox" className="accent-accent" checked={untested} onChange={(e) => setUntested(e.target.checked)} /> {t("pk_untested")}
                </label>
              </fieldset>
              {src && <p className="text-xs text-subtle">{t("pk_license", { l: src.license })}</p>}
              {startPreview.error && <ErrorBox message={(startPreview.error as Error).message} />}
              <div className="flex flex-wrap gap-2">
                <button type="submit" disabled={!editor || running} className={btnPrimary} title={!editor ? t("pk_need_editor") : undefined}>
                  <Search size={15} aria-hidden /> {t("pk_preview")}
                </button>
                {!editor && <span className="self-center text-xs text-subtle">{t("pk_need_editor")}</span>}
              </div>
            </form>
          </Card>

          {preview.data && (
            <Card className="mb-5 space-y-3 p-5">
              <Progress job={preview.data} />
              {preview.data.error && <ErrorBox message={preview.data.error} />}
              {preview.data.state === "done" && (
                <>
                  <p className="text-sm text-muted">{t("pk_matched", { n: preview.data.result?.matched ?? 0, shown: items.length })}</p>
                  <div className="max-h-[420px] overflow-auto">
                    <table className="w-full text-left text-[13px]">
                      <thead className="sticky top-0 border-b border-line bg-surface text-[11.5px] uppercase tracking-wide text-subtle">
                        <tr>
                          <th className="w-8 py-2" />
                          <th className="py-2 pr-3 font-medium">{t("rule")}</th>
                          <th className="px-3 py-2 font-medium">{t("severity")}</th>
                          <th className="px-3 py-2 font-medium">{t("pk_cases")}</th>
                          <th className="py-2 pl-3 font-medium">{t("state")}</th>
                        </tr>
                      </thead>
                      <tbody>
                        {items.map((i) => (
                          <tr key={i.path} className="border-b border-line last:border-0">
                            <td className="py-2">
                              <input
                                type="checkbox"
                                className="accent-accent"
                                aria-label={i.title}
                                checked={selected.has(i.path)}
                                disabled={!pickable(i) || (!selected.has(i.path) && selected.size >= Math.min(limit, max))}
                                onChange={() => toggle(i.path)}
                              />
                            </td>
                            <td className="py-2 pr-3">
                              <span className="font-medium text-text">{i.title}</span>
                              <span className="block font-mono text-xs text-subtle">{i.path}</span>
                            </td>
                            <td className="px-3 py-2">
                              <LevelTag level={i.level} />
                            </td>
                            <td className="px-3 py-2 tabular-nums">{i.cases}</td>
                            <td className="py-2 pl-3 text-xs">
                              {i.exists ? (
                                <span className="inline-flex items-center gap-1 text-muted">
                                  <AlertTriangle size={12} aria-hidden /> {t("pk_exists")}
                                </span>
                              ) : i.state === "untested" ? (
                                <span className="inline-flex items-center gap-1 text-warn" title={i.reason ?? undefined}>
                                  <AlertTriangle size={12} aria-hidden /> {t("pk_untested_row")}
                                </span>
                              ) : (
                                <span className="inline-flex items-center gap-1 text-good">
                                  <CheckCircle2 size={12} aria-hidden /> {t("pk_ready")}
                                </span>
                              )}
                            </td>
                          </tr>
                        ))}
                        {items.length === 0 && (
                          <tr>
                            <td colSpan={5} className="py-6 text-center text-muted">
                              {t("pk_none")}
                            </td>
                          </tr>
                        )}
                      </tbody>
                    </table>
                  </div>
                  {startImport.error && <ErrorBox message={(startImport.error as Error).message} />}
                  <button type="button" disabled={!editor || selected.size === 0 || running} onClick={() => startImport.mutate()} className={btnPrimary}>
                    <Download size={15} aria-hidden /> {t("pk_import", { n: selected.size })}
                  </button>
                </>
              )}
            </Card>
          )}

          {imported.data && (
            <Card className="space-y-3 p-5">
              <Progress job={imported.data} />
              {imported.data.error && <ErrorBox message={imported.data.error} />}
              {imported.data.state === "done" && (
                <>
                  <h2 className="text-[15px] font-semibold text-strong">{t("pk_created", { n: created.length })}</h2>
                  <ul className="divide-y divide-line text-[13px]">
                    {created.map((i) => (
                      <li key={i.draft_id} className="flex flex-wrap items-center gap-x-3 gap-y-1 py-2">
                        <Link to={`/editor?draft=${i.draft_id}`} className="font-medium text-text hover:text-accent">
                          {i.title}
                        </Link>
                        <span className="font-mono text-xs text-subtle">{i.path}</span>
                      </li>
                    ))}
                  </ul>
                  {(imported.data.result?.skipped.length ?? 0) > 0 && (
                    <div>
                      <h3 className="text-[11px] font-semibold uppercase tracking-wider text-subtle">{t("pk_skipped")}</h3>
                      <ul className="mt-1 space-y-0.5 text-xs text-muted">
                        {imported.data.result?.skipped.map((s) => (
                          <li key={s.path}>
                            <span className="font-mono">{s.path}</span> — {s.reason}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                  {created.length > 0 && <PublishBatch ids={created.map((i) => i.draft_id!)} titles={Object.fromEntries(created.map((i) => [i.draft_id!, i.title]))} />}
                </>
              )}
            </Card>
          )}
        </>
      )}
    </div>
  );
}

function PublishBatch({ ids, titles }: { ids: string[]; titles: Record<string, string> }) {
  const [title, setTitle] = useState("");
  const publish = useMutation({ mutationFn: () => api.submitDrafts({ draft_ids: ids, title: title.trim() || null }) });
  const blocked: BlockedDraft[] = publish.error instanceof ApiError && publish.error.status === 422 && Array.isArray(publish.error.body?.blocked) ? (publish.error.body.blocked as BlockedDraft[]) : [];
  const sub: Submission | undefined = publish.data;
  return (
    <div className="space-y-3 border-t border-line pt-4">
      <h3 className="text-[15px] font-semibold text-strong">{t("pk_publish_title")}</h3>
      <p className="text-sm text-muted">{t("pk_publish_sub")}</p>
      <label className="block max-w-lg space-y-1">
        <span className="text-[13px] font-medium text-strong">{t("pull_request_title")}</span>
        <input value={title} onChange={(e) => setTitle(e.target.value)} maxLength={200} className={inputCls} />
      </label>
      {publish.error && <ErrorBox message={(publish.error as Error).message} />}
      {blocked.length > 0 && (
        <ul className="space-y-2 text-[13px]">
          {blocked.map((b) => (
            <li key={b.id} className="rounded-[10px] border border-bad/30 bg-bad-soft p-3">
              <Link to={`/editor?draft=${b.id}`} className="font-medium text-bad hover:underline">
                {titles[b.id] ?? b.path ?? b.id}
              </Link>
              <ul className="mt-1 list-disc pl-5 text-bad">
                {b.reasons.map((r) => (
                  <li key={r}>{r}</li>
                ))}
              </ul>
            </li>
          ))}
        </ul>
      )}
      {sub ? (
        <p className="flex flex-wrap items-center gap-2 text-sm text-good">
          <CheckCircle2 size={15} aria-hidden /> {t("pk_pushed", { b: sub.branch, n: sub.files.length })}
          {safeHref(sub.url) && (
            <a href={safeHref(sub.url)!} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-accent hover:underline">
              <ExternalLink size={13} aria-hidden /> {t("view_on_github")}
            </a>
          )}
        </p>
      ) : (
        <button type="button" disabled={publish.isPending} onClick={() => publish.mutate()} className={btnSecondary}>
          {publish.isPending ? <Loader2 size={15} className="animate-spin" aria-hidden /> : <Rocket size={15} aria-hidden />} {t("pk_publish_batch", { n: ids.length })}
        </button>
      )}
    </div>
  );
}
