import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, CheckCircle2, FilePen, Loader2, Minus, Search, Trash2, X, XCircle } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { api } from "../api";
import type { DraftSummary } from "../types";
import { timeAgo } from "./dash";
import { ErrorBox, LevelTag, btnPrimary, btnSecondary, inputCls } from "./ui";
import { t } from "../i18n";

/** Local drafts (SQLite on this machine): search, open, delete. A modal dialog, so Esc closes it. */
export function DraftsSheet(props: { dirty: boolean; isAdmin: boolean; currentId: string | null; onOpen: (id: string) => void; onDeleted: (id: string) => void; onClose: () => void }) {
  const { dirty, isAdmin, currentId, onOpen, onDeleted, onClose } = props;
  const ref = useRef<HTMLDialogElement>(null);
  const qc = useQueryClient();
  const list = useQuery({ queryKey: ["drafts"], queryFn: api.drafts, retry: false });
  const [needle, setNeedle] = useState("");
  const [confirmOpen, setConfirmOpen] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null);
  const del = useMutation({
    mutationFn: (id: string) => api.deleteDraft(id),
    onSuccess: (_, id) => {
      setConfirmDelete(null);
      onDeleted(id);
      void qc.invalidateQueries({ queryKey: ["drafts"] });
    },
  });

  useEffect(() => {
    const dlg = ref.current;
    if (dlg && !dlg.open) dlg.showModal();
  }, []);

  const q = needle.trim().toLowerCase();
  const rows = (list.data?.drafts ?? []).filter((d) => !q || [d.title, d.path ?? ""].some((s) => s.toLowerCase().includes(q)));

  const row = (d: DraftSummary) => {
    const canDelete = d.mine || isAdmin;
    return (
      <li key={d.id} className={`space-y-1.5 rounded-xl border border-line p-3 ${d.id === currentId ? "bg-accent-soft" : "bg-surface hover:bg-surface-2"}`}>
        <div className="flex flex-wrap items-start justify-between gap-2">
          <div className="min-w-0">
            <h3 className="flex flex-wrap items-center gap-2 truncate text-[14px] font-semibold text-strong">
              {d.title || t("dr_untitled")}
              {d.id === currentId && <span className="rounded bg-accent px-1.5 py-0.5 text-[10.5px] font-semibold uppercase text-on-brand">{t("dr_current")}</span>}
            </h3>
            <p className="text-xs text-subtle">
              {d.path ? <span className="font-mono">{d.path} · </span> : <span>{t("dr_no_file")} · </span>}
              <span title={new Date(d.updated_at).toLocaleString()}>{t("updated")} {timeAgo(d.updated_at)}</span>
              {!d.mine && d.author && ` · by ${d.author.name || d.author.email}`}
            </p>
            <p className="mt-1 flex flex-wrap items-center gap-2 text-xs">
              {d.quality ? (
                d.quality.ready ? (
                  <span className="inline-flex items-center gap-1 text-good"><CheckCircle2 size={12} aria-hidden /> {t("dr_gate_ready")}</span>
                ) : (
                  <span className="inline-flex items-center gap-1 text-bad"><XCircle size={12} aria-hidden /> {t("dr_blockers", { n: d.quality.blockers })}</span>
                )
              ) : (
                <span className="inline-flex items-center gap-1 text-muted"><Minus size={12} aria-hidden /> {t("dr_not_checked")}</span>
              )}
              {d.level && <LevelTag level={d.level} />}
              {d.target && <span className="rounded bg-surface-2 px-1.5 py-0.5 font-mono text-[10.5px] text-muted">{d.target}</span>}
            </p>
            {d.stale && (
              <p className="mt-0.5 flex items-center gap-1 text-xs text-warn">
                <AlertTriangle size={12} aria-hidden /> {t("rule_changed_in_the_repo_since_this_dr")}
              </p>
            )}
          </div>
          <div className="flex shrink-0 gap-1.5">
            <button
              type="button"
              className={btnSecondary}
              onClick={() => (dirty && d.id !== currentId ? setConfirmOpen(d.id) : onOpen(d.id))}
            >
              Open
            </button>
            <button
              type="button"
              className={btnSecondary}
              aria-disabled={!canDelete}
              aria-describedby={canDelete ? undefined : `nodel-${d.id}`}
              onClick={() => canDelete && setConfirmDelete(d.id)}
              style={canDelete ? undefined : { opacity: 0.5, cursor: "not-allowed" }}
            >
              <Trash2 size={13} aria-hidden /> {t("dr_discard")}
            </button>
          </div>
        </div>
        {!canDelete && (
          <p id={`nodel-${d.id}`} className="text-xs text-subtle">
            {t("only_the_author_or_an_admin_can_delete")}
          </p>
        )}
        {confirmOpen === d.id && (
          <p className="flex flex-wrap items-center gap-2 text-xs text-text">
            {t("replace_the_current_editor_content_wit")}
            <button type="button" className="font-semibold text-accent hover:underline" onClick={() => onOpen(d.id)}>
              {t("replace")}
            </button>
            <button type="button" className="text-muted hover:text-text" onClick={() => setConfirmOpen(null)}>
              {t("cancel")}
            </button>
          </p>
        )}
        {confirmDelete === d.id && (
          <p className="flex flex-wrap items-center gap-2 text-xs text-text">
            {t("delete_this_draft_this_cannot_be_undon")}
            <button type="button" disabled={del.isPending} className="font-semibold text-bad hover:underline" onClick={() => del.mutate(d.id)}>
              {del.isPending ? t("l_deleting") : "Delete"}
            </button>
            <button type="button" className="text-muted hover:text-text" onClick={() => setConfirmDelete(null)}>
              {t("cancel")}
            </button>
          </p>
        )}
      </li>
    );
  };

  return (
    <dialog
      ref={ref}
      onClose={onClose}
      aria-labelledby="drafts-title"
      className="glass m-auto w-[min(720px,calc(100vw-32px))] rounded-2xl bg-surface p-0 text-text backdrop:bg-black/50"
    >
      <div className="space-y-4 p-6">
        <div className="flex items-start justify-between gap-4">
          <h2 id="drafts-title" className="text-lg font-semibold text-strong">
            {t("local_drafts")}
          </h2>
          <button type="button" onClick={onClose} aria-label={t("close")} className="rounded-md p-1 text-muted hover:bg-surface-2 hover:text-text">
            <X size={18} aria-hidden />
          </button>
        </div>
        <p className="text-sm text-muted">{t("dr_intro")}</p>
        <label className="relative block">
          <span className="sr-only">{t("search_drafts")}</span>
          <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-subtle" aria-hidden />
          <input value={needle} onChange={(e) => setNeedle(e.target.value)} placeholder={t("search_drafts")} className={`${inputCls} pl-9`} />
        </label>
        {list.isLoading && (
          <p className="flex items-center gap-2 text-sm text-muted">
            <Loader2 size={14} className="animate-spin" aria-hidden /> {t("loading")}
          </p>
        )}
        {list.error && <ErrorBox message={(list.error as Error).message} />}
        {del.error && <ErrorBox message={(del.error as Error).message} />}
        {list.data && !list.data.enabled && <p className="text-sm text-muted">{list.data.reason ?? t("l_local_drafts_are_off")}</p>}
        {list.data?.enabled && rows.length === 0 && (
          list.data.drafts.length ? (
            <p className="text-sm text-muted">{t("l_no_draft_matches_the_search")}</p>
          ) : (
            <div className="flex flex-col items-center gap-2 py-6 text-center">
              <FilePen size={26} className="text-subtle" aria-hidden />
              <p className="font-medium text-text">{t("dr_empty")}</p>
              <p className="max-w-sm text-sm text-muted">{t("dr_empty_sub")}</p>
              <button type="button" className={btnPrimary} onClick={onClose}>
                {t("new_rule")}
              </button>
            </div>
          )
        )}
        <ul aria-label={`${t("drafts")}, ${rows.length}`} className="max-h-[55vh] space-y-2 overflow-auto">{rows.map(row)}</ul>
      </div>
    </dialog>
  );
}
