import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, Loader2, Search, X } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { api } from "../api";
import type { DraftSummary } from "../types";
import { timeAgo } from "./dash";
import { ErrorBox, btnSecondary, inputCls } from "./ui";
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
      <li key={d.id} className="space-y-1.5 py-3">
        <div className="flex flex-wrap items-start justify-between gap-2">
          <div className="min-w-0">
            <p className="truncate text-[13.5px] font-semibold text-strong">{d.title}</p>
            <p className="text-xs text-subtle">
              {d.path && <span className="font-mono">{d.path} · </span>}
              <span title={new Date(d.updated_at).toLocaleString()}>{t("updated")} {timeAgo(d.updated_at)}</span>
              {!d.mine && d.author && ` · by ${d.author.name || d.author.email}`}
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
              Delete
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
      className="glass m-auto w-[min(560px,calc(100vw-32px))] rounded-2xl bg-surface p-0 text-text backdrop:bg-black/50"
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
          <p className="text-sm text-muted">{list.data.drafts.length ? t("l_no_draft_matches_the_search") : t("l_no_local_drafts_yet_use_save_local")}</p>
        )}
        <ul className="max-h-[50vh] divide-y divide-line overflow-auto">{rows.map(row)}</ul>
      </div>
    </dialog>
  );
}
