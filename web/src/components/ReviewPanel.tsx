import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, CheckCircle2, Clock, Loader2, MessageSquare, MessageSquareWarning, Send, Trash2, UserCheck, XCircle, type LucideIcon } from "lucide-react";
import { useState, type FormEvent } from "react";
import { ApiError, api } from "../api";
import type { Review, ReviewState } from "../types";
import { t } from "../i18n";
import { can, useMe } from "./auth";
import { formatDate, timeAgo } from "./dash";
import { ErrorBox, btnPrimary, btnSecondary, inputCls } from "./ui";

const STATE: Record<ReviewState, { label: () => string; cls: string; Icon: LucideIcon }> = {
  pending: { label: () => t("rv_pending"), cls: "bg-warn-soft text-warn", Icon: Clock },
  approved: { label: () => t("rv_approved"), cls: "bg-good-soft text-good", Icon: CheckCircle2 },
  changes_requested: { label: () => t("rv_changes"), cls: "bg-bad-soft text-bad", Icon: MessageSquareWarning },
  cancelled: { label: () => t("rv_cancelled"), cls: "bg-surface-3 text-muted", Icon: XCircle },
};

/** Review state is always icon + text. */
export function ReviewStateBadge({ state }: { state: ReviewState }) {
  const { label, cls, Icon } = STATE[state];
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-medium ${cls}`}>
      <Icon size={14} aria-hidden /> {label()}
    </span>
  );
}

/** Owner and review_by live in the rule's `vitrix:` block; read-only here. */
export function parseGovernance(text: string): { owner: string | null; review_by: string | null } {
  const block = /^vitrix:[ \t]*\r?\n((?:[ \t]+.*(?:\r?\n|$))*)/m.exec(text)?.[1] ?? "";
  const get = (key: string) => {
    const v = new RegExp(`^[ \\t]+${key}:[ \\t]*(.*?)[ \\t]*$`, "m").exec(block)?.[1]?.replace(/^["']|["']$/g, "");
    return v ? v : null;
  };
  return { owner: get("owner"), review_by: get("review_by") };
}

function invalidate(qc: ReturnType<typeof useQueryClient>) {
  void qc.invalidateQueries({ queryKey: ["reviews"] });
  void qc.invalidateQueries({ queryKey: ["review-counts"] });
  void qc.invalidateQueries({ queryKey: ["comments"] });
}

/** One review with the actions the signed-in person may take (server re-checks every one). */
export function ReviewCard({ review }: { review: Review }) {
  const qc = useQueryClient();
  const [note, setNote] = useState("");
  const open = review.state === "pending" || review.state === "changes_requested";
  const act = useMutation({
    mutationFn: (kind: "approved" | "changes_requested" | "rerequest" | "cancel") =>
      kind === "rerequest"
        ? api.rerequestReview(review.id, review.version)
        : kind === "cancel"
          ? api.cancelReview(review.id, review.version)
          : api.decideReview(review.id, { decision: kind, note: note.trim() || null, version: review.version }),
    onSuccess: () => {
      setNote("");
      invalidate(qc);
    },
    onError: (e) => {
      if (e instanceof ApiError && e.status === 409) invalidate(qc); // someone else moved first or the target changed: show the fresh state
    },
  });
  const err = act.error as Error | null;
  return (
    <div className="space-y-2 rounded-[10px] border border-line bg-surface p-3 text-[13px]">
      <div className="flex flex-wrap items-center gap-2">
        <ReviewStateBadge state={review.state} />
        <span className="text-muted">
          {review.requester.name} → <span className="font-medium text-text">{review.reviewer.name}</span>
        </span>
        <span className="ml-auto text-xs text-subtle" title={formatDate(review.updated_at)}>
          {timeAgo(review.updated_at)}
        </span>
      </div>
      {review.note && <p className="whitespace-pre-wrap text-text">{review.note}</p>}
      {review.decision_note && (
        <p className="whitespace-pre-wrap border-l-2 border-line pl-2 text-muted">
          <span className="font-medium text-text">{review.reviewer.name}:</span> {review.decision_note}
        </p>
      )}
      {review.stale && open && (
        <p className="flex items-start gap-1.5 text-warn">
          <AlertTriangle size={14} className="mt-0.5 shrink-0" aria-hidden /> {t("rv_stale")}
        </p>
      )}
      {open && review.mine_to_review && review.state === "pending" && !review.stale && (
        <div className="space-y-2">
          <label className="block">
            <span className="sr-only">{t("rv_decision_note")}</span>
            <textarea value={note} onChange={(e) => setNote(e.target.value)} rows={2} maxLength={2000} placeholder={t("rv_decision_note")} className={inputCls} />
          </label>
          <div className="flex flex-wrap gap-2">
            <button type="button" disabled={act.isPending} onClick={() => act.mutate("approved")} className={btnPrimary}>
              <CheckCircle2 size={14} aria-hidden /> {t("rv_approve")}
            </button>
            <button type="button" disabled={act.isPending} onClick={() => act.mutate("changes_requested")} className={btnSecondary}>
              <MessageSquareWarning size={14} aria-hidden /> {t("rv_request_changes")}
            </button>
          </div>
        </div>
      )}
      {open && review.mine_requested && (
        <div className="flex flex-wrap gap-2">
          {(review.stale || review.state === "changes_requested") && (
            <button type="button" disabled={act.isPending} onClick={() => act.mutate("rerequest")} className={btnSecondary}>
              <Send size={14} aria-hidden /> {t("rv_rerequest")}
            </button>
          )}
          <button type="button" disabled={act.isPending} onClick={() => act.mutate("cancel")} className={btnSecondary}>
            {t("rv_cancel")}
          </button>
        </div>
      )}
      {err && <ErrorBox message={err instanceof ApiError && err.status === 409 ? `${t("rv_conflict")} ${err.message}` : err.message} />}
    </div>
  );
}

function RequestForm({ kind, target }: { kind: "rule" | "draft"; target: string }) {
  const qc = useQueryClient();
  const reviewers = useQuery({ queryKey: ["reviewers"], queryFn: api.reviewers, retry: false });
  const [who, setWho] = useState("");
  const [note, setNote] = useState("");
  const send = useMutation({
    mutationFn: () => api.requestReview({ target_kind: kind, target_ref: target, reviewer_id: Number(who), note: note.trim() || null }),
    onSuccess: () => {
      setNote("");
      setWho("");
      invalidate(qc);
    },
  });
  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    if (who && !send.isPending) send.mutate();
  };
  return (
    <form onSubmit={onSubmit} className="space-y-2">
      <h4 className="text-[11px] font-semibold uppercase tracking-wider text-subtle">{t("rv_request")}</h4>
      <label className="block space-y-1">
        <span className="text-[13px] font-medium text-strong">{t("rv_reviewer")}</span>
        <select value={who} onChange={(e) => setWho(e.target.value)} className={inputCls} required>
          <option value="">{t("rv_pick")}</option>
          {(reviewers.data ?? []).map((r) => (
            <option key={r.id} value={r.id}>
              {r.name} ({r.email})
            </option>
          ))}
        </select>
      </label>
      {reviewers.data?.length === 0 && <p className="text-xs text-subtle">{t("rv_no_reviewers")}</p>}
      <label className="block">
        <span className="sr-only">{t("rv_note")}</span>
        <textarea value={note} onChange={(e) => setNote(e.target.value)} rows={2} maxLength={2000} placeholder={t("rv_note")} className={inputCls} />
      </label>
      {send.error && <ErrorBox message={(send.error as Error).message} />}
      <button type="submit" disabled={!who || send.isPending} className={btnPrimary}>
        {send.isPending ? <Loader2 size={14} className="animate-spin" aria-hidden /> : <UserCheck size={14} aria-hidden />} {t("rv_request")}
      </button>
    </form>
  );
}

function Thread({ kind, target }: { kind: "rule" | "draft"; target: string }) {
  const qc = useQueryClient();
  const comments = useQuery({ queryKey: ["comments", kind, target], queryFn: () => api.comments(kind, target), retry: false });
  const [body, setBody] = useState("");
  const add = useMutation({
    mutationFn: () => api.addComment({ target_kind: kind, target_ref: target, body: body.trim() }),
    onSuccess: () => {
      setBody("");
      invalidate(qc);
    },
  });
  const remove = useMutation({ mutationFn: (id: string) => api.deleteComment(id), onSuccess: () => invalidate(qc) });
  const list = comments.data?.comments ?? [];
  return (
    <div className="space-y-2">
      <h4 className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-subtle">
        <MessageSquare size={13} aria-hidden /> {t("rv_comments")} ({list.length})
      </h4>
      {comments.error && <ErrorBox message={(comments.error as Error).message} />}
      <ul className="space-y-2">
        {list.map((c) => (
          <li key={c.id} className="rounded-[10px] border border-line bg-surface p-2.5 text-[13px]">
            <div className="flex flex-wrap items-center gap-x-2 text-xs text-subtle">
              <span className="font-medium text-text">{c.author.name}</span>
              <span title={formatDate(c.created_at)}>{timeAgo(c.created_at)}</span>
              {c.outdated && (
                <span className="inline-flex items-center gap-1 text-warn">
                  <AlertTriangle size={12} aria-hidden /> {t("rv_outdated")}
                </span>
              )}
              {c.mine && !c.deleted && (
                <button type="button" onClick={() => remove.mutate(c.id)} aria-label={t("rv_delete_comment")} className="ml-auto rounded p-1 text-muted hover:bg-surface-2 hover:text-bad">
                  <Trash2 size={13} aria-hidden />
                </button>
              )}
            </div>
            <p className={`mt-1 whitespace-pre-wrap ${c.deleted ? "italic text-subtle" : "text-text"}`}>{c.deleted ? t("rv_deleted") : c.body}</p>
          </li>
        ))}
        {!comments.isLoading && list.length === 0 && <li className="text-sm text-muted">{t("rv_no_comments")}</li>}
      </ul>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (body.trim() && !add.isPending) add.mutate();
        }}
        className="space-y-2"
      >
        <label className="block">
          <span className="sr-only">{t("rv_add_comment")}</span>
          <textarea value={body} onChange={(e) => setBody(e.target.value)} rows={2} maxLength={4000} placeholder={t("rv_add_comment")} className={inputCls} />
        </label>
        {add.error && <ErrorBox message={(add.error as Error).message} />}
        <button type="submit" disabled={!body.trim() || add.isPending} className={btnSecondary}>
          <Send size={14} aria-hidden /> {t("rv_post")}
        </button>
      </form>
    </div>
  );
}

/** Editor side panel for a rule or a saved draft. `target` is the rule id (`windows/x.yml`) or the draft id. */
export function ReviewPanel({ kind, target, ruleText }: { kind: "rule" | "draft"; target: string | null; ruleText: string }) {
  const me = useMe();
  const gov = parseGovernance(ruleText);
  const reviews = useQuery({ queryKey: ["reviews", "target", kind, target], queryFn: () => api.reviews({ scope: "all", state: "open", kind, ref: target ?? "" }), enabled: me.enabled && target !== null, retry: false });
  const off = !me.enabled ? t("rv_need_accounts") : reviews.data && !reviews.data.enabled ? (reviews.data.reason ?? t("rv_need_accounts")) : null;

  return (
    <div className="space-y-4">
      <dl className="grid grid-cols-[7rem_1fr] gap-y-1 text-[13px]">
        <dt className="text-subtle">{t("rv_owner")}</dt>
        <dd className="text-text">{gov.owner ?? "—"}</dd>
        <dt className="text-subtle">{t("rv_review_by")}</dt>
        <dd className="text-text">{gov.review_by ?? "—"}</dd>
      </dl>
      <p className="text-xs text-subtle">{t("rv_gov_hint")}</p>
      {off ? (
        <div className="flex items-start gap-2 rounded-[10px] border border-dashed border-line p-4 text-sm text-muted">
          <UserCheck size={18} className="mt-0.5 shrink-0 text-subtle" aria-hidden />
          <div>
            <p className="font-medium text-text">{t("rv_need_accounts")}</p>
            <p className="mt-0.5">{off}</p>
          </div>
        </div>
      ) : target === null ? (
        <p className="text-sm text-muted">{t("rv_save_first")}</p>
      ) : (
        <>
          {reviews.error && <ErrorBox message={(reviews.error as Error).message} />}
          {(reviews.data?.reviews ?? []).map((r) => (
            <ReviewCard key={r.id} review={r} />
          ))}
          {can(me, "editor") && <RequestForm kind={kind} target={target} />}
          <Thread kind={kind} target={target} />
        </>
      )}
    </div>
  );
}
