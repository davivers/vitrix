import { useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, CheckCircle2, Loader2, MessageSquareWarning, PencilLine, RefreshCw, Send } from "lucide-react";
import { useEffect } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "../api";
import { Diff } from "../components/Diff";
import { formatDate, timeAgo } from "../components/dash";
import { ReviewCard, ReviewStateBadge, Thread } from "../components/ReviewPanel";
import { Card, ErrorBox } from "../components/ui";
import { t } from "../i18n";

const EVENT_ICON: Record<string, typeof Send> = { requested: Send, rerequested: RefreshCw, changes_requested: MessageSquareWarning, approved: CheckCircle2, cancelled: PencilLine };
const EVENT_TEXT: Record<string, "rv_ev_requested" | "rv_ev_rerequested" | "rv_ev_changes_requested" | "rv_ev_approved" | "rv_ev_edited"> = {
  requested: "rv_ev_requested",
  rerequested: "rv_ev_rerequested",
  changes_requested: "rv_ev_changes_requested",
  approved: "rv_ev_approved",
  cancelled: "rv_ev_edited",
};

/** /reviews/:id: request, what changed since, decision and history. Opening it marks the review read. */
export default function ReviewPage() {
  const id = useParams().id ?? "";
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["review", id], queryFn: () => api.review(id), retry: false });
  const r = q.data;
  const target = r?.target;

  useEffect(() => {
    if (!r?.unread) return;
    void api
      .readReview(id)
      .then(() => {
        void qc.invalidateQueries({ queryKey: ["review-counts"] });
        void qc.invalidateQueries({ queryKey: ["reviews"] });
      })
      .catch(() => undefined);
  }, [id, r?.unread, qc]);

  if (q.isLoading) {
    return (
      <div className="p-8 text-muted">
        <Loader2 className="animate-spin" size={18} aria-label={t("loading")} />
      </div>
    );
  }
  if (q.error || !r || !target) {
    return (
      <div className="p-8">
        <ErrorBox message={(q.error as Error | null)?.message ?? t("rv_not_found")} />
      </div>
    );
  }
  const open = target.kind === "rule" ? `/editor/${target.ref}` : `/editor?draft=${target.ref}`;
  return (
    <div className="mx-auto max-w-4xl space-y-5 px-4 py-8 sm:px-8">
      <Link to="/reviews" className="inline-flex items-center gap-1.5 text-sm text-muted hover:text-text">
        <ArrowLeft size={14} aria-hidden /> {t("rv_my_reviews")}
      </Link>
      <header className="space-y-1">
        <h1 className="flex flex-wrap items-center gap-3 text-[24px] font-bold tracking-[-0.02em] text-strong">
          {target.title || target.ref} <ReviewStateBadge state={r.state} />
        </h1>
        <p className="text-sm text-muted">
          <span className="font-mono">{target.ref}</span> · {target.kind === "rule" ? t("rv_kind_rule") : t("rv_kind_draft")} · {t("rv_requested_by", { a: r.requester.name, ago: timeAgo(r.created_at) })}
        </p>
        {!target.missing && (
          <Link to={open} className="text-sm font-medium text-accent hover:underline">
            {t("rv_open_editor")}
          </Link>
        )}
      </header>
      {(r.diff_too_large || (r.base_text != null && r.current_text != null)) && (
        <section aria-labelledby="rv-diff">
          <h2 id="rv-diff" className="mb-2 text-[15px] font-semibold text-strong">
            {t("rv_changes_since")}
          </h2>
          {r.diff_too_large ? <p className="text-sm text-muted">{t("df_too_large")}</p> : <Diff before={r.base_text ?? ""} after={r.current_text ?? ""} />}
        </section>
      )}
      <section aria-labelledby="rv-decide">
        <h2 id="rv-decide" className="mb-2 text-[15px] font-semibold text-strong">
          {t("rv_decision")}
        </h2>
        <ReviewCard review={r} />
      </section>
      {!target.missing && (
        <section aria-labelledby="rv-discussion">
          <h2 id="rv-discussion" className="mb-2 text-[15px] font-semibold text-strong">
            {t("rv_discussion")}
          </h2>
          <Thread kind={target.kind} target={target.ref} />
        </section>
      )}
      {(r.events?.length ?? 0) > 0 && (
        <section aria-labelledby="rv-history">
          <h2 id="rv-history" className="mb-2 text-[15px] font-semibold text-strong">
            {t("rv_history")}
          </h2>
          <Card className="p-4">
            <ol className="space-y-2 text-[13px]">
              {r.events!.map((e, i) => {
                const Icon = EVENT_ICON[e.type] ?? Send;
                return (
                  <li key={i} className="flex items-start gap-2">
                    <Icon size={14} className="mt-0.5 shrink-0 text-muted" aria-hidden />
                    <span className="min-w-0 flex-1 text-text">
                      <span className="font-medium">{e.actor?.name ?? ""}</span> {EVENT_TEXT[e.type] ? t(EVENT_TEXT[e.type]) : e.type}
                      {e.text && <span className="block text-muted">{e.text}</span>}
                    </span>
                    <time className="shrink-0 text-xs text-subtle" dateTime={e.at} title={formatDate(e.at)}>
                      {timeAgo(e.at)}
                    </time>
                  </li>
                );
              })}
            </ol>
          </Card>
        </section>
      )}
    </div>
  );
}
