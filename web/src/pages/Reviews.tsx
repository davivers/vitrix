import { useQuery } from "@tanstack/react-query";
import clsx from "clsx";
import { UserCheck } from "lucide-react";
import { Link, useSearchParams } from "react-router-dom";
import { api } from "../api";
import { useMe } from "../components/auth";
import { ReviewCard } from "../components/ReviewPanel";
import { Card, ErrorBox, PageHeader } from "../components/ui";
import { t } from "../i18n";

export default function ReviewsPage() {
  const me = useMe();
  const [params, setParams] = useSearchParams();
  const scope = params.get("tab") === "requested" ? "requested" : "to_review";
  const { data, error, isLoading } = useQuery({ queryKey: ["reviews", "page", scope], queryFn: () => api.reviews({ scope, state: "open" }), enabled: me.enabled, retry: false });
  const counts = useQuery({ queryKey: ["review-counts"], queryFn: api.reviewCounts, enabled: me.enabled, retry: false });
  const off = !me.enabled ? t("rv_need_accounts") : data && !data.enabled ? (data.reason ?? t("rv_need_accounts")) : null;

  return (
    <div className="mx-auto max-w-4xl px-4 py-8 sm:px-8">
      <PageHeader title={t("rv_my_reviews")} subtitle={t("rv_page_sub")} />
      {off ? (
        <Card className="flex flex-col items-center gap-3 p-10 text-center">
          <UserCheck size={28} className="text-subtle" aria-hidden />
          <p className="font-medium text-text">{t("rv_need_accounts")}</p>
          <p className="max-w-md text-sm text-muted">{off}</p>
        </Card>
      ) : (
        <>
          <div className="mb-4 flex gap-1 border-b border-line" role="tablist" aria-label={t("rv_my_reviews")}>
            {(
              [
                ["to_review", t("rv_to_review"), counts.data?.to_review],
                ["requested", t("rv_requested"), counts.data?.requested],
              ] as const
            ).map(([key, label, n]) => (
              <button
                key={key}
                type="button"
                role="tab"
                aria-selected={scope === key}
                onClick={() => setParams(key === "to_review" ? {} : { tab: key }, { replace: true })}
                className={clsx("-mb-px border-b-2 px-3 py-2 text-sm", scope === key ? "border-accent font-semibold text-strong" : "border-transparent text-muted hover:text-text")}
              >
                {label}
                {n ? <span className="ml-1.5 tabular-nums text-muted">({n})</span> : null}
              </button>
            ))}
          </div>
          {error && <ErrorBox message={(error as Error).message} />}
          {isLoading && <p className="text-sm text-muted">{t("loading")}</p>}
          <ul className="space-y-3">
            {(data?.reviews ?? []).map((r) => (
              <li key={r.id}>
                <div className="mb-1 flex flex-wrap items-baseline gap-2 text-sm">
                  {r.target.missing ? (
                    <span className="font-semibold text-muted">{r.target.title || r.target.ref}</span>
                  ) : (
                    <Link to={r.target.kind === "rule" ? `/editor/${r.target.ref}` : `/editor?draft=${r.target.ref}`} className="font-semibold text-strong hover:text-accent">
                      {r.target.title || r.target.ref}
                    </Link>
                  )}
                  <span className="text-xs text-subtle">{r.target.kind === "rule" ? t("rv_kind_rule") : t("rv_kind_draft")}</span>
                  {r.target.missing && <span className="text-xs text-warn">{t("rv_missing")}</span>}
                </div>
                <ReviewCard review={r} />
              </li>
            ))}
            {data?.enabled && data.reviews.length === 0 && (
              <li>
                <Card className="p-8 text-center text-sm text-muted">{scope === "to_review" ? t("rv_none_to_review") : t("rv_none_requested")}</Card>
              </li>
            )}
          </ul>
        </>
      )}
    </div>
  );
}
