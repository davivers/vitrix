import { useQuery } from "@tanstack/react-query";
import clsx from "clsx";
import { ArrowDown, ArrowUp, Equal, GitCompare, Loader2, Minus, Plus, type LucideIcon } from "lucide-react";
import { useState, type FormEvent } from "react";
import { ApiError, api } from "../api";
import type { DriftState } from "../types";
import { t } from "../i18n";
import { ErrorBox, btnSecondary, inputCls } from "./ui";

const STATE: Record<DriftState, { label: () => string; Icon: LucideIcon }> = {
  more: { label: () => t("dr_more"), Icon: ArrowUp },
  fewer: { label: () => t("dr_fewer"), Icon: ArrowDown },
  added: { label: () => t("dr_added"), Icon: Plus },
  removed: { label: () => t("dr_removed"), Icon: Minus },
  same: { label: () => t("dr_same"), Icon: Equal },
};

/** Drift is information, not pass/fail: neutral chip, always icon + text. */
export function DriftBadge({ state, modified }: { state: DriftState; modified?: boolean }) {
  const { label, Icon } = STATE[state];
  return (
    <span className={clsx("inline-flex items-center gap-1.5 rounded-full bg-surface-3 px-2.5 py-1 text-xs font-medium", state === "same" ? "text-muted" : "text-strong")}>
      <Icon size={13} aria-hidden /> {label()}
      {modified && <span className="text-accent">· {t("dr_modified")}</span>}
    </span>
  );
}

export const count = (n: number | null) => (n === null ? "—" : n);

/** 409 = not a Git repo, 422 = bad ref; the server text says which, we only add the likely remedy. */
export function driftErrorMessage(e: unknown): string {
  if (e instanceof ApiError && e.status === 409) return `${t("dr_not_git")} ${e.message}`;
  if (e instanceof ApiError && e.status === 422) return `${t("dr_bad_ref")} ${e.message}`;
  return (e as Error).message;
}

/** Match counts of the current rule at a Git ref versus now, per replay dataset. */
export function DriftPanel({ ruleId }: { ruleId: string }) {
  const [ref, setRef] = useState("");
  const [applied, setApplied] = useState<string | null>(null);
  const { data, error, isFetching } = useQuery({ queryKey: ["drift", applied, ruleId], queryFn: () => api.drift(applied, ruleId), retry: false });
  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    setApplied(ref.trim() || null);
  };
  const row = data?.rules.find((r) => r.rule === ruleId);
  return (
    <div className="space-y-3">
      <form onSubmit={onSubmit} className="flex flex-wrap items-end gap-2">
        <label className="block min-w-48 flex-1 space-y-1">
          <span className="text-[13px] font-medium text-strong">{t("dr_ref")}</span>
          <input value={ref} onChange={(e) => setRef(e.target.value)} placeholder={t("dr_ref_ph")} className={inputCls} maxLength={200} spellCheck={false} />
        </label>
        <button type="submit" disabled={isFetching} className={btnSecondary}>
          {isFetching ? <Loader2 size={14} className="animate-spin" aria-hidden /> : <GitCompare size={14} aria-hidden />} {t("dr_compare")}
        </button>
      </form>
      {error && <ErrorBox message={driftErrorMessage(error)} />}
      {isFetching && !data && <p className="text-sm text-muted">{t("dr_running")}</p>}
      {data && (
        <>
          <p className="text-[13px] text-muted">
            {t("dr_vs")} <span className="font-mono text-text">{data.ref}</span> <span className="font-mono text-xs text-subtle">{data.sha.slice(0, 8)}</span>
          </p>
          {!row ? (
            <p className="text-sm text-muted">{t("dr_no_row")}</p>
          ) : (
            <>
              <div className="flex flex-wrap items-center gap-3 text-sm">
                <DriftBadge state={row.state} modified={row.modified} />
                <span className="tabular-nums text-text">
                  {count(row.before)} → {count(row.after)}
                  {row.delta !== 0 && <span className="ml-1 text-muted">({row.delta > 0 ? "+" : ""}{row.delta})</span>}
                </span>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-[13px]">
                  <thead className="border-b border-line text-[11.5px] uppercase tracking-wide text-subtle">
                    <tr>
                      <th className="py-2 pr-3 font-medium">{t("dr_dataset")}</th>
                      <th className="px-3 py-2 text-right font-medium">{t("dr_events")}</th>
                      <th className="px-3 py-2 text-right font-medium">{t("dr_before")}</th>
                      <th className="px-3 py-2 text-right font-medium">{t("dr_after")}</th>
                      <th className="py-2 pl-3 font-medium">{t("state")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.datasets.map((d) => {
                      const r = d.rules[0];
                      return (
                        <tr key={d.dataset} className="border-b border-line last:border-0">
                          <td className="py-2 pr-3 font-mono text-xs">{d.dataset}</td>
                          <td className="px-3 py-2 text-right tabular-nums">{d.events}</td>
                          {d.error || r?.error ? (
                            <td colSpan={3} className="py-2 pl-3 text-xs text-bad">
                              {d.error ?? r?.error}
                            </td>
                          ) : r ? (
                            <>
                              <td className="px-3 py-2 text-right tabular-nums">{count(r.before)}</td>
                              <td className="px-3 py-2 text-right tabular-nums">{count(r.after)}</td>
                              <td className="py-2 pl-3">
                                <DriftBadge state={r.state} />
                              </td>
                            </>
                          ) : (
                            <td colSpan={3} className="py-2 pl-3 text-xs text-subtle">
                              —
                            </td>
                          )}
                        </tr>
                      );
                    })}
                    {data.datasets.length === 0 && (
                      <tr>
                        <td colSpan={5} className="py-3 text-sm text-muted">
                          {t("dr_no_datasets")}
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </>
      )}
    </div>
  );
}
