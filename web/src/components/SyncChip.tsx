import { useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, ArrowDown, ArrowUp, CheckCircle2, CloudOff, Loader2, RefreshCw, XCircle } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { DEMO, api } from "../api";
import { can, useMe } from "./auth";
import { timeAgo } from "./dash";
import { toast } from "./Toast";
import type { SyncStatus } from "../types";
import { tn, t } from "../i18n";

/**
 * GitHub sync (ADR 0006): trigger on load and window focus (the server throttles), poll while a fetch runs,
 * and when HEAD moved refresh every rule/activity query and say what changed.
 */
export function useSync() {
  const qc = useQueryClient();
  const head = useRef<string | null | undefined>(undefined);
  const q = useQuery({
    queryKey: ["sync"],
    queryFn: api.syncStatus,
    enabled: !DEMO,
    retry: false,
    refetchInterval: (query) => (query.state.data?.fetching ? 2000 : false),
  });

  useEffect(() => {
    if (DEMO) return;
    const fire = () => void api.syncTrigger().then((s) => qc.setQueryData(["sync"], s)).catch(() => undefined);
    fire();
    const onFocus = () => document.visibilityState === "visible" && fire();
    window.addEventListener("focus", onFocus);
    document.addEventListener("visibilitychange", onFocus);
    return () => {
      window.removeEventListener("focus", onFocus);
      document.removeEventListener("visibilitychange", onFocus);
    };
  }, [qc]);

  const cur = q.data?.head;
  useEffect(() => {
    if (q.data === undefined) return;
    if (head.current !== undefined && cur !== head.current) {
      void qc.invalidateQueries({ predicate: (x) => x.queryKey[0] !== "sync" && x.queryKey[0] !== "me" });
      const n = q.data.changed_rules.length;
      if (n > 0) toast(t("sync_toast", { n }), { to: "/rules", label: t("sync_view_rules") });
    }
    head.current = cur;
  }, [cur, q.data, qc]);
  return q;
}

function view(s: SyncStatus): { Icon: typeof CheckCircle2; text: string; tone: string } {
  if (s.conflicts.length > 0) return { Icon: XCircle, text: tn("sync_conflicts", s.conflicts.length), tone: "text-bad" };
  switch (s.state) {
    case "synced":
      return { Icon: CheckCircle2, text: t("sync_synced"), tone: "text-good" };
    case "behind":
      return { Icon: ArrowDown, text: t("sync_behind", { n: s.behind }), tone: "text-warn" };
    case "ahead":
      return { Icon: ArrowUp, text: t("sync_ahead", { n: s.ahead }), tone: "text-muted" };
    case "diverged":
      return { Icon: AlertTriangle, text: t("sync_diverged"), tone: "text-warn" };
    case "no_remote":
      return { Icon: CloudOff, text: t("sync_no_remote"), tone: "text-muted" };
    case "no_commits":
      return { Icon: CloudOff, text: t("sync_no_commits"), tone: "text-muted" };
    case "error":
      return { Icon: XCircle, text: t("sync_error"), tone: "text-bad" };
    default:
      return { Icon: CloudOff, text: t("sync_off"), tone: "text-muted" };
  }
}

/** Sidebar footer chip: state + "last sync", details and "Sync now" (editor+) in a popover. */
export function SyncChip() {
  const me = useMe();
  const qc = useQueryClient();
  const q = useSync();
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const s = q.data;
  if (DEMO || !s) return null;
  const v = view(s);
  const now = async () => {
    setBusy(true);
    try {
      qc.setQueryData(["sync"], await api.syncTrigger(true));
    } catch {
      /* the chip keeps the last known state */
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="relative mt-2 px-1 lg:px-2">
      <button
        type="button"
        onClick={() => setOpen(!open)}
        aria-expanded={open}
        title={`${v.text}${s.last_fetch ? ` · ${t("sync_last", { v: timeAgo(s.last_fetch) })}` : ""}`}
        className={`flex w-full items-center justify-center gap-1.5 rounded-md py-1 text-[12px] hover:bg-surface-3 lg:justify-start ${v.tone}`}
        data-testid="sync-chip"
      >
        {s.fetching ? <Loader2 size={14} className="animate-spin" aria-hidden /> : <v.Icon size={14} aria-hidden />}
        <span className="sr-only lg:not-sr-only">{v.text}</span>
      </button>
      {open && (
        <div role="dialog" aria-label={t("sync_title")} className="absolute bottom-full left-2 z-40 mb-1 w-72 space-y-2 rounded-[10px] border border-line bg-surface p-3 text-[12.5px] text-text shadow-lg">
          <p className="font-semibold text-strong">{t("sync_title")}</p>
          <p className="text-muted">
            {s.base ? `origin/${s.base}` : "origin"} {s.last_fetch ? `· ${t("sync_last", { v: timeAgo(s.last_fetch) })}` : ""}
          </p>
          {s.reason && <p className="text-muted">{s.reason}</p>}
          {s.blocked && <p className="text-warn">{s.blocked}</p>}
          {s.last_error && <p className="text-bad [overflow-wrap:anywhere]">{s.last_error}</p>}
          {s.conflicts.length > 0 && (
            <ul className="max-h-40 space-y-1 overflow-auto">
              {s.conflicts.map((c) => (
                <li key={c.path}>
                  <span className="font-mono text-xs">{c.path}</span> <span className="text-muted">({c.reason})</span>
                </li>
              ))}
            </ul>
          )}
          {s.incoming_rules.length > 0 && <p className="text-muted">{tn("sync_incoming", s.incoming_rules.length)}</p>}
          {can(me, "editor") && (
            <button type="button" onClick={now} disabled={busy || !s.enabled} className="inline-flex items-center gap-1.5 rounded-md border border-line px-2.5 py-1 text-xs font-medium hover:bg-surface-2 disabled:opacity-50">
              <RefreshCw size={12} className={busy ? "animate-spin" : undefined} aria-hidden /> {t("sync_now")}
            </button>
          )}
        </div>
      )}
    </div>
  );
}
