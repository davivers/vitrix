import { useQuery } from "@tanstack/react-query";
import clsx from "clsx";
import { AlertTriangle, CheckCircle2, CircleDashed, ExternalLink, GitBranch, RefreshCw, XCircle } from "lucide-react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { useSync } from "../components/SyncChip";
import { Section, safeHref, timeAgo } from "../components/dash";
import { ErrorBox, PageHeader, TARGET_CODE, TargetSwatch, btnSecondary } from "../components/ui";
import type { Activity, GitHubStatus } from "../types";
import { t, tn } from "../i18n";

type Tone = "ok" | "warn" | "fail" | "off";
const TONE: Record<Tone, { cls: string; Icon: typeof CheckCircle2 }> = {
  ok: { cls: "bg-good-soft text-good", Icon: CheckCircle2 },
  warn: { cls: "bg-warn-soft text-warn", Icon: AlertTriangle },
  fail: { cls: "bg-bad-soft text-bad", Icon: XCircle },
  off: { cls: "bg-surface-2 text-muted", Icon: CircleDashed },
};

function Pill({ tone, children }: { tone: Tone; children: string }) {
  const { cls, Icon } = TONE[tone];
  return (
    <span className={clsx("inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-semibold", cls)}>
      <Icon size={13} aria-hidden /> {children}
    </span>
  );
}

function githubState(status: GitHubStatus | undefined, activity: Activity | undefined): [Tone, string] {
  if (!status) return ["off", t("l_checking")];
  if (!status.configured) return ["off", t("l_not_configured")];
  if (!status.token) return ["warn", t("l_no_token")];
  if (!activity) return ["off", t("l_checking")];
  return activity.available ? ["ok", t("l_connected")] : ["fail", t("l_connection_error")];
}

const SETUP = `# in your detections folder (stop vitrix serve first)
gh auth login                       # once: GitHub CLI login, used as the token
vitrix connect your-org/your-repo   # links the folder and checks the CI, step by step
vitrix serve`;

function GitHubCard() {
  const status = useQuery({ queryKey: ["github"], queryFn: api.github });
  const activity = useQuery({ queryKey: ["activity"], queryFn: () => api.activity(), enabled: Boolean(status.data?.configured && status.data.token) });
  const test = useQuery({ queryKey: ["activity-refresh"], queryFn: () => api.activity(true), enabled: false });
  const act = test.data ?? activity.data;
  const sync = useSync().data;
  const [tone, label] = githubState(status.data, act);

  return (
    <Section title="GitHub" aside={<Pill tone={tone}>{label}</Pill>}>
      <div className="flex items-start gap-4">
        <span className="grid size-11 shrink-0 place-items-center rounded-xl bg-surface-2 text-strong">
          <GitBranch size={22} aria-hidden />
        </span>
        <div className="min-w-0 flex-1 space-y-3 text-[13px]">
          <p className="text-muted">
            {t("cn_intro")}
          </p>
          {status.error && <ErrorBox message={(status.error as Error).message} />}
          {status.data?.configured && (
            <dl className="grid grid-cols-[8rem_1fr] gap-y-1.5">
              <dt className="text-subtle">{t("repository")}</dt>
              <dd className="font-mono text-text">
                {act?.available ? (
                  <a href={safeHref(act.repo.url)} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 hover:text-accent">
                    {status.data.repo} <ExternalLink size={12} aria-hidden />
                  </a>
                ) : (
                  status.data.repo
                )}
              </dd>
              <dt className="text-subtle">{t("base_branch")}</dt>
              <dd className="font-mono text-text">{status.data.base}</dd>
              <dt className="text-subtle">{t("settings")}</dt>
              <dd className="text-text">{status.data.source === "git remote" ? t("cn_detected") : t("cn_section")}</dd>
              <dt className="text-subtle">{t("ci_workflow")}</dt>
              <dd className="font-mono text-text">{status.data.workflow ?? t("cn_anywf")}</dd>
              <dt className="text-subtle">{t("token")}</dt>
              <dd className="flex items-center gap-1.5 text-text">
                {status.data.token ? <CheckCircle2 size={14} className="text-good" aria-hidden /> : <XCircle size={14} className="text-bad" aria-hidden />}
                {status.data.token ? t("cn_from", { src: status.data.token_source ?? "" }) : t("cn_missing")}
              </dd>
              {sync && (
                <>
                  <dt className="text-subtle">{t("cn_sync")}</dt>
                  <dd className="text-text">
                    {sync.state === "synced" && <span className="inline-flex items-center gap-1.5"><CheckCircle2 size={14} className="text-good" aria-hidden /> {t("cn_in_sync", { b: sync.base ?? "" })}</span>}
                    {sync.state === "behind" && <span className="inline-flex items-center gap-1.5"><AlertTriangle size={14} className="text-warn" aria-hidden /> {t("cn_behind", { b: sync.base ?? "", n: sync.behind })}</span>}
                    {sync.state === "ahead" && <span className="inline-flex items-center gap-1.5"><AlertTriangle size={14} className="text-warn" aria-hidden /> {t("cn_ahead", { b: sync.base ?? "", n: sync.ahead })}</span>}
                    {sync.state === "diverged" && <span className="inline-flex items-center gap-1.5"><XCircle size={14} className="text-bad" aria-hidden /> {t("cn_diverged", { b: sync.base ?? "" })}</span>}
                    {!["synced", "behind", "ahead", "diverged"].includes(sync.state) && <span className="text-muted">{sync.reason ?? sync.last_error ?? sync.state}</span>}
                    {sync.last_fetch && <span className="text-muted"> · {t("sync_last", { v: timeAgo(sync.last_fetch) })}</span>}
                  </dd>
                </>
              )}
              {act?.available && (
                <>
                  <dt className="text-subtle">HEAD</dt>
                  <dd className="truncate text-text">
                    <span className="font-mono">{act.head.sha.slice(0, 7)}</span> · {act.head.message}
                  </dd>
                  <dt className="text-subtle">{t("last_read")}</dt>
                  <dd className="text-text">{timeAgo(act.fetched_at)}</dd>
                </>
              )}
            </dl>
          )}
          {act && !act.available && act.reason === "error" && <ErrorBox message={act.message} />}
          {status.data && (!status.data.configured || !status.data.token) && (
            <pre className="overflow-auto rounded-[10px] border border-line bg-code p-3 font-mono text-xs leading-relaxed text-code-text">{SETUP}</pre>
          )}
          {status.data?.configured && status.data.token && (
            <button type="button" onClick={() => test.refetch()} className={btnSecondary}>
              <RefreshCw size={14} className={test.isFetching ? "animate-spin" : undefined} aria-hidden /> {t("test_connection")}
            </button>
          )}
          <p className="text-xs text-muted">{t("cn_publishing")}</p>
          <p className="text-xs text-subtle">
            {t("fine_grained_token_limited_to_the_repo")}{" "}
            <span className="font-mono">vitrix/**</span> {t("branches")}
          </p>
        </div>
      </div>
    </Section>
  );
}

const FLAVOR: Record<string, string> = { splunk: "PCRE", kql: "RE2", kusto: "RE2", "elastic-lucene": "Lucene regex", "elastic-eql": "Java regex" };

function Languages() {
  const targets = useQuery({ queryKey: ["targets"], queryFn: api.targets });
  const list = targets.data ?? [];
  return (
    <Section title={t("cn_languages")} aside={t("cn_local_conv")}>
      {targets.error && (
        <div className="space-y-2">
          <ErrorBox message={(targets.error as Error).message} />
          <button type="button" className={btnSecondary} onClick={() => targets.refetch()}>
            {t("try_again")}
          </button>
        </div>
      )}
      {targets.data && list.length === 0 && <p className="text-sm text-muted">{t("cn_none")}</p>}
      {list.length > 0 && (
        <div className="-mx-2 overflow-x-auto">
          <table className="w-full min-w-[34rem] text-left text-[13px]">
            <caption className="sr-only">{t("cn_languages")}</caption>
            <thead className="border-b border-line text-[11.5px] uppercase tracking-wide text-subtle">
              <tr>
                <th className="px-2 py-2 font-medium">{t("cn_col_lang")}</th>
                <th className="px-2 py-2 font-medium">{t("cn_col_backend")}</th>
                <th className="px-2 py-2 font-medium">{t("cn_col_flavor")}</th>
                <th className="px-2 py-2 font-medium">{t("cn_col_final")}</th>
                <th className="px-2 py-2 font-medium">{t("state")}</th>
              </tr>
            </thead>
            <tbody>
              {list.map((tg) => (
                <tr key={tg.name} className="border-b border-line last:border-0">
                  <td className="px-2 py-2.5">
                    <span className="flex flex-wrap items-center gap-2 font-medium text-strong">
                      <TargetSwatch target={tg.name} />
                      {tg.label}
                      <span className="rounded bg-surface-2 px-1.5 py-0.5 font-mono text-[10.5px] text-muted">{TARGET_CODE[tg.name] ?? tg.extension.toUpperCase()}</span>
                      {tg.default && <span className="rounded bg-accent-soft px-1.5 py-0.5 text-[10.5px] font-semibold text-accent">{t("cn_default")}</span>}
                      {!tg.active && <span className="text-xs font-normal text-muted">{t("cn_not_enabled")}</span>}
                    </span>
                  </td>
                  <td className="px-2 py-2.5">
                    <span className="block font-mono text-xs text-text">{tg.backend ?? tg.name}</span>
                    {tg.plugin && <span className="block font-mono text-[11px] text-subtle">{tg.plugin}</span>}
                  </td>
                  <td className="px-2 py-2.5 text-muted">{FLAVOR[tg.name] ?? "-"}</td>
                  <td className="px-2 py-2.5">
                    {tg.used_by === undefined ? (
                      "-"
                    ) : (
                      <Link to={`/rules?target=${encodeURIComponent(tg.name)}`} className="text-accent hover:underline">
                        {tn("n_rules", tg.used_by)}
                      </Link>
                    )}
                  </td>
                  <td className="px-2 py-2.5">
                    {tg.status === "missing_plugin" ? (
                      <span className="inline-flex items-center gap-1 text-warn"><AlertTriangle size={13} aria-hidden /> {t("cn_plugin_missing")}</span>
                    ) : tg.status === "error" ? (
                      <span className="inline-flex items-center gap-1 text-bad"><XCircle size={13} aria-hidden /> {tg.message ?? t("cn_error")}</span>
                    ) : (
                      <span className="inline-flex items-center gap-1 text-good"><CheckCircle2 size={13} aria-hidden /> {t("cn_ready")}</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <p className="mt-4 text-xs text-subtle">
        {t("cn_choose")} <Link to="/settings" className="font-medium text-accent hover:underline">{t("cn_open_settings")}</Link>
      </p>
    </Section>
  );
}

export default function ConnectionsPage() {
  return (
    <div className="mx-auto max-w-6xl px-4 py-8 sm:px-8">
      <PageHeader title={t("connections")} subtitle={t("integrations_with_the_git_repository_a")} />
      <div className="grid gap-5">
        <GitHubCard />
        <Languages />
      </div>
    </div>
  );
}
