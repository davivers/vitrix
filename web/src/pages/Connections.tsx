import { useQuery } from "@tanstack/react-query";
import clsx from "clsx";
import { AlertTriangle, CheckCircle2, CircleDashed, ExternalLink, GitBranch, RefreshCw, XCircle } from "lucide-react";
import { api } from "../api";
import { Section, safeHref, timeAgo } from "../components/dash";
import { ErrorBox, PageHeader, TARGET_CODE, TargetSwatch, btnSecondary } from "../components/ui";
import type { Activity, GitHubStatus } from "../types";
import { t } from "../i18n";

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
          <p className="text-xs text-subtle">
            {t("fine_grained_token_limited_to_the_repo")}{" "}
            <span className="font-mono">vitrix/**</span> {t("branches")}
          </p>
        </div>
      </div>
    </Section>
  );
}

function SiemTargets() {
  const targets = useQuery({ queryKey: ["targets"], queryFn: api.targets });
  return (
    <Section title="SIEMs" aside={t("cn_local_conv")}>
      {targets.error && <ErrorBox message={(targets.error as Error).message} />}
      <ul className="grid gap-3 sm:grid-cols-2">
        {(targets.data ?? []).map((tg) => (
          <li key={tg.name} className="rounded-[12px] border border-line bg-surface p-4">
            <div className="mb-2 flex items-center justify-between gap-2">
              <span className="flex items-center gap-2 font-semibold text-strong">
                <TargetSwatch target={tg.name} />
                {tg.label}
              </span>
              <Pill tone={tg.active ? "ok" : "off"}>{tg.active ? t("l_active") : t("l_available")}</Pill>
            </div>
            <dl className="grid grid-cols-[6rem_1fr] gap-y-1 text-[12.5px]">
              <dt className="text-subtle">{t("target")}</dt>
              <dd className="font-mono text-text">
                {tg.name} · {TARGET_CODE[tg.name] ?? tg.extension.toUpperCase()}
              </dd>
              <dt className="text-subtle">{t("conversion")}</dt>
              <dd className="flex items-center gap-1.5 text-text">
                <CheckCircle2 size={13} className="text-good" aria-hidden /> {t("local_no_siem_access")}
              </dd>
              <dt className="text-subtle">{t("deploy")}</dt>
              <dd className="flex items-center gap-1.5 text-muted">
                <CircleDashed size={13} aria-hidden /> {t("not_available_yet")}
              </dd>
            </dl>
          </li>
        ))}
      </ul>
      <p className="mt-4 text-xs text-subtle">
        {t("turn_targets_on_or_off_in")} <span className="font-mono">targets</span> {t("of_vitrix_yml_settings_other_siems_com")}{" "}
        <span className="font-mono">vitrix.targets</span> {t("entry_point_the_conversion_output_is_t")} <span className="font-mono">dist/</span> {t("built_by_ci")}
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
        <SiemTargets />
      </div>
    </div>
  );
}
