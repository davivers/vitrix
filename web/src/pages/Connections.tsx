import { useQuery } from "@tanstack/react-query";
import clsx from "clsx";
import { AlertTriangle, CheckCircle2, CircleDashed, ExternalLink, GitBranch, RefreshCw, XCircle } from "lucide-react";
import { api } from "../api";
import { Section, safeHref, timeAgo } from "../components/dash";
import { ErrorBox, PageHeader, TARGET_CODE, TargetSwatch, btnSecondary } from "../components/ui";
import type { Activity, GitHubStatus } from "../types";

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
  if (!status) return ["off", "Checking"];
  if (!status.configured) return ["off", "Not configured"];
  if (!status.token) return ["warn", "No token"];
  if (!activity) return ["off", "Checking"];
  return activity.available ? ["ok", "Connected"] : ["fail", "Connection error"];
}

const SETUP = `# vitrix.yml
github:
  repo: my-org/detections
  base: main
  path: ""            # project folder inside the repository
  workflow: vitrix    # workflow whose runs count as CI validation

# in the terminal, before vitrix serve
export VITRIX_GITHUB_TOKEN=github_pat_...`;

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
            Validates every change in the repository&apos;s real CI (GitHub Actions) and only then opens the pull request. It also reads open PRs, CI runs and time to merge for the
            dashboards. One token for reading and writing; it never leaves the server.
          </p>
          {status.error && <ErrorBox message={(status.error as Error).message} />}
          {status.data?.configured && (
            <dl className="grid grid-cols-[8rem_1fr] gap-y-1.5">
              <dt className="text-subtle">Repository</dt>
              <dd className="font-mono text-text">
                {act?.available ? (
                  <a href={safeHref(act.repo.url)} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 hover:text-accent">
                    {status.data.repo} <ExternalLink size={12} aria-hidden />
                  </a>
                ) : (
                  status.data.repo
                )}
              </dd>
              <dt className="text-subtle">Base branch</dt>
              <dd className="font-mono text-text">{status.data.base}</dd>
              <dt className="text-subtle">CI workflow</dt>
              <dd className="font-mono text-text">{status.data.workflow ?? "any workflow"}</dd>
              <dt className="text-subtle">Token</dt>
              <dd className="flex items-center gap-1.5 text-text">
                {status.data.token ? <CheckCircle2 size={14} className="text-good" aria-hidden /> : <XCircle size={14} className="text-bad" aria-hidden />}
                {status.data.token ? "set in the environment" : "VITRIX_GITHUB_TOKEN missing"}
              </dd>
              {act?.available && (
                <>
                  <dt className="text-subtle">HEAD</dt>
                  <dd className="truncate text-text">
                    <span className="font-mono">{act.head.sha.slice(0, 7)}</span> · {act.head.message}
                  </dd>
                  <dt className="text-subtle">Last read</dt>
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
              <RefreshCw size={14} className={test.isFetching ? "animate-spin" : undefined} aria-hidden /> Test connection
            </button>
          )}
          <p className="text-xs text-subtle">
            Fine-grained token limited to the repository: Contents and Pull requests (read/write), Actions (read). The workflow must run on pushes to{" "}
            <span className="font-mono">vitrix/**</span> branches.
          </p>
        </div>
      </div>
    </Section>
  );
}

function SiemTargets() {
  const targets = useQuery({ queryKey: ["targets"], queryFn: api.targets });
  return (
    <Section title="SIEMs" aside="local conversion with pySigma">
      {targets.error && <ErrorBox message={(targets.error as Error).message} />}
      <ul className="grid gap-3 sm:grid-cols-2">
        {(targets.data ?? []).map((t) => (
          <li key={t.name} className="rounded-[12px] border border-line bg-surface p-4">
            <div className="mb-2 flex items-center justify-between gap-2">
              <span className="flex items-center gap-2 font-semibold text-strong">
                <TargetSwatch target={t.name} />
                {t.label}
              </span>
              <Pill tone={t.active ? "ok" : "off"}>{t.active ? "Active" : "Available"}</Pill>
            </div>
            <dl className="grid grid-cols-[6rem_1fr] gap-y-1 text-[12.5px]">
              <dt className="text-subtle">Target</dt>
              <dd className="font-mono text-text">
                {t.name} · {TARGET_CODE[t.name] ?? t.extension.toUpperCase()}
              </dd>
              <dt className="text-subtle">Conversion</dt>
              <dd className="flex items-center gap-1.5 text-text">
                <CheckCircle2 size={13} className="text-good" aria-hidden /> local, no SIEM access
              </dd>
              <dt className="text-subtle">Deploy</dt>
              <dd className="flex items-center gap-1.5 text-muted">
                <CircleDashed size={13} aria-hidden /> not available yet
              </dd>
            </dl>
          </li>
        ))}
      </ul>
      <p className="mt-4 text-xs text-subtle">
        Turn targets on or off in <span className="font-mono">targets</span> of vitrix.yml (Settings). Other SIEMs come in through plugins, using the{" "}
        <span className="font-mono">vitrix.targets</span> entry point. The conversion output is the <span className="font-mono">dist/</span> built by CI.
      </p>
    </Section>
  );
}

export default function ConnectionsPage() {
  return (
    <div className="mx-auto max-w-6xl px-4 py-8 sm:px-8">
      <PageHeader title="Connections" subtitle="Integrations with the Git repository and the target SIEMs." />
      <div className="grid gap-5">
        <GitHubCard />
        <SiemTargets />
      </div>
    </div>
  );
}
