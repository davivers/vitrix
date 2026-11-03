import { useMutation, useQuery } from "@tanstack/react-query";
import clsx from "clsx";
import { AlertTriangle, CheckCircle2, CircleDashed, ExternalLink, GitPullRequest, Loader2, Rocket, X, XCircle } from "lucide-react";
import { useEffect, useRef, useState, type FormEvent } from "react";
import { api } from "../api";
import type { CiState, StageState } from "../types";
import { RunBadge, formatDuration, safeHref } from "./dash";
import { STAGE_META } from "./flow";
import { ErrorBox, btnPrimary, btnSecondary, inputCls } from "./ui";
import { t } from "../i18n";

/** Suggested path for a new rule, from the `title:` of the YAML. */
export function suggestPath(rule: string): string {
  const title = /^title:[ \t]*(.+)$/m.exec(rule)?.[1] ?? "";
  const slug = title
    .normalize("NFD")
    .replace(/[̀-ͯ]/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .slice(0, 60);
  return `${slug || "new_rule"}.yml`;
}

const SETUP_YAML = `# in your detections folder (stop vitrix serve first)
gh auth login                       # once: GitHub CLI login, used as the token
vitrix connect your-org/your-repo   # links the folder and checks the CI, step by step
vitrix serve`;

type Mode = { kind: "rule"; ruleId: string | null; rule: string; cases: string } | { kind: "config"; text: string };

interface Props {
  mode: Mode;
  /** The local quality gate (or config validation) passed. null = still validating. */
  localReady: boolean | null;
  localDetail?: string;
  /** Shown when the local gate approved the change, e.g. "Approved: health 96/100 (80 required)". */
  approval?: string;
  onClose: () => void;
}

const CI_COPY: Record<CiState, { title: string; hint: string; state: StageState }> = {
  none: { title: t("l_waiting_for_the_ci_to_start"), hint: t("l_github_has_not_reported_a_workflow"), state: "pending" },
  pending: { title: t("l_ci_is_running"), hint: t("l_the_pull_request_unlocks_when_ever"), state: "pending" },
  failure: { title: t("l_ci_failed"), hint: t("l_the_pull_request_stays_blocked_ope"), state: "fail" },
  success: { title: t("l_ci_passed"), hint: t("l_every_workflow_run_for_this_exact_"), state: "ok" },
};

function Step({ n, title, state, children }: { n: number; title: string; state: StageState; children?: React.ReactNode }) {
  const { Icon, cls } = STAGE_META[state];
  return (
    <li className="flex gap-3">
      <span className={clsx("mt-0.5 grid size-6 shrink-0 place-items-center rounded-full bg-surface-2 text-[11px] font-bold", cls)} aria-hidden>
        {state === "ok" ? <Icon size={14} /> : n}
      </span>
      <div className="min-w-0 flex-1 space-y-2">
        <p className="flex items-center gap-2 text-sm font-semibold text-strong">
          {title}
          <span className="sr-only">{STAGE_META[state].label}</span>
          {state === "pending" && <Loader2 size={14} className="animate-spin text-muted" aria-hidden />}
          {state === "fail" && <XCircle size={14} className="text-bad" aria-hidden />}
        </p>
        {children}
      </div>
    </li>
  );
}

/**
 * Publish flow: 1) local quality gate → 2) push a branch and wait for the REAL CI (GitHub Actions)
 * → 3) open the pull request, only after CI passed for that exact commit. The server enforces the
 * same rule: the button is a convenience, not the guard.
 */
export function PublishDialog({ mode, localReady, localDetail, approval, onClose }: Props) {
  const ref = useRef<HTMLDialogElement>(null);
  const github = useQuery({ queryKey: ["github"], queryFn: api.github });
  const [path, setPath] = useState(() => (mode.kind === "rule" ? (mode.ruleId ?? suggestPath(mode.rule)) : ""));
  const [title, setTitle] = useState("");

  const submit = useMutation({
    mutationFn: () =>
      mode.kind === "rule"
        ? api.submitRule({ path: path.trim(), rule: mode.rule, cases: mode.cases.trim() ? mode.cases : null, title: title.trim() || null })
        : api.submitConfig({ text: mode.text, title: title.trim() || null }),
  });
  const sub = submit.data;

  const ci = useQuery({
    queryKey: ["ci", sub?.commit],
    queryFn: () => api.ciStatus(sub!.commit),
    enabled: Boolean(sub),
    refetchInterval: (q) => (q.state.data && (q.state.data.state === "none" || q.state.data.state === "pending") ? 5000 : q.state.data ? false : 5000),
    retry: 2,
  });
  const ciState: CiState | null = ci.data?.state ?? null;

  const pr = useMutation({ mutationFn: () => api.openPullRequest({ branch: sub!.branch, commit: sub!.commit, title: title.trim() || null }) });

  useEffect(() => {
    const dlg = ref.current;
    if (dlg && !dlg.open) dlg.showModal();
  }, []);

  const ready = Boolean(github.data?.configured && github.data.token);
  const canSubmit = ready && localReady === true && !submit.isPending && !sub && (mode.kind === "config" || path.trim() !== "");
  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    if (canSubmit) submit.mutate();
  };

  const localState: StageState = localReady === null ? "pending" : localReady ? "ok" : "fail";
  const ciStep: StageState = !sub ? "skip" : ciState === null ? "pending" : CI_COPY[ciState].state;
  const prStep: StageState = pr.data ? "ok" : ciState === "success" ? "pending" : "skip";

  return (
    <dialog
      ref={ref}
      onClose={onClose}
      aria-labelledby="pub-title"
      className="glass m-auto w-[min(600px,calc(100vw-32px))] rounded-2xl bg-surface p-0 text-text backdrop:bg-black/50"
    >
      <form onSubmit={onSubmit} className="space-y-5 p-6">
        <div className="flex items-start justify-between gap-4">
          <div>
            <h2 id="pub-title" className="text-lg font-semibold text-strong">
              {mode.kind === "rule" ? t("pd_publish_rule") : t("pd_publish_config")}
            </h2>
            <p className="mt-1 text-sm text-muted">
              {t("pd_intro")}
              {github.data?.repo && (
                <>
                  {" "}
                  {t("pd_target")} <span className="font-mono text-text">{github.data.repo}</span> → <span className="font-mono text-text">{github.data.base}</span>.
                </>
              )}
            </p>
          </div>
          <button type="button" onClick={onClose} aria-label={t("close")} className="rounded-md p-1 text-muted hover:bg-surface-2 hover:text-text">
            <X size={18} aria-hidden />
          </button>
        </div>

        {github.error && <ErrorBox message={(github.error as Error).message} />}
        {github.data && !ready && (
          <div className="space-y-2 rounded-[10px] border border-warn/30 bg-warn-soft p-3 text-sm text-text">
            <p className="flex items-center gap-2 font-medium text-warn">
              <AlertTriangle size={16} aria-hidden /> {github.data.configured ? t("l_github_token_missing") : t("l_github_is_not_configured")}
            </p>
            {!github.data.configured && <pre className="rounded-md bg-code p-2 font-mono text-xs text-code-text">{SETUP_YAML}</pre>}
            {github.data.configured && !github.data.token && <pre className="rounded-md bg-code p-2 font-mono text-xs text-code-text">{SETUP_YAML}</pre>}
          </div>
        )}

        {!sub && (
          <div className="space-y-4">
            {mode.kind === "rule" && (
              <label className="block space-y-1.5">
                <span className="text-sm font-medium text-strong">{t("file_inside_rules")}</span>
                <input
                  value={path}
                  onChange={(e) => setPath(e.target.value)}
                  className={clsx(inputCls, "font-mono", mode.ruleId !== null && "text-muted")}
                  placeholder="windows/my_rule.yml"
                  readOnly={mode.ruleId !== null}
                  required
                />
                <span className="block text-xs text-subtle">
                  {mode.ruleId ? t("l_change_to_an_existing_rule") : t("l_test_cases_go_to_the_same_path_ins")}
                </span>
              </label>
            )}
            <label className="block space-y-1.5">
              <span className="text-sm font-medium text-strong">
                {t("pull_request_title")} <span className="font-normal text-subtle">(optional)</span>
              </span>
              <input
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                className={inputCls}
                maxLength={200}
                placeholder={mode.kind === "config" ? "chore: update vitrix.yml" : mode.ruleId ? "tune: …" : "feat: new rule …"}
              />
            </label>
          </div>
        )}

        <ol className="space-y-4 border-t border-line pt-4">
          <Step n={1} title={t("local_quality_gate")} state={localState}>
            <p className="text-[13px] text-muted">
              {localReady === null && t("l_validating")}
              {localReady === true && (approval ?? t("l_lint_conversion_test_cases_and_the"))}
              {localReady === false && (localDetail || t("l_blocked_by_the_local_quality_gate_"))}
            </p>
          </Step>

          <Step n={2} title={sub ? CI_COPY[ciState ?? "none"].title : t("l_validate_in_the_real_ci")} state={ciStep}>
            {!sub && <p className="text-[13px] text-muted">{t("pd_pushes")}</p>}
            {sub && (
              <div className="space-y-2">
                <p className="text-[13px] text-muted">{CI_COPY[ciState ?? "none"].hint}</p>
                <p className="text-xs text-subtle">
                  {t("branch")}{" "}
                  <a href={safeHref(sub.url)} target="_blank" rel="noreferrer" className="font-mono text-accent hover:underline">
                    {sub.branch}
                  </a>{" "}
                  {t("pd_commit")} <span className="font-mono">{sub.commit.slice(0, 7)}</span>
                </p>
                {ci.data && ci.data.runs.length > 0 && (
                  <ul className="space-y-1">
                    {ci.data.runs.map((r) => (
                      <li key={r.id}>
                        <a href={safeHref(r.url)} target="_blank" rel="noreferrer" className="flex items-center gap-2 rounded-md px-2 py-1 text-[13px] hover:bg-surface-2">
                          <RunBadge state={r.state} />
                          <span className="min-w-0 flex-1 truncate text-text">
                            {r.name} #{r.number}
                          </span>
                          <span className="text-xs text-subtle">{formatDuration(r.duration_s)}</span>
                          <ExternalLink size={12} className="text-subtle" aria-hidden />
                        </a>
                      </li>
                    ))}
                  </ul>
                )}
                {ci.error && <ErrorBox message={(ci.error as Error).message} />}
              </div>
            )}
          </Step>

          <Step n={3} title={pr.data ? t("pd_pr_opened", { n: pr.data.number }) : t("l_open_the_pull_request")} state={prStep}>
            {!pr.data && (
              <p className="flex items-center gap-1.5 text-[13px] text-muted">
                {ciState === "success" ? (
                  <>
                    <CheckCircle2 size={14} className="text-good" aria-hidden /> {t("unlocked_ci_passed_for_this_commit")}
                  </>
                ) : (
                  <>
                    <CircleDashed size={14} aria-hidden /> {t("locked_until_the_ci_passes")}
                  </>
                )}
              </p>
            )}
            {pr.data && (
              <a href={safeHref(pr.data.url)} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1.5 text-[13px] font-medium text-good hover:underline">
                {t("view_on_github")} <ExternalLink size={13} aria-hidden />
              </a>
            )}
          </Step>
        </ol>

        {submit.error && <ErrorBox message={(submit.error as Error).message} />}
        {pr.error && <ErrorBox message={(pr.error as Error).message} />}

        <div className="flex flex-wrap justify-end gap-2">
          <button type="button" onClick={onClose} className={btnSecondary}>
            {pr.data ? t("l_done") : t("l_close")}
          </button>
          {!sub && (
            <button type="submit" disabled={!canSubmit} className={btnPrimary}>
              {submit.isPending ? <Loader2 size={16} className="animate-spin" aria-hidden /> : <Rocket size={16} aria-hidden />}
              {submit.isPending ? t("l_pushing") : t("l_validate_in_ci")}
            </button>
          )}
          {sub && !pr.data && (
            <button type="button" disabled={ciState !== "success" || pr.isPending} onClick={() => pr.mutate()} className={btnPrimary}>
              {pr.isPending ? <Loader2 size={16} className="animate-spin" aria-hidden /> : <GitPullRequest size={16} aria-hidden />}
              {pr.isPending ? t("l_opening") : t("l_open_pull_request")}
            </button>
          )}
        </div>
      </form>
    </dialog>
  );
}
