import { useMutation, useQuery } from "@tanstack/react-query";
import clsx from "clsx";
import { AlertTriangle, CheckCircle2, CircleDashed, ExternalLink, GitPullRequest, Loader2, Rocket, X, XCircle } from "lucide-react";
import { useEffect, useRef, useState, type FormEvent } from "react";
import { api } from "../api";
import type { CiState, StageState } from "../types";
import { RunBadge, formatDuration, safeHref } from "./dash";
import { STAGE_META } from "./flow";
import { ErrorBox, btnPrimary, btnSecondary, inputCls } from "./ui";

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

const SETUP_YAML = `# vitrix.yml
github:
  repo: my-org/detections
  base: main
  workflow: vitrix   # the workflow that runs vitrix check --gate`;

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
  none: { title: "Waiting for the CI to start", hint: "GitHub has not reported a workflow run for this commit yet. The workflow must run on pushes to vitrix/** branches.", state: "pending" },
  pending: { title: "CI is running", hint: "The pull request unlocks when every run for this commit finishes successfully.", state: "pending" },
  failure: { title: "CI failed", hint: "The pull request stays blocked. Open the failed run on GitHub, fix the rule here and validate again.", state: "fail" },
  success: { title: "CI passed", hint: "Every workflow run for this exact commit succeeded.", state: "ok" },
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
      className="glass m-auto w-[min(600px,calc(100vw-32px))] rounded-2xl bg-ink/95 p-0 text-text backdrop:bg-black/60 backdrop:backdrop-blur-sm"
    >
      <form onSubmit={onSubmit} className="space-y-5 p-6">
        <div className="flex items-start justify-between gap-4">
          <div>
            <h2 id="pub-title" className="text-lg font-semibold text-strong">
              Publish {mode.kind === "rule" ? "rule" : "configuration"}
            </h2>
            <p className="mt-1 text-sm text-muted">
              A pull request can only be opened after the repository&apos;s real CI (GitHub Actions) has passed for the exact commit. Local tests are not enough.
              {github.data?.repo && (
                <>
                  {" "}
                  Target: <span className="font-mono text-text">{github.data.repo}</span> → <span className="font-mono text-text">{github.data.base}</span>.
                </>
              )}
            </p>
          </div>
          <button type="button" onClick={onClose} aria-label="Close" className="rounded-md p-1 text-muted hover:bg-surface-2 hover:text-text">
            <X size={18} aria-hidden />
          </button>
        </div>

        {github.error && <ErrorBox message={(github.error as Error).message} />}
        {github.data && !ready && (
          <div className="space-y-2 rounded-[10px] border border-warn/30 bg-warn-soft p-3 text-sm text-text">
            <p className="flex items-center gap-2 font-medium text-warn">
              <AlertTriangle size={16} aria-hidden /> {github.data.configured ? "GitHub token missing" : "GitHub is not configured"}
            </p>
            {!github.data.configured && <pre className="rounded-md bg-code p-2 font-mono text-xs text-code-text">{SETUP_YAML}</pre>}
            {!github.data.token && (
              <p>
                Set <code className="font-mono text-xs">VITRIX_GITHUB_TOKEN</code> in the environment of <code className="font-mono text-xs">vitrix serve</code> (Contents,
                Pull requests: read/write; Actions: read) and restart the server.
              </p>
            )}
          </div>
        )}

        {!sub && (
          <div className="space-y-4">
            {mode.kind === "rule" && (
              <label className="block space-y-1.5">
                <span className="text-sm font-medium text-strong">File inside rules/</span>
                <input
                  value={path}
                  onChange={(e) => setPath(e.target.value)}
                  className={clsx(inputCls, "font-mono", mode.ruleId !== null && "text-muted")}
                  placeholder="windows/my_rule.yml"
                  readOnly={mode.ruleId !== null}
                  required
                />
                <span className="block text-xs text-subtle">
                  {mode.ruleId ? "Change to an existing rule." : "Test cases go to the same path inside cases/."}
                </span>
              </label>
            )}
            <label className="block space-y-1.5">
              <span className="text-sm font-medium text-strong">
                Pull request title <span className="font-normal text-subtle">(optional)</span>
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
          <Step n={1} title="Local quality gate" state={localState}>
            <p className="text-[13px] text-muted">
              {localReady === null && "Validating…"}
              {localReady === true && (approval ?? "Lint, conversion, test cases and the quality gate pass locally.")}
              {localReady === false && (localDetail || "Blocked by the local quality gate. Fix the rule before sending it to CI.")}
            </p>
          </Step>

          <Step n={2} title={sub ? CI_COPY[ciState ?? "none"].title : "Validate in the real CI"} state={ciStep}>
            {!sub && <p className="text-[13px] text-muted">Pushes a vitrix/… branch with one commit. GitHub Actions runs the repository&apos;s workflow on it.</p>}
            {sub && (
              <div className="space-y-2">
                <p className="text-[13px] text-muted">{CI_COPY[ciState ?? "none"].hint}</p>
                <p className="text-xs text-subtle">
                  Branch{" "}
                  <a href={safeHref(sub.url)} target="_blank" rel="noreferrer" className="font-mono text-accent hover:underline">
                    {sub.branch}
                  </a>{" "}
                  · commit <span className="font-mono">{sub.commit.slice(0, 7)}</span>
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

          <Step n={3} title={pr.data ? `Pull request #${pr.data.number} opened` : "Open the pull request"} state={prStep}>
            {!pr.data && (
              <p className="flex items-center gap-1.5 text-[13px] text-muted">
                {ciState === "success" ? (
                  <>
                    <CheckCircle2 size={14} className="text-good" aria-hidden /> Unlocked: CI passed for this commit.
                  </>
                ) : (
                  <>
                    <CircleDashed size={14} aria-hidden /> Locked until the CI passes.
                  </>
                )}
              </p>
            )}
            {pr.data && (
              <a href={safeHref(pr.data.url)} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1.5 text-[13px] font-medium text-good hover:underline">
                View on GitHub <ExternalLink size={13} aria-hidden />
              </a>
            )}
          </Step>
        </ol>

        {submit.error && <ErrorBox message={(submit.error as Error).message} />}
        {pr.error && <ErrorBox message={(pr.error as Error).message} />}

        <div className="flex flex-wrap justify-end gap-2">
          <button type="button" onClick={onClose} className={btnSecondary}>
            {pr.data ? "Done" : "Close"}
          </button>
          {!sub && (
            <button type="submit" disabled={!canSubmit} className={btnPrimary}>
              {submit.isPending ? <Loader2 size={16} className="animate-spin" aria-hidden /> : <Rocket size={16} aria-hidden />}
              {submit.isPending ? "Pushing…" : "Validate in CI"}
            </button>
          )}
          {sub && !pr.data && (
            <button type="button" disabled={ciState !== "success" || pr.isPending} onClick={() => pr.mutate()} className={btnPrimary}>
              {pr.isPending ? <Loader2 size={16} className="animate-spin" aria-hidden /> : <GitPullRequest size={16} aria-hidden />}
              {pr.isPending ? "Opening…" : "Open pull request"}
            </button>
          )}
        </div>
      </form>
    </dialog>
  );
}
