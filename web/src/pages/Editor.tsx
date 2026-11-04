import { useQuery, useQueryClient } from "@tanstack/react-query";
import CodeMirror from "@uiw/react-codemirror";
import clsx from "clsx";
import { AlertTriangle, Check, CheckCircle2, ChevronDown, CircleDot, Copy, Download, Eye, FilePlus, FolderOpen, GitMerge, GitPullRequest, HardDrive, Loader2, Rocket, Save, ShieldCheck, XCircle } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { ApiError, DEMO, api } from "../api";
import { useIsDark } from "../theme";
import { can, useMe } from "../components/auth";
import { EditorView } from "@codemirror/view";
import { issueRange, paintIssues, yamlExtensions } from "../components/code";
import { IssueList } from "../components/Issues";
import { HealthMeter, formatDate, timeAgo } from "../components/dash";
import { DraftsSheet } from "../components/DraftsSheet";
import { DriftPanel } from "../components/Drift";
import { CheckList, FlowStepper, GATE_LABELS, fmt } from "../components/flow";
import { PublishDialog, suggestPath } from "../components/PublishDialog";
import { ReplayPanel } from "../components/ReplayPanel";
import { ReviewPanel } from "../components/ReviewPanel";
import { Card, ErrorBox, LevelTag, StateBadge, TargetSwatch, btnPrimary, btnSecondary, inputCls } from "../components/ui";
import type { Draft, DraftQuality, LintIssue, Publication, Validation } from "../types";
import { locale, t, tn } from "../i18n";

function newRuleTemplate(): string {
  return `title: Rule name
id: ${crypto.randomUUID()}
status: experimental
description: What this rule detects
author: your name
date: ${new Date().toISOString().slice(0, 10)}
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains: ' -enc '
  condition: selection
falsepositives:
  - Legitimate automation
level: medium
`;
}

const CASES_TEMPLATE = `cases:
  - name: Positive · powershell -enc
    expect: match
    event:
      Image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'
      CommandLine: 'powershell.exe -enc JABz'
  - name: Negative · plain cmd
    expect: no_match
    event:
      Image: 'C:\\Windows\\System32\\cmd.exe'
      CommandLine: 'cmd.exe /c dir'
  - name: False positive · legitimate admin script
    kind: false_positive
    expect: no_match
    event:
      Image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'
      CommandLine: 'powershell.exe -File C:\\scripts\\inventory.ps1'
  - name: Edge · event without CommandLine
    kind: edge
    expect: no_match
    event:
      Image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'
`;

export default function EditorPage() {
  const id = useParams()["*"] || null;
  const draftId = useSearchParams()[0].get("draft");
  const detail = useQuery({ queryKey: ["rule", id], queryFn: () => api.rule(id!), enabled: id !== null && draftId === null });
  const draft = useQuery({ queryKey: ["draft", draftId], queryFn: () => api.draft(draftId!), enabled: draftId !== null, staleTime: 0, gcTime: 0 });

  const failure = (draftId ? draft.error : detail.error) as Error | null;
  if (draftId ? draft.isLoading : id !== null && detail.isLoading) return <div className="p-8 text-muted">{t("loading")}</div>;
  if (failure) {
    return (
      <div className="p-8">
        <ErrorBox message={failure.message} />
      </div>
    );
  }
  const d = draftId ? (draft.data ?? null) : null;
  return (
    <EditorWorkspace
      key={d ? `draft:${d.id}:${d.version}` : (id ?? "new")}
      ruleId={d ? d.path : id}
      file={d ? (d.path ?? d.title) : (detail.data?.file ?? null)}
      initialRule={d ? d.rule : (detail.data?.text ?? newRuleTemplate())}
      initialCases={d ? (d.cases ?? "") : detail.data ? (detail.data.tests.cases_text ?? "") : CASES_TEMPLATE}
      draft={d}
      disk={!d && detail.data ? { sha: detail.data.sha ?? null, cases_sha: detail.data.cases_sha ?? null, publication: detail.data.publication ?? null } : null}
    />
  );
}

/** B3 issue codes after which the rule cannot be evaluated at all (anything else still lets replay run). */
const REPLAY_BLOCKERS = new Set(["invalid-yaml", "not-a-mapping", "missing-condition", "no-selection", "unknown-selection", "pattern-no-match", "bad-logsource"]);

type Panel = "gate" | "replay" | "queries" | "history" | "drift" | "review";

interface Disk {
  sha: string | null;
  cases_sha: string | null;
  publication: Publication | null;
}

function EditorWorkspace(props: { ruleId: string | null; file: string | null; initialRule: string; initialCases: string; draft: Draft | null; disk: Disk | null }) {
  const { ruleId, file, initialRule, initialCases } = props;
  const me = useMe();
  const dark = useIsDark();
  const isEditor = can(me, "editor");
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [rule, setRule] = useState(initialRule);
  const [cases, setCases] = useState(initialCases);
  const [tab, setTab] = useState<"rule" | "cases">("rule");
  const [panel, setPanel] = useState<Panel>("gate");
  const [result, setResult] = useState<Validation | null>(null);
  const [pending, setPending] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [publishOpen, setPublishOpen] = useState(() => isEditor && !DEMO && new URLSearchParams(window.location.search).get("publish") === "1");
  const publishAfterSave = useRef(false);
  const [replayBroken, setReplayBroken] = useState<boolean | null>(null);
  const [draftsOpen, setDraftsOpen] = useState(false);
  const [offerDelete, setOfferDelete] = useState(false);
  // The rule file on disk (U2): Save writes rules/<id>; `sha` guards against someone else changing it meanwhile.
  const [disk, setDisk] = useState<Disk | null>(props.disk);
  const [fileSave, setFileSave] = useState<{ busy: boolean; error: string | null; conflict: boolean; askPath: boolean; savedAt: Date | null }>({ busy: false, error: null, conflict: false, askPath: false, savedAt: null });
  const [newPath, setNewPath] = useState(() => props.draft?.path ?? suggestPath(initialRule));
  const fileDirty = disk ? rule !== initialRule || cases !== initialCases : false;
  // Local draft state: id + version of the loaded/saved draft, and what was last saved (for the "unsaved" dot).
  const [saved, setSaved] = useState<{ id: string; version: number; rule: string; cases: string; at: Date } | null>(
    // Only the author's own draft keeps its id (PUT); someone else's opens as a copy and Save creates a new draft.
    props.draft?.mine ? { id: props.draft.id, version: props.draft.version, rule: props.draft.rule, cases: props.draft.cases ?? "", at: new Date(props.draft.updated_at) } : null,
  );
  const [saveState, setSaveState] = useState<{ busy: boolean; error: string | null; conflict: boolean }>({ busy: false, error: null, conflict: false });
  const draftsInfo = useQuery({ queryKey: ["drafts"], queryFn: api.drafts, retry: false, enabled: isEditor });
  const draftsOn = draftsInfo.data?.enabled === true;
  const draftsReason = draftsInfo.data && !draftsInfo.data.enabled ? (draftsInfo.data.reason ?? t("l_local_drafts_are_off")) : null;
  const dirty = saved ? saved.rule !== rule || saved.cases !== cases : rule !== initialRule || cases !== initialCases;

  // Validates 500 ms after the last keystroke; cancels the previous call if still in flight.
  useEffect(() => {
    const ctrl = new AbortController();
    setPending(true);
    const timer = setTimeout(() => {
      api
        .validate(rule, cases.trim() ? cases : null, ruleId, ctrl.signal)
        .then((v) => {
          setResult(v);
          setError(null);
          setPending(false);
        })
        .catch((e: Error) => {
          if (e.name === "AbortError") return;
          setError(e.message);
          setPending(false);
        });
    }, 500);
    return () => {
      clearTimeout(timer);
      ctrl.abort();
    };
  }, [rule, cases, ruleId]);

  const extensions = useMemo(() => yamlExtensions(dark), [dark]);

  // Inline diagnostics: rule issues live in the rule tab, test-case problems in the cases tab.
  const viewRef = useRef<EditorView | null>(null);
  const jumpRef = useRef<LintIssue | null>(null);
  const inCases = useCallback((i: LintIssue) => (i.file ? i.file === "cases" : !result?.lint.includes(i)), [result]);
  const tabIssues = useMemo(() => [...(result?.lint ?? []), ...(result?.tests?.problems ?? [])].filter((i) => inCases(i) === (tab === "cases")), [tab, result, inCases]);
  const issuesRef = useRef(tabIssues);
  issuesRef.current = tabIssues;
  const applyJump = (view: EditorView) => {
    const issue = jumpRef.current;
    jumpRef.current = null;
    const r = issue && issueRange(view.state, issue);
    if (!r) return;
    view.dispatch({ selection: { anchor: r.from }, effects: EditorView.scrollIntoView(r.from, { y: "center" }) });
    view.focus();
  };
  const onCreateEditor = (view: EditorView) => {
    viewRef.current = view;
    paintIssues(view, issuesRef.current);
    applyJump(view);
  };
  useEffect(() => {
    if (viewRef.current) paintIssues(viewRef.current, tabIssues);
  }, [tabIssues]);
  const jumpTo = (issue: LintIssue) => {
    jumpRef.current = issue;
    const target = inCases(issue) ? "cases" : "rule";
    if (target === tab && viewRef.current) applyJump(viewRef.current);
    else setTab(target);
  };
  const quality = result?.quality;
  const meta = useMemo(() => parseMeta(rule), [rule]);
  const localReady: boolean | null = pending || !result ? null : result.state !== "fail" && Boolean(quality?.ready);

  const saveDraft = useCallback(async () => {
    if (!isEditor || !draftsOn || saveState.busy) return;
    setSaveState({ busy: true, error: null, conflict: false });
    const body = { path: ruleId, title: null, rule, cases: cases.trim() ? cases : null };
    try {
      const d = saved ? await api.updateDraft(saved.id, { ...body, version: saved.version }) : await api.createDraft(body);
      setSaved({ id: d.id, version: d.version, rule, cases, at: new Date() });
      setSaveState({ busy: false, error: null, conflict: false });
      void qc.invalidateQueries({ queryKey: ["drafts"] });
    } catch (e) {
      const status = e instanceof ApiError ? e.status : 0;
      setSaveState({ busy: false, error: (e as Error).message, conflict: status === 409 && saved !== null });
    }
  }, [isEditor, draftsOn, saveState.busy, ruleId, rule, cases, saved, qc]);

  /** Save = write the rule (and cases) into rules/ (ADR 0007). Returns the saved id/sha on success. */
  const saveFile = useCallback(async (): Promise<{ id: string; sha: string; cases_sha: string | null } | null> => {
    if (!isEditor || DEMO || fileSave.busy) return null;
    if (!disk?.sha && !fileSave.askPath) {
      setFileSave((f) => ({ ...f, askPath: true, error: null }));
      return null;
    }
    setFileSave((f) => ({ ...f, busy: true, error: null, conflict: false }));
    try {
      const casesBody = cases.trim() ? cases : null;
      const saved = ruleId && disk?.sha
        ? await api.updateRule(ruleId, { rule, cases: casesBody, remove_cases: casesBody === null && disk.cases_sha !== null, sha: disk.sha, cases_sha: disk.cases_sha })
        : await api.createRule({ path: newPath.trim(), rule, cases: casesBody });
      setDisk({ sha: saved.sha ?? null, cases_sha: saved.cases_sha ?? null, publication: saved.publication ?? null });
      setFileSave({ busy: false, error: null, conflict: false, askPath: false, savedAt: new Date() });
      void qc.invalidateQueries({ queryKey: ["rules"] });
      void qc.invalidateQueries({ queryKey: ["rule", saved.id] });
      if (!disk?.sha) navigate(`/editor/${saved.id}${publishAfterSave.current ? "?publish=1" : ""}`, { replace: true });
      else if (publishAfterSave.current) setPublishOpen(true);
      publishAfterSave.current = false;
      return { id: saved.id, sha: saved.sha ?? "", cases_sha: saved.cases_sha ?? null };
    } catch (e) {
      const status = e instanceof ApiError ? e.status : 0;
      setFileSave((f) => ({ ...f, busy: false, error: (e as Error).message, conflict: status === 409 }));
      return null;
    }
  }, [isEditor, fileSave.busy, fileSave.askPath, ruleId, disk, rule, cases, newPath, qc, navigate]);

  // Ctrl/Cmd+S saves the rule file (never publishes).
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "s") {
        e.preventDefault();
        void saveFile();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [saveFile]);

  const saveAsNew = () => {
    setSaved(null);
    setSaveState({ busy: false, error: null, conflict: false });
  };
  const closePublish = () => {
    setPublishOpen(false);
    if (saved) setOfferDelete(true);
  };
  const deleteLoaded = async () => {
    if (!saved) return;
    try {
      await api.deleteDraft(saved.id);
      setSaved(null);
      void qc.invalidateQueries({ queryKey: ["drafts"] });
    } catch (e) {
      setSaveState({ busy: false, error: (e as Error).message, conflict: false });
    }
    setOfferDelete(false);
  };

  const download = () => {
    const url = URL.createObjectURL(new Blob([rule], { type: "text/yaml" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = file?.split("/").pop() ?? "new_rule.yml";
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="flex h-full flex-col px-4 py-4 sm:px-8">
      <RuleHeader
        title={meta.title}
        meta={meta}
        file={file}
        result={result}
        publication={disk?.publication ?? null}
        isNew={!disk}
        dirty={disk ? fileDirty : dirty}
        savedAt={fileSave.savedAt}
        isEditor={isEditor}
        actions={
          <div className="flex flex-wrap items-center gap-2">
            {isEditor && (
              <button type="button" onClick={() => setDraftsOpen(true)} disabled={!draftsOn} aria-describedby={draftsReason ? "drafts-off" : undefined} className={btnSecondary}>
                <FolderOpen size={16} aria-hidden /> {t("drafts")}{draftsInfo.data ? ` (${draftsInfo.data.drafts.length})` : ""}
              </button>
            )}
            <button type="button" onClick={download} className={btnSecondary}>
              <Download size={16} aria-hidden /> {t("download_yml")}
            </button>
            <button
              type="button"
              onClick={() => void saveFile()}
              aria-disabled={!isEditor || DEMO}
              aria-describedby={!isEditor ? "viewer-save" : undefined}
              aria-busy={fileSave.busy}
              title={DEMO ? t("demo_disabled") : t("ed_save_tip")}
              className={clsx(btnSecondary, (!isEditor || DEMO) && "cursor-not-allowed opacity-50")}
            >
              {fileSave.busy ? <Loader2 size={16} className="animate-spin" aria-hidden /> : <Save size={16} aria-hidden />} {t("ed_save_locally")}
            </button>
            <button
              type="button"
              onClick={async () => {
                if (!isEditor || DEMO) return;
                if (!disk || fileDirty) {
                  publishAfterSave.current = true;
                  const ok = await saveFile();
                  if (!ok) return;
                }
                setPublishOpen(true);
              }}
              aria-disabled={!isEditor || DEMO}
              title={DEMO ? t("demo_disabled") : undefined}
              aria-describedby={!isEditor ? "viewer-publish" : undefined}
              className={clsx(btnPrimary, (!isEditor || DEMO) && "cursor-not-allowed opacity-50 shadow-none hover:brightness-100")}
            >
              <Rocket size={16} aria-hidden /> {t("publish")}
            </button>
          </div>
        }
      />
      <div className="mb-3 space-y-1 text-xs" aria-live="polite">
        {fileSave.askPath && !disk?.sha && (
          <form
            className="flex flex-wrap items-center gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              void saveFile();
            }}
          >
            <label className="flex items-center gap-2 text-muted">
              <span className="font-mono">rules/</span>
              <input value={newPath} onChange={(e) => setNewPath(e.target.value)} aria-label={t("ed_save_path")} className={clsx(inputCls, "w-72 py-1 font-mono")} />
            </label>
            <button type="submit" className={btnPrimary} disabled={fileSave.busy || !newPath.trim()}>
              {t("ed_save_here")}
            </button>
            <button type="button" className="text-muted hover:text-text" onClick={() => { publishAfterSave.current = false; setFileSave((f) => ({ ...f, askPath: false })); }}>
              {t("cancel")}
            </button>
          </form>
        )}
        {fileSave.error && !fileSave.conflict && (
          <p className="flex items-center gap-1.5 text-bad">
            <XCircle size={13} aria-hidden /> {fileSave.error}
          </p>
        )}
        {fileSave.conflict && (
          <p className="flex flex-wrap items-center gap-2 text-warn">
            <AlertTriangle size={13} aria-hidden /> {fileSave.error}
            {disk?.sha && (
              <button type="button" className="font-semibold text-accent hover:underline" onClick={() => window.location.reload()}>
                {t("ed_reload_disk")}
              </button>
            )}
          </p>
        )}
        {isEditor && draftsOn && (
          <p className="text-muted">
            <button type="button" title={t("ed_drafts_note")} className="font-semibold text-accent hover:underline" onClick={() => void saveDraft()} aria-busy={saveState.busy}>
              {t("ed_keep_scratch")}
            </button>
            {saved && !dirty && ` · ${t("ed_saved_at", { t: saved.at.toLocaleTimeString(locale(), { hour: "2-digit", minute: "2-digit" }) })}`}
            {fileSave.savedAt && !fileDirty && ` · ${t("ed_saved_at", { t: fileSave.savedAt.toLocaleTimeString(locale(), { hour: "2-digit", minute: "2-digit" }) })}`}
          </p>
        )}
        {draftsReason && (
          <p id="drafts-off" className="text-muted">
            {t("local_drafts_are_unavailable")} {draftsReason}
          </p>
        )}
        {saveState.error && !saveState.conflict && (
          <p className="flex items-center gap-1.5 text-bad">
            <XCircle size={13} aria-hidden /> {saveState.error}
          </p>
        )}
        {saveState.conflict && (
          <p className="flex flex-wrap items-center gap-2 text-warn">
            <AlertTriangle size={13} aria-hidden /> {t("someone_saved_a_newer_version")}
            <button type="button" className="font-semibold text-accent hover:underline" onClick={() => {
                if (!saved) return;
                navigate(`/editor?draft=${saved.id}`, { replace: true });
                void qc.invalidateQueries({ queryKey: ["draft", saved.id] });
              }}>
              {t("reload_draft")}
            </button>
            <button type="button" className="font-semibold text-accent hover:underline" onClick={saveAsNew}>
              {t("overwrite_as_new")}
            </button>
          </p>
        )}
        {offerDelete && saved && (
          <p className="flex flex-wrap items-center gap-2 text-text">
            {t("if_you_published_this_draft_delete_the")}
            <button type="button" className="font-semibold text-accent hover:underline" onClick={() => void deleteLoaded()}>
              {t("delete")}
            </button>
            <button type="button" className="text-muted hover:text-text" onClick={() => setOfferDelete(false)}>
              {t("keep")}
            </button>
          </p>
        )}
      </div>
      {!isEditor && (
        <Card className="mb-4 flex items-start gap-2 p-4 text-sm text-muted">
          <Eye size={16} className="mt-0.5 shrink-0" aria-hidden />
          <div>
            <p>{t("you_have_view_only_access_you_can_try_")}</p>
            <p id="viewer-save" className="mt-1 text-xs text-subtle">
              {t("save_locally_saving_needs_the_editor_r")}
            </p>
            <p id="viewer-publish" className="text-xs text-subtle">
              {t("publish_publishing_needs_the_editor_ro")}
            </p>
          </div>
        </Card>
      )}
      {publishOpen && isEditor && (
        <PublishDialog
          mode={{ kind: "rule", ruleId: ruleId ?? (disk ? newPath.trim() : null), rule, cases, draftId: saved?.id ?? props.draft?.id ?? null, file: disk?.sha ? { sha: disk.sha, cases_sha: disk.cases_sha } : undefined }}
          localReady={localReady}
          approval={quality ? t("ed_approved_by", { n: quality.score, req: quality.min_score ? t("ed_req_paren", { n: quality.min_score }) : "" }) : undefined}
          localDetail={quality && !quality.ready ? `Blocked: ${quality.blockers.join("; ")}` : result?.state === "fail" ? t("l_the_rule_has_lint_conversion_or_te") : undefined}
          onClose={closePublish}
        />
      )}
      {draftsOpen && (
        <DraftsSheet
          dirty={dirty}
          isAdmin={can(me, "admin")}
          currentId={saved?.id ?? null}
          onOpen={(draftId) => {
            setDraftsOpen(false);
            navigate(`/editor?draft=${draftId}`);
          }}
          onDeleted={(draftId) => saved?.id === draftId && setSaved(null)}
          onClose={() => setDraftsOpen(false)}
        />
      )}

      <div className="grid min-h-0 flex-1 grid-cols-1 gap-4 xl:grid-cols-2 xl:grid-rows-[minmax(0,1fr)]">
        <Card className="flex min-h-[420px] flex-col overflow-hidden xl:min-h-0">
          <div className="flex gap-1 border-b border-line px-3 pt-2" role="tablist">
            {(
              [
                ["rule", t("l_sigma_rule")],
                ["cases", t("ed_cases_file")],
              ] as const
            ).map(([key, label]) => (
              <button
                key={key}
                type="button"
                role="tab"
                aria-selected={tab === key}
                onClick={() => setTab(key)}
                className={clsx("-mb-px border-b-2 px-3 py-2 text-sm", tab === key ? "border-accent font-semibold text-strong" : "border-transparent text-muted hover:text-text")}
              >
                {label}
              </button>
            ))}
          </div>
          <div className="min-h-0 flex-1 overflow-auto bg-code">
            {tab === "rule" ? (
              <CodeMirror key="rule" value={rule} onChange={setRule} onCreateEditor={onCreateEditor} extensions={extensions} theme="none" height="100%" basicSetup={{ foldGutter: false }} />
            ) : (
              <CodeMirror key="cases" value={cases} onChange={setCases} onCreateEditor={onCreateEditor} extensions={extensions} theme="none" height="100%" basicSetup={{ foldGutter: false }} />
            )}
          </div>
        </Card>

        <div className="flex min-h-0 flex-col gap-4">
          {error && <ErrorBox message={error} />}
          {!result && !error && (
            <Card className="flex items-center gap-2 p-5 text-sm text-muted">
              <Loader2 size={16} className="animate-spin" aria-hidden /> {t("validating")}
            </Card>
          )}
          {result && (
            <>
              <AboutBand ruleId={ruleId} rule={rule} />
              <StatusBar result={result} pending={pending} />
              <Card className="flex flex-col overflow-hidden xl:min-h-0 xl:flex-1">
                <div className="no-scrollbar flex shrink-0 gap-1 overflow-x-auto overflow-y-hidden border-b border-line px-3 pt-2" role="tablist" aria-label={t("rule_panels")}>
                  {(
                    [
                      ["gate", t("l_quality_gate")],
                      ["replay", t("ed_test_replay")],
                      ["queries", t("l_queries")],
                      ...(ruleId ? ([["history", t("l_history")]] as const) : []),
                      ...(ruleId ? ([["drift", t("dr_tab")]] as const) : []),
                      ...(DEMO ? [] : ([["review", t("rv_tab")]] as const)),
                    ] as const
                  ).map(([key, label]) => (
                    <button
                      key={key}
                      type="button"
                      role="tab"
                      aria-selected={panel === key}
                      onClick={() => setPanel(key)}
                      className={clsx(
                        "-mb-px flex items-center gap-1.5 whitespace-nowrap border-b-2 px-3 py-2 text-sm",
                        panel === key ? "border-accent font-semibold text-strong" : "border-transparent text-muted hover:text-text",
                      )}
                    >
                      {label}
                      {key === "gate" && quality && !quality.ready && <XCircle size={13} className="text-bad" aria-label={t("blocked")} />}
                      {key === "replay" && replayBroken && <XCircle size={13} className="text-bad" aria-label={t("expectation_broken")} />}
                    </button>
                  ))}
                </div>
                <div className="p-4 xl:min-h-0 xl:flex-1 xl:overflow-y-auto" data-testid="editor-panel-body">
                  {panel === "gate" && quality && <GatePanel quality={quality} />}
                  {panel === "replay" && (
                    <div className="space-y-5">
                      <ProblemsPanel result={result} onJump={jumpTo} />
                      <ReplayPanel rule={rule} cases={cases} ruleId={ruleId} invalid={result.lint.some((i) => i.severity === "error" && REPLAY_BLOCKERS.has(i.code ?? ""))} onBroken={setReplayBroken} />
                    </div>
                  )}
                  {panel === "queries" && <QueriesPanel result={result} />}
                  {panel === "history" && ruleId && <HistoryPanel ruleId={ruleId} />}
                  {panel === "drift" && ruleId && <DriftPanel ruleId={ruleId} />}
                  {panel === "review" && <ReviewPanel kind={props.draft ? "draft" : "rule"} target={props.draft ? (saved?.id ?? props.draft.id) : ruleId} ruleText={rule} />}
                </div>
              </Card>
            </>
          )}
        </div>
      </div>
    </div>
  );
}


/** Always-visible summary: validation state, publish readiness and health score. */
function StatusBar({ result, pending }: { result: Validation; pending: boolean }) {
  const issues = [...result.lint, ...(result.tests?.problems ?? [])];
  const q = result.quality;
  return (
    <Card className="flex flex-wrap items-center justify-between gap-3 p-4">
      <span className="flex flex-wrap items-center gap-3">
        <StateBadge state={result.state} />
        {q && (
          <span
            className={clsx("inline-flex items-center gap-1 rounded-full px-2.5 py-1 text-xs font-semibold", q.ready ? "bg-good-soft text-good" : "bg-bad-soft text-bad")}
          >
            {q.ready ? <ShieldCheck size={13} aria-hidden /> : <XCircle size={13} aria-hidden />}
            {q.ready ? t("l_approved") : t("l_not_approved")}
          </span>
        )}
        {q && <HealthMeter score={q.score} />}
        {q && q.min_score > 0 && <span className="text-xs text-subtle">{q.score >= q.min_score ? t("ed_req_ge", { n: q.min_score }) : t("ed_req", { n: q.min_score })}</span>}
      </span>
      <span className="flex items-center gap-2 text-xs text-muted" aria-live="polite">
        {pending && <Loader2 size={14} className="animate-spin" aria-hidden />}
        {pending ? t("l_validating") : `${tn("n_errors", issues.filter((i) => i.severity === "error").length)} · ${tn("n_warnings", issues.filter((i) => i.severity === "warning").length)}`}
      </span>
    </Card>
  );
}

/** Approval: the rule is approved when no blocking check fails and the health score reaches the required minimum. */
function ApprovalCard({ quality }: { quality: DraftQuality }) {
  const { score, min_score: min, ready } = quality;
  const scoreOk = min === 0 || score >= min;
  const hardBlockers = quality.blockers.filter((b) => !b.startsWith("Health score at least"));
  const tone = ready ? "border-good/30 bg-good-soft" : "border-bad/30 bg-bad-soft";
  return (
    <div className={clsx("rounded-[10px] border p-4", tone)}>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className={clsx("flex items-center gap-2 text-sm font-semibold", ready ? "text-good" : "text-bad")}>
          {ready ? <ShieldCheck size={16} aria-hidden /> : <XCircle size={16} aria-hidden />}
          {ready ? t("l_approved_ready_to_publish") : t("l_not_approved_yet")}
        </p>
        <span className="font-mono text-sm font-bold text-strong tabular-nums">
          {score}
          <span className="font-normal text-muted"> / 100</span>
        </span>
      </div>
      {min > 0 && (
        <div className="mt-3" role="img" aria-label={t("ed_meter_aria", { s: score, m: min })}>
          <div className="relative h-2 rounded-full bg-surface-2">
            <span className={clsx("absolute inset-y-0 left-0 rounded-full", scoreOk ? "bg-good" : "bg-warn")} style={{ width: `${score}%` }} />
            <span className="absolute -top-1 bottom-[-4px] w-0.5 rounded bg-strong" style={{ left: `calc(${min}% - 1px)` }} />
          </div>
          <p className="mt-1.5 text-xs text-muted">
            {t("required_score")} <b className="text-strong">{min}</b> {t("ed_marker")} {scoreOk ? t("ed_score_met") : t("ed_score_more", { n: min - score })}
          </p>
        </div>
      )}
      <p className="mt-2 text-xs text-muted">
        {ready
          ? t("l_publishing_still_requires_the_real")
          : hardBlockers.length
            ? t("l_fix_every_blocker_first_the_score_")
            : t("l_no_blocker_but_the_health_score_is")}
      </p>
    </div>
  );
}

/** The quality gate, inside the editor: lifecycle, every check, blockers and replay. */
function GatePanel({ quality }: { quality: DraftQuality }) {
  return (
    <div className="space-y-4">
      <ApprovalCard quality={quality} />
      <FlowStepper stages={quality.stages} />
      {quality.blockers.length > 0 && (
        <div className="rounded-[10px] border border-bad/30 bg-bad-soft p-3">
          <p className="mb-1 flex items-center gap-1.5 text-sm font-semibold text-bad">
            <XCircle size={15} aria-hidden /> {t("ed_to_fix", { x: tn("n_blockers", quality.blockers.length) })}
          </p>
          <ul className="space-y-0.5 text-[13px] text-text">
            {quality.blockers.map((b) => (
              <li key={b}>• {b}</li>
            ))}
          </ul>
        </div>
      )}
      {quality.datasets.length > 0 && (
        <p className="text-xs text-muted">
          {t("replay")}{" "}
          {quality.datasets.map((d, i) => (
            <span key={d.dataset}>
              {i > 0 && " · "}
              <span className="font-mono">{d.dataset}</span> {d.error ? `(${d.error})` : t("ed_matches_of", { a: d.matches ?? 0, b: d.events ?? 0 })}
            </span>
          ))}
        </p>
      )}
      <CheckList checks={quality.checks} />
      <GateCriteria />
    </div>
  );
}

/** The workspace gate settings (what "approved" means), collapsed at the bottom of the Gate panel. */
function GateCriteria() {
  const { data } = useQuery({ queryKey: ["quality"], queryFn: api.quality });
  if (!data) return null;
  return (
    <details className="rounded-[10px] border border-line bg-surface">
      <summary className="cursor-pointer px-3 py-2 text-[13px] font-medium text-text">{t("gate_criteria")}</summary>
      <dl className="space-y-1.5 border-t border-line p-3 text-[12.5px]">
        {Object.entries(data.gate).map(([k, v]) => (
          <div key={k} className="flex justify-between gap-3">
            <dt className="text-muted">{GATE_LABELS[k] ?? k}</dt>
            <dd className="text-right font-mono text-text">{fmt(v, k)}</dd>
          </div>
        ))}
        <p className="pt-1 text-xs text-subtle">
          {t("tune")} <span className="font-mono">quality_gate</span> {t("in_vitrix_yml_in_ci")} <span className="font-mono">vitrix check --gate</span>.
        </p>
      </dl>
    </details>
  );
}

function QueriesPanel({ result }: { result: Validation }) {
  const [siem, setSiem] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const names = Object.keys(result.conversions);
  const active = siem && names.includes(siem) ? siem : (names[0] ?? null);
  const conv = active ? result.conversions[active] : null;

  const copy = async () => {
    if (!conv?.query) return;
    try {
      await navigator.clipboard.writeText(conv.query);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* no clipboard permission */
    }
  };

  if (names.length === 0) return <p className="text-sm text-muted">{t("fix_the_yaml_to_see_the_queries")}</p>;
  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between gap-2">
        <div className="no-scrollbar flex min-w-0 gap-1 overflow-x-auto overflow-y-hidden" role="tablist" aria-label={t("target_siem")}>
          {names.map((n) => (
            <button
              key={n}
              type="button"
              role="tab"
              aria-selected={n === active}
              onClick={() => setSiem(n)}
              className={clsx(
                "flex items-center gap-1.5 whitespace-nowrap rounded-md px-2.5 py-1.5 text-[13px]",
                n === active ? "bg-accent-soft font-semibold text-strong" : "text-muted hover:text-text",
              )}
            >
              {result.conversions[n].ok ? <CheckCircle2 size={13} className="text-good" aria-hidden /> : <XCircle size={13} className="text-bad" aria-hidden />}
              <TargetSwatch target={n} />
              {result.conversions[n].label}
              {result.targets.includes(n) && <span className="rounded bg-accent-soft px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-accent">{t("final")}</span>}
            </button>
          ))}
        </div>
        {conv?.ok && (
          <button type="button" onClick={copy} className="inline-flex shrink-0 items-center gap-1.5 rounded-md px-2 py-1 text-xs text-muted hover:bg-surface-2 hover:text-text">
            {copied ? <Check size={14} aria-hidden /> : <Copy size={14} aria-hidden />} {copied ? t("l_copied") : t("l_copy")}
          </button>
        )}
      </div>
      {conv?.ok && <pre className="overflow-auto whitespace-pre-wrap break-words rounded-[10px] border border-line bg-code p-4 font-mono text-[12.5px] leading-relaxed text-code-text">{conv.query}</pre>}
      {conv && !conv.ok && <ErrorBox message={conv.error ?? "conversion failed"} />}
      {conv && !conv.ok && conv.issues && conv.issues.length > 0 && <IssueList issues={conv.issues} />}
    </div>
  );
}

/** Lint and case-file problems with jump links (the case results live in the Test & Replay table). */
function ProblemsPanel({ result, onJump }: { result: Validation; onJump: (issue: LintIssue) => void }) {
  const issues = [...result.lint, ...(result.tests?.problems ?? [])];
  if (issues.length === 0) return null;
  return (
    <div>
      <h3 className="mb-1.5 text-[11px] font-semibold uppercase tracking-wider text-subtle">{t("problems")}</h3>
      <IssueList issues={issues} onJump={onJump} />
    </div>
  );
}

/** Audit trail: who created and changed this rule, from the Git history. */
function HistoryPanel({ ruleId }: { ruleId: string }) {
  const { data, error, isLoading } = useQuery({ queryKey: ["rule-history", ruleId], queryFn: () => api.ruleHistory(ruleId) });
  if (isLoading) return <p className="text-sm text-muted">{t("reading_git_history")}</p>;
  if (error) return <ErrorBox message={(error as Error).message} />;
  if (!data || !data.available) return <p className="text-sm text-muted">{data && !data.available ? (data.message ?? `${t("no_git_history_2")} ${data.reason}.`) : t("no_git_history_2")}</p>;
  if (!data.tracked) return <p className="text-sm text-muted">{t("this_rule_is_not_committed_yet")}</p>;
  return (
    <div className="space-y-3">
      <dl className="grid grid-cols-[7rem_1fr] gap-y-1 text-[13px]">
        <dt className="text-subtle">{t("created")}</dt>
        <dd className="text-text">
          {data.created ? formatDate(data.created) : "—"} by {data.created_by}
        </dd>
        <dt className="text-subtle">{t("last_change")}</dt>
        <dd className="text-text">
          {timeAgo(data.modified)} by {data.modified_by}
        </dd>
        <dt className="text-subtle">{t("commits")}</dt>
        <dd className="text-text">
          {data.commits} · {data.authors?.join(", ")}
        </dd>
      </dl>
      <ul className="divide-y divide-line">
        {data.log?.map((e) => (
          <li key={e.sha} className="py-2 text-[13px]">
            <span className="font-mono text-xs text-accent">{e.sha}</span> <span className="text-text">{e.subject}</span>
            <span className="block text-xs text-subtle">
              {e.change} · {e.author} · {formatDate(e.date)}
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}


interface RuleMeta {
  title: string | null;
  status: string | null;
  level: string | null;
  author: string | null;
  logsource: string | null;
}

/** Cheap read of the top-level scalar fields for the header (the server validates the real thing). */
function parseMeta(rule: string): RuleMeta {
  const top = (k: string) => {
    const m = new RegExp("^" + k + ":[ \t]*(.+?)[ \t]*$", "m").exec(rule);
    return m ? m[1].replace(/^['"]|['"]$/g, "") : null;
  };
  const ls = /^logsource:[ \t]*\r?\n((?:[ \t]+.*(?:\r?\n|$))+)/m.exec(rule)?.[1] ?? "";
  const part = (k: string) => new RegExp("^[ \t]+" + k + ":[ \t]*(.+?)[ \t]*$", "m").exec(ls)?.[1] ?? null;
  const parts = [part("product"), part("category"), part("service")].filter(Boolean);
  return { title: top("title"), status: top("status"), level: top("level"), author: top("author"), logsource: parts.length ? parts.join("/") : null };
}

const PUB: Record<string, { Icon: typeof HardDrive; cls: string; key: "ed_pub_local" | "ed_pub_pushed" | "ed_pub_pr" | "ed_pub_merged" | "ed_pub_unknown" }> = {
  local: { Icon: HardDrive, cls: "bg-warn-soft text-warn", key: "ed_pub_local" },
  pushed: { Icon: GitPullRequest, cls: "bg-accent-soft text-accent", key: "ed_pub_pushed" },
  in_pr: { Icon: GitPullRequest, cls: "bg-accent-soft text-accent", key: "ed_pub_pr" },
  published: { Icon: GitMerge, cls: "bg-good-soft text-good", key: "ed_pub_merged" },
  unknown: { Icon: CircleDot, cls: "bg-surface-2 text-muted", key: "ed_pub_unknown" },
};

/** Publication state of a rule: icon + text (never colour alone). */
export function PublicationBadge({ pub, isNew }: { pub: Publication | null; isNew: boolean }) {
  if (!isNew && !pub) return null;
  if (isNew || !pub) {
    return (
      <span className="inline-flex items-center gap-1.5 rounded-full bg-surface-2 px-2.5 py-1 text-xs font-semibold text-muted">
        <FilePlus size={13} aria-hidden /> {t("ed_pub_new")}
      </span>
    );
  }
  const v = PUB[pub.state] ?? PUB.unknown;
  const label = pub.state === "in_pr" && pub.pr ? t("ed_pub_pr_n", { n: pub.pr.number }) : t(v.key);
  const body = (
    <>
      <v.Icon size={13} aria-hidden /> {label}
    </>
  );
  const cls = clsx("inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-semibold", v.cls);
  const tip = pub.state === "local" ? t("ed_pub_local_tip") : (pub.reason ?? undefined);
  return pub.pr && /^https:/.test(pub.pr.url) ? (
    <a href={pub.pr.url} target="_blank" rel="noreferrer" className={cls} title={tip}>
      {body}
    </a>
  ) : (
    <span className={cls} title={tip}>
      {body}
    </span>
  );
}

function RuleHeader(props: { title: string | null; meta: RuleMeta; file: string | null; result: Validation | null; publication: Publication | null; isNew: boolean; dirty: boolean; savedAt: Date | null; isEditor: boolean; actions: React.ReactNode }) {
  const { title, meta, file, result, publication, isNew, dirty, savedAt, actions } = props;
  const finals = result?.targets ?? [];
  const others = Object.keys(result?.conversions ?? {}).filter((n) => !finals.includes(n));
  return (
    <header className="mb-3 flex flex-wrap items-start justify-between gap-3" data-testid="rule-header">
      <div className="min-w-0 flex-1 space-y-1.5">
        <h1 className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[22px] font-bold tracking-[-0.02em] text-strong">
          <span className="truncate" title={title ?? undefined}>
            {title ?? t("l_new_rule")}
          </span>
          <PublicationBadge pub={publication} isNew={isNew} />
          {meta?.level && <LevelTag level={meta.level} />}
          {dirty && (
            <span className="inline-flex items-center gap-1.5 text-xs font-normal text-text">
              <span className="size-2 rounded-full bg-accent" aria-hidden /> {t("unsaved_changes")}
            </span>
          )}
        </h1>
        <p className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted">
          {meta?.status && <span>{meta.status}</span>}
          <span>{meta?.author ? t("ed_by", { a: meta.author }) : t("ed_no_author")}</span>
          {meta?.logsource && <span className="font-mono">{meta.logsource}</span>}
          {finals.length > 0 && (
            <span className="inline-flex items-center gap-1.5">
              {t("ed_final_lang")} {finals.map((n) => <TargetSwatch key={n} target={n} />)} {finals.map((n) => result?.conversions[n]?.label ?? n).join(", ")}
              {others.length > 0 && <span className="text-subtle">+{others.length}</span>}
            </span>
          )}
          <span className="font-mono">{file ?? t("ed_not_saved")}</span>
          {savedAt && <span>{t("ed_saved_at", { t: savedAt.toLocaleTimeString(locale(), { hour: "2-digit", minute: "2-digit" }) })}</span>}
        </p>
      </div>
      {actions}
    </header>
  );
}

/** Collapsible "About this rule": what the panels mean, related rules, last changes. Remembered per browser. */
function AboutBand({ ruleId, rule }: { ruleId: string | null; rule: string }) {
  const [open, setOpen] = useState(() => {
    try {
      return localStorage.getItem("vitrix.editor.about") === "open";
    } catch {
      return false;
    }
  });
  const [all, setAll] = useState(false);
  const related = useQuery({
    queryKey: ["related", ruleId],
    queryFn: () => (ruleId ? api.related(ruleId, 20) : api.relatedDraft(rule)),
    enabled: open && ruleId !== null,
    retry: false,
  });
  const history = useQuery({ queryKey: ["rule-history", ruleId], queryFn: () => api.ruleHistory(ruleId!), enabled: open && ruleId !== null, retry: false });
  const rows = related.data ?? [];
  const shown = all ? rows : rows.slice(0, 3);
  return (
    <details
      open={open}
      onToggle={(e) => {
        const o = (e.currentTarget as HTMLDetailsElement).open;
        setOpen(o);
        try {
          localStorage.setItem("vitrix.editor.about", o ? "open" : "closed");
        } catch {
          /* storage unavailable */
        }
      }}
      className="rounded-[12px] border border-line bg-surface text-[13px]"
    >
      <summary className="flex cursor-pointer items-center gap-2 px-4 py-2.5 font-semibold text-strong">
        <ChevronDown size={14} className="text-muted" aria-hidden /> {t("ed_about")}
      </summary>
      <div className="space-y-4 border-t border-line px-4 py-3">
        <div>
          <h3 className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-subtle">{t("ed_panels_mean")}</h3>
          <dl className="grid grid-cols-[8.5rem_1fr] gap-y-0.5 text-muted">
            <dt className="text-text">{t("l_quality_gate")}</dt>
            <dd>{t("ed_help_gate")}</dd>
            <dt className="text-text">{t("ed_test_replay")}</dt>
            <dd>{t("ed_help_replay")}</dd>
            <dt className="text-text">{t("l_queries")}</dt>
            <dd>{t("ed_help_queries")}</dd>
          </dl>
        </div>
        <div>
          <h3 className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-subtle">{t("ed_related")}</h3>
          {ruleId === null ? (
            <p className="text-muted">{t("ed_related_unsaved")}</p>
          ) : related.isLoading ? (
            <p className="text-muted">{t("loading")}</p>
          ) : related.error ? (
            <p className="text-muted">{t("ed_related_none")}</p>
          ) : rows.length === 0 ? (
            <p className="text-muted">{t("ed_related_none")}</p>
          ) : (
            <ul className="divide-y divide-line">
              {shown.map((r) => (
                <li key={r.id} className="flex flex-wrap items-baseline gap-x-3 py-1.5">
                  <Link to={`/editor/${r.id}`} className="font-medium text-text hover:text-accent">
                    {r.title}
                  </Link>
                  <span className="font-mono text-xs text-subtle">{r.logsource}</span>
                  {r.shared_fields.length > 0 && <span className="text-xs text-muted">{t("ed_shares")} {r.shared_fields.join(", ")}</span>}
                </li>
              ))}
            </ul>
          )}
          {rows.length > 3 && (
            <button type="button" className="mt-1 text-xs font-medium text-accent hover:underline" onClick={() => setAll(!all)}>
              {all ? t("ed_show_less") : t("ed_show_all", { n: rows.length - 3 })}
            </button>
          )}
        </div>
        <div>
          <h3 className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-subtle">{t("ed_last_changes")}</h3>
          {ruleId === null ? (
            <p className="text-muted">{t("ed_history_unsaved")}</p>
          ) : history.data && !history.data.available ? (
            <p className="text-muted">{history.data.message ?? history.data.reason}</p>
          ) : history.data?.available && history.data.log && history.data.log.length > 0 ? (
            <ul className="space-y-0.5">
              {history.data.log.slice(0, 3).map((e) => (
                <li key={e.sha}>
                  <span className="font-mono text-xs text-accent">{e.sha}</span> <span className="text-text">{e.subject}</span> <span className="text-xs text-subtle">{e.author} · {timeAgo(e.date)}</span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-muted">{history.isLoading ? t("loading") : t("this_rule_is_not_committed_yet")}</p>
          )}
        </div>
      </div>
    </details>
  );
}
