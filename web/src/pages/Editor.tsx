import { useQuery } from "@tanstack/react-query";
import CodeMirror from "@uiw/react-codemirror";
import clsx from "clsx";
import { Check, CheckCircle2, Copy, Download, Loader2, Rocket, ShieldCheck, XCircle } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { useParams } from "react-router-dom";
import { api } from "../api";
import { yamlExtensions } from "../components/code";
import { HealthMeter, formatDate, timeAgo } from "../components/dash";
import { CheckList, FlowStepper, KindTag } from "../components/flow";
import { PublishDialog } from "../components/PublishDialog";
import { Card, ErrorBox, PageHeader, StateBadge, TargetSwatch, btnPrimary, btnSecondary } from "../components/ui";
import type { DraftQuality, Impact, Validation } from "../types";

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
  const detail = useQuery({ queryKey: ["rule", id], queryFn: () => api.rule(id!), enabled: id !== null });

  if (id !== null && detail.isLoading) return <div className="p-8 text-muted">Loading rule…</div>;
  if (id !== null && detail.error) {
    return (
      <div className="p-8">
        <ErrorBox message={(detail.error as Error).message} />
      </div>
    );
  }
  return (
    <EditorWorkspace
      key={id ?? "new"}
      ruleId={id}
      file={detail.data?.file ?? null}
      initialRule={detail.data?.text ?? newRuleTemplate()}
      initialCases={detail.data ? (detail.data.tests.cases_text ?? "") : CASES_TEMPLATE}
    />
  );
}

type Panel = "gate" | "queries" | "tests" | "impact" | "history";

function EditorWorkspace(props: { ruleId: string | null; file: string | null; initialRule: string; initialCases: string }) {
  const { ruleId, file, initialRule, initialCases } = props;
  const [rule, setRule] = useState(initialRule);
  const [cases, setCases] = useState(initialCases);
  const [tab, setTab] = useState<"rule" | "cases">("rule");
  const [panel, setPanel] = useState<Panel>("gate");
  const [result, setResult] = useState<Validation | null>(null);
  const [pending, setPending] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [publishOpen, setPublishOpen] = useState(false);

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

  const extensions = useMemo(yamlExtensions, []);
  const quality = result?.quality;
  const localReady: boolean | null = pending || !result ? null : result.state !== "fail" && Boolean(quality?.ready);

  const download = () => {
    const url = URL.createObjectURL(new Blob([rule], { type: "text/yaml" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = file?.split("/").pop() ?? "new_rule.yml";
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="flex h-full flex-col px-4 py-8 sm:px-8">
      <PageHeader
        title={file ?? "New rule"}
        subtitle="Validation, tests and the quality gate run on every change. Nothing is written to disk: a change goes to the repository through CI, then a pull request."
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <button type="button" onClick={download} className={btnSecondary}>
              <Download size={16} aria-hidden /> Download .yml
            </button>
            <button type="button" onClick={() => setPublishOpen(true)} className={btnPrimary}>
              <Rocket size={16} aria-hidden /> Publish
            </button>
          </div>
        }
      />
      {publishOpen && (
        <PublishDialog
          mode={{ kind: "rule", ruleId, rule, cases }}
          localReady={localReady}
          approval={quality ? `Approved by the quality gate: health ${quality.score}/100${quality.min_score ? ` (${quality.min_score} required)` : ""}.` : undefined}
          localDetail={quality && !quality.ready ? `Blocked: ${quality.blockers.join("; ")}` : result?.state === "fail" ? "The rule has lint, conversion or test errors." : undefined}
          onClose={() => setPublishOpen(false)}
        />
      )}

      <div className="grid min-h-0 flex-1 grid-cols-1 gap-4 xl:grid-cols-2">
        <Card className="flex min-h-[420px] flex-col overflow-hidden">
          <div className="flex gap-1 border-b border-line px-3 pt-2" role="tablist">
            {(
              [
                ["rule", "Sigma rule"],
                ["cases", "Test cases"],
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
          <div className="min-h-0 flex-1 overflow-auto">
            {tab === "rule" ? (
              <CodeMirror key="rule" value={rule} onChange={setRule} extensions={extensions} theme="none" height="100%" basicSetup={{ foldGutter: false }} />
            ) : (
              <CodeMirror key="cases" value={cases} onChange={setCases} extensions={extensions} theme="none" height="100%" basicSetup={{ foldGutter: false }} />
            )}
          </div>
        </Card>

        <div className="flex min-h-0 flex-col gap-4 overflow-auto">
          {error && <ErrorBox message={error} />}
          {!result && !error && (
            <Card className="flex items-center gap-2 p-5 text-sm text-muted">
              <Loader2 size={16} className="animate-spin" aria-hidden /> Validating…
            </Card>
          )}
          {result && (
            <>
              <StatusBar result={result} pending={pending} />
              <Card className="overflow-hidden">
                <div className="flex gap-1 overflow-x-auto border-b border-line px-3 pt-2" role="tablist" aria-label="Rule panels">
                  {(
                    [
                      ["gate", "Quality gate"],
                      ["queries", "Queries"],
                      ["tests", "Tests"],
                      ["impact", "Impact"],
                      ...(ruleId ? ([["history", "History"]] as const) : []),
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
                      {key === "gate" && quality && !quality.ready && <XCircle size={13} className="text-bad" aria-label="blocked" />}
                    </button>
                  ))}
                </div>
                <div className="p-4">
                  {panel === "gate" && quality && <GatePanel quality={quality} />}
                  {panel === "queries" && <QueriesPanel result={result} />}
                  {panel === "tests" && <TestsPanel result={result} />}
                  {panel === "impact" && <ImpactPanel rule={rule} ruleId={ruleId} />}
                  {panel === "history" && ruleId && <HistoryPanel ruleId={ruleId} />}
                </div>
              </Card>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;

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
            {q.ready ? "Approved" : "Not approved"}
          </span>
        )}
        {q && <HealthMeter score={q.score} />}
        {q && q.min_score > 0 && <span className="text-xs text-subtle">{q.score >= q.min_score ? `≥ ${q.min_score} required` : `${q.min_score} required`}</span>}
      </span>
      <span className="flex items-center gap-2 text-xs text-muted" aria-live="polite">
        {pending && <Loader2 size={14} className="animate-spin" aria-hidden />}
        {pending ? "Validating…" : `${plural(issues.filter((i) => i.severity === "error").length, "error", "errors")} · ${plural(issues.filter((i) => i.severity === "warning").length, "warning", "warnings")}`}
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
          {ready ? "Approved: ready to publish" : "Not approved yet"}
        </p>
        <span className="font-mono text-sm font-bold text-strong tabular-nums">
          {score}
          <span className="font-normal text-muted"> / 100</span>
        </span>
      </div>
      {min > 0 && (
        <div className="mt-3" role="img" aria-label={`Health score ${score} of 100; ${min} required for approval`}>
          <div className="relative h-2 rounded-full bg-surface-2">
            <span className={clsx("absolute inset-y-0 left-0 rounded-full", scoreOk ? "bg-good" : "bg-warn")} style={{ width: `${score}%` }} />
            <span className="absolute -top-1 bottom-[-4px] w-0.5 rounded bg-strong" style={{ left: `calc(${min}% - 1px)` }} />
          </div>
          <p className="mt-1.5 text-xs text-muted">
            Required score: <b className="text-strong">{min}</b> (marker). {scoreOk ? "The score requirement is met." : `${min - score} more point(s) needed: fix the failing checks below.`}
          </p>
        </div>
      )}
      <p className="mt-2 text-xs text-muted">
        {ready
          ? "Publishing still requires the real CI to pass for the exact commit."
          : hardBlockers.length
            ? "Fix every blocker first; the score only counts once nothing blocks."
            : "No blocker, but the health score is below the required minimum."}
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
            <XCircle size={15} aria-hidden /> {plural(quality.blockers.length, "blocker", "blockers")} to fix
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
          Replay:{" "}
          {quality.datasets.map((d, i) => (
            <span key={d.dataset}>
              {i > 0 && " · "}
              <span className="font-mono">{d.dataset}</span> {d.error ? `(${d.error})` : `matches ${d.matches}/${d.events} events`}
            </span>
          ))}
        </p>
      )}
      <CheckList checks={quality.checks} />
    </div>
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

  if (names.length === 0) return <p className="text-sm text-muted">Fix the YAML to see the queries.</p>;
  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between gap-2">
        <div className="flex min-w-0 gap-1 overflow-x-auto" role="tablist" aria-label="Target SIEM">
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
              {result.targets.includes(n) && <span className="rounded bg-accent-soft px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-accent">final</span>}
            </button>
          ))}
        </div>
        {conv?.ok && (
          <button type="button" onClick={copy} className="inline-flex shrink-0 items-center gap-1.5 rounded-md px-2 py-1 text-xs text-muted hover:bg-surface-2 hover:text-text">
            {copied ? <Check size={14} aria-hidden /> : <Copy size={14} aria-hidden />} {copied ? "Copied" : "Copy"}
          </button>
        )}
      </div>
      {conv?.ok && <pre className="overflow-auto whitespace-pre-wrap break-words rounded-[10px] border border-line bg-code p-4 font-mono text-[12.5px] leading-relaxed text-code-text">{conv.query}</pre>}
      {conv && !conv.ok && <ErrorBox message={conv.error ?? "conversion failed"} />}
    </div>
  );
}

function TestsPanel({ result }: { result: Validation }) {
  const issues = [...result.lint, ...(result.tests?.problems ?? [])];
  return (
    <div className="space-y-4">
      {result.tests === null ? (
        <p className="text-sm text-muted">No test cases. Add them in the “Test cases” tab.</p>
      ) : result.tests.results.length === 0 ? (
        <p className="text-sm text-muted">No valid case found.</p>
      ) : (
        <ul className="space-y-1.5 text-sm">
          {result.tests.results.map((r, n) => (
            <li key={n} className="flex items-start gap-2">
              {r.passed ? <CheckCircle2 size={16} className="mt-0.5 shrink-0 text-good" aria-hidden /> : <XCircle size={16} className="mt-0.5 shrink-0 text-bad" aria-hidden />}
              <span>
                {r.name} <KindTag kind={r.kind} />
                {r.exercises_filter && <span className="ml-1.5 text-xs text-subtle">· proves the exclusion</span>}
                {!r.passed && <span className="block text-xs text-bad">{r.error ?? `expected ${r.expect}, got ${r.got}`}</span>}
              </span>
            </li>
          ))}
        </ul>
      )}
      {issues.length > 0 && (
        <div>
          <h3 className="mb-1.5 text-[11px] font-semibold uppercase tracking-wider text-subtle">Problems</h3>
          <ul className="space-y-1.5 text-sm">
            {issues.map((i, n) => (
              <li key={n} className="flex gap-2">
                <span className={clsx("shrink-0 font-medium", i.severity === "error" ? "text-bad" : "text-warn")}>{i.severity === "error" ? "Error" : "Warning"}</span>
                <span className="text-text">{i.message}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

/** Impact analysis: how many events the edited rule matches vs. the saved one, per dataset. */
function ImpactPanel({ rule, ruleId }: { rule: string; ruleId: string | null }) {
  const [data, setData] = useState<Impact | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const ctrl = new AbortController();
    const timer = setTimeout(() => {
      api
        .impact(rule, ruleId, ctrl.signal)
        .then((r) => {
          setData(r);
          setError(null);
        })
        .catch((e: Error) => {
          if (e.name !== "AbortError") setError(e.message);
        });
    }, 600);
    return () => {
      clearTimeout(timer);
      ctrl.abort();
    };
  }, [rule, ruleId]);

  if (error) return <ErrorBox message={error} />;
  if (!data) return <p className="flex items-center gap-2 text-sm text-muted"><Loader2 size={14} className="animate-spin" aria-hidden /> Replaying datasets…</p>;
  if (data.datasets.length === 0) {
    return (
      <p className="text-sm text-muted">
        No dataset in <span className="font-mono">datasets/</span>. Add logs there to see how a change moves the matches before opening a pull request.
      </p>
    );
  }
  return (
    <div className="space-y-3">
      <p className="text-[13px] text-muted">
        {data.saved ? "Edited version vs. the version saved in the repository, replayed on the same datasets." : "New rule: events each dataset would match."}
        {data.saved && !data.changed && " No event changes its result."}
      </p>
      <ul className="space-y-3">
        {data.datasets.map((d) => (
          <li key={d.dataset} className="rounded-[10px] border border-line bg-surface p-3 text-[13px]">
            <p className="font-mono text-xs text-subtle">{d.dataset}</p>
            {d.error ? (
              <p className="text-bad">{d.error}</p>
            ) : (
              <>
                <p className="mt-1 text-text">
                  {d.before !== null && d.before !== undefined && (
                    <>
                      <span className="tabular-nums">{d.before}</span> → <b className="tabular-nums text-strong">{d.after}</b> matches
                    </>
                  )}
                  {(d.before === null || d.before === undefined) && (
                    <>
                      <b className="tabular-nums text-strong">{d.after}</b> of {d.events} events match
                    </>
                  )}
                </p>
                {(d.added?.length ?? 0) > 0 && <p className="text-xs text-muted">Now matching: events {d.added!.map((i) => `#${i}`).join(", ")}</p>}
                {(d.removed?.length ?? 0) > 0 && <p className="text-xs text-muted">No longer matching: events {d.removed!.map((i) => `#${i}`).join(", ")}</p>}
                {d.meets_expectation !== null && d.meets_expectation !== undefined && (
                  <p className="mt-1 flex items-center gap-1.5 text-xs">
                    {d.meets_expectation ? <CheckCircle2 size={13} className="text-good" aria-hidden /> : <XCircle size={13} className="text-bad" aria-hidden />}
                    <span className={d.meets_expectation ? "text-muted" : "text-bad"}>
                      {d.meets_expectation ? "Meets" : "Breaks"} the dataset expectation
                      {d.expected && ` (${d.expected.max === d.expected.min ? `exactly ${d.expected.min}` : `${d.expected.min}–${d.expected.max ?? "∞"}`})`}
                    </span>
                  </p>
                )}
              </>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}

/** Audit trail: who created and changed this rule, from the Git history. */
function HistoryPanel({ ruleId }: { ruleId: string }) {
  const { data, error, isLoading } = useQuery({ queryKey: ["rule-history", ruleId], queryFn: () => api.ruleHistory(ruleId) });
  if (isLoading) return <p className="text-sm text-muted">Reading Git history…</p>;
  if (error) return <ErrorBox message={(error as Error).message} />;
  if (!data || !data.available) return <p className="text-sm text-muted">No Git history: {data && !data.available ? data.reason : "unavailable"}.</p>;
  if (!data.tracked) return <p className="text-sm text-muted">This rule is not committed yet.</p>;
  return (
    <div className="space-y-3">
      <dl className="grid grid-cols-[7rem_1fr] gap-y-1 text-[13px]">
        <dt className="text-subtle">Created</dt>
        <dd className="text-text">
          {data.created ? formatDate(data.created) : "—"} by {data.created_by}
        </dd>
        <dt className="text-subtle">Last change</dt>
        <dd className="text-text">
          {timeAgo(data.modified)} by {data.modified_by}
        </dd>
        <dt className="text-subtle">Commits</dt>
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
