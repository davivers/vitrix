import { useQuery } from "@tanstack/react-query";
import CodeMirror from "@uiw/react-codemirror";
import clsx from "clsx";
import { Check, CheckCircle2, Copy, Download, GitPullRequest, Loader2, XCircle } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { useParams } from "react-router-dom";
import { api } from "../api";
import { PullRequestDialog } from "../components/PullRequestDialog";
import { yamlExtensions } from "../components/code";
import { Card, ErrorBox, PageHeader, StateBadge, TargetSwatch } from "../components/ui";
import type { DraftQuality, Validation } from "../types";
import { CheckList, FlowStepper, KindTag } from "../components/flow";

function newRuleTemplate(): string {
  return `title: Nome da regra
id: ${crypto.randomUUID()}
status: experimental
description: O que esta regra detecta
author: seu nome
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
  - Automação legítima
level: medium
`;
}

const CASES_TEMPLATE = `cases:
  - name: Positivo · powershell -enc
    expect: match
    event:
      Image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'
      CommandLine: 'powershell.exe -enc JABz'
  - name: Negativo · cmd comum
    expect: no_match
    event:
      Image: 'C:\\Windows\\System32\\cmd.exe'
      CommandLine: 'cmd.exe /c dir'
`;

export default function EditorPage() {
  const id = useParams()["*"] || null;
  const detail = useQuery({ queryKey: ["rule", id], queryFn: () => api.rule(id!), enabled: id !== null });

  if (id !== null && detail.isLoading) return <div className="p-8 text-muted">Carregando regra…</div>;
  if (id !== null && detail.error) {
    return (
      <div className="p-8">
        <ErrorBox message={(detail.error as Error).message} />
      </div>
    );
  }
  return (
    <EditorWorkspace
      key={id ?? "nova"}
      ruleId={id}
      file={detail.data?.file ?? null}
      initialRule={detail.data?.text ?? newRuleTemplate()}
      initialCases={detail.data ? (detail.data.tests.cases_text ?? "") : CASES_TEMPLATE}
    />
  );
}

function EditorWorkspace(props: { ruleId: string | null; file: string | null; initialRule: string; initialCases: string }) {
  const { ruleId, file, initialRule, initialCases } = props;
  const [rule, setRule] = useState(initialRule);
  const [cases, setCases] = useState(initialCases);
  const [tab, setTab] = useState<"rule" | "cases">("rule");
  const [result, setResult] = useState<Validation | null>(null);
  const [pending, setPending] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [prOpen, setPrOpen] = useState(false);

  // Valida 500 ms depois da última tecla; cancela a chamada anterior se ainda estiver em voo.
  useEffect(() => {
    const ctrl = new AbortController();
    setPending(true);
    const timer = setTimeout(() => {
      api
        .validate(rule, cases.trim() ? cases : null, ctrl.signal)
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
  }, [rule, cases]);

  const extensions = useMemo(yamlExtensions, []);

  const download = () => {
    const url = URL.createObjectURL(new Blob([rule], { type: "text/yaml" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = file?.split("/").pop() ?? "nova_regra.yml";
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="flex h-full flex-col px-8 py-8">
      <PageHeader
        title={file ?? "Nova regra"}
        subtitle="A validação roda a cada alteração. Nada é gravado em disco: a mudança vai para o repositório por pull request."
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={download}
              className="inline-flex items-center gap-2 rounded-[10px] border border-line bg-surface-2 px-3 py-2 text-[13.5px] font-semibold text-text hover:bg-surface-3"
            >
              <Download size={16} aria-hidden /> Baixar .yml
            </button>
            <button
              type="button"
              onClick={() => setPrOpen(true)}
              className="inline-flex items-center gap-2 rounded-[10px] bg-brand px-4 py-2 text-[13.5px] font-semibold text-strong shadow-[0_8px_24px_-10px_rgb(109_91_240/0.8)] hover:brightness-110"
            >
              <GitPullRequest size={16} aria-hidden /> Abrir pull request
            </button>
          </div>
        }
      />
      {prOpen && (
        <PullRequestDialog
          onClose={() => setPrOpen(false)}
          ruleId={ruleId}
          rule={rule}
          cases={cases}
          state={pending ? null : (result?.state ?? null)}
        />
      )}

      <div className="grid min-h-0 flex-1 grid-cols-1 gap-4 xl:grid-cols-2">
        <Card className="flex min-h-[420px] flex-col overflow-hidden">
          <div className="flex gap-1 border-b border-line px-3 pt-2" role="tablist">
            {(
              [
                ["rule", "Regra Sigma"],
                ["cases", "Casos de teste"],
              ] as const
            ).map(([key, label]) => (
              <button
                key={key}
                type="button"
                role="tab"
                aria-selected={tab === key}
                onClick={() => setTab(key)}
                className={clsx(
                  "-mb-px border-b-2 px-3 py-2 text-sm",
                  tab === key ? "border-accent font-semibold text-strong" : "border-transparent text-muted hover:text-text",
                )}
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
          <ResultPanel result={result} pending={pending} error={error} />
        </div>
      </div>
    </div>
  );
}

/** O fluxo da regra em edição: trilha de etapas, bloqueios do gate e replay nos datasets. */
function QualityCard({ quality }: { quality: DraftQuality }) {
  const [open, setOpen] = useState(false);
  return (
    <Card className="p-4">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <h2 className="text-sm font-semibold text-strong">Fluxo até a publicação</h2>
        <span className={clsx("inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-semibold", quality.ready ? "bg-good-soft text-good" : "bg-bad-soft text-bad")}>
          {quality.ready ? <CheckCircle2 size={12} aria-hidden /> : <XCircle size={12} aria-hidden />}
          {quality.ready ? "Pronta para publicar" : "Bloqueada no quality gate"}
        </span>
      </div>
      <FlowStepper stages={quality.stages} />
      {quality.blockers.length > 0 && (
        <ul className="mt-3 space-y-1 text-[13px]">
          {quality.blockers.map((b) => (
            <li key={b} className="flex gap-2">
              <XCircle size={14} className="mt-0.5 shrink-0 text-bad" aria-hidden />
              <span className="text-text">{b}</span>
            </li>
          ))}
        </ul>
      )}
      {quality.datasets.length > 0 && (
        <p className="mt-3 text-xs text-muted">
          Replay:{" "}
          {quality.datasets.map((d, i) => (
            <span key={d.dataset}>
              {i > 0 && " · "}
              <span className="font-mono">{d.dataset}</span> {d.error ? `(${d.error})` : `${d.matches}/${d.events} eventos`}
            </span>
          ))}
        </p>
      )}
      <button type="button" onClick={() => setOpen(!open)} aria-expanded={open} className="mt-3 text-xs font-medium text-accent hover:underline">
        {open ? "Ocultar verificações" : "Ver todas as verificações"}
      </button>
      {open && (
        <div className="mt-3">
          <CheckList checks={quality.checks} />
        </div>
      )}
    </Card>
  );
}

const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;

function ResultPanel({ result, pending, error }: { result: Validation | null; pending: boolean; error: string | null }) {
  const [siem, setSiem] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  if (error) return <ErrorBox message={error} />;
  if (!result) {
    return (
      <Card className="flex items-center gap-2 p-5 text-sm text-muted">
        <Loader2 size={16} className="animate-spin" aria-hidden /> Validando…
      </Card>
    );
  }

  const names = Object.keys(result.conversions);
  const active = siem && names.includes(siem) ? siem : (names[0] ?? null);
  const conv = active ? result.conversions[active] : null;
  const issues = [...result.lint, ...(result.tests?.problems ?? [])];

  const copy = async () => {
    if (!conv?.query) return;
    try {
      await navigator.clipboard.writeText(conv.query);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* sem permissão de área de transferência */
    }
  };

  return (
    <>
      <Card className="flex items-center justify-between p-4">
        <StateBadge state={result.state} />
        <span className="flex items-center gap-2 text-xs text-muted" aria-live="polite">
          {pending && <Loader2 size={14} className="animate-spin" aria-hidden />}
          {pending ? "Validando…" : `${plural(issues.filter((i) => i.severity === "error").length, "erro", "erros")} · ${plural(issues.filter((i) => i.severity === "warning").length, "aviso", "avisos")}`}
        </span>
      </Card>

      {result.quality && <QualityCard quality={result.quality} />}

      {issues.length > 0 && (
        <Card className="p-4">
          <h2 className="mb-2 text-sm font-semibold text-strong">Problemas</h2>
          <ul className="space-y-1.5 text-sm">
            {issues.map((i, n) => (
              <li key={n} className={clsx("flex gap-2", i.severity === "error" ? "text-bad" : "text-warn")}>
                <span className="shrink-0 font-medium">{i.severity === "error" ? "Erro" : "Aviso"}</span>
                <span className="text-text">{i.message}</span>
              </li>
            ))}
          </ul>
        </Card>
      )}

      <Card className="overflow-hidden">
        <div className="flex items-center justify-between border-b border-line px-3 pt-2">
          <div className="flex min-w-0 gap-1 overflow-x-auto" role="tablist" aria-label="SIEM de destino">
            {names.map((n) => (
              <button
                key={n}
                type="button"
                role="tab"
                aria-selected={n === active}
                onClick={() => setSiem(n)}
                className={clsx(
                  "-mb-px flex items-center gap-1.5 whitespace-nowrap border-b-2 px-3 py-2 text-sm",
                  n === active ? "border-accent font-semibold text-strong" : "border-transparent text-muted hover:text-text",
                )}
              >
                {result.conversions[n].ok ? <CheckCircle2 size={14} className="text-good" aria-hidden /> : <XCircle size={14} className="text-bad" aria-hidden />}
                <TargetSwatch target={n} />
                {result.conversions[n].label}
                {result.targets.includes(n) && <span className="rounded bg-accent-soft px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-accent">final</span>}
              </button>
            ))}
          </div>
          {conv?.ok && (
            <button type="button" onClick={copy} className="mb-1 inline-flex shrink-0 items-center gap-1.5 rounded-md px-2 py-1 text-xs text-muted hover:bg-surface-2 hover:text-text">
              {copied ? <Check size={14} aria-hidden /> : <Copy size={14} aria-hidden />} {copied ? "Copiado" : "Copiar"}
            </button>
          )}
        </div>
        <div className="p-4">
          {names.length === 0 && <p className="text-sm text-muted">Corrija o YAML para ver as consultas.</p>}
          {conv?.ok && <pre className="overflow-auto whitespace-pre-wrap break-words rounded-[10px] border border-line bg-code p-4 font-mono text-[12.5px] leading-relaxed text-code-text">{conv.query}</pre>}
          {conv && !conv.ok && <ErrorBox message={conv.error ?? "falha na conversão"} />}
        </div>
      </Card>

      <Card className="p-4">
        <h2 className="mb-2 text-sm font-semibold text-strong">Testes locais</h2>
        {result.tests === null ? (
          <p className="text-sm text-muted">Sem casos de teste. Adicione na aba “Casos de teste”.</p>
        ) : result.tests.results.length === 0 ? (
          <p className="text-sm text-muted">Nenhum caso válido encontrado.</p>
        ) : (
          <ul className="space-y-1.5 text-sm">
            {result.tests.results.map((r, n) => (
              <li key={n} className="flex items-start gap-2">
                {r.passed ? <CheckCircle2 size={16} className="mt-0.5 shrink-0 text-good" aria-hidden /> : <XCircle size={16} className="mt-0.5 shrink-0 text-bad" aria-hidden />}
                <span>
                  {r.name} <KindTag kind={r.kind} />
                  {!r.passed && (
                    <span className="block text-xs text-bad">{r.error ?? `esperado ${r.expect}, obtido ${r.got}`}</span>
                  )}
                </span>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </>
  );
}
