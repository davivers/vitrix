import { useMutation, useQuery } from "@tanstack/react-query";
import CodeMirror from "@uiw/react-codemirror";
import { AlertTriangle, CheckCircle2, ExternalLink, GitPullRequest, Loader2, RotateCcw, XCircle } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { api } from "../api";
import { yamlExtensions } from "../components/code";
import { Section, safeHref } from "../components/dash";
import { Card, ErrorBox, PageHeader, TargetSwatch } from "../components/ui";
import type { ConfigCheck, ConfigView } from "../types";

function Effective({ cfg }: { cfg: Omit<ConfigView, "path" | "text"> }) {
  const row = "grid grid-cols-[9rem_1fr] gap-3 py-2 text-[13px]";
  return (
    <dl className="divide-y divide-line">
      <div className={row}>
        <dt className="text-subtle">SIEMs ativos</dt>
        <dd className="flex flex-wrap gap-1.5">
          {cfg.targets.map((t) => (
            <span key={t} className="inline-flex items-center gap-1.5 rounded-md bg-surface-2 px-2 py-0.5 font-mono text-xs text-text">
              <TargetSwatch target={t} /> {t}
            </span>
          ))}
        </dd>
      </div>
      <div className={row}>
        <dt className="text-subtle">Linguagem padrão</dt>
        <dd className="font-mono text-text">{cfg.default_target ?? "— (todos os ativos)"}</dd>
      </div>
      <div className={row}>
        <dt className="text-subtle">Rotas</dt>
        <dd className="text-text">
          {cfg.routes.length === 0 ? (
            <span className="text-muted">nenhuma</span>
          ) : (
            <ul className="space-y-0.5 font-mono text-xs">
              {cfg.routes.map((r) => (
                <li key={r.match}>
                  {r.match} → {r.target.join(", ")}
                </li>
              ))}
            </ul>
          )}
        </dd>
      </div>
      <div className={row}>
        <dt className="text-subtle">Pastas</dt>
        <dd className="font-mono text-xs text-text">
          regras {cfg.rules_dir}/ · casos {cfg.cases_dir}/ · saída {cfg.output_dir}/
        </dd>
      </div>
      <div className={row}>
        <dt className="text-subtle">Exige casos</dt>
        <dd className="text-text">{cfg.require_cases ? "sim: ao menos um match e um no_match por regra" : "não"}</dd>
      </div>
      <div className={row}>
        <dt className="text-subtle">Pipelines extras</dt>
        <dd className="font-mono text-xs text-text">{cfg.extra_pipelines.length ? cfg.extra_pipelines.join(", ") : <span className="font-sans text-muted">nenhum</span>}</dd>
      </div>
      <div className={row}>
        <dt className="text-subtle">GitHub</dt>
        <dd className="font-mono text-xs text-text">
          {cfg.github ? `${cfg.github.repo} @ ${cfg.github.base}${cfg.github.path ? ` (${cfg.github.path}/)` : ""}` : <span className="font-sans text-muted">não configurado</span>}
        </dd>
      </div>
    </dl>
  );
}

function CheckResult({ check, pending, dirty }: { check: ConfigCheck | null; pending: boolean; dirty: boolean }) {
  if (!check) return null;
  return (
    <div className="space-y-2" aria-live="polite">
      <p className="flex items-center gap-2 text-sm font-medium">
        {pending ? (
          <Loader2 size={15} className="animate-spin text-muted" aria-hidden />
        ) : check.ok ? (
          <CheckCircle2 size={15} className="text-good" aria-hidden />
        ) : (
          <XCircle size={15} className="text-bad" aria-hidden />
        )}
        <span className="text-strong">{pending ? "Validando…" : check.ok ? (dirty ? "Configuração válida" : "Configuração atual válida") : "Configuração inválida"}</span>
      </p>
      {check.errors.map((e) => (
        <p key={e} className="flex gap-2 text-[13px]">
          <span className="shrink-0 font-medium text-bad">Erro</span>
          <span className="text-text [overflow-wrap:anywhere]">{e}</span>
        </p>
      ))}
      {check.warnings.map((w) => (
        <p key={w} className="flex gap-2 text-[13px]">
          <AlertTriangle size={14} className="mt-0.5 shrink-0 text-warn" aria-hidden />
          <span className="text-text">{w}</span>
        </p>
      ))}
    </div>
  );
}

export default function SettingsPage() {
  const config = useQuery({ queryKey: ["config"], queryFn: api.config });
  const github = useQuery({ queryKey: ["github"], queryFn: api.github });
  const health = useQuery({ queryKey: ["health"], queryFn: () => fetch("/api/health").then((r) => r.json() as Promise<{ version: string }>) });
  const [text, setText] = useState<string | null>(null);
  const [title, setTitle] = useState("");
  const [check, setCheck] = useState<ConfigCheck | null>(null);
  const [pending, setPending] = useState(false);
  const pr = useMutation({ mutationFn: api.configPullRequest });
  const extensions = useMemo(yamlExtensions, []);

  const original = config.data?.text ?? "";
  const current = text ?? original;
  const dirty = text !== null && text !== original;

  useEffect(() => {
    if (!config.data) return;
    const ctrl = new AbortController();
    setPending(true);
    const timer = setTimeout(() => {
      api
        .validateConfig(current, ctrl.signal)
        .then((c) => {
          setCheck(c);
          setPending(false);
        })
        .catch((e: Error) => {
          if (e.name !== "AbortError") setPending(false);
        });
    }, 400);
    return () => {
      clearTimeout(timer);
      ctrl.abort();
    };
  }, [current, config.data]);

  const canPr = dirty && !pending && check?.ok && github.data?.configured && github.data.token && !pr.isPending;

  return (
    <div className="mx-auto max-w-7xl px-4 py-8 sm:px-8">
      <PageHeader
        title="Configurações"
        subtitle="O vitrix.yml do repositório. Nada é gravado em disco: a alteração vai por pull request e passa pelo CI como qualquer regra."
      />
      {config.error && <ErrorBox message={(config.error as Error).message} />}

      {config.data && (
        <div className="grid gap-5 xl:grid-cols-[1fr_1.15fr]">
          <div className="flex flex-col gap-5">
            <Section title="Configuração efetiva" aside={dirty ? "com as suas alterações" : (config.data.path ?? "padrões (sem vitrix.yml)")}>
              <Effective cfg={check?.config ?? config.data} />
            </Section>
            <Section title="Sobre">
              <dl className="grid grid-cols-[9rem_1fr] gap-y-1.5 text-[13px]">
                <dt className="text-subtle">Versão</dt>
                <dd className="font-mono text-text">{health.data?.version ?? "—"}</dd>
                <dt className="text-subtle">Servidor</dt>
                <dd className="text-text">local, sem autenticação (só localhost)</dd>
                <dt className="text-subtle">Escrita</dt>
                <dd className="text-text">somente por pull request no GitHub</dd>
              </dl>
            </Section>
          </div>

          <Card className="flex h-[680px] flex-col overflow-hidden">
            <div className="flex items-center justify-between gap-3 border-b border-line px-4 py-3">
              <h2 className="font-mono text-[13px] font-semibold text-strong">{config.data.path ?? "vitrix.yml"}</h2>
              {dirty && (
                <button type="button" onClick={() => setText(null)} className="inline-flex items-center gap-1.5 rounded-md px-2 py-1 text-xs text-muted hover:bg-surface-2 hover:text-text">
                  <RotateCcw size={13} aria-hidden /> Descartar alterações
                </button>
              )}
            </div>
            <div className="min-h-0 flex-1 overflow-auto">
              <CodeMirror value={current} onChange={setText} extensions={extensions} theme="none" height="100%" basicSetup={{ foldGutter: false }} />
            </div>
            <div className="space-y-3 border-t border-line p-4">
              <CheckResult check={check} pending={pending} dirty={dirty} />
              {github.data && (!github.data.configured || !github.data.token) && (
                <p className="text-xs text-subtle">Para abrir o PR, configure o GitHub em Conexões.</p>
              )}
              {pr.error && <ErrorBox message={(pr.error as Error).message} />}
              {pr.data ? (
                <a href={safeHref(pr.data.url)} target="_blank" rel="noreferrer" className="inline-flex items-center gap-2 text-sm font-medium text-good hover:underline">
                  <CheckCircle2 size={15} aria-hidden /> Pull request #{pr.data.number} aberto <ExternalLink size={13} aria-hidden />
                </a>
              ) : (
                <form
                  className="flex flex-wrap gap-2"
                  onSubmit={(e) => {
                    e.preventDefault();
                    if (canPr) pr.mutate({ text: current, title: title.trim() || null });
                  }}
                >
                  <label className="min-w-[14rem] flex-1">
                    <span className="sr-only">Título do PR</span>
                    <input
                      value={title}
                      onChange={(e) => setTitle(e.target.value)}
                      maxLength={200}
                      placeholder="chore: atualiza vitrix.yml"
                      className="w-full rounded-[10px] border border-line bg-surface px-3 py-2 text-sm text-text placeholder:text-subtle focus:border-accent/50"
                    />
                  </label>
                  <button
                    type="submit"
                    disabled={!canPr}
                    className="inline-flex items-center gap-2 rounded-[10px] bg-brand px-4 py-2 text-[13.5px] font-semibold text-strong hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    {pr.isPending ? <Loader2 size={16} className="animate-spin" aria-hidden /> : <GitPullRequest size={16} aria-hidden />}
                    {pr.isPending ? "Abrindo…" : "Abrir pull request"}
                  </button>
                </form>
              )}
            </div>
          </Card>
        </div>
      )}
    </div>
  );
}
