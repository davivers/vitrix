import { useQuery } from "@tanstack/react-query";
import clsx from "clsx";
import { AlertTriangle, CheckCircle2, CircleDashed, ExternalLink, GitBranch, RefreshCw, XCircle } from "lucide-react";
import { api } from "../api";
import { Section, safeHref, timeAgo } from "../components/dash";
import { ErrorBox, PageHeader, TargetSwatch } from "../components/ui";
import type { Activity, GitHubStatus } from "../types";

const TARGET_CODE: Record<string, string> = { splunk: "SPL", kql: "KQL", "elastic-eql": "EQL", "elastic-lucene": "LUCENE" };

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
  if (!status) return ["off", "Verificando"];
  if (!status.configured) return ["off", "Não configurado"];
  if (!status.token) return ["warn", "Sem token"];
  if (!activity) return ["off", "Verificando"];
  return activity.available ? ["ok", "Conectado"] : ["fail", "Erro de conexão"];
}

const SETUP = `# vitrix.yml
github:
  repo: minha-org/deteccoes
  base: main
  path: ""   # pasta do projeto no repositório

# no terminal, antes do vitrix serve
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
            Abre pull requests com as regras editadas e lê PRs abertos, execuções do CI e tempo até o merge para os dashboards. Leitura e escrita usam o mesmo token, que
            fica só no servidor.
          </p>
          {status.error && <ErrorBox message={(status.error as Error).message} />}
          {status.data?.configured && (
            <dl className="grid grid-cols-[8rem_1fr] gap-y-1.5">
              <dt className="text-subtle">Repositório</dt>
              <dd className="font-mono text-text">
                {act?.available ? (
                  <a href={safeHref(act.repo.url)} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 hover:text-accent">
                    {status.data.repo} <ExternalLink size={12} aria-hidden />
                  </a>
                ) : (
                  status.data.repo
                )}
              </dd>
              <dt className="text-subtle">Branch base</dt>
              <dd className="font-mono text-text">{status.data.base}</dd>
              <dt className="text-subtle">Token</dt>
              <dd className="flex items-center gap-1.5 text-text">
                {status.data.token ? <CheckCircle2 size={14} className="text-good" aria-hidden /> : <XCircle size={14} className="text-bad" aria-hidden />}
                {status.data.token ? "definido no ambiente" : "VITRIX_GITHUB_TOKEN ausente"}
              </dd>
              {act?.available && (
                <>
                  <dt className="text-subtle">HEAD</dt>
                  <dd className="truncate text-text">
                    <span className="font-mono">{act.head.sha.slice(0, 7)}</span> · {act.head.message}
                  </dd>
                  <dt className="text-subtle">Última leitura</dt>
                  <dd className="text-text">{timeAgo(act.fetched_at)}</dd>
                </>
              )}
            </dl>
          )}
          {act && !act.available && act.reason === "error" && <ErrorBox message={act.message} />}
          {(!status.data?.configured || !status.data.token) && status.data && (
            <pre className="overflow-auto rounded-[10px] border border-line bg-code p-3 font-mono text-xs leading-relaxed text-code-text">{SETUP}</pre>
          )}
          {status.data?.configured && status.data.token && (
            <button
              type="button"
              onClick={() => test.refetch()}
              className="inline-flex items-center gap-2 rounded-[10px] border border-line bg-surface-2 px-3 py-2 text-[13px] font-semibold text-text hover:bg-surface-3"
            >
              <RefreshCw size={14} className={test.isFetching ? "animate-spin" : undefined} aria-hidden /> Testar conexão
            </button>
          )}
          <p className="text-xs text-subtle">Token fine-grained, restrito ao repositório: Contents e Pull requests (leitura e escrita), Actions (leitura).</p>
        </div>
      </div>
    </Section>
  );
}

function SiemTargets() {
  const targets = useQuery({ queryKey: ["targets"], queryFn: api.targets });
  return (
    <Section title="SIEMs" aside="conversão local com pySigma">
      {targets.error && <ErrorBox message={(targets.error as Error).message} />}
      <ul className="grid gap-3 sm:grid-cols-2">
        {(targets.data ?? []).map((t) => (
          <li key={t.name} className="rounded-[12px] border border-line bg-surface p-4">
            <div className="mb-2 flex items-center justify-between gap-2">
              <span className="flex items-center gap-2 font-semibold text-strong">
                <TargetSwatch target={t.name} />
                {t.label}
              </span>
              <Pill tone={t.active ? "ok" : "off"}>{t.active ? "Ativo" : "Disponível"}</Pill>
            </div>
            <dl className="grid grid-cols-[6rem_1fr] gap-y-1 text-[12.5px]">
              <dt className="text-subtle">Alvo</dt>
              <dd className="font-mono text-text">
                {t.name} · {TARGET_CODE[t.name] ?? t.extension.toUpperCase()}
              </dd>
              <dt className="text-subtle">Conversão</dt>
              <dd className="flex items-center gap-1.5 text-text">
                <CheckCircle2 size={13} className="text-good" aria-hidden /> local, sem acesso ao SIEM
              </dd>
              <dt className="text-subtle">Deploy</dt>
              <dd className="flex items-center gap-1.5 text-muted">
                <CircleDashed size={13} aria-hidden /> ainda não disponível
              </dd>
            </dl>
          </li>
        ))}
      </ul>
      <p className="mt-4 text-xs text-subtle">
        Ative ou desative em <span className="font-mono">targets</span> do vitrix.yml (tela Configurações). Outros SIEMs entram por plugin, pelo entry point{" "}
        <span className="font-mono">vitrix.targets</span>. O resultado da conversão é o <span className="font-mono">dist/</span> gerado no CI.
      </p>
    </Section>
  );
}

export default function ConnectionsPage() {
  return (
    <div className="mx-auto max-w-6xl px-4 py-8 sm:px-8">
      <PageHeader title="Conexões" subtitle="Integrações com o repositório Git e os SIEMs de destino." />
      <div className="grid gap-5">
        <GitHubCard />
        <SiemTargets />
      </div>
    </div>
  );
}
