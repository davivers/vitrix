import { useMutation, useQuery } from "@tanstack/react-query";
import clsx from "clsx";
import { AlertTriangle, CheckCircle2, ExternalLink, GitPullRequest, Loader2, X } from "lucide-react";
import { useEffect, useRef, useState, type FormEvent } from "react";
import { api } from "../api";
import type { GitHubStatus, State } from "../types";
import { safeHref } from "./dash";
import { ErrorBox } from "./ui";

/** Caminho sugerido para uma regra nova, a partir do `title:` do YAML. */
export function suggestPath(rule: string): string {
  const title = /^title:[ \t]*(.+)$/m.exec(rule)?.[1] ?? "";
  const slug = title
    .normalize("NFD")
    .replace(/[̀-ͯ]/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .slice(0, 60);
  return `${slug || "nova_regra"}.yml`;
}

const inputCls = "w-full rounded-[10px] border border-line bg-surface px-3 py-2 text-sm text-text placeholder:text-subtle focus:border-accent/50";
const primaryCls =
  "inline-flex items-center gap-2 rounded-[10px] bg-brand px-4 py-2 text-[13.5px] font-semibold text-strong hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-50 disabled:hover:brightness-100";

const SETUP_YAML = `# vitrix.yml
github:
  repo: minha-org/deteccoes
  base: main`;

function GitHubSetup({ status }: { status: GitHubStatus }) {
  return (
    <div className="space-y-2 rounded-[10px] border border-warn/30 bg-warn-soft p-3 text-sm text-text">
      <p className="flex items-center gap-2 font-medium text-warn">
        <AlertTriangle size={16} aria-hidden /> {status.configured ? "Falta o token do GitHub" : "GitHub não configurado"}
      </p>
      {!status.configured && <pre className="rounded-md bg-code p-2 font-mono text-xs text-code-text">{SETUP_YAML}</pre>}
      {!status.token && (
        <p>
          Defina <code className="font-mono text-xs">VITRIX_GITHUB_TOKEN</code> no ambiente do <code className="font-mono text-xs">vitrix serve</code>, com escrita em
          Contents e Pull requests, e reinicie o servidor.
        </p>
      )}
    </div>
  );
}

interface Props {
  onClose: () => void;
  ruleId: string | null; // null = regra nova
  rule: string;
  cases: string;
  state: State | null; // null = validação em andamento
}

/** Abre um PR com a regra e os casos editados. Nada é gravado no disco local. */
export function PullRequestDialog({ onClose, ruleId, rule, cases, state }: Props) {
  const ref = useRef<HTMLDialogElement>(null);
  const github = useQuery({ queryKey: ["github"], queryFn: api.github });
  const [path, setPath] = useState(() => ruleId ?? suggestPath(rule));
  const [title, setTitle] = useState("");
  const pr = useMutation({ mutationFn: api.pullRequest });

  useEffect(() => {
    const dlg = ref.current;
    if (dlg && !dlg.open) dlg.showModal();
  }, []);

  const ready = Boolean(github.data?.configured && github.data.token);
  const blocked = state === "fail";
  const canSubmit = ready && !blocked && state !== null && path.trim() !== "" && !pr.isPending;

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (canSubmit) pr.mutate({ path: path.trim(), rule, cases: cases.trim() ? cases : null, title: title.trim() || null });
  };

  return (
    <dialog
      ref={ref}
      onClose={onClose}
      aria-labelledby="pr-title"
      className="glass m-auto w-[min(560px,calc(100vw-32px))] rounded-2xl bg-ink/95 p-0 text-text backdrop:bg-black/60 backdrop:backdrop-blur-sm"
    >
      <form onSubmit={submit} className="space-y-4 p-6">
        <div className="flex items-start justify-between gap-4">
          <div>
            <h2 id="pr-title" className="text-lg font-semibold text-strong">
              Abrir pull request
            </h2>
            <p className="mt-1 text-sm text-muted">
              {github.data?.repo ? (
                <>
                  Um commit com a regra e os casos em um branch novo de <span className="font-mono text-text">{github.data.repo}</span>, contra{" "}
                  <span className="font-mono text-text">{github.data.base}</span>.
                </>
              ) : (
                "Um commit com a regra e os casos em um branch novo, contra o branch base."
              )}
            </p>
          </div>
          <button type="button" onClick={onClose} aria-label="Fechar" className="rounded-md p-1 text-muted hover:bg-surface-2 hover:text-text">
            <X size={18} aria-hidden />
          </button>
        </div>

        {github.isLoading && (
          <p className="flex items-center gap-2 text-sm text-muted">
            <Loader2 size={14} className="animate-spin" aria-hidden /> Conferindo a configuração do GitHub…
          </p>
        )}
        {github.error && <ErrorBox message={(github.error as Error).message} />}
        {github.data && !ready && <GitHubSetup status={github.data} />}

        {pr.data ? (
          <div className="space-y-3" aria-live="polite">
            <p className="flex items-center gap-2 text-sm font-medium text-good">
              <CheckCircle2 size={16} aria-hidden /> Pull request #{pr.data.number} aberto
            </p>
            <ul className="space-y-0.5 font-mono text-xs text-subtle">
              {pr.data.files.map((f) => (
                <li key={f}>{f}</li>
              ))}
            </ul>
            <a href={safeHref(pr.data.url)} target="_blank" rel="noreferrer" className={primaryCls}>
              <ExternalLink size={16} aria-hidden /> Ver no GitHub
            </a>
          </div>
        ) : (
          <>
            <label className="block space-y-1.5">
              <span className="text-sm font-medium text-strong">Arquivo dentro de rules/</span>
              <input
                value={path}
                onChange={(e) => setPath(e.target.value)}
                className={clsx(inputCls, "font-mono", ruleId !== null && "text-muted")}
                placeholder="windows/minha_regra.yml"
                readOnly={ruleId !== null}
                required
              />
              <span className="block text-xs text-subtle">
                {ruleId ? "Alteração de uma regra existente." : "Os casos de teste vão para o mesmo caminho dentro de cases/."}
              </span>
            </label>
            <label className="block space-y-1.5">
              <span className="text-sm font-medium text-strong">
                Título do PR <span className="font-normal text-subtle">(opcional)</span>
              </span>
              <input
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                className={inputCls}
                maxLength={200}
                placeholder={ruleId ? "tune: ajusta …" : "feat: nova regra …"}
              />
            </label>

            {blocked && <ErrorBox message="A regra está reprovada (erros de lint, conversão ou testes). Corrija antes de abrir o pull request." />}
            {pr.error && <ErrorBox message={(pr.error as Error).message} />}

            <div className="flex justify-end gap-2 pt-1">
              <button
                type="button"
                onClick={onClose}
                className="rounded-[10px] border border-line bg-surface-2 px-3 py-2 text-[13.5px] font-semibold text-text hover:bg-surface-3"
              >
                Cancelar
              </button>
              <button type="submit" disabled={!canSubmit} className={primaryCls}>
                {pr.isPending || state === null ? <Loader2 size={16} className="animate-spin" aria-hidden /> : <GitPullRequest size={16} aria-hidden />}
                {pr.isPending ? "Abrindo…" : state === null ? "Validando…" : "Abrir pull request"}
              </button>
            </div>
          </>
        )}
      </form>
    </dialog>
  );
}
