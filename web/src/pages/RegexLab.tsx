import clsx from "clsx";
import { AlertTriangle, Check, CheckCircle2, Copy, Info, Loader2, Plus, Timer, Trash2, XCircle } from "lucide-react";
import { useEffect, useState } from "react";
import { request } from "../api";
import { Card, ErrorBox, PageHeader } from "../components/ui";

interface Match {
  start: number;
  end: number;
  text: string;
  groups: (string | null)[];
  named: Record<string, string | null>;
}

interface RegexResult {
  ok: boolean;
  timeout: boolean;
  error?: string;
  position?: number;
  groups?: number;
  names?: string[];
  results?: { matched: boolean; matches: Match[]; duration_ms: number }[];
  tips: { severity: "error" | "warning" | "info"; message: string }[];
  sigma: string | null;
  elapsed_ms?: number;
}

const START_SAMPLES = [
  "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA",
  "POWERSHELL.EXE -EncodedCommand JABjAD0ATgBlAHcA",
  "powershell.exe -File C:\\scripts\\backup.ps1",
];

const FLAG_INFO: [string, string][] = [
  ["i", "ignorar maiúsculas"],
  ["m", "^ e $ por linha"],
  ["s", ". casa quebra de linha"],
];

/** Destaca os trechos que casaram, sem innerHTML. */
function Highlighted({ text, matches }: { text: string; matches: Match[] }) {
  const parts: { t: string; hit: boolean }[] = [];
  let pos = 0;
  for (const m of matches) {
    if (m.start > pos) parts.push({ t: text.slice(pos, m.start), hit: false });
    if (m.end > m.start) parts.push({ t: text.slice(m.start, m.end), hit: true });
    pos = Math.max(pos, m.end);
  }
  if (pos < text.length) parts.push({ t: text.slice(pos), hit: false });
  return (
    <span className="whitespace-pre-wrap break-all font-mono text-[12.5px] text-code-text">
      {parts.map((p, i) =>
        p.hit ? (
          <mark key={i} className="rounded-[3px] bg-accent/35 px-0.5 text-strong underline decoration-accent decoration-2 underline-offset-2">
            {p.t}
          </mark>
        ) : (
          <span key={i}>{p.t}</span>
        ),
      )}
    </span>
  );
}

export default function RegexLabPage() {
  const [pattern, setPattern] = useState(String.raw`\s-(e|en|enc|enco|encodedcommand)\s+[A-Za-z0-9+/=]{8,}`);
  const [flags, setFlags] = useState("i");
  const [samples, setSamples] = useState<string[]>(START_SAMPLES);
  const [result, setResult] = useState<RegexResult | null>(null);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    const ctrl = new AbortController();
    setPending(true);
    const timer = setTimeout(() => {
      request<RegexResult>("/api/regex", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ pattern, flags, samples }),
        signal: ctrl.signal,
      })
        .then((r) => {
          setResult(r);
          setError(null);
          setPending(false);
        })
        .catch((e: Error) => {
          if (e.name === "AbortError") return;
          setError(e.message);
          setPending(false);
        });
    }, 350);
    return () => {
      clearTimeout(timer);
      ctrl.abort();
    };
  }, [pattern, flags, samples]);

  const toggle = (f: string) => setFlags((cur) => (cur.includes(f) ? cur.replace(f, "") : [...cur, f].sort().join("")));
  const hits = result?.results?.filter((r) => r.matched).length ?? 0;
  const slowest = Math.max(0, ...(result?.results ?? []).map((r) => r.duration_ms));

  const copy = async () => {
    if (!result?.sigma) return;
    try {
      await navigator.clipboard.writeText(result.sigma);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* sem permissão */
    }
  };

  return (
    <div className="mx-auto max-w-6xl px-4 py-8 sm:px-8">
      <PageHeader
        title="Regex Workbench"
        subtitle="Desenvolva, teste e otimize expressões regulares com o mesmo motor dos testes locais (re do Python). Cada execução tem tempo limite de 2 s."
      />

      <Card className="mb-5 p-5">
        <label className="block">
          <span className="mb-1.5 block text-sm font-medium text-strong">Expressão</span>
          <span className="flex items-stretch overflow-hidden rounded-[10px] border border-line bg-code focus-within:border-accent/50">
            <span className="grid place-items-center px-3 font-mono text-subtle">/</span>
            <input
              value={pattern}
              onChange={(e) => setPattern(e.target.value)}
              spellCheck={false}
              className="min-w-0 flex-1 bg-transparent py-2.5 font-mono text-[14px] text-code-text outline-none"
              aria-invalid={result?.ok === false && !result.timeout}
            />
            <span className="grid place-items-center px-3 font-mono text-subtle">/{flags}</span>
          </span>
        </label>
        <div className="mt-3 flex flex-wrap items-center gap-2">
          {FLAG_INFO.map(([f, label]) => (
            <label key={f} className={clsx("flex cursor-pointer items-center gap-1.5 rounded-md border px-2.5 py-1 text-[12.5px]", flags.includes(f) ? "border-accent/50 bg-accent-soft text-strong" : "border-line text-muted")}>
              <input type="checkbox" className="sr-only" checked={flags.includes(f)} onChange={() => toggle(f)} />
              <span className="font-mono">{f}</span> {label}
            </label>
          ))}
          <span className="ml-auto flex items-center gap-1.5 text-xs text-muted" aria-live="polite">
            {pending ? (
              <>
                <Loader2 size={13} className="animate-spin" aria-hidden /> testando…
              </>
            ) : result?.timeout ? (
              <>
                <Timer size={13} className="text-bad" aria-hidden /> estourou o tempo
              </>
            ) : result?.ok ? (
              <>
                <CheckCircle2 size={13} className="text-good" aria-hidden /> {hits}/{samples.length} amostras casaram · mais lenta {slowest} ms
              </>
            ) : result ? (
              <>
                <XCircle size={13} className="text-bad" aria-hidden /> regex inválida
              </>
            ) : null}
          </span>
        </div>
        {result && !result.ok && <div className="mt-3"><ErrorBox message={result.error + (result.position !== undefined ? ` (posição ${result.position})` : "")} /></div>}
        {error && <div className="mt-3"><ErrorBox message={error} /></div>}
      </Card>

      <div className="grid gap-5 lg:grid-cols-[1fr_20rem]">
        <Card className="p-5">
          <div className="mb-3 flex items-center justify-between">
            <h2 className="text-[15px] font-semibold text-strong">Amostras</h2>
            <button type="button" onClick={() => setSamples([...samples, ""])} className="inline-flex items-center gap-1.5 rounded-md px-2 py-1 text-xs text-muted hover:bg-surface-2 hover:text-text">
              <Plus size={13} aria-hidden /> amostra
            </button>
          </div>
          <ul className="space-y-3">
            {samples.map((s, i) => {
              const r = result?.ok ? result.results?.[i] : undefined;
              return (
                <li key={i} className="rounded-[10px] border border-line bg-surface p-3">
                  <div className="mb-2 flex items-center gap-2">
                    {r ? (
                      <span className={clsx("inline-flex items-center gap-1 text-xs font-semibold", r.matched ? "text-good" : "text-muted")}>
                        {r.matched ? <CheckCircle2 size={13} aria-hidden /> : <XCircle size={13} aria-hidden />}
                        {r.matched ? `casou (${r.matches.length})` : "não casou"}
                      </span>
                    ) : (
                      <span className="text-xs text-subtle">—</span>
                    )}
                    {r && <span className="text-[11px] text-subtle tabular-nums">{r.duration_ms} ms</span>}
                    <button type="button" aria-label={`Remover amostra ${i + 1}`} onClick={() => setSamples(samples.filter((_, j) => j !== i))} className="ml-auto rounded p-1 text-subtle hover:bg-surface-2 hover:text-text">
                      <Trash2 size={13} aria-hidden />
                    </button>
                  </div>
                  <label>
                    <span className="sr-only">Amostra {i + 1}</span>
                    <textarea
                      value={s}
                      onChange={(e) => setSamples(samples.map((x, j) => (j === i ? e.target.value : x)))}
                      rows={1}
                      spellCheck={false}
                      className="w-full resize-y rounded-md border border-line bg-code px-2 py-1.5 font-mono text-[12.5px] text-code-text focus:border-accent/50"
                    />
                  </label>
                  {r?.matched && (
                    <div className="mt-2 space-y-1.5">
                      <Highlighted text={s} matches={r.matches} />
                      {r.matches.some((m) => m.groups.length > 0) && (
                        <ul className="space-y-0.5 text-[11.5px] text-muted">
                          {r.matches.slice(0, 3).map((m, k) => (
                            <li key={k} className="font-mono">
                              {m.groups.map((g, gi) => {
                                const name = Object.entries(m.named).find(([, v]) => v === g)?.[0];
                                return (
                                  <span key={gi} className="mr-3">
                                    <span className="text-subtle">{name ?? `$${gi + 1}`}=</span>
                                    {g ?? "∅"}
                                  </span>
                                );
                              })}
                            </li>
                          ))}
                        </ul>
                      )}
                    </div>
                  )}
                </li>
              );
            })}
          </ul>
        </Card>

        <div className="flex flex-col gap-5">
          <Card className="p-5">
            <h2 className="mb-3 text-[15px] font-semibold text-strong">Otimização</h2>
            {result && result.tips.length === 0 && (
              <p className="flex items-center gap-2 text-[13px] text-muted">
                <CheckCircle2 size={14} className="text-good" aria-hidden /> Nenhum problema conhecido.
              </p>
            )}
            <ul className="space-y-2">
              {result?.tips.map((t, i) => (
                <li key={i} className="flex gap-2 text-[13px]">
                  {t.severity === "error" ? (
                    <XCircle size={14} className="mt-0.5 shrink-0 text-bad" aria-label="grave" />
                  ) : t.severity === "warning" ? (
                    <AlertTriangle size={14} className="mt-0.5 shrink-0 text-warn" aria-label="aviso" />
                  ) : (
                    <Info size={14} className="mt-0.5 shrink-0 text-subtle" aria-label="dica" />
                  )}
                  <span className="text-text">{t.message}</span>
                </li>
              ))}
            </ul>
          </Card>
          <Card className="p-5">
            <div className="mb-2 flex items-center justify-between">
              <h2 className="text-[15px] font-semibold text-strong">Na regra Sigma</h2>
              {result?.sigma && (
                <button type="button" onClick={copy} className="inline-flex items-center gap-1 rounded-md px-2 py-1 text-xs text-muted hover:bg-surface-2 hover:text-text">
                  {copied ? <Check size={13} aria-hidden /> : <Copy size={13} aria-hidden />} {copied ? "Copiado" : "Copiar"}
                </button>
              )}
            </div>
            <pre className="overflow-auto whitespace-pre-wrap break-all rounded-[10px] border border-line bg-code p-3 font-mono text-[12px] text-code-text">
              {result?.sigma ?? "—"}
            </pre>
            <p className="mt-2 text-xs text-subtle">Troque Field pelo campo (ex.: CommandLine). Aspas simples no YAML: a barra invertida vale literal.</p>
          </Card>
        </div>
      </div>
    </div>
  );
}
