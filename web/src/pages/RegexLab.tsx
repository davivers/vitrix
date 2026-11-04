import clsx from "clsx";
import { AlertTriangle, Check, Cpu, CheckCircle2, Copy, Info, Loader2, Plus, Timer, Trash2, XCircle } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { request } from "../api";
import { JS_ENGINE_ID, runJs } from "../regexJs";
import { Card, ErrorBox, PageHeader } from "../components/ui";
import { t } from "../i18n";

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
  /** Same engine as Replay and the evaluator (telemetry contract). */
  engine?: { id?: string; name: string; version?: string | null; timeout_ms?: number };
}

interface EngineInfo {
  id: string;
  label: string;
  version?: string | null;
  available: boolean;
  hint?: string | null;
  /** Flags the engine supports (i, m, s). */
  flags?: string[];
}

const ENGINE_KEY = "vitrix.regex.engine";
const JS_ENGINE: EngineInfo = { id: JS_ENGINE_ID, label: "JavaScript (ECMAScript)", version: "browser", available: true, flags: ["i", "m", "s"] };
const FALLBACK_ENGINES: EngineInfo[] = [{ id: "python-regex", label: "Python regex (Vitrix evaluator)", available: true }];

/** GET /api/regex/engines -> [{id, name, version, available, notes, flags_supported}] (default python-regex). */
async function loadEngines(): Promise<{ list: EngineInfo[]; def: string }> {
  try {
    const raw = await request<Record<string, unknown>[]>("/api/regex/engines");
    const list = raw.map((e) => ({
      id: String(e.id),
      label: String(e.name ?? e.id),
      version: (e.version as string | null | undefined) ?? null,
      available: e.available !== false,
      hint: (e.notes as string | null | undefined) ?? null,
      flags: (e.flags_supported as string[] | undefined) ?? ["i", "m", "s"],
    }));
    return { list: list.length ? list : FALLBACK_ENGINES, def: "python-regex" };
  } catch {
    return { list: FALLBACK_ENGINES, def: "python-regex" };
  }
}

const START_SAMPLES = [
  "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA",
  "POWERSHELL.EXE -EncodedCommand JABjAD0ATgBlAHcA",
  "powershell.exe -File C:\\scripts\\backup.ps1",
];

const FLAG_INFO: [string, string][] = [
  ["i", t("rx_i")],
  ["m", t("rx_m")],
  ["s", t("rx_s")],
];

/** Highlights the matched spans, without innerHTML. */
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
          <mark key={i} className="rounded-[3px] bg-accent-soft px-0.5 text-strong underline decoration-accent decoration-2 underline-offset-2">
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
  const engines = useQuery({ queryKey: ["regex-engines"], queryFn: loadEngines, retry: false, staleTime: 300_000 });
  const all = useMemo(() => [...(engines.data?.list ?? FALLBACK_ENGINES), JS_ENGINE], [engines.data]);
  const [chosen, setChosen] = useState<string | null>(() => {
    try {
      return localStorage.getItem(ENGINE_KEY);
    } catch {
      return null;
    }
  });
  const engine = all.find((e) => e.id === chosen && e.available)?.id ?? engines.data?.def ?? "python-regex";
  const pick = (id: string) => {
    setChosen(id);
    try {
      localStorage.setItem(ENGINE_KEY, id);
    } catch {
      /* storage unavailable */
    }
  };

  useEffect(() => {
    const ctrl = new AbortController();
    setPending(true);
    const timer = setTimeout(() => {
      if (engine === JS_ENGINE_ID) {
        void runJs(pattern, flags, samples).then((res) => {
          if (ctrl.signal.aborted) return;
          setResult(res as RegexResult);
          setError(null);
          setPending(false);
        });
        return;
      }
      request<RegexResult>("/api/regex", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ pattern, flags, samples, engine }),
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
  }, [pattern, flags, samples, engine]);

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
      /* no clipboard permission */
    }
  };

  return (
    <div className="mx-auto max-w-6xl px-4 py-8 sm:px-8">
      <PageHeader
        title={t("regex_workbench")}
        subtitle={t("develop_test_and_optimise_regular_expr")}
      />

      <Card className="mb-5 p-5">
        <label className="block">
          <span className="mb-1.5 block text-sm font-medium text-strong">{t("expression")}</span>
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
        <div className="mt-2 flex flex-wrap items-center gap-3">
          <label className="flex items-center gap-2 text-[13px] text-muted">
            {t("rx_engine_label")}
            <select value={engine} onChange={(e) => pick(e.target.value)} className="rounded-[10px] border border-line bg-surface px-2.5 py-1.5 text-[13px] text-text">
              {all.map((e) => (
                <option key={e.id} value={e.id} disabled={!e.available} title={e.hint ?? undefined}>
                  {e.label}
                  {e.version ? ` ${e.version}` : ""}
                  {!e.available ? ` (${t("rx_unavailable")})` : ""}
                </option>
              ))}
            </select>
          </label>
          <p className="inline-flex items-center gap-1.5 rounded-md bg-surface-2 px-2 py-1 font-mono text-xs text-text" title={t("rx_engine_tip")} data-testid="regex-engine">
            <Cpu size={12} aria-hidden />{" "}
            {result?.engine
              ? t("rx_engine", { e: `${result.engine.name === "regex" ? "Python regex" : result.engine.name}${result.engine.version ? ` ${result.engine.version}` : ""}${result.engine.timeout_ms ? ` \u00b7 ${t("rx_timeout", { ms: result.engine.timeout_ms })}` : ""}` })
              : t("rx_engine", { e: all.find((e) => e.id === engine)?.label ?? engine })}
          </p>
          {all.find((e) => e.id === engine)?.hint && <p className="basis-full text-xs text-muted">{all.find((e) => e.id === engine)?.hint}</p>}
        </div>
        <div className="mt-3 flex flex-wrap items-center gap-2">
          {FLAG_INFO.map(([f, label]) => (
            <label key={f} className={clsx("flex cursor-pointer items-center gap-1.5 rounded-md border px-2.5 py-1 text-[12.5px]", flags.includes(f) ? "border-accent/50 bg-accent-soft text-strong" : "border-line text-muted")}>
              <input type="checkbox" className="sr-only" checked={flags.includes(f)} disabled={!(all.find((e) => e.id === engine)?.flags ?? ["i", "m", "s"]).includes(f)} onChange={() => toggle(f)} />
              <span className="font-mono">{f}</span> {label}
            </label>
          ))}
          <span className="ml-auto flex items-center gap-1.5 text-xs text-muted" aria-live="polite">
            {pending ? (
              <>
                <Loader2 size={13} className="animate-spin" aria-hidden /> {t("testing")}
              </>
            ) : result?.timeout ? (
              <>
                <Timer size={13} className="text-bad" aria-hidden /> {t("timed_out")}
              </>
            ) : result?.ok ? (
              <>
                <CheckCircle2 size={13} className="text-good" aria-hidden /> {t("rx_summary", { a: hits, b: samples.length, ms: slowest })}
              </>
            ) : result ? (
              <>
                <XCircle size={13} className="text-bad" aria-hidden /> {t("invalid_regex")}
              </>
            ) : null}
          </span>
        </div>
        {result && !result.ok && <div className="mt-3"><ErrorBox message={result.error + (typeof result.position === "number" ? ` (position ${result.position})` : "")} /></div>}
        {error && <div className="mt-3"><ErrorBox message={error} /></div>}
      </Card>

      <div className="grid gap-5 lg:grid-cols-[1fr_20rem]">
        <Card className="p-5">
          <div className="mb-3 flex items-center justify-between">
            <h2 className="text-[15px] font-semibold text-strong">{t("samples")}</h2>
            <button type="button" onClick={() => setSamples([...samples, ""])} className="inline-flex items-center gap-1.5 rounded-md px-2 py-1 text-xs text-muted hover:bg-surface-2 hover:text-text">
              <Plus size={13} aria-hidden /> {t("sample")}
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
                        {r.matched ? t("rx_matched", { n: r.matches.length }) : t("rx_nomatch")}
                      </span>
                    ) : (
                      <span className="text-xs text-subtle">—</span>
                    )}
                    {r && <span className="text-[11px] text-subtle tabular-nums">{r.duration_ms} ms</span>}
                    <button type="button" aria-label={t("rx_remove", { n: i + 1 })} onClick={() => setSamples(samples.filter((_, j) => j !== i))} className="ml-auto rounded p-1 text-subtle hover:bg-surface-2 hover:text-text">
                      <Trash2 size={13} aria-hidden />
                    </button>
                  </div>
                  <label>
                    <span className="sr-only">{t("rx_sample_n", { n: i + 1 })}</span>
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
            <h2 className="mb-3 text-[15px] font-semibold text-strong">{t("optimisation")}</h2>
            {result && result.tips.length === 0 && (
              <p className="flex items-center gap-2 text-[13px] text-muted">
                <CheckCircle2 size={14} className="text-good" aria-hidden /> {t("no_known_problem")}
              </p>
            )}
            <ul className="space-y-2">
              {result?.tips.map((tip, i) => (
                <li key={i} className="flex gap-2 text-[13px]">
                  {tip.severity === "error" ? (
                    <XCircle size={14} className="mt-0.5 shrink-0 text-bad" aria-label={t("rx_sev_error")} />
                  ) : tip.severity === "warning" ? (
                    <AlertTriangle size={14} className="mt-0.5 shrink-0 text-warn" aria-label={t("rx_sev_warn")} />
                  ) : (
                    <Info size={14} className="mt-0.5 shrink-0 text-subtle" aria-label={t("rx_sev_tip")} />
                  )}
                  <span className="text-text">{tip.message}</span>
                </li>
              ))}
            </ul>
          </Card>
          <Card className="p-5">
            <div className="mb-2 flex items-center justify-between">
              <h2 className="text-[15px] font-semibold text-strong">{t("in_the_sigma_rule")}</h2>
              {result?.sigma && (
                <button type="button" onClick={copy} className="inline-flex items-center gap-1 rounded-md px-2 py-1 text-xs text-muted hover:bg-surface-2 hover:text-text">
                  {copied ? <Check size={13} aria-hidden /> : <Copy size={13} aria-hidden />} {copied ? t("l_copied") : t("l_copy")}
                </button>
              )}
            </div>
            <pre className="overflow-auto whitespace-pre-wrap break-all rounded-[10px] border border-line bg-code p-3 font-mono text-[12px] text-code-text">
              {result?.sigma ?? "—"}
            </pre>
            <p className="mt-2 text-xs text-subtle">{t("replace_field_with_the_field_name_e_g_")}</p>
          </Card>
        </div>
      </div>
    </div>
  );
}
