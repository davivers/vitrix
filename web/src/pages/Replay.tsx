import { useMutation, useQuery } from "@tanstack/react-query";
import clsx from "clsx";
import { CheckCircle2, Database, Play, Upload, XCircle } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { Section } from "../components/dash";
import { Card, ErrorBox, LevelTag, PageHeader } from "../components/ui";
import type { ReplayResult } from "../types";

const EXAMPLE = `{"Image": "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe", "CommandLine": "powershell.exe -enc SQBFAFgA"}
{"Image": "C:\\\\Windows\\\\System32\\\\schtasks.exe", "CommandLine": "schtasks /create /tn x /tr c:\\\\x.exe /ru SYSTEM"}
{"Image": "C:\\\\Windows\\\\explorer.exe", "CommandLine": "explorer.exe"}`;

function Result({ res }: { res: ReplayResult }) {
  const matched = res.rules.filter((r) => r.matches > 0);
  const skipped = res.rules.filter((r) => r.error);
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap gap-x-6 gap-y-1 text-[13px] text-muted">
        <span>
          <b className="text-strong tabular-nums">{res.events}</b> events
        </span>
        <span>
          <b className="text-strong tabular-nums">{res.rules_matched}</b> of {res.rules.length} rules fired
        </span>
        <span>
          <b className="text-strong tabular-nums">{res.duration_ms}</b> ms no total
        </span>
      </div>

      {res.checks && res.checks.length > 0 && (
        <div>
          <h3 className="mb-1.5 text-[11px] font-semibold uppercase tracking-wider text-subtle">Expectations (regression)</h3>
          <ul className="space-y-1 text-[13px]">
            {res.checks.map((c) => (
              <li key={c.rule} className="flex items-start gap-2">
                {c.passed ? <CheckCircle2 size={15} className="mt-0.5 shrink-0 text-good" aria-hidden /> : <XCircle size={15} className="mt-0.5 shrink-0 text-bad" aria-hidden />}
                <span>
                  <span className="font-mono text-xs text-text">{c.rule}</span>
                  <span className="ml-2 text-muted">{c.passed ? `${c.got} evento(s), como esperado` : c.message}</span>
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}

      <table className="w-full text-left text-[13px]">
        <caption className="sr-only">Rules and the events that matched</caption>
        <thead className="text-[11px] uppercase tracking-wide text-subtle">
          <tr>
            <th className="py-2 pr-4 font-medium">Rule</th>
            <th className="py-2 pr-4 font-medium">Severity</th>
            <th className="py-2 pr-4 text-right font-medium">Events</th>
            <th className="py-2 pr-4 font-medium">Which</th>
            <th className="py-2 text-right font-medium">Time</th>
          </tr>
        </thead>
        <tbody>
          {res.rules.map((r) => (
            <tr key={r.rule} className={clsx("border-t border-line", r.matches === 0 && !r.error && "text-muted")}>
              <td className="py-2 pr-4">
                {r.rule === "<editor>" ? (
                  <span className="text-text">{r.title}</span>
                ) : (
                  <Link to={`/editor/${r.rule}`} className="text-text hover:text-accent">
                    {r.title}
                  </Link>
                )}
                <span className="block font-mono text-[11px] text-subtle">{r.rule}</span>
                {r.error && <span className="block text-xs text-warn">not evaluated: {r.error}</span>}
              </td>
              <td className="py-2 pr-4">
                <LevelTag level={r.level} />
              </td>
              <td className="py-2 pr-4 text-right font-semibold text-strong tabular-nums">{r.error ? "—" : r.matches}</td>
              <td className="py-2 pr-4 font-mono text-xs text-subtle">
                {r.sample.length ? `#${r.sample.join(", #")}${r.matches > r.sample.length ? "…" : ""}` : "—"}
              </td>
              <td className="py-2 text-right text-xs text-subtle tabular-nums">{r.duration_ms} ms</td>
            </tr>
          ))}
        </tbody>
      </table>
      {matched.length === 0 && skipped.length === 0 && <p className="text-sm text-muted">No rule fired on these events.</p>}
    </div>
  );
}

export default function ReplayPage() {
  const datasets = useQuery({ queryKey: ["datasets"], queryFn: api.datasets });
  const [selected, setSelected] = useState<string | null>(null);
  const run = useQuery({ queryKey: ["dataset-replay", selected], queryFn: () => api.runDataset(selected!), enabled: selected !== null });
  const [text, setText] = useState("");
  const paste = useMutation({ mutationFn: (events: string) => api.replay(events) });

  const onFile = async (file: File | undefined) => {
    if (!file) return;
    setText(await file.text());
  };

  return (
    <div className="mx-auto max-w-7xl px-4 py-8 sm:px-8">
      <PageHeader
        title="Log replay"
        subtitle="Replays local logs against every rule: attack simulation, production noise and regression (how many events each rule must match). Nothing leaves your machine."
      />

      <div className="grid gap-5 xl:grid-cols-[22rem_1fr]">
        <div className="flex flex-col gap-5">
          <Section title="Repository datasets" aside={<Database size={15} aria-hidden />}>
            {datasets.error && <ErrorBox message={(datasets.error as Error).message} />}
            {datasets.data?.length === 0 && (
              <p className="text-[13px] text-muted">
                No file in <span className="font-mono">datasets/</span>. Put events there as JSON, JSONL or YAML and, next to them, a{" "}
                <span className="font-mono">name.expect.yml</span> with the expected counts.
              </p>
            )}
            <ul className="space-y-1.5">
              {datasets.data?.map((d) => (
                <li key={d.name}>
                  <button
                    type="button"
                    onClick={() => setSelected(d.name)}
                    aria-pressed={selected === d.name}
                    className={clsx(
                      "flex w-full items-center gap-3 rounded-[10px] border px-3 py-2 text-left text-[13px]",
                      selected === d.name ? "border-accent/50 bg-accent-soft" : "border-line bg-surface hover:bg-surface-2",
                    )}
                  >
                    <Play size={14} className="shrink-0 text-accent" aria-hidden />
                    <span className="min-w-0 flex-1">
                      <span className="block truncate font-mono text-text">{d.name}</span>
                      <span className="block text-xs text-subtle">
                        {(d.size / 1024).toFixed(1)} KB · {d.expectations ? `${d.expectations} expectations` : "no expectations"}
                        {d.expect_error && <span className="text-bad"> · {d.expect_error}</span>}
                      </span>
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          </Section>

          <Section title="Pasted events">
            <label className="block">
              <span className="sr-only">Eventos em JSON, JSONL ou YAML</span>
              <textarea
                value={text}
                onChange={(e) => setText(e.target.value)}
                rows={9}
                placeholder="Paste events as JSON, JSON Lines or YAML"
                className="w-full rounded-[10px] border border-line bg-code p-3 font-mono text-xs text-code-text placeholder:text-subtle focus:border-accent/50"
              />
            </label>
            <div className="mt-2 flex flex-wrap gap-2">
              <button
                type="button"
                disabled={!text.trim() || paste.isPending}
                onClick={() => {
                  setSelected(null);
                  paste.mutate(text);
                }}
                className="inline-flex items-center gap-2 rounded-[10px] bg-brand px-3 py-2 text-[13px] font-semibold text-strong hover:brightness-110 disabled:opacity-50"
              >
                <Play size={14} aria-hidden /> Replay
              </button>
              <label className="inline-flex cursor-pointer items-center gap-2 rounded-[10px] border border-line bg-surface-2 px-3 py-2 text-[13px] font-semibold text-text hover:bg-surface-3">
                <Upload size={14} aria-hidden /> File
                <input type="file" accept=".json,.jsonl,.ndjson,.yml,.yaml" className="sr-only" onChange={(e) => onFile(e.target.files?.[0])} />
              </label>
              <button type="button" onClick={() => setText(EXAMPLE)} className="rounded-[10px] px-3 py-2 text-[13px] text-muted hover:text-text">
                Example
              </button>
            </div>
          </Section>
        </div>

        <Card className="p-5">
          <h2 className="mb-4 text-[15px] font-semibold text-strong">{selected ? `Replay of ${selected}` : paste.data ? "Replay of the pasted events" : "Result"}</h2>
          {selected && run.isFetching && <p className="text-sm text-muted">Replaying…</p>}
          {selected && run.error && <ErrorBox message={(run.error as Error).message} />}
          {selected && run.data && !run.isFetching && <Result res={run.data} />}
          {!selected && paste.error && <ErrorBox message={(paste.error as Error).message} />}
          {!selected && paste.data && <Result res={paste.data} />}
          {!selected && !paste.data && !paste.error && <p className="text-sm text-muted">Pick a dataset or paste events to see which rules fire.</p>}
        </Card>
      </div>
    </div>
  );
}
