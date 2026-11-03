import { useQuery } from "@tanstack/react-query";
import { Copy, Download, FileJson, FileText, RefreshCw, Route } from "lucide-react";
import { useState } from "react";
import { Card, ErrorBox, PageHeader, btnSecondary } from "../components/ui";

async function fetchText(url: string): Promise<string> {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.text();
}

function download(name: string, text: string, type: string) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

export default function ReportsPage() {
  const md = useQuery({ queryKey: ["report-md"], queryFn: () => fetchText("/api/report?format=md") });
  const [copied, setCopied] = useState(false);
  const stamp = new Date().toISOString().slice(0, 10);

  const copy = async () => {
    if (!md.data) return;
    try {
      await navigator.clipboard.writeText(md.data);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* no clipboard permission */
    }
  };

  return (
    <div className="mx-auto max-w-5xl px-4 py-8 sm:px-8">
      <PageHeader
        title="Reports"
        subtitle="Quality gate, tests by kind, ATT&CK coverage, data sources, replay and rule-set health in one document. The same one `vitrix report` builds in CI."
        actions={
          <div className="flex flex-wrap gap-2">
            <button type="button" className={btnSecondary} onClick={() => md.refetch()}>
              <RefreshCw size={14} className={md.isFetching ? "animate-spin" : undefined} aria-hidden /> Regenerate
            </button>
            <button type="button" className={btnSecondary} disabled={!md.data} onClick={copy}>
              <Copy size={14} aria-hidden /> {copied ? "Copied" : "Copy Markdown"}
            </button>
            <button type="button" className={btnSecondary} disabled={!md.data} onClick={() => md.data && download(`vitrix-report-${stamp}.md`, md.data, "text/markdown")}>
              <FileText size={14} aria-hidden /> .md
            </button>
            <button
              type="button"
              className={btnSecondary}
              onClick={async () => download(`vitrix-report-${stamp}.json`, await fetchText("/api/report?format=json"), "application/json")}
            >
              <FileJson size={14} aria-hidden /> .json
            </button>
            <a href="/api/coverage/navigator" download="vitrix-attack-layer.json" className={btnSecondary}>
              <Route size={14} aria-hidden /> ATT&amp;CK layer
            </a>
          </div>
        }
      />
      {md.error && <ErrorBox message={(md.error as Error).message} />}
      {md.isLoading && <p className="text-sm text-muted">Building the report…</p>}
      {md.data && (
        <Card className="p-5">
          <div className="mb-3 flex items-center gap-2 text-xs text-subtle">
            <Download size={13} aria-hidden /> Markdown preview: paste it into a PR, wiki or ticket.
          </div>
          <pre className="max-h-[70vh] overflow-auto whitespace-pre-wrap rounded-[10px] border border-line bg-code p-4 font-mono text-[12.5px] leading-relaxed text-code-text">{md.data}</pre>
        </Card>
      )}
    </div>
  );
}
