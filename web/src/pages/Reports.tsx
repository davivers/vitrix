import { useQuery } from "@tanstack/react-query";
import { Copy, Download, FileJson, FileText, RefreshCw } from "lucide-react";
import { useState } from "react";
import { Card, ErrorBox, PageHeader } from "../components/ui";

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
      /* sem permissão */
    }
  };

  const btn = "inline-flex items-center gap-2 rounded-[10px] border border-line bg-surface-2 px-3 py-2 text-[13px] font-semibold text-text hover:bg-surface-3 disabled:opacity-50";

  return (
    <div className="mx-auto max-w-5xl px-4 py-8 sm:px-8">
      <PageHeader
        title="Relatórios"
        subtitle="Quality gate, testes por tipo, cobertura ATT&CK, replay e saúde do acervo em um documento. O mesmo que `vitrix report` gera no CI."
        actions={
          <div className="flex flex-wrap gap-2">
            <button type="button" className={btn} onClick={() => md.refetch()}>
              <RefreshCw size={14} className={md.isFetching ? "animate-spin" : undefined} aria-hidden /> Gerar de novo
            </button>
            <button type="button" className={btn} disabled={!md.data} onClick={copy}>
              <Copy size={14} aria-hidden /> {copied ? "Copiado" : "Copiar Markdown"}
            </button>
            <button type="button" className={btn} disabled={!md.data} onClick={() => md.data && download(`vitrix-relatorio-${stamp}.md`, md.data, "text/markdown")}>
              <FileText size={14} aria-hidden /> .md
            </button>
            <button
              type="button"
              className={btn}
              onClick={async () => download(`vitrix-relatorio-${stamp}.json`, await fetchText("/api/report?format=json"), "application/json")}
            >
              <FileJson size={14} aria-hidden /> .json
            </button>
          </div>
        }
      />
      {md.error && <ErrorBox message={(md.error as Error).message} />}
      {md.isLoading && <p className="text-sm text-muted">Gerando o relatório…</p>}
      {md.data && (
        <Card className="p-5">
          <div className="mb-3 flex items-center gap-2 text-xs text-subtle">
            <Download size={13} aria-hidden /> Pré-visualização em Markdown: cole em um PR, wiki ou ticket.
          </div>
          <pre className="max-h-[70vh] overflow-auto whitespace-pre-wrap rounded-[10px] border border-line bg-code p-4 font-mono text-[12.5px] leading-relaxed text-code-text">{md.data}</pre>
        </Card>
      )}
    </div>
  );
}
