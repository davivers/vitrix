import { useQuery } from "@tanstack/react-query";
import { Copy, Download, FileJson, FileText, RefreshCw, Route } from "lucide-react";
import { useState } from "react";
import { api } from "../api";
import { Card, ErrorBox, PageHeader, btnSecondary } from "../components/ui";
import { t } from "../i18n";

function download(name: string, text: string, type: string) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

export default function ReportsPage() {
  const md = useQuery({ queryKey: ["report-md"], queryFn: () => api.report("md") });
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
        title={t("reports")}
        subtitle={t("rp_sub")}
        actions={
          <div className="flex flex-wrap gap-2">
            <button type="button" className={btnSecondary} onClick={() => md.refetch()}>
              <RefreshCw size={14} className={md.isFetching ? "animate-spin" : undefined} aria-hidden /> {t("regenerate")}
            </button>
            <button type="button" className={btnSecondary} disabled={!md.data} onClick={copy}>
              <Copy size={14} aria-hidden /> {copied ? t("l_copied") : t("rp_copy_md")}
            </button>
            <button type="button" className={btnSecondary} disabled={!md.data} onClick={() => md.data && download(`vitrix-report-${stamp}.md`, md.data, "text/markdown")}>
              <FileText size={14} aria-hidden /> .md
            </button>
            <button
              type="button"
              className={btnSecondary}
              onClick={async () => download(`vitrix-report-${stamp}.json`, await api.report("json"), "application/json")}
            >
              <FileJson size={14} aria-hidden /> .json
            </button>
            <a href="/api/coverage/navigator" download="vitrix-attack-layer.json" className={btnSecondary}>
              <Route size={14} aria-hidden /> {t("rp_layer")}
            </a>
          </div>
        }
      />
      {md.error && <ErrorBox message={(md.error as Error).message} />}
      {md.isLoading && <p className="text-sm text-muted">{t("building_the_report")}</p>}
      {md.data && (
        <Card className="p-5">
          <div className="mb-3 flex items-center gap-2 text-xs text-subtle">
            <Download size={13} aria-hidden /> {t("markdown_preview_paste_it_into_a_pr_wi")}
          </div>
          <pre className="max-h-[70vh] overflow-auto whitespace-pre-wrap rounded-[10px] border border-line bg-code p-4 font-mono text-[12.5px] leading-relaxed text-code-text">{md.data}</pre>
        </Card>
      )}
    </div>
  );
}
