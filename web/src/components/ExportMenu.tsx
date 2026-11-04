import { ChevronDown, Copy, Download, FileText, Printer } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { btnSecondary } from "./ui";
import { t } from "../i18n";

export interface ExportTable {
  /** Machine-friendly name used in the CSV filename and the Markdown heading. */
  name: string;
  label: string;
  columns: string[];
  rows: (string | number | null)[][];
}

interface Props {
  page: string;
  title: string;
  /** Headline numbers as "label: value" bullets. */
  facts: [string, string | number][];
  tables: ExportTable[];
  disabled?: boolean;
}

export function download(name: string, text: string, type: string) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

/** RFC 4180 with a CSV-injection guard (cells starting with = + - @ get a leading quote). */
export function toCsv(columns: string[], rows: (string | number | null)[][]): string {
  const cell = (v: string | number | null) => {
    let s = v === null ? "" : String(v);
    if (/^[=+\-@]/.test(s) && typeof v !== "number") s = `'${s}`;
    return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  return "﻿" + [columns, ...rows].map((r) => r.map(cell).join(",")).join("\r\n") + "\r\n";
}

export function toMarkdown(title: string, stamp: string, facts: [string, string | number][], tables: ExportTable[]): string {
  const esc = (v: string | number | null) => String(v ?? "").replace(/\|/g, "\\|").replace(/\r?\n/g, " ");
  const out = [`# ${title}`, "", `Generated ${stamp}`, ""];
  out.push(...facts.map(([k, v]) => `- ${k}: ${v}`), "");
  for (const tb of tables) {
    if (!tb.rows.length) continue;
    out.push(`## ${tb.label}`, "", `| ${tb.columns.join(" | ")} |`, `| ${tb.columns.map(() => "---").join(" | ")} |`);
    out.push(...tb.rows.map((r) => `| ${r.map(esc).join(" | ")} |`), "");
  }
  return out.join("\n");
}

export default function ExportMenu({ page, title, facts, tables, disabled }: Props) {
  const [open, setOpen] = useState(false);
  const [msg, setMsg] = useState("");
  const root = useRef<HTMLDivElement>(null);
  const stamp = new Date().toISOString().slice(0, 10);

  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => !root.current?.contains(e.target as Node) && setOpen(false);
    document.addEventListener("mousedown", onDown);
    return () => document.removeEventListener("mousedown", onDown);
  }, [open]);

  const items = () => Array.from(root.current?.querySelectorAll<HTMLElement>('[role="menuitem"]:not([disabled])') ?? []);
  const onKey = (e: React.KeyboardEvent) => {
    if (e.key === "Escape") {
      setOpen(false);
      root.current?.querySelector<HTMLElement>("button")?.focus();
      return;
    }
    if (e.key !== "ArrowDown" && e.key !== "ArrowUp") return;
    e.preventDefault();
    const list = items();
    const i = list.indexOf(document.activeElement as HTMLElement);
    list[(i + (e.key === "ArrowDown" ? 1 : -1) + list.length) % list.length]?.focus();
  };
  const done = (m: string) => {
    setMsg(m);
    setOpen(false);
    setTimeout(() => setMsg(""), 3000);
  };
  const markdown = () => toMarkdown(title, stamp, facts, tables);

  const item = "flex w-full items-center gap-2 px-3 py-2 text-left text-[13px] text-text hover:bg-surface-2 disabled:cursor-not-allowed disabled:text-subtle";
  return (
    <div ref={root} className="relative print:hidden" onKeyDown={onKey}>
      <button
        type="button"
        className={btnSecondary}
        aria-haspopup="menu"
        aria-expanded={open}
        disabled={disabled}
        onClick={() => {
          setOpen(!open);
          setTimeout(() => items()[0]?.focus(), 0);
        }}
      >
        <Download size={15} aria-hidden /> {t("ex_export")} <ChevronDown size={13} aria-hidden />
      </button>
      {open && (
        <div role="menu" aria-label={t("ex_export")} className="absolute right-0 z-30 mt-1 min-w-[15rem] overflow-hidden rounded-[10px] border border-line bg-surface py-1 shadow-lg">
          <button type="button" role="menuitem" className={item} onClick={() => { setOpen(false); window.print(); }}>
            <Printer size={14} aria-hidden /> {t("ex_print")}
          </button>
          <button type="button" role="menuitem" className={item} onClick={() => { download(`vitrix-${page}-${stamp}.md`, markdown(), "text/markdown"); done(t("ex_md_done")); }}>
            <FileText size={14} aria-hidden /> {t("ex_markdown")}
          </button>
          <button
            type="button"
            role="menuitem"
            className={item}
            onClick={async () => {
              try {
                await navigator.clipboard.writeText(markdown());
                done(t("ex_copied"));
              } catch {
                done(t("ex_copy_failed"));
              }
            }}
          >
            <Copy size={14} aria-hidden /> {t("ex_copy_md")}
          </button>
          {tables.map((tb) => (
            <button
              key={tb.name}
              type="button"
              role="menuitem"
              className={item}
              disabled={tb.rows.length === 0}
              title={tb.rows.length === 0 ? t("ex_no_rows") : undefined}
              onClick={() => { download(`vitrix-${page}-${tb.name}-${stamp}.csv`, toCsv(tb.columns, tb.rows), "text/csv;charset=utf-8"); done(t("ex_csv_done")); }}
            >
              <Download size={14} aria-hidden /> CSV: {tb.label}
              {tb.rows.length === 0 && <span className="ml-auto text-xs">{t("ex_no_rows")}</span>}
            </button>
          ))}
        </div>
      )}
      <span role="status" aria-live="polite" className="sr-only">
        {msg}
      </span>
    </div>
  );
}
