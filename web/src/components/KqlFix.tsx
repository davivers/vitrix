import { useQueryClient } from "@tanstack/react-query";
import { Loader2, Wrench } from "lucide-react";
import { createContext, useContext, useState } from "react";
import { isMap, parseDocument } from "yaml";
import { api } from "../api";
import type { LintIssue, MappingsPatch } from "../types";
import { ErrorBox, btnPrimary, inputCls } from "./ui";
import { t } from "../i18n";

/** Lets an issue list edit the rule text and re-validate without knowing about the Editor. */
export interface FixActions {
  /** Put `vitrix: {kql_table: X}` into the rule YAML (unsaved, like any edit). */
  applyRuleTable: (table: string) => void;
  /** Validate again right now (after a mappings.yml change). */
  revalidate: () => void;
}
export const FixContext = createContext<FixActions | null>(null);

/**
 * Sets `vitrix.<key>: <value>` with a real YAML document editor: comments, flow style (`vitrix: {owner: x}`) and
 * every other key survive. Text that does not parse as a single mapping is returned untouched.
 */
export function setVitrixKey(yaml: string, key: string, value: string): string {
  const doc = parseDocument(yaml);
  if (doc.errors.length || !isMap(doc.contents)) return yaml;
  if (isMap(doc.get("vitrix", true))) doc.setIn(["vitrix", key], value);
  else doc.set("vitrix", doc.createNode({ [key]: value }));
  return doc.toString({ lineWidth: 0 });
}

/** Removes `vitrix.<key>`; drops the whole `vitrix` block when it ends up empty. */
export function removeVitrixKey(yaml: string, key: string): string {
  const doc = parseDocument(yaml);
  if (doc.errors.length || !isMap(doc.contents)) return yaml;
  const block = doc.get("vitrix", true);
  if (!isMap(block) || !block.has(key)) return yaml;
  doc.deleteIn(["vitrix", key]);
  if (isMap(doc.get("vitrix", true)) && (doc.get("vitrix", true) as { items: unknown[] }).items.length === 0) doc.delete("vitrix");
  return doc.toString({ lineWidth: 0 });
}

export const isKqlFix = (i: LintIssue) => i.code === "kql-table" || i.code === "kql-field";

/** Inline fix for a missing KQL table / unmapped fields: no vitrix.yml editing needed. */
export function KqlFixForm({ issue }: { issue: LintIssue }) {
  const ctx = useContext(FixContext);
  const qc = useQueryClient();
  const fix = issue.fix ?? {};
  const isField = issue.code === "kql-field";
  const key = fix.key ?? null;
  const [table, setTable] = useState(fix.suggestion ?? fix.table ?? "");
  const [scope, setScope] = useState<"rule" | "all">("rule");
  const fields = fix.fields ?? (fix.field ? [fix.field] : []);
  const [cols, setCols] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  if (!ctx) return null;
  // Field mapping needs a known table (the backend reports the inferred one); without it there is nothing to write to.
  if (isField && !fix.table) return null;

  const apply = async () => {
    setBusy(true);
    setError(null);
    try {
      if (!isField && scope === "rule") {
        ctx.applyRuleTable(table.trim());
      } else {
        const cur = await api.mappings();
        const kql: MappingsPatch = isField
          ? { fields: { [fix.table ?? ""]: Object.fromEntries(Object.entries(cols).filter(([, c]) => c.trim())) } }
          : { tables: { [key ?? ""]: table.trim() } };
        await api.putMappings({ kql, sha: cur.sha ?? null });
        void qc.invalidateQueries({ queryKey: ["mappings"] });
        void qc.invalidateQueries({ queryKey: ["rules"] });
      }
      ctx.revalidate();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <form
      className="mt-2 space-y-2 rounded-lg border border-line bg-surface-2 p-3 text-[13px]"
      aria-label={t("kf_title")}
      onSubmit={(e) => {
        e.preventDefault();
        void apply();
      }}
    >
      <p className="flex items-center gap-1.5 font-medium text-strong">
        <Wrench size={13} aria-hidden /> {isField ? t("kf_fields_title", { t: fix.table ?? "" }) : t("kf_title")}
      </p>
      {isField ? (
        <ul className="space-y-1">
          {fields.map((f) => (
            <li key={f} className="flex items-center gap-2">
              <span className="w-40 shrink-0 truncate font-mono text-xs text-text" title={f}>
                {f}
              </span>
              <span aria-hidden>{"->"}</span>
              <label className="flex-1">
                <span className="sr-only">{t("kf_column_for", { f })}</span>
                <input value={cols[f] ?? ""} onChange={(e) => setCols({ ...cols, [f]: e.target.value })} placeholder={f.replace(/[^A-Za-z0-9_]/g, "_")} className={`${inputCls} py-1 font-mono`} spellCheck={false} />
              </label>
            </li>
          ))}
        </ul>
      ) : (
        <>
          <div className="flex flex-wrap items-end gap-2">
            <label className="min-w-[10rem] flex-1">
              <span className="mb-1 block text-muted">{t("kf_table")}</span>
              <input value={table} onChange={(e) => setTable(e.target.value)} placeholder="Okta_CL" maxLength={100} className={`${inputCls} py-1.5 font-mono`} spellCheck={false} />
            </label>
            <button type="submit" disabled={busy || !table.trim()} aria-busy={busy} className={btnPrimary}>
              {busy && <Loader2 size={14} className="animate-spin" aria-hidden />} {t("kf_apply")}
            </button>
          </div>
          <fieldset className="flex flex-wrap gap-x-4 gap-y-1">
            <legend className="sr-only">{t("kf_scope")}</legend>
            <label className="flex items-center gap-2">
              <input type="radio" name={`kf-scope-${issue.line ?? 0}`} className="accent-accent" checked={scope === "rule"} onChange={() => setScope("rule")} /> {t("kf_this_rule")}
            </label>
            {key && (
              <label className="flex items-center gap-2">
                <input type="radio" name={`kf-scope-${issue.line ?? 0}`} className="accent-accent" checked={scope === "all"} onChange={() => setScope("all")} /> {t("kf_all", { k: key })}
              </label>
            )}
          </fieldset>
        </>
      )}
      {error && <ErrorBox message={error} />}
      {isField && (
        <button type="submit" disabled={busy || !Object.values(cols).some((c) => c.trim())} aria-busy={busy} className={btnPrimary}>
          {busy && <Loader2 size={14} className="animate-spin" aria-hidden />} {t("kf_apply")}
        </button>
      )}
    </form>
  );
}
