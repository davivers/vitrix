import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Loader2, Rocket, Trash2 } from "lucide-react";
import { useState } from "react";
import { api } from "../api";
import { can, useMe } from "./auth";
import { PublicationBadge } from "../pages/Editor";
import { ErrorBox, btnSecondary, inputCls } from "./ui";
import { SIGMA, languageOptions } from "./FinalLanguage";
import type { FinalLanguagePatch, MappingsPatch } from "../types";
import { t } from "../i18n";

type Kql = MappingsPatch;

/** Settings -> Query mappings: the KQL tables and field columns kept in mappings.yml (written only by the app). */
export function MappingsPanel() {
  const me = useMe();
  const editor = can(me, "editor");
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["mappings"], queryFn: api.mappings, retry: false });
  const [newKey, setNewKey] = useState("");
  const [newTable, setNewTable] = useState("");
  const [edits, setEdits] = useState<Record<string, string>>({});
  const save = useMutation({
    mutationFn: (kql: Kql) => api.putMappings({ kql, sha: q.data?.sha ?? null }),
    onSuccess: () => {
      setEdits({});
      void qc.invalidateQueries({ queryKey: ["mappings"] });
      void qc.invalidateQueries({ queryKey: ["rules"] });
    },
  });
  const publish = useMutation({ mutationFn: () => api.publishMappings(null) });

  if (q.isLoading) return <p className="text-sm text-muted">{t("loading")}</p>;
  if (q.error) return <p className="text-sm text-muted">{(q.error as Error).message}</p>;
  const m = q.data;
  if (!m) return null;
  const tables = Object.entries(m.kql.tables);
  const fields = Object.entries(m.kql.fields);
  const put = (kql: Kql) => save.mutate(kql);
  const err = (save.error ?? publish.error) as Error | null;

  return (
    <div className="space-y-4 py-2 text-[13px]">
      <div className="flex flex-wrap items-center gap-3">
        <PublicationBadge pub={m.publication ?? null} isNew={false} />
        <span className="font-mono text-xs text-muted">{m.file ?? "mappings.yml"}</span>
        {editor && m.publication && m.publication.state !== "published" && (
          <button type="button" className={btnSecondary} disabled={publish.isPending} onClick={() => publish.mutate()}>
            {publish.isPending ? <Loader2 size={14} className="animate-spin" aria-hidden /> : <Rocket size={14} aria-hidden />} {t("mp_publish")}
          </button>
        )}
        {publish.data && <span className="text-good">{t("mp_published", { b: publish.data.branch })}</span>}
      </div>
      {err && <ErrorBox message={err.message} />}

      <section aria-labelledby="mp-tables">
        <h3 id="mp-tables" className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-subtle">
          {t("mp_tables")}
        </h3>
        {tables.length === 0 && <p className="text-muted">{t("mp_none")}</p>}
        <ul className="divide-y divide-line">
          {tables.map(([k, v]) => (
            <li key={k} className="flex flex-wrap items-center gap-2 py-1.5">
              <span className="w-56 shrink-0 font-mono text-xs text-text">{k}</span>
              <label className="flex-1">
                <span className="sr-only">{t("mp_table_for", { k })}</span>
                <input value={edits[k] ?? v} onChange={(e) => setEdits({ ...edits, [k]: e.target.value })} disabled={!editor} className={`${inputCls} py-1 font-mono`} spellCheck={false} />
              </label>
              {editor && (
                <>
                  <button type="button" className={btnSecondary} disabled={save.isPending || (edits[k] ?? v) === v || !(edits[k] ?? v).trim()} onClick={() => put({ tables: { [k]: (edits[k] ?? v).trim() } })}>
                    {t("save")}
                  </button>
                  <button
                    type="button"
                    className="rounded-md p-1.5 text-muted hover:bg-surface-2 hover:text-bad"
                    aria-label={t("mp_delete", { k })}
                    onClick={() => put({ tables: { [k]: null } })}
                  >
                    <Trash2 size={14} aria-hidden />
                  </button>
                </>
              )}
            </li>
          ))}
        </ul>
        {editor && (
          <form
            className="mt-2 flex flex-wrap items-center gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              if (newKey.trim() && newTable.trim()) {
                put({ tables: { [newKey.trim()]: newTable.trim() } });
                setNewKey("");
                setNewTable("");
              }
            }}
          >
            <label className="w-56">
              <span className="sr-only">{t("mp_new_key")}</span>
              <input value={newKey} onChange={(e) => setNewKey(e.target.value)} placeholder="okta/system" className={`${inputCls} py-1 font-mono`} spellCheck={false} />
            </label>
            <label className="min-w-[10rem] flex-1">
              <span className="sr-only">{t("mp_new_table")}</span>
              <input value={newTable} onChange={(e) => setNewTable(e.target.value)} placeholder="Okta_CL" className={`${inputCls} py-1 font-mono`} spellCheck={false} />
            </label>
            <button type="submit" className={btnSecondary} disabled={save.isPending || !newKey.trim() || !newTable.trim()}>
              {t("mp_add")}
            </button>
          </form>
        )}
      </section>

      <section aria-labelledby="mp-fields">
        <h3 id="mp-fields" className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-subtle">
          {t("mp_fields")}
        </h3>
        {fields.length === 0 && <p className="text-muted">{t("mp_none_fields")}</p>}
        {fields.map(([table, cols]) => (
          <div key={table} className="mb-2">
            <p className="font-mono text-xs font-semibold text-text">{table}</p>
            <ul className="ml-3 divide-y divide-line">
              {Object.entries(cols).map(([f, c]) => (
                <li key={f} className="flex items-center gap-2 py-1 font-mono text-xs">
                  <span className="w-48 shrink-0 truncate text-muted">{f}</span>
                  <span aria-hidden>{"->"}</span>
                  <span className="flex-1 text-text">{c}</span>
                  {editor && (
                    <button
                      type="button"
                      className="rounded-md p-1 text-muted hover:bg-surface-2 hover:text-bad"
                      aria-label={t("mp_delete", { k: `${table}.${f}` })}
                      onClick={() => put({ fields: { [table]: { [f]: null } } })}
                    >
                      <Trash2 size={13} aria-hidden />
                    </button>
                  )}
                </li>
              ))}
            </ul>
          </div>
        ))}
      </section>
    </div>
  );
}

/** Settings -> Final language: workspace default and per-folder defaults, stored in mappings.yml. */
export function FinalLanguagePanel() {
  const me = useMe();
  const editor = can(me, "editor");
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["mappings"], queryFn: api.mappings, retry: false });
  const targets = useQuery({ queryKey: ["targets"], queryFn: api.targets, retry: false });
  const [glob, setGlob] = useState("");
  const [lang, setLang] = useState(SIGMA);
  const save = useMutation({
    mutationFn: (patch: FinalLanguagePatch) => api.putMappings({ final_language: patch, sha: q.data?.sha ?? null }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["mappings"] });
      void qc.invalidateQueries({ queryKey: ["rules"] });
    },
  });
  if (q.isLoading) return <p className="text-sm text-muted">{t("loading")}</p>;
  if (q.error) return <p className="text-sm text-muted">{(q.error as Error).message}</p>;
  const m = q.data;
  if (!m) return null;
  const opts = languageOptions(targets.data);
  const fl = m.final_language ?? { default: null, folders: {} };
  const label = (id: string) => opts.find((o) => o.id === id)?.label ?? id;
  const folders = Object.entries(fl.folders);
  return (
    <div className="space-y-4 py-2 text-[13px]">
      <div className="flex flex-wrap items-center gap-3">
        <PublicationBadge pub={m.publication ?? null} isNew={false} />
        <span className="font-mono text-xs text-muted">{m.file ?? "mappings.yml"}</span>
      </div>
      {save.error && <ErrorBox message={(save.error as Error).message} />}
      <label className="flex flex-wrap items-center gap-3">
        <span className="w-48 text-muted">{t("fl_workspace_default")}</span>
        <select
          className={`${inputCls} max-w-xs py-1.5`}
          disabled={!editor || save.isPending}
          value={fl.default ?? ""}
          onChange={(e) => save.mutate({ default: e.target.value || null })}
        >
          <option value="">{t("fl_all_active")}</option>
          {opts.map((o) => (
            <option key={o.id} value={o.id}>
              {o.label}
            </option>
          ))}
        </select>
      </label>
      <section aria-labelledby="fl-folders">
        <h3 id="fl-folders" className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-subtle">
          {t("fl_folders")}
        </h3>
        {folders.length === 0 && <p className="text-muted">{t("fl_no_folders")}</p>}
        <ul className="divide-y divide-line">
          {folders.map(([g, id]) => (
            <li key={g} className="flex flex-wrap items-center gap-2 py-1.5">
              <span className="w-56 shrink-0 font-mono text-xs text-text">{g}</span>
              <label>
                <span className="sr-only">{t("fl_lang_for", { g })}</span>
                <select className={`${inputCls} w-auto py-1`} disabled={!editor || save.isPending} value={id} onChange={(e) => save.mutate({ folders: { [g]: e.target.value } })}>
                  {opts.map((o) => (
                    <option key={o.id} value={o.id}>
                      {o.label}
                    </option>
                  ))}
                </select>
              </label>
              <span className="text-xs text-muted">{label(id)}</span>
              {editor && (
                <button type="button" className="ml-auto rounded-md p-1.5 text-muted hover:bg-surface-2 hover:text-bad" aria-label={t("mp_delete", { k: g })} onClick={() => save.mutate({ folders: { [g]: null } })}>
                  <Trash2 size={14} aria-hidden />
                </button>
              )}
            </li>
          ))}
        </ul>
        {editor && (
          <form
            className="mt-2 flex flex-wrap items-center gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              if (glob.trim()) {
                save.mutate({ folders: { [glob.trim()]: lang } });
                setGlob("");
              }
            }}
          >
            <label className="w-56">
              <span className="sr-only">{t("fl_new_folder")}</span>
              <input value={glob} onChange={(e) => setGlob(e.target.value)} placeholder="windows/*" className={`${inputCls} py-1 font-mono`} spellCheck={false} />
            </label>
            <label>
              <span className="sr-only">{t("ed_final_lang")}</span>
              <select className={`${inputCls} w-auto py-1`} value={lang} onChange={(e) => setLang(e.target.value)}>
                {opts.map((o) => (
                  <option key={o.id} value={o.id}>
                    {o.label}
                  </option>
                ))}
              </select>
            </label>
            <button type="submit" className={btnSecondary} disabled={save.isPending || !glob.trim()}>
              {t("mp_add")}
            </button>
          </form>
        )}
      </section>
    </div>
  );
}
