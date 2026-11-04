import { useQuery, useQueryClient } from "@tanstack/react-query";
import clsx from "clsx";
import { Check, ChevronDown, FileCode2 } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { api } from "../api";
import { TargetSwatch } from "./ui";
import type { Target } from "../types";
import { t } from "../i18n";

export const SIGMA = "sigma";

/** Targets for a chooser: Sigma (no conversion) first, then every active language. */
export function languageOptions(targets: Target[] | undefined): { id: string; label: string }[] {
  // /api/targets lists `sigma` first (pseudo target), then every active language.
  return (targets ?? []).filter((x) => x.active).map((x) => ({ id: x.name, label: x.name === SIGMA ? t("fl_sigma") : x.label }));
}

export function LangIcon({ id }: { id: string }) {
  return id === SIGMA ? <FileCode2 size={13} className="text-muted" aria-hidden /> : <TargetSwatch target={id} />;
}

const SOURCE_KEY: Record<string, "fl_src_rule" | "fl_src_folder" | "fl_src_default" | "fl_src_legacy" | "fl_src_all"> = {
  rule: "fl_src_rule",
  override: "fl_src_rule",
  folder: "fl_src_folder",
  workspace: "fl_src_default",
  "legacy-config": "fl_src_legacy",
  default: "fl_src_default",
  route: "fl_src_legacy",
  all: "fl_src_all",
};

interface Props {
  /** Final language(s) of the validated rule (ids). */
  finals: string[];
  labels: Record<string, string>;
  /** Why it is the final language (rule / folder / default / all). */
  source: string | null;
  /** The rule's own `vitrix.target`, or null when it follows the default. */
  own: string | null;
  /** Folder of the rule under rules/ ("windows"), or null at the top level / unsaved. */
  folder: string | null;
  disabled: boolean;
  onChoose: (id: string | null) => void;
}

/** Final language chooser: Sigma (no conversion), each active language, or the default. Writes `vitrix.target` for the rule. */
export function FinalLanguageSelect({ finals, labels, source, own, folder, disabled, onChoose }: Props) {
  const targets = useQuery({ queryKey: ["targets"], queryFn: api.targets, retry: false });
  const qc = useQueryClient();
  const [open, setOpen] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const root = useRef<HTMLDivElement>(null);
  const opts = languageOptions(targets.data);
  const labelOf = (id: string) => (id === SIGMA ? t("fl_sigma") : (labels[id] ?? opts.find((o) => o.id === id)?.label ?? id));
  const current = finals.length ? finals.map(labelOf).join(", ") : t("fl_all_active");

  useEffect(() => {
    if (!open) return;
    const away = (e: MouseEvent) => !root.current?.contains(e.target as Node) && setOpen(false);
    document.addEventListener("mousedown", away);
    return () => document.removeEventListener("mousedown", away);
  }, [open]);

  const folderDefault = async (id: string) => {
    if (!folder) return;
    try {
      const cur = await api.mappings();
      await api.putMappings({ final_language: { folders: { [`${folder}/*`]: id } }, sha: cur.sha ?? null });
      void qc.invalidateQueries({ queryKey: ["mappings"] });
      setMsg(t("fl_folder_saved", { f: folder }));
      onChoose(null); // the folder default now applies to this rule
    } catch (e) {
      setMsg((e as Error).message);
    }
    setOpen(false);
  };

  const key = source ? SOURCE_KEY[source] : undefined;
  const item = "flex w-full items-center gap-2 px-3 py-1.5 text-left text-[13px] text-text hover:bg-surface-2";
  return (
    <div ref={root} className="relative inline-flex items-center gap-2" onKeyDown={(e) => e.key === "Escape" && setOpen(false)}>
      <span className="text-muted">{t("ed_final_lang")}</span>
      <button
        type="button"
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label={`${t("ed_final_lang")}: ${current}`}
        disabled={disabled}
        onClick={() => setOpen(!open)}
        className="inline-flex items-center gap-1.5 rounded-md border border-line bg-surface px-2 py-1 text-xs font-medium text-text hover:bg-surface-2 disabled:opacity-60"
      >
        {finals.map((n) => (
          <LangIcon key={n} id={n} />
        ))}
        {current}
        <ChevronDown size={12} aria-hidden />
      </button>
      {key && <span className="text-subtle">({t(key)})</span>}
      {msg && (
        <span role="status" className="text-good">
          {msg}
        </span>
      )}
      {open && (
        <div role="menu" aria-label={t("ed_final_lang")} className="absolute left-0 top-full z-30 mt-1 min-w-[17rem] overflow-hidden rounded-[10px] border border-line bg-surface py-1 shadow-lg">
          <button type="button" role="menuitemradio" aria-checked={own === null} className={item} onClick={() => { onChoose(null); setOpen(false); }}>
            <span className="w-4">{own === null && <Check size={13} aria-hidden />}</span>
            {t("fl_use_default")}
            <span className="ml-auto text-xs text-subtle">{own === null ? `${current}` : ""}</span>
          </button>
          <div className="my-1 border-t border-line" role="separator" />
          {opts.map((o) => (
            <button key={o.id} type="button" role="menuitemradio" aria-checked={own === o.id} className={clsx(item)} onClick={() => { onChoose(o.id); setOpen(false); }}>
              <span className="w-4">{own === o.id && <Check size={13} aria-hidden />}</span>
              <LangIcon id={o.id} /> {o.label}
            </button>
          ))}
          {folder && (
            <>
              <div className="my-1 border-t border-line" role="separator" />
              <p className="px-3 pb-0.5 pt-1 text-[11px] font-semibold uppercase tracking-wider text-subtle">{t("fl_for_folder", { f: folder })}</p>
              {opts.map((o) => (
                <button key={`f-${o.id}`} type="button" role="menuitem" className={item} onClick={() => void folderDefault(o.id)}>
                  <span className="w-4" />
                  <LangIcon id={o.id} /> {o.label}
                </button>
              ))}
            </>
          )}
        </div>
      )}
    </div>
  );
}
