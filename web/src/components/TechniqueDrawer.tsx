import { ExternalLink, X } from "lucide-react";
import { useEffect, useRef } from "react";
import { Link } from "react-router-dom";
import { LEVEL_RANK, type Cell } from "./AttackMatrix";
import { LevelTag, StateBadge } from "./ui";
import { t } from "../i18n";

/** Non-modal detail panel for one technique: where it appears and the rules behind it. Esc closes. */
export function TechniqueDrawer(props: { cell: Cell; tactics: string[]; onClose: () => void }) {
  const { cell, tactics, onClose } = props;
  const closeRef = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    closeRef.current?.focus();
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const rules = [...cell.rules].sort((a, b) => (LEVEL_RANK[b.level ?? ""] ?? -1) - (LEVEL_RANK[a.level ?? ""] ?? -1) || a.title.localeCompare(b.title));
  const attack = /^T\d{4}(\.\d{3})?$/.test(cell.id) ? `https://attack.mitre.org/techniques/${cell.id.replace(".", "/")}/` : null;

  return (
    <aside
      role="dialog"
      aria-modal="false"
      aria-labelledby="tech-title"
      className="glass fixed inset-x-0 bottom-0 z-30 flex max-h-[90vh] flex-col rounded-t-2xl bg-surface shadow-pop sm:inset-x-auto sm:bottom-4 sm:right-4 sm:top-4 sm:max-h-none sm:w-[420px] sm:rounded-2xl"
    >
      <div className="flex items-start justify-between gap-3 border-b border-line p-4">
        <div className="min-w-0">
          <h2 id="tech-title" className="font-mono text-lg font-semibold text-strong">
            {cell.id}
          </h2>
          <p className="mt-0.5 text-xs text-muted">{t("appears_in")} {tactics.join(", ") || "—"}</p>
        </div>
        <button ref={closeRef} type="button" onClick={onClose} aria-label={t("close")} className="rounded-md p-1 text-muted hover:bg-surface-2 hover:text-text">
          <X size={18} aria-hidden />
        </button>
      </div>
      <div className="min-h-0 flex-1 space-y-3 overflow-auto p-4">
        {attack && (
          <a href={attack} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1.5 text-[13px] font-medium text-accent hover:underline">
            <ExternalLink size={14} aria-hidden /> {t("open_on_attack_mitre_org")}
          </a>
        )}
        <h3 className="text-[11px] font-semibold uppercase tracking-wider text-subtle">{t("rules")}{rules.length})</h3>
        {rules.length === 0 ? (
          <p className="text-sm text-muted">
            {t("no_rule_detects_this_technique_yet")}{" "}
            <Link to="/editor" className="text-accent hover:underline">
              {t("write_a_rule")}
            </Link>
          </p>
        ) : (
          <ul className="divide-y divide-line">
            {rules.map((r) => (
              <li key={r.id} className="flex flex-wrap items-center gap-x-3 gap-y-1 py-2.5">
                <StateBadge state={r.state} />
                <Link to={`/editor/${r.id}`} className="min-w-0 flex-1 truncate text-[13px] text-text hover:text-accent" title={r.id}>
                  {r.title || r.id}
                </Link>
                <LevelTag level={r.level} />
              </li>
            ))}
          </ul>
        )}
      </div>
    </aside>
  );
}
