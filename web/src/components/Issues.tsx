import clsx from "clsx";
import { AlertTriangle, Check, Copy, XCircle } from "lucide-react";
import { Fragment, useState, type ReactNode } from "react";
import type { LintIssue } from "../types";
import { t } from "../i18n";

/** Renders `backticked` spans as inline code; everything else stays plain text (no HTML is ever injected). */
export function HintText({ text }: { text: string }): ReactNode {
  return (
    <>
      {text.split(/(`[^`]+`)/g).map((part, i) =>
        part.startsWith("`") && part.endsWith("`") && part.length > 2 ? (
          <code key={i} className="rounded bg-surface-3 px-1 py-0.5 font-mono text-[0.92em] text-text">
            {part.slice(1, -1)}
          </code>
        ) : (
          <Fragment key={i}>{part}</Fragment>
        ),
      )}
    </>
  );
}

export function CopySnippet({ snippet }: { snippet: string }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    void navigator.clipboard?.writeText(snippet).then(
      () => {
        setCopied(true);
        setTimeout(() => setCopied(false), 1500);
      },
      () => undefined,
    );
  };
  return (
    <div className="mt-1.5 overflow-hidden rounded-lg border border-line bg-code">
      <pre className="overflow-auto whitespace-pre p-2.5 font-mono text-xs text-code-text">{snippet}</pre>
      <button type="button" onClick={copy} className="flex w-full items-center gap-1.5 border-t border-line px-2.5 py-1.5 text-xs font-medium text-accent hover:bg-surface-2">
        {copied ? <Check size={12} aria-hidden /> : <Copy size={12} aria-hidden />} {copied ? t("is_copied") : t("is_copy_fix")}
      </button>
    </div>
  );
}

/** Location label "line 12 · detection.selection.Image" (or just the path when the line is unknown). */
export const issueWhere = (i: LintIssue) => [i.line ? t("is_line", { n: i.line }) : null, i.path].filter(Boolean).join(" · ");

/** One issue: icon + message, a jump link to the line, the hint, and a copyable fix snippet. */
export function IssueItem({ issue, onJump }: { issue: LintIssue; onJump?: (issue: LintIssue) => void }) {
  const err = issue.severity === "error";
  const where = issueWhere(issue);
  return (
    <li className="flex items-start gap-2">
      {err ? <XCircle size={15} className="mt-0.5 shrink-0 text-bad" aria-label={t("l_error")} /> : <AlertTriangle size={15} className="mt-0.5 shrink-0 text-warn" aria-label={t("l_warning")} />}
      <div className="min-w-0 flex-1">
        <span className={clsx("text-text [overflow-wrap:anywhere]")}>{issue.message}</span>
        {where &&
          (onJump && issue.line ? (
            <button type="button" onClick={() => onJump(issue)} aria-label={t("is_go_to", { n: issue.line })} className="ml-2 font-mono text-xs text-accent hover:underline">
              {where}
            </button>
          ) : (
            <span className="ml-2 font-mono text-xs text-subtle">{where}</span>
          ))}
        {issue.hint && (
          <p className="mt-0.5 text-[12.5px] text-muted">
            <span className="font-medium text-strong">{t("is_how_to_fix")}</span> <HintText text={issue.hint} />
          </p>
        )}
        {issue.fix?.snippet && <CopySnippet snippet={issue.fix.snippet} />}
      </div>
    </li>
  );
}

export function IssueList({ issues, onJump }: { issues: LintIssue[]; onJump?: (issue: LintIssue) => void }) {
  return (
    <ul className="space-y-2.5 text-sm">
      {issues.map((i, n) => (
        <IssueItem key={`${i.code ?? ""}${i.line ?? ""}${n}`} issue={i} onJump={onJump} />
      ))}
    </ul>
  );
}
