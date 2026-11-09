import { yaml } from "@codemirror/lang-yaml";
import { HighlightStyle, syntaxHighlighting } from "@codemirror/language";
import { lintGutter, setDiagnostics, type Diagnostic } from "@codemirror/lint";
import type { EditorState } from "@codemirror/state";
import { EditorView } from "@codemirror/view";
import { HintText } from "./Issues";
import type { LintIssue } from "../types";
import { createElement } from "react";
import { flushSync } from "react-dom";
import { createRoot } from "react-dom/client";
import { tags as t } from "@lezer/highlight";

interface Palette {
  dark: boolean;
  bg: string;
  gutter: string;
  text: string;
  gutterText: string;
  cursor: string;
  selection: string;
  activeLine: string;
  bracketBg: string;
  key: string;
  string: string;
  literal: string;
  comment: string;
  punct: string;
  error: string;
}

// Neutral syntax palettes (colors.md). All text colours are >= 4.5:1 on their editor background.
const LIGHT: Palette = {
  dark: false,
  bg: "#F8FAFC",
  gutter: "#F1F5F9",
  text: "#1E293B",
  gutterText: "#64748B",
  cursor: "#1D4ED8",
  selection: "#ADD6FF",
  activeLine: "rgba(15, 23, 42, 0.04)", // translucent: CodeMirror draws the selection behind the line
  bracketBg: "#DBEAFE",
  key: "#1D4ED8",
  string: "#0B6B5B",
  literal: "#B45309",
  comment: "#64748B",
  punct: "#475569",
  error: "#B91C1C",
};
const DARK: Palette = {
  dark: true,
  bg: "#0B0D11",
  gutter: "#11141A",
  text: "#E6E9EF",
  gutterText: "#8A93A3",
  cursor: "#60A5FA",
  selection: "#264F78",
  activeLine: "rgba(255, 255, 255, 0.04)",
  bracketBg: "#1E3A5F",
  key: "#7DB4FA",
  string: "#5EEAD4",
  literal: "#FBBF24",
  comment: "#8A93A3",
  punct: "#A4ACBA",
  error: "#F87171",
};

function build(p: Palette) {
  const theme = EditorView.theme(
    {
      "&": { fontSize: "13px", height: "100%", color: p.text, backgroundColor: p.bg },
      ".cm-content": { fontFamily: "var(--font-mono)", caretColor: p.cursor },
      ".cm-cursor, .cm-dropCursor": { borderLeftColor: p.cursor },
      ".cm-gutters": { backgroundColor: p.gutter, border: "none", color: p.gutterText },
      ".cm-activeLineGutter": { backgroundColor: p.activeLine },
      ".cm-activeLine": { backgroundColor: p.activeLine },
      // Same specificity as CodeMirror's base theme; a shorter selector would lose to its default colour.
      "&.cm-focused > .cm-scroller > .cm-selectionLayer .cm-selectionBackground, .cm-selectionBackground, .cm-content ::selection": { backgroundColor: p.selection },
      ".cm-selectionMatch": { backgroundColor: p.selection },
      "&.cm-focused .cm-matchingBracket": { backgroundColor: p.bracketBg, outline: `1px solid ${p.cursor}` },
      ".cm-tooltip": { backgroundColor: p.bg, border: `1px solid ${p.gutterText}`, color: p.text },
      "&.cm-focused": { outline: "none" },
    },
    { dark: p.dark },
  );
  const highlight = HighlightStyle.define([
    { tag: [t.propertyName, t.definition(t.propertyName)], color: p.key },
    { tag: [t.string, t.special(t.string)], color: p.string },
    { tag: [t.number, t.bool, t.null, t.atom], color: p.literal },
    { tag: [t.keyword, t.typeName, t.labelName], color: p.literal },
    { tag: [t.comment, t.lineComment], color: p.comment, fontStyle: "italic" },
    { tag: [t.punctuation, t.separator, t.operator], color: p.punct },
    { tag: t.invalid, color: p.error },
  ]);
  return [theme, syntaxHighlighting(highlight)];
}

/** YAML editor extensions for the current theme (create with useMemo keyed on the theme). */
export function yamlExtensions(dark = false) {
  return [yaml(), lintGutter(), ...build(dark ? DARK : LIGHT), EditorView.lineWrapping];
}

/** Offsets of an issue in the document (clamped: the text may have changed since the server validated it). */
export function issueRange(state: EditorState, issue: LintIssue): { from: number; to: number } | null {
  if (!issue.line || issue.line < 1) return null;
  const line = state.doc.line(Math.min(issue.line, state.doc.lines));
  const text = line.text;
  const indent = text.length - text.trimStart().length;
  let from = line.from + indent;
  let to = line.to;
  if (issue.column && issue.column >= 1) {
    from = Math.min(line.from + issue.column - 1, line.to);
    const word = /^\S+/.exec(text.slice(from - line.from));
    to = word ? from + word[0].length : Math.min(from + 1, line.to);
  }
  return { from, to: Math.max(to, Math.min(from + 1, state.doc.length)) };
}

/** Paints server issues as gutter markers + underline; the tooltip shows the message and the hint. */
export function paintIssues(view: EditorView, issues: LintIssue[]) {
  const diags: Diagnostic[] = [];
  for (const issue of issues) {
    const r = issueRange(view.state, issue);
    if (!r) continue;
    diags.push({
      ...r,
      severity: issue.severity,
      message: issue.hint ? `${issue.message} ${issue.hint}` : issue.message,
      renderMessage: () => {
        const el = document.createElement("div");
        el.className = "text-[13px]";
        const root = createRoot(el);
        flushSync(() => root.render(createElement("div", null, createElement("p", null, issue.message), issue.hint ? createElement("p", { className: "mt-1 opacity-80" }, createElement(HintText, { text: issue.hint })) : null)));
        return el;
      },
    });
  }
  view.dispatch(setDiagnostics(view.state, diags));
}
