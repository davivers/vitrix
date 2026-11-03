import { yaml } from "@codemirror/lang-yaml";
import { HighlightStyle, syntaxHighlighting } from "@codemirror/language";
import { EditorView } from "@codemirror/view";
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
  selection: "#CFE0FD",
  activeLine: "#EEF2F7",
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
  selection: "#1E3A5F",
  activeLine: "#151922",
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
      "&.cm-focused .cm-selectionBackground, .cm-selectionBackground, .cm-content ::selection": { backgroundColor: p.selection },
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
  return [yaml(), ...build(dark ? DARK : LIGHT), EditorView.lineWrapping];
}
