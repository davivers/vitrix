import { yaml } from "@codemirror/lang-yaml";
import { HighlightStyle, syntaxHighlighting } from "@codemirror/language";
import { EditorView } from "@codemirror/view";
import { tags as t } from "@lezer/highlight";

// Tema escuro "vidro" do CodeMirror; cores do canvas de design.
const editorTheme = EditorView.theme(
  {
    "&": { fontSize: "13px", height: "100%", color: "#dce3f5", backgroundColor: "transparent" },
    ".cm-content": { fontFamily: "var(--font-mono)", caretColor: "#22d3ee" },
    ".cm-cursor, .cm-dropCursor": { borderLeftColor: "#22d3ee" },
    ".cm-gutters": { backgroundColor: "transparent", border: "none", color: "#5c6684" },
    ".cm-activeLineGutter": { backgroundColor: "transparent", color: "#a3adc4" },
    ".cm-activeLine": { backgroundColor: "rgb(255 255 255 / 0.03)" },
    "&.cm-focused .cm-selectionBackground, .cm-selectionBackground, .cm-content ::selection": { backgroundColor: "rgb(139 124 246 / 0.3)" },
    ".cm-selectionMatch": { backgroundColor: "rgb(139 124 246 / 0.15)" },
    "&.cm-focused .cm-matchingBracket": { backgroundColor: "rgb(34 211 238 / 0.18)", outline: "none" },
    ".cm-tooltip": { backgroundColor: "#0b1020", border: "1px solid rgb(255 255 255 / 0.09)", color: "#e8ecf5" },
    "&.cm-focused": { outline: "none" },
  },
  { dark: true },
);

const editorHighlight = HighlightStyle.define([
  { tag: [t.propertyName, t.definition(t.propertyName)], color: "#93c5fd" },
  { tag: [t.string, t.special(t.string)], color: "#86efac" },
  { tag: [t.number, t.bool, t.null, t.atom], color: "#c4b5fd" },
  { tag: [t.keyword, t.typeName, t.labelName], color: "#c4b5fd" },
  { tag: [t.comment, t.lineComment], color: "#8791ab", fontStyle: "italic" },
  { tag: [t.punctuation, t.separator, t.operator], color: "#8791ab" },
  { tag: t.invalid, color: "#f87171" },
]);

/** Extensões do editor de YAML (criar uma vez por componente, com useMemo). */
export function yamlExtensions() {
  return [yaml(), editorTheme, syntaxHighlighting(editorHighlight), EditorView.lineWrapping];
}
