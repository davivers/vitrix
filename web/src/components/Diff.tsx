import { t } from "../i18n";

type Op = { k: " " | "+" | "-"; text: string; a?: number; b?: number };

/** Line diff by longest common subsequence (inputs are rule files: a few hundred lines at most). */
export function diffLines(a: string, b: string): Op[] | null {
  const x = a.split("\n");
  const y = b.split("\n");
  if (x.length * y.length > 4_000_000) return null; // too large: the caller says so
  const dp: number[][] = Array.from({ length: x.length + 1 }, () => new Array<number>(y.length + 1).fill(0));
  for (let i = x.length - 1; i >= 0; i--) for (let j = y.length - 1; j >= 0; j--) dp[i][j] = x[i] === y[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
  const out: Op[] = [];
  let i = 0;
  let j = 0;
  while (i < x.length && j < y.length) {
    if (x[i] === y[j]) out.push({ k: " ", text: x[i], a: ++i, b: ++j });
    else if (dp[i + 1][j] >= dp[i][j + 1]) out.push({ k: "-", text: x[i], a: ++i });
    else out.push({ k: "+", text: y[j], b: ++j });
  }
  while (i < x.length) out.push({ k: "-", text: x[i], a: ++i });
  while (j < y.length) out.push({ k: "+", text: y[j], b: ++j });
  return out;
}

/** Unified diff: +/- markers in the gutter (never colour alone), unchanged runs beyond 3 lines collapsed. */
export function Diff({ before, after }: { before: string; after: string }) {
  const ops = diffLines(before, after);
  if (!ops) return <p className="text-sm text-muted">{t("df_too_large")}</p>;
  const added = ops.filter((o) => o.k === "+").length;
  const removed = ops.filter((o) => o.k === "-").length;
  if (added + removed === 0) return <p className="text-sm text-muted">{t("df_none")}</p>;
  const keep = ops.map((o, i) => o.k !== " " || ops.slice(Math.max(0, i - 3), i + 4).some((n) => n.k !== " "));
  const rows: React.ReactNode[] = [];
  let hidden = 0;
  const gap = (key: string, n: number) => (
    <tr key={key} className="text-subtle">
      <td colSpan={3} className="px-3 py-0.5 text-center text-xs">
        {t("df_unchanged", { n })}
      </td>
    </tr>
  );
  ops.forEach((o, i) => {
    if (!keep[i]) {
      hidden++;
      return;
    }
    if (hidden) {
      rows.push(gap(`h${i}`, hidden));
      hidden = 0;
    }
    const tone = o.k === "+" ? "bg-good-soft" : o.k === "-" ? "bg-bad-soft" : "bg-code";
    rows.push(
      <tr key={i} className={tone}>
        <td className="w-10 select-none px-2 text-right tabular-nums text-subtle">{o.a ?? o.b}</td>
        <td className="w-5 select-none text-center font-semibold" aria-label={o.k === "+" ? t("df_added") : o.k === "-" ? t("df_removed") : undefined}>
          {o.k === " " ? "" : o.k}
        </td>
        <td className="whitespace-pre pr-3 text-code-text">{o.text}</td>
      </tr>,
    );
  });
  if (hidden) rows.push(gap("tail", hidden));
  return (
    <div>
      <p className="mb-1 text-xs tabular-nums text-muted">
        +{added} -{removed}
      </p>
      <div role="region" aria-label={t("df_title")} className="overflow-auto rounded-[10px] border border-line">
        <table className="w-full font-mono text-[12.5px] leading-5">
          <tbody>{rows}</tbody>
        </table>
      </div>
    </div>
  );
}
