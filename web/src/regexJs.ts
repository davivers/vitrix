/** The JavaScript (ECMAScript) regex engine of the workbench: runs in a Web Worker, killed after a hard timeout. */

export interface JsMatch {
  start: number;
  end: number;
  text: string;
  groups: (string | null)[];
  named: Record<string, string | null>;
}

export interface JsResult {
  ok: boolean;
  timeout: boolean;
  error?: string;
  position?: number;
  groups?: number;
  names?: string[];
  results?: { matched: boolean; matches: JsMatch[]; duration_ms: number }[];
  tips: { severity: "error" | "warning" | "info"; message: string }[];
  sigma: string | null;
  elapsed_ms?: number;
  engine: { name: string; version?: string; timeout_ms?: number };
}

// Plain-text worker source (no build step): evaluates every sample, same result shape as /api/regex.
const SOURCE = `
self.onmessage = (e) => {
  const { pattern, flags, samples } = e.data;
  let re;
  try {
    re = new RegExp(pattern, flags.replace(/[^imsu]/g, "") + "g");
  } catch (err) {
    self.postMessage({ ok: false, error: String(err && err.message || err) });
    return;
  }
  const t0 = performance.now();
  const names = [];
  const probe = new RegExp(re.source + "|", re.flags).exec("");
  const groups = probe ? probe.length - 1 : 0;
  const results = samples.map((s) => {
    const a = performance.now();
    const matches = [];
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(s)) !== null) {
      for (const k of Object.keys(m.groups || {})) if (!names.includes(k)) names.push(k);
      matches.push({ start: m.index, end: m.index + m[0].length, text: m[0], groups: m.slice(1).map((g) => (g === undefined ? null : g)), named: Object.fromEntries(Object.entries(m.groups || {}).map(([k, v]) => [k, v === undefined ? null : v])) });
      if (m[0] === "") re.lastIndex++;
      if (matches.length >= 200) break;
    }
    return { matched: matches.length > 0, matches, duration_ms: Math.round((performance.now() - a) * 100) / 100 };
  });
  self.postMessage({ ok: true, groups, names, results, elapsed_ms: Math.round(performance.now() - t0) });
};
`;

export const JS_ENGINE_ID = "javascript";
export const JS_TIMEOUT_MS = 1000;

export function runJs(pattern: string, flags: string, samples: string[]): Promise<JsResult> {
  const engine = { name: "JavaScript (ECMAScript)", version: "browser", timeout_ms: JS_TIMEOUT_MS };
  return new Promise((resolve) => {
    let worker: Worker;
    let url = "";
    try {
      url = URL.createObjectURL(new Blob([SOURCE], { type: "text/javascript" }));
      worker = new Worker(url);
    } catch (e) {
      if (url) URL.revokeObjectURL(url);
      resolve({ ok: false, timeout: false, error: (e as Error).message, tips: [], sigma: null, engine });
      return;
    }
    const done = (r: Omit<JsResult, "tips" | "sigma" | "engine" | "timeout"> & { timeout?: boolean }) => {
      clearTimeout(timer);
      worker.terminate();
      URL.revokeObjectURL(url);
      resolve({ timeout: false, tips: [], sigma: null, engine, ...r });
    };
    const timer = setTimeout(() => done({ ok: false, timeout: true, error: `timed out after ${JS_TIMEOUT_MS} ms` }), JS_TIMEOUT_MS);
    worker.onmessage = (e) => done(e.data);
    worker.onerror = (e) => done({ ok: false, error: e.message || "worker error" });
    worker.postMessage({ pattern, flags, samples });
  });
}
