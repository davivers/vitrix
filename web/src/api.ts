import type { Activity, ConfigCheck, ConfigView, Coverage, Dataset, GitHubStatus, PullRequest, QualityReport, QualityRule, ReplayResult, RuleDetail, RuleSummary, Stats, Target, TestSuites, Validation } from "./types";

class ApiError extends Error {}

export async function request<T>(url: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(url, init);
  } catch {
    throw new ApiError("Não consegui falar com a API. O `vitrix serve` está rodando?");
  }
  if (!res.ok) {
    let detail = `${res.status} ${res.statusText}`;
    try {
      const body = await res.json();
      if (typeof body.detail === "string") detail = body.detail;
      else if (Array.isArray(body.detail)) detail = body.detail.map((d: { msg: string }) => d.msg).join("; ");
    } catch {
      /* corpo não é JSON */
    }
    throw new ApiError(detail);
  }
  return res.json() as Promise<T>;
}

export const api = {
  rules: () => request<RuleSummary[]>("/api/rules"),
  rule: (id: string) => request<RuleDetail>(`/api/rules/${id.split("/").map(encodeURIComponent).join("/")}`),
  stats: () => request<Stats>("/api/stats"),
  validate: (rule: string, cases: string | null, signal?: AbortSignal) =>
    request<Validation>("/api/validate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ rule, cases }),
      signal,
    }),
  github: () => request<GitHubStatus>("/api/github"),
  pullRequest: (body: { path: string; rule: string; cases: string | null; title: string | null }) =>
    request<PullRequest>("/api/pull-requests", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }),
  activity: (refresh = false) => request<Activity>(`/api/github/activity${refresh ? "?refresh=true" : ""}`),
  targets: () => request<Target[]>("/api/targets"),
  config: () => request<ConfigView>("/api/config"),
  validateConfig: (text: string, signal?: AbortSignal) =>
    request<ConfigCheck>("/api/config/validate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text }),
      signal,
    }),
  configPullRequest: (body: { text: string; title: string | null }) =>
    request<PullRequest>("/api/config/pull-requests", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }),
  quality: () => request<QualityReport>("/api/quality"),
  qualityRule: (id: string) => request<QualityRule>(`/api/quality/${id.split("/").map(encodeURIComponent).join("/")}`),
  tests: () => request<TestSuites>("/api/tests"),
  coverage: () => request<Coverage>("/api/coverage"),
  datasets: () => request<Dataset[]>("/api/datasets"),
  runDataset: (name: string) => request<ReplayResult>(`/api/datasets/${name.split("/").map(encodeURIComponent).join("/")}/replay`),
  replay: (events: string, rule?: string) =>
    request<ReplayResult>("/api/replay", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ events, rule: rule ?? null }),
    }),
};
