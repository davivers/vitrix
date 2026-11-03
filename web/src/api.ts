import type {
  Activity,
  AuditEntry,
  AuthConfig,
  CreatedInvite,
  Me,
  Role,
  WorkspaceInfo,
  CiStatus,
  ConfigCheck,
  ConfigView,
  Coverage,
  Dataset,
  GitHubStatus,
  History,
  Impact,
  PullRequest,
  QualityReport,
  QualityRule,
  ReplayResult,
  RuleDetail,
  RuleHistory,
  RuleSummary,
  Stats,
  Submission,
  Target,
  TestSuites,
  Validation,
} from "./types";

class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}

export async function request<T>(url: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(url, init);
  } catch (e) {
    if ((e as Error).name === "AbortError") throw e;
    throw new ApiError("Cannot reach the API. Is `vitrix serve` running?", 0);
  }
  if (res.status === 401 && !url.startsWith("/api/auth/")) window.dispatchEvent(new Event("vitrix:unauthorized")); // session expired or revoked
  if (!res.ok) {
    let detail = `${res.status} ${res.statusText}`;
    try {
      const body = await res.json();
      if (typeof body.detail === "string") detail = body.detail;
      else if (Array.isArray(body.detail)) detail = body.detail.map((d: { msg: string }) => d.msg).join("; ");
    } catch {
      /* body is not JSON */
    }
    throw new ApiError(detail, res.status);
  }
  return res.json() as Promise<T>;
}

const path = (id: string) => id.split("/").map(encodeURIComponent).join("/");

function post<T>(url: string, body: unknown, signal?: AbortSignal): Promise<T> {
  return request<T>(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body), signal });
}

function del<T>(url: string): Promise<T> {
  return request<T>(url, { method: "DELETE" });
}

function patch<T>(url: string, body: unknown): Promise<T> {
  return request<T>(url, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
}

export const api = {
  // accounts and workspace
  authConfig: () => request<AuthConfig>("/api/auth/config"),
  me: () => request<Me>("/api/auth/me"),
  login: (email: string, password: string) => post<Me>("/api/auth/login", { email, password }),
  register: (body: { email: string; name: string; password: string; invite: string | null }) => post<Me>("/api/auth/register", body),
  logout: () => post<{ ok: boolean }>("/api/auth/logout", {}),
  changePassword: (current: string, next: string) => post<{ ok: boolean }>("/api/auth/password", { current, new: next }),
  workspace: () => request<WorkspaceInfo>("/api/workspace"),
  renameWorkspace: (name: string) => patch<{ name: string }>("/api/workspace", { name }),
  setRole: (id: number, role: Role) => patch<{ ok: boolean }>(`/api/workspace/members/${id}`, { role }),
  removeMember: (id: number) => del<{ ok: boolean }>(`/api/workspace/members/${id}`),
  invite: (email: string, role: Role) => post<CreatedInvite>("/api/workspace/invites", { email, role }),
  revokeInvite: (id: number) => del<{ ok: boolean }>(`/api/workspace/invites/${id}`),
  audit: () => request<AuditEntry[]>("/api/workspace/audit?limit=100"),

  rules: () => request<RuleSummary[]>("/api/rules"),
  rule: (id: string) => request<RuleDetail>(`/api/rules/${path(id)}`),
  stats: () => request<Stats>("/api/stats"),
  validate: (rule: string, cases: string | null, rulePath: string | null, signal?: AbortSignal) =>
    post<Validation>("/api/validate", { rule, cases, path: rulePath }, signal),
  impact: (rule: string, rulePath: string | null, signal?: AbortSignal) => post<Impact>("/api/impact", { rule, path: rulePath }, signal),

  github: () => request<GitHubStatus>("/api/github"),
  activity: (refresh = false) => request<Activity>(`/api/github/activity${refresh ? "?refresh=true" : ""}`),
  submitRule: (body: { path: string; rule: string; cases: string | null; title: string | null }) => post<Submission>("/api/ci/rules", body),
  submitConfig: (body: { text: string; title: string | null }) => post<Submission>("/api/ci/config", body),
  ciStatus: (commit: string) => request<CiStatus>(`/api/ci/status?commit=${encodeURIComponent(commit)}`),
  openPullRequest: (body: { branch: string; commit: string; title: string | null }) => post<PullRequest>("/api/pull-requests", body),

  targets: () => request<Target[]>("/api/targets"),
  config: () => request<ConfigView>("/api/config"),
  validateConfig: (text: string, signal?: AbortSignal) => post<ConfigCheck>("/api/config/validate", { text }, signal),

  quality: () => request<QualityReport>("/api/quality"),
  qualityRule: (id: string) => request<QualityRule>(`/api/quality/${path(id)}`),
  tests: () => request<TestSuites>("/api/tests"),
  coverage: () => request<Coverage>("/api/coverage"),
  history: () => request<History>("/api/history"),
  ruleHistory: (id: string) => request<RuleHistory>(`/api/history/${path(id)}`),
  datasets: () => request<Dataset[]>("/api/datasets"),
  runDataset: (name: string) => request<ReplayResult>(`/api/datasets/${path(name)}/replay`),
  replay: (events: string, rule?: string) => post<ReplayResult>("/api/replay", { events, rule: rule ?? null }),
};
