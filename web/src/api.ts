import { t } from "./i18n";
import type {
  Activity,
  AuditEntry,
  AuthConfig,
  CreatedInvite,
  Me,
  Role,
  WorkspaceInfo,
  CiStatus,
  CommentList,
  ConfigCheck,
  ConfigView,
  Coverage,
  Draft,
  DraftBody,
  DraftList,
  DraftReplay,
  DriftReport,
  ReplayDatasetInfo,
  GitHubStatus,
  History,
  Impact,
  PackJob,
  PackJobBody,
  PackSources,
  PullRequest,
  QualityReport,
  QualityRule,
  ReplayResult,
  Review,
  ReviewComment,
  ReviewCounts,
  ReviewList,
  Reviewer,
  RuleDetail,
  RuleHistory,
  RuleSummary,
  Stats,
  Submission,
  Target,
  TestSuites,
  Validation,
} from "./types";

export class ApiError extends Error {
  status: number;
  /** Extra JSON fields of the error body (e.g. `blocked` on a 422 from /api/ci/drafts). */
  body: Record<string, unknown> | null;
  constructor(message: string, status: number, body: Record<string, unknown> | null = null) {
    super(message);
    this.status = status;
    this.body = body;
  }
}

/** Build-time switch (ADR 0003): a static read-only demo served from captured fixtures. */
export const DEMO = import.meta.env.VITE_DEMO === "1";
const FIXTURES = `${import.meta.env.BASE_URL}fixtures/`;
let manifest: Promise<{ routes: Record<string, string> }> | null = null;

async function fixture<T>(file: string): Promise<T> {
  const res = await fetch(FIXTURES + file);
  if (!res.ok) throw new ApiError(t("demo_unavailable"), 404);
  return res.json() as Promise<T>;
}

async function sha256(text: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// Local single-user session: with accounts off the real API answers the same.
const DEMO_ME = { enabled: false, authenticated: true, user: null, workspace: null, can: { viewer: true, editor: true, admin: true, owner: true } };
const DEMO_COMPUTE = new Set(["/api/validate", "/api/impact", "/api/replay/draft"]);

async function demoRequest<T>(url: string, init?: RequestInit): Promise<T> {
  manifest ??= fetch(`${FIXTURES}manifest.json`).then((r) => {
    if (!r.ok) throw new ApiError(t("demo_unavailable"), 404);
    return r.json();
  });
  const { routes } = await manifest;
  const method = (init?.method ?? "GET").toUpperCase();
  if (method === "GET") {
    const file = routes[`GET ${url}`];
    if (file) return fixture<T>(file);
    if (url === "/api/auth/me") return DEMO_ME as T;
    throw new ApiError(t("demo_unavailable"), 404);
  }
  // Compute endpoints answer from a fixture only while the rule text equals the captured one.
  const [route] = url.split("?");
  if (DEMO_COMPUTE.has(route) && typeof init?.body === "string") {
    const body = JSON.parse(init.body) as { rule?: string; path?: string | null };
    const file = routes[`POST ${route}#${body.path ?? ""}`];
    if (file && typeof body.rule === "string") {
      const wrapped = await fixture<{ rule_sha256: string; body: T }>(file);
      if (wrapped.rule_sha256 === (await sha256(body.rule))) return wrapped.body;
    }
    throw new ApiError(t("demo_edited"), 403);
  }
  throw new ApiError(t("demo_readonly"), 403); // never dispatches vitrix:forbidden
}

export async function request<T>(url: string, init?: RequestInit): Promise<T> {
  if (DEMO) return demoRequest<T>(url, init);
  let res: Response;
  try {
    res = await fetch(url, init);
  } catch (e) {
    if ((e as Error).name === "AbortError") throw e;
    throw new ApiError("Cannot reach the API. Is `vitrix serve` running?", 0);
  }
  // 403 = the role changed (or never allowed this): refresh /api/me so the UI adapts. Never treated as logged out.
  if (res.status === 403 && !url.startsWith("/api/auth/")) window.dispatchEvent(new Event("vitrix:forbidden"));
  if (res.status === 401 && !url.startsWith("/api/auth/")) window.dispatchEvent(new Event("vitrix:unauthorized")); // session expired or revoked
  if (!res.ok) {
    let detail = `${res.status} ${res.statusText}`;
    let extra: Record<string, unknown> | null = null;
    try {
      const body = await res.json();
      if (typeof body.detail === "string") detail = body.detail;
      else if (Array.isArray(body.detail)) detail = body.detail.map((d: { msg: string }) => d.msg).join("; ");
      extra = body;
    } catch {
      /* body is not JSON */
    }
    throw new ApiError(detail, res.status, extra);
  }
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

const path = (id: string) => id.split("/").map(encodeURIComponent).join("/");

function post<T>(url: string, body: unknown, signal?: AbortSignal): Promise<T> {
  return request<T>(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body), signal });
}

function del<T>(url: string): Promise<T> {
  return request<T>(url, { method: "DELETE" });
}

function put<T>(url: string, body: unknown): Promise<T> {
  return request<T>(url, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
}

function patch<T>(url: string, body: unknown): Promise<T> {
  return request<T>(url, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
}

/** Text endpoints (reports): same demo handling as request(). */
async function requestText(url: string): Promise<string> {
  if (DEMO) {
    const body = await demoRequest<unknown>(url);
    return typeof body === "string" ? body : JSON.stringify(body, null, 2);
  }
  const res = await fetch(url).catch(() => {
    throw new ApiError("Cannot reach the API. Is `vitrix serve` running?", 0);
  });
  if (!res.ok) throw new ApiError(`${res.status} ${res.statusText}`, res.status);
  return res.text();
}

export const api = {
  report: (format: "md" | "json") => requestText(`/api/report?format=${format}`),
  // accounts and workspace
  health: () => request<{ version: string }>("/api/health"),
  authConfig: () => request<AuthConfig>("/api/auth/config"),
  me: () => request<Me>("/api/auth/me"),
  login: (email: string, password: string) => post<Me>("/api/auth/login", { email, password }),
  register: (body: { email: string; name: string; password: string; invite: string | null; setup_token?: string | null }) => post<Me>("/api/auth/register", body),
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
  submitRule: (body: { path: string; rule: string; cases: string | null; title: string | null; draft_id?: string | null }) => post<Submission>("/api/ci/rules", body),
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
  replayDatasets: () => request<ReplayDatasetInfo[]>("/api/replay/datasets"),
  replayDraft: (body: { rule: string; datasets?: string[]; path?: string | null }, signal?: AbortSignal) => post<DraftReplay>("/api/replay/draft", body, signal),

  drift: (ref: string | null, rule?: string | null) => {
    const q = new URLSearchParams();
    if (ref) q.set("ref", ref);
    if (rule) q.set("rule", rule);
    return request<DriftReport>(`/api/drift${q.size ? `?${q}` : ""}`);
  },

  packSources: () => request<PackSources>("/api/packs/sources"),
  startPackJob: (body: PackJobBody) => post<PackJob>("/api/packs/jobs", body),
  packJob: (id: string) => request<PackJob>(`/api/packs/jobs/${encodeURIComponent(id)}`),
  submitDrafts: (body: { draft_ids: string[]; title: string | null }) => post<Submission>("/api/ci/drafts", body),

  reviews: (q: { scope?: string; state?: string; kind?: string; ref?: string } = {}) => {
    const p = new URLSearchParams(Object.entries(q).filter((e): e is [string, string] => Boolean(e[1])));
    return request<ReviewList>(`/api/reviews${p.size ? `?${p}` : ""}`);
  },
  reviewCounts: () => request<ReviewCounts>("/api/reviews/counts"),
  reviewers: () => request<Reviewer[]>("/api/reviews/reviewers"),
  requestReview: (body: { target_kind: "rule" | "draft"; target_ref: string; reviewer_id: number; note: string | null }) => post<Review>("/api/reviews", body),
  decideReview: (id: string, body: { decision: "approved" | "changes_requested"; note: string | null; version: number }) => post<Review>(`/api/reviews/${encodeURIComponent(id)}/decision`, body),
  rerequestReview: (id: string, version: number) => post<Review>(`/api/reviews/${encodeURIComponent(id)}/rerequest`, { version }),
  cancelReview: (id: string, version: number) => post<Review>(`/api/reviews/${encodeURIComponent(id)}/cancel`, { version }),
  comments: (kind: string, ref: string) => request<CommentList>(`/api/comments?kind=${kind}&ref=${encodeURIComponent(ref)}`),
  addComment: (body: { target_kind: "rule" | "draft"; target_ref: string; body: string; review_id?: string | null }) => post<ReviewComment>("/api/comments", body),
  deleteComment: (id: string) => request<void>(`/api/comments/${encodeURIComponent(id)}`, { method: "DELETE" }),

  drafts: () => request<DraftList>("/api/drafts"),
  draft: (id: string) => request<Draft>(`/api/drafts/${encodeURIComponent(id)}`),
  createDraft: (body: DraftBody) => post<Draft>("/api/drafts", body),
  updateDraft: (id: string, body: DraftBody & { version: number }) => put<Draft>(`/api/drafts/${encodeURIComponent(id)}`, body),
  deleteDraft: (id: string) => request<void>(`/api/drafts/${encodeURIComponent(id)}`, { method: "DELETE" }),
  replay: (events: string, rule?: string) => post<ReplayResult>("/api/replay", { events, rule: rule ?? null }),
};
