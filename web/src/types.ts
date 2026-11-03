// Shapes returned by the API (src/vitrix/service.py, flow.py, history.py, github.py).
// Hand-maintained for now; the next step is generating them from the API's OpenAPI schema.

export type State = "ok" | "warn" | "fail";

// How the final language was chosen: in the rule, a vitrix.yml route, default_target or "all targets".
export type TargetSource = "rule" | "route" | "default" | "all" | "override";

export interface LintIssue {
  severity: "error" | "warning";
  message: string;
}

export interface RuleSummary {
  id: string; // path inside rules/, used in URLs
  file: string;
  sigma_id: string;
  title: string;
  status: string | null;
  level: string | null;
  description: string;
  tags: string[];
  tactics: string[];
  techniques: string[];
  logsource: string | null;
  targets: string[]; // final query language(s)
  target_source: TargetSource | null;
  conversion: Record<string, boolean>; // did the final-language conversion work?
  state: State;
  error?: string;
  issues: LintIssue[]; // up to 3 problems, errors first
  lint: { errors: number; warnings: number };
  tests: { total: number; passed: number };
}

export interface Conversion {
  ok: boolean;
  label: string;
  extension?: string;
  query?: string;
  error?: string;
}

export type CaseKind = "positive" | "negative" | "false_positive" | "edge";

export interface CaseResult {
  name: string;
  expect: string;
  got: string | null;
  passed: boolean;
  error: string | null;
  kind: CaseKind;
  exercises_filter: boolean; // no_match that only did not fire because of an exclusion
  event: Record<string, unknown> | null; // the sample event that was tested
}

export interface TestReport {
  results: CaseResult[];
  problems: LintIssue[];
}

export interface Validation {
  state: State;
  targets: string[];
  target_source: TargetSource | null;
  lint: LintIssue[];
  conversions: Record<string, Conversion>;
  tests: TestReport | null;
  quality?: DraftQuality;
}

export interface RuleDetail {
  id: string;
  file: string;
  text: string;
  summary: Omit<RuleSummary, "id" | "file" | "state" | "lint" | "tests" | "issues" | "logsource" | "targets" | "target_source" | "conversion">;
  state: State;
  targets: string[];
  target_source: TargetSource | null;
  lint: LintIssue[];
  conversions: Record<string, Conversion>;
  tests: TestReport & { cases_file: string | null; cases_text: string | null };
}

export interface Tactic {
  slug: string;
  id: string; // TA0002
  name: string;
  count: number;
}

export interface Stats {
  pipeline: {
    parse: { ok: number; failed: number };
    validation: Record<State, number>;
    conversion: { ok: number; failed: number };
  };
  rules: {
    total: number;
    by_status: Record<string, number>;
    by_level: Record<string, number>;
    by_state: Record<string, number>;
    by_logsource: Record<string, number>;
  };
  mitre: { tactics: Tactic[]; coverage_pct: number; covered: number; total: number; techniques: number; uncovered: string[] };
  lint: { errors: number; warnings: number };
  tests: { total: number; passed: number; rules_without_cases: number; rules_all_passing: number };
  targets: string[];
  by_target: Record<string, number>;
  conversion_failures: number;
}

// ---------------------------------------------------------------- GitHub

export type RunState = "success" | "failure" | "pending";

export interface CiRun {
  id: number;
  number: number;
  name: string;
  title: string;
  state: RunState | null;
  conclusion: string | null;
  sha: string;
  created_at: string;
  duration_s: number | null;
  url: string;
}

export interface OpenPull {
  number: number;
  title: string;
  author: string | null;
  url: string;
  branch: string;
  draft: boolean;
  created_at: string;
  age_hours: number | null;
  ci: RunState | null;
  from_vitrix: boolean;
}

/** GitHub connector data. Without a connection, `available: false` and no numbers. */
export type Activity =
  | { available: false; reason: "not_configured" | "no_token" | "error"; message: string }
  | {
      available: true;
      fetched_at: string;
      repo: { name: string; url: string; default_branch: string; private: boolean; base: string };
      head: { sha: string; message: string; author: string | null; date: string | null; url: string };
      pulls: { open: number; failing: number; from_vitrix: number; items: OpenPull[] };
      merge: { sample: number; median_hours: number | null; p90_hours: number | null };
      ci: { runs: CiRun[]; sample: number; success_rate: number | null; last: CiRun | null };
    };

export interface GitHubStatus {
  configured: boolean; // github section in vitrix.yml
  repo: string | null;
  base: string | null;
  workflow: string | null;
  token: boolean; // a token exists in the environment of `vitrix serve` (its value never leaves the server)
}

/** Step 1: the change was pushed to a branch so the real CI validates it. */
export interface Submission {
  branch: string;
  commit: string;
  base: string;
  base_commit: string;
  url: string;
  title: string;
  files: string[];
  is_new: boolean;
}

export type CiState = "none" | "pending" | "failure" | "success";

export interface CiStatus {
  commit: string;
  state: CiState;
  runs: CiRun[];
  workflow: string | null;
}

/** Step 2: opened only after CI passed for the exact commit. */
export interface PullRequest {
  url: string;
  number: number;
  branch: string;
  commit: string;
  ci: CiStatus;
}

// ---------------------------------------------------------------- configuration

export interface Target {
  name: string;
  label: string;
  extension: string;
  active: boolean;
}

export interface ConfigView {
  path: string | null;
  text: string;
  targets: string[];
  default_target: string | null;
  routes: { match: string; target: string[] }[];
  rules_dir: string;
  cases_dir: string;
  output_dir: string;
  datasets_dir: string | null;
  extra_pipelines: string[];
  require_cases: boolean;
  quality_gate: Record<string, unknown>;
  github: { repo: string; base: string; path: string; workflow: string | null } | null;
}

export interface ConfigCheck {
  ok: boolean;
  errors: string[];
  warnings: string[];
  config: Omit<ConfigView, "path" | "text"> | null;
}

// ---------------------------------------------------------------- lifecycle and quality gate

export type StageId = "write" | "validate" | "test" | "replay" | "analyze" | "gate" | "deploy";
export type StageState = "ok" | "warn" | "fail" | "skip" | "pending";

export interface GateCheck {
  id: string;
  stage: StageId;
  question: 1 | 2 | 3 | 4 | 5;
  label: string;
  passed: boolean | null; // null = not applicable
  blocking: boolean;
  detail: string;
}

export interface RuleQuality {
  ready: boolean;
  score: number; // health 0–100
  min_score: number; // score required for approval (0 = no threshold)
  stages: Record<StageId, StageState>;
  checks: GateCheck[];
  blockers: string[];
  answers: Record<string, StageState>;
}

export interface DraftQuality extends RuleQuality {
  datasets: { dataset: string; events?: number; matches?: number; duration_ms?: number; error?: string | null }[];
}

export interface QualityRule extends RuleQuality {
  id: string;
  file: string;
  title: string;
  level: string | null;
  status: string | null;
  age_days: number | null;
}

export interface DatasetSummary {
  dataset: string;
  events: number;
  duration_ms?: number;
  rules_matched: number;
  passed: boolean;
  has_expectations?: boolean;
  checks: ReplayCheck[];
  error?: string;
}

export interface QualityReport {
  summary: { total: number; ready: number; blocked: number; health: number | null; stale: number };
  stages: { id: StageId; label: string; counts: Partial<Record<StageState, number>> }[];
  questions: { id: number; text: string; counts: Partial<Record<StageState, number>> }[];
  gate: Record<string, unknown>;
  datasets: DatasetSummary[];
  rules: QualityRule[];
}

export interface SuiteRule {
  id: string;
  file: string;
  title: string;
  level: string | null;
  results: CaseResult[];
  problems: LintIssue[];
}

export interface TestSuites {
  duration_ms: number;
  total: number;
  passed: number;
  by_kind: Record<CaseKind, { total: number; passed: number }>;
  rules: SuiteRule[];
  broken: { file: string; error: string }[];
}

export interface CoverageTactic {
  slug: string;
  id: string;
  name: string;
  rules: number;
  techniques: { id: string; rules: { id: string; title: string; state: State; level: string | null }[] }[];
}

export interface LogsourceCoverage {
  logsource: string;
  product: string | null;
  rules: number;
  techniques: string[];
  tactics: string[];
}

export interface Coverage {
  tactics: CoverageTactic[];
  logsources: LogsourceCoverage[];
  unmapped: { id: string; title: string }[];
  techniques: number;
  covered: number;
  total: number;
}

export interface Dataset {
  name: string;
  size: number;
  expectations: number;
  others: number | null;
  expect_error: string | null;
}

export interface ReplayRule {
  rule: string;
  title: string;
  level: string | null;
  matches: number;
  sample: number[];
  duration_ms: number;
  error: string | null;
}

export interface ReplayCheck {
  rule: string;
  expected: { min: number; max: number | null };
  got: number | null;
  passed: boolean;
  message: string | null;
}

export interface ReplayResult {
  events: number;
  duration_ms: number;
  rules_matched: number;
  rules: ReplayRule[];
  dataset?: string;
  checks?: ReplayCheck[];
  passed?: boolean;
  has_expectations?: boolean;
}

export interface Impact {
  rule: string | null;
  saved: boolean;
  changed: boolean;
  datasets: {
    dataset: string;
    events?: number;
    before?: number | null;
    after?: number;
    added?: number[];
    removed?: number[];
    error?: string | null;
    expected?: { min: number; max: number | null } | null;
    meets_expectation?: boolean | null;
  }[];
}

// ---------------------------------------------------------------- Git history

export interface HistoryCommit {
  sha: string;
  date: string;
  author: string;
  subject: string;
  files: { status: string; path: string }[];
  more_files: number;
}

export interface RuleLogEntry {
  sha: string;
  date: string;
  author: string;
  subject: string;
  change: "created" | "modified";
}

export interface RuleHistoryInfo {
  created: string;
  created_by: string;
  modified: string;
  modified_by: string;
  commits: number;
  authors: string[];
  log: RuleLogEntry[];
  age_days: number;
  deleted: boolean;
}

export type History =
  | { available: false; reason: string }
  | {
      available: true;
      head: string;
      commits: number;
      truncated: boolean;
      timeline: { date: string; sha: string; rules: number; tactics: number; techniques: number }[];
      weekly: { week: string; commits: number }[];
      activity: HistoryCommit[];
      rules: Record<string, RuleHistoryInfo>;
      authors: { name: string; commits: number; rules_created?: number; rules_changed?: number; rules_deleted?: number }[];
    };

export type RuleHistory = { available: false; reason: string } | ({ available: true; tracked: boolean } & Partial<RuleHistoryInfo>);

// ---------------------------------------------------------------- accounts and workspace

export type Role = "viewer" | "editor" | "admin" | "owner";

export interface AuthConfig {
  enabled: boolean;
  workspace?: string;
  bootstrap?: boolean; // no account yet: the first one becomes the owner
  allow_signup?: boolean;
  github?: boolean; // GitHub sign-in is configured on the server
}

export interface UserInfo {
  id: number;
  email: string;
  name: string;
  role: Role;
  github_login: string | null;
  avatar_url: string | null;
}

export interface Me {
  enabled: boolean;
  authenticated: boolean;
  user: UserInfo | null;
  workspace: string | null;
  can: Partial<Record<Role, boolean>>;
}

export interface Member {
  id: number;
  email: string;
  name: string;
  github_login: string | null;
  avatar_url: string | null;
  last_login: number | null;
  role: Role;
  joined_at: number;
  has_password: boolean;
}

export interface Invite {
  id: number;
  email: string;
  role: Role;
  created_at: number;
  expires_at: number;
}

export interface WorkspaceInfo {
  name: string;
  role: Role;
  member_count: number;
  members?: Member[]; // admins only
  invites?: Invite[];
}

export interface CreatedInvite {
  link: string; // shown once; only its hash is stored
  email: string;
  role: Role;
  expires_in_days: number;
}

export interface AuditEntry {
  ts: number;
  actor: string;
  action: string;
  detail: string;
}
