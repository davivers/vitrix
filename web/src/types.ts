// Shapes returned by the API (src/vitrix/service.py, flow.py, history.py, github.py).
// Hand-maintained for now; the next step is generating them from the API's OpenAPI schema.

export type State = "ok" | "warn" | "fail";

// How the final language was chosen: in the rule, a vitrix.yml route, default_target or "all targets".
export type TargetSource = "rule" | "route" | "default" | "legacy-config" | "all" | "override";

/** Resolved final language (E1): order rule > folder > workspace > legacy vitrix.yml > all. */
export interface FinalLanguage {
  targets: string[];
  source: "rule" | "folder" | "workspace" | "legacy-config" | "all" | "override";
  folder: string | null;
}

/** Contract B3: where (path/line/column) and how to fix (hint, snippet). All new fields are optional. */
export interface LintIssue {
  severity: "error" | "warning" | "info";
  message: string;
  rule?: string;
  file?: string | null; // "rule" | "cases": which editor tab the line refers to
  code?: string;
  path?: string | null;
  line?: number | null; // 1-based
  column?: number | null; // 1-based
  hint?: string | null;
  /** `kind`/`key`/`suggestion`/`table`/`fields` drive the inline KQL fix form (E1 contract, provisional until posted). */
  fix?: { replace_path?: string; snippet?: string; kind?: string; key?: string; suggestion?: string; table?: string; field?: string; fields?: string[] } | null;
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
  publication?: Publication;
}

export interface Conversion {
  ok: boolean;
  issues?: LintIssue[];
  label: string;
  extension?: string;
  query?: string;
  error?: string;
  /** Flat issue fields of a failed conversion (E1): code, hint, fix, position, `final` = it is the rule's final language. */
  code?: string;
  hint?: string | null;
  fix?: LintIssue["fix"];
  line?: number | null;
  column?: number | null;
  path?: string | null;
  final?: boolean;
  severity?: "error" | "warning" | "info";
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
  final_language?: FinalLanguage;
  /** errors include final-language conversion failures; info = preview-language failures. */
  counts?: { errors: number; warnings: number; info: number };
  preview_issues?: LintIssue[];
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
  sha?: string;
  cases_sha?: string | null;
  publication?: Publication;
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
  base?: string;
  against_base?: boolean;
  fork?: boolean;
}

/** GitHub connector data. Without a connection, `available: false` and no numbers. */
export type Activity =
  | { available: false; reason: "not_configured" | "no_token" | "error"; message: string }
  | {
      available: true;
      fetched_at: string;
      repo: { name: string; url: string; default_branch: string; private: boolean; base: string };
      head: { sha: string; message: string; author: string | null; date: string | null; url: string };
      pulls: { open: number; failing: number; from_vitrix: number; against_base?: number; items: OpenPull[] };
      merge: { sample: number; median_hours: number | null; p90_hours: number | null };
      ci: { runs: CiRun[]; sample: number; success_rate: number | null; last: CiRun | null };
    };

export interface GitHubStatus {
  configured: boolean; // github section in vitrix.yml, or detected from `git remote origin`
  source: "vitrix.yml" | "git remote" | null;
  repo: string | null;
  base: string | null;
  workflow: string | null;
  token: boolean; // a token exists for `vitrix serve` (its value never leaves the server)
  token_source: string | null; // VITRIX_GITHUB_TOKEN, GITHUB_TOKEN or "gh CLI"
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
  mappings_included?: boolean;
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
  backend?: string;
  plugin?: string;
  status?: "ok" | "missing_plugin" | "error";
  message?: string | null;
  used_by?: number;
  default?: boolean;
}

export interface ConfigView {
  path: string | null;
  file?: string | null; // absolute path of the vitrix.yml in use (B4)
  loaded_at?: string | number | null; // hot reload (B4)
  reload_error?: string | null; // the last reload failed; the previous config stays active
  restart_required?: string[]; // changed keys that only apply after a restart
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
  techniques: { id: string; name?: string; rules: { id: string; title: string; state: State; level: string | null }[] }[];
}

/** Local MITRE ATT&CK catalogue (S7): tactics matched by TA id, techniques reference tactic ids. */
export interface AttackCatalog {
  version: string;
  source?: string;
  url?: string;
  tactics: { id: string; name: string; order: number }[];
  techniques: { id: string; name: string; tactics: string[]; parent?: string | null }[];
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
  catalog?: AttackCatalog | null;
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
  | { available: false; reason: string; state?: "no_commits" | "not_a_repo" | "git_missing" | "error"; message?: string }
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

export type RuleHistory = { available: false; reason: string; state?: string; message?: string } | ({ available: true; tracked: boolean } & Partial<RuleHistoryInfo>);

// ---------------------------------------------------------------- accounts and workspace

export type Role = "viewer" | "editor" | "admin" | "owner";

export interface AuthConfig {
  enabled: boolean;
  workspace?: string;
  bootstrap?: boolean; // no account yet: the first one becomes the owner
  registration?: "owner-bootstrap" | "invite-only"; // who may create an account without an invite
  github?: boolean; // GitHub sign-in is configured on the server
  setup_token_required?: boolean; // no account yet and the server printed a setup link (VITRIX_BOOTSTRAP_TOKEN)
  enabled_source?: "env" | "config" | "default";
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

/** G1: dataset picker entry for the Editor Replay panel. */
export interface ReplayDatasetInfo {
  name: string;
  events: number | null;
  size: number;
  error: string | null;
  has_expectations: boolean;
  expect_error: string | null;
}

export interface DraftReplayDataset {
  dataset: string;
  events: number;
  matches: number;
  duration_ms: number;
  expectation: { min: number; max: number | null } | null;
  passed: boolean | null;
  message: string | null;
  error: ReplayError | null;
  error_text?: string | null;
  truncated: boolean;
  sample: { index: number; event: Record<string, unknown> }[];
  before?: number | null;
  added?: { index: number; event: Record<string, unknown> }[];
  removed?: { index: number; event: Record<string, unknown> }[];
}

export interface ReplayError {
  code: string;
  message: string;
  hint?: string | null;
  dataset?: string;
}

export interface ReplaySelection {
  name: string;
  exclusion: boolean;
  matched: boolean;
  fields: { field: string; expected: unknown; actual: unknown; present: boolean; matched: boolean }[];
}

export interface ReplayCase {
  name: string;
  kind: string;
  expected: string;
  matched: boolean | null;
  passed: boolean;
  hint?: string | null;
  event?: Record<string, unknown> | null;
  error: ReplayError | null;
  selections?: ReplaySelection[];
}

export interface DraftReplay {
  rule: string;
  duration_ms: number;
  passed: boolean;
  errors: number;
  saved?: boolean | null;
  cases?: ReplayCase[];
  cases_passed?: boolean | null;
  case_problems?: { severity: string; code?: string; message: string; hint?: string | null; line?: number | null }[];
  datasets: DraftReplayDataset[];
}

/** G4: local drafts (`/api/drafts`). */
export interface DraftSummary {
  id: string;
  path: string | null;
  title: string;
  author: { id: number; email: string; name: string } | null;
  created_at: string;
  updated_at: string;
  version: number;
  stale: boolean;
  mine: boolean;
  quality?: { ready: boolean; blockers: number; score: number | null } | null;
  level?: string | null;
  target?: string | null;
}

export interface Draft extends DraftSummary {
  rule: string;
  cases: string | null;
  base_hash: string | null;
}

export interface DraftList {
  enabled: boolean;
  reason: string | null;
  drafts: DraftSummary[];
}

export interface DraftBody {
  path: string | null;
  title: string | null;
  rule: string;
  cases: string | null;
}

// ── S9 drift ────────────────────────────────────────────────────────────────────────────────────────────
export type DriftState = "more" | "fewer" | "added" | "removed" | "same";

export interface DriftRuleRow {
  rule: string;
  title: string;
  before: number | null; // null = not at the ref
  after: number | null; // null = removed
  delta: number;
  state: DriftState;
  error?: string | null;
}

export interface DriftReport {
  ref: string;
  sha: string;
  summary: { more: number; fewer: number; added: number; removed: number; same: number; modified: number; drifted: number };
  rules: (DriftRuleRow & { modified: boolean; datasets_changed: number })[];
  datasets: { dataset: string; events: number; error?: string | null; rules: DriftRuleRow[] }[];
}

// ── S6 content packs ────────────────────────────────────────────────────────────────────────────────────
export interface PackSources {
  enabled: boolean;
  reason: string | null;
  sources: { id: string; name: string; url: string; license: string; refs: string[]; cached: { ref: string; size: number; sha256: string; fetched_at: string }[] }[];
  limits: { max_rules: number; drafts_free: number | null };
}

export interface PackFilters {
  product: string | null;
  category: string | null;
  service: string | null;
  statuses: string[];
  text: string | null;
}

export interface PackJobBody {
  mode: "preview" | "import";
  source: string;
  ref: string;
  refresh?: boolean;
  filters: PackFilters;
  into: string;
  paths: string[] | null;
  include_untested?: boolean;
  owner?: string | null;
}

export interface PackItem {
  path: string;
  title: string;
  level: string | null;
  status: string | null;
  logsource: string | null;
  cases: number;
  state: "ready" | "untested";
  reason: string | null;
  exists: boolean;
  rule?: string | null;
  draft_id?: string | null;
}

export type PackJobState = "queued" | "downloading" | "scanning" | "importing" | "done" | "failed";

export interface PackJob {
  id: string;
  mode: "preview" | "import";
  state: PackJobState;
  progress: { bytes: number; total: number | null; scanned: number; matched: number; imported: number };
  error: string | null;
  created_at: string;
  finished_at: string | null;
  result: null | { matched: number; items: PackItem[]; skipped: { path: string; reason: string }[] };
}

export interface BlockedDraft {
  id: string;
  path: string | null;
  reasons: string[];
}

// ── S8 reviews and comments ─────────────────────────────────────────────────────────────────────────────
export type ReviewState = "pending" | "approved" | "changes_requested" | "cancelled";
export interface PersonRef {
  id: number;
  email: string;
  name: string;
}

export interface Review {
  id: string;
  target: { kind: "rule" | "draft"; ref: string; title: string; missing: boolean };
  requester: PersonRef;
  reviewer: PersonRef;
  note: string | null;
  state: ReviewState;
  decision_note: string | null;
  created_at: string;
  updated_at: string;
  decided_at: string | null;
  version: number;
  stale: boolean;
  mine_to_review: boolean;
  mine_requested: boolean;
  governance: { owner: string | null; review_by: string | null; review_state: string | null } | null;
  /** U10 (backend, provisional until posted): unread mark, request snapshot and timeline. */
  unread?: boolean;
  snapshot?: { changed_lines: number | null; added: number; removed: number; stale: boolean } | null;
  snapshot_text?: string | null;
  base_text?: string | null;
  current_text?: string | null;
  diff_too_large?: boolean;
  events?: { id?: number; type: string; actor?: { id: number; name: string } | null; text?: string | null; at: string }[];
}

export interface ReviewComment {
  id: string;
  target: { kind: "rule" | "draft"; ref: string };
  review_id: string | null;
  author: PersonRef;
  body: string;
  deleted: boolean;
  created_at: string;
  edited_at: string | null;
  outdated: boolean;
  mine: boolean;
}

export interface ReviewList {
  enabled: boolean;
  reason: string | null;
  reviews: Review[];
}

export interface CommentList {
  enabled: boolean;
  reason: string | null;
  comments: ReviewComment[];
}

export interface ReviewCounts {
  enabled: boolean;
  to_review: number;
  requested: number;
  unread?: number;
  latest?: { id: string; title: string; requester?: string; actor?: string; kind?: "assigned" | "decided"; state?: string }[];
}

export interface Reviewer {
  id: number;
  email: string;
  name: string;
  role: Role;
}

// ---------------------------------------------------------------- GitHub sync (ADR 0006)

export interface SyncStatus {
  enabled: boolean;
  reason: string | null;
  state: "synced" | "behind" | "ahead" | "diverged" | "no_remote" | "no_commits" | "not_a_repo" | "disabled" | "error";
  branch: string | null;
  base: string | null;
  on_base: boolean;
  head: string | null;
  remote_head: string | null;
  behind: number;
  ahead: number;
  fetching: boolean;
  last_fetch: string | null;
  last_attempt: string | null;
  next_fetch_in: number;
  last_error: string | null;
  blocked: string | null;
  conflicts: { path: string; rule: string | null; reason: string }[];
  incoming_rules: { rule: string; change: "added" | "modified" | "deleted" }[];
  changed_rules: { rule: string; change: "added" | "modified" | "deleted" }[];
  last_pull: string | null;
  config_changed: boolean;
}

/** `publication` on rule rows (ADR 0007). */
export interface Publication {
  state: "published" | "local" | "pushed" | "in_pr" | "unknown";
  change: "added" | "modified" | null;
  git: "untracked" | "modified" | "committed" | "clean" | null;
  branch: string | null;
  pr: { number: number; url: string } | null;
  base_ref: string | null;
  reason: string | null;
}

export interface RelatedRule {
  id: string;
  title: string;
  file: string;
  logsource: string | null;
  shared_fields: string[];
  same_logsource: boolean;
  level: string | null;
}

/** Final-language defaults kept in mappings.yml (Sprint 5 addendum, provisional shape). */
export interface FinalLanguageCfg {
  default: string | null;
  folders: Record<string, string>;
}

export interface FinalLanguagePatch {
  default?: string | null;
  folders?: Record<string, string | null>;
}

/** Merge-patch for PUT /api/mappings: `null` removes an entry, absent keys stay. */
export interface MappingsPatch {
  tables?: Record<string, string | null>;
  fields?: Record<string, Record<string, string | null> | null>;
}

/** `mappings.yml` (E1): KQL table per product/service and field -> column per table. */
export interface MappingsView {
  schema_version: number;
  kql: { tables: Record<string, string>; fields: Record<string, Record<string, string>> };
  final_language?: FinalLanguageCfg;
  sha?: string | null;
  file?: string | null;
  publication?: Publication | null;
}
