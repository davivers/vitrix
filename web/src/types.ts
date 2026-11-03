// Formatos devolvidos pela API (src/vitrix/service.py). Mantidos à mão por enquanto;
// o passo seguinte é gerar a partir do OpenAPI da API.

export type State = "ok" | "warn" | "fail";

// Como a linguagem final foi decidida: na regra, numa rota do vitrix.yml, no default_target ou "todos os alvos".
export type TargetSource = "rule" | "route" | "default" | "all" | "override";

export interface RuleSummary {
  id: string; // caminho dentro de rules/, usado nas URLs
  file: string;
  sigma_id: string;
  title: string;
  status: string | null;
  level: string | null;
  description: string;
  tags: string[];
  tactics: string[];
  techniques: string[];
  targets: string[]; // linguagem(ns) final(is)
  target_source: TargetSource | null;
  conversion: Record<string, boolean>; // a conversão da linguagem final funcionou?
  state: State;
  error?: string;
  issues: LintIssue[]; // até 3 pendências, erros primeiro
  lint: { errors: number; warnings: number };
  tests: { total: number; passed: number };
}

export interface LintIssue {
  severity: "error" | "warning";
  message: string;
}

export interface Conversion {
  ok: boolean;
  label: string;
  extension?: string;
  query?: string;
  error?: string;
}

export interface CaseResult {
  name: string;
  expect: string;
  got: string | null;
  passed: boolean;
  error: string | null;
  kind: CaseKind;
  exercises_filter: boolean; // no_match que só não disparou por causa de uma exclusão
}

export type CaseKind = "positive" | "negative" | "false_positive" | "edge";

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

// ---------------------------------------------------------------- fluxo e quality gate

export type StageId = "write" | "validate" | "test" | "replay" | "analyze" | "gate" | "deploy";
export type StageState = "ok" | "warn" | "fail" | "skip" | "pending";

export interface GateCheck {
  id: string;
  stage: StageId;
  question: 1 | 2 | 3 | 4 | 5;
  label: string;
  passed: boolean | null; // null = não se aplica
  blocking: boolean;
  detail: string;
}

export interface RuleQuality {
  ready: boolean;
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
  summary: { total: number; ready: number; blocked: number };
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

export interface Coverage {
  tactics: CoverageTactic[];
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

export interface RuleDetail {
  id: string;
  file: string;
  text: string;
  summary: Omit<RuleSummary, "id" | "file" | "state" | "lint" | "tests">;
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
  rules: { total: number; by_status: Record<string, number>; by_level: Record<string, number>; by_state: Record<string, number> };
  mitre: { tactics: Tactic[]; coverage_pct: number; covered: number; total: number; techniques: number; uncovered: string[] };
  lint: { errors: number; warnings: number };
  tests: { total: number; passed: number; rules_without_cases: number; rules_all_passing: number };
  targets: string[];
  by_target: Record<string, number>;
  conversion_failures: number;
}

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

/** Dados do conector do GitHub. Sem conexão, `available: false` e nenhum número. */
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
  extra_pipelines: string[];
  require_cases: boolean;
  github: { repo: string; base: string; path: string } | null;
}

export interface ConfigCheck {
  ok: boolean;
  errors: string[];
  warnings: string[];
  config: Omit<ConfigView, "path" | "text"> | null;
}

export interface GitHubStatus {
  configured: boolean; // seção github no vitrix.yml
  repo: string | null;
  base: string | null;
  token: boolean; // há token no ambiente do `vitrix serve` (o valor nunca sai do servidor)
}

export interface PullRequest {
  url: string;
  number: number;
  branch: string;
  commit: string;
  title: string;
  files: string[];
  is_new: boolean;
  state: State;
}
