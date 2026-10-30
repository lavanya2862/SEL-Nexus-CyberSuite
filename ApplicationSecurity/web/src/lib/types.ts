// Types for the Application Security API (/api/v1/*). Mirrors remediation/api.py and remediation/insights.py.

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'unknown'
export type JobStatus = 'queued' | 'running' | 'completed' | 'failed' | 'cancelled'
export type StageStatus = 'pending' | 'running' | 'completed' | 'warning' | 'failed' | 'skipped'
export type Verdict = 'passed' | 'flagged' | 'failed' | 'not_run'
export type FixStatus = 'verified' | 'fixed' | 'failed' | 'manual' | 'skipped' | 'not_attempted'
export type AgentId = 'analysis' | 'remediation' | 'validation' | 'reporting'

/** A signed-in person (email is null for the local user without the shared sign-in). */
export interface Person { email: string | null; name: string | null }

export interface JobSummary {
  findings?: number
  severity_counts?: Partial<Record<Severity, number>>
  fixes_applied?: number
  ai_fixes?: number
  verified_fixed?: number
  validation_status?: Verdict
  pull_request_url?: string | null
  pull_request_draft?: boolean
  approval_status?: 'awaiting_approval' | 'publishing' | 'pr_opened' | 'failed' | string
  publish_error?: string | null
  branch?: string | null
  tests?: TestLoop
  approved_by?: Person & { at: string }
  draft_reviewed_by?: Person
}

/** The Test & Fix loop on GitHub Actions (remediation/testloop.py), kept in the run's summary. */
export interface TestRun {
  n: number
  sha: string
  run_id?: number
  url?: string
  status: string
  conclusion: string | null
  failed: string[]
  started_at?: string
  finished_at?: string
  fix: { files: string[]; explanation: string; commit: string | null; touched_tests: boolean } | null
  fix_error?: string
}

export interface TestLoop {
  status: 'starting' | 'running' | 'passed' | 'failed' | 'no_tests' | 'error' | 'cancelled' | 'interrupted'
  phase?: string
  message?: string
  attempt: number
  max_attempts: number
  branch?: string
  branch_pushed?: boolean
  workflow?: string
  test_command?: string
  language?: string
  runs: TestRun[]
  started_at?: string
  finished_at?: string | null
  started_by?: Person | null
}

export interface Step { name: string; status: StageStatus; detail?: string }

export interface Stage {
  id: string
  name: string
  agent: string | null
  description: string
  status: StageStatus
  steps: Step[]
  metrics: Record<string, string | number | null>
  summary: string
  duration_seconds?: number | null
}

export interface Job {
  id: string
  repo_url: string
  repo: string
  ref: string | null
  commit: string | null
  status: JobStatus
  stage: string
  progress: number
  error: string | null
  summary: JobSummary | null
  attempts: number
  cached_from: string | null
  cancel_requested: boolean
  created_at: string | null
  started_at: string | null
  finished_at: string | null
  options?: Record<string, unknown>
  stages?: Stage[]
  artifacts?: { name: string; size: number; url: string }[]
  started_by?: Person | null
  /** Only the person who started a scan may act on it; everyone else can look and download. */
  can_act?: boolean
}

/** One line of the activity log: who did what, when, on which scan. */
export interface ActivityEntry {
  id: number
  ts: string
  email: string | null
  name: string | null
  action: string
  job_id: string | null
  repo: string | null
  detail: string
}

export interface KV { label: string; value: string; tone?: 'good' | 'warn' | 'bad' | '' }
export interface Learning { text: string; tone: 'good' | 'warn' | 'bad' | 'info' }

export interface AgentView {
  id: AgentId
  name: string
  role: string
  status: StageStatus
  duration: number | null
  summary: string
  inputs: KV[]
  outputs: KV[]
  learnings: Learning[]
  steps: Step[]
  contract_in: string[]
  contract_out: string[]
}

export interface Story {
  headline: string
  lines: string[]
  decision: { kind: 'approve' | 'flagged' | 'pr' | 'manual' | string; text: string; url?: string | null } | null
}

export interface Finding {
  finding_id: string
  title: string
  severity: Severity
  priority_score: number | null
  priority_rank: number | null
  priority_reasons?: string[]
  fix_status: FixStatus
  fix_note?: string | null
  scanner: string
  also_reported_by?: string[]
  category: string
  rule_id?: string | null
  cwe?: string[]
  advisory_id?: string | null
  aliases?: string[]
  file_path?: string | null
  line?: number | null
  end_line?: number | null
  package_name?: string | null
  installed_version?: string | null
  fixed_version?: string | null
  ecosystem?: string | null
  description?: string | null
  code_context?: string | null
  context_start_line?: number | null
  references?: string[]
  confidence?: string
  remediation_type?: string
  // only on /api/v1/vulnerabilities
  repo?: string
  job_id?: string
  scanned_at?: string
}

export interface Fix {
  summary: string
  method: 'dependency' | 'rule' | 'llm' | string
  risk: 'low' | 'medium' | 'high' | string
  status: string
  verified: boolean | null
  validation_status: Verdict | null
  commit: string | null
  files: string[]
  explanation?: string | null
  detail?: string | null
  finding_ids: string[]
  diff: string
}

export interface Check {
  name: string
  category: 'static' | 'security-regression' | 'functional' | 'security-rescan' | 'policy'
  status: 'passed' | 'failed' | 'warning' | 'skipped'
  detail: string
  fix_index: number | null
}

export interface Report {
  run_id?: string
  severity_counts: Partial<Record<Severity, number>>
  findings_input: number
  findings_selected: number
  patches_proposed: number
  patches_applied: number
  verified_fixed: number
  validation_status: Verdict
  validation_checks: Check[]
  fixes: Fix[]
  notes: string[]
  category_counts: Record<string, number>
  scanner_counts: Record<string, number>
  scanners: { name: string; status: string; message: string }[]
  branch: string | null
  base_commit: string | null
  duration_seconds: number
  llm_enabled: boolean
  pull_request_url?: string | null
}

export interface Dashboard {
  runs: number
  by_status: Record<string, number>
  repositories: number
  open_findings: number
  severity: Partial<Record<Severity, number>>
  fixes_applied: number
  ai_fixes: number
  verified_fixed: number
  pull_requests: number
  validation: Record<string, number>
  validation_pass_rate: number | null
  recent: Job[]
}

export interface NeededFix {
  job_id: string
  finding_id: string
  repo: string
  title: string
  severity: Severity
  score: number | null
  location: string
  /** Which kind of reason (remediation/insights.py REASONS), e.g. needs_llm, transitive, partial. */
  reason_key?: string
  reason: string
  action: string
  note?: string
}

export interface ErrorItem {
  severity: 'high' | 'medium' | 'low'
  kind: string
  message: string
  action: string
  link?: string | null
  repo?: string
  job_id?: string
  when?: string | null
}

export interface Attention {
  counts: { approvals: number; fixes_needed: number; errors: number }
  /** draft_review: a draft PR the pipeline opened on its own for a flagged run, not yet looked at. */
  approvals: (Job & { failed_checks: { name: string; detail: string }[]; draft_review?: boolean })[]
  fixes_needed: NeededFix[]
  errors: ErrorItem[]
  config_errors: ErrorItem[]
}

export interface Capabilities {
  version: string
  scanners: Record<string, { available: boolean; enabled: boolean; primary?: boolean; description: string }>
  llm: { enabled: boolean; provider: string | null; model: string | null }
  github_token_configured: boolean
  git: boolean
  auth_required: boolean
}

export interface Repository {
  repo: string
  repo_url: string
  runs: number
  latest: Job
  latest_completed: Job | null
  history: { when: string | null; findings: number; fixed: number }[]
}

export interface SettingEntry { value: string | number | null; configured: boolean; source: 'ui' | 'env' | 'default' | 'unset'; secret: boolean }
export interface SettingsView {
  settings: Record<string, SettingEntry>
  llm_enabled: boolean
  llm_provider: string | null
  llm_endpoint: string | null
  /** Shared sign-in on: these are the signed-in person's own keys, used only for the scans they start. */
  per_user: boolean
  user: string | null
  ai_managed?: boolean   // the AI model is the organisation's, set on the server
  llm_model?: string | null
}

export interface AgentHistory {
  agent: { id: AgentId; name: string; role: string; contract_in: string[]; contract_out: string[] }
  runs: { job_id: string; repo: string; when: string | null; status: StageStatus; duration: number | null; outputs: KV[]; learnings: Learning[] }[]
}
