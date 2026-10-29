// Words and orderings shared by every page, so a status means the same thing everywhere.
import { Bot, FileText, GitPullRequestArrow, Download, ScanSearch, ShieldCheck, Wrench, type LucideIcon } from 'lucide-react'
import type { AgentId, Finding, Severity, Stage } from '@/lib/types'

export const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info', 'unknown']
export const sevLabel = (s: string) => (s === 'unknown' || s === 'info' ? (s === 'info' ? 'Info' : 'Unrated') : s[0].toUpperCase() + s.slice(1))

/** The six steps of every scan, in order. The names come from here so old scans read the same as new ones. */
export const STAGES: { id: string; name: string; short: string; agent: string | null; description: string; icon: LucideIcon }[] = [
  { id: 'ingest', name: 'Repository Ingestion', short: 'Ingest source', agent: null, icon: Download,
    description: 'Validates the repository URL, retrieves the source code and identifies languages and dependency manifests.' },
  { id: 'analysis', name: 'Vulnerability Analysis & Prioritization', short: 'Detect and prioritise', agent: 'Analysis Agent', icon: ScanSearch,
    description: 'Runs CodeQL, Trivy and supporting scanners, consolidates duplicate findings and prioritises them by risk.' },
  { id: 'remediation', name: 'Remediation', short: 'Remediate', agent: 'Remediation Agent', icon: Wrench,
    description: 'Applies targeted remediations on an isolated Git branch, one commit per remediation. The source branch is never modified.' },
  { id: 'validation', name: 'Testing & Validation', short: 'Validate', agent: 'Validation Agent', icon: ShieldCheck,
    description: 'Verifies each remediation through syntax checks, a security-regression guard, the project’s test suite and a confirmation scan.' },
  { id: 'reporting', name: 'Reporting', short: 'Report', agent: 'Reporting Agent', icon: FileText,
    description: 'Produces the assessment report, the SARIF file, a diff for each remediation and the final validation verdict.' },
  { id: 'approval', name: 'Human Approval & PR', short: 'Approve', agent: null, icon: GitPullRequestArrow,
    description: 'An authorised reviewer approves the remediations; the branch is then pushed and a pull request raised.' },
]

export function mergedStages(stages: Stage[] | undefined): Stage[] {
  const byId: Record<string, Partial<Stage>> = Object.fromEntries((stages ?? []).map((s) => [s.id, s]))
  return STAGES.map((d) => ({ status: 'pending', steps: [], metrics: {}, summary: '', ...byId[d.id], id: d.id, name: d.name, agent: d.agent, description: d.description }) as Stage)
}

/** The four security agents. Each has its own colour (used on its icon tile and in charts). */
export const AGENTS: Record<AgentId, { name: string; n: number; icon: LucideIcon; tone: string; short: string }> = {
  analysis: { name: 'Analysis Agent', n: 1, icon: ScanSearch, tone: 'var(--violet)', short: 'Detects and prioritises security vulnerabilities' },
  remediation: { name: 'Remediation Agent', n: 2, icon: Wrench, tone: 'var(--blue)', short: 'Remediates vulnerabilities on an isolated branch' },
  validation: { name: 'Validation Agent', n: 3, icon: ShieldCheck, tone: 'var(--teal)', short: 'Verifies remediations and guards against regressions' },
  reporting: { name: 'Reporting Agent', n: 4, icon: FileText, tone: 'var(--signal)', short: 'Delivers the assessment report and pull request' },
}
export const AGENT_IDS = Object.keys(AGENTS) as AgentId[]
export const AgentIcon = Bot

export const AGENT_STATUS: Record<string, { label: string; tone: 'good' | 'warn' | 'bad' | 'info' | 'idle' }> = {
  completed: { label: 'Completed', tone: 'good' },
  warning: { label: 'Completed with warnings', tone: 'warn' },
  failed: { label: 'Failed', tone: 'bad' },
  running: { label: 'In progress', tone: 'info' },
  pending: { label: 'Pending', tone: 'idle' },
  skipped: { label: 'Skipped', tone: 'idle' },
}

export const FIX_STATUS: Record<string, { label: string; tone: 'good' | 'warn' | 'bad' | 'info' | 'idle'; hint: string }> = {
  verified: { label: 'Remediated and verified', tone: 'good', hint: 'Remediated by the Remediation Agent and no longer reported by the Validation Agent’s confirmation scan.' },
  fixed: { label: 'Remediated', tone: 'info', hint: 'The Remediation Agent applied a remediation on the remediation branch.' },
  manual: { label: 'Manual remediation', tone: 'warn', hint: 'Cannot be remediated automatically. Review the recommended action.' },
  failed: { label: 'Remediation failed', tone: 'bad', hint: 'The Remediation Agent attempted a remediation, but it did not pass validation.' },
  skipped: { label: 'Deferred', tone: 'idle', hint: 'Not attempted in this scan, for example because no AI model is configured or the per-scan limit was reached.' },
  not_attempted: { label: 'Out of scope', tone: 'idle', hint: 'Below the minimum severity threshold or outside the per-scan remediation limit.' },
}

export const VERDICT: Record<string, { label: string; tone: 'good' | 'warn' | 'bad' | 'idle' }> = {
  passed: { label: 'Validated', tone: 'good' },
  flagged: { label: 'Review required', tone: 'warn' },
  failed: { label: 'Failed', tone: 'bad' },
  not_run: { label: 'Not validated', tone: 'idle' },
}

export const JOB_STATUS: Record<string, { label: string; tone: 'good' | 'warn' | 'bad' | 'info' | 'idle' }> = {
  queued: { label: 'Queued', tone: 'idle' },
  running: { label: 'Running', tone: 'info' },
  completed: { label: 'Completed', tone: 'good' },
  failed: { label: 'Failed', tone: 'bad' },
  cancelled: { label: 'Cancelled', tone: 'warn' },
}

// The activity log (remediation/activity.py)
export const ACTIVITY: Record<string, { label: string; tone: 'good' | 'warn' | 'bad' | 'info' | 'idle' }> = {
  scan_started: { label: 'Initiated a scan', tone: 'info' },
  scan_rerun: { label: 'Re-initiated a scan', tone: 'info' },
  scan_cancelled: { label: 'Cancelled a scan', tone: 'warn' },
  fixes_approved: { label: 'Approved remediations', tone: 'good' },
  pr_opened: { label: 'Pull request raised', tone: 'good' },
  pr_failed: { label: 'Pull request failed', tone: 'bad' },
  tests_started: { label: 'Started CI test validation', tone: 'info' },
  tests_cancelled: { label: 'Stopped CI test validation', tone: 'warn' },
  draft_reviewed: { label: 'Completed draft PR review', tone: 'good' },
  settings_changed: { label: 'Updated personal settings', tone: 'idle' },
}

export const METHOD: Record<string, { label: string; tone: string }> = {
  dependency: { label: 'Dependency upgrade', tone: 'var(--sky)' },
  rule: { label: 'Rule-based remediation', tone: 'var(--teal)' },
  llm: { label: 'AI-assisted remediation', tone: 'var(--violet)' },
}

export type FindingType = 'code' | 'dependency' | 'secret' | 'config'
export const FINDING_TYPES: [FindingType, string][] = [['code', 'Source code'], ['dependency', 'Dependency'], ['secret', 'Secret'], ['config', 'Misconfiguration']]
export function findingType(f: Pick<Finding, 'remediation_type'>): FindingType {
  if (f.remediation_type === 'dependency_upgrade') return 'dependency'
  if (f.remediation_type === 'secret_removal') return 'secret'
  if (f.remediation_type === 'configuration_fix') return 'config'
  return 'code'
}

export const where = (f: Finding) =>
  f.package_name ? `${f.package_name}@${f.installed_version ?? ''}` : `${f.file_path ?? ''}${f.line ? `:${f.line}` : ''}`

export const detectedBy = (f: Finding) => [f.scanner, ...(f.also_reported_by ?? [])].join(', ')

/** "Upgrade X 1 -> 2 (CVE-…, CVE-…)" → a readable title and a short second line. */
export function splitFixTitle(summary: string): [string, string] {
  const m = String(summary || '').match(/^(.*?)\s*\((.*)\)\s*$/)
  const main = (m ? m[1] : summary).replace(' -> ', ' → ')
  const extra = m ? m[2] : ''
  return [main, extra.length > 90 ? extra.slice(0, 89) + '…' : extra]
}

export const dur = (sec: number | null | undefined) =>
  sec == null ? '' : sec < 60 ? `${sec.toFixed(sec < 10 ? 1 : 0)} s` : `${Math.floor(sec / 60)} min ${Math.round(sec % 60)} s`

export const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? '' : 's'}`
