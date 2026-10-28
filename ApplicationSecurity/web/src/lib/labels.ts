// Words and orderings shared by every page, so a status means the same thing everywhere.
import { Bot, FileText, GitPullRequestArrow, Download, ScanSearch, ShieldCheck, Wrench, type LucideIcon } from 'lucide-react'
import type { AgentId, Finding, Severity, Stage } from '@/lib/types'

export const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info', 'unknown']
export const sevLabel = (s: string) => (s === 'unknown' || s === 'info' ? (s === 'info' ? 'Info' : 'Unrated') : s[0].toUpperCase() + s.slice(1))

/** The six steps of every scan, in order. The names come from here so old scans read the same as new ones. */
export const STAGES: { id: string; name: string; short: string; agent: string | null; description: string; icon: LucideIcon }[] = [
  { id: 'ingest', name: 'Repository Ingestion', short: 'Get the code', agent: null, icon: Download,
    description: 'Check the link, download the code, detect languages and dependency files.' },
  { id: 'analysis', name: 'Vulnerability Analysis & Prioritization', short: 'Find issues', agent: 'Analysis Agent', icon: ScanSearch,
    description: 'CodeQL (main code scanner) + Trivy + supporting scanners, then remove duplicates and rank by risk.' },
  { id: 'remediation', name: 'Remediation', short: 'Fix them', agent: 'Remediation Agent', icon: Wrench,
    description: 'Targeted fixes on a separate Git branch, one commit per fix. Your original code is untouched.' },
  { id: 'validation', name: 'Testing & Validation', short: 'Prove the fixes', agent: 'Validation Agent', icon: ShieldCheck,
    description: 'Syntax checks, security-regression guard, the project’s tests, and a fresh security scan.' },
  { id: 'reporting', name: 'Reporting', short: 'Write it up', agent: 'Reporting Agent', icon: FileText,
    description: 'Report, SARIF file, one diff per fix and the final validation verdict.' },
  { id: 'approval', name: 'Human Approval & PR', short: 'You decide', agent: null, icon: GitPullRequestArrow,
    description: 'You approve, then the branch is pushed and a pull request opened.' },
]

export function mergedStages(stages: Stage[] | undefined): Stage[] {
  const byId: Record<string, Partial<Stage>> = Object.fromEntries((stages ?? []).map((s) => [s.id, s]))
  return STAGES.map((d) => ({ status: 'pending', steps: [], metrics: {}, summary: '', ...byId[d.id], id: d.id, name: d.name, agent: d.agent, description: d.description }) as Stage)
}

/** The four security agents. Each has its own colour (used on its icon tile and in charts). */
export const AGENTS: Record<AgentId, { name: string; n: number; icon: LucideIcon; tone: string; short: string }> = {
  analysis: { name: 'Analysis Agent', n: 1, icon: ScanSearch, tone: 'var(--violet)', short: 'Finds and ranks the security issues' },
  remediation: { name: 'Remediation Agent', n: 2, icon: Wrench, tone: 'var(--blue)', short: 'Writes the fixes on a safe branch' },
  validation: { name: 'Validation Agent', n: 3, icon: ShieldCheck, tone: 'var(--teal)', short: 'Proves the fixes work and break nothing' },
  reporting: { name: 'Reporting Agent', n: 4, icon: FileText, tone: 'var(--signal)', short: 'Hands over the report and pull request' },
}
export const AGENT_IDS = Object.keys(AGENTS) as AgentId[]
export const AgentIcon = Bot

export const AGENT_STATUS: Record<string, { label: string; tone: 'good' | 'warn' | 'bad' | 'info' | 'idle' }> = {
  completed: { label: 'Done', tone: 'good' },
  warning: { label: 'Done, with warnings', tone: 'warn' },
  failed: { label: 'Failed', tone: 'bad' },
  running: { label: 'Working…', tone: 'info' },
  pending: { label: 'Waiting', tone: 'idle' },
  skipped: { label: 'Skipped', tone: 'idle' },
}

export const FIX_STATUS: Record<string, { label: string; tone: 'good' | 'warn' | 'bad' | 'info' | 'idle'; hint: string }> = {
  verified: { label: 'Fixed & confirmed', tone: 'good', hint: 'The Remediation Agent fixed it, and the Validation Agent’s rescan no longer reports it.' },
  fixed: { label: 'Fixed', tone: 'info', hint: 'The Remediation Agent applied a fix on the branch.' },
  manual: { label: 'Needs a person', tone: 'warn', hint: 'Cannot be fixed automatically; see what to do.' },
  failed: { label: 'Fix failed', tone: 'bad', hint: 'The Remediation Agent tried a fix, but it did not work.' },
  skipped: { label: 'Skipped', tone: 'idle', hint: 'The Remediation Agent did not try it in this scan (for example it had no AI model, or the limit was reached).' },
  not_attempted: { label: 'Not attempted', tone: 'idle', hint: 'Below the minimum severity or the per-scan limit.' },
}

export const VERDICT: Record<string, { label: string; tone: 'good' | 'warn' | 'bad' | 'idle' }> = {
  passed: { label: 'Validated', tone: 'good' },
  flagged: { label: 'Needs review', tone: 'warn' },
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
  scan_started: { label: 'Started a scan', tone: 'info' },
  scan_rerun: { label: 'Re-ran a scan', tone: 'info' },
  scan_cancelled: { label: 'Cancelled a scan', tone: 'warn' },
  fixes_approved: { label: 'Approved the fixes', tone: 'good' },
  pr_opened: { label: 'Pull request opened', tone: 'good' },
  pr_failed: { label: 'Pull request failed', tone: 'bad' },
  tests_started: { label: 'Ran tests on GitHub', tone: 'info' },
  tests_cancelled: { label: 'Stopped the tests', tone: 'warn' },
  draft_reviewed: { label: 'Reviewed a draft PR', tone: 'good' },
  settings_changed: { label: 'Changed own settings', tone: 'idle' },
}

export const METHOD: Record<string, { label: string; tone: string }> = {
  dependency: { label: 'Dependency upgrade', tone: 'var(--sky)' },
  rule: { label: 'Safe rewrite', tone: 'var(--teal)' },
  llm: { label: 'Code fix', tone: 'var(--violet)' },
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
