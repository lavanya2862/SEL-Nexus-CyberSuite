// Triage (UC4): types for /api/uc4/* and the agree/disagree action. Mirrors src/portal/sources.py (UC4).
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { statusColor } from '@/lib/theme'

export type Verdict = 'likely_true_positive' | 'needs_investigation' | 'likely_false_positive' | 'benign_positive'

// Microsoft Defender's own classification words (same as UC4's labels.py) + a plain-English help line + colour.
export const VERDICT: Record<Verdict, { label: string; short: string; color: string; help: string }> = {
  likely_true_positive: { label: 'True positive', short: 'True positive', color: statusColor.critical, help: 'Confirmed malicious activity: the evidence indicates a genuine attack. Respond immediately.' },
  needs_investigation: { label: 'Needs review', short: 'Needs review', color: statusColor.warning, help: 'The agent could not classify it, or Microsoft rated it too severe for automated closure.' },
  likely_false_positive: { label: 'False positive', short: 'False positive', color: 'var(--sky)', help: 'Benign: the alert was a false detection or the activity was authorised.' },
  // older verdicts only: harmless activity is now filed as a false positive
  benign_positive: { label: 'False positive', short: 'False positive', color: 'var(--sky)', help: 'Benign: the alert was a false detection or the activity was authorised.' },
}
export const VERDICT_ORDER: Verdict[] = ['likely_true_positive', 'likely_false_positive', 'needs_investigation']
export const verdictMeta = (v: string) => VERDICT[v as Verdict] ?? { label: v || '–', short: v || '–', color: 'var(--ink-3)', help: '' }

export const CONTAINMENT: Record<string, string> = {
  isolate_device: 'Isolate the computer from the network',
  release_device: 'Release the computer from isolation',
  disable_user: 'Disable the user account',
  revoke_sessions: "Sign the user out everywhere (revoke sessions)",
  block_indicator: 'Block the bad file, web address or IP',
  collect_investigation_package: 'Collect an investigation package from the computer',
  remove_inbox_rule: 'Remove the suspicious mailbox rule',
}

export const SOURCE_NAMES: Record<string, string> = {
  microsoftDefenderForEndpoint: 'Defender for Endpoint', microsoftSentinel: 'Sentinel', microsoftDefenderForIdentity: 'Defender for Identity',
  microsoftDefenderForOffice365: 'Defender for Office 365', microsoftDefenderForCloudApps: 'Defender for Cloud Apps',
  microsoft365Defender: 'Defender XDR', microsoftDefenderForCloud: 'Defender for Cloud', defender: 'Defender', sentinel: 'Sentinel',
  scheduledAlerts: 'Sentinel rule', nrtAlerts: 'Sentinel near-real-time rule',
}
export const sourceNames = (s: string | string[] | null | undefined) =>
  (Array.isArray(s) ? s : String(s ?? '').split(',')).filter(Boolean).map((x) => SOURCE_NAMES[x] ?? x).join(', ')

export interface Feedback { agree: boolean; analyst_verdict: string | null }

export interface QueueRow {
  incident_id: string
  title: string
  severity: string
  status: string
  sources: string
  is_lab: boolean
  web_url: string | null
  created_at: string | null
  devices: string[]
  accounts: string[]
  verdict: Verdict
  confidence: 'low' | 'medium' | 'high'
  recommended_severity: string
  escalate: boolean
  guardrails: string[]
  summary: string
  ai_status: string
  triaged_at: string | null
  queries_run: number
  ti_lookups: number
  seconds: number
  feedback: Feedback | null
  last_action?: { action: string; status: string; done_at: string | null } | null
}

// The rules UC4 applies (UC4 config/guardrails.yaml). No rules of our own: it never overrules Microsoft, and it
// protects the AI from attacker text. Ids not listed here are rules from an older version.
export const RULES: Record<string, { label: string; basis: string; link: string; linkText: string }> = {
  microsoft_high_severity: { label: 'Microsoft rated it high severity', basis: 'Microsoft', link: 'https://learn.microsoft.com/en-us/defender-xdr/incident-queue', linkText: 'Microsoft: severity levels' },
  microsoft_malicious_evidence: { label: 'Defender marked evidence as malicious', basis: 'Microsoft', link: 'https://learn.microsoft.com/en-us/graph/api/resources/security-alertevidence?view=graph-rest-1.0', linkText: 'Microsoft: evidence verdicts' },
  injection_marker: { label: 'Attacker text tried to instruct the agent', basis: 'Agent protection', link: 'https://owasp.org/www-project-top-10-for-large-language-model-applications/', linkText: 'OWASP: prompt injection' },
}
export const ruleMeta = (id: string) => RULES[id] ?? { label: id.replace(/_/g, ' '), basis: 'Older team rule (no longer used)', link: '', linkText: '' }
export const mitreLink = (t: string) => `https://attack.mitre.org/techniques/${t.toUpperCase().replace('.', '/')}/`

export interface Automation { auto_resolve: boolean; writeback: boolean; known: boolean }

/** Who decides, as UC4's autoresolve.decide() with config/auto_resolve.yaml: the AI's verdict is final (a true
 *  positive is escalated, a false positive is closed). A person decides only "needs review", a
 *  verdict made without the AI, a non-lab incident, or one a person reopened. */
export function needsPerson(r: { verdict: string; ai_status: string; is_lab: boolean }, auto: boolean, reopened = false) {
  return !auto || reopened || !r.is_lab || r.ai_status !== 'ai' || r.verdict === 'needs_investigation'
}

// What UC4 did by itself (data/feedback/actions.jsonl), in plain words
export const ACTION_WORDS: Record<string, string> = {
  auto_resolve: 'Closed', auto_escalate: 'Escalated', auto_needs_human: 'Tagged for review',
  close_incident: 'Closed by a person',
  escalate_incident: 'Escalated by a person', reopen: 'Reopened', isolate_device: 'Computer isolated', release_device: 'Computer released',
  av_scan: 'Antivirus scan requested', quarantine_file: 'File quarantine requested',
}

export interface Uc4LastRun { run_id: string; started_at: string; finished_at: string; status: string; steps: Record<string, unknown> }

export interface Uc4Queue {
  generated_at: string
  last_run: string | null
  totals: { incidents: number; escalate: number; lab: number }
  by_verdict: Record<string, number>
  queue: QueueRow[]
  last_run_detail: Uc4LastRun | null
  automation: Automation
  site_up: boolean
  site_url: string
}

export interface Evidence { source: string; query_id: string; finding: string }
export interface Query { id: string; status: string; row_count: number; rows: Record<string, unknown>[]; rows_total: number; query?: string; error?: string }

export interface Uc4Case {
  packet: {
    incident_id: string
    title: string
    severity: string
    status: string
    created_at: string | null
    updated_at: string | null
    web_url: string | null
    services: string[]
    detection_sources: string[]
    alerts: { id: string; title: string; severity: string; category: string; status: string; detection_source: string; threat_family?: string; techniques: string[]; created: string; first_activity?: string; web_url?: string; untrusted?: { description?: string }
      service_source?: string; investigation_state?: string; threat_name?: string; product?: string; recommended_actions?: string
      sentinel_rule?: { name: string; ids: string[]; template_id: string; data_sources: string[]; results: string; trigger: string } | null
      evidence_verdicts?: { kind: string; name: string; verdict: string; remediation: string }[] }[]
    entities: Record<string, Record<string, unknown>[]>
    techniques: string[]
    first_activity: string | null
    last_activity: string | null
    is_lab: boolean
  }
  verdict: {
    summary: string
    verdict: Verdict
    confidence: 'low' | 'medium' | 'high'
    recommended_severity: string
    evidence: Evidence[]
    mitre_techniques: string[]
    recommended_actions: string[]
    containment_options: string[]
    escalate: boolean
    would_change_verdict_if: string
    guardrails: string[]
    guardrail_reasons: string[]
    ai_status: string
    checker_notes: string[]
  }
  queries: Query[]
  ti: { indicator: string; type: string; verdict: string; sources?: string[]; detail?: string }[]
  context: { devices?: { name: string; os?: string; risk?: string; exposure?: string; health?: string; opco?: string; is_lab?: boolean; admin_account?: boolean }[]; watchlist_hits?: Record<string, unknown>; account_is_admin?: boolean }
  history: { note?: string; prior_total?: number; prior_benign_rate?: number | null; prior_verdicts?: Record<string, number> }
  injection: { where: string; phrase: string }[]
  playbook: { id: string; label: string; description: string; notes?: string }
  triaged_at: string | null
  seconds: number | null
  feedback: { feedback_id: string; agree: boolean; analyst_verdict: string | null; reason: string; minutes: number | null; created_at: string }[]
  actions: { action_id?: string; action: string; target: string; status: string; detail?: string; requested_at: string; done_at?: string | null }[]
  questions?: Question[]
  automation: Automation
  site_up: boolean
  site_url: string
}

export interface Metric { name: string; value: number | { n: number; median: number | null; mean: number | null } | null; label: 'MEASURED' | 'ASSUMPTION'; note: string }
export interface BacktestSet {
  n: number
  decided_pct: number
  accuracy_when_decided_pct: number
  missed_true_positives: number
  real_attacks_kept_for_humans_pct: number
  false_alarms_closable_pct: number
  baseline_history_accuracy_pct?: number
  confusion?: Record<string, Record<string, number>>
}
export interface Uc4Quality { metrics: { metrics: Metric[] } | null; backtest: { generated_at?: string; sets: Record<string, BacktestSet> } | null }

async function get<T>(url: string): Promise<T> {
  const res = await fetch(url)
  if (res.status === 404) throw new NotFound((await res.json().catch(() => ({}))).error ?? 'not found')
  if (!res.ok) throw new Error(`Portal API answered ${res.status}`)
  return res.json()
}

export class NotFound extends Error {}

export const useUc4Queue = () => useQuery({ queryKey: ['uc4', 'queue'], queryFn: () => get<Uc4Queue>('/api/uc4/queue'), refetchInterval: 30_000, retry: 0 })
export const useUc4Case = (id: string) =>
  useQuery({ queryKey: ['uc4', 'case', id], queryFn: () => get<Uc4Case>(`/api/uc4/cases/${encodeURIComponent(id)}`), enabled: !!id, retry: 0 })
export const useUc4Quality = () => useQuery({ queryKey: ['uc4', 'quality'], queryFn: () => get<Uc4Quality>('/api/uc4/quality'), staleTime: 60_000 })

export interface FeedbackInput { incident_id: string; agree: boolean; analyst_verdict?: Verdict | null; reason?: string; minutes?: number | null }

/** Agree / disagree: forwarded to UC4's own website (X-Portal: feedback). Throws with UC4's message. */
export function useFeedback() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (body: FeedbackInput) => {
      const res = await fetch('/api/uc4/feedback', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Portal': 'feedback' }, body: JSON.stringify(body) })
      const out = await res.json().catch(() => ({}))
      if (!res.ok) throw new Error(out.error ?? `the assistant answered ${res.status}`)
      return out
    },
    onSettled: () => qc.invalidateQueries({ queryKey: ['uc4'] }),
  })
}

/** One "Ask about this incident" turn, saved by UC4 in data/feedback/ask.jsonl. */
export interface Question { ask_id: string; incident_id: string; question: string; answer: string; based_on: string[]; created_at: string }

/** "Ask about this incident": forwarded to UC4's own website (X-Portal: ask). The AI answers from the saved
 *  evidence only and never changes anything. Throws with UC4's message. */
export function useAsk() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (body: { incident_id: string; question: string }) => {
      const res = await fetch('/api/uc4/ask', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Portal': 'ask' }, body: JSON.stringify(body) })
      const out = await res.json().catch(() => ({}))
      if (!res.ok) throw new Error(out.error ?? `the assistant answered ${res.status}`)
      return out.saved as Question
    },
    onSettled: (_d, _e, body) => qc.invalidateQueries({ queryKey: ['uc4', 'case', body.incident_id] }),
  })
}

/** Undo an automatic close: the incident is reopened in Defender (a person's click, X-Portal: reopen). */
export function useReopen() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (incident_id: string) => {
      const res = await fetch('/api/uc4/reopen', {
        method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Portal': 'reopen' },
        body: JSON.stringify({ incident_id, confirm: true, reason: 'Reopened from the portal' }),
      })
      const out = await res.json().catch(() => ({}))
      if (!res.ok) throw new Error(out.error ?? `the assistant answered ${res.status}`)
      return out
    },
    onSettled: () => qc.invalidateQueries({ queryKey: ['uc4'] }),
  })
}

/** "2026-10-05 17:32:02" (UTC, no zone) → Date */
export const utc = (s: string | null | undefined) => (s ? new Date(s.replace(' ', 'T') + (/[zZ]|[+-]\d\d:?\d\d$/.test(s) ? '' : 'Z')) : null)
