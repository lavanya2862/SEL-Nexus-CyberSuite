// Triage (Alert Triage): types for /api/alert-triage/* and the agree/disagree action. Mirrors src/portal/sources.py (Alert Triage).
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { statusColor } from '@/lib/theme'

export type Verdict = 'likely_true_positive' | 'needs_investigation' | 'likely_false_positive' | 'benign_positive'

// Microsoft Defender's own classification words (same as Alert Triage's labels.py) + a plain-English help line + colour.
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
  isolate_device: 'Isolate the device from the network',
  release_device: 'Release the device from isolation',
  disable_user: 'Disable the user account',
  revoke_sessions: "Sign the user out everywhere (revoke sessions)",
  block_indicator: 'Block the bad file, web address or IP',
  collect_investigation_package: 'Collect an investigation package from the device',
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

/** The final classification once one is made (portal sources.alert_triage_decision): an analyst's decision made in
 *  CyberSuite (written into Defender), else the classification Defender holds. null while nobody has classified it.
 *  status is Defender's: resolved = closed; active / inProgress = open. */
export interface Decision {
  outcome: Verdict
  by: 'analyst' | 'defender'
  who?: string
  at?: string | null
  classification: string | null
  determination: string | null
  status: string | null
}

// Defender's incident status values, as its incident list words them
export const STATUS_WORDS: Record<string, string> = {
  active: 'Active (not picked up yet)', inProgress: 'In progress', resolved: 'Resolved', redirected: 'Merged into another incident',
}

/** Defender's incident status in two words: resolved (or redirected into another incident) is closed, the rest open. */
export const isClosed = (status: string | null | undefined) => ['resolved', 'redirected'].includes((status ?? '').toLowerCase())

// What an analyst's decision does in Defender (Alert Triage close.plan) and the "why" Defender records with it
export const DECISION_EFFECT: Record<'likely_true_positive' | 'likely_false_positive', { effect: string; button: string; reasons: [string, string][] }> = {
  likely_true_positive: {
    effect: 'Stays open in Defender as In progress, classified true positive, so the response can continue.',
    button: 'Save: true positive, keep open in Defender',
    reasons: [['other', 'Other'], ['malware', 'Malware'], ['compromisedAccount', 'Compromised account'], ['maliciousUserActivity', 'Malicious user activity']],
  },
  likely_false_positive: {
    effect: 'Closed in Defender (Resolved), classified false positive.',
    button: 'Save: false positive, close in Defender',
    reasons: [['notMalicious', 'Not malicious'], ['notEnoughDataToValidate', 'Not enough data to validate']],
  },
}

// Defender's classification and determination values, in its own words
export const CLASSIFICATION_WORDS: Record<string, string> = {
  truePositive: 'True positive', falsePositive: 'False positive', informationalExpectedActivity: 'Informational, expected activity',
}
export const DETERMINATION_WORDS: Record<string, string> = {
  malware: 'Malware', compromisedAccount: 'Compromised account', maliciousUserActivity: 'Malicious user activity', other: 'Other',
  notMalicious: 'Not malicious', notEnoughDataToValidate: 'Not enough data to validate', securityTesting: 'Security test',
  confirmedUserActivity: 'Confirmed user activity', lineOfBusinessApplication: 'Line-of-business application',
  phishing: 'Phishing', unwantedSoftware: 'Unwanted software', multiStagedAttack: 'Multi-staged attack',
}

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
  classification?: string | null
  determination?: string | null
  decision: Decision | null
  /** what the queue shows: the decision when there is one, else the agent's verdict */
  outcome: Verdict
}

// The rules Alert Triage applies (Alert Triage config/guardrails.yaml). No rules of our own: it never overrules Microsoft, and it
// protects the AI from attacker text. Ids not listed here are rules from an older version.
export const RULES: Record<string, { label: string; basis: string; link: string; linkText: string }> = {
  microsoft_high_severity: { label: 'Microsoft rated it high severity', basis: 'Microsoft', link: 'https://learn.microsoft.com/en-us/defender-xdr/incident-queue', linkText: 'Microsoft: severity levels' },
  microsoft_malicious_evidence: { label: 'Defender marked evidence as malicious', basis: 'Microsoft', link: 'https://learn.microsoft.com/en-us/graph/api/resources/security-alertevidence?view=graph-rest-1.0', linkText: 'Microsoft: evidence verdicts' },
  injection_marker: { label: 'Attacker text tried to instruct the agent', basis: 'Agent protection', link: 'https://owasp.org/www-project-top-10-for-large-language-model-applications/', linkText: 'OWASP: prompt injection' },
}
export const ruleMeta = (id: string) => RULES[id] ?? { label: id.replace(/_/g, ' '), basis: 'Older team rule (no longer used)', link: '', linkText: '' }
export const mitreLink = (t: string) => `https://attack.mitre.org/techniques/${t.toUpperCase().replace('.', '/')}/`

export interface Automation { auto_resolve: boolean; writeback: boolean; known: boolean }

/** Who decides, as Alert Triage's autoresolve.decide() with config/auto_resolve.yaml: the AI's verdict is final (a true
 *  positive is escalated, a false positive is closed). A person decides only "needs review", a
 *  verdict made without the AI, a non-lab incident, or one a person reopened. */
export function needsPerson(r: { verdict: string; ai_status: string; is_lab: boolean }, auto: boolean, reopened = false) {
  return !auto || reopened || !r.is_lab || r.ai_status !== 'ai' || r.verdict === 'needs_investigation'
}

// What Alert Triage did by itself (data/feedback/actions.jsonl), in plain words
export const ACTION_WORDS: Record<string, string> = {
  auto_resolve: 'Closed', auto_escalate: 'Escalated', auto_needs_human: 'Tagged for review',
  close_incident: 'Closed by a person',
  escalate_incident: 'Escalated by a person', reopen: 'Reopened', isolate_device: 'Device isolated', release_device: 'Device released',
  av_scan: 'Antivirus scan requested', quarantine_file: 'File quarantine requested',
}

export interface TriageLastRun { run_id: string; started_at: string; finished_at: string; status: string; steps: Record<string, unknown> }

export interface TriageQueue {
  generated_at: string
  last_run: string | null
  totals: { incidents: number; escalate: number; lab: number }
  by_verdict: Record<string, number>
  by_outcome: Record<string, number>
  queue: QueueRow[]
  last_run_detail: TriageLastRun | null
  automation: Automation
  site_up: boolean
  site_url: string
}

export interface Evidence { source: string; query_id: string; finding: string }
export interface Query { id: string; status: string; row_count: number; rows: Record<string, unknown>[]; rows_total: number; query?: string; error?: string }

export interface TriageCase {
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
  defender_state: { status: string | null; classification: string | null; determination: string | null; updated_at: string | null }
  decision: Decision | null
  outcome: Verdict
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
export interface TriageQuality { metrics: { metrics: Metric[] } | null; backtest: { generated_at?: string; sets: Record<string, BacktestSet> } | null }

async function get<T>(url: string): Promise<T> {
  const res = await fetch(url)
  if (res.status === 404) throw new NotFound((await res.json().catch(() => ({}))).error ?? 'not found')
  if (!res.ok) throw new Error(`CyberSuite could not complete the request (error ${res.status})`)
  return res.json()
}

export class NotFound extends Error {}

export const useTriageQueue = () => useQuery({ queryKey: ['alert_triage', 'queue'], queryFn: () => get<TriageQueue>('/api/alert-triage/queue'), refetchInterval: 30_000, retry: 0 })
export const useTriageCase = (id: string) =>
  useQuery({ queryKey: ['alert_triage', 'case', id], queryFn: () => get<TriageCase>(`/api/alert-triage/cases/${encodeURIComponent(id)}`), enabled: !!id, retry: 0 })
export const useTriageQuality = () => useQuery({ queryKey: ['alert_triage', 'quality'], queryFn: () => get<TriageQuality>('/api/alert-triage/quality'), staleTime: 60_000 })

export interface FeedbackInput { incident_id: string; agree: boolean; analyst_verdict?: Verdict | null; reason?: string; minutes?: number | null }

/** Agree / disagree: forwarded to Alert Triage's own website (X-Portal: feedback). Throws with Alert Triage's message. */
export function useFeedback() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (body: FeedbackInput) => {
      const res = await fetch('/api/alert-triage/feedback', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Portal': 'feedback' }, body: JSON.stringify(body) })
      const out = await res.json().catch(() => ({}))
      if (!res.ok) throw new Error(out.error ?? `CyberSuite could not complete the request (error ${res.status})`)
      return out
    },
    onSettled: () => qc.invalidateQueries({ queryKey: ['alert_triage'] }),
  })
}

export interface DecideInput { incident_id: string; verdict: 'likely_true_positive' | 'likely_false_positive'; determination: string; reason?: string }

/** An analyst's decision, written into Defender by Alert Triage (X-Portal: decide): a false positive is closed, a true
 *  positive stays open as in progress. Throws with Alert Triage's or Defender's message. */
export function useDecide() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (body: DecideInput) => {
      const res = await fetch('/api/alert-triage/decide', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Portal': 'decide' }, body: JSON.stringify(body) })
      const out = await res.json().catch(() => ({}))
      if (!res.ok) throw new Error(out.error ?? `CyberSuite could not complete the request (error ${res.status})`)
      return out
    },
    onSettled: () => qc.invalidateQueries({ queryKey: ['alert_triage'] }),
  })
}

/** One "Ask about this incident" turn, saved by Alert Triage in data/feedback/ask.jsonl. */
export interface Question { ask_id: string; incident_id: string; question: string; answer: string; based_on: string[]; created_at: string }

/** "Ask about this incident": forwarded to Alert Triage's own website (X-Portal: ask). The AI answers from the saved
 *  evidence only and never changes anything. Throws with Alert Triage's message. */
export function useAsk() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (body: { incident_id: string; question: string }) => {
      const res = await fetch('/api/alert-triage/ask', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Portal': 'ask' }, body: JSON.stringify(body) })
      const out = await res.json().catch(() => ({}))
      if (!res.ok) throw new Error(out.error ?? `CyberSuite could not complete the request (error ${res.status})`)
      return out.saved as Question
    },
    onSettled: (_d, _e, body) => qc.invalidateQueries({ queryKey: ['alert_triage', 'case', body.incident_id] }),
  })
}

/** Undo an automatic close: the incident is reopened in Defender (a person's click, X-Portal: reopen). */
export function useReopen() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (incident_id: string) => {
      const res = await fetch('/api/alert-triage/reopen', {
        method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Portal': 'reopen' },
        body: JSON.stringify({ incident_id, confirm: true, reason: 'Reopened from CyberSuite' }),
      })
      const out = await res.json().catch(() => ({}))
      if (!res.ok) throw new Error(out.error ?? `CyberSuite could not complete the request (error ${res.status})`)
      return out
    },
    onSettled: () => qc.invalidateQueries({ queryKey: ['alert_triage'] }),
  })
}

/** "2026-10-05 17:32:02" (UTC, no zone) → Date */
export const utc = (s: string | null | undefined) => (s ? new Date(s.replace(' ', 'T') + (/[zZ]|[+-]\d\d:?\d\d$/.test(s) ? '' : 'Z')) : null)
