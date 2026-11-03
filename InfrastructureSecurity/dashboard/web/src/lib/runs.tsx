import { createContext, useContext, useEffect, useRef, useState, type ReactNode } from 'react'
import { useNavigate } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useAuth } from '@/lib/auth'

// attack = the Attack Detection Agent (Threat Intel's attack-check run, on its own so it can run more often than the news)
export type AgentKey = 'threat_intel' | 'vulnerability' | 'alert_triage' | 'attack_detection'
export const AGENT_KEYS: AgentKey[] = ['vulnerability', 'threat_intel', 'attack_detection', 'alert_triage']
/** waiting = the Fix stage: done by the agent, waiting for a person to decide on every new fix */
export type StepStatus = 'pending' | 'running' | 'done' | 'error' | 'skipped' | 'waiting'

export interface RunStep {
  key: string
  label: string
  description: string
  status: StepStatus
  detail: string
  started_at: string | null
  finished_at: string | null
}

export interface RunFact { label: string; value: string; hint: string }

/** One thing a Threat Intel / Attack Detection run found, by name (src/portal/runs.py run_findings) */
export interface RunFinding {
  kind: 'threat' | 'attack' | 'alert'; id: string; title: string; rating: string | null
  why: string; where: string; action: string; test: boolean; to: string
}

/** The Vulnerability Agent's Fix stage: the fixes this run proposed (fix engine ids), waiting for a person */
export interface RunFix {
  new: number; new_ids: string[]; waiting: number; saved: number; fixable?: number; urgent?: number; verified?: number
  /** how many of the new ones are app updates / security settings (unknown for older runs) */
  new_apps?: number; new_settings?: number
  /** earlier fixes (same app version, same computer) that gained vulnerabilities in this run: fix id → how many more */
  grew?: Record<string, number>; grew_vulns?: number
  /** live, from the fix engine's decisions: new fixes still to decide, and decided ones */
  open?: number; to_fix?: number; saved_now?: number
}

export interface RunState {
  run_id: string
  uc: AgentKey
  status: 'running' | 'ok' | 'partial' | 'failed' | 'skipped'
  message: string
  started_at: string
  finished_at: string | null
  exit_code: number | null
  steps: RunStep[]
  facts: RunFact[]
  /** what the run found, by name (Threat Intel and Attack Detection runs) */
  findings?: RunFinding[]
  report_file: string | null
  report_files?: string[]
  files_from?: 'threat_intel' | 'vulnerability' | 'alert_triage'
  lines: number
  log_tail: string[]
  typical_seconds?: number | null
  fix?: RunFix | null
  /** the Fix stage still has new fixes nobody decided on */
  waiting_for_you?: boolean
}

export type Runs = Record<AgentKey, RunState | null>

// What each run will do, shown before the first run (mirrors src/portal/runs.py).
export const PLANNED_STEPS: Record<AgentKey, { label: string; description: string }[]> = {
  vulnerability: [
    { label: 'Defender Data Acquisition', description: 'Retrieves vulnerability data and incremental updates from Microsoft Defender.' },
    { label: 'Data Validation', description: 'Validates snapshot completeness and data integrity.' },
    { label: 'Vulnerability Prioritization & Reporting', description: 'Prioritizes vulnerabilities and generates analytical reports.' },
    { label: 'Remediation Drafting', description: 'Drafts actionable remediation steps for identified vulnerabilities.' },
    { label: 'Remediation Execution', description: 'Executes approved remediation actions.' },
  ],
  threat_intel: [
    { label: 'Intelligence Gathering', description: 'Collects and analyses threat intelligence from multiple public sources.' },
    { label: 'Threat Assessment', description: 'Checks identified threats against managed device software to determine applicability and risk.' },
    { label: 'Remediation Guidance', description: 'Generates actionable remediation recommendations for identified vulnerabilities.' },
    { label: 'Security Reporting', description: 'Generates security reports, updates dashboards, and distributes relevant alerts.' },
    { label: 'Remediation Approval', description: 'Presents proposed remediation actions for analyst review, approval, or deferral.' },
  ],
  attack_detection: [
    { label: 'Device Activity Hunting', description: 'Retrieves managed devices from Microsoft Defender and searches the last 30 days of activity for techniques associated with 12 known attacks.' },
    { label: 'Evidence Correlation', description: 'Links hunting findings to managed devices, signed-in users, Defender alerts, and activity timelines to establish investigation context.' },
    { label: 'Remediation Drafting', description: 'Generates evidence-backed remediation steps for newly identified detections, including host isolation, malware scanning, and account resets.' },
    { label: 'Results & Report Publishing', description: 'Updates the Attack Detection dashboard, publishes analytical reports, and distributes alerts for identified attacks.' },
    { label: 'Remediation Execution', description: 'Prepares Defender scan-and-clean actions for detected attacks and executes approved actions when automated remediation is enabled.' },
  ],
  alert_triage: [
    { label: 'Incident Retrieval', description: 'Retrieves new and updated incidents from Microsoft Defender and Microsoft Sentinel.' },
    { label: 'Incident Classification', description: 'Analyzes incident evidence and classifies potential threats to determine the required response.' },
    { label: 'Incident Response', description: 'Executes response actions, escalates confirmed threats, and initiates Defender scans or cleanup when enabled.' },
    { label: 'Results & Report Publishing', description: 'Publishes incident classification results, triage metrics, and reports to the Alert Triage dashboard.' },
  ],
}

// What people see instead of 'Threat Intel/Vulnerability/Alert Triage' (the same names as the side menu)
export const AGENT_LABEL: Record<AgentKey, string> = { threat_intel: 'Threats', vulnerability: 'Vulnerabilities', alert_triage: 'Alert Triage', attack_detection: 'Attack Detection' }
// The four agents (each does one job end to end)
export const AGENT_SHORT: Record<AgentKey, string> = { threat_intel: 'Threat Intel', vulnerability: 'Vulnerability', alert_triage: 'Alert Triage', attack_detection: 'Attack Detection' }   // under an 'Agents' heading
export const AGENT_NAME: Record<AgentKey, string> = { threat_intel: 'Threat Intel Agent', vulnerability: 'Vulnerability Agent', alert_triage: 'Alert Triage Agent', attack_detection: 'Attack Detection Agent' }
export const AGENT_DOT: Record<AgentKey, string> = { threat_intel: 'bg-violet', vulnerability: 'bg-sky', alert_triage: 'bg-rose', attack_detection: 'bg-signal' }
// Fallback when there is no run history yet (measured 5 Oct: Vulnerability 11 s, Threat Intel 12 min with a big news day)
const UC_TYPICAL_FALLBACK: Record<AgentKey, string> = { threat_intel: 'usually 5–15 minutes', vulnerability: 'usually under a minute', alert_triage: 'seconds, plus about 10 s per new incident', attack_detection: 'usually about a minute' }

export function typicalLabel(uc: AgentKey, seconds?: number | null) {
  if (!seconds) return UC_TYPICAL_FALLBACK[uc]
  return seconds < 90 ? `usually about ${Math.max(5, Math.round(seconds / 5) * 5)} s` : `usually about ${Math.round(seconds / 60)} min`
}

async function fetchRuns(): Promise<Runs> {
  const res = await fetch('/api/runs')
  if (!res.ok) throw new Error(`CyberSuite could not complete the request (error ${res.status})`)
  return res.json()
}

async function postRun(uc: AgentKey): Promise<{ started: boolean; message: string }> {
  const res = await fetch(`/api/runs/${uc}`, { method: 'POST', headers: { 'X-Portal': 'run' } })
  return res.json()
}

interface RunCtx {
  runs: Runs | undefined
  /** true when the portal stopped answering: the page must not pretend a run is still ticking */
  offline: boolean
  start: (uc: AgentKey) => void
  starting: AgentKey | null
  /** the portal's reason when it refused the last start (e.g. another agent holds the same database) */
  refused: { uc: AgentKey; message: string } | null
  /** opens the full-screen run page (kept under its old name so every caller keeps working) */
  openDrawer: (focus?: AgentKey) => void
  /** runs started from this browser tab, so the page may offer to jump to the results */
  startedHere: Set<string>
}

const Ctx = createContext<RunCtx | null>(null)

export function RunProvider({ children }: { children: ReactNode }) {
  const qc = useQueryClient()
  const navigate = useNavigate()
  const [startedHere] = useState(() => new Set<string>())
  const { user } = useAuth()
  const { data: runs, isError } = useQuery({
    queryKey: ['runs'],
    queryFn: fetchRuns,
    enabled: !!user, // nothing to watch on the sign-in pages
    retry: 0,
    refetchInterval: (q) => (Object.values(q.state.data ?? {}).some((r) => r?.status === 'running') ? 1000 : 8000),
  })
  const mutation = useMutation({
    mutationFn: postRun,
    onSettled: () => qc.invalidateQueries({ queryKey: ['runs'] }),
  })

  // When a run finishes, refresh every page's data from the new results.
  const prev = useRef<Record<string, string | undefined>>({})
  useEffect(() => {
    for (const uc of AGENT_KEYS) {
      const now = runs?.[uc]?.status
      if (prev.current[uc] === 'running' && now && now !== 'running') {
        for (const key of ['summary', 'reports', 'run-history', uc]) qc.invalidateQueries({ queryKey: [key] })
      }
      prev.current[uc] = now
    }
  }, [runs, qc])

  const value: RunCtx = {
    runs,
    offline: isError,
    start: (uc) => {
      startedHere.add(uc)
      navigate(`/runs/${uc}`)
      mutation.mutate(uc)
    },
    starting: mutation.isPending ? (mutation.variables ?? null) : null,
    refused: mutation.data && !mutation.data.started && mutation.variables ? { uc: mutation.variables, message: mutation.data.message } : null,
    openDrawer: (f) => navigate(f ? `/runs/${f}` : '/runs'),
    startedHere,
  }
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>
}

export function useRuns() {
  const ctx = useContext(Ctx)
  if (!ctx) throw new Error('useRuns must be used inside RunProvider')
  return ctx
}

/** Seconds between two ISO times; ticks every second while `live` (and only then). */
export function useElapsed(from: string | null | undefined, to: string | null | undefined, live: boolean) {
  const [, tick] = useState(0)
  const frozen = useRef<number | null>(null)
  useEffect(() => {
    if (!live) return
    frozen.current = null
    const id = setInterval(() => tick((n) => n + 1), 1000)
    return () => clearInterval(id)
  }, [live])
  if (!from) return 0
  let end: number
  if (to) end = new Date(to).getTime()
  else if (live) end = Date.now()
  else end = frozen.current ??= Date.now() // not live (e.g. portal offline): stop the clock where it was
  return Math.max(0, Math.round((end - new Date(from).getTime()) / 1000))
}

export const fmtSeconds = (s: number) => {
  if (s < 60) return `${s} s`
  if (s < 3600) return `${Math.floor(s / 60)} min ${String(s % 60).padStart(2, '0')} s`
  return `${Math.floor(s / 3600)} h ${String(Math.floor((s % 3600) / 60)).padStart(2, '0')} min`
}
