import { createContext, useContext, useEffect, useRef, useState, type ReactNode } from 'react'
import { useNavigate } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useAuth } from '@/lib/auth'

// attack = the Attack Detection Agent (UC1's attack-check run, on its own so it can run more often than the news)
export type UcKey = 'uc1' | 'uc3' | 'uc4' | 'attack'
export const UC_KEYS: UcKey[] = ['uc3', 'uc1', 'attack', 'uc4']
export type StepStatus = 'pending' | 'running' | 'done' | 'error' | 'skipped'

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

export interface RunState {
  run_id: string
  uc: UcKey
  status: 'running' | 'ok' | 'partial' | 'failed' | 'skipped'
  message: string
  started_at: string
  finished_at: string | null
  exit_code: number | null
  steps: RunStep[]
  facts: RunFact[]
  report_file: string | null
  lines: number
  log_tail: string[]
  typical_seconds?: number | null
}

export type Runs = Record<UcKey, RunState | null>

// What each run will do, shown before the first run (mirrors src/portal/runs.py).
export const PLANNED_STEPS: Record<UcKey, { label: string; description: string }[]> = {
  uc3: [
    { label: 'Extract', description: 'Collect every weakness from Microsoft Defender' },
    { label: 'Validate', description: "Save today's copy and check nothing is missing" },
    { label: 'Score and report', description: 'Rate each problem and prepare the report numbers' },
    { label: 'Advice agent', description: "AI writes the steps to fix every problem" },
  ],
  uc1: [
    { label: 'Gather threat news and understand it', description: 'New threats from 10 public feeds; AI reads each one and how likely it is to be used' },
    { label: 'Check if it affects us', description: 'Is the software these threats target on our computers?' },
    { label: 'Write fix steps', description: "AI writes how to fix each threat that affects us, checked against Defender's data" },
    { label: 'Write the report', description: 'The new threats that affect us and how to fix them, alerts and the report' },
  ],
  attack: [
    { label: 'Search our computers', description: 'Look in Microsoft Defender (last 30 days) for the warning signs from threat news and known attacker tricks' },
    { label: 'Connect the evidence', description: 'Who was logged in and what Defender said; earlier signs are kept, new ones added' },
    { label: 'Write resolution steps', description: 'AI writes how to resolve each new sign of attack, checked against the evidence' },
    { label: 'Publish', description: 'Update the Attack detection page and raise alerts' },
  ],
  uc4: [
    { label: 'Read new alerts', description: 'New or changed incidents from Microsoft Defender and Sentinel' },
    { label: 'Check each alert', description: 'AI looks at the evidence and decides: real threat, false alarm, or needs a person' },
    { label: 'Take action', description: 'Close false alarms, escalate real threats, ask Defender to scan or clean up (lab only, when switched on)' },
    { label: 'Update the queue', description: 'Results ready to review on the Alert triage page' },
  ],
}

// What people see instead of 'UC1/UC3/UC4' (the same names as the side menu)
export const UC_LABEL: Record<UcKey, string> = { uc1: 'Threat news', uc3: 'Vulnerabilities', uc4: 'Alert triage', attack: 'Attack detection' }
// The four agents (each does one job end to end)
export const UC_SHORT: Record<UcKey, string> = { uc1: 'Threat Intel', uc3: 'Vulnerability', uc4: 'Alert Triage', attack: 'Attack Detection' }   // under an 'Agents' heading
export const UC_NAME: Record<UcKey, string> = { uc1: 'Threat Intel Agent', uc3: 'Vulnerability Agent', uc4: 'Alert Triage Agent', attack: 'Attack Detection Agent' }
export const UC_DOT: Record<UcKey, string> = { uc1: 'bg-violet', uc3: 'bg-sky', uc4: 'bg-rose', attack: 'bg-signal' }
// Fallback when there is no run history yet (measured 5 Oct: UC3 11 s, UC1 12 min with a big news day)
const UC_TYPICAL_FALLBACK: Record<UcKey, string> = { uc1: 'usually 5–15 minutes', uc3: 'usually under a minute', uc4: 'seconds, plus about 10 s per new incident', attack: 'usually about a minute' }

export function typicalLabel(uc: UcKey, seconds?: number | null) {
  if (!seconds) return UC_TYPICAL_FALLBACK[uc]
  return seconds < 90 ? `usually about ${Math.max(5, Math.round(seconds / 5) * 5)} s` : `usually about ${Math.round(seconds / 60)} min`
}

async function fetchRuns(): Promise<Runs> {
  const res = await fetch('/api/runs')
  if (!res.ok) throw new Error(`Portal API answered ${res.status}`)
  return res.json()
}

async function postRun(uc: UcKey): Promise<{ started: boolean; message: string }> {
  const res = await fetch(`/api/runs/${uc}`, { method: 'POST', headers: { 'X-Portal': 'run' } })
  return res.json()
}

interface RunCtx {
  runs: Runs | undefined
  /** true when the portal stopped answering: the page must not pretend a run is still ticking */
  offline: boolean
  start: (uc: UcKey) => void
  starting: UcKey | null
  /** opens the full-screen run page (kept under its old name so every caller keeps working) */
  openDrawer: (focus?: UcKey) => void
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
    for (const uc of UC_KEYS) {
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
