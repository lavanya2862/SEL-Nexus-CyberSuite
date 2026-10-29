// Fix' automatic fixing = UC1's fix engine, reached through the portal (/api/fix -> UC1's /api/fix).
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'

export type FixStatus = 'proposed' | 'saved' | 'approved' | 'queued' | 'running' | 'done' | 'failed' | 'verified' | 'still_there' | 'gone' | 'info'
export type FixMethod = 'runcommand' | 'liveresponse'
export type FixSource = 'vulnerability' | 'threat_intel' | 'attack_detection'

/** The fix engine's name for each agent → the portal's agent key (UC_NAME / UC_DOT in lib/runs) */
export const SOURCE_UC = { vulnerability: 'uc3', threat_intel: 'uc1', attack_detection: 'attack' } as const
export type FixAgent = (typeof SOURCE_UC)[FixSource]
/** The fix engine writes UTC times without a zone */
export const fixTime = (s: string | null | undefined) => (s ? s.replace(' ', 'T') + (s.endsWith('Z') || s.includes('+') ? '' : 'Z') : null)

export interface FixRow {
  fix_id: string; device_name: string; opco: string; app: string; software_name: string; version: string
  action: 'upgrade' | 'remove' | 'replace' | 'setting' | 'respond' | 'none'; winget_id: string; stage: number; findings: number; cves: number
  max_epss: number; note: string; status: FixStatus
  method: FixMethod | null; approved_by: string | null; approved_at: string | null; started_at: string | null
  /** Save for later (on the run page's new-fix cards): reviewed, not fixed yet */
  saved_by?: string | null; saved_at?: string | null
  /** Which agents' runs proposed this fix, and when (UTC, no zone; null = before this was recorded) */
  found_by?: Partial<Record<FixSource, string | null>>
  /** The threats in the news that target this app on this computer (Threat Intel Agent), most urgent first */
  threats?: { id: string; title: string }[]
  finished_at: string | null; verified_at: string | null; message: string | null
  /** Security settings (kind 'setting', software_name 'setting:<config_id>'): what the fix engine changes */
  kind?: 'setting' | 'response' | null; config_id?: string | null; category?: string | null; subcategory?: string | null; impact?: number | null
  setting_kind?: 'asr' | 'defender' | 'registry' | null; setting_target?: string | null; setting_value?: number | null
  /** What the computer reported back after a fix run (UC1 fix engine). A setting reports numbers: the value before/after */
  result?: {
    exit?: number; engine?: string; reboot?: boolean; log?: string[]; wanted?: number; error?: string
    before?: { name?: string; version?: string } | number | null; after?: { name?: string; version?: string } | number | null
  } | null
}
export interface FixView {
  generated_at: string | null; inventory_at: string | null; stages: Record<string, string>; rows: FixRow[]
  totals: Record<FixStatus, number>
  events: { at: string; fix_id: string | null; text: string }[]
  probes: Record<string, { error?: string; method?: string; checked_at?: string; winget?: string; apps?: string[]; reboot_pending?: boolean }>
  default_method: FixMethod
  impact: { findings_open: number; findings_cleared: number }
  worker: { running: boolean; elsewhere: boolean; task: string; step: string; message: string }
}

export class FixDown extends Error {}

async function fetchFix(): Promise<FixView> {
  const res = await fetch('/api/fix')
  const body = await res.json().catch(() => ({}))
  if (res.status === 503 && body.uc1_down) throw new FixDown(body.error)
  if (!res.ok) throw new Error(body.error ?? `CyberSuite could not complete the request (error ${res.status})`)
  return body
}

export function useFix() {
  return useQuery({
    queryKey: ['fix'],
    queryFn: fetchFix,
    retry: false,
    refetchInterval: (q) => {
      const v = q.state.data
      const busy = v && (v.worker.running || v.worker.elsewhere || v.rows.some((r) => r.status === 'queued' || r.status === 'running'))
      return busy ? 1500 : 15000
    },
  })
}

async function post(action: string, body: object = {}) {
  const res = await fetch(`/api/fix/${action}`, { method: 'POST', headers: { 'X-Portal': 'fix', 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
  const out = await res.json().catch(() => ({}))
  if (!res.ok) throw new Error(out.error ?? `CyberSuite could not complete the request (error ${res.status})`)
  return out
}

/** approve / unapprove / save / unsave / run / probe / start-uc1, then refresh the view. */
export function useFixAction() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ action, ids, method }: { action: 'approve' | 'unapprove' | 'save' | 'unsave' | 'run' | 'probe' | 'start-uc1'; ids?: string[]; method?: FixMethod }) =>
      post(action, { ids: ids ?? [], ...(method ? { method } : {}) }),
    onSettled: () => {
      qc.invalidateQueries({ queryKey: ['fix'] })
      qc.invalidateQueries({ queryKey: ['runs'] })     // a decision can end a run's Fix stage
    },
  })
}

export const STATUS: Record<FixStatus, { label: string; tone: 'muted' | 'sky' | 'run' | 'teal' | 'good' | 'bad' | 'warn' }> = {
  proposed: { label: 'Proposed', tone: 'muted' },
  saved: { label: 'Deferred', tone: 'muted' },
  approved: { label: 'Approved', tone: 'sky' },
  queued: { label: 'Queued', tone: 'sky' },
  running: { label: 'Running…', tone: 'run' },
  done: { label: 'Pending verification', tone: 'teal' },
  verified: { label: 'Verified by Defender', tone: 'good' },
  failed: { label: 'Failed', tone: 'bad' },
  still_there: { label: 'Still listed by Defender', tone: 'warn' },
  gone: { label: 'Resolved before remediation', tone: 'muted' },
  info: { label: 'No action', tone: 'muted' },
}

export const ACTION_LABEL: Record<FixRow['action'], string> = { upgrade: 'Update', remove: 'Remove', replace: 'Replace', setting: 'Change setting', respond: 'Scan and clean', none: 'No action' }
export const isSetting = (r: Pick<FixRow, 'kind' | 'software_name'>) => r.kind === 'setting' || r.software_name.startsWith('setting:')
/** The app version a fix result reports (settings report plain numbers, so they have none) */
export const versionOf = (v: { version?: string } | number | null | undefined) => (typeof v === 'object' && v ? v.version : undefined)

const DEFENDER_OPTION: Record<string, string> = {
  DisableEmailScanning: 'Turns on e-mail scanning in Defender Antivirus',
  PUAProtection: 'Makes Defender block potentially unwanted apps',
  DisableRemovableDriveScanning: 'Makes Defender scan USB drives during a full scan',
  EnableNetworkProtection: 'Turns on Network Protection (blocks dangerous websites)',
  EnableControlledFolderAccess: 'Turns on Controlled folder access in audit mode (it only logs)',
}

/** One plain sentence: what the assistant changes on the computer for this setting. */
export function settingChange(r: Pick<FixRow, 'setting_kind' | 'setting_target' | 'setting_value'>): string {
  if (r.setting_kind === 'asr') return 'Turns on this attack-protection rule in block mode'
  if (r.setting_kind === 'defender') return DEFENDER_OPTION[r.setting_target ?? ''] ?? 'Changes a Defender Antivirus option'
  if (r.setting_kind === 'registry') return `Sets the Windows setting ${(r.setting_target ?? '').split('|').pop()} to ${r.setting_value}`
  return 'Changes it to what Microsoft recommends'
}
export const METHOD_LABEL: Record<FixMethod, string> = { runcommand: 'Azure Run Command', liveresponse: 'Defender Live Response' }
export const canApprove = (r: FixRow) => r.action !== 'none' && ['proposed', 'saved', 'failed', 'still_there', 'gone'].includes(r.status)
export const canWithdraw = (r: FixRow) => ['approved', 'failed', 'still_there'].includes(r.status)
