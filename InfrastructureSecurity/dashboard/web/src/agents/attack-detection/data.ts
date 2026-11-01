// The Attack Detection Agent's own data: its data/out/findings.json, read by the dashboard's attack_detection adapter.
// Nothing here comes from the Threat Intel Agent.

import { useQuery } from '@tanstack/react-query'
import type { Hit, Hunt } from '@/agents/threat-intel/data'
import { STATUS, type FixStatus } from '@/agents/fixes/data'

export interface AttackDevice { device_id: string; device_name: string; opco: string; os_platform: string; last_seen: string }
export interface AttackSearch { key: string; name: string; technique: string; needs: string; query?: string }
/** One of the 12 attacks searched for (config/attacks.csv in the agent) */
export interface Attack { attack: number; name: string; description: string; tactics: string; severity: string; lab_test: string; searches: AttackSearch[] }
/** The scan-and-clean response the fix engine proposed for a finding, and where it stands */
export interface FindingRemediation { fix_id: string; status: string }
export interface Finding extends Hit {
  search: string; search_name: string; technique: string; attack: number; attack_name: string; severity: string
  remediation?: FindingRemediation | null
  /** the hunt result rows behind the finding (newest first, at most 25) and how many there are in total */
  events?: { time: string; account: string | null; columns: Record<string, unknown> }[]
  event_count?: number
  last_hit?: string | null
  sign_ins?: { account: string; logon_types?: string[]; last_logon?: string; logons?: number }[]
}
export interface AttackData { generated: string; run_id: string | null; hits: Finding[]; hunts: Hunt[]; devices: AttackDevice[]; attacks: Attack[] }

async function getJson<T>(url: string): Promise<T> {
  const res = await fetch(url)
  if (!res.ok) throw new Error((await res.json().catch(() => null))?.error ?? `CyberSuite could not complete the request (error ${res.status})`)
  return res.json()
}

export const useAttackDetectionData = () =>
  useQuery({ queryKey: ['attack_detection'], queryFn: () => getJson<AttackData>('/api/attack-detection/data'), refetchInterval: 60_000 })

export const SEVERITIES = ['Critical', 'High', 'Medium', 'Low'] as const
export const sevRank = (s: string) => { const i = SEVERITIES.indexOf(s as typeof SEVERITIES[number]); return i < 0 ? 9 : i }

/** Remediation status with the Fix Centre's own label (the same words as on the Remediation page), and a tone. */
export function remediationLabel(r?: FindingRemediation | null): { label: string; tone: 'bad' | 'warn' | 'good' | 'none' } {
  if (!r) return { label: 'No response proposed', tone: 'none' }
  const label = STATUS[r.status as FixStatus]?.label ?? r.status
  const tone = ['failed', 'still_there'].includes(r.status) ? 'bad' : ['done', 'verified'].includes(r.status) ? 'good'
    : ['proposed', 'approved', 'queued', 'running'].includes(r.status) ? 'warn' : 'none'
  return { label, tone }
}
