// UC3's own dashboard data (GET /api/uc3/dashboard = the bundle build.py packs into its HTML dashboard).
// The helpers mirror UC3's app.js so every number matches the UC3 dashboard exactly.
import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useShownName } from '@/lib/deviceNames'
import { useFilters } from '@/lib/filters'

export const SEVS = ['Critical', 'High', 'Medium', 'Low', 'Unrated'] as const
export type Sev = (typeof SEVS)[number]
const EXPL_RANK: Record<string, number> = { ExploitIsInKit: 3, ExploitIsVerified: 2, ExploitIsPublic: 1, NoExploit: 0 }
const PRIO_RANK: Record<string, number> = { P1: 1, P2: 2, P3: 3, P4: 4 }
export const BUCKETS = ['0-30', '31-60', '61-90', '90+'] as const
const PRETTY: Record<string, string> = {
  acrobat_reader_dc: 'Acrobat Reader', visual_studio_code: 'VS Code', meetings: 'Zoom', vlc_media_player: 'VLC',
  'notepad++': 'Notepad++', '7-zip': '7-Zip', edge_chromium: 'Edge', 'edge_chromium-based': 'Edge', jre: 'Java',
  winrar: 'WinRAR', openssl: 'OpenSSL', gimp: 'GIMP', putty: 'PuTTY', libreoffice: 'LibreOffice', nodejs: 'Node.js', powershell: 'PowerShell 7',
}
export const pretty = (s: string) => PRETTY[s] || (s ? s.charAt(0).toUpperCase() + s.slice(1).replace(/_/g, ' ') : '')

export interface Uc3Device {
  id: string; name: string; opco: string; os: string | null; osv: string | null; tags: string[]; last_seen: string | null
  health: string; exposure: string | null; stale: boolean; rbac_group_name?: string; findings: number; critical: number; p1: number
}
export interface Uc3Run {
  run_date: string; started_at: string; duration_seconds: number; export_generated_time: string | null; machines: number
  /** vulnerability_rows = rows downloaded; repeats = findings Defender listed twice (one copy kept); vulnerabilities = kept */
  vulnerability_rows: number; repeats?: number | null; vulnerabilities?: number | null; defender_count: number | null; coverage: number | null; change_rows: number; retries: number; quality: string | null
}
export interface Uc3Check { name: string; status: string; value: string; expected: string; message: string }
/** How a card is remediated, in Defender's remediation-type words (UC3 fixes.py decides; first match wins in that order). */
export const FIX_TYPES = {
  upgrade: 'Software upgrade',
  os: 'OS security update',
  none: 'Attention required',
  update: 'Software update',
} as const
export type FixKind = keyof typeof FIX_TYPES
/** The fix_type values cards carried before the Defender wording, so older runs still sort into the right type */
const OLD_FIX_TYPES: Record<string, FixKind> = {
  'Upgrade to a supported version': 'upgrade', 'Install the Windows update': 'os',
  'No fix yet: protect it another way': 'none', 'Update the app': 'update',
}
/** Cards built before fix types existed have none: they were all app updates or upgrades. */
export const fixKind = (a: Pick<Uc3FixApp, 'fix_type'>): FixKind =>
  (Object.entries(FIX_TYPES).find(([, t]) => t === a.fix_type)?.[0] as FixKind | undefined) ?? OLD_FIX_TYPES[a.fix_type ?? ''] ?? 'update'
/** Remediation priority by urgency level: shown instead of the run's stored label, so older runs read the same */
export const PRIORITY: Record<number, string> = { 1: 'High', 2: 'Medium', 3: 'Low' }
export const pastEos = (a: Uc3FixApp) => a.versions.filter((v) => v.eos?.status === 'EOS Version')
export const nearEos = (a: Uc3FixApp) => a.versions.filter((v) => v.eos?.status === 'Upcoming EOS Version')

export interface Uc3FixApp {
  key: string; app: string; fix_type?: string; os?: boolean
  /** CVEs Defender says have no security update from the vendor yet */
  no_patch?: string[]
  versions: { version: string; cves: number; devices: string[]; folders: string[]; eos?: { status: string; date: string | null } | null }[]
  devices: { name: string; opco: string }[]; opcos: string[]; findings: number; cves: number; p1: number; critical: number; high: number
  overdue: number; fix_by: string | null; oldest_days: number
  urgency: { level: 1 | 2 | 3; label: string }
  fix: { action: string; command: string | null; url: string | null; note: string | null }
  ai: { what_is_wrong?: string; worst_case?: string; why_now?: string; verify?: string; side_effects?: string; steps?: string[] } | null
  source: string; model: string | null; guard_notes: string[]
}
/** One wrong security setting (Defender secure configuration assessment), all computers together, with UC3's advice */
export interface Uc3FixSetting {
  key: string; kind: 'setting'; config_id: string; app: string; category: string; subcategory: string | null; impact: number
  fix_type: string; urgency: { level: 1 | 2 | 3; label: string }; user_impact: boolean
  devices: { name: string; opco: string; context?: string }[]; opcos: string[]
  microsoft: { description?: string; risk?: string; remediation?: string; links?: string[] }
  fix: { action: string; command: string | null; note: string | null; url: string | null; in_catalog: boolean }
  ai: Uc3FixApp['ai']; source: string; model: string | null
}
export interface Uc3Data {
  meta: { snapshot: string; built_at: string; source: string; sla: Record<string, number> }
  run: Uc3Run | null
  runs: Uc3Run[]
  kql: { rows_exist: number; rows_returned: number; coverage: number; measured_at: string } | null
  devices: Uc3Device[]
  f: { cols: string[]; rows: unknown[][] }
  /** The latest run's download: the full list, plus Defender's own change list since the run before (absent in older data) */
  download?: {
    run_date: string; started_at: string | null; export_generated_time: string | null; previous_export_time: string | null
    changes_since: string | null
    counts: { machines?: number; vulnerability_rows?: number; new?: number; fixed?: number; updated?: number; previous_rows?: number | null; defender_refreshed?: boolean; export_reused?: boolean }
  } | null
  /** Vulnerabilities Defender reported as fixed (newest first); absent in data built before 13 Oct */
  fixed?: { cols: string[]; rows: unknown[][] }
  daily: [string, string, string, string, number, number, number][]
  changes: [string, string, string, string, number][]
  remed: [string, string, string, number][]
  dq: Uc3Check[]
  status: { status: string; message: string; run_at: string } | null
  fixes: {
    snapshot: string; built_at: string; ai_enabled: boolean; ai_message: string | null; model: string | null; stale?: boolean
    kb: { status: string; entries: number }; counts: { apps: number; ai: number; corrections: number }; apps: Uc3FixApp[]
    settings?: Uc3FixSetting[]
  } | null
}

export interface FixedFinding {
  d: number; sw: string; ver: string; cve: string; sev: Sev; fixed: string; fs: string | null; days: number | null; dev: Uc3Device; o: string
}

/** The fixed list as objects, filtered by the portal-wide OpCo filter. */
export function useFixedFindings(data: Uc3Data | undefined): FixedFinding[] {
  const { opco } = useFilters()
  return useMemo(() => {
    if (!data?.fixed) return []
    const cols = data.fixed.cols
    return data.fixed.rows
      .map((r) => {
        const f = Object.fromEntries(cols.map((c, i) => [c, r[i]])) as unknown as FixedFinding
        f.dev = data.devices[f.d]
        f.o = f.dev?.opco ?? ''
        return f
      })
      .filter((f) => opco === 'all' || f.o === opco)
  }, [data, opco])
}

export interface Finding {
  d: number; sw: string; ver: string; cve: string; sev: Sev; cvss: number | null; ex: string; pr: string; age: number
  bk: string; br: number; upd: string; fs: string
  /** 0 = the vendor has no security update yet; absent in data built before 14 Oct */
  ua?: number
  dev: Uc3Device; o: string; u: string
}

async function fetchUc3(): Promise<Uc3Data> {
  const res = await fetch('/api/uc3/dashboard')
  if (!res.ok) throw new Error((await res.json().catch(() => null))?.error ?? `CyberSuite could not complete the request (error ${res.status})`)
  const data: Uc3Data = await res.json()
  for (const card of [...(data.fixes?.apps ?? []), ...(data.fixes?.settings ?? [])]) if (card.ai) card.ai = scrubAi(card.ai)
  for (const s of data.fixes?.settings ?? []) {
    s.microsoft = { ...s.microsoft, description: dropExploitTalk(s.microsoft.description), risk: dropExploitTalk(s.microsoft.risk) }
  }
  return data
}

/** The portal never says a hole is exploited or used by attackers (the agent's guard does the same from its next run;
 *  this covers texts written before). Microsoft's product names "Exploit Guard / protection" may stay. */
const exploitTalk = (s: string) => /exploit|attack kit|in the wild|used by attackers|known.exploited|weaponi[sz]|proof.of.concept/i
  .test(s.replace(/exploit (?:guard|protection)/gi, ''))
const dropExploitTalk = (t?: string) => t && t.split(/(?<=[.!?])\s+/).filter((s) => !exploitTalk(s)).join(' ')
function scrubAi(ai: NonNullable<Uc3FixApp['ai']>): NonNullable<Uc3FixApp['ai']> {
  return {
    ...ai, what_is_wrong: dropExploitTalk(ai.what_is_wrong), worst_case: dropExploitTalk(ai.worst_case), why_now: dropExploitTalk(ai.why_now),
    verify: dropExploitTalk(ai.verify), side_effects: dropExploitTalk(ai.side_effects), steps: ai.steps?.filter((s) => !exploitTalk(s)),
  }
}

/** One open vulnerability of one app version on one computer */
export interface VmCve { cve: string; sev: string; cvss: number | null; nofix: boolean; fs: string | null }
/** One app version on one computer: its open vulnerabilities (worst first), when Defender first found them, and its own
 *  deadline (the earliest first seen + the patching rule's days for that severity) */
export interface VmDetail { cves: VmCve[]; firstSeen: string | null; due: string | null }
export const vmKey = (device: string, software: string, version: string) => `${device}|${software}|${version}`.toLowerCase()

const vmCache = new WeakMap<Uc3Data, Map<string, VmDetail>>()
/** vmKey → VmDetail for every computer + app version with open vulnerabilities (computed once per data load) */
export function vmDetails(data: Uc3Data): Map<string, VmDetail> {
  const hit = vmCache.get(data)
  if (hit) return hit
  const [d, sw, ver, cve, sev, cvss, ua, fs] = ['d', 'sw', 'ver', 'cve', 'sev', 'cvss', 'ua', 'fs'].map((k) => data.f.cols.indexOf(k))
  const lists = new Map<string, VmCve[]>()
  for (const r of data.f.rows) {
    const k = vmKey(data.devices[r[d] as number]?.name ?? '', String(r[sw]), String(r[ver]))
    const list = lists.get(k) ?? []
    list.push({ cve: String(r[cve]), sev: String(r[sev]), cvss: (r[cvss] as number) ?? null, nofix: r[ua] === 0, fs: r[fs] ? String(r[fs]).slice(0, 10) : null })
    lists.set(k, list)
  }
  const rank = (s: string) => { const i = (SEVS as readonly string[]).indexOf(s); return i < 0 ? SEVS.length : i }
  const earliest = (xs: (string | null)[]) => xs.filter((x): x is string => !!x).sort()[0] ?? null
  const out = new Map<string, VmDetail>()
  for (const [k, list] of lists) {
    list.sort((a, b) => rank(a.sev) - rank(b.sev) || (b.cvss ?? 0) - (a.cvss ?? 0))
    const dues = list.map((c) => (c.fs && data.meta.sla[c.sev] != null ? addDays(c.fs, data.meta.sla[c.sev]) : null))
    out.set(k, { cves: list, firstSeen: earliest(list.map((c) => c.fs)), due: earliest(dues) })
  }
  vmCache.set(data, out)
  return out
}

export function useUc3Data() {
  return useQuery({ queryKey: ['uc3'], queryFn: fetchUc3, refetchInterval: 60_000 })
}

/** Findings as objects, filtered by the portal-wide OpCo filter and this page's severity chips. */
export function useUc3View(data: Uc3Data | undefined) {
  const { opco } = useFilters()
  const [sevs, setSevs] = useState<Set<Sev>>(new Set(SEVS))
  const all = useMemo<Finding[]>(() => {
    if (!data) return []
    const cols = data.f.cols
    return data.f.rows.map((r) => {
      const f = Object.fromEntries(cols.map((c, i) => [c, r[i]])) as unknown as Finding
      f.dev = data.devices[f.d]
      f.o = f.dev?.opco ?? ''
      f.u = `Update ${pretty(f.sw)} (installed ${f.ver})`
      return f
    })
  }, [data])
  const keepOpco = (o: string) => opco === 'all' || o === opco
  const rows = useMemo(() => all.filter((f) => keepOpco(f.o) && sevs.has(f.sev)), [all, opco, sevs]) // eslint-disable-line react-hooks/exhaustive-deps
  const opcos = useMemo(() => [...new Set((data?.devices ?? []).map((d) => d.opco))].sort().filter(keepOpco), [data, opco]) // eslint-disable-line react-hooks/exhaustive-deps
  const toggleSev = (s: Sev) =>
    setSevs((cur) => {
      const next = new Set(cur)
      if (next.has(s)) {
        if (next.size > 1) next.delete(s)
      } else next.add(s)
      return next
    })
  return { all, rows, opcos, opco, keepOpco, sevs, toggleSev, activeSevs: [...SEVS].filter((s) => sevs.has(s)) }
}

export type Uc3View = ReturnType<typeof useUc3View>

/** " · OpCo" after a computer's name, or nothing when the group would only repeat the name on screen
 *  (config/device_names.csv shows both opca-wks-01 and OpCo A as "VM 1", which read "VM 1 · VM 1"). */
export function useGroupAfter() {
  const shown = useShownName()
  return (f: { dev?: Uc3Device; o: string }) =>
    f.o && shown(f.o).toLowerCase() !== shown(f.dev?.name ?? '').toLowerCase() ? ` · ${f.o}` : ''
}

/** One finding = one CVE in one app version on one computer; this key names it in the detail page's address. */
export const findingKey = (f: Finding) => [f.dev?.id, f.cve, f.sw, f.ver].join('|')
export const findingHref = (f: Finding) => `/uc3/vuln/${encodeURIComponent(findingKey(f))}`

export function groupBy<T>(a: T[], key: (t: T) => string): Record<string, T[]> {
  return a.reduce<Record<string, T[]>>((m, r) => {
    const k = key(r)
    ;(m[k] ||= []).push(r)
    return m
  }, {})
}
export const sumBy = <T,>(a: T[], f: (t: T) => number) => a.reduce((t, r) => t + f(r), 0)
export const daysBetween = (a: string, b: string) => Math.round((new Date(b).getTime() - new Date(a).getTime()) / 86400000)
export const addDays = (d: string, n: number) => {
  const x = new Date(d)
  x.setDate(x.getDate() + n)
  return x.toISOString().slice(0, 10)
}

export function cveList(rows: Finding[]) {
  return Object.entries(groupBy(rows, (f) => f.cve))
    .map(([cve, fs]) => {
      const best = fs.reduce((a, f) => ((EXPL_RANK[f.ex] || 0) > (EXPL_RANK[a.ex] || 0) ? f : a), fs[0])
      return {
        cve, fs, sev: fs[0].sev, cvss: Math.max(...fs.map((f) => f.cvss ?? 0)), ex: best.ex,
        pr: fs.map((f) => f.pr).sort()[0], devs: new Set(fs.map((f) => f.d)).size,
      }
    })
    .sort((a, b) => PRIO_RANK[a.pr] - PRIO_RANK[b.pr] || b.devs - a.devs || b.cvss - a.cvss)
}

export function downloadCsv(rows: Finding[], snapshot: string, opco: string) {
  const cols = ['device', 'opco', 'software', 'version', 'cve', 'severity', 'cvss', 'priority', 'age_days', 'sla_breached', 'recommended_update', 'first_seen']
  const q = (v: unknown) => {
    const s = String(v ?? '')
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s
  }
  const lines = [cols.join(',')].concat(
    rows.map((f) => [f.dev?.name, f.o, f.sw, f.ver, f.cve, f.sev, f.cvss, f.pr, f.age, f.br ? 'yes' : 'no', f.upd, f.fs].map(q).join(',')),
  )
  const a = document.createElement('a')
  a.href = URL.createObjectURL(new Blob(['﻿' + lines.join('\r\n')], { type: 'text/csv;charset=utf-8' }))
  a.download = `vulnerability_findings_${snapshot}${opco === 'all' ? '' : '_' + opco.replace(/\W+/g, '_')}.csv`
  a.click()
  setTimeout(() => URL.revokeObjectURL(a.href), 1000)
}

export const CHECK_LABEL: Record<string, string> = {
  completeness: 'Complete', coverage_vs_defender: 'Coverage vs Defender', not_empty: 'Data received', freshness: 'Fresh',
  no_duplicates: 'No duplicates', mandatory_fields: 'Key fields filled', volume_change: 'Normal volume', devices_known: 'Devices known',
  opco_mapping: 'VM mapping', stale_devices: 'Stale devices', unrated_cves: 'Not yet rated',
}
