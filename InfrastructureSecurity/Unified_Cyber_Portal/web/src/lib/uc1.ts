// UC1's own data: GET /api/uc1/dashboard (= dashboard.gather(), the bundle its dashboard is drawn from)
// and GET /api/uc1/threats/<id> (one entry of its site_data.json, the detail page data).
import { useQuery } from '@tanstack/react-query'
import { useSearchParams } from 'react-router-dom'

export type Rating = 'Critical' | 'High' | 'Medium' | 'Low'

export interface ExplorerRow {
  id: string; title: string; source: string; kind: string; url: string | null; test: boolean; published: string | null
  rating: Rating; score: number; why: string; chips: string[]; action: string | null; summary: string | null; devices: string | null; hits: number
  first_seen?: string   // when UC1 collected it, "YYYY-MM-DD HH:MM" UTC (older UC1 output doesn't have it)
  /** How it reaches us: a sign of attack, a CVE Defender lists on our computer, one it doesn't list yet (the installed
   *  version is affected), or one it never listed after 30 days (EARLY_DAYS). null = not on our computers. Older UC1 output: absent. */
  match?: 'sign' | 'defender' | 'early' | 'closed' | null
  /** Its CVEs on our computers ("cve" = Defender lists it), with when the CVE was announced and when we first knew */
  on_us?: { cve: string; device: string; app: string; version: string; match: 'cve' | 'early' | 'closed'; announced: string; known: string }[]
}
/** The numbers the period filter changes, for threats UC1 collected since `start` (dashboard._window). */
export interface Uc1Window {
  start: string; days: string[]; series: Record<string, number[]>; earlier: Record<string, number>
  ratings: Record<Rating, number>; threats_collected: number
  sources?: Record<string, { threats: number; clues: number; affect: number }>   // per source: threats, distinct clues, threats that affect us
  funnel: { stage: string; value: number; note: string }[]; tactics: { tactic: string; threats: number }[]; ioc_types: Record<string, number>
}
export interface Hit {
  finding_id: string; threat_id: string; hunt_id: string; kind: string; device_name: string; opco: string; detail: string
  users: string[]; alerts: string[]; timeline: { time: string; what: string; account: string | null }[]
  is_test: boolean; first_hit: string; created_at: string; title: string
  resolution?: Resolution | null
}
/** How to resolve a sign of attack: written by AI and checked by UC1, or standard steps when the AI was unavailable */
export interface Resolution { what_happened: string; steps: string[]; done_when: string; source: 'ai' | 'standard'; model: string | null }
export interface Hunt { name: string; origin: string; technique: string | null; status: string; row_count: number; error: string | null }
export interface Feed { feed: string; last_run_at: string | null; last_success_at: string | null; last_status: string; last_count: number; last_error: string | null }
export interface Alert { alert_id: string; threat_id: string; rating: Rating; title: string; message: string; is_test: boolean; created_at: string; delivered: string }

export interface Uc1Data {
  generated: string
  days: string[]
  series: Record<string, number[]>
  ratings: Record<Rating, number>
  posture: { rating: Rating; urgent: number; affecting: number }
  funnel: { stage: string; value: number; note: string }[]
  matrix: { device_name: string; app: string; cves: number }[]
  apps: string[]
  scatter: [number, number, string, string][]   // cvss, epss, cve, app
  tactics: { tactic: string; threats: number }[]
  ioc_types: Record<string, number>
  ioc_hits: number
  threats_collected?: number   // last 30 days without the clue bundles (older UC1 output doesn't have it)
  top: ExplorerRow[]
  explorer: ExplorerRow[]
  hits: Hit[]
  devices: { device_name: string; opco: string; os_platform: string; last_seen: string; exposed: number; hits: number; test_hits: number; vulns: number }[]
  alerts: Alert[]
  feeds: Feed[]
  hunts: Hunt[]
  model: string | null
  metrics: Record<string, number | string | null | Record<string, number>>
  periods?: Record<Period, Uc1Window>   // older UC1 output doesn't have it
}

/** Period filter of the Threats page, kept in the address (?period=7 or 30; none = all time). */
export type Period = '7' | '30' | 'all'
export const PERIODS: [Period, string][] = [['7', '7 days'], ['30', '30 days'], ['all', 'All time']]
export function usePeriod(): [Period, (p: Period) => void] {
  const [params, setParams] = useSearchParams()
  const raw = params.get('period')
  const period: Period = raw === '7' || raw === '30' ? raw : 'all'
  const set = (p: Period) => setParams((prev) => {
    const next = new URLSearchParams(prev)
    if (p === 'all') next.delete('period')
    else next.set('period', p)
    return next
  }, { replace: true })
  return [period, set]
}
/** The period's numbers; older UC1 output has none, so its fixed windows stand in. */
export function periodData(d: Uc1Data, p: Period): Uc1Window {
  return d.periods?.[p] ?? {
    start: d.days[0] ?? d.generated, days: d.days, series: d.series, earlier: {}, ratings: d.ratings,
    threats_collected: d.threats_collected ?? 0, funnel: d.funnel, tactics: d.tactics, ioc_types: d.ioc_types,
  }
}
/** True when something UC1 collected at `when` ("YYYY-MM-DD HH:MM", UTC) falls in the period. */
export const inPeriod = (w: Uc1Window, p: Period, when?: string) =>
  p === 'all' || !when || when >= w.start.replace('T', ' ').slice(0, 16)
export const periodLabel = (w: Uc1Window, p: Period) => (p === 'all' ? `since ${w.start.slice(0, 10)}` : `last ${p} days`)

export interface ThreatDetail {
  id: string; title: string; source: string; kind: string; url: string | null; published: string | null; first_seen: string; is_test: boolean
  text: string; score: number; rating: Rating; factors: string[]; why: string; summary: string | null; threat_type: string | null
  confidence: string | null; ai_status: string; ai_model: string | null; dropped: Record<string, unknown>; analysed_at: string | null
  actions: string[]
  cves: { id: string; origin: string; cvss: number | null; severity: string | null; epss: number | null; epss_percentile: number | null; description: string | null }[]
  techniques: { id: string; origin: string; name: string; tactics: string; url: string; reason?: string }[]
  products: { value: string; origin: string }[]
  ioc_count: number
  iocs: { type: string; value: string; origin: string }[]
  exposure: { device_name: string; opco: string; match_type: string; detail: string; recommended_update: string }[]
  findings: {
    kind: string; device: string; opco: string; detail: string; is_test: boolean; first_hit: string; hunt_id: string
    users: { account: string; logon_types: string[]; last_logon: string; logons: number }[]
    alerts: { id: string; title: string; severity: string; status: string; category: string; time: string }[]
    timeline: { time: string; what: string; account: string | null }[]
    resolution?: Resolution | null
  }[]
  hunts: { name: string; origin: string; technique: string | null; status: string; row_count: number; error: string | null; started_at: string; query: string }[]
  /** How to fix it on our computers (only for threats that affect us): written by AI and checked, or standard steps */
  fix?: Pick<Resolution, 'steps' | 'done_when' | 'source' | 'model'> | null
}

async function getJson<T>(url: string): Promise<T> {
  const res = await fetch(url)
  if (!res.ok) throw new Error((await res.json().catch(() => null))?.error ?? `CyberSuite could not complete the request (error ${res.status})`)
  return res.json()
}

export const useUc1Data = () => useQuery({ queryKey: ['uc1'], queryFn: () => getJson<Uc1Data>('/api/uc1/dashboard'), refetchInterval: 60_000 })
/** One clue (IP, domain, web link, file hash) from GET /api/uc1/clues (UC1's clues.json), value made safe (hxxp, [.]). */
export interface Clue {
  type: string; value: string; malware: string; source: string; first_seen: string; test: boolean
  threat_id: string; threat: string; seen_on: string[]
  collected?: string   // when UC1 last collected it, "YYYY-MM-DD HH:MM" UTC (the period filter uses it)
}
export const useUc1Clues = (enabled = true) =>
  useQuery({ queryKey: ['uc1', 'clues'], queryFn: () => getJson<Clue[]>('/api/uc1/clues'), enabled, staleTime: 60_000 })
/** The IOC feeds' daily bundles ("ThreatFox: X indicators"): lists of clues, not threats. */
export const isClueBundle = (kind: string) => kind === 'ioc'

export const useThreat = (id: string) =>
  useQuery({ queryKey: ['uc1', 'threat', id], queryFn: () => getJson<ThreatDetail>(`/api/uc1/threats/${encodeURIComponent(id)}`), enabled: !!id })

/** One app's vulnerabilities that a threat in the news names (GET /api/uc1/matches/<software>, UC1's threat_matches.json).
 *  found = when UC1 first collected the news, published = when the source published it ("YYYY-MM-DD"). */
export interface ThreatMatches {
  built_at: string | null
  rows: { device: string; version: string; cve: string; threat: string }[]
  threats: Record<string, { title: string; found: string | null; published: string | null; score: number }>
}
export const useThreatMatches = (software: string) =>
  useQuery({ queryKey: ['uc1', 'matches', software], queryFn: () => getJson<ThreatMatches>(`/api/uc1/matches/${encodeURIComponent(software)}`), enabled: !!software, staleTime: 60_000, retry: false })
/** Per app (Defender's software name): how many of its vulnerabilities are in the news; split = [still open, fixed];
 *  vm_cves = per computer + app + version (vmKey), the CVEs a threat in the news names */
export const useThreatMatchCounts = () =>
  useQuery({ queryKey: ['uc1', 'matches'], queryFn: () => getJson<{ built_at: string | null; counts: Record<string, number>; split?: Record<string, [number, number]>; vm_cves?: Record<string, string[]> }>('/api/uc1/matches'), staleTime: 60_000, retry: false })

export const RATINGS: Rating[] = ['Critical', 'High', 'Medium', 'Low']
export const FEED_NAME: Record<string, string> = {
  attack: 'MITRE ATT&CK', nvd: 'NVD', epss: 'FIRST EPSS', ncsc_nl: 'NCSC-NL', cert_eu: 'CERT-EU', msrc: 'Microsoft MSRC',
  threatfox: 'ThreatFox', urlhaus: 'URLhaus', malwarebazaar: 'MalwareBazaar', otx: 'AlienVault OTX', abusech: 'abuse.ch', lab_test: 'Validation',
}
export const IOC_NAME: Record<string, string> = {
  ip: 'IP addresses', domain: 'Domains', url: 'Web links', sha256: 'Files (SHA-256)', sha1: 'Files (SHA-1)', md5: 'Files (MD5)',
}
/** A hidden PowerShell command that UC1 decoded, if this timeline event has one. */
export const decoded = (what: string) => String(what).split(' | decoded command: ')[1] ?? null
export const threatHref = (id: string) => `/uc1/threat/${encodeURIComponent(id)}`
/** A "threat" UC1 made from activity found on our computers (a sign of attack), not from the news */
export const isSign = (kind: string) => kind === 'hunt'

// ---- signs of attack in plain words (Attack detection page and the detail page)
export interface AttackType { label: string; category: string; what: string }

/** What kind of attack a sign is, from the search that found it ("Antivirus detections" → "Malware caught by antivirus"). */
export function attackType(kind: string, detail: string): AttackType {
  const d = detail.toLowerCase()
  if (kind === 'ioc_hit') {
    const [, type = '', value = ''] = detail.match(/^matched (\w+) (.+)$/) ?? []
    if (type === 'domain' || type === 'url')
      return { label: 'Connection to a known malicious domain', category: 'Malicious domain', what: `The device connected to ${value}, a domain on a known-malicious list.` }
    if (type === 'ip')
      return { label: 'Connection to a known malicious IP address', category: 'Malicious IP', what: `The device connected to ${value}, an address on a known-malicious list.` }
    return { label: 'Known malicious file found', category: 'Malware', what: 'A file on the device matches a known malicious file.' }
  }
  if (d.includes('powershell') && (d.includes('encoded') || d.includes('hidden')))
    return { label: 'Encoded PowerShell command', category: 'Obfuscated script', what: 'A PowerShell command was run in encoded form, a technique used to conceal what a script does.' }
  if (d.includes('antivirus'))
    return { label: 'Malware caught by antivirus', category: 'Malware', what: 'Microsoft Defender antivirus found a harmful file on the device.' }
  if (/\bt1204\b/.test(d) || d.includes('user execution'))
    return { label: 'Program started from a document', category: 'Malicious document', what: 'A document application (such as a PDF reader) launched another program, a common technique of malicious documents.' }
  const name = detail.replace(/^AI-drafted:\s*/, '').replace(/^T\d{4}(\.\d{3})?\s+/, '')
  return { label: name, category: 'Suspicious activity', what: `Activity that matches a known attacker trick: ${name}.` }
}

/** Defender stopped it: an antivirus finding whose Defender alert says the malware was prevented, blocked or removed. */
export const wasBlocked = (t: AttackType, alerts: string[]) =>
  t.category === 'Malware' && alerts.some((a) => /prevented|blocked|removed|quarantined/i.test(a))

/** The key facts from the evidence ("File eicar.txt · Started by powershell.exe"), read from the timeline. */
export function evidenceOf(timeline: { what: string }[]): string[] {
  const vals = (key: string) => [...new Set(timeline.flatMap((e) => [...e.what.split(' | decoded command: ')[0].matchAll(new RegExp(`(?<![A-Za-z])${key}=([^;]+)`, 'g'))].map((m) => m[1].trim().replace(/^"|"$/g, ''))))]
  const out: string[] = []
  const urls = vals('RemoteUrl'), ips = vals('RemoteIP'), files = vals('FileName'), by = vals('InitiatingProcessFileName')
  if (urls.length) out.push(`Website ${urls.join(', ')}` + (ips.length ? ` (${ips.join(', ')})` : ''))
  else if (ips.length) out.push(`Address ${ips.join(', ')}`)
  if (files.length) out.push(`File ${files.join(', ')}`)
  if (by.length) out.push(`Started by ${by.join(', ')}`)
  return out
}
