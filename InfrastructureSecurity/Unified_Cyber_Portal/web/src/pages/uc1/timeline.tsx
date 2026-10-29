// The "Affects us" timeline: when a hole was announced, when the Threat Intel Agent knew, when Defender listed it on
// our computer and when it was fixed. The first two come from UC1 (explorer `on_us`); Defender's dates come from the
// Vulnerability Agent's data (UC3 `f` = still open, `fixed` = gone), joined on computer + CVE.
import { useMemo } from 'react'
import { CircleCheck, Clock, Hourglass } from 'lucide-react'
import { shortDate } from '@/lib/format'
import { statusColor } from '@/lib/theme'
import { cn } from '@/lib/utils'
import { useUc3Data } from '@/lib/uc3'
import type { ExplorerRow } from '@/lib/uc1'

export interface DefenderDates {
  listed: Map<string, string>    // "computer|CVE" -> first day Defender listed it
  fixed: Map<string, string>     // "computer|CVE" -> day it disappeared (fixed), only when no longer open
  appFirst: Map<string, string>  // "computer|app" -> first day Defender listed any hole in that app on that computer
  ready: boolean
}

const earliest = (m: Map<string, string>, k: string, v: string | null | undefined) => {
  if (v && (!m.has(k) || v < m.get(k)!)) m.set(k, v)
}

export function useDefenderDates(): DefenderDates {
  const { data } = useUc3Data()
  return useMemo(() => {
    const listed = new Map<string, string>(), fixed = new Map<string, string>(), appFirst = new Map<string, string>()
    if (!data) return { listed, fixed, appFirst, ready: false }
    const name = (d: number) => data.devices[d]?.name ?? ''
    const open = new Set<string>()
    const col = (cols: string[], k: string) => cols.indexOf(k)
    const f = data.f as unknown as { cols: string[]; rows: unknown[][] }
    const [fd, fsw, fcve, ffs] = ['d', 'sw', 'cve', 'fs'].map((k) => col(f.cols, k))
    for (const r of f.rows) {
      const dev = name(r[fd] as number), day = String(r[ffs] ?? '').slice(0, 10)
      open.add(`${dev}|${r[fcve]}`)
      earliest(listed, `${dev}|${r[fcve]}`, day)
      earliest(appFirst, `${dev}|${r[fsw]}`, day)
    }
    if (data.fixed) {
      const [xd, xsw, xcve, xfs, xfixed] = ['d', 'sw', 'cve', 'fs', 'fixed'].map((k) => col(data.fixed!.cols, k))
      for (const r of data.fixed.rows) {
        const dev = name(r[xd] as number), key = `${dev}|${r[xcve]}`, day = String(r[xfs] ?? '').slice(0, 10)
        earliest(listed, key, day)
        earliest(appFirst, `${dev}|${r[xsw]}`, day)
        if (!open.has(key)) fixed.set(key, String(r[xfixed] ?? '').slice(0, 10))
      }
    }
    return { listed, fixed, appFirst, ready: true }
  }, [data])
}

const dayNo = (s: string) => Math.floor(Date.parse(`${s.slice(0, 10)}T00:00:00Z`) / 864e5)
const today = () => dayNo(new Date().toISOString())

export interface Story {
  match: 'defender' | 'early' | 'closed'
  cve: string; device: string; app: string; version: string
  announced: string | null; known: string | null; listed: string | null; fixed: string | null
  ahead: number | null      // days Defender listed it after we knew (only when the app was already on that computer)
  behind: boolean           // Defender listed it on an earlier day than we knew: we only repeated its list
  waiting: number | null    // days since we knew, while Defender hasn't listed it
}

/** The one line of the card's timeline: for Defender-confirmed cards the CVE/computer where we were most ahead. */
export function storyOf(e: ExplorerRow, dd: DefenderDates): Story | null {
  const match = e.match
  if (!dd.ready || !e.on_us?.length || (match !== 'defender' && match !== 'early' && match !== 'closed')) return null
  const want = match === 'defender' ? 'cve' : match
  const stories = e.on_us.filter((x) => x.match === want).map((x): Story => {
    const key = `${x.device}|${x.cve}`
    const listed = want === 'cve' ? dd.listed.get(key) ?? null : null
    const knownDay = x.known ? x.known.slice(0, 10) : null
    const appThere = dd.appFirst.get(`${x.device}|${x.app}`)
    // "ahead" only counts when the app was already on the computer when we knew: otherwise the late Defender date
    // just means the app was installed later
    const ahead = listed && knownDay && appThere && appThere <= knownDay ? dayNo(listed) - dayNo(knownDay) : null
    return {
      match, cve: x.cve, device: x.device, app: x.app, version: x.version,
      announced: x.announced || null, known: x.known || null, listed, fixed: want === 'cve' ? dd.fixed.get(key) ?? null : null,
      ahead: ahead && ahead > 0 ? ahead : null,
      behind: !!(listed && knownDay && listed < knownDay),
      waiting: want !== 'cve' && knownDay ? Math.max(0, today() - dayNo(knownDay)) : null,
    }
  })
  // most ahead first, then ones where we were no later than Defender (same rule as the matches list)
  return stories.sort((a, b) => (b.ahead ?? -1) - (a.ahead ?? -1) || Number(a.behind) - Number(b.behind))[0] ?? null
}

/** Small badge for the card header. */
export function StoryBadge({ s }: { s: Story | null }) {
  if (!s) return null
  if (s.match === 'early')
    return <span className="inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-[11px] font-semibold" style={{ color: statusColor.warning, background: 'color-mix(in oklab, currentColor 14%, transparent)' }}><Hourglass className="size-3" /> Not in Defender yet · {s.waiting} day{s.waiting === 1 ? '' : 's'}</span>
  if (s.match === 'closed')
    return <span className="inline-flex items-center gap-1 rounded-md bg-well px-2 py-0.5 text-[11px] font-medium text-ink-2"><Clock className="size-3" /> Not reported by Defender</span>
  if (s.ahead)
    return <span className="inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-[11px] font-semibold" style={{ color: statusColor.good, background: 'color-mix(in oklab, currentColor 14%, transparent)' }}>{s.ahead} day{s.ahead === 1 ? '' : 's'} ahead of Defender</span>
  return null
}

/** Announced → we knew → Defender listed → fixed, for one CVE on one computer; Defender before us when it was first. */
export function Timeline({ s }: { s: Story }) {
  type Step = { label: string; when: string | null; note?: string; tone?: 'good' | 'warn' | 'muted' }
  const identified: Step = { label: 'Identified', when: s.known, note: s.behind ? 'Threat Intel Agent · after Defender' : 'Threat Intel Agent' }
  const defender: Step = s.match === 'defender'
    ? { label: 'Defender listed it', when: s.listed, note: s.ahead ? `${s.ahead} day${s.ahead === 1 ? '' : 's'} after us` : 'on our device', tone: s.ahead ? 'good' : undefined }
    : s.match === 'early'
      ? { label: 'Defender', when: null, note: `not listed yet · waiting ${s.waiting} day${s.waiting === 1 ? '' : 's'}`, tone: 'warn' }
      : { label: 'Defender', when: null, note: 'not reported (14+ days)', tone: 'muted' }
  const steps: Step[] = [
    { label: 'Announced', when: s.announced, note: 'by the vendor / NVD' },
    ...(s.behind ? [defender, identified] : [identified, defender]),
    s.fixed ? { label: 'Remediated', when: s.fixed, note: 'gone from Defender', tone: 'good' } : { label: 'Remediated', when: null, note: 'not yet', tone: 'muted' },
  ]
  return (
    <div className="rounded-xl bg-well px-4 py-3">
      <div className="text-xs text-ink-3">
        Timeline for <span className="tabular font-medium text-ink-2">{s.cve}</span> in {s.app.replace(/_/g, ' ')} {s.version} on <span className="font-medium text-ink-2">{s.device}</span>
      </div>
      <ol className="mt-2.5 grid grid-cols-2 gap-x-3 gap-y-3 sm:grid-cols-4">
        {steps.map((st, i) => (
          <li key={st.label} className="relative">
            {i > 0 && <span className="absolute -left-3 top-[7px] hidden h-px w-3 bg-hairline-strong sm:block" aria-hidden />}
            <div className="flex items-center gap-1.5 text-xs font-medium">
              {st.tone === 'good' ? <CircleCheck className="size-3.5" style={{ color: statusColor.good }} />
                : st.tone === 'warn' ? <Hourglass className="size-3.5" style={{ color: statusColor.warning }} />
                : <span className={cn('size-2 rounded-full', st.when ? 'bg-sky' : 'bg-hairline-strong')} />}
              {st.label}
            </div>
            <div className={cn('tabular mt-0.5 text-sm', st.when ? 'text-ink' : 'text-ink-3')}>{st.when ? shortDate(st.when.slice(0, 10)) : '–'}</div>
            {st.note && <div className="text-[11px] leading-snug text-ink-3">{st.note}</div>}
          </li>
        ))}
      </ol>
    </div>
  )
}
