// The vulnerabilities pop-up on a Fix card: every CVE of one app on every computer, which agent found it and when,
// and how far its fix got. One row per computer + version + CVE still open (the same count as the Vulnerabilities page),
// plus one per computer + CVE that Defender reports fixed and no version on that computer still has.
import { useEffect, useMemo, useState, type ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { ArrowDown, ArrowUp, Check, ChevronDown, ChevronLeft, ChevronRight, Circle, Download, ExternalLink, Search, X } from 'lucide-react'
import { Dialog, DialogContent, DialogDescription, DialogTitle } from '@/components/ui/dialog'
import { Choice, SevTag } from '@/components/kit'
import { useShownName } from '@/lib/deviceNames'
import type { FixRow, FixStatus } from '@/lib/fix'
import { num } from '@/lib/format'
import { UC_DOT, UC_NAME } from '@/lib/runs'
import { statusColor } from '@/lib/theme'
import { threatHref, useThreatMatches, type ThreatMatches } from '@/lib/uc1'
import { SEVS, type Uc3Data, type Uc3FixApp } from '@/lib/uc3'
import { cn } from '@/lib/utils'

type Status = 'open' | 'nofix' | 'waiting' | 'approved' | 'running' | 'failed' | 'checking' | 'fixed'
const STATUS: Record<Status, { label: string; color: string }> = {
  open: { label: 'Open', color: statusColor.critical },
  nofix: { label: 'No security update available', color: statusColor.warning },
  waiting: { label: 'Waiting for approval', color: statusColor.critical },
  approved: { label: 'Remediation approved', color: 'var(--blue)' },
  running: { label: 'Remediation running', color: 'var(--blue)' },
  failed: { label: 'Remediation failed', color: statusColor.critical },
  checking: { label: 'Pending verification', color: 'var(--teal)' },
  fixed: { label: 'Remediated', color: statusColor.good },
}
/** The fix engine's status of the computer's fix → what the row says (a fix covers every CVE of that app version) */
const FROM_ENGINE: Partial<Record<FixStatus, Status>> = {
  proposed: 'waiting', saved: 'waiting', gone: 'waiting', approved: 'approved', queued: 'approved', running: 'running',
  failed: 'failed', still_there: 'failed', done: 'checking', verified: 'checking', info: 'nofix',
}
const STEPS = ['Found', 'Remediation proposed', 'Approved', 'Remediated', 'Verified by Defender']
const REACHED: Record<Status, number> = { open: 0, nofix: 0, waiting: 1, approved: 2, running: 2, failed: 2, checking: 3, fixed: 4 }

interface News { id: string; title: string; found: string | null; published: string | null; score: number }
interface VRow {
  key: string; cve: string; device: string; versions: string[]; sev: string; cvss: number | null
  open: boolean; status: Status; vulnFound: string | null; fixedOn: string | null; advisory: string | null
  news: News[]; newsFound: string | null
  /** fixed for another version on this computer, while this version still has it */
  fixedElsewhere: { version: string; on: string }[]
}

const SEV_RANK = (s: string) => { const i = (SEVS as readonly string[]).indexOf(s); return i < 0 ? SEVS.length : i }
const ORDER: Status[] = ['open', 'waiting', 'failed', 'nofix', 'approved', 'running', 'checking', 'fixed']
const day = (s: unknown) => (s ? String(s).slice(0, 10) : null)
const longDate = (d: string | null) => (d ? new Date(`${d}T00:00:00`).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' }) : '')
const minDate = (a: string | null, b: string | null) => (!a ? b : !b ? a : a < b ? a : b)
/** The table's short label: the headline without this CVE and the product list
 *  ("New CRITICAL vulnerability CVE-… in mozilla firefox, …" → "New critical vulnerability") */
const newsLabel = (n: News, cve: string) => n.title.replace(cve, '').replace(/ in [a-z].*$/, '').replace(/\b[A-Z]{4,}\b/g, (w) => w.toLowerCase()).replace(/\s+/g, ' ').trim()

function buildRows(data: Uc3Data, software: string, fixRows: FixRow[], engine: boolean, matches: ThreatMatches | undefined): VRow[] {
  const col = (cols: string[]) => (name: string) => cols.indexOf(name)
  const news = new Map<string, News[]>()                     // computer|CVE → the threats in the news that name it
  for (const m of matches?.rows ?? []) {
    const t = matches!.threats[m.threat]
    const list = news.get(`${m.device}|${m.cve}`) ?? []
    if (!list.some((n) => n.id === m.threat)) list.push({ id: m.threat, title: t?.title ?? m.threat, found: t?.found ?? null, published: t?.published ?? null, score: t?.score ?? 0 })
    news.set(`${m.device}|${m.cve}`, list)
  }
  const newsOf = (pair: string) => {
    const list = (news.get(pair) ?? []).sort((a, b) => b.score - a.score)
    return { news: list, newsFound: list.reduce<string | null>((m, n) => minDate(m, n.found), null) }
  }
  const engineRow = new Map(fixRows.filter((r) => r.software_name === software).map((r) => [`${r.device_name}|${r.version}`, r]))

  const out: VRow[] = []
  const openPairs = new Map<string, VRow[]>()
  const F = col(data.f.cols)
  for (const r of data.f.rows) {
    if (r[F('sw')] !== software) continue
    const device = data.devices[r[F('d')] as number]?.name ?? ''
    const cve = String(r[F('cve')]), ver = String(r[F('ver')]), pair = `${device}|${cve}`
    const fix = engineRow.get(`${device}|${ver}`)
    const status: Status = r[F('ua')] === 0 ? 'nofix' : engine && fix ? FROM_ENGINE[fix.status] ?? 'open' : 'open'
    const row: VRow = {
      key: `${device}|${ver}|${cve}`, cve, device, versions: [ver], sev: String(r[F('sev')]), cvss: (r[F('cvss')] as number) ?? null,
      open: true, status, vulnFound: day(r[F('fs')]), fixedOn: null, advisory: (r[F('upd')] as string) || null,
      ...newsOf(pair), fixedElsewhere: [],
    }
    out.push(row)
    openPairs.set(pair, [...(openPairs.get(pair) ?? []), row])
  }
  if (data.fixed) {
    const X = col(data.fixed.cols)
    const fixedOnly = new Map<string, VRow>()
    for (const r of data.fixed.rows) {
      if (r[X('sw')] !== software) continue
      const device = data.devices[r[X('d')] as number]?.name ?? ''
      const cve = String(r[X('cve')]), ver = String(r[X('ver')]), pair = `${device}|${cve}`, on = day(r[X('fixed')]) ?? ''
      const stillOpen = openPairs.get(pair)
      if (stillOpen) {                                         // fixed in one version, still there in another
        for (const o of stillOpen) if (!o.versions.includes(ver)) o.fixedElsewhere.push({ version: ver, on })
        continue
      }
      const row = fixedOnly.get(pair)
      if (row) {
        if (!row.versions.includes(ver)) row.versions.push(ver)
        if (on > (row.fixedOn ?? '')) row.fixedOn = on
        row.vulnFound = minDate(row.vulnFound, day(r[X('fs')]))
        continue
      }
      fixedOnly.set(pair, {
        key: pair, cve, device, versions: [ver], sev: String(r[X('sev')]), cvss: null, open: false,
        status: 'fixed', vulnFound: day(r[X('fs')]), fixedOn: on, advisory: null, ...newsOf(pair), fixedElsewhere: [],
      })
    }
    out.push(...fixedOnly.values())
  }
  return out
}

/** Default order: in the news first, then still open, then worst first */
const byDefault = (a: VRow, b: VRow) =>
  Number(!a.news.length) - Number(!b.news.length) || Number(!a.open) - Number(!b.open) || SEV_RANK(a.sev) - SEV_RANK(b.sev)
  || (b.cvss ?? 0) - (a.cvss ?? 0) || a.cve.localeCompare(b.cve) || a.device.localeCompare(b.device)

type SortKey = 'cve' | 'device' | 'sev' | 'vuln' | 'news' | 'status'
const SORTERS: Record<SortKey, (a: VRow, b: VRow) => number> = {
  cve: (a, b) => a.cve.localeCompare(b.cve, undefined, { numeric: true }),
  device: (a, b) => a.device.localeCompare(b.device),
  sev: (a, b) => SEV_RANK(a.sev) - SEV_RANK(b.sev) || (b.cvss ?? 0) - (a.cvss ?? 0),
  vuln: (a, b) => (a.vulnFound ?? '9').localeCompare(b.vulnFound ?? '9'),
  news: (a, b) => (a.newsFound ?? '9').localeCompare(b.newsFound ?? '9'),
  status: (a, b) => ORDER.indexOf(a.status) - ORDER.indexOf(b.status),
}

const PAGE = 50
const WHEN: [string, string][] = [['', 'Found: any time'], ['7', 'Found: last 7 days'], ['30', 'Found: last 30 days'], ['90', 'Found: last 90 days'], ['pick', 'Found: pick dates…']]
const isoDaysAgo = (n: number) => new Date(Date.now() - n * 86_400_000).toISOString().slice(0, 10)

export function VulnList({ app, software, data, fixRows, engine, startAgent, startDevice, onClose, prev, next }: {
  app: Uc3FixApp; software: string; data: Uc3Data; fixRows: FixRow[]; engine: boolean; startAgent?: 'uc3' | 'uc1' | null
  /** open on one computer (a run page's card) */
  startDevice?: string
  onClose: () => void; prev?: { name: string; go: () => void }; next?: { name: string; go: () => void }
}) {
  const shown = useShownName()
  const matches = useThreatMatches(software)
  const rows = useMemo(() => buildRows(data, software, fixRows, engine, matches.data), [data, software, fixRows, engine, matches.data])

  const [st, setSt] = useState<'' | 'open' | 'fixed'>('')
  const [ag, setAg] = useState<'' | 'uc3' | 'uc1'>(startAgent ?? '')
  const [q, setQ] = useState('')
  const [sev, setSev] = useState('')
  const [when, setWhen] = useState('')
  const [from, setFrom] = useState('')
  const [to, setTo] = useState('')
  const [status, setStatus] = useState('')
  const [device, setDevice] = useState(startDevice ?? '')
  const [sort, setSort] = useState<{ key: SortKey; dir: 1 | -1 } | null>(null)
  const [page, setPage] = useState(0)
  const [openKey, setOpenKey] = useState<string | null>(null)
  useEffect(() => { setPage(0) }, [st, ag, q, sev, when, from, to, status, device, sort, software])
  // another app: keep the four quick filters, drop what only fits the last app (its CVEs, computers, dates)
  useEffect(() => { setOpenKey(null); setQ(''); setSev(''); setWhen(''); setFrom(''); setTo(''); setStatus(''); setDevice(startDevice ?? '') }, [software, startDevice])

  const devices = useMemo(() => [...new Set(rows.map((r) => r.device))].sort(), [rows])
  const statuses = useMemo(() => ORDER.filter((s) => rows.some((r) => r.status === s)), [rows])
  const counts = { open: rows.filter((r) => r.open).length, fixed: rows.filter((r) => !r.open).length, uc1: rows.filter((r) => r.news.length).length }

  const [since, until] = when === 'pick' ? [from || '0000', to || '9999'] : when ? [isoDaysAgo(Number(when)), '9999'] : ['', '']
  const inRange = (d: string | null) => !!d && d >= since && d <= until
  const term = q.trim().toUpperCase()
  const list = useMemo(() => {
    const keep = rows.filter((r) => (!st || (st === 'open') === r.open) && (ag !== 'uc1' || r.news.length > 0)
      && (!term || r.cve.includes(term)) && (!sev || r.sev === sev) && (!status || r.status === status) && (!device || r.device === device)
      && (!since || inRange(r.vulnFound) || inRange(r.newsFound)))
    return keep.sort(sort ? (a, b) => sort.dir * SORTERS[sort.key](a, b) || byDefault(a, b) : byDefault)
  }, [rows, st, ag, term, sev, status, device, since, until, sort]) // eslint-disable-line react-hooks/exhaustive-deps
  const pages = Math.max(1, Math.ceil(list.length / PAGE))
  const shownRows = list.slice(page * PAGE, page * PAGE + PAGE)
  const filtered = !!(st || ag || term || sev || when || status || device)
  const clear = () => { setSt(''); setAg(''); setQ(''); setSev(''); setWhen(''); setFrom(''); setTo(''); setStatus(''); setDevice('') }
  const sortBy = (key: SortKey) => setSort((s) => (s?.key !== key ? { key, dir: 1 } : s.dir === 1 ? { key, dir: -1 } : null))

  const fixedTotal = counts.fixed
  const computers = new Set(rows.map((r) => r.device)).size

  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent showCloseButton={false}
        className="flex max-h-[92vh] w-[min(1280px,calc(100%-1.5rem))] max-w-none flex-col gap-3 overflow-y-auto border-hairline bg-panel p-4 sm:max-w-none sm:overflow-hidden sm:p-5">
        <div className="flex flex-wrap items-start gap-2">
          <div className="w-full min-w-0 sm:w-auto sm:flex-1">
            <DialogTitle className="text-lg font-semibold">{app.app}: every vulnerability</DialogTitle>
            <DialogDescription className="text-sm text-ink-3">
              {computers} device{computers === 1 ? '' : 's'} · {num(fixedTotal)} of {num(rows.length)} remediated · {app.fix.action}
            </DialogDescription>
          </div>
          <div className="flex items-center gap-1.5">
            <NavButton disabled={!prev} onClick={prev?.go} title={prev ? `Previous app: ${prev.name}` : undefined}><ChevronLeft className="size-4" /> Previous app</NavButton>
            <NavButton disabled={!next} onClick={next?.go} title={next ? `Next app: ${next.name}` : undefined}>Next{next ? `: ${next.name}` : ' app'} <ChevronRight className="size-4" /></NavButton>
            <button onClick={onClose} aria-label="Close" className="grid size-8 place-items-center rounded-lg hover:bg-well"><X className="size-4" /></button>
          </div>
        </div>

        {/* quick filters: status, then which agent reported it */}
        <div className="flex flex-wrap items-center gap-2 text-sm">
          <Pill on={st === 'open'} onClick={() => setSt(st === 'open' ? '' : 'open')} label="Open" n={counts.open} />
          <Pill on={st === 'fixed'} onClick={() => setSt(st === 'fixed' ? '' : 'fixed')} label="Remediated" n={counts.fixed} />
          <span className="mx-1 h-5 w-px bg-hairline-strong" />
          <Pill on={ag === 'uc3'} onClick={() => setAg(ag === 'uc3' ? '' : 'uc3')} label={UC_NAME.uc3} n={rows.length} dot={UC_DOT.uc3}
            title="All vulnerabilities found by Defender's device scan" />
          <Pill on={ag === 'uc1'} onClick={() => setAg(ag === 'uc1' ? '' : 'uc1')} label={UC_NAME.uc1} n={matches.isLoading ? null : counts.uc1} dot={UC_DOT.uc1}
            title="Reported in threat intelligence before Defender's device scan found it: attackers are aware of it, so remediate these first" />
        </div>

        <div className="flex flex-wrap items-center gap-2 text-sm">
          <label className="flex min-w-[200px] flex-1 items-center gap-2 rounded-lg border border-hairline-strong bg-field px-3 py-1.5 focus-within:border-blue/60">
            <Search className="size-3.5 text-ink-3" />
            <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search a CVE, e.g. CVE-2024-9680" className="w-full bg-transparent outline-none placeholder:text-ink-3" />
          </label>
          <Select value={sev} onChange={setSev} label="Severity" options={[['', 'All severities'], ...SEVS.filter((s) => rows.some((r) => r.sev === s)).map((s) => [s, s] as [string, string])]} />
          <Select value={when} onChange={setWhen} label="Found" options={WHEN} />
          {when === 'pick' && (
            <span className="flex items-center gap-1.5">
              <input type="date" value={from} onChange={(e) => setFrom(e.target.value)} aria-label="Found from" className="rounded-lg border border-hairline-strong bg-field px-2 py-1" />
              <span className="text-ink-3">to</span>
              <input type="date" value={to} onChange={(e) => setTo(e.target.value)} aria-label="Found until" className="rounded-lg border border-hairline-strong bg-field px-2 py-1" />
            </span>
          )}
          <Select value={status} onChange={setStatus} label="Status" options={[['', 'All statuses'], ...statuses.map((s) => [s, STATUS[s].label] as [string, string])]} />
          <Select value={device} onChange={setDevice} label="Device" options={[['', 'All devices'], ...devices.map((d) => [d, shown(d)] as [string, string])]} />
          {filtered && <button onClick={clear} className="rounded-lg px-2.5 py-1.5 text-ink-2 hover:bg-well">Clear</button>}
          <button onClick={() => downloadCsv(list, app.app, shown)} className="ml-auto inline-flex items-center gap-1.5 rounded-lg border border-hairline-strong px-3 py-1.5 hover:bg-well"
            title="Download the rows that match the filters (opens in Excel)">
            <Download className="size-3.5" /> Excel
          </button>
        </div>

        {matches.isError && (
          <p className="text-xs text-ink-3">The {UC_NAME.uc1} has not yet reported which of these appear in threat intelligence; its next run adds them.</p>
        )}

        <div className="min-h-[60vh] shrink-0 overflow-auto rounded-xl border border-hairline sm:min-h-0 sm:flex-1 sm:shrink">
          <table className="w-full min-w-[960px] border-collapse text-sm">
            <thead className="sticky top-0 z-10 bg-panel text-left text-xs text-ink-3">
              <tr>
                <th rowSpan={2} className="w-12 px-3 py-2 font-medium">#</th>
                <Th rowSpan={2} k="cve" sort={sort} onSort={sortBy}>CVE</Th>
                <Th rowSpan={2} k="device" sort={sort} onSort={sortBy}>Device</Th>
                <Th rowSpan={2} k="sev" sort={sort} onSort={sortBy}>Severity</Th>
                <th colSpan={2} className="border-b border-hairline px-3 pt-2 pb-1 text-center font-medium">Found by</th>
                <Th rowSpan={2} k="status" sort={sort} onSort={sortBy}>Status</Th>
                <th rowSpan={2} className="w-8" />
              </tr>
              <tr>
                <Th k="vuln" sort={sort} onSort={sortBy}>
                  <span className="flex items-center gap-1.5"><span className={cn('size-2 rounded-full', UC_DOT.uc3)} />{UC_NAME.uc3}</span>
                  <span className="block font-normal">on the device</span>
                </Th>
                <Th k="news" sort={sort} onSort={sortBy}>
                  <span className="flex items-center gap-1.5"><span className={cn('size-2 rounded-full', UC_DOT.uc1)} />{UC_NAME.uc1}</span>
                  <span className="block font-normal">in threat intel</span>
                </Th>
              </tr>
              <tr><th colSpan={8} className="h-px bg-hairline p-0" /></tr>
            </thead>
            <tbody>
              {shownRows.map((r, i) => (
                <Row key={r.key} r={r} n={page * PAGE + i + 1} app={app} shown={shown} open={openKey === r.key} newsLoading={matches.isLoading}
                  onToggle={() => setOpenKey(openKey === r.key ? null : r.key)} />
              ))}
              {!shownRows.length && (
                <tr><td colSpan={8} className="px-3 py-10 text-center text-ink-3">{rows.length ? 'No vulnerabilities match these filters.' : 'No vulnerabilities recorded for this app.'}</td></tr>
              )}
            </tbody>
          </table>
        </div>

        <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-ink-3">
          <span>
            {list.length ? `Showing ${num(page * PAGE + 1)}–${num(Math.min(list.length, page * PAGE + PAGE))} of ${num(list.length)}` : 'No results'}
            {filtered && ` (filtered from ${num(rows.length)})`}
            {!sort && ' · threat intel first, then open, then by severity'}
          </span>
          {pages > 1 && (
            <span className="flex items-center gap-1">
              <NavButton disabled={page === 0} onClick={() => setPage(page - 1)} title="Previous page"><ChevronLeft className="size-4" /></NavButton>
              <span className="px-1 tabular">Page {page + 1} of {pages}</span>
              <NavButton disabled={page >= pages - 1} onClick={() => setPage(page + 1)} title="Next page"><ChevronRight className="size-4" /></NavButton>
            </span>
          )}
        </div>
      </DialogContent>
    </Dialog>
  )
}

function Row({ r, n, app, shown, open, onToggle, newsLoading }: {
  r: VRow; n: number; app: Uc3FixApp; shown: (d: string) => string; open: boolean; onToggle: () => void; newsLoading: boolean
}) {
  const s = STATUS[r.status]
  const first = r.news[0]
  return (
    <>
      <tr onClick={onToggle} aria-expanded={open} className={cn('cursor-pointer border-t border-hairline align-top hover:bg-well/60', open && 'bg-well/60')}>
        <td className="px-3 py-2.5 tabular text-ink-3">{n}</td>
        <td className="px-3 py-2.5">
          <span className="font-mono text-[13px]">{r.cve}</span>
        </td>
        <td className="px-3 py-2.5">{shown(r.device)}<div className="text-[11px] text-ink-3">{app.app} {r.versions.join(', ')}</div></td>
        <td className="px-3 py-2.5"><SevTag sev={r.sev} />{r.cvss != null && <span className="ml-1 tabular text-xs text-ink-3">{r.cvss}</span>}</td>
        <td className="px-3 py-2.5">{r.vulnFound ? longDate(r.vulnFound) : '–'}<div className="text-[11px] text-ink-3">Defender scan</div></td>
        <td className={cn('px-3 py-2.5', first && 'bg-violet/8')}>
          {first ? (
            <>
              {r.newsFound ? longDate(r.newsFound) : 'In the news'}
              <div className="text-[11px] text-violet">{newsLabel(first, r.cve)}{r.news.length > 1 && ` +${r.news.length - 1} more`}</div>
            </>
          ) : <span className="text-xs text-ink-3">{newsLoading ? 'Checking threat intelligence…' : 'Not in threat intelligence'}</span>}
        </td>
        <td className="px-3 py-2.5">
          <span className="inline-block whitespace-nowrap rounded-md px-2 py-0.5 text-xs font-medium"
            style={{ color: s.color, background: `color-mix(in oklab, ${s.color} 14%, transparent)` }}>
            {r.status === 'fixed' && r.fixedOn ? `Remediated ${longDate(r.fixedOn)}` : s.label}
          </span>
          {r.status === 'fixed' && <div className="mt-0.5 text-[11px] text-ink-3">verified by Defender</div>}
        </td>
        <td className="px-2 py-2.5 text-ink-3"><ChevronDown className={cn('size-4 transition-transform', open && 'rotate-180')} /></td>
      </tr>
      {open && (
        <tr className="bg-well/40">
          <td />
          <td colSpan={7} className="px-3 pt-1 pb-4">
            <div className="grid gap-5 text-[13px] leading-relaxed md:grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)_minmax(0,0.8fr)]">
              <div>
                <h4 className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-ink-3">Why it is listed</h4>
                <p className="flex gap-2">
                  <span className={cn('mt-1.5 size-2 shrink-0 rounded-full', UC_DOT.uc3)} />
                  <span><b className="font-semibold">{r.vulnFound ? longDate(r.vulnFound) : 'Date not recorded'}</b>: the {UC_NAME.uc3} found it in Defender's scan of {shown(r.device)} ({app.app} {r.versions.join(', ')}).
                    {r.status === 'fixed' && r.fixedOn && <> Defender stopped listing it on {longDate(r.fixedOn)}, so it is remediated.</>}</span>
                </p>
                {r.news.length ? r.news.slice(0, 4).map((t) => (
                  <p key={t.id} className="mt-2 flex gap-2">
                    <span className={cn('mt-1.5 size-2 shrink-0 rounded-full', UC_DOT.uc1)} />
                    <span>
                      <b className="font-semibold">{t.found ? longDate(t.found) : 'Date not recorded'}</b>: the {UC_NAME.uc1} reported it in threat intelligence: “{t.title}”
                      {t.published && <> (published {longDate(t.published)})</>}.
                      {' '}
                      <Link to={threatHref(t.id)} className="inline-flex items-center gap-1 text-blue hover:underline">Open the threat <ExternalLink className="size-3" /></Link>
                    </span>
                  </p>
                )) : (
                  <p className="mt-2 flex gap-2 text-ink-3"><span className="mt-1.5 size-2 shrink-0 rounded-full bg-hairline-strong" />No threat intelligence references it.</p>
                )}
                {r.news.length > 4 && <p className="mt-1 pl-4 text-xs text-ink-3">and {r.news.length - 4} more threat intelligence reports</p>}
              </div>
              <div>
                <h4 className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-ink-3">Remediation</h4>
                <p>{app.fix.action}{r.advisory && <span className="text-ink-3"> (vendor advisory {r.advisory})</span>}.</p>
                {r.fixedElsewhere.map((f) => (
                  <p key={f.version} className="mt-1.5 text-xs text-ink-3">Already remediated for {app.app} {f.version} on this device on {longDate(f.on)}; {app.app} {r.versions.join(', ')} still has it.</p>
                ))}
              </div>
              <div>
                <h4 className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-ink-3">Progress</h4>
                <ol className="space-y-1">
                  {STEPS.map((step, i) => {
                    const done = i <= REACHED[r.status]
                    const failed = r.status === 'failed' && i === 3
                    return (
                      <li key={step} className={cn('flex items-center gap-2', done ? 'text-ink' : 'text-ink-3')}>
                        {failed ? <X className="size-3.5" style={{ color: statusColor.critical }} />
                          : done ? <Check className="size-3.5" style={{ color: statusColor.good }} /> : <Circle className="size-3" />}
                        {failed ? 'Remediation failed: retry from the card' : step}
                        {i === 0 && r.vulnFound && <span className="text-xs text-ink-3">{longDate(r.vulnFound)}</span>}
                        {i === 4 && r.fixedOn && <span className="text-xs text-ink-3">{longDate(r.fixedOn)}</span>}
                      </li>
                    )
                  })}
                </ol>
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  )
}

function Th({ k, sort, onSort, children, rowSpan }: { k: SortKey; sort: { key: SortKey; dir: 1 | -1 } | null; onSort: (k: SortKey) => void; children: ReactNode; rowSpan?: number }) {
  const on = sort?.key === k
  return (
    <th rowSpan={rowSpan} className="px-3 py-2 align-bottom font-medium" aria-sort={on ? (sort!.dir === 1 ? 'ascending' : 'descending') : undefined}>
      <button onClick={() => onSort(k)} className={cn('flex items-end gap-1 text-left hover:text-ink', on && 'text-ink')} title="Sort by this column">
        <span>{children}</span>
        {on && (sort!.dir === 1 ? <ArrowUp className="mb-0.5 size-3 shrink-0" /> : <ArrowDown className="mb-0.5 size-3 shrink-0" />)}
      </button>
    </th>
  )
}

function Pill({ on, onClick, label, n, dot, title }: { on: boolean; onClick: () => void; label: string; n: number | null; dot?: string; title?: string }) {
  return (
    <button onClick={onClick} aria-pressed={on} title={title}
      className={cn('flex items-center gap-2 rounded-full border px-3.5 py-1.5', on ? 'pill-on' : 'border-hairline bg-panel hover:bg-well')}>
      {dot && <span className={cn('size-2 rounded-full', dot)} />}{label} <span className="tabular opacity-60">{n == null ? '…' : num(n)}</span>
    </button>
  )
}

/** A filter dropdown in the portal's own style (the first option means "no filter") */
function Select({ value, onChange, label, options }: { value: string; onChange: (v: string) => void; label: string; options: [string, string][] }) {
  return (
    <div className="w-40 sm:w-44">
      <Choice label={label} value={value} onChange={onChange} options={options.map(([v, l]) => ({ value: v, label: l }))} className="py-1.5" />
    </div>
  )
}

function NavButton({ disabled, onClick, title, children }: { disabled?: boolean; onClick?: () => void; title?: string; children: ReactNode }) {
  return (
    <button disabled={disabled} onClick={onClick} title={title}
      className="inline-flex max-w-[220px] items-center gap-1 truncate rounded-lg border border-hairline px-2.5 py-1.5 text-xs hover:bg-well disabled:opacity-40 disabled:hover:bg-transparent">
      {children}
    </button>
  )
}

function downloadCsv(rows: VRow[], app: string, shown: (d: string) => string) {
  const esc = (v: unknown) => { const s = String(v ?? ''); return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s }
  const head = ['#', 'CVE', 'Device', 'Version', 'Severity', 'CVSS', `${UC_NAME.uc3}: found`,
    `${UC_NAME.uc1}: found in threat intelligence`, 'Threat intelligence reports', 'Status', 'Remediated on']
  const lines = rows.map((r, i) => [i + 1, r.cve, shown(r.device), r.versions.join(' / '), r.sev, r.cvss ?? '',
    r.vulnFound ?? '', r.newsFound ?? '', r.news.map((n) => n.title).join(' | '), STATUS[r.status].label, r.fixedOn ?? ''].map(esc).join(','))
  const blob = new Blob(['﻿' + [head.map(esc).join(','), ...lines].join('\r\n')], { type: 'text/csv;charset=utf-8' })
  const a = document.createElement('a')
  a.href = URL.createObjectURL(blob)
  a.download = `${app.replace(/[^\w.-]+/g, '_')}_vulnerabilities_${new Date().toISOString().slice(0, 10)}.csv`
  a.click()
  URL.revokeObjectURL(a.href)
}
