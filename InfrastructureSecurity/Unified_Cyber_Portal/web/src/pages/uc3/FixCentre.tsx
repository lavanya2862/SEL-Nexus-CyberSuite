import { useEffect, useMemo, useState } from 'react'
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom'
import {
  AlertTriangle, Check, ChevronDown, Copy, ExternalLink, Loader2, Play, Search, ShieldCheck, ShoppingBasket,
  SlidersHorizontal, Sparkles, Undo2, UserRound, X, Zap,
} from 'lucide-react'
import { ConfirmDialog, FixLoop, StatusPill } from '@/components/FixLoop'
import { Empty, HopLink, Panel, Tabs, Tag } from '@/components/kit'
import { FixHistory } from './FixHistory'
import { Dialog, DialogContent, DialogDescription, DialogTitle } from '@/components/ui/dialog'
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from '@/components/ui/sheet'
import { FixDown, canApprove, isSetting, settingChange, useFix, useFixAction, type FixRow, type FixView } from '@/lib/fix'
import { useFilters } from '@/lib/filters'
import { ago, num, shortDate } from '@/lib/format'
import { statusColor } from '@/lib/theme'
import { cn } from '@/lib/utils'
import { useKevThreatHref } from '@/lib/uc1'
import { fixKind, nearEos, pastEos, useUc3Data, useUc3View, type FixKind, type Uc3FixApp, type Uc3FixSetting } from '@/lib/uc3'
import { GettingReady, useAutoStart } from '@/lib/services'
import { Uc3Loading } from './common'

const LEVEL = {
  1: { label: 'Fix now', color: statusColor.critical },
  2: { label: 'Fix this month', color: statusColor.warning },
  3: { label: 'Plan in the next update cycle', color: 'var(--ink-3)' },
} as const

const softwareOf = (a: Uc3FixApp) => a.key.split(':').pop() ?? ''
/** The card a "Fix this" link means: exact software name or app name, else the first whose name starts with it. */
const findApp = (apps: Uc3FixApp[], focus: string) => {
  const f = focus.toLowerCase().replace(/\s+/g, '_')
  return apps.find((a) => softwareOf(a) === f || a.app.toLowerCase() === focus.toLowerCase())
    ?? apps.find((a) => softwareOf(a).startsWith(f))
}

type View = 'cards' | 'settings' | 'history' | 'table'
const VIEWS: [View, string][] = [['cards', 'Updates & upgrades'], ['settings', 'Security settings'], ['history', 'Fixed history'], ['table', 'All fixes as a table']]

/** The fix-type chips on Updates & upgrades (?type= picks one, e.g. from the Vulnerabilities overview). */
const KINDS: [FixKind, string, string][] = [
  ['update', 'App updates', 'A newer version of the app closes the holes'],
  ['os', 'Windows updates', 'The holes are in Windows itself: install the Windows update (Windows Update, WSUS or Intune), usually with a restart'],
  ['upgrade', 'Unsupported software', 'Past or near its end-of-support date: the vendor stops fixing it, so move to a supported version'],
  ['none', 'No fix yet', 'The vendor has not released a fix: reduce the risk another way until it comes'],
]
const KIND_PHRASE: Record<FixKind, [string, string]> = {
  update: ['app update', 'app updates'], os: ['Windows update', 'Windows updates'],
  upgrade: ['upgrade of unsupported software', 'upgrades of unsupported software'], none: ['app with no fix yet', 'apps with no fix yet'],
}

/** Act › Fix & protect: what to update and why (UC3 advice), and "fix it for me" on every computer (UC1 fix engine). */
export function FixCentre() {
  const { tab } = useParams()
  const navigate = useNavigate()
  const view: View = tab === 'table' || tab === 'history' || tab === 'settings' ? tab : 'cards'
  return (
    <div className="flex flex-col gap-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Fix & protect</h1>
          <p className="mt-1 text-sm text-ink-3">Close the holes and lock the doors before attackers use them: updates, upgrades and security settings, or let the portal fix them for you</p>
        </div>
      </div>
      <Tabs<View> tabs={VIEWS} value={view} onChange={(t) => navigate(t === 'cards' ? '/fixes' : `/fixes/${t}`)} />
      {view === 'table' ? <FixLoop /> : view === 'history' ? <FixHistory /> : view === 'settings' ? <SettingsCards /> : <FixCards />}
    </div>
  )
}

/* ───────────────────────── the card page ───────────────────────── */

function FixCards() {
  const { data, error, isLoading } = useUc3Data()
  const fix = useFix()
  const act = useFixAction()
  const { opco } = useFilters()
  const [params] = useSearchParams()
  const navigate = useNavigate()
  const [level, setLevel] = useState<0 | 1 | 2 | 3>(0)
  const typeParam = params.get('type')
  const [kind, setKind] = useState<'all' | FixKind>(KINDS.some(([k]) => k === typeParam) ? (typeParam as FixKind) : 'all')
  const [q, setQ] = useState('')
  const [chooser, setChooser] = useState(false)
  const rows = useUc3View(data).rows
  const vulns = rows.length                               // the same count the Vulnerabilities page shows
  const noPatch = rows.filter((f) => f.ua === 0).length
  const v = fix.data
  const down = fix.error instanceof FixDown
  const auto = useAutoStart(down, 'fix')
  const rowsBySoftware = useMemo(() => {
    const m = new Map<string, FixRow[]>()
    for (const r of v?.rows ?? []) m.set(r.software_name, [...(m.get(r.software_name) ?? []), r])
    return m
  }, [v])

  // ?app=<name> or ?sw=<software> (from "Fix this" buttons elsewhere): scroll to that card and highlight it
  const focus = params.get('sw') ?? params.get('app')
  const fixSettled = fix.isFetched || fix.isError
  useEffect(() => {
    // wait for both data sets: the computer rows change the card heights, so jumping earlier lands in the wrong place
    if (!focus || !data?.fixes || !fixSettled) return
    const app = findApp(data.fixes.apps, focus)
    if (!app) return
    const go = () => document.getElementById(`fix-${softwareOf(app)}`)?.scrollIntoView({ behavior: 'smooth', block: 'start' })
    const t1 = setTimeout(go, 150)
    const t2 = setTimeout(go, 900)                            // once more, after late layout changes
    return () => { clearTimeout(t1); clearTimeout(t2) }
  }, [focus, data, fixSettled])

  if (isLoading || error || !data) return <Uc3Loading error={error} />
  const X = data.fixes
  if (!X) return <Empty text="The fix guide has not been built yet. Run the vulnerability update to create it." />
  const inOpco = X.apps.filter((a) => opco === 'all' || a.opcos.includes(opco))
  const ofKind = (k: FixKind) => inOpco.filter((a) => fixKind(a) === k).length
  const inKind = inOpco.filter((a) => kind === 'all' || fixKind(a) === kind)
  const apps = inKind.filter((a) => (level === 0 || a.urgency.level === level) && (!q || a.app.toLowerCase().includes(q.toLowerCase())))
  const count = (l: number) => inKind.filter((a) => a.urgency.level === l).length
  const pickKind = (k: 'all' | FixKind) => {
    setKind(k)
    navigate({ search: k === 'all' ? '' : `?type=${k}` }, { replace: true })
  }
  const noFixSw = new Set(X.apps.filter((a) => fixKind(a) === 'none').map(softwareOf))   // nothing to install yet
  const urgentRows = (v?.rows ?? []).filter((r) => r.stage === 1 && canApprove(r) && !noFixSw.has(r.software_name))
  const urgentApps = new Set(urgentRows.map((r) => r.software_name)).size
  const approve = (ids: string[]) => v && act.mutate({ action: 'approve', ids, method: v.default_method })
  const withdraw = (ids: string[]) => act.mutate({ action: 'unapprove', ids })
  const highlighted = focus ? findApp(X.apps, focus) : undefined
  const settings = (X.settings ?? []).filter((s) => opco === 'all' || s.opcos.includes(opco)).length
  const verified = (v?.rows ?? []).filter((r) => r.status === 'verified')

  return (
    <div className="flex flex-col gap-5">
      <Banner v={v} down={down} urgentApps={urgentApps} onUrgent={() => setChooser(true)} auto={auto} />

      <Panel className="grid gap-6 p-6 md:grid-cols-[auto_minmax(0,1fr)] md:items-center">
        <div className="flex items-baseline gap-3">
          <span className="tabular text-[40px] leading-none tracking-tight">{num(vulns - noPatch)}</span>
          <span className="text-sm text-ink-3">vulnerabilities<br />these fixes close</span>
        </div>
        <div className="text-sm text-ink-2">
          <p>
            <b>{num(inOpco.length)} fixes</b> cover the <b>{num(vulns)} vulnerabilities</b> Defender found:{' '}
            {KINDS.filter(([k]) => k !== 'none' && ofKind(k)).map(([k], i, all) => (
              <span key={k}>{i > 0 && (i === all.length - 1 ? ' and ' : ', ')}{num(ofKind(k))} {KIND_PHRASE[k][ofKind(k) === 1 ? 0 : 1]}</span>
            ))}
            {settings > 0 && <>, plus <Link to="/fixes/settings" className="underline decoration-hairline underline-offset-2 hover:decoration-ink"><b>{num(settings)} security settings</b></Link> to change</>}.{' '}
            {num(inOpco.filter((a) => a.urgency.level === 1).length)} are marked “Fix now”.
          </p>
          <p className="mt-1.5">
            {noPatch > 0
              ? <><b style={{ color: statusColor.warning }}>{num(noPatch)} have no fix from the vendor yet</b>: their cards say how to protect the computers until one comes.</>
              : <>Every vulnerability has a fix from its vendor today.</>}
          </p>
          <p className="mt-1.5 text-xs text-ink-3">
            Urgency, numbers and commands come from Defender data and fixed catalogues; the AI only explains them. Built {ago(X.built_at)}.
          </p>
          {verified.length > 0 && (
            <Link to="/fixes/history" className="mt-2 inline-flex items-center gap-1.5 text-sm font-medium hover:underline" style={{ color: statusColor.good }}
              title={verified.map((r) => `${r.app} on ${r.device_name}`).join('\n')}>
              <ShieldCheck className="size-4" /> Already fixed: {verified.length} · verified by Defender · see the history
            </Link>
          )}
        </div>
      </Panel>

      <div className="flex flex-wrap gap-1 rounded-xl border border-hairline bg-panel p-1 text-sm" role="group" aria-label="How it gets fixed">
        {([['all', 'All fixes', 'Every update and upgrade', inOpco.length], ...KINDS.map(([k, l, h]) => [k, l, h, ofKind(k)] as const)] as const).map(([k, label, hint, n]) => (
          <button key={k} onClick={() => pickKind(k)} aria-pressed={kind === k} title={hint}
            className={cn('flex items-center gap-2 rounded-lg px-3.5 py-1.5', kind === k ? 'pill-on' : 'hover:bg-well', !n && kind !== k && 'text-ink-3')}>
            {label} <span className="tabular opacity-60">{n}</span>
          </button>
        ))}
      </div>
      {kind !== 'all' && <p className="-mt-2 text-xs text-ink-3">{KINDS.find(([k]) => k === kind)?.[2]}.</p>}

      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap gap-2 text-sm">
          {([[0, 'All', inKind.length], [1, LEVEL[1].label, count(1)], [2, LEVEL[2].label, count(2)], [3, LEVEL[3].label, count(3)]] as const).map(([l, label, n]) => (
            <button key={l} onClick={() => setLevel(l)} aria-pressed={level === l}
              className={cn('flex items-center gap-2 rounded-full border px-3.5 py-1.5', level === l ? 'pill-on' : 'border-hairline bg-panel hover:bg-well')}>
              {l !== 0 && <span className="size-2 rounded-full" style={{ background: LEVEL[l].color }} />}
              {label} <span className="tabular opacity-60">{n}</span>
            </button>
          ))}
        </div>
        <label className="flex items-center gap-2 rounded-lg border border-hairline-strong bg-field px-3 py-1.5 text-sm transition-[border-color,box-shadow] focus-within:border-blue/60 focus-within:ring-3 focus-within:ring-blue/15">
          <Search className="size-3.5 text-ink-3" />
          <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Find an app" className="w-40 bg-transparent outline-none placeholder:text-ink-3" />
        </label>
      </div>

      {apps.length ? (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2 2xl:grid-cols-3">
          {apps.map((a) => (
            <FixCard key={a.key} a={a} rank={X.apps.indexOf(a) + 1} rows={rowsBySoftware.get(softwareOf(a)) ?? []}
              engine={!!v} busy={act.isPending} highlight={highlighted === a} onApprove={approve} onWithdraw={withdraw} />
          ))}
        </div>
      ) : <Empty text={kind === 'none' ? 'Nothing here: every vulnerability has a fix from its vendor.' : kind === 'os' ? 'No Windows updates needed: Defender found no holes in Windows itself.' : 'No apps match this filter.'} />}

      {v && <BasketBar v={v} />}
      {v && <UrgentChooser open={chooser} onClose={() => setChooser(false)} rows={urgentRows} onApprove={(ids) => { approve(ids); setChooser(false) }} />}
      {act.error && <div className="fixed bottom-24 right-6 z-30 rounded-xl border bg-panel px-4 py-3 text-sm shadow-lg" style={{ borderColor: statusColor.critical }}>{String((act.error as Error).message)}</div>}
    </div>
  )
}

/* ───────── banner: tells everyone the portal can fix things ───────── */

function Banner({ v, down, urgentApps, onUrgent, auto }: {
  v?: FixView; down: boolean; urgentApps: number; onUrgent: () => void; auto: ReturnType<typeof useAutoStart>
}) {
  const [how, setHow] = useState(false)
  if (down) {
    return (
      <Panel className="flex flex-wrap items-center gap-4 p-5">
        <span className="grid size-11 place-items-center rounded-xl bg-well"><Zap className="size-5 text-ink-3" /></span>
        <div className="min-w-0 flex-1">
          <div className="font-semibold">Automatic fixing</div>
          <GettingReady what="automatic fixing" {...auto} off="Automatic fixing is switched off. You can still copy the commands below."
            retryLabel="Switch it on (takes ~10 seconds)" className="mt-1" />
        </div>
      </Panel>
    )
  }
  if (!v) return null
  const devices = Object.entries(v.probes)
  return (
    <section className="overflow-hidden rounded-[20px] border border-blue/35 bg-[color-mix(in_oklab,var(--blue)_8%,var(--panel))] shadow-elev">
      <div className="flex flex-wrap items-center gap-4 p-5">
        <span className="tile-signal grid size-11 place-items-center rounded-[11px]"><Zap className="size-5" /></span>
        <div className="min-w-0 flex-1">
          <div className="text-[17px] font-semibold tracking-tight">The portal can fix these for you</div>
          <p className="text-sm text-ink-2">
            Press <b className="whitespace-nowrap"><Zap className="mb-0.5 inline size-3.5 text-sky" aria-hidden /> Fix it for me</b> next to a computer to put the fix in your basket. Nothing runs until you press <b>Run fixes</b>, and Defender confirms every fix afterwards.
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <button onClick={() => setHow(!how)} className="rounded-lg border border-hairline bg-panel px-3 py-2 text-sm font-medium hover:bg-well" aria-expanded={how}>How it works</button>
          <button onClick={onUrgent} disabled={!urgentApps} className="inline-flex items-center gap-2 rounded-lg btn-blue px-4 py-2 text-sm font-medium text-white disabled:opacity-40">
            <Zap className="size-4" /> Fix all {urgentApps} urgent apps
          </button>
        </div>
      </div>
      {how && (
        <ol className="grid gap-px border-t border-signal/20 bg-signal/10 text-sm sm:grid-cols-5 animate-in fade-in duration-200">
          {[
            ['Found', 'Defender finds an old app with known holes'],
            ['Explained', 'The card says what’s wrong, why now and the fix'],
            ['Approved', 'You press ⚡ Fix it for me (you can take it out again)'],
            ['Fixed', 'You press Run fixes: the app is updated or removed'],
            ['Verified ✓', 'Defender rescans (2–6 h) and confirms it’s gone'],
          ].map(([t, d], i) => (
            <li key={t} className="bg-panel/80 p-4">
              <div className="text-xs font-semibold text-signal">Step {i + 1}</div>
              <div className="font-medium">{t}</div>
              <div className="mt-0.5 text-xs text-ink-3">{d}</div>
            </li>
          ))}
        </ol>
      )}
      {devices.length > 0 && (
        <div className="flex flex-wrap gap-x-5 gap-y-1 border-t border-signal/20 px-5 py-2.5 text-xs text-ink-3">
          {devices.map(([d, p]) => (
            <span key={d} className="flex items-center gap-1.5">
              <span className="size-1.5 rounded-full" style={{ background: !p.error ? statusColor.good : p.error.includes('switched off') ? statusColor.warning : statusColor.critical }} />
              <b className="font-medium text-ink-2">{d}</b> {!p.error ? 'reachable' : p.error.includes('switched off') ? 'switched off (a fix run switches it on)' : 'not reachable'}
            </span>
          ))}
        </div>
      )}
    </section>
  )
}

/* ───────── one app: advice + parcel tracker + a fix button per computer ───────── */

const TRACK = ['Found', 'Explained', 'Approved', 'Fixed', 'Verified'] as const

/** How far one computer got: 1 found, 2 explained, 3 approved (or tried and failed), 4 fixed, 5 verified by Defender. */
function rowStep(r: FixRow, explained: boolean): number {
  if (r.status === 'verified' || r.status === 'gone') return 5
  if (r.status === 'done' || r.status === 'still_there') return 4
  if (['approved', 'queued', 'running', 'failed'].includes(r.status)) return 3
  return explained ? 2 : 1
}

/** Per step, how many of the card's computers reached it; a step is done only when all of them did. */
function trackerCounts(a: { ai: unknown; fix: unknown }, rows: FixRow[]): { total: number; reached: number[] } {
  const explained = !!(a.ai || a.fix)
  const fixable = rows.filter((r) => r.action !== 'none')
  if (!fixable.length) return { total: 1, reached: [1, explained ? 1 : 0, 0, 0, 0] }
  const steps = fixable.map((r) => rowStep(r, explained))
  return { total: fixable.length, reached: TRACK.map((_, i) => steps.filter((s) => s > i).length) }
}

function Tracker({ total, reached }: { total: number; reached: number[] }) {
  const many = total > 1
  return (
    <div className="flex items-center" aria-label={`Progress: ${TRACK.map((t, i) => `${t} ${reached[i]} of ${total}`).join(', ')}`}>
      {TRACK.map((t, i) => {
        const n = reached[i]
        const done = n >= total
        const part = n > 0 && !done
        const next = i < TRACK.length - 1 ? reached[i + 1] / total : 0
        return (
          <div key={t} className={cn('flex items-center', i < TRACK.length - 1 && 'flex-1')}>
            <div className="flex flex-col items-center gap-1">
              <span className={cn('tabular grid size-5 place-items-center rounded-full border-2 text-[9px] font-bold transition-colors duration-500',
                done ? 'border-sky bg-sky text-white' : part ? 'border-sky bg-sky/20 text-sky' : 'border-hairline bg-panel')}>
                {done ? <Check className="size-3 animate-in zoom-in-50 duration-300" strokeWidth={3} /> : part ? n : null}
              </span>
              <span className={cn('whitespace-nowrap text-[10px]', done || part ? 'font-medium text-ink' : 'text-ink-3')}>{t}</span>
              {many && <span className={cn('tabular -mt-1 text-[9px]', part ? 'font-semibold text-sky' : 'text-ink-3')}>{n} of {total}</span>}
            </div>
            {i < TRACK.length - 1 && (
              <span className={cn('mx-1 h-0.5 flex-1 overflow-hidden rounded-full bg-hairline', many ? 'mb-7' : 'mb-4')}>
                <span className="block h-full bg-sky transition-[width] duration-700 ease-out" style={{ width: `${Math.round(next * 100)}%` }} />
              </span>
            )}
          </div>
        )
      })}
    </div>
  )
}

function FixCard({ a, rank, rows, engine, busy, highlight, onApprove, onWithdraw }: {
  a: Uc3FixApp; rank: number; rows: FixRow[]; engine: boolean; busy: boolean; highlight: boolean
  onApprove: (ids: string[]) => void; onWithdraw: (ids: string[]) => void
}) {
  const kevHref = useKevThreatHref()
  const lv = LEVEL[a.urgency.level]
  const ai = (a.source || '').startsWith('ai')
  const txt = a.ai ?? {}
  const kindOf = fixKind(a)
  const ended = pastEos(a)
  const ending = nearEos(a)
  const noPatch = a.no_patch ?? []
  // a.findings counts only what Defender still lists, so add back the holes already fixed on other computers
  const fixedVulns = rows.filter((r) => cleared(r) && !isSetting(r)).reduce((s, r) => s + r.findings, 0)
  const eosList = (vs: typeof ended) => vs.map((v) => `${v.version}${v.eos?.date ? ` (${shortDate(v.eos.date)})` : ''}`).join(', ')
  return (
    <section id={`fix-${softwareOf(a)}`} className={cn('flex scroll-mt-28 flex-col overflow-hidden rounded-2xl border border-hairline bg-panel transition-shadow', highlight && 'ring-2 ring-signal ring-offset-2 ring-offset-canvas')}>
      <span className="h-[3px]" style={{ background: lv.color }} />
      <div className="flex flex-1 flex-col gap-4 p-5">
        <div className="flex items-start gap-3">
          <span className="tabular grid size-8 shrink-0 place-items-center rounded-lg bg-well text-xs font-semibold text-ink-2">#{rank}</span>
          <div className="min-w-0 flex-1">
            <h3 className="font-semibold leading-tight">{a.app}</h3>
            <div className="mt-1 flex flex-wrap gap-x-3 text-xs text-ink-3">
              <span>{a.findings + fixedVulns ? `${num(a.findings + fixedVulns)} vulnerabilities${fixedVulns ? ` · ${num(fixedVulns)} fixed` : ''}` : 'no known holes yet'}</span>
              {a.fix_by && <span title="The latest date allowed by our patching rules (SLA). Fix now still means now.">fix by {shortDate(a.fix_by)} (SLA deadline)</span>}
            </div>
            <div className="mt-1.5"><Tag tone={kindOf === 'none' ? 'warn' : undefined}>{KINDS.find(([k]) => k === kindOf)?.[1]}</Tag></div>
          </div>
          <span className="flex shrink-0 items-center gap-1.5 text-xs font-medium" style={{ color: lv.color }}>
            {a.urgency.level === 1 && <AlertTriangle className="size-3.5" />}{a.urgency.label.split(':')[0]}
          </span>
        </div>

        {txt.what_is_wrong && <p className="text-sm leading-relaxed text-ink-2">{txt.what_is_wrong}</p>}

        {(ended.length > 0 || ending.length > 0 || noPatch.length > 0) && (
          <ul className="space-y-1 rounded-xl bg-well px-3.5 py-2.5 text-xs text-ink-2">
            {ended.length > 0 && <li><b className="text-ink">Support ended:</b> {eosList(ended)}. The vendor no longer fixes these versions, so updating within them is not enough.</li>}
            {ending.length > 0 && <li><b className="text-ink">Support ends soon:</b> {eosList(ending)}. Plan the move to a supported version.</li>}
            {noPatch.length > 0 && (
              <li title={noPatch.join(', ')}>
                <b style={{ color: statusColor.warning }}>No fix from the vendor yet:</b>{' '}
                {noPatch.length >= a.cves ? 'for any of its holes' : `for ${num(noPatch.length)} of its ${num(a.cves)} holes (updating closes the others)`}.
                Reduce the risk another way until the fix comes.
              </li>
            )}
          </ul>
        )}

        <Tracker {...trackerCounts(a, rows)} />

        {/* the computers this app is on, each with its own fix button */}
        <div className="rounded-xl border border-hairline">
          <div className="flex items-center justify-between gap-3 border-b border-hairline px-3.5 py-2 text-xs">
            <span className="font-medium text-ink-2">On your computers</span>
            <span className="truncate text-ink-3">{a.fix.action}</span>
          </div>
          {rows.length > 0 && kindOf !== 'none' && (
            <div className="border-b border-hairline bg-well/50 px-3.5 py-1.5 text-xs empty:hidden"><FixedSoFar rows={rows} /></div>
          )}
          {rows.length && kindOf !== 'none' ? (
            <ul className="divide-y divide-hairline">
              {rows.map((r) => <ComputerRow key={r.fix_id} r={r} busy={busy} onApprove={onApprove} onWithdraw={onWithdraw} />)}
            </ul>
          ) : (
            <ul className="divide-y divide-hairline">
              {a.devices.map((d) => (
                <li key={d.name} className="flex items-center justify-between gap-3 px-3.5 py-2.5 text-sm">
                  <span className="font-medium">{d.name}</span>
                  <span className="text-xs text-ink-3">
                    {kindOf === 'none' ? 'Nothing to install yet' : engine ? 'Not in the automatic fix plan yet' : 'Automatic fixing is off'}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </div>

        {a.fix.command && kindOf !== 'none' && (
          <div className="text-xs text-ink-3">
            Prefer to do it yourself? <CommandLine command={a.fix.command} />
          </div>
        )}

        {txt.why_now && (
          <Details title="Why now">
            <p className="text-sm leading-relaxed text-ink-2">{txt.why_now}</p>
            {txt.worst_case && <p className="mt-2 text-sm text-ink-2"><b className="text-ink">Worst case if ignored: </b>{txt.worst_case}</p>}
          </Details>
        )}
        {txt.steps?.length ? (
          <Details title={<>Step by step (doing it by hand) {ai && <AiBadge />}</>}>
            <ol className="ml-4 list-decimal space-y-1 text-sm text-ink-2">{txt.steps.map((s, i) => <li key={i}>{s}</li>)}</ol>
            {a.fix.note && <p className="mt-2 text-xs text-ink-3">{a.fix.note}</p>}
          </Details>
        ) : null}
        {(txt.verify || txt.side_effects) && (
          <Details title="How to check it worked · what users will notice">
            {txt.verify && <p className="text-sm text-ink-2"><b className="text-ink">Check: </b>{txt.verify}</p>}
            {txt.side_effects && <p className="mt-2 text-sm text-ink-2"><b className="text-ink">Users will notice: </b>{txt.side_effects}</p>}
          </Details>
        )}
        {a.kev_cves.length > 0 && (
          <Details title={`On the CISA “used by attackers” list (${a.kev_cves.length})`}>
            <ul className="space-y-1.5 text-sm text-ink-2">
              {a.kev_cves.map((k) => (
                <li key={k.cve} className="flex items-start justify-between gap-2">
                  <span><span className="tabular font-medium text-ink">{k.cve}</span>{k.name ? ` · ${k.name}` : ''}</span>
                  {kevHref(k.cve) && <HopLink to={kevHref(k.cve)!} title="What the outside world says about this hole, and whether anyone used it on us">Threat news</HopLink>}
                </li>
              ))}
            </ul>
          </Details>
        )}

        <div className="mt-auto flex flex-wrap items-center gap-2 border-t border-hairline pt-3 text-xs text-ink-3">
          {ai ? <><AiBadge text="AI-explained · check before acting" /></> : <Tag>Data-based text (no AI)</Tag>}
          <HopLink to={`/uc3/all?q=${encodeURIComponent(softwareOf(a))}`} title="This app's holes in our full vulnerability list">Vulnerabilities</HopLink>
          {a.fix.url && (
            <a href={a.fix.url} target="_blank" rel="noopener noreferrer" className="ml-auto inline-flex items-center gap-1 font-medium text-ink hover:underline">
              Official download <ExternalLink className="size-3" />
            </a>
          )}
        </div>
      </div>
    </section>
  )
}

/** Gone from Defender's list: fixed and checked, or cleared before the fix ran. */
const cleared = (r: FixRow) => r.status === 'verified' || r.status === 'gone'

/** "1 of 2 computers fixed · 7 of 14 vulnerabilities gone", for the card's computer list. */
function FixedSoFar({ rows }: { rows: FixRow[] }) {
  const fixable = rows.filter((r) => r.action !== 'none' && !isSetting(r))
  if (fixable.length < 2 && !fixable.some(cleared)) return null
  const done = fixable.filter(cleared)
  const vulns = fixable.reduce((s, r) => s + r.findings, 0)
  const gone = done.reduce((s, r) => s + r.findings, 0)
  return (
    <span className="tabular text-ink-3">
      <b className={done.length ? 'text-ink' : undefined}>{done.length} of {fixable.length}</b> computers fixed
      {vulns > 0 && <> · <b className={gone ? 'text-ink' : undefined}>{num(gone)} of {num(vulns)}</b> vulnerabilities gone</>}
    </span>
  )
}

function ComputerRow({ r, busy, onApprove, onWithdraw }: { r: FixRow; busy: boolean; onApprove: (ids: string[]) => void; onWithdraw: (ids: string[]) => void }) {
  const what = r.action === 'setting' ? 'changes this setting' : r.action === 'remove' ? 'removes the old version' : r.action === 'replace' ? 'replaces it with the current version' : 'updates it to the latest version'
  return (
    <li className="flex flex-wrap items-center gap-x-3 gap-y-1.5 px-3.5 py-2.5">
      <div className="min-w-0 flex-1">
        <div className="text-sm font-medium">{r.device_name} {r.version && <span className="font-normal text-ink-3">· {r.version}</span>}</div>
        {!isSetting(r) && r.findings > 0 && (
          <div className="mt-0.5 text-xs text-ink-3">
            {num(r.findings)} vulnerabilit{r.findings === 1 ? 'y' : 'ies'}{cleared(r) ? ' fixed' : ' on this computer'}
          </div>
        )}
        <div className="mt-0.5"><StatusPill r={r} /></div>
        {r.message && ['failed', 'done', 'still_there'].includes(r.status) && <div className="mt-0.5 line-clamp-2 text-[11px] text-ink-3">{r.message}</div>}
      </div>
      {r.action === 'none' ? (
        <span className="max-w-[55%] text-right text-xs text-ink-3">{r.note || 'No action needed'}</span>
      ) : canApprove(r) ? (
        <button
          onClick={() => onApprove([r.fix_id])}
          disabled={busy}
          title={`Puts it in your basket: the assistant ${what} when you press Run fixes`}
          className="btn-blue inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-semibold disabled:opacity-50"
        >
          <Zap className="size-3.5" /> {r.status === 'failed' ? 'Try again' : 'Fix it for me'}
        </button>
      ) : r.status === 'approved' ? (
        <button onClick={() => onWithdraw([r.fix_id])} disabled={busy} className="inline-flex items-center gap-1.5 rounded-lg border border-hairline px-3 py-1.5 text-xs font-medium hover:bg-well disabled:opacity-50">
          <Undo2 className="size-3.5" /> Take out of basket
        </button>
      ) : r.status === 'verified' ? (
        <ShieldCheck className="size-5" style={{ color: statusColor.good }} />
      ) : null}
    </li>
  )
}

/* ───────── security settings: wrong Windows/Defender settings (UC3 advice) + "fix it for me" (UC1 fix engine) ───────── */

type SettingFilter = 'all' | 'auto' | 'manual'

function SettingsCards() {
  const { data, error, isLoading } = useUc3Data()
  const fix = useFix()
  const act = useFixAction()
  const { opco } = useFilters()
  const [params] = useSearchParams()
  const [filter, setFilter] = useState<SettingFilter>('all')
  const [q, setQ] = useState(params.get('q') ?? '')                  // ?q= from the Summary's "Fix" button
  const v = fix.data
  const down = fix.error instanceof FixDown
  const auto = useAutoStart(down, 'fix')
  const rowsByConfig = useMemo(() => {
    const m = new Map<string, FixRow[]>()
    for (const r of v?.rows ?? []) {
      if (!isSetting(r)) continue
      const id = r.config_id ?? r.software_name.replace('setting:', '')
      m.set(id, [...(m.get(id) ?? []), r])
    }
    return m
  }, [v])

  if (isLoading || error || !data) return <Uc3Loading error={error} />
  if (!data.fixes?.settings?.length) return <Empty text="No security-setting checks yet. Run the vulnerability update to read them from Defender." />
  const canAuto = (s: Uc3FixSetting) => (rowsByConfig.get(s.config_id) ?? []).some((r) => r.action === 'setting')
  const inOpco = data.fixes.settings.filter((s) => opco === 'all' || s.opcos.includes(opco))
  const autoCount = inOpco.filter(canAuto).length
  const shown = inOpco
    .filter((s) => (filter === 'all' || (filter === 'auto') === canAuto(s)) && (!q || s.app.toLowerCase().includes(q.toLowerCase())))
    .sort((a, b) => Number(canAuto(b)) - Number(canAuto(a)))             // the ones the portal can change first
  const approve = (ids: string[]) => v && act.mutate({ action: 'approve', ids, method: v.default_method })
  const withdraw = (ids: string[]) => act.mutate({ action: 'unapprove', ids })
  const ready = shown.flatMap((s) => rowsByConfig.get(s.config_id) ?? []).filter((r) => r.action === 'setting' && canApprove(r))

  return (
    <div className="flex flex-col gap-5">
      {down && <Banner v={v} down urgentApps={0} onUrgent={() => {}} auto={auto} />}

      <Panel className="grid gap-6 p-6 md:grid-cols-[auto_minmax(0,1fr)] md:items-center">
        <div className="flex items-baseline gap-3">
          <span className="tabular text-[40px] leading-none tracking-tight">{num(inOpco.length)}</span>
          <span className="text-sm text-ink-3">security settings<br />need changing</span>
        </div>
        <div className="text-sm text-ink-2">
          <p>
            Windows and Defender settings that are weaker than Microsoft recommends. They are <b>not vulnerabilities</b> (no app has a hole, so they are not in the vulnerability count)
            and <b>not alerts</b> (nothing has happened): it is a door left unlocked.
          </p>
          <p className="mt-1.5">
            The portal can change <b>{num(autoCount)}</b> of them for you with <b>⚡ Fix it for me</b>. The other <b>{num(inOpco.length - autoCount)}</b> need an IT person,
            usually through Group Policy or Intune, because changing them on one computer could lock people out.
          </p>
          <p className="mt-1.5 text-xs text-ink-3">Defender re-checks settings by itself, usually within a day; the card then shows Verified.</p>
        </div>
      </Panel>

      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap gap-2 text-sm">
          {([['all', 'All', inOpco.length], ['auto', 'The portal can fix', autoCount], ['manual', 'Needs a person', inOpco.length - autoCount]] as const).map(([f, label, n]) => (
            <button key={f} onClick={() => setFilter(f)} aria-pressed={filter === f}
              className={cn('flex items-center gap-2 rounded-full border px-3.5 py-1.5', filter === f ? 'pill-on' : 'border-hairline bg-panel hover:bg-well')}>
              {f === 'auto' && <Zap className="size-3.5" />}{f === 'manual' && <UserRound className="size-3.5" />}
              {label} <span className="tabular opacity-60">{n}</span>
            </button>
          ))}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {ready.length > 0 && (
            <button onClick={() => approve(ready.map((r) => r.fix_id))} disabled={act.isPending}
              title="Puts every setting shown here that the portal can change into your basket. Nothing runs until you press Run fixes."
              className="btn-blue inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-sm font-semibold disabled:opacity-50">
              <Zap className="size-4" /> Fix all {ready.length} for me
            </button>
          )}
          <label className="flex items-center gap-2 rounded-lg border border-hairline-strong bg-field px-3 py-1.5 text-sm transition-[border-color,box-shadow] focus-within:border-blue/60 focus-within:ring-3 focus-within:ring-blue/15">
            <Search className="size-3.5 text-ink-3" />
            <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Find a setting" className="w-40 bg-transparent outline-none placeholder:text-ink-3" />
          </label>
        </div>
      </div>

      {shown.length ? (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2 2xl:grid-cols-3">
          {shown.map((s) => (
            <SettingCard key={s.key} s={s} rows={rowsByConfig.get(s.config_id) ?? []} engine={!!v} busy={act.isPending}
              onApprove={approve} onWithdraw={withdraw} />
          ))}
        </div>
      ) : <Empty text="No settings match this filter." />}

      {v && <BasketBar v={v} />}
      {act.error && <div className="fixed bottom-24 right-6 z-30 rounded-xl border bg-panel px-4 py-3 text-sm shadow-lg" style={{ borderColor: statusColor.critical }}>{String((act.error as Error).message)}</div>}
    </div>
  )
}

function SettingCard({ s, rows, engine, busy, onApprove, onWithdraw }: {
  s: Uc3FixSetting; rows: FixRow[]; engine: boolean; busy: boolean; onApprove: (ids: string[]) => void; onWithdraw: (ids: string[]) => void
}) {
  const lv = LEVEL[s.urgency.level]
  const txt = s.ai ?? {}
  const ai = (s.source || '').startsWith('ai')
  const autoRow = rows.find((r) => r.action === 'setting')
  const link = s.microsoft.links?.[0]
  return (
    <section id={`setting-${s.config_id}`} className="flex scroll-mt-28 flex-col overflow-hidden rounded-2xl border border-hairline bg-panel">
      <span className="h-[3px]" style={{ background: lv.color }} />
      <div className="flex flex-1 flex-col gap-4 p-5">
        <div className="flex items-start gap-3">
          <span className="grid size-8 shrink-0 place-items-center rounded-lg bg-well text-ink-2"><SlidersHorizontal className="size-4" /></span>
          <div className="min-w-0 flex-1">
            <h3 className="font-semibold leading-tight">{s.app}</h3>
            <div className="mt-1 flex flex-wrap gap-x-3 text-xs text-ink-3">
              <span>{[s.category, s.subcategory].filter(Boolean).join(' · ')}</span>
              <span title="Microsoft's own score for how much this setting matters (0-10)">impact {s.impact}/10</span>
            </div>
          </div>
          <span className="shrink-0 text-xs font-medium" style={{ color: lv.color }}>{s.urgency.label.split(':')[0]}</span>
        </div>

        {(txt.what_is_wrong || s.microsoft.risk) && <p className="text-sm leading-relaxed text-ink-2">{txt.what_is_wrong ?? s.microsoft.risk}</p>}

        <Tracker {...trackerCounts(s, rows)} />

        <div className="rounded-xl border border-hairline">
          <div className="flex items-center justify-between gap-3 border-b border-hairline px-3.5 py-2 text-xs">
            <span className="font-medium text-ink-2">On your computers</span>
            <span className="truncate text-ink-3">{autoRow ? settingChange(autoRow) : 'Change by hand (needs a person)'}</span>
          </div>
          {rows.length ? (
            <ul className="divide-y divide-hairline">
              {rows.map((r) => <ComputerRow key={r.fix_id} r={r} busy={busy} onApprove={onApprove} onWithdraw={onWithdraw} />)}
            </ul>
          ) : (
            <ul className="divide-y divide-hairline">
              {s.devices.map((d) => (
                <li key={d.name} className="flex items-center justify-between gap-3 px-3.5 py-2.5 text-sm">
                  <span className="font-medium">{d.name}</span>
                  <span className="text-right text-xs text-ink-3">{engine ? 'Not in the automatic fix plan yet (after the next threat check)' : 'Automatic fixing is off'}</span>
                </li>
              ))}
            </ul>
          )}
        </div>

        {!autoRow && s.fix.note && (
          <p className="flex gap-2 rounded-lg bg-well px-3 py-2 text-xs leading-relaxed text-ink-2"><UserRound className="mt-0.5 size-3.5 shrink-0" />{s.fix.note}</p>
        )}
        {!autoRow && s.fix.command && (
          <div className="text-xs text-ink-3">For one computer, an IT person can run: <CommandLine command={s.fix.command} /></div>
        )}

        {txt.why_now && (
          <Details title="Why now">
            <p className="text-sm leading-relaxed text-ink-2">{txt.why_now}</p>
            {txt.worst_case && <p className="mt-2 text-sm text-ink-2"><b className="text-ink">Worst case if ignored: </b>{txt.worst_case}</p>}
          </Details>
        )}
        {(txt.verify || txt.side_effects) && (
          <Details title="How to check it worked · what users will notice">
            {txt.verify && <p className="text-sm text-ink-2"><b className="text-ink">Check: </b>{txt.verify}</p>}
            {txt.side_effects && <p className="mt-2 text-sm text-ink-2"><b className="text-ink">Users will notice: </b>{txt.side_effects}</p>}
            {autoRow?.note && <p className="mt-2 text-xs text-ink-3">{autoRow.note}</p>}
          </Details>
        )}
        {s.microsoft.remediation && (
          <Details title="Microsoft's advice">
            <p className="whitespace-pre-line text-sm leading-relaxed text-ink-2">{s.microsoft.remediation}</p>
          </Details>
        )}

        <div className="mt-auto flex flex-wrap items-center gap-2 border-t border-hairline pt-3 text-xs text-ink-3">
          {ai ? <AiBadge text="AI-explained · check before acting" /> : <Tag>Microsoft's text (no AI)</Tag>}
          {link && (
            <a href={link} target="_blank" rel="noopener noreferrer" className="ml-auto inline-flex items-center gap-1 font-medium text-ink hover:underline">
              Microsoft guidance <ExternalLink className="size-3" />
            </a>
          )}
        </div>
      </div>
    </section>
  )
}

/* ───────── basket bar: approved fixes waiting to run, and live progress while they run ───────── */

function BasketBar({ v }: { v: FixView }) {
  const act = useFixAction()
  const [review, setReview] = useState(false)
  const navigate = useNavigate()
  const watch = () => navigate('/fixes/progress')
  const [confirm, setConfirm] = useState(false)
  const [hideDone, setHideDone] = useState('')
  const approved = v.rows.filter((r) => r.status === 'approved')
  const approvedSettings = approved.filter(isSetting).length
  const inFlight = v.rows.filter((r) => r.status === 'queued' || r.status === 'running')
  const busy = v.worker.running || v.worker.elsewhere || inFlight.length > 0
  const byDevice = [...new Set(approved.map((r) => r.device_name))].sort().map((d) => [d, approved.filter((r) => r.device_name === d)] as const)
  const runSet = v.rows.filter((r) => r.started_at && (['queued', 'running'].includes(r.status) || v.worker.running))
  const finished = runSet.filter((r) => !['queued', 'running'].includes(r.status)).length
  const showDone = !busy && !approved.length && !!v.worker.message && v.worker.task === 'run' && hideDone !== v.worker.message
  return (
    <>
      {(busy || approved.length > 0 || showDone) && (
        <div className="sticky bottom-4 z-20 animate-in slide-in-from-bottom-4 fade-in duration-300">
          <div className="flex flex-wrap items-center gap-3 rounded-2xl border border-hairline bg-panel/95 px-5 py-3.5 shadow-[0_18px_40px_-16px_rgba(0,0,0,.35)] backdrop-blur">
            {busy ? (
              <>
                <Loader2 className="size-5 animate-spin text-sky" />
                <div className="min-w-0 flex-1">
                  <div className="text-sm font-semibold">
                    {v.worker.task === 'probe' ? 'Checking the computers…' : `Fixing…${runSet.length ? ` ${finished} of ${runSet.length} done` : ''}`}
                  </div>
                  <div key={v.worker.step} className="truncate text-xs text-ink-3 animate-in fade-in duration-300">{v.worker.step || 'Starting'}</div>
                  {runSet.length > 0 && (
                    <div className="mt-1.5 h-1 overflow-hidden rounded-full bg-well">
                      <div className="h-full rounded-full bg-sky transition-[width] duration-700 ease-out" style={{ width: `${Math.max(5, (finished / runSet.length) * 100)}%` }} />
                    </div>
                  )}
                </div>
                <button onClick={watch} className="rounded-lg border border-hairline px-3 py-2 text-sm font-medium hover:bg-well">Watch full screen</button>
              </>
            ) : approved.length ? (
              <>
                <span className="grid size-10 place-items-center rounded-xl bg-signal/15"><ShoppingBasket className="size-5 text-signal" /></span>
                <div className="min-w-0 flex-1">
                  <div className="text-sm font-semibold">{approved.length} fix{approved.length === 1 ? '' : 'es'} in your basket</div>
                  <div className="truncate text-xs text-ink-3">
                    {byDevice.map(([d, rs]) => `${d}: ${rs.length}`).join(' · ')} · clears {num(approved.reduce((n, r) => n + r.findings, 0))} findings, {approved.reduce((n, r) => n + r.kev, 0)} exploited holes{approvedSettings ? `, ${approvedSettings} security setting${approvedSettings === 1 ? '' : 's'}` : ''}
                  </div>
                </div>
                <button onClick={() => setReview(true)} className="rounded-lg border border-hairline px-3 py-2 text-sm font-medium hover:bg-well">Review</button>
                <button onClick={() => setConfirm(true)} disabled={act.isPending} className="inline-flex items-center gap-2 rounded-lg btn-blue px-4 py-2 text-sm font-medium text-white disabled:opacity-50">
                  <Play className="size-4" /> Run fixes
                </button>
              </>
            ) : (
              <>
                <ShieldCheck className="size-5" style={{ color: statusColor.good }} />
                <div className="min-w-0 flex-1 text-sm"><b>{v.worker.message}.</b> <span className="text-ink-3">Defender confirms within a few hours (next threat check).</span></div>
                <button onClick={watch} className="rounded-lg border border-hairline px-3 py-2 text-sm font-medium hover:bg-well">See the results</button>
                <button onClick={() => setHideDone(v.worker.message)} className="grid size-8 place-items-center rounded-lg hover:bg-well" aria-label="Hide"><X className="size-4" /></button>
              </>
            )}
          </div>
        </div>
      )}

      <Sheet open={review} onOpenChange={setReview}>
        <SheetContent side="right" className="w-full gap-0 overflow-y-auto border-hairline bg-canvas p-0 sm:max-w-[460px]">
          <SheetHeader className="border-b border-hairline bg-panel px-6 py-5">
            <SheetTitle className="flex items-center gap-2 text-lg"><ShoppingBasket className="size-5" /> Your fix basket</SheetTitle>
            <SheetDescription>These run when you press Run fixes. Take out anything you don’t want changed yet.</SheetDescription>
          </SheetHeader>
          <div className="flex flex-col gap-4 p-4">
            {byDevice.map(([d, rs]) => (
              <Panel key={d} className="p-4">
                <div className="mb-2 font-medium">{d}</div>
                <ul className="divide-y divide-hairline">
                  {rs.map((r) => (
                    <li key={r.fix_id} className="flex items-center justify-between gap-3 py-2 text-sm">
                      <span>{r.action === 'setting' ? 'Change setting:' : r.action === 'remove' ? 'Remove' : r.action === 'replace' ? 'Replace' : 'Update'} {r.app} <span className="text-ink-3">{r.version}</span></span>
                      <button onClick={() => act.mutate({ action: 'unapprove', ids: [r.fix_id] })} className="text-xs font-medium text-ink-2 hover:text-ink">Take out</button>
                    </li>
                  ))}
                </ul>
              </Panel>
            ))}
            {!approved.length && <Empty text="The basket is empty." />}
          </div>
        </SheetContent>
      </Sheet>

      <ConfirmDialog
        open={confirm}
        onClose={() => setConfirm(false)}
        title={`Run ${approved.length} fix${approved.length === 1 ? '' : 'es'} now?`}
        body={`${byDevice.map(([d, rs]) => `${d}: ${rs.length}`).join(', ')}. the assistant switches a computer on if it is off, closes the apps and updates or removes them${approvedSettings ? ', and changes the chosen security settings' : ''}. This changes the computers and the numbers on every page. Leave a switched-on VM running for about 6 hours so Defender can confirm.`}
        confirmLabel="Run the fixes"
        onConfirm={() => { act.mutate({ action: 'run' }); setConfirm(false); watch() }}
      />
    </>
  )
}

/* ───────── "fix all urgent": you choose the computers first ───────── */

function UrgentChooser({ open, onClose, rows, onApprove }: { open: boolean; onClose: () => void; rows: FixRow[]; onApprove: (ids: string[]) => void }) {
  const devices = [...new Set(rows.map((r) => r.device_name))].sort()
  const [picked, setPicked] = useState<Set<string>>(new Set())
  useEffect(() => { if (open) setPicked(new Set()) }, [open])
  const ids = rows.filter((r) => picked.has(r.device_name)).map((r) => r.fix_id)
  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="max-w-md border-hairline bg-panel">
        <DialogTitle className="flex items-center gap-2"><Zap className="size-5 text-signal" /> Fix all urgent apps</DialogTitle>
        <DialogDescription className="text-sm leading-relaxed text-ink-2">
          Urgent = holes attackers are known to use (CISA KEV list). Choose the computers: their urgent fixes go into your basket. Nothing runs yet.
        </DialogDescription>
        <ul className="flex flex-col gap-2">
          {devices.map((d) => {
            const rs = rows.filter((r) => r.device_name === d)
            return (
              <li key={d}>
                <label className="flex cursor-pointer items-center gap-3 rounded-xl border border-hairline p-3 hover:bg-well">
                  <input type="checkbox" className="size-4 accent-[var(--blue)]" checked={picked.has(d)}
                    onChange={(e) => setPicked((s) => { const n = new Set(s); if (e.target.checked) n.add(d); else n.delete(d); return n })} />
                  <span className="min-w-0 flex-1">
                    <span className="block text-sm font-medium">{d}</span>
                    <span className="block truncate text-xs text-ink-3">{rs.map((r) => r.app).join(', ')}</span>
                  </span>
                  <span className="tabular text-xs text-ink-2">{rs.length}</span>
                </label>
              </li>
            )
          })}
          {!devices.length && <li className="text-sm text-ink-3">Every urgent fix is already in the basket or done.</li>}
        </ul>
        <div className="mt-1 flex justify-end gap-2">
          <button onClick={onClose} className="rounded-lg border border-hairline px-4 py-2 text-sm hover:bg-well">Cancel</button>
          <button onClick={() => onApprove(ids)} disabled={!ids.length} className="rounded-lg btn-blue px-4 py-2 text-sm font-medium text-white disabled:opacity-40">
            Put {ids.length} in the basket
          </button>
        </div>
      </DialogContent>
    </Dialog>
  )
}

/* ───────── small parts ───────── */

function CommandLine({ command }: { command: string }) {
  const [done, setDone] = useState(false)
  return (
    <div className="mt-1.5 flex items-center gap-2 rounded-lg bg-well px-3 py-2">
      <code className="min-w-0 flex-1 truncate font-mono text-xs text-ink-2" title={command}>{command}</code>
      <button
        onClick={() => { navigator.clipboard?.writeText(command); setDone(true); setTimeout(() => setDone(false), 1400) }}
        className="flex shrink-0 items-center gap-1 rounded-md px-2 py-1 text-xs font-medium text-ink hover:bg-panel"
      >
        {done ? <><Check className="size-3.5" style={{ color: statusColor.good }} /> Copied</> : <><Copy className="size-3.5" /> Copy</>}
      </button>
    </div>
  )
}

function Details({ title, children }: { title: React.ReactNode; children: React.ReactNode }) {
  const [open, setOpen] = useState(false)
  return (
    <div className="border-t border-hairline pt-3">
      <button onClick={() => setOpen(!open)} className="flex w-full items-center justify-between gap-2 text-left text-sm font-medium" aria-expanded={open}>
        <span className="flex items-center gap-2">{title}</span>
        <ChevronDown className={cn('size-4 text-ink-3 transition-transform', open && 'rotate-180')} />
      </button>
      {open && <div className="mt-2.5 animate-in fade-in slide-in-from-top-1 duration-200">{children}</div>}
    </div>
  )
}

function AiBadge({ text = 'AI' }: { text?: string }) {
  return (
    <span className="inline-flex items-center gap-1 rounded-md bg-violet/15 px-1.5 py-0.5 text-[11px] font-medium text-violet">
      <Sparkles className="size-3" /> {text}
    </span>
  )
}
