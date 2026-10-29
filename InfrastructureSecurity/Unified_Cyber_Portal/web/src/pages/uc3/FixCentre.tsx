import { useEffect, useMemo, useState } from 'react'
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom'
import {
  AlertTriangle, Check, ChevronDown, ChevronRight, Copy, RotateCcw, ExternalLink, ListChecks, Loader2, Play, Search, ShieldCheck, ShoppingBasket,
  SlidersHorizontal, Sparkles, Undo2, UserRound, X, Zap,
} from 'lucide-react'
import { ConfirmDialog, StatusPill } from '@/components/FixLoop'
import { Choice, Empty, HopLink, Panel, Tabs, Tag } from '@/components/kit'
import { FixHistory } from './FixHistory'
import { AttackResponses } from './AttackResponses'
import { AgentFilterBar, AgentTags, RowFound, RunBanner, belongs, useAgentFilter } from '@/components/AgentTags'
import { VulnList } from '@/components/VulnList'
import { Dialog, DialogContent, DialogDescription, DialogTitle } from '@/components/ui/dialog'
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from '@/components/ui/sheet'
import { FixDown, canApprove, isSetting, settingChange, useFix, useFixAction, type FixRow, type FixView } from '@/lib/fix'
import { useFilters } from '@/lib/filters'
import { ago, num, shortDate } from '@/lib/format'
import { statusColor } from '@/lib/theme'
import { cn } from '@/lib/utils'
import { UC_DOT, UC_NAME } from '@/lib/runs'
import { useThreatMatchCounts } from '@/lib/uc1'
import { fixKind, nearEos, pastEos, useUc3Data, useUc3View, type FixKind, type Uc3FixApp, type Uc3FixSetting } from '@/lib/uc3'
import { GettingReady, useAutoStart } from '@/lib/services'
import { Uc3Loading } from './common'

const LEVEL = {
  1: { label: 'High', color: statusColor.critical },
  2: { label: 'Medium', color: statusColor.warning },
  3: { label: 'Low', color: 'var(--ink-3)' },
} as const

const softwareOf = (a: Uc3FixApp) => a.key.split(':').pop() ?? ''
/** The card a "Fix this" link means: exact software name or app name, else the first whose name starts with it. */
const findApp = (apps: Uc3FixApp[], focus: string) => {
  const f = focus.toLowerCase().replace(/\s+/g, '_')
  return apps.find((a) => softwareOf(a) === f || a.app.toLowerCase() === focus.toLowerCase())
    ?? apps.find((a) => softwareOf(a).startsWith(f))
}

type View = 'cards' | 'settings' | 'attacks' | 'history'
const VIEWS: [View, string][] = [['cards', 'Updates & upgrades'], ['settings', 'Security settings'], ['attacks', 'Attack responses'], ['history', 'Remediation history']]

/** The fix-type chips on Updates & upgrades (?type= picks one, e.g. from the Vulnerabilities overview). */
const KINDS: [FixKind, string, string][] = [
  ['update', 'Software update', 'A newer version of the software resolves the vulnerabilities'],
  ['os', 'OS security update', 'The vulnerabilities are in Windows itself: install the Windows security update (Windows Update, WSUS or Intune), usually with a restart'],
  ['upgrade', 'Software upgrade', 'At or near end of support: the vendor no longer issues security updates, so upgrade to a supported version'],
  ['none', 'Attention required', 'No security update available: apply compensating controls until the vendor releases one'],
]
const KIND_PHRASE: Record<FixKind, [string, string]> = {
  update: ['software update', 'software updates'], os: ['OS security update', 'OS security updates'],
  upgrade: ['software upgrade', 'software upgrades'], none: ['app needing attention', 'apps needing attention'],
}

/** Act › Fix: what to update and why (UC3 advice), and "fix it for me" on every computer (UC1 fix engine). */
export function FixCentre() {
  const { tab } = useParams()
  const navigate = useNavigate()
  const view: View = tab === 'history' || tab === 'settings' || tab === 'attacks' ? tab : 'cards'
  return (
    <div className="flex flex-col gap-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Remediation</h1>
          <p className="mt-1 text-sm text-ink-3">Remediate vulnerabilities and harden security settings through updates, upgrades and configuration changes, manually or with automated remediation</p>
        </div>
      </div>
      <Tabs<View> tabs={VIEWS} value={view} onChange={(t) => navigate(t === 'cards' ? '/fixes' : `/fixes/${t}`)} />
      {view === 'attacks' ? <AttackResponses /> : view === 'history' ? <FixHistory /> : view === 'settings' ? <SettingsCards /> : <FixCards />}
    </div>
  )
}

/* ───────────────────────── the card page ───────────────────────── */

function FixCards() {
  const { data, error, isLoading } = useUc3Data()
  const fix = useFix()
  const act = useFixAction()
  const { opco } = useFilters()
  const [params, setParams] = useSearchParams()
  const matchCounts = useThreatMatchCounts().data
  const inNews = matchCounts?.counts
  const [level, setLevel] = useState<0 | 1 | 2 | 3>(0)
  const typeParam = params.get('type')
  const [kind, setKind] = useState<'all' | FixKind>(KINDS.some(([k]) => k === typeParam) ? (typeParam as FixKind) : 'all')
  const [q, setQ] = useState('')
  const [chooser, setChooser] = useState(false)
  const agentFilter = useAgentFilter()
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

  // Per app: computer + CVE pairs Defender reports fixed that no version on that computer still has (the card's "fixed"
  // and the vulnerabilities pop-up count the same way). null for data built before the fixed list existed.
  const fixedPairs = useMemo(() => {
    if (!data?.fixed) return null
    const F = data.f.cols, X = data.fixed.cols
    const open = new Set(data.f.rows.map((r) => `${r[F.indexOf('sw')]}|${r[F.indexOf('d')]}|${r[F.indexOf('cve')]}`))
    const m = new Map<string, Set<string>>()
    for (const r of data.fixed.rows) {
      const sw = String(r[X.indexOf('sw')]), pair = `${r[X.indexOf('d')]}|${r[X.indexOf('cve')]}`
      if (!open.has(`${sw}|${pair}`)) m.set(sw, (m.get(sw) ?? new Set()).add(pair))
    }
    return new Map([...m].map(([sw, pairs]) => [sw, pairs.size]))
  }, [data])

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
  if (!X) return <Empty text="Remediation guidance is not available yet. Run the Vulnerability Agent to generate it." />
  const rowsOf = (a: Uc3FixApp) => rowsBySoftware.get(softwareOf(a)) ?? []
  const inOpcoAll = X.apps.filter((a) => opco === 'all' || a.opcos.includes(opco))
  // in the news before the Vulnerability Agent found it (the portal drops later matches); once known, this decides Threat Intel
  const newsOf = (a: Uc3FixApp) => (inNews ? inNews[softwareOf(a)] ?? 0 : undefined)
  const isAgent = (a: Uc3FixApp, ag: 'uc3' | 'uc1') => (ag === 'uc1' && newsOf(a) === 0 ? false : rowsOf(a).some((r) => belongs(r, ag)))
  const agentCounts = { uc3: inOpcoAll.filter((a) => isAgent(a, 'uc3')).length, uc1: inOpcoAll.filter((a) => isAgent(a, 'uc1')).length }
  const inOpco = agentFilter.agent ? inOpcoAll.filter((a) => isAgent(a, agentFilter.agent!) && rowsOf(a).some(agentFilter.matches)) : inOpcoAll
  const ofKind = (k: FixKind) => inOpco.filter((a) => fixKind(a) === k).length
  const inKind = inOpco.filter((a) => kind === 'all' || fixKind(a) === kind)
  const apps = inKind.filter((a) => (level === 0 || a.urgency.level === level) && (!q || a.app.toLowerCase().includes(q.toLowerCase())))
  const count = (l: number) => inKind.filter((a) => a.urgency.level === l).length
  const pickKind = (k: 'all' | FixKind) => {
    setKind(k)
    const n = new URLSearchParams(params)               // keep the other filters (agent, run) in the address
    if (k === 'all') n.delete('type')
    else n.set('type', k)
    setParams(n, { replace: true })
  }
  const clearFilters = () => {
    setQ(''); setLevel(0); setKind('all')
    const n = new URLSearchParams(params)
    for (const key of ['type', 'agent', 'since']) n.delete(key)
    setParams(n, { replace: true })
  }
  const noFixSw = new Set(X.apps.filter((a) => fixKind(a) === 'none').map(softwareOf))   // nothing to install yet
  const urgentRows = (v?.rows ?? []).filter((r) => r.stage === 1 && canApprove(r) && !noFixSw.has(r.software_name))
  const urgentApps = new Set(urgentRows.map((r) => r.software_name)).size
  const approve = (ids: string[]) => v && act.mutate({ action: 'approve', ids, method: v.default_method })
  const withdraw = (ids: string[]) => act.mutate({ action: 'unapprove', ids })
  const highlighted = focus ? findApp(X.apps, focus) : undefined
  const settings = (X.settings ?? []).filter((s) => opco === 'all' || s.opcos.includes(opco)).length
  const verified = (v?.rows ?? []).filter((r) => r.status === 'verified')
  // ?vulns=<software>: that card's vulnerabilities pop-up (a link can open it; Back closes it)
  const listSw = params.get('vulns')
  const listApp = listSw ? apps.find((a) => softwareOf(a) === listSw) ?? X.apps.find((a) => softwareOf(a) === listSw) : undefined
  const showList = (a: Uc3FixApp, replace = false) => { const n = new URLSearchParams(params); n.set('vulns', softwareOf(a)); setParams(n, { replace }) }
  const closeList = () => { const n = new URLSearchParams(params); n.delete('vulns'); setParams(n, { replace: true }) }
  const listAt = listApp ? apps.indexOf(listApp) : -1
  const step = (a: Uc3FixApp | undefined) => (a ? { name: a.app, go: () => showList(a, true) } : undefined)

  return (
    <div className="flex flex-col gap-5">
      <Banner v={v} down={down} urgentApps={urgentApps} onUrgent={() => setChooser(true)} auto={auto} />

      <Panel className="grid gap-6 p-6 md:grid-cols-[auto_minmax(0,1fr)] md:items-center">
        <div className="flex items-baseline gap-3">
          <span className="tabular text-[40px] leading-none tracking-tight">{num(vulns - noPatch)}</span>
          <span className="text-sm text-ink-3">vulnerabilities<br />these remediations close</span>
        </div>
        <div className="text-sm text-ink-2">
          <p>
            <b>{num(inOpco.length)} remediations</b> cover the <b>{num(vulns)} vulnerabilities</b> Defender found:{' '}
            {KINDS.filter(([k]) => k !== 'none' && ofKind(k)).map(([k], i, all) => (
              <span key={k}>{i > 0 && (i === all.length - 1 ? ' and ' : ', ')}{num(ofKind(k))} {KIND_PHRASE[k][ofKind(k) === 1 ? 0 : 1]}</span>
            ))}
            {settings > 0 && <>, plus <Link to="/fixes/settings" className="underline decoration-hairline underline-offset-2 hover:decoration-ink"><b>{num(settings)} security settings</b></Link> to change</>}.{' '}
            {num(inOpco.filter((a) => a.urgency.level === 1).length)} are marked High priority.
          </p>
          <p className="mt-1.5">
            {noPatch > 0
              ? <><b style={{ color: statusColor.warning }}>{num(noPatch)} have no security update available</b>: their cards list compensating controls until one is released.</>
              : <>A security update is available for every vulnerability.</>}
          </p>
          <p className="mt-1.5 text-xs text-ink-3">
            Priority, numbers and commands come from Defender data and fixed catalogues; the agent only explains them. Built {ago(X.built_at)}.
          </p>
          {verified.length > 0 && (
            <Link to="/fixes/history" className="mt-2 inline-flex items-center gap-1.5 text-sm font-medium hover:underline" style={{ color: statusColor.good }}
              title={verified.map((r) => `${r.app} on ${r.device_name}`).join('\n')}>
              <ShieldCheck className="size-4" /> Remediated: {verified.length} · verified by Defender · view history
            </Link>
          )}
        </div>
      </Panel>

      {/* one filter panel: search, then three labelled choices (each option shows how many apps it has) */}
      <Panel className="flex flex-col gap-3 p-4">
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-[minmax(0,1.3fr)_repeat(3,minmax(0,1fr))]">
          <Field label="Find an app">
            <label className="flex items-center gap-2 rounded-lg border border-hairline-strong bg-field px-3 py-2 text-sm transition-[border-color,box-shadow] focus-within:border-blue/60 focus-within:ring-3 focus-within:ring-blue/15">
              <Search className="size-3.5 shrink-0 text-ink-3" />
              <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Firefox, Java, Windows…" aria-label="Find an app" className="min-w-0 flex-1 bg-transparent outline-none placeholder:text-ink-3" />
            </label>
          </Field>
          <Field label="Found by">
            <Choice label="Found by" value={agentFilter.agent ?? 'all'} onChange={(a) => agentFilter.set(a === 'all' ? null : a as 'uc3' | 'uc1')} options={[
              { value: 'all', label: 'All agents', count: inOpcoAll.length },
              { value: 'uc3', label: UC_NAME.uc3, count: agentCounts.uc3, dot: 'var(--sky)' },
              { value: 'uc1', label: UC_NAME.uc1, count: agentCounts.uc1, dot: 'var(--violet)' }]} />
          </Field>
          <Field label="Remediation type">
            <Choice label="Remediation type" value={kind} onChange={(k) => pickKind(k as 'all' | FixKind)}
              options={[{ value: 'all', label: 'All remediation types', count: inOpco.length }, ...KINDS.map(([k, l]) => ({ value: k, label: l, count: ofKind(k) }))]} />
          </Field>
          <Field label="Priority">
            <Choice label="Priority" value={String(level)} onChange={(l) => setLevel(Number(l) as 0 | 1 | 2 | 3)} options={[
              { value: '0', label: 'All priorities', count: inKind.length },
              ...([1, 2, 3] as const).map((l) => ({ value: String(l), label: LEVEL[l].label, count: count(l), dot: LEVEL[l].color }))]} />
          </Field>
        </div>
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-ink-3">
          <span>Showing <b className="text-ink-2">{num(apps.length)}</b> of {num(inOpcoAll.length)} apps</span>
          {kind !== 'all' && <span>· {KINDS.find(([k]) => k === kind)?.[2]}</span>}
          {(q || level || kind !== 'all' || agentFilter.agent) && (
            <button onClick={clearFilters}
              className="ml-auto inline-flex items-center gap-1 rounded-md px-2 py-1 font-medium text-ink-2 hover:bg-well hover:text-ink">
              <RotateCcw className="size-3.5" /> Clear filters
            </button>
          )}
        </div>
      </Panel>
      <RunBanner filter={agentFilter} what="software remediations" />

      {apps.length ? (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2 2xl:grid-cols-3">
          {apps.map((a) => (
            <FixCard key={a.key} a={a} rank={X.apps.indexOf(a) + 1} rows={rowsOf(a)} isNew={agentFilter.isNew}
              engine={!!v} busy={act.isPending} highlight={highlighted === a} onApprove={approve} onWithdraw={withdraw}
              fixedCount={fixedPairs ? fixedPairs.get(softwareOf(a)) ?? 0 : undefined} inNews={newsOf(a)} onList={() => showList(a)}
              agent={agentFilter.agent} newsSplit={agentFilter.agent === 'uc1' ? matchCounts?.split?.[softwareOf(a)] ?? [0, 0] : undefined} />
          ))}
        </div>
      ) : <Empty text={agentFilter.agent ? 'No remediations from this agent match these filters.' : kind === 'none' ? 'No items: a security update is available for every vulnerability.' : kind === 'os' ? 'No Windows updates needed: Defender found no vulnerabilities in Windows itself.' : 'No apps match this filter.'} />}

      {listApp && (
        <VulnList app={listApp} software={softwareOf(listApp)} data={data} fixRows={v?.rows ?? []} engine={!!v} onClose={closeList}
          startAgent={agentFilter.agent} prev={listAt > 0 ? step(apps[listAt - 1]) : undefined} next={listAt >= 0 ? step(apps[listAt + 1]) : undefined} />
      )}
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
          <div className="font-semibold">Automated remediation</div>
          <GettingReady what="automated remediation" {...auto} off="Automated remediation is disabled. Commands below can still be copied and run manually."
            retryLabel="Enable automated remediation" className="mt-1" />
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
          <div className="text-[17px] font-semibold tracking-tight">Eligible for automated remediation</div>
          <p className="text-sm text-ink-2">
            Press <b className="whitespace-nowrap"><Zap className="mb-0.5 inline size-3.5 text-sky" aria-hidden /> Remediate</b> next to a device to add it to the remediation queue. Nothing runs until you select <b>Execute remediation</b>, and Defender verifies every change afterwards.
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <button onClick={() => setHow(!how)} className="rounded-lg border border-hairline bg-panel px-3 py-2 text-sm font-medium hover:bg-well" aria-expanded={how}>How it works</button>
          <button onClick={onUrgent} disabled={!urgentApps} className="inline-flex items-center gap-2 rounded-lg btn-blue px-4 py-2 text-sm font-medium text-white disabled:opacity-40">
            <Zap className="size-4" /> Remediate {urgentApps} high-priority apps
          </button>
        </div>
      </div>
      {how && (
        <ol className="grid gap-px border-t border-signal/20 bg-signal/10 text-sm sm:grid-cols-5 animate-in fade-in duration-200">
          {[
            ['Found', 'Defender identifies an application with known vulnerabilities'],
            ['Explained', 'Each card shows the issue, its priority and the remediation'],
            ['Approved', 'You select ⚡ Remediate (it can be removed from the queue)'],
            ['Remediated', 'You select Execute remediation: the application is updated or removed'],
            ['Verified ✓', 'Defender rescans (2–6 h) and confirms resolution'],
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
              <b className="font-medium text-ink-2">{d}</b> {!p.error ? 'reachable' : p.error.includes('switched off') ? 'switched off (a remediation run switches it on)' : 'not reachable'}
            </span>
          ))}
        </div>
      )}
    </section>
  )
}

/* ───────── one app: advice + parcel tracker + a fix button per computer ───────── */

const TRACK = ['Found', 'Explained', 'Approved', 'Remediated', 'Verified'] as const

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

function FixCard({ a, rank, rows, engine, busy, highlight, onApprove, onWithdraw, isNew, fixedCount, inNews, onList, agent, newsSplit }: {
  a: Uc3FixApp; rank: number; rows: FixRow[]; engine: boolean; busy: boolean; highlight: boolean; isNew: (r: FixRow) => boolean
  onApprove: (ids: string[]) => void; onWithdraw: (ids: string[]) => void
  /** Defender's own fixed count (see fixedPairs); inNews: how many of its vulnerabilities are in the news */
  fixedCount?: number; inNews?: number; onList: () => void
  /** set while "Found by: Threat Intel Agent" is chosen: its vulnerabilities on this app, [still open, fixed] */
  newsSplit?: [number, number]; agent?: 'uc3' | 'uc1' | null
}) {
  const lv = LEVEL[a.urgency.level]
  const ai = (a.source || '').startsWith('ai')
  const txt = a.ai ?? {}
  const kindOf = fixKind(a)
  const ended = pastEos(a)
  const ending = nearEos(a)
  const noPatch = a.no_patch ?? []
  // a.findings counts only what Defender still lists, so add back the vulnerabilities already fixed (Defender's fixed
  // list when there is one, else what the fix engine cleared)
  const fixedVulns = fixedCount ?? rows.filter((r) => cleared(r) && !isSetting(r)).reduce((s, r) => s + r.findings, 0)
  // the numbers follow the "Found by" filter: Threat Intel shows only what it found in the news first
  const [open, fixed] = newsSplit ?? [a.findings, fixedVulns]
  const total = open + fixed
  const kind = KINDS.find(([k]) => k === kindOf)
  const eosList = (vs: typeof ended) => vs.map((v) => `${v.version}${v.eos?.date ? ` (${shortDate(v.eos.date)})` : ''}`).join(', ')
  return (
    <section id={`fix-${softwareOf(a)}`} className={cn('flex scroll-mt-28 flex-col overflow-hidden rounded-2xl border border-hairline bg-panel transition-shadow', highlight && 'ring-2 ring-signal ring-offset-2 ring-offset-canvas')}>
      <span className="h-[3px]" style={{ background: lv.color }} />
      <div className="flex flex-1 flex-col gap-4 p-5">
        <div className="flex items-start gap-3">
          <span className="tabular grid size-8 shrink-0 place-items-center rounded-lg bg-well text-xs font-semibold text-ink-2">#{rank}</span>
          <div className="min-w-0 flex-1">
            <h3 className="font-semibold leading-tight">{a.app}</h3>
            {/* what kind of fix and the deadline, in one plain line */}
            <p className="mt-1 text-xs text-ink-3">
              <span title={kind?.[2]} style={{ color: kindOf === 'none' ? statusColor.warning : undefined }}>{kind?.[1]}</span>
              {a.fix_by && <span title="Latest date permitted by the patching SLA. High-priority items should be remediated now."> · due {shortDate(a.fix_by)}</span>}
            </p>
          </div>
          <span className="flex shrink-0 items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-medium"
            style={{ color: lv.color, background: `color-mix(in oklab, ${lv.color} 12%, transparent)` }}>
            {a.urgency.level === 1 && <AlertTriangle className="size-3.5" />}{lv.label} priority
          </span>
        </div>

        {total > 0 ? (
          <>
            <div className="flex flex-col gap-1.5">
              {agent && (
                <span className="flex items-center gap-1.5 text-[11px] text-ink-3">
                  <span className={cn('size-1.5 rounded-full', UC_DOT[agent])} />
                  {agent === 'uc1' ? `${UC_NAME.uc1}: reported in threat intelligence before Defender's scan` : `${UC_NAME.uc3}: found by Defender's scan`}
                </span>
              )}
              <div className="grid grid-cols-3 gap-2">
                <Stat n={total} label="Found" />
                <Stat n={open} label="Open" color={open ? statusColor.critical : undefined} />
                <Stat n={fixed} label="Remediated" color={fixed ? statusColor.good : undefined} />
              </div>
            </div>
            <AgentTags rows={rows} inNews={inNews} />
            <button onClick={onList}
              className="flex w-full items-center justify-center gap-2 rounded-xl bg-blue/15 px-3 py-2.5 text-sm font-semibold text-sky transition-colors hover:bg-blue/25">
              <ListChecks className="size-4" /> {newsSplit ? `View these ${num(total)}` : `View all ${num(total)}`} vulnerabilities <ChevronRight className="size-4" />
            </button>
          </>
        ) : <p className="text-sm text-ink-3">No known vulnerabilities yet.</p>}

        {txt.what_is_wrong && <p className="text-sm leading-relaxed text-ink-2">{txt.what_is_wrong}</p>}

        {(ended.length > 0 || ending.length > 0 || noPatch.length > 0) && (
          <ul className="space-y-1 rounded-xl bg-well px-3.5 py-2.5 text-xs text-ink-2">
            {ended.length > 0 && <li><b className="text-ink">Support ended:</b> {eosList(ended)}. The vendor no longer issues security updates for these versions, so updating within them is not enough.</li>}
            {ending.length > 0 && <li><b className="text-ink">Support ends soon:</b> {eosList(ending)}. Plan the move to a supported version.</li>}
            {noPatch.length > 0 && (
              <li title={noPatch.join(', ')}>
                <b style={{ color: statusColor.warning }}>No security update available:</b>{' '}
                {noPatch.length >= a.cves ? 'for any of its vulnerabilities' : `for ${num(noPatch.length)} of its ${num(a.cves)} vulnerabilities (updating remediates the others)`}.
                Apply compensating controls until a security update is released.
              </li>
            )}
          </ul>
        )}

        <Tracker {...trackerCounts(a, rows)} />

        {/* the computers this app is on, each with its own fix button */}
        <div className="rounded-xl border border-hairline">
          <div className="flex items-center justify-between gap-3 border-b border-hairline px-3.5 py-2 text-xs">
            <span className="font-medium text-ink-2">Affected devices</span>
            <span className="truncate text-ink-3">{a.fix.action}</span>
          </div>
          {rows.length > 0 && kindOf !== 'none' && (
            <div className="border-b border-hairline bg-well/50 px-3.5 py-1.5 text-xs empty:hidden"><FixedSoFar rows={rows} /></div>
          )}
          {rows.length && kindOf !== 'none' ? (
            <ul className="divide-y divide-hairline">
              {rows.map((r) => <ComputerRow key={r.fix_id} r={r} busy={busy} onApprove={onApprove} onWithdraw={onWithdraw} fresh={isNew(r)} />)}
            </ul>
          ) : (
            <ul className="divide-y divide-hairline">
              {a.devices.map((d) => (
                <li key={d.name} className="flex items-center justify-between gap-3 px-3.5 py-2.5 text-sm">
                  <span className="font-medium">{d.name}</span>
                  <span className="text-xs text-ink-3">
                    {kindOf === 'none' ? 'No update available yet' : engine ? 'Not yet in the automated remediation plan' : 'Automated remediation is disabled'}
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
            {txt.worst_case && <p className="mt-2 text-sm text-ink-2"><b className="text-ink">Potential impact: </b>{txt.worst_case}</p>}
          </Details>
        )}
        {txt.steps?.length ? (
          <Details title={<>Manual remediation steps {ai && <AiBadge />}</>}>
            <ol className="ml-4 list-decimal space-y-1 text-sm text-ink-2">{txt.steps.map((s, i) => <li key={i}>{s}</li>)}</ol>
            {a.fix.note && <p className="mt-2 text-xs text-ink-3">{a.fix.note}</p>}
          </Details>
        ) : null}
        {(txt.verify || txt.side_effects) && (
          <Details title="Verification and user impact">
            {txt.verify && <p className="text-sm text-ink-2"><b className="text-ink">Check: </b>{txt.verify}</p>}
            {txt.side_effects && <p className="mt-2 text-sm text-ink-2"><b className="text-ink">User impact: </b>{txt.side_effects}</p>}
          </Details>
        )}

        <div className="mt-auto flex flex-wrap items-center gap-2 border-t border-hairline pt-3 text-xs text-ink-3">
          {ai ? <><AiBadge text="Agent-generated · review before acting" /></> : <Tag>Based on Defender data</Tag>}
          <HopLink to={`/uc3/all?q=${encodeURIComponent(softwareOf(a))}`} title="This app in our full vulnerability list">Vulnerabilities</HopLink>
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
      <b className={done.length ? 'text-ink' : undefined}>{done.length} of {fixable.length}</b> computers remediated
      {vulns > 0 && <> · <b className={gone ? 'text-ink' : undefined}>{num(gone)} of {num(vulns)}</b> vulnerabilities gone</>}
    </span>
  )
}

function ComputerRow({ r, busy, onApprove, onWithdraw, fresh }: { r: FixRow; busy: boolean; onApprove: (ids: string[]) => void; onWithdraw: (ids: string[]) => void; fresh?: boolean }) {
  const what = r.action === 'setting' ? 'changes this setting' : r.action === 'remove' ? 'removes the old version' : r.action === 'replace' ? 'replaces it with the current version' : 'updates it to the latest version'
  return (
    <li className="flex flex-wrap items-center gap-x-3 gap-y-1.5 px-3.5 py-2.5">
      <div className="min-w-0 flex-1">
        <div className="text-sm font-medium">{r.device_name} {r.version && <span className="font-normal text-ink-3">· {r.version}</span>}</div>
        {!isSetting(r) && r.findings > 0 && (
          <div className="mt-0.5 text-xs text-ink-3">
            {num(r.findings)} vulnerabilit{r.findings === 1 ? 'y' : 'ies'}{cleared(r) ? ' remediated' : ' on this computer'}
          </div>
        )}
        <div className="mt-0.5"><StatusPill r={r} /></div>
        <RowFound r={r} fresh={fresh} />
        {r.message && ['failed', 'done', 'still_there'].includes(r.status) && <div className="mt-0.5 line-clamp-2 text-[11px] text-ink-3">{r.message}</div>}
      </div>
      {r.action === 'none' ? (
        <span className="max-w-[55%] text-right text-xs text-ink-3">{r.note || 'No action needed'}</span>
      ) : canApprove(r) ? (
        <button
          onClick={() => onApprove([r.fix_id])}
          disabled={busy}
          title={`Adds it to the remediation queue: the agent ${what} when you select Execute remediation`}
          className="btn-blue inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-semibold disabled:opacity-50"
        >
          <Zap className="size-3.5" /> {r.status === 'failed' ? 'Retry' : 'Remediate'}
        </button>
      ) : r.status === 'approved' ? (
        <button onClick={() => onWithdraw([r.fix_id])} disabled={busy} className="inline-flex items-center gap-1.5 rounded-lg border border-hairline px-3 py-1.5 text-xs font-medium hover:bg-well disabled:opacity-50">
          <Undo2 className="size-3.5" /> Remove from queue
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
  const agentFilter = useAgentFilter()
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
  const settingRows = (s: Uc3FixSetting) => rowsByConfig.get(s.config_id) ?? []
  const inOpcoAll = data.fixes.settings.filter((s) => opco === 'all' || s.opcos.includes(opco))
  const agentCounts = { uc3: inOpcoAll.filter((s) => settingRows(s).some((r) => belongs(r, 'uc3'))).length, uc1: 0 }
  const inOpco = agentFilter.agent ? inOpcoAll.filter((s) => settingRows(s).some(agentFilter.matches)) : inOpcoAll
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
            Windows and Defender settings that are weaker than Microsoft recommends. These are <b>configuration findings</b>, tracked separately from software vulnerabilities,
            and <b>not alerts</b>: no malicious activity has occurred, but each one weakens the security baseline.
          </p>
          <p className="mt-1.5">
            <b>{num(autoCount)}</b> can be changed with <b>⚡ Remediate</b>. The other <b>{num(inOpco.length - autoCount)}</b> require manual change by IT,
            usually through Group Policy or Intune, because changing them on a single device could lock users out.
          </p>
          <p className="mt-1.5 text-xs text-ink-3">Defender re-assesses settings automatically, usually within a day; the card then shows Verified.</p>
        </div>
      </Panel>

      <AgentFilterBar filter={agentFilter} counts={agentCounts} total={inOpcoAll.length} what="security settings" />

      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap gap-2 text-sm">
          {([['all', 'All', inOpco.length], ['auto', 'Automatable', autoCount], ['manual', 'Manual action required', inOpco.length - autoCount]] as const).map(([f, label, n]) => (
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
              title="Adds every automatable setting shown here to the remediation queue. Nothing runs until you select Execute remediation."
              className="btn-blue inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-sm font-semibold disabled:opacity-50">
              <Zap className="size-4" /> Remediate all ({ready.length})
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
            <SettingCard key={s.key} s={s} rows={settingRows(s)} engine={!!v} busy={act.isPending} isNew={agentFilter.isNew}
              onApprove={approve} onWithdraw={withdraw} />
          ))}
        </div>
      ) : <Empty text="No settings match this filter." />}

      {v && <BasketBar v={v} />}
      {act.error && <div className="fixed bottom-24 right-6 z-30 rounded-xl border bg-panel px-4 py-3 text-sm shadow-lg" style={{ borderColor: statusColor.critical }}>{String((act.error as Error).message)}</div>}
    </div>
  )
}

function SettingCard({ s, rows, engine, busy, onApprove, onWithdraw, isNew }: {
  s: Uc3FixSetting; rows: FixRow[]; engine: boolean; busy: boolean; onApprove: (ids: string[]) => void; onWithdraw: (ids: string[]) => void
  isNew: (r: FixRow) => boolean
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
            <div className="mt-1.5"><AgentTags rows={rows} /></div>
          </div>
          <span className="shrink-0 text-xs font-medium" style={{ color: lv.color }}>{lv.label} priority</span>
        </div>

        {(txt.what_is_wrong || s.microsoft.risk) && <p className="text-sm leading-relaxed text-ink-2">{txt.what_is_wrong ?? s.microsoft.risk}</p>}

        <Tracker {...trackerCounts(s, rows)} />

        <div className="rounded-xl border border-hairline">
          <div className="flex items-center justify-between gap-3 border-b border-hairline px-3.5 py-2 text-xs">
            <span className="font-medium text-ink-2">Affected devices</span>
            <span className="truncate text-ink-3">{autoRow ? settingChange(autoRow) : 'Manual change required'}</span>
          </div>
          {rows.length ? (
            <ul className="divide-y divide-hairline">
              {rows.map((r) => <ComputerRow key={r.fix_id} r={r} busy={busy} onApprove={onApprove} onWithdraw={onWithdraw} fresh={isNew(r)} />)}
            </ul>
          ) : (
            <ul className="divide-y divide-hairline">
              {s.devices.map((d) => (
                <li key={d.name} className="flex items-center justify-between gap-3 px-3.5 py-2.5 text-sm">
                  <span className="font-medium">{d.name}</span>
                  <span className="text-right text-xs text-ink-3">{engine ? 'Not yet in the automated remediation plan (added after the next Threat Intel run)' : 'Automated remediation is disabled'}</span>
                </li>
              ))}
            </ul>
          )}
        </div>

        {!autoRow && s.fix.note && (
          <p className="flex gap-2 rounded-lg bg-well px-3 py-2 text-xs leading-relaxed text-ink-2"><UserRound className="mt-0.5 size-3.5 shrink-0" />{s.fix.note}</p>
        )}
        {!autoRow && s.fix.command && (
          <div className="text-xs text-ink-3">To apply on a single device, IT can run: <CommandLine command={s.fix.command} /></div>
        )}

        {txt.why_now && (
          <Details title="Why now">
            <p className="text-sm leading-relaxed text-ink-2">{txt.why_now}</p>
            {txt.worst_case && <p className="mt-2 text-sm text-ink-2"><b className="text-ink">Potential impact: </b>{txt.worst_case}</p>}
          </Details>
        )}
        {(txt.verify || txt.side_effects) && (
          <Details title="Verification and user impact">
            {txt.verify && <p className="text-sm text-ink-2"><b className="text-ink">Check: </b>{txt.verify}</p>}
            {txt.side_effects && <p className="mt-2 text-sm text-ink-2"><b className="text-ink">User impact: </b>{txt.side_effects}</p>}
            {autoRow?.note && <p className="mt-2 text-xs text-ink-3">{autoRow.note}</p>}
          </Details>
        )}
        {s.microsoft.remediation && (
          <Details title="Microsoft's advice">
            <p className="whitespace-pre-line text-sm leading-relaxed text-ink-2">{s.microsoft.remediation}</p>
          </Details>
        )}

        <div className="mt-auto flex flex-wrap items-center gap-2 border-t border-hairline pt-3 text-xs text-ink-3">
          {ai ? <AiBadge text="Agent-generated · review before acting" /> : <Tag>Microsoft guidance</Tag>}
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

/** scope (a run page): only that run's fixes count and run; anything approved earlier stays queued for Remediation. */
export function BasketBar({ v, scope }: { v: FixView; scope?: string[] }) {
  const act = useFixAction()
  const [review, setReview] = useState(false)
  const navigate = useNavigate()
  const watch = () => navigate('/fixes/progress')
  const [confirm, setConfirm] = useState(false)
  const [hideDone, setHideDone] = useState('')
  const queued = v.rows.filter((r) => r.status === 'approved')
  const inScope = scope && new Set(scope)
  const approved = inScope ? queued.filter((r) => inScope.has(r.fix_id)) : queued
  const earlier = queued.length - approved.length
  const earlierNote = earlier ? `${earlier} remediation${earlier === 1 ? '' : 's'} approved earlier stay${earlier === 1 ? 's' : ''} in the queue and do${earlier === 1 ? 'es' : ''} not run from here.` : ''
  const approvedSettings = approved.filter(isSetting).length
  const approvedResponses = approved.filter((r) => r.action === 'respond').length
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
                    {v.worker.task === 'probe' ? 'Checking device connectivity…' : `Remediating…${runSet.length ? ` ${finished} of ${runSet.length} complete` : ''}`}
                  </div>
                  <div key={v.worker.step} className="truncate text-xs text-ink-3 animate-in fade-in duration-300">{v.worker.step || 'Starting'}</div>
                  {runSet.length > 0 && (
                    <div className="mt-1.5 h-1 overflow-hidden rounded-full bg-well">
                      <div className="h-full rounded-full bg-sky transition-[width] duration-700 ease-out" style={{ width: `${Math.max(5, (finished / runSet.length) * 100)}%` }} />
                    </div>
                  )}
                </div>
                <button onClick={watch} className="rounded-lg border border-hairline px-3 py-2 text-sm font-medium hover:bg-well">Open live view</button>
              </>
            ) : approved.length ? (
              <>
                <span className="grid size-10 place-items-center rounded-xl bg-signal/15"><ShoppingBasket className="size-5 text-signal" /></span>
                <div className="min-w-0 flex-1">
                  <div className="text-sm font-semibold">{approved.length} remediation{approved.length === 1 ? '' : 's'} queued{scope ? ' from this run' : ''}</div>
                  <div className="truncate text-xs text-ink-3" title={earlierNote || undefined}>
                    {byDevice.map(([d, rs]) => `${d}: ${rs.length}`).join(' · ')} · clears {num(approved.reduce((n, r) => n + r.findings, 0))} findings{approvedSettings ? `, ${approvedSettings} security setting${approvedSettings === 1 ? '' : 's'}` : ''}
                    {earlier > 0 && <> · <b className="text-ink-2">{earlier} approved earlier not included</b></>}
                  </div>
                </div>
                <button onClick={() => setReview(true)} className="rounded-lg border border-hairline px-3 py-2 text-sm font-medium hover:bg-well">Review</button>
                <button onClick={() => setConfirm(true)} disabled={act.isPending} className="inline-flex items-center gap-2 rounded-lg btn-blue px-4 py-2 text-sm font-medium text-white disabled:opacity-50">
                  <Play className="size-4" /> Execute remediation
                </button>
              </>
            ) : (
              <>
                <ShieldCheck className="size-5" style={{ color: statusColor.good }} />
                <div className="min-w-0 flex-1 text-sm"><b>{v.worker.message}.</b> <span className="text-ink-3">Defender verifies within a few hours.</span></div>
                <button onClick={watch} className="rounded-lg border border-hairline px-3 py-2 text-sm font-medium hover:bg-well">View results</button>
                <button onClick={() => setHideDone(v.worker.message)} className="grid size-8 place-items-center rounded-lg hover:bg-well" aria-label="Hide"><X className="size-4" /></button>
              </>
            )}
          </div>
        </div>
      )}

      <Sheet open={review} onOpenChange={setReview}>
        <SheetContent side="right" className="w-full gap-0 overflow-y-auto border-hairline bg-canvas p-0 sm:max-w-[460px]">
          <SheetHeader className="border-b border-hairline bg-panel px-6 py-5">
            <SheetTitle className="flex items-center gap-2 text-lg"><ShoppingBasket className="size-5" /> Remediation queue</SheetTitle>
            <SheetDescription>These run when you select Execute remediation. Remove anything that should not change yet.</SheetDescription>
          </SheetHeader>
          <div className="flex flex-col gap-4 p-4">
            {byDevice.map(([d, rs]) => (
              <Panel key={d} className="p-4">
                <div className="mb-2 font-medium">{d}</div>
                <ul className="divide-y divide-hairline">
                  {rs.map((r) => (
                    <li key={r.fix_id} className="flex items-center justify-between gap-3 py-2 text-sm">
                      <span>{r.action === 'setting' ? 'Change setting:' : r.action === 'respond' ? 'Scan and clean after:' : r.action === 'remove' ? 'Remove' : r.action === 'replace' ? 'Replace' : 'Update'} {r.app} <span className="text-ink-3">{r.version}</span></span>
                      <button onClick={() => act.mutate({ action: 'unapprove', ids: [r.fix_id] })} className="text-xs font-medium text-ink-2 hover:text-ink">Remove</button>
                    </li>
                  ))}
                </ul>
              </Panel>
            ))}
            {!approved.length && <Empty text="The remediation queue is empty." />}
          </div>
        </SheetContent>
      </Sheet>

      <ConfirmDialog
        open={confirm}
        onClose={() => setConfirm(false)}
        title={`Execute ${scope ? "this run's " : ''}${approved.length} remediation${approved.length === 1 ? '' : 's'} now?`}
        body={`${byDevice.map(([d, rs]) => `${d}: ${rs.length}`).join(', ')}. The agent powers on each device if needed, closes the applications and updates or removes them${approvedSettings ? ', and changes the chosen security settings' : ''}${approvedResponses ? ', and scans devices with detections and removes what Defender finds' : ''}. This changes the devices and the figures on every page. Keep powered-on VMs running for about 6 hours so Defender can verify the changes.${earlierNote ? ` ${earlierNote}` : ''}`}
        confirmLabel="Execute remediation"
        onConfirm={() => { act.mutate({ action: 'run', ids: scope ? approved.map((r) => r.fix_id) : undefined }); setConfirm(false); watch() }}
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
        <DialogTitle className="flex items-center gap-2"><Zap className="size-5 text-signal" /> Remediate all high-priority apps</DialogTitle>
        <DialogDescription className="text-sm leading-relaxed text-ink-2">
          High priority: the applications prioritised by the remediation plan. Select devices to add their high-priority remediations to the queue. Nothing runs until approved.
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
          {!devices.length && <li className="text-sm text-ink-3">Every high-priority remediation is already queued or complete.</li>}
        </ul>
        <div className="mt-1 flex justify-end gap-2">
          <button onClick={onClose} className="rounded-lg border border-hairline px-4 py-2 text-sm hover:bg-well">Cancel</button>
          <button onClick={() => onApprove(ids)} disabled={!ids.length} className="rounded-lg btn-blue px-4 py-2 text-sm font-medium text-white disabled:opacity-40">
            Add {ids.length} to queue
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

/** One number on a fix card: found, still to fix, fixed */
function Stat({ n, label, color }: { n: number; label: string; color?: string }) {
  return (
    <div className="rounded-xl bg-well px-3 py-2.5">
      <div className="tabular text-xl font-semibold leading-none tracking-tight" style={{ color }}>{num(n)}</div>
      <div className="mt-1.5 text-[11px] text-ink-3">{label}</div>
    </div>
  )
}

/** A filter with its label above it */
function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex min-w-0 flex-col gap-1.5">
      <span className="text-xs font-medium text-ink-3">{label}</span>
      {children}
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

function AiBadge({ text = 'Agent' }: { text?: string }) {
  return (
    <span className="inline-flex items-center gap-1 rounded-md bg-violet/15 px-1.5 py-0.5 text-[11px] font-medium text-violet">
      <Sparkles className="size-3" /> {text}
    </span>
  )
}
