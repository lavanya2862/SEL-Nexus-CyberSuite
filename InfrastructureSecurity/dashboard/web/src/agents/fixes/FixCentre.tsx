import { ExpandableCard } from '@/components/DetailDialog'
import { useEffect, useMemo, useState } from 'react'
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom'
import {
  AlertTriangle, Bot, Check, ChevronDown, ChevronRight, Copy, Monitor, ExternalLink, ListChecks, Loader2, Play, ShieldCheck, ShoppingBasket,
  SlidersHorizontal, Sparkles, Undo2, UserCog, UserRound, Wrench, X, Zap,
} from 'lucide-react'
import { ConfirmDialog, StatusPill } from '@/components/FixLoop'
import {
  DateFilter, Empty, FilterBar, FilterChoice, FilterSearch, HopLink, Panel, StatBox, Tabs, Tag, choiceChip, dateChip, inDateRange,
  type ActiveFilter, type DateRange,
} from '@/components/kit'
import { FixHistory } from '@/agents/fixes/FixHistory'
import { AttackResponses } from '@/agents/fixes/AttackResponses'
import { AgentTags, RowFound, RunBanner, belongs, useAgentFilter } from '@/components/AgentTags'
import { VulnList } from '@/components/VulnList'
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from '@/components/ui/sheet'
import { FixDown, canApprove, isSetting, settingChange, useFix, useFixAction, type FixRow, type FixView } from '@/agents/fixes/data'
import { FixProgress } from '@/agents/fixes/FixProgress'
import { ManualAction, PersonLine } from '@/components/ManualAction'
import { QuickActions } from '@/agents/fixes/QuickActions'
import { RecordLink } from '@/components/FixRecord'
import { useFilters } from '@/lib/filters'
import { ago, num, shortDate } from '@/lib/format'
import { statusColor } from '@/lib/theme'
import { cn } from '@/lib/utils'
import { AGENT_NAME } from '@/lib/runs'
import { useThreatMatchCounts } from '@/agents/threat-intel/data'
import { daysBetween, fixKind, nearEos, pastEos, useVulnData, useVulnView, vmDetails, vmKey, type FixKind, type VulnFixApp, type VulnFixSetting, type VmDetail } from '@/agents/vulnerability/data'
import { GettingReady, useAutoStart } from '@/lib/services'
import { VulnLoading } from '@/agents/vulnerability/common'

const LEVEL = {
  1: { label: 'High', color: statusColor.critical },
  2: { label: 'Medium', color: statusColor.warning },
  3: { label: 'Low', color: 'var(--ink-3)' },
} as const

const softwareOf = (a: VulnFixApp) => a.key.split(':').pop() ?? ''
/** The card a "Fix this" link means: exact software name or app name, else the first whose name starts with it. */
const findApp = (apps: VulnFixApp[], focus: string) => {
  const f = focus.toLowerCase().replace(/\s+/g, '_')
  return apps.find((a) => softwareOf(a) === f || a.app.toLowerCase() === focus.toLowerCase())
    ?? apps.find((a) => softwareOf(a).startsWith(f))
}

type View = 'cards' | 'settings' | 'indicators' | 'attacks' | 'progress' | 'history'
const VIEWS: [View, string][] = [['cards', 'Updates & upgrades'], ['settings', 'Security configuration'], ['indicators', 'Indicator responses'], ['attacks', 'Attack responses'], ['progress', 'Remediation progress'], ['history', 'Remediation history']]

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

/** Act › Fix: what to update and why (Vulnerability advice), and "fix it for me" on every computer (Threat Intel fix engine). */
export function FixCentre() {
  const { tab } = useParams()
  const navigate = useNavigate()
  const view: View = VIEWS.some(([v]) => v === tab) ? (tab as View) : 'cards'
  return (
    <div className="flex flex-col gap-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Remediation</h1>
          <p className="mt-1 text-sm text-ink-3">Remediate vulnerabilities and harden security settings through updates, upgrades and configuration changes, manually or with automated remediation</p>
        </div>
      </div>
      <Tabs<View> tabs={VIEWS} value={view} onChange={(t) => navigate(t === 'cards' ? '/fixes' : `/fixes/${t}`)} />
      {view === 'attacks' ? <AttackResponses /> : view === 'indicators' ? <AttackResponses owner="threat_intel" /> : view === 'history' ? <FixHistory /> : view === 'progress' ? <FixProgress embedded /> : view === 'settings' ? <SettingsCards /> : <FixCards />}
    </div>
  )
}

/* ───────────────────────── the card page ───────────────────────── */

/** One remediation card: one app version on one computer (with the fix engine's row when it has one) */
interface Unit { key: string; a: VulnFixApp; device: string; opco: string; version: string; r?: FixRow; d?: VmDetail }

function FixCards() {
  const { data, error, isLoading } = useVulnData()
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
  const [found, setFound] = useState<DateRange>({ preset: 'any' })
  const [vm, setVm] = useState('all')
  // ?status=manual_required (from the progress page or the bell): only the remediations waiting for a person
  const [state, setState] = useState(['manual_required', 'awaiting_vendor', 'info'].includes(params.get('status') ?? '') ? params.get('status')! : 'all')
  const [showDone, setShowDone] = useState(false)
  const agentFilter = useAgentFilter()
  const rows = useVulnView(data).rows
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

  // One card per app version per computer: the fix engine's rows, plus the computers it has no row for (no security
  // update yet, or not in its plan). High priority first, then the nearest (or longest overdue) deadline.
  const units = useMemo<Unit[]>(() => {
    if (!data?.fixes) return []
    const vms = vmDetails(data)
    const out: Unit[] = []
    for (const a of data.fixes.apps) {
      const sw = softwareOf(a), seen = new Set<string>()
      for (const r of rowsBySoftware.get(sw) ?? []) {
        const k = vmKey(r.device_name, sw, r.version)
        if (isSetting(r) || r.action === 'respond' || seen.has(k)) continue
        seen.add(k)
        out.push({ key: r.fix_id, a, device: r.device_name, opco: r.opco, version: r.version, r, d: vms.get(k) })
      }
      for (const ver of a.versions) {
        for (const dev of ver.devices) {
          const k = vmKey(dev, sw, ver.version)
          if (seen.has(k)) continue
          seen.add(k)
          out.push({ key: k, a, device: dev, opco: a.devices.find((x) => x.name === dev)?.opco ?? '', version: ver.version, d: vms.get(k) })
        }
      }
    }
    return out.sort((x, y) => x.a.urgency.level - y.a.urgency.level || (x.d?.due ?? '9').localeCompare(y.d?.due ?? '9')
      || (y.d?.cves.length ?? 0) - (x.d?.cves.length ?? 0) || x.a.app.localeCompare(y.a.app) || x.device.localeCompare(y.device))
  }, [data, rowsBySoftware])

  // ?app=<name> or ?sw=<software> (from "Fix this" buttons elsewhere): scroll to that app's first card and highlight its cards
  const focus = params.get('sw') ?? params.get('app')
  const fixSettled = fix.isFetched || fix.isError
  useEffect(() => {
    // wait for both data sets: the fix engine's rows add cards, so jumping earlier lands in the wrong place
    if (!focus || !data?.fixes || !fixSettled) return
    const app = findApp(data.fixes.apps, focus)
    if (!app) return
    const go = () => document.getElementById(`fix-${softwareOf(app)}`)?.scrollIntoView({ behavior: 'smooth', block: 'start' })
    const t1 = setTimeout(go, 150)
    const t2 = setTimeout(go, 900)                            // once more, after late layout changes
    return () => { clearTimeout(t1); clearTimeout(t2) }
  }, [focus, data, fixSettled])

  if (isLoading || error || !data) return <VulnLoading error={error} />
  const X = data.fixes
  if (!X) return <Empty text="Remediation guidance is not available yet. Run the Vulnerability Agent to generate it." />
  const today = String(data.meta.snapshot).slice(0, 10)
  // in the news before the Vulnerability Agent found it (the portal drops later matches); once known, this decides Threat Intel
  const newsOf = (a: VulnFixApp) => (inNews ? inNews[softwareOf(a)] ?? 0 : undefined)
  const done = (u: Unit) => !!u.r && cleared(u.r)
  // this card's own open vulnerabilities that a threat in the news names (undefined until the Threat Intel data loads;
  // older portal data has no per-computer lists: then the app's fix row decides, as before)
  const vmCves = matchCounts?.vm_cves
  const newsOn = (u: Unit): number | undefined => {
    if (!vmCves) return undefined
    const named = new Set(vmCves[vmKey(u.device, softwareOf(u.a), u.version)] ?? [])
    return (u.d?.cves ?? []).filter((c) => named.has(c.cve)).length
  }
  // the Vulnerability Agent (Defender's scan) found every card; the Threat Intel Agent only the cards with news on them
  const isAgent = (u: Unit, ag: 'vulnerability' | 'threat_intel') => ag === 'vulnerability'
    || ((newsOn(u) ?? (u.r && belongs(u.r, 'threat_intel') && newsOf(u.a) !== 0 ? 1 : 0)) > 0)
  const term = q.trim().toLowerCase()
  const matchesText = (u: Unit) => !term || u.a.app.toLowerCase().includes(term) || u.device.toLowerCase().includes(term)
  const inOpcoAll = units.filter((u) => !done(u) && (opco === 'all' || u.opco === opco))
  const agentCounts = { vulnerability: inOpcoAll.filter((u) => isAgent(u, 'vulnerability')).length, threat_intel: inOpcoAll.filter((u) => isAgent(u, 'threat_intel')).length }
  // ?since (a run page's link) keeps the cards that agent's run proposed
  const inAgent = agentFilter.agent
    ? inOpcoAll.filter((u) => isAgent(u, agentFilter.agent!) && (agentFilter.since == null || (!!u.r && agentFilter.matches(u.r))))
    : inOpcoAll
  const vmNames = [...new Set(inAgent.map((u) => u.device))].sort()
  const inVm = inAgent.filter((u) => vm === 'all' || u.device === vm)
  const ofKind = (k: FixKind) => inVm.filter((u) => fixKind(u.a) === k).length
  const inKind = inVm.filter((u) => kind === 'all' || fixKind(u.a) === kind)
  const firstFound = (u: Unit) => {
    const t = Object.values(u.r?.found_by ?? {}).filter((x): x is string => !!x).sort()[0]
    return t ? new Date(t.replace(' ', 'T') + (/[zZ]|[+-]\d\d:?\d\d$/.test(t) ? '' : 'Z')) : null
  }
  const cards = inKind.filter((u) => (level === 0 || u.a.urgency.level === level) && matchesText(u) && inDateRange(firstFound(u), found)
    && (state === 'all' || u.r?.status === state))
    // a remediation waiting for a person stays at the top until someone marks it fixed
    .sort((x, y) => Number(y.r?.status === 'manual_required') - Number(x.r?.status === 'manual_required'))
  const count = (l: number) => inKind.filter((u) => u.a.urgency.level === l).length
  // the summary follows the filters: what these cards' remediations clear, in all and from threat intel
  const shownVulns = inVm.reduce((n, u) => n + (u.d?.cves.length ?? 0), 0)
  const shownNoPatch = inVm.reduce((n, u) => n + (u.d?.cves.filter((c) => c.nofix).length ?? 0), 0)
  const shownNews = inVm.reduce((n, u) => n + (newsOn(u) ?? 0), 0)
  // per computer + app: every version with a card, so a card can name the other versions it does not change
  const versionsOn = new Map<string, string[]>()
  for (const u of units) if (!done(u)) versionsOn.set(`${u.device}|${softwareOf(u.a)}`, [...(versionsOn.get(`${u.device}|${softwareOf(u.a)}`) ?? []), u.version])
  const doneCards = units.filter((u) => done(u) && (opco === 'all' || u.opco === opco) && (vm === 'all' || u.device === vm) && matchesText(u))
  const pickKind = (k: 'all' | FixKind) => {
    setKind(k)
    const n = new URLSearchParams(params)               // keep the other filters (agent, run) in the address
    if (k === 'all') n.delete('type')
    else n.set('type', k)
    setParams(n, { replace: true })
  }
  const clearFilters = () => {
    setQ(''); setLevel(0); setKind('all'); setVm('all'); setFound({ preset: 'any' }); setState('all')
    const n = new URLSearchParams(params)
    for (const key of ['type', 'agent', 'since']) n.delete(key)
    setParams(n, { replace: true })
  }
  const vmOptions = [{ value: 'all', label: 'All VMs', count: inAgent.length },
    ...vmNames.map((d) => ({ value: d, label: d, count: inAgent.filter((u) => u.device === d).length }))]
  const agentOptions = [{ value: 'all', label: 'All agents', count: inOpcoAll.length },
    { value: 'vulnerability', label: AGENT_NAME.vulnerability, count: agentCounts.vulnerability, dot: 'var(--sky)' },
    { value: 'threat_intel', label: AGENT_NAME.threat_intel, count: agentCounts.threat_intel, dot: 'var(--violet)' }]
  const kindOptions = [{ value: 'all', label: 'All types', count: inVm.length }, ...KINDS.map(([k, l]) => ({ value: k, label: l, count: ofKind(k) }))]
  const stateOptions = [{ value: 'all', label: 'All statuses', count: inKind.length },
    { value: 'manual_required', label: 'Waiting for a person', count: inKind.filter((u) => u.r?.status === 'manual_required').length, dot: statusColor.critical },
    { value: 'awaiting_vendor', label: 'Awaiting vendor package', count: inKind.filter((u) => u.r?.status === 'awaiting_vendor').length, dot: '#b37400' },
    { value: 'info', label: 'No automatic fix', count: inKind.filter((u) => u.r?.status === 'info').length, dot: 'var(--ink-3)' }]
  const levelOptions = [{ value: '0', label: 'All priorities', count: inKind.length },
    ...([1, 2, 3] as const).map((l) => ({ value: String(l), label: LEVEL[l].label, count: count(l), dot: LEVEL[l].color }))]
  const chips: ActiveFilter[] = [
    ...(q ? [{ key: 'q', label: `“${q}”`, onRemove: () => setQ('') }] : []),
    ...dateChip(found, () => setFound({ preset: 'any' })),
    ...choiceChip('vm', vmOptions, vm, () => setVm('all')),
    ...choiceChip('agent', agentOptions, agentFilter.agent ?? 'all', () => agentFilter.set(null)),
    ...choiceChip('kind', kindOptions, kind, () => pickKind('all')),
    ...choiceChip('lvl', levelOptions, String(level), () => setLevel(0)),
    ...choiceChip('state', stateOptions, state, () => setState('all')),
  ]
  const approve = (ids: string[]) => v && act.mutate({ action: 'approve', ids, method: v.default_method })
  const withdraw = (ids: string[]) => act.mutate({ action: 'unapprove', ids })
  const handOver = (ids: string[]) => act.mutate({ action: 'handover', ids })
  const highlighted = focus ? findApp(X.apps, focus) : undefined
  const settings = (X.settings ?? []).filter((s) => opco === 'all' || s.opcos.includes(opco)).length
  const verified = (v?.rows ?? []).filter((r) => r.status === 'verified')
  // the first card of each app carries its anchor (#fix-<software>) for "Fix this" links
  const anchors = new Set<string>()
  const anchored = new Set<VulnFixApp>()
  for (const u of cards) if (!anchored.has(u.a)) { anchored.add(u.a); anchors.add(u.key) }
  // ?vulns=<software>&vm=<computer>: that card's vulnerabilities pop-up (a link can open it; Back closes it)
  const apps = [...new Set(cards.map((u) => u.a))]
  const listSw = params.get('vulns')
  const listApp = listSw ? apps.find((a) => softwareOf(a) === listSw) ?? X.apps.find((a) => softwareOf(a) === listSw) : undefined
  const showList = (a: VulnFixApp, device?: string, replace = false) => {
    const n = new URLSearchParams(params)
    n.set('vulns', softwareOf(a))
    if (device) n.set('vm', device)
    else n.delete('vm')
    setParams(n, { replace })
  }
  const closeList = () => { const n = new URLSearchParams(params); n.delete('vulns'); n.delete('vm'); setParams(n, { replace: true }) }
  const listAt = listApp ? apps.indexOf(listApp) : -1
  const step = (a: VulnFixApp | undefined) => (a ? { name: a.app, go: () => showList(a, undefined, true) } : undefined)
  const card = (u: Unit, i: number) => (
    <ExpandableCard key={u.key} id={anchors.has(u.key) ? `fix-${softwareOf(u.a)}` : undefined} highlight={highlighted === u.a}
      accent={LEVEL[u.a.urgency.level].color} title={`${u.a.app} ${u.version}`.trim()} subtitle={[u.device, u.opco].filter(Boolean).join(' · ')}
      eyebrow={<><span className="font-medium" style={{ color: LEVEL[u.a.urgency.level].color }}>{LEVEL[u.a.urgency.level].label} priority</span><span className="text-ink-3">{KINDS.find(([k]) => k === fixKind(u.a))?.[1]}</span></>}
      summary={<UnitSummary u={u} today={today} />}
      actions={u.r && v ? <QuickActions rows={[u.r]} busy={act.isPending} onApprove={approve} onWithdraw={withdraw} onSave={(ids) => act.mutate({ action: 'save', ids })} onHandOver={handOver} /> : null}>
      <VmCard u={u} rank={i + 1} today={today} engine={!!v} busy={act.isPending} highlight={false} anchor={false}
        onApprove={approve} onWithdraw={withdraw} onList={() => showList(u.a, u.device)} fresh={!!u.r && agentFilter.isNew(u.r)}
        news={newsOn(u) ?? (u.r?.threats?.length ? newsOf(u.a) : 0)} agent={agentFilter.agent}
        otherVersions={(versionsOn.get(`${u.device}|${softwareOf(u.a)}`) ?? []).filter((x) => x !== u.version)} />
    </ExpandableCard>
  )

  return (
    <div className="flex flex-col gap-5">
      {down && <Banner auto={auto} />}

      <section className="grid gap-6 rounded-[20px] border border-blue/35 bg-[color-mix(in_oklab,var(--blue)_8%,var(--panel))] p-6 shadow-elev md:grid-cols-[auto_minmax(0,1fr)] md:items-center">
        <div className="flex items-baseline gap-3">
          <span className="tabular text-[40px] leading-none tracking-tight">{num(shownVulns - shownNoPatch)}</span>
          <span className="text-sm text-ink-3">vulnerabilities<br />these remediations close</span>
        </div>
        <div className="text-sm text-ink-2">
          <p>
            <b>{num(inVm.length)} remediations</b> on <b>{num(new Set(inVm.map((u) => u.device)).size)} VMs</b> cover <b>{num(shownVulns)}</b>{shownVulns === vulns ? <> (all) of the <b>{num(vulns)}</b></> : <> of the {num(vulns)}</>} vulnerabilities Defender found:{' '}
            {KINDS.filter(([k]) => k !== 'none' && ofKind(k)).map(([k], i, all) => (
              <span key={k}>{i > 0 && (i === all.length - 1 ? ' and ' : ', ')}{num(ofKind(k))} {KIND_PHRASE[k][ofKind(k) === 1 ? 0 : 1]}</span>
            ))}
            {settings > 0 && <>, plus <Link to="/fixes/settings" className="underline decoration-hairline underline-offset-2 hover:decoration-ink"><b>{num(settings)} security settings</b></Link> to change</>}.{' '}
            {num(count(1))} are marked High priority.
          </p>
          {agentFilter.agent === 'threat_intel' && (
            <p className="mt-1.5 rounded-lg px-3 py-2" style={{ background: `color-mix(in oklab, ${statusColor.warning} 10%, transparent)` }}>
              <b>{num(shownNews)}</b> of these {num(shownVulns)} were reported in threat intelligence. A remediation updates or removes the whole app version,
              so approving these cards also clears the other <b>{num(shownVulns - shownNews)}</b> on the same versions that the {AGENT_NAME.vulnerability} found.
            </p>
          )}
          <p className="mt-1.5">
            {shownNoPatch > 0
              ? <><b style={{ color: statusColor.warning }}>{num(shownNoPatch)} have no security update available</b>: their cards list compensating controls until one is released.</>
              : noPatch > 0 && shownVulns !== vulns ? <>A security update is available for every vulnerability shown.</> : <>A security update is available for every vulnerability.</>}
          </p>
          <p className="mt-1.5 text-xs text-ink-3">
            One card per app version on each VM, with that VM's own deadline. Priority, numbers and commands come from Defender data and fixed catalogues; the agent only explains them. Built {ago(X.built_at)}.
          </p>
          {verified.length > 0 && (
            <Link to="/fixes/history" className="mt-2 inline-flex items-center gap-1.5 text-sm font-medium hover:underline" style={{ color: statusColor.good }}
              title={verified.map((r) => `${r.app} on ${r.device_name}`).join('\n')}>
              <ShieldCheck className="size-4" /> Remediated: {verified.length} · verified by Defender · view history
            </Link>
          )}
        </div>
      </section>

      <FilterBar chips={chips} onClear={clearFilters} count={`${num(cards.length)} of ${num(inOpcoAll.length)} remediations`}>
        <FilterSearch value={q} onChange={setQ} placeholder="Search app or VM…" label="Find an app or VM" />
        <DateFilter label="Found" value={found} onChange={setFound} />
        <FilterChoice label="VM" icon={Monitor} value={vm} onChange={setVm} options={vmOptions} />
        <FilterChoice label="Found by" icon={Bot} value={agentFilter.agent ?? 'all'} onChange={(a) => agentFilter.set(a === 'all' ? null : a as 'vulnerability' | 'threat_intel')} options={agentOptions} />
        <FilterChoice label="Remediation type" icon={Wrench} value={kind} onChange={(k) => pickKind(k as 'all' | FixKind)} options={kindOptions} />
        <FilterChoice label="Priority" icon={AlertTriangle} value={String(level)} onChange={(l) => setLevel(Number(l) as 0 | 1 | 2 | 3)} options={levelOptions} />
        <FilterChoice label="Status" icon={UserCog} value={state} onChange={setState} options={stateOptions} />
      </FilterBar>
      <RunBanner filter={agentFilter} what="software remediations" />

      {state === 'info' && v && cards.some((u) => u.r?.status === 'info') && (
        <HandOverAll ids={cards.flatMap((u) => (u.r?.status === 'info' ? [u.r.fix_id] : []))} busy={act.isPending} onHandOver={handOver} />
      )}
      {cards.length ? (
        <div className="grid grid-cols-1 gap-3 lg:grid-cols-2 2xl:grid-cols-3">{cards.map(card)}</div>
      ) : <Empty text={agentFilter.agent ? 'No remediations from this agent match these filters.' : kind === 'none' ? 'No items: a security update is available for every vulnerability.' : kind === 'os' ? 'No Windows updates needed: Defender found no vulnerabilities in Windows itself.' : 'No remediations match this filter.'} />}

      {doneCards.length > 0 && (
        <div className="flex flex-col gap-3">
          <button onClick={() => setShowDone(!showDone)} aria-expanded={showDone}
            className="inline-flex w-fit items-center gap-1.5 rounded-lg px-2 py-1 text-sm font-medium text-ink-2 hover:bg-well hover:text-ink">
            <ShieldCheck className="size-4" style={{ color: statusColor.good }} /> {showDone ? 'Hide' : 'Show'} {num(doneCards.length)} remediated
            <ChevronDown className={cn('size-4 transition-transform', showDone && 'rotate-180')} />
          </button>
          {showDone && <div className="grid grid-cols-1 gap-4 lg:grid-cols-2 2xl:grid-cols-3 animate-in fade-in duration-200">{doneCards.map(card)}</div>}
        </div>
      )}

      {listApp && (
        <VulnList app={listApp} software={softwareOf(listApp)} data={data} fixRows={v?.rows ?? []} engine={!!v} onClose={closeList}
          startAgent={agentFilter.agent} startDevice={params.get('vm') ?? undefined}
          prev={listAt > 0 ? step(apps[listAt - 1]) : undefined} next={listAt >= 0 ? step(apps[listAt + 1]) : undefined} />
      )}
      {v && <BasketBar v={v} />}
      {act.error && <div className="fixed bottom-24 right-6 z-30 rounded-xl border bg-panel px-4 py-3 text-sm shadow-lg" style={{ borderColor: statusColor.critical }}>{String((act.error as Error).message)}</div>}
    </div>
  )
}

/* ───────── banner: shown only while automated remediation is unavailable ───────── */

function Banner({ auto }: { auto: ReturnType<typeof useAutoStart> }) {
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

/* ───────── one app: advice + parcel tracker + a fix button per computer ───────── */

const TRACK = ['Found', 'Explained', 'Approved', 'Remediated', 'Verified'] as const

/** How far one computer got: 1 found, 2 explained, 3 approved (or tried and failed), 4 fixed, 5 verified by Defender. */
function rowStep(r: FixRow, explained: boolean): number {
  if (r.status === 'verified' || r.status === 'gone') return 5
  if (r.status === 'done' || r.status === 'still_there') return 4
  if (['approved', 'queued', 'running', 'failed', 'manual_required', 'awaiting_vendor'].includes(r.status)) return 3
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

/** One app version on one VM, in the Remediation card's usual look: numbers, vulnerabilities button, tracker, the
 *  Remediate button, and the longer advice folded under Why now / Manual remediation steps / Verification. */
/** The small card in the Updates & upgrades grid: what, where, three numbers and the state; the full VmCard opens on click. */
function UnitSummary({ u, today }: { u: Unit; today: string }) {
  const lv = LEVEL[u.a.urgency.level]
  const vulns = u.d?.cves.length || u.r?.findings || 0
  const severe = (u.d?.cves ?? []).filter((c) => c.sev === 'Critical' || c.sev === 'High').length
  const left = u.d?.due && !(u.r && cleared(u.r)) ? daysBetween(today, u.d.due) : null
  const late = left != null && left < 0
  return (
    <>
      <div className="flex items-center justify-between gap-2 text-[11px] font-medium">
        <span className="truncate" style={{ color: lv.color }}>{lv.label} priority · <span className="font-normal text-ink-3">{KINDS.find(([k]) => k === fixKind(u.a))?.[1]}</span></span>
        <span className="shrink-0 rounded-md bg-well px-1.5 py-0.5 text-ink-2">{u.device}</span>
      </div>
      <div className="truncate font-semibold leading-snug">{u.a.app} <span className="font-normal text-ink-3">{u.version}</span></div>
      <div className="grid grid-cols-3 gap-2">
        <StatBox value={vulns} label="Vulnerabilities" />
        <StatBox value={severe} label="Critical / high" color={severe ? statusColor.critical : undefined} />
        {left != null
          ? <StatBox value={Math.abs(left)} label={late ? 'Days overdue' : left === 0 ? 'Due today' : 'Days left'} color={late ? statusColor.critical : undefined} />
          : <StatBox value="–" label="No deadline" />}
      </div>
      {u.r && <div className="flex min-w-0 items-center gap-2"><StatusPill r={u.r} /><PersonLine r={u.r} short /></div>}
    </>
  )
}

/** The small card in the Security configuration grid: the setting, three numbers and the state; the full SettingCard opens on click. */
function SettingSummary({ s, rows }: { s: VulnFixSetting; rows: FixRow[] }) {
  const lv = LEVEL[s.urgency.level]
  const fixes = rows.filter((r) => r.action === 'setting')
  const devices = new Set(rows.map((r) => r.device_name)).size
  const open = fixes.filter((r) => !cleared(r)).length
  const shown = fixes.find((x) => x.status === 'manual_required') ?? fixes.find((x) => x.status !== 'proposed') ?? fixes[0]
  return (
    <>
      <div className="flex items-center justify-between gap-2 text-[11px] font-medium">
        <span className="truncate" style={{ color: lv.color }}>{lv.label} priority · <span className="font-normal text-ink-3">{s.category}</span></span>
      </div>
      <div className="line-clamp-2 font-semibold leading-snug">{s.app}</div>
      <div className="grid grid-cols-3 gap-2">
        <StatBox value={devices} label={devices === 1 ? 'Device' : 'Devices'} />
        <StatBox value={open} label="Not yet fixed" color={open ? statusColor.critical : undefined} />
        <StatBox value={`${s.impact}/10`} label="Impact" />
      </div>
      {shown && <div className="flex min-w-0 items-center gap-2"><StatusPill r={shown} /><PersonLine r={shown} short /></div>}
    </>
  )
}

function VmCard({ u, rank, today, engine, busy, highlight, anchor, onApprove, onWithdraw, onList, fresh, news, agent, otherVersions }: {
  u: Unit; rank: number; today: string; engine: boolean; busy: boolean; highlight: boolean; anchor: boolean
  onApprove: (ids: string[]) => void; onWithdraw: (ids: string[]) => void; onList: () => void; fresh: boolean
  /** this card's open vulnerabilities a threat in the news names; agent: the "Found by" filter; otherVersions: the
   *  app's other versions on this VM (their own cards: this remediation does not change them) */
  news?: number; agent: 'vulnerability' | 'threat_intel' | null; otherVersions: string[]
}) {
  const { a, r, d } = u
  const lv = LEVEL[a.urgency.level]
  const ai = (a.source || '').startsWith('ai')
  const txt = a.ai ?? {}
  const kindOf = fixKind(a)
  const kind = KINDS.find(([k]) => k === kindOf)
  const isDone = !!r && cleared(r)
  const cves = d?.cves ?? []
  const vulns = cves.length || (r && !isDone ? r.findings : 0)
  const severe = cves.filter((c) => c.sev === 'Critical' || c.sev === 'High').length
  const noFix = cves.filter((c) => c.nofix).length
  const left = d?.due && !isDone ? daysBetween(today, d.due) : null
  const late = left != null && left < 0
  const ended = pastEos(a).find((x) => x.version === u.version)
  const ending = !ended ? nearEos(a).find((x) => x.version === u.version) : undefined
  const what = r?.action === 'remove' ? 'removes the old version' : r?.action === 'replace' ? 'replaces it with the current version' : 'updates it to the latest version'
  // what the automated remediation does, in the type line: a "Software upgrade" of Python removes this one version
  const does = r?.action === 'remove' ? 'removes this version' : r?.action === 'replace' ? 'replaces this version' : r && r.action !== 'none' ? 'updates this version' : null
  const verb = r?.action === 'remove' ? 'removes' : r?.action === 'replace' ? 'replaces' : 'updates'
  const inNews = Math.min(news ?? 0, vulns)
  const clears = !!r && r.action !== 'none' && kindOf !== 'none' && !isDone && vulns > 0

  return (
    <section id={anchor ? `fix-${softwareOf(a)}` : undefined}
      className={cn('flex scroll-mt-28 flex-col overflow-hidden rounded-2xl border border-hairline bg-panel transition-shadow',
        highlight && 'ring-2 ring-signal ring-offset-2 ring-offset-canvas', isDone && 'opacity-75')}>
      <span className="h-[3px]" style={{ background: lv.color }} />
      <div className="flex flex-1 flex-col gap-4 p-5">
        <div className="flex items-start gap-3">
          <span className="tabular grid size-8 shrink-0 place-items-center rounded-lg bg-well text-xs font-semibold text-ink-2">#{rank}</span>
          <div className="min-w-0 flex-1">
            <h3 className="font-semibold leading-tight">{a.app} <span className="font-normal text-ink-3">{u.version}</span></h3>
            <p className="mt-1 flex flex-wrap items-center gap-x-1.5 text-xs text-ink-3">
              <Monitor className="size-3.5" /><b className="font-medium text-ink-2">{u.device}</b>
              <span>·</span>
              <span title={kind?.[2]} style={{ color: kindOf === 'none' ? statusColor.warning : undefined }}>{kind?.[1]}</span>
              {does && <><span>·</span><span>{does}</span></>}
              {fresh &&<span className="rounded-md bg-signal/15 px-1.5 py-0.5 text-[10px] font-semibold text-signal">New</span>}
            </p>
            {d?.due && !isDone && (
              <p className="mt-0.5 text-xs" style={{ color: late ? statusColor.critical : undefined }}
                title={`Defender first found these on ${u.device} on ${shortDate(d.firstSeen ?? d.due)}; the patching rule counts the deadline from that day.`}>
                {late ? <b className="font-medium">Overdue since {shortDate(d.due)}</b> : <span className="text-ink-3">Due {shortDate(d.due)}</span>}
                <span className="text-ink-3"> · first found {shortDate(d.firstSeen ?? d.due)}</span>
              </p>
            )}
          </div>
          <span className="flex shrink-0 items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-medium"
            style={{ color: lv.color, background: `color-mix(in oklab, ${lv.color} 12%, transparent)` }}>
            {a.urgency.level === 1 && <AlertTriangle className="size-3.5" />}{lv.label} priority
          </span>
        </div>

        {vulns > 0 ? (
          <>
            <div className="grid grid-cols-3 gap-2">
              <Stat n={vulns} label="Vulnerabilities" />
              <Stat n={severe} label="Critical / high" color={severe ? statusColor.critical : undefined} />
              {left != null
                ? <Stat n={Math.abs(left)} label={late ? `Day${left === -1 ? '' : 's'} overdue` : left === 0 ? 'Due today' : `Day${left === 1 ? '' : 's'} left`} color={late ? statusColor.critical : undefined} />
                : <Stat n={noFix} label="No update yet" color={noFix ? statusColor.warning : undefined} />}
            </div>
            <AgentTags rows={r ? [r] : []} inNews={inNews} />
            <button onClick={onList}
              className="flex w-full items-center justify-center gap-2 rounded-xl bg-blue/15 px-3 py-2.5 text-sm font-semibold text-sky transition-colors hover:bg-blue/25">
              <ListChecks className="size-4" /> View all {num(vulns)} vulnerabilit{vulns === 1 ? 'y' : 'ies'} on {u.device} <ChevronRight className="size-4" />
            </button>
          </>
        ) : <p className="text-sm text-ink-3">{isDone ? 'Remediated: Defender no longer lists vulnerabilities for this version.' : 'No open vulnerabilities.'}</p>}

        {txt.what_is_wrong && <p className="line-clamp-3 text-sm leading-relaxed text-ink-2" title={txt.what_is_wrong}>{txt.what_is_wrong}</p>}

        {(ended || ending || noFix > 0) && (
          <ul className="space-y-1 rounded-xl bg-well px-3.5 py-2.5 text-xs text-ink-2">
            {ended && <li><b className="text-ink">Support ended{ended.eos?.date ? ` (${shortDate(ended.eos.date)})` : ''}:</b> the vendor no longer issues security updates for this version, so upgrade to a supported one.</li>}
            {ending && <li><b className="text-ink">Support ends soon{ending.eos?.date ? ` (${shortDate(ending.eos.date)})` : ''}:</b> plan the move to a supported version.</li>}
            {noFix > 0 && (
              <li>
                <b style={{ color: statusColor.warning }}>No security update available</b>{' '}
                {noFix >= cves.length ? 'for any of these.' : `for ${num(noFix)} of these (updating remediates the others).`} Apply compensating controls until one is released.
              </li>
            )}
          </ul>
        )}

        <Tracker {...trackerCounts(a, r ? [r] : [])} />

        {/* this VM's remediation: exactly what it clears (one update or removal clears every vulnerability on this version,
            whichever agent reported it), its state and its button */}
        <div className="flex flex-col gap-2 rounded-xl border border-hairline px-3.5 py-2.5">
        {clears && (
          <p className="rounded-lg px-2.5 py-1.5 text-xs leading-relaxed text-ink-2"
            style={{ background: agent === 'threat_intel' ? `color-mix(in oklab, ${statusColor.warning} 12%, transparent)` : 'var(--well)' }}>
            <b className="text-ink">Remediate</b> {verb} {a.app} {u.version} on {u.device} and clears <b className="text-ink">all {num(vulns)}</b> vulnerabilit{vulns === 1 ? 'y' : 'ies'} on it
            {inNews > 0
              ? <>: <b className="text-ink">{num(inNews)}</b> reported in threat intelligence and <b className="text-ink">{num(vulns - inNews)}</b> found only by the {AGENT_NAME.vulnerability}.</>
              : <>.</>}
            {otherVersions.length > 0 && <> {a.app} {otherVersions.join(', ')} on {u.device} {otherVersions.length === 1 ? 'has its own card and is' : 'have their own cards and are'} not changed.</>}
          </p>
        )}
        <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
          <div className="min-w-0 flex-1 text-xs">
            {r ? <><StatusPill r={r} /><RowFound r={r} fresh={fresh} /></> : <span className="text-ink-3">{a.fix.action}</span>}
            {r?.message && ['failed', 'awaiting_vendor', 'done', 'still_there'].includes(r.status) && !r.manual && <div className="mt-0.5 line-clamp-2 text-[11px] text-ink-3">{r.message}</div>}
            {r && <ManualAction r={r} compact />}
            {r?.started_at && <RecordLink id={r.fix_id} className="mt-1" />}
          </div>
          {kindOf === 'none' || r?.action === 'none' ? (
            <span className="max-w-[60%] text-right text-xs text-ink-3">{kindOf === 'none' ? 'No update available yet' : r?.note || 'Manual remediation only'}</span>
          ) : !r ? (
            <span className="text-xs text-ink-3">{engine ? 'Not yet in the automated remediation plan' : 'Automated remediation is disabled'}</span>
          ) : canApprove(r) ? (
            <button onClick={() => onApprove([r.fix_id])} disabled={busy}
              title={`Adds it to the remediation queue: the agent ${what} on ${u.device} when you select Execute remediation. This clears all ${num(vulns)} vulnerabilities on this version${inNews ? `, not only the ${num(inNews)} in threat intelligence` : ''}.`}
              className="btn-blue inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-semibold disabled:opacity-50">
              <Zap className="size-3.5" /> {r.status === 'failed' ? 'Retry' : 'Remediate'}
            </button>
          ) : r.status === 'approved' ? (
            <button onClick={() => onWithdraw([r.fix_id])} disabled={busy} className="inline-flex items-center gap-1.5 rounded-lg border border-hairline px-3 py-1.5 text-xs font-medium hover:bg-well disabled:opacity-50">
              <Undo2 className="size-3.5" /> Remove from queue
            </button>
          ) : r.status === 'verified' ? <ShieldCheck className="size-5" style={{ color: statusColor.good }} /> : null}
        </div>
        </div>

        {(txt.why_now || txt.worst_case) && (
          <Details title="Why now">
            {txt.why_now && <p className="text-sm leading-relaxed text-ink-2">{txt.why_now}</p>}
            {txt.worst_case && <p className="mt-2 text-sm text-ink-2"><b className="text-ink">Potential impact: </b>{txt.worst_case}</p>}
          </Details>
        )}
        {(txt.steps?.length || (a.fix.command && kindOf !== 'none')) ? (
          <Details title={<>Manual remediation steps {ai && <AiBadge />}</>}>
            {txt.steps?.length ? <ol className="ml-4 list-decimal space-y-1 text-sm text-ink-2">{txt.steps.map((s, i) => <li key={i}>{s}</li>)}</ol> : null}
            {a.fix.note && <p className="mt-2 text-xs text-ink-3">{a.fix.note}</p>}
            {a.fix.command && kindOf !== 'none' && <div className="mt-2 text-xs text-ink-3">Prefer to do it yourself? <CommandLine command={a.fix.command} /></div>}
          </Details>
        ) : null}
        {(txt.verify || txt.side_effects) && (
          <Details title="Verification and user impact">
            {txt.verify && <p className="text-sm text-ink-2"><b className="text-ink">Check: </b>{txt.verify}</p>}
            {txt.side_effects && <p className="mt-2 text-sm text-ink-2"><b className="text-ink">User impact: </b>{txt.side_effects}</p>}
          </Details>
        )}

        <div className="mt-auto flex flex-wrap items-center gap-2 border-t border-hairline pt-3 text-xs text-ink-3">
          {ai ? <AiBadge text="Agent-generated · review before acting" /> : <Tag>Based on Defender data</Tag>}
          <HopLink to={`/vulnerabilities/all?q=${encodeURIComponent(softwareOf(a))}`} title="This app in our full vulnerability list">Vulnerabilities</HopLink>
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

/** One number on a remediation card */
function Stat({ n, label, color }: { n: number; label: string; color?: string }) {
  return (
    <div className="rounded-xl bg-well px-3 py-2.5">
      <div className="tabular text-xl font-semibold leading-none tracking-tight" style={{ color }}>{num(n)}</div>
      <div className="mt-1.5 text-[11px] text-ink-3">{label}</div>
    </div>
  )
}

/** Gone from Defender's list: fixed and checked, or cleared before the fix ran. */
const cleared = (r: FixRow) => r.status === 'verified' || r.status === 'gone'

/** One computer under a security-setting card, with its own Remediate button */
function ComputerRow({ r, busy, onApprove, onWithdraw, fresh }: { r: FixRow; busy: boolean; onApprove: (ids: string[]) => void; onWithdraw: (ids: string[]) => void; fresh?: boolean }) {
  const what = r.action === 'setting' ? 'changes this setting' : r.action === 'remove' ? 'removes the old version' : r.action === 'replace' ? 'replaces it with the current version' : 'updates it to the latest version'
  return (
    <li className="flex flex-wrap items-center gap-x-3 gap-y-1.5 px-3.5 py-2.5">
      <div className="min-w-0 flex-1">
        <div className="text-sm font-medium">{r.device_name} {r.version && <span className="font-normal text-ink-3">· {r.version}</span>}</div>
        {!isSetting(r) && r.findings > 0 && (
          <div className="mt-0.5 text-xs text-ink-3">
            {num(r.findings)} vulnerabilit{r.findings === 1 ? 'y' : 'ies'}{cleared(r) ? ' remediated' : ' on this device'}
          </div>
        )}
        <div className="mt-0.5"><StatusPill r={r} /></div>
        <RowFound r={r} fresh={fresh} />
        {r.message && ['failed', 'awaiting_vendor', 'done', 'still_there'].includes(r.status) && !r.manual && <div className="mt-0.5 line-clamp-2 text-[11px] text-ink-3">{r.message}</div>}
        <ManualAction r={r} compact />
        {r.started_at && <RecordLink id={r.fix_id} className="mt-1" />}
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

/* ───────── security settings: wrong Windows/Defender settings (Vulnerability advice) + "fix it for me" (Threat Intel fix engine) ───────── */

type SettingFilter = 'all' | 'auto' | 'manual'

function SettingsCards() {
  const { data, error, isLoading } = useVulnData()
  const fix = useFix()
  const act = useFixAction()
  const { opco } = useFilters()
  const [params] = useSearchParams()
  const [filter, setFilter] = useState<SettingFilter>('all')
  const [q, setQ] = useState(params.get('q') ?? '')                  // ?q= from the Summary's "Fix" button
  const [found, setFound] = useState<DateRange>({ preset: 'any' })
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

  if (isLoading || error || !data) return <VulnLoading error={error} />
  // the Vulnerability Agent's published settings, plus any the fix engine already proposes that its last run did not
  // publish (e.g. Defender's settings export was still empty then): a minimal card from the fix engine's own rows
  const published = data.fixes?.settings ?? []
  const known = new Set(published.map((s) => s.config_id))
  const allSettings: VulnFixSetting[] = [...published, ...[...rowsByConfig.entries()].filter(([id]) => !known.has(id)).map(([id, rs]) => ({
    key: `setting:${id}`, kind: 'setting' as const, config_id: id, app: rs[0].app, category: rs[0].category ?? 'Security setting',
    subcategory: rs[0].subcategory ?? null, impact: rs[0].impact ?? 0, fix_type: 'setting', urgency: { level: 3 as const, label: LEVEL[3].label },
    user_impact: false, devices: rs.map((r) => ({ name: r.device_name, opco: r.opco })), opcos: [...new Set(rs.map((r) => r.opco))],
    microsoft: {}, fix: { action: 'setting', command: null, note: null, url: null, in_catalog: true }, ai: null, source: 'fix engine', model: null,
  }))]
  if (!allSettings.length) return <Empty text="No security-setting checks yet. Run the vulnerability update to read them from Defender." />
  const canAuto = (s: VulnFixSetting) => (rowsByConfig.get(s.config_id) ?? []).some((r) => r.action === 'setting')
  const settingRows = (s: VulnFixSetting) => rowsByConfig.get(s.config_id) ?? []
  const inOpcoAll = allSettings.filter((s) => opco === 'all' || s.opcos.includes(opco))
  const agentCounts = { vulnerability: inOpcoAll.filter((s) => settingRows(s).some((r) => belongs(r, 'vulnerability'))).length, threat_intel: 0 }
  const inOpco = agentFilter.agent ? inOpcoAll.filter((s) => settingRows(s).some(agentFilter.matches)) : inOpcoAll
  const autoCount = inOpco.filter(canAuto).length
  const firstFound = (s: VulnFixSetting) => {
    const t = settingRows(s).flatMap((r) => Object.values(r.found_by ?? {})).filter((x): x is string => !!x).sort()[0]
    return t ? new Date(t.replace(' ', 'T') + (/[zZ]|[+-]\d\d:?\d\d$/.test(t) ? '' : 'Z')) : null
  }
  const shown = inOpco
    .filter((s) => (filter === 'all' || (filter === 'auto') === canAuto(s)) && (!q || s.app.toLowerCase().includes(q.toLowerCase()))
      && inDateRange(firstFound(s), found))
    .sort((a, b) => Number(canAuto(b)) - Number(canAuto(a)))             // the ones the portal can change first
  const approve = (ids: string[]) => v && act.mutate({ action: 'approve', ids, method: v.default_method })
  const withdraw = (ids: string[]) => act.mutate({ action: 'unapprove', ids })
  const ready = shown.flatMap((s) => rowsByConfig.get(s.config_id) ?? []).filter((r) => r.action === 'setting' && canApprove(r))
  const agentOptions = [{ value: 'all', label: 'All agents', count: inOpcoAll.length },
    { value: 'vulnerability', label: AGENT_NAME.vulnerability, count: agentCounts.vulnerability, dot: 'var(--sky)' }]
  const modeOptions = [{ value: 'all', label: 'All settings', count: inOpco.length }, { value: 'auto', label: 'Automatable', count: autoCount },
    { value: 'manual', label: 'Manual action required', count: inOpco.length - autoCount }]
  const chips: ActiveFilter[] = [
    ...(q ? [{ key: 'q', label: `“${q}”`, onRemove: () => setQ('') }] : []),
    ...dateChip(found, () => setFound({ preset: 'any' })),
    ...choiceChip('agent', agentOptions, agentFilter.agent ?? 'all', () => agentFilter.set(null)),
    ...choiceChip('mode', modeOptions, filter, () => setFilter('all')),
  ]
  const clearAll = () => { setQ(''); setFound({ preset: 'any' }); setFilter('all'); agentFilter.set(null) }

  return (
    <div className="flex flex-col gap-5">
      {down && <Banner auto={auto} />}

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

      <FilterBar chips={chips} onClear={clearAll} count={
        <span className="inline-flex items-center gap-3">{num(shown.length)} of {num(inOpcoAll.length)} settings
          {ready.length > 0 && (
            <button onClick={() => approve(ready.map((r) => r.fix_id))} disabled={act.isPending}
              title="Adds every automatable setting shown here to the remediation queue. Nothing runs until you select Execute remediation."
              className="btn-blue inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-sm font-semibold text-white disabled:opacity-50">
              <Zap className="size-4" /> Remediate all ({ready.length})
            </button>
          )}
        </span>}>
        <FilterSearch value={q} onChange={setQ} placeholder="Find a setting" />
        <DateFilter label="Found" value={found} onChange={setFound} />
        <FilterChoice label="Found by" icon={Bot} value={agentFilter.agent ?? 'all'} onChange={(a) => agentFilter.set(a === 'all' ? null : a as 'vulnerability' | 'threat_intel')} options={agentOptions} />
        <FilterChoice label="Remediation" icon={Zap} value={filter} onChange={(f) => setFilter(f as typeof filter)} options={modeOptions} />
      </FilterBar>
      <RunBanner filter={agentFilter} what="security settings" />
      {filter === 'manual' && v && (() => {
        const ids = shown.flatMap((s) => rowsByConfig.get(s.config_id) ?? []).filter((r) => r.status === 'info').map((r) => r.fix_id)
        return ids.length ? <HandOverAll ids={ids} busy={act.isPending} onHandOver={(x) => act.mutate({ action: 'handover', ids: x })} /> : null
      })()}

      {shown.length ? (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2 2xl:grid-cols-3">
          {shown.map((s) => (
            <ExpandableCard key={s.key} id={`setting-${s.config_id}`} accent={LEVEL[s.urgency.level].color} title={s.app}
              subtitle={[s.category, s.subcategory].filter(Boolean).join(' · ')}
              eyebrow={<><span className="font-medium" style={{ color: LEVEL[s.urgency.level].color }}>{LEVEL[s.urgency.level].label} priority</span><span className="text-ink-3">Configuration change · impact {s.impact}/10</span></>}
              summary={<SettingSummary s={s} rows={settingRows(s)} />}
              actions={v ? <QuickActions rows={settingRows(s).filter((r) => r.action === 'setting' || r.action === 'none')} busy={act.isPending} onApprove={approve} onWithdraw={withdraw} onSave={(ids) => act.mutate({ action: 'save', ids })} onHandOver={(ids) => act.mutate({ action: 'handover', ids })} /> : null}>
              <SettingCard s={s} rows={settingRows(s)} engine={!!v} busy={act.isPending} isNew={agentFilter.isNew}
                onApprove={approve} onWithdraw={withdraw} />
            </ExpandableCard>
          ))}
        </div>
      ) : <Empty text="No settings match this filter." />}

      {v && <BasketBar v={v} />}
      {act.error && <div className="fixed bottom-24 right-6 z-30 rounded-xl border bg-panel px-4 py-3 text-sm shadow-lg" style={{ borderColor: statusColor.critical }}>{String((act.error as Error).message)}</div>}
    </div>
  )
}

function SettingCard({ s, rows, engine, busy, onApprove, onWithdraw, isNew }: {
  s: VulnFixSetting; rows: FixRow[]; engine: boolean; busy: boolean; onApprove: (ids: string[]) => void; onWithdraw: (ids: string[]) => void
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

function AiBadge({ text = 'Agent' }: { text?: string }) {
  return (
    <span className="inline-flex items-center gap-1 rounded-md bg-violet/15 px-1.5 py-0.5 text-[11px] font-medium text-violet">
      <Sparkles className="size-3" /> {text}
    </span>
  )
}

/** Remediations the agent cannot do (no automatic fix): hand them all to the people who must do them by hand. */
function HandOverAll({ ids, busy, onHandOver }: { ids: string[]; busy: boolean; onHandOver: (ids: string[]) => void }) {
  return (
    <Panel className="flex flex-wrap items-center gap-3 px-5 py-3.5">
      <UserCog className="size-5 shrink-0" style={{ color: statusColor.critical }} />
      <p className="min-w-0 flex-1 text-sm text-ink-2">
        <b className="text-ink">{num(ids.length)} remediation{ids.length === 1 ? '' : 's'} the agent cannot do.</b> Hand them over: each becomes
        "Manual action required" with an owner and steps, and stays open until someone marks it fixed and Defender confirms it.
      </p>
      <button onClick={() => onHandOver(ids)} disabled={busy} className="btn-blue inline-flex items-center gap-1.5 rounded-lg px-3.5 py-2 text-sm font-semibold text-white disabled:opacity-50">
        <UserCog className="size-4" /> Hand all {num(ids.length)} over
      </button>
    </Panel>
  )
}
