import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import {
  AlertTriangle, ArrowRight, CheckCircle2, Clock, ExternalLink, Hand, HelpCircle, Play, SlidersHorizontal,
  X, XCircle,
} from 'lucide-react'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuLabel, DropdownMenuRadioGroup, DropdownMenuRadioItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { UC_LABEL, useRuns, type UcKey } from '@/lib/runs'
import { VERDICT, VERDICT_ORDER, sourceNames, useUc4Queue, utc } from '@/lib/uc4'
import { attackType, useUc1Data } from '@/lib/uc1'
import { Skeleton } from '@/components/ui/skeleton'
import { Chart } from '@/components/Chart'
import { Chip, InfoTip, Panel, Tabs } from '@/components/kit'
import { fetchSummary, type Health, type Summary } from '@/lib/api'
import { qualityWord } from '@/lib/format'
import { useFilters } from '@/lib/filters'
import { ago, dateTime, num, shortDate } from '@/lib/format'
import { chartTokens, statusColor, useTheme } from '@/lib/theme'
import { cn } from '@/lib/utils'

export function Home() {
  const { data, isLoading, error } = useQuery({ queryKey: ['summary'], queryFn: fetchSummary, refetchInterval: 30_000 })
  if (isLoading) return <HomeSkeleton />
  if (error || !data)
    return (
      <Panel className="p-6">
        <h2 className="font-semibold">CyberSuite is not available</h2>
        <p className="mt-1 text-sm text-ink-3">{String(error ?? 'No data')}. Reload the page; if this continues, contact your administrator.</p>
      </Panel>
    )
  return <HomeView s={data} />
}

/* ───────────────────────── derived, filter-aware view model ───────────────────────── */

export function useView(s: Summary) {
  const { opco } = useFilters()
  return useMemo(() => {
    const all = opco === 'all'
    const ot = s.uc3.opco_totals.find((o) => o.opco === opco)
    const totals = all
      ? { findings: s.uc3.totals.total ?? 0, p1: s.uc3.totals.p1 ?? 0,
          fixed: s.uc3.totals.remediated ?? 0, fixedSince: s.uc3.totals.fixed_since ?? null }
      : { findings: ot?.findings ?? 0, p1: ot?.p1 ?? 0,
          fixed: ot?.fixed ?? 0, fixedSince: ot?.fixed_since ?? null }
    const trend = all
      ? s.uc3.trend.map((r) => ({ date: r.date, total: r.total }))
      : s.uc3.trend_opco.filter((r) => r.opco === opco).map((r) => ({ date: r.date, total: r.total }))

    const byApp = new Map<string, { app: string; findings: number }>()
    for (const a of s.uc3.apps) {
      if (!all && a.opco !== opco) continue
      const row = byApp.get(a.software_name) ?? { app: a.app, findings: 0 }
      row.findings += a.findings
      byApp.set(a.software_name, row)
    }
    const apps = [...byApp.values()].sort((a, b) => b.findings - a.findings)
    const deviceOpco = new Map(s.devices.map((d) => [d.name, d.opco]))
    return {
      opco,
      totals,
      trend,
      apps,
      fixes: s.uc3.fixes.filter((f) => all || f.opcos.split(',').map((x) => x.trim()).includes(opco)),
      threats: s.uc1.top_threats.filter(
        (t) => all || (t.devices ?? '').split(',').some((d) => deviceOpco.get(d.trim()) === opco),
      ),
      devices: s.devices.filter((d) => all || d.opco === opco),
    }
  }, [s, opco])
}

export type View = ReturnType<typeof useView>

/* ───────────────────────── page ───────────────────────── */

// The page's own tab row (same look as the other pages): each tab jumps to its part of the page.
type Section = 'summary' | 'risk' | 'agents'
const SECTIONS: [Section, string][] = [['summary', 'Summary'], ['risk', 'Apps and VMs'], ['agents', 'Agents']]
const SECTION_TARGET: Record<Section, string> = { summary: 'top', risk: 'work', agents: 'pipelines' }

function HomeView({ s }: { s: Summary }) {
  const v = useView(s)
  const [section, setSection] = useState<Section>('summary')
  const attack = useAttackHealth()
  const goTo = (t: Section) => {
    setSection(t)
    document.getElementById(SECTION_TARGET[t])?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }
  return (
    <div className="flex flex-col gap-5">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Summary</h1>
          <p className="mt-1 text-sm text-ink-3">
            {v.opco === 'all' ? 'All VMs' : v.opco} · Defender vulnerabilities, threat intelligence, attack detection and triage
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {/* same order as the menu: vulnerability management (UC3), threat news (UC1), attack detection, alert triage (UC4) */}
          {[...['uc3', 'uc1'].map((k) => s.health.find((h) => h.key === k)), attack, s.health.find((h) => h.key === 'uc4')]
            .filter((h): h is PillHealth => !!h).map((h) => <HealthPill key={h.key} h={h} />)}
          <FiltersButton s={s} />
        </div>
      </div>
      <Tabs<Section> tabs={SECTIONS} value={section} onChange={goTo} />
      <ActiveFilters />

      <div className="card-row gap-5 [--card-min:280px]">
        <PriorityCard v={v} />
        <FixedCard v={v} />
        <TrendCard v={v} />
      </div>

      <div id="work" className="grid scroll-mt-32 grid-cols-1 gap-5 lg:grid-cols-2">
        <AppsCard v={v} />
        <VmCard s={s} v={v} />
      </div>

      <div id="pipelines" className="grid scroll-mt-32 grid-cols-1 gap-5 lg:grid-cols-2">
        <Uc3Panel s={s} />
        <Uc1Panel s={s} />
        <AttackPanel />
        <Uc4Panel s={s} />
      </div>
    </div>
  )
}

/* ───────────────────────── building blocks ───────────────────────── */




const HEALTH = {
  ok: { icon: CheckCircle2, color: statusColor.good, label: 'Up to date' },
  stale: { icon: Clock, color: statusColor.warning, label: 'Out of date' },
  error: { icon: XCircle, color: statusColor.critical, label: 'Last run failed' },
  missing: { icon: HelpCircle, color: statusColor.serious, label: 'No data yet' },
} as const

type PillHealth = Pick<Health, 'name' | 'status' | 'data_as_of' | 'quality'> & { key: UcKey }

/** Attack detection's status, from the attack check's own data and its last run (the summary covers only UC1/3/4). */
function useAttackHealth(): PillHealth {
  const { data } = useUc1Data()
  const { runs } = useRuns()
  // UC1 writes "YYYY-MM-DD HH:MM:SS" in UTC, sometimes with an offset
  const checked = data?.generated ? new Date(data.generated.replace(/[+Z].*$/, '').replace(' ', 'T') + 'Z') : null
  const status = runs?.attack?.status === 'failed' ? 'error' : !checked ? 'missing'
    : Date.now() - checked.getTime() > 26 * 3600_000 ? 'stale' : 'ok'
  return { key: 'attack', name: 'Attack detection', status, data_as_of: checked ? checked.toISOString() : null, quality: null }
}

function HealthPill({ h }: { h: PillHealth }) {
  const st = HEALTH[h.status]
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span className="flex items-center gap-2 rounded-full border border-hairline bg-panel py-1.5 pl-2.5 pr-3.5 text-xs">
          <st.icon className="size-3.5" style={{ color: st.color }} />
          <span className="font-medium">{UC_LABEL[h.key]}</span>
          <span className="text-ink-3">{st.label} · {ago(h.data_as_of)}</span>
        </span>
      </TooltipTrigger>
      <TooltipContent>
        {h.name}: data as of {dateTime(h.data_as_of)}{h.quality ? ` · quality ${qualityWord(h.quality)}` : ''}
      </TooltipContent>
    </Tooltip>
  )
}

/* ───────────────────────── KPI cards ───────────────────────── */

export const shortApp = (app: string) =>
  app.replace(/^(Mozilla|Adobe|Microsoft) /, '').replace(/^Acrobat Reader$/, 'Acrobat').replace(/ \(.*\)$/, '')

function PriorityCard({ v }: { v: View }) {
  const pct = v.totals.findings ? (v.totals.p1 / v.totals.findings) * 100 : 0
  const rest = 100 - pct
  return (
    <Panel className="card-hero flex flex-col p-6">
      <div className="flex items-start justify-between">
        <h3 className="flex items-center gap-1.5 text-sm">P1 findings <InfoTip text="Share of all findings rated P1: the vulnerabilities to remediate first. The chip shows the count." /></h3>
        <Chip>{num(v.totals.p1)}</Chip>
      </div>
      <div className="mt-2 text-[34px] font-normal leading-none tracking-tight tabular">{pct.toFixed(1)}%</div>
      <div className="mt-auto pt-7">
        <div className="relative">
          <div className="mb-2 text-center text-xs text-ink-3">P2–P4</div>
          <div className="h-[3px] rounded-full" style={{ background: 'linear-gradient(90deg, rgb(255 255 255 / 0.55), #ffd166 75%, var(--signal))' }} />
          <div className="absolute top-6 h-3 w-px bg-ink" style={{ left: `${rest}%` }} />
          <div className="tabular mt-3 text-right text-xs font-medium" style={{ paddingRight: `${Math.max(0, pct - 6)}%` }}>{rest.toFixed(1)}%</div>
        </div>
      </div>
    </Panel>
  )
}

function FixedCard({ v }: { v: View }) {
  const { theme } = useTheme()
  const { fixed, findings: open, fixedSince } = v.totals
  const pct = fixed + open ? Math.round((fixed / (fixed + open)) * 100) : 0
  return (
    <Panel className="flex flex-col p-6">
      <div className="flex items-start justify-between">
        <h3 className="flex items-center gap-1.5 text-sm">Vulnerabilities remediated <InfoTip text="Vulnerabilities Defender no longer reports on managed devices, counted since tracking began. The ring shows remediated against still open." /></h3>
        <Chip>{num(open)} still open</Chip>
      </div>
      <div className="mt-2 flex flex-1 items-end justify-between gap-4">
        <div className="flex min-w-0 flex-col">
          <div className="text-[34px] leading-none tracking-tight tabular" style={{ color: fixed ? statusColor.good : undefined }}>{num(fixed)}</div>
          {/* the start date needs the portal's newer summary; without it, show the count alone */}
          {(fixedSince || !fixed) && <div className="mt-2 text-xs text-ink-3">{fixed ? `since ${shortDate(fixedSince!)}` : 'none remediated yet'}</div>}
          <ul className="mt-4 flex flex-col gap-1.5 text-xs text-ink-2">
            <li className="flex items-center gap-1.5"><span className="size-1.5 rounded-full" style={{ background: statusColor.good }} />{pct}% of everything found is remediated</li>
            <li className="flex items-center gap-1.5"><span className="size-1.5 rounded-full" style={{ background: chartTokens[theme].axis }} />{100 - pct}% still to do</li>
          </ul>
        </div>
        <div className="size-[92px] shrink-0">
          <Chart
            height={92}
            build={(tk) => ({
              tooltip: { trigger: 'item', formatter: '{b}: {c}' },
              series: [{
                type: 'pie', radius: ['78%', '96%'], padAngle: 3, itemStyle: { borderRadius: 4 }, label: { show: false },
                data: [{ name: 'Remediated', value: fixed, itemStyle: { color: statusColor.good } },
                       { name: 'Still open', value: open, itemStyle: { color: tk.axis } }],
              }],
            })}
          />
        </div>
      </div>
    </Panel>
  )
}

function TrendCard({ v }: { v: View }) {
  const last = v.trend.at(-1)?.total ?? 0
  const prev = v.trend.at(-2)?.total ?? last
  const delta = last - prev
  return (
    <Panel className="flex flex-col p-6 md:col-span-2 xl:col-span-1">
      <div className="flex items-start justify-between">
        <h3 className="flex items-center gap-1.5 text-sm">Open findings <InfoTip text="Every vulnerability Defender reports, counted once per application per device. The line shows each daily snapshot." /></h3>
        <Chip>{delta >= 0 ? '+' : '−'}{num(Math.abs(delta))} since {v.trend.at(-2) ? shortDate(v.trend.at(-2)!.date) : '–'}</Chip>
      </div>
      <div className="mt-2 text-[34px] leading-none tracking-tight tabular">{num(last)}</div>
      <div className="-mx-2 mt-auto">
        <Chart
          height={70}
          build={(tk) => ({
            grid: { left: 6, right: 6, top: 8, bottom: 4 },
            tooltip: { trigger: 'axis', axisPointer: { type: 'line', lineStyle: { color: tk.axis } }, valueFormatter: (x: unknown) => num(Number(x)) },
            xAxis: { type: 'category', show: false, boundaryGap: false, data: v.trend.map((r) => shortDate(r.date)) },
            yAxis: { type: 'value', show: false, min: (m: { min: number }) => m.min * 0.85 },
            series: [{ type: 'line', smooth: 0.5, symbol: 'none', data: v.trend.map((r) => r.total), lineStyle: { width: 2.5, color: tk.series[0] } }],
          })}
        />
        <div className="flex justify-between px-2 text-[11px] text-ink-3">
          <span>{v.trend[0] ? shortDate(v.trend[0].date) : ''}</span>
          <span>{v.trend.at(-1) ? shortDate(v.trend.at(-1)!.date) : ''}</span>
        </div>
      </div>
    </Panel>
  )
}

/* ───────────────────────── apps and VMs ───────────────────────── */

const SEVERITIES = ['Critical', 'High', 'Medium', 'Low'] as const

function AppsCard({ v }: { v: View }) {
  const { theme } = useTheme()
  const t = chartTokens[theme]
  const top = v.apps.slice(0, 14)
  const max = top[0]?.findings ?? 1
  return (
    <Panel className="p-6">
      <h3 className="font-semibold">Most vulnerable apps</h3>
      <p className="mt-1 text-sm text-ink-3">Which apps cause the most vulnerabilities?</p>
      <ul className="mt-5 flex flex-col gap-3.5">
        {top.map((a, i) => (
          <li key={a.app} className="grid grid-cols-[112px_1fr] items-center gap-3 text-xs">
            <span className="truncate text-right text-ink-3" title={a.app}>{shortApp(a.app)}</span>
            <span className="flex items-center gap-2">
              <span className="rank-bar h-2.5 rounded-full" style={{ width: `${Math.max(3, (a.findings / max) * 82)}%`, background: t.series[i % t.series.length], animationDelay: `${i * 40}ms` }} />
              <span className="tabular font-medium">{num(a.findings)}</span>
            </span>
          </li>
        ))}
      </ul>
    </Panel>
  )
}

function VmCard({ s, v }: { s: Summary; v: View }) {
  const { theme } = useTheme()
  const t = chartTokens[theme]
  const opcos = s.uc3.opco_totals
  const opcoMax = Math.max(...opcos.map((o) => o.findings), 1)
  return (
    <Panel className="p-6">
      <h3 className="font-semibold">Findings on each VM</h3>
      <p className="mt-1 text-sm text-ink-3">How severe is each VM's exposure?</p>
      <ul className="mt-6 flex flex-col gap-6">
        {opcos.map((o) => {
          const rows = s.uc3.opco.filter((r) => r.opco === o.opco)
          return (
            <li key={o.opco} className={cn(v.opco !== 'all' && v.opco !== o.opco && 'opacity-40')}>
              <div className="mb-2 flex items-baseline justify-between text-sm">
                <span className="font-medium">{o.opco}</span>
                <span className="tabular text-ink-3">{num(o.findings)}</span>
              </div>
              <div className="flex h-2 gap-0.5" style={{ width: `${(o.findings / opcoMax) * 100}%` }}>
                {SEVERITIES.map((sev) => {
                  const c = rows.find((r) => r.severity === sev)?.count ?? 0
                  return (
                    <Tooltip key={sev}>
                      <TooltipTrigger asChild>
                        <span className="h-full first:rounded-l-full last:rounded-r-full" style={{ flexGrow: c, background: t.severity[sev] }} />
                      </TooltipTrigger>
                      <TooltipContent>{sev}: {num(c)}</TooltipContent>
                    </Tooltip>
                  )
                })}
              </div>
            </li>
          )
        })}
      </ul>
      <div className="mt-6 flex flex-wrap gap-x-4 gap-y-1.5 text-xs text-ink-3">
        {SEVERITIES.map((sev) => (
          <span key={sev} className="flex items-center gap-1.5">
            <span className="size-2 rounded-full" style={{ background: t.severity[sev] }} /> {sev}
          </span>
        ))}
      </div>
    </Panel>
  )
}

/* ───────────────────────── the two use cases ───────────────────────── */

function PipelineHeader({ tag, tone, title, h }: { tag: string; tone: string; title: string; h?: Pick<Health, 'status' | 'last_run_at'> }) {
  const st = HEALTH[h?.status ?? 'missing']
  return (
    <div className="flex items-start justify-between gap-3">
      <div>
        <div className="flex items-center gap-2 text-xs font-medium text-ink-3">
          <span className={cn('size-2 rounded-full', tone)} /> {tag}
        </div>
        <h3 className="mt-1 text-lg font-semibold tracking-tight">{title}</h3>
      </div>
      <span className="flex items-center gap-1.5 whitespace-nowrap text-xs text-ink-2">
        <st.icon className="size-3.5" style={{ color: st.color }} /> {st.label} · {ago(h?.last_run_at)}
      </span>
    </div>
  )
}

function Stat({ value, label }: { value: string; label: string }) {
  return (
    <div>
      <div className="tabular text-2xl leading-none tracking-tight">{value}</div>
      <div className="mt-1.5 text-xs text-ink-3">{label}</div>
    </div>
  )
}

function PipelineActions({ to, uc, open }: { to: string; uc: UcKey; open: string }) {
  return (
    <div className="flex flex-wrap gap-2">
      <Link to={to} className="inline-flex items-center gap-2 rounded-lg btn-blue px-4 py-2 text-sm font-medium text-white">
        {open} <ArrowRight className="size-4" />
      </Link>
      <RunButton uc={uc} />
    </div>
  )
}

function RunButton({ uc }: { uc: UcKey }) {
  const { runs, start, openDrawer } = useRuns()
  const running = runs?.[uc]?.status === 'running'
  // the last run is paused at its Fix step until every new fix has a decision: open it instead of starting another
  const waiting = !running && !!runs?.[uc]?.waiting_for_you
  return (
    <button
      onClick={() => (running || waiting ? openDrawer(uc) : start(uc))}
      className="inline-flex items-center gap-2 rounded-lg border border-hairline px-4 py-2 text-sm font-medium hover:bg-well"
    >
      {running ? <span className="size-2 animate-pulse rounded-full bg-sky" /> : waiting ? <Hand className="size-3.5" /> : <Play className="size-3.5" />}
      {running ? 'Running… view progress' : waiting ? 'Awaiting approval' : 'Run agent'}
    </button>
  )
}


function FiltersButton({ s }: { s: Summary }) {
  const { opco, setOpco } = useFilters()
  const active = opco !== 'all' ? 1 : 0
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <button className="flex items-center gap-2 rounded-full border border-hairline bg-panel px-3.5 py-1.5 text-xs font-medium hover:bg-well">
          <SlidersHorizontal className="size-3.5" /> Filters
          {active ? <span className="tabular grid size-4 place-items-center rounded-full btn-blue text-[10px] text-white">{active}</span> : null}
        </button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-60">
        <DropdownMenuLabel>VM</DropdownMenuLabel>
        <DropdownMenuRadioGroup value={opco} onValueChange={setOpco}>
          <DropdownMenuRadioItem value="all">All VMs</DropdownMenuRadioItem>
          {s.uc3.opco_totals.map((o) => (
            <DropdownMenuRadioItem key={o.opco} value={o.opco}>{o.opco} · {num(o.findings)} findings</DropdownMenuRadioItem>
          ))}
        </DropdownMenuRadioGroup>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}

function ActiveFilters() {
  const { opco, setOpco } = useFilters()
  if (opco === 'all') return null
  return (
    <div className="-mt-2 flex flex-wrap items-center gap-2 text-xs">
      <span className="text-ink-3">Filtered by</span>
      {opco !== 'all' && (
        <button onClick={() => setOpco('all')} className="flex items-center gap-1.5 rounded-full btn-blue px-3 py-1 text-white">
          {opco} <X className="size-3" />
        </button>
      )}
    </div>
  )
}

function Uc1Panel({ s }: { s: Summary }) {
  const u = s.uc1.totals
  const { days, series } = s.uc1.threat_trend
  const names = Object.keys(series)
  const { theme } = useTheme()
  const t = chartTokens[theme]
  return (
    <Panel className="flex flex-col gap-5 p-6">
      <PipelineHeader tag="Agent" tone="bg-violet" title="Threat Intel Agent" h={s.health.find((h) => h.key === 'uc1')} />
      <div className="grid grid-cols-3 gap-4 border-y border-hairline py-4">
        <Stat value={num(u.new_threats)} label="threats collected (30 days)" />
        <Stat value={num(u.affecting)} label="applicable to managed devices" />
        <Stat value={num(u.urgent)} label="high priority, remediate first" />
      </div>
      <div>
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h4 className="text-sm font-medium">New intelligence per day</h4>
          <div className="flex flex-wrap gap-3 text-xs text-ink-3">
            {names.map((n, i) => (
              <span key={n} className="flex items-center gap-1.5"><span className="size-1.5 rounded-full" style={{ background: t.series[i] }} />{n}</span>
            ))}
          </div>
        </div>
        <Chart
          height={130}
          build={(tk) => ({
            grid: { left: 4, right: 4, top: 12, bottom: 4, containLabel: true },
            tooltip: { trigger: 'axis', axisPointer: { type: 'shadow', shadowStyle: { color: tk.grid } } },
            xAxis: { type: 'category', data: days.map(shortDate), axisLine: { lineStyle: { color: tk.axis } }, axisTick: { show: false }, axisLabel: { color: tk.muted, fontSize: 10, interval: 3 } },
            yAxis: { type: 'value', splitNumber: 3, axisLabel: { color: tk.muted, fontSize: 10 }, splitLine: { lineStyle: { color: tk.grid } } },
            series: names.map((n, i) => ({ name: n, type: 'bar', stack: 'a', barWidth: '55%', data: series[n], itemStyle: { color: tk.series[i], borderColor: tk.surface, borderWidth: 1, borderRadius: i === names.length - 1 ? [3, 3, 0, 0] : 0 } })),
          })}
        />
      </div>
      <PipelineActions to="/uc1" uc="uc1" open="Open threat intelligence" />
    </Panel>
  )
}

function Uc3Panel({ s }: { s: Summary }) {
  const h = s.health.find((x) => x.key === 'uc3')
  const q = s.uc3.quality
  const passed = q.filter((c) => c.status === 'PASS').length
  const label = (n: string) => {
    const t = n.replace(/_/g, ' ').replace('vs defender', 'vs Defender').replace('opco', 'VM').replace(' cves', ' CVEs')
    return t.charAt(0).toUpperCase() + t.slice(1)
  }
  return (
    <Panel className="flex flex-col gap-5 p-6">
      <PipelineHeader tag="Agent" tone="bg-sky" title="Vulnerability Agent" h={h} />
      <div className="grid grid-cols-3 gap-4 border-y border-hairline py-4">
        <Stat value={num(h?.vulnerabilities ?? h?.rows)} label="findings in Defender" />
        <Stat value={`${Math.round((h?.coverage ?? 0) * 100)}%`} label="coverage, nothing missing" />
        <Stat value={num(s.uc3.totals.cves)} label="unique CVEs" />
      </div>
      <div>
        <div className="flex items-center justify-between">
          <h4 className="text-sm font-medium">Data quality checks</h4>
          <span className="text-xs text-ink-3">{passed} of {q.length} passed · quality {qualityWord(h?.quality)}</span>
        </div>
        <ul className="mt-3 grid grid-cols-1 gap-x-6 gap-y-2 text-sm sm:grid-cols-2">
          {q.slice(0, 10).map((c) => {
            const ok = c.status === 'PASS'
            const Icon = ok ? CheckCircle2 : c.status === 'INFO' ? HelpCircle : AlertTriangle
            const color = ok ? statusColor.good : c.status === 'INFO' ? 'var(--ink-3)' : c.status === 'WARN' ? statusColor.warning : statusColor.critical
            return (
              <Tooltip key={c.check_name}>
                <TooltipTrigger asChild>
                  <li className="flex items-center gap-2 text-ink-2">
                    <Icon className="size-3.5 shrink-0" style={{ color }} />
                    <span className="truncate">{label(c.check_name)}</span>
                    {!ok && <span className="text-xs text-ink-3">{c.status.toLowerCase()}</span>}
                  </li>
                </TooltipTrigger>
                <TooltipContent className="max-w-72">{c.message}</TooltipContent>
              </Tooltip>
            )
          })}
        </ul>
      </div>
      <div className="mt-auto">
        <PipelineActions to="/uc3" uc="uc3" open="Open vulnerabilities" />
      </div>
    </Panel>
  )
}

function Uc4Panel({ s }: { s: Summary }) {
  const u = s.uc4.totals
  const total = Object.values(u.by_verdict).reduce((a, b) => a + b, 0)
  return (
    <Panel className="flex flex-col gap-5 p-6">
      <PipelineHeader tag="Agent" tone="bg-rose" title="Alert Triage Agent" h={s.health.find((h) => h.key === 'uc4')} />
      <div className="grid grid-cols-1 gap-5">
        <div className="flex flex-col gap-4">
          <div className="grid grid-cols-3 gap-4 border-y border-hairline py-4">
            <Stat value={num(u.incidents)} label="incidents triaged" />
            <Stat value={num(u.escalate)} label="escalated" />
            <Stat value={num(u.awaiting_review)} label="need your decision" />
          </div>
          <div>
            <div className="flex h-2 overflow-hidden rounded-full bg-well">
              {VERDICT_ORDER.map((v) => (u.by_verdict[v] ? <span key={v} style={{ width: `${(u.by_verdict[v] / total) * 100}%`, background: VERDICT[v].color }} /> : null))}
            </div>
            <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-ink-3">
              {VERDICT_ORDER.map((v) => (
                <span key={v} className="flex items-center gap-1.5"><span className="size-1.5 rounded-full" style={{ background: VERDICT[v].color }} />{VERDICT[v].short} {u.by_verdict[v] ?? 0}</span>
              ))}
            </div>
          </div>
        </div>
        <div>
          <h4 className="text-sm font-medium">Latest verdicts</h4>
          {s.uc4.latest.length ? (
            <ul className="mt-2 flex flex-col divide-y divide-hairline">
              {s.uc4.latest.map((r) => (
                <li key={r.incident_id}>
                  <Link to={`/respond/${encodeURIComponent(r.incident_id)}`} className="flex items-center gap-3 py-2 text-sm hover:underline">
                    <span className="size-2 shrink-0 rounded-full" style={{ background: VERDICT[r.verdict as keyof typeof VERDICT]?.color ?? 'var(--ink-3)' }} />
                    <span className="min-w-0 flex-1 truncate">{r.title}</span>
                    <span className="shrink-0 text-xs text-ink-3">{VERDICT[r.verdict as keyof typeof VERDICT]?.short ?? r.verdict} · {ago(utc(r.triaged_at)?.toISOString())}</span>
                  </Link>
                </li>
              ))}
            </ul>
          ) : <p className="mt-2 text-sm text-ink-3">No incidents yet.</p>}
        </div>
      </div>
      <div className="mt-auto">
        <PipelineActions to="/respond" uc="uc4" open="Open alert triage" />
      </div>
    </Panel>
  )
}

/** Attack Detection Agent: the same numbers as the Attack detection page (our own checks + attacks Microsoft's
 *  alarms caught, i.e. the triage agent's true positives). */
function AttackPanel() {
  const { data } = useUc1Data()
  const { data: triage } = useUc4Queue()
  const health = useAttackHealth()
  const hits = data?.hits ?? []
  const caught = (triage?.queue ?? []).filter((r) => r.verdict === 'likely_true_positive')
  const computers = new Set(hits.map((h) => h.device_name)).size
  const at = (t: string) => new Date(t.replace(/[+Z].*$/, '').replace(' ', 'T') + 'Z')
  const latest = [
    ...hits.map((h) => ({ key: `h${h.finding_id}`, to: '/uc1/hunts', what: attackType(h.kind, h.detail).label,
      where: h.device_name, by: '', when: at(h.first_hit) })),
    ...caught.map((r) => ({ key: `c${r.incident_id}`, to: `/respond/${encodeURIComponent(r.incident_id)}`, what: r.title,
      where: r.devices[0] ?? r.accounts[0] ?? '', by: `Detected by ${sourceNames(r.sources) || 'Microsoft'}`,
      when: utc(r.created_at) ?? new Date(0) })),
  ].sort((a, b) => b.when.getTime() - a.when.getTime()).slice(0, 4)
  const tone = hits.length + caught.length ? statusColor.critical : statusColor.good
  return (
    <Panel className="flex flex-col gap-5 p-6">
      <PipelineHeader tag="Agent" tone="bg-signal" title="Attack Detection Agent"
        h={{ status: health.status, last_run_at: health.data_as_of }} />
      <div className="grid grid-cols-3 gap-4 border-y border-hairline py-4">
        <div>
          <div className="tabular text-2xl leading-none tracking-tight" style={{ color: tone }}>{num(hits.length + caught.length)}</div>
          <div className="mt-1.5 text-xs text-ink-3">detections</div>
        </div>
        <Stat value={num(hits.length)} label={`found by agent hunts${computers ? `, on ${computers} device${computers === 1 ? '' : 's'}` : ''}`} />
        <Stat value={num(caught.length)} label="detected by Microsoft" />
      </div>
      <div>
        <h4 className="text-sm font-medium">Latest detections</h4>
        {latest.length ? (
          <ul className="mt-2 flex flex-col divide-y divide-hairline">
            {latest.map((x) => (
              <li key={x.key}>
                <Link to={x.to} className="flex items-center gap-3 py-2 text-sm hover:underline">
                  <span className="size-2 shrink-0 rounded-full" style={{ background: statusColor.critical }} />
                  <span className="min-w-0 flex-1 truncate">{x.what}{x.where ? <span className="text-ink-3"> · {x.where}</span> : null}</span>
                  <span className="shrink-0 text-xs text-ink-3">{x.by ? `${x.by} · ` : ''}{ago(x.when.toISOString())}</span>
                </Link>
              </li>
            ))}
          </ul>
        ) : <p className="mt-2 text-sm text-ink-3">{data ? 'No detections found.' : 'Not checked yet.'}</p>}
      </div>
      <div className="mt-auto">
        <PipelineActions to="/uc1/hunts" uc="attack" open="Open attack detection" />
      </div>
    </Panel>
  )
}

/* ───────────────────────── loading + placeholders ───────────────────────── */

function HomeSkeleton() {
  return (
    <div className="flex flex-col gap-5">
      <Skeleton className="h-12 w-80 rounded-xl" />
      <div className="card-row gap-5 [--card-min:280px]">
        {[0, 1, 2].map((i) => <Skeleton key={i} className="h-40 rounded-2xl" />)}
      </div>
      <div className="grid gap-5 xl:grid-cols-3">
        <Skeleton className="h-96 rounded-2xl xl:col-span-2" />
        <Skeleton className="h-96 rounded-2xl" />
      </div>
    </div>
  )
}

export function ComingSoon({ title, phase, oldSite }: { title: string; phase: string; oldSite?: string }) {
  return (
    <Panel className="mx-auto mt-10 max-w-xl p-8 text-center">
      <h2 className="text-lg font-semibold">{title}</h2>
      <p className="mt-1 text-sm text-ink-3">Being rebuilt in the new design ({phase}).</p>
      {oldSite && (
        <a href={oldSite} target="_blank" rel="noreferrer" className="mt-5 inline-flex items-center gap-2 rounded-lg border border-hairline px-4 py-2 text-sm font-medium hover:bg-well">
          Open the current site <ExternalLink className="size-4" />
        </a>
      )}
    </Panel>
  )
}
