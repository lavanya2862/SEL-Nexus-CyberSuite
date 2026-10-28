import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import {
  AlertTriangle, ArrowRight, CheckCircle2, Clock, Copy, ExternalLink, Hand, HelpCircle, LayoutGrid, List, Play, SlidersHorizontal,
  X, XCircle, Zap,
} from 'lucide-react'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuLabel, DropdownMenuRadioGroup, DropdownMenuRadioItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { UC_LABEL, useRuns, type UcKey } from '@/lib/runs'
import { VERDICT, VERDICT_ORDER, sourceNames, useUc4Queue, utc } from '@/lib/uc4'
import { attackType, threatHref, useUc1Data } from '@/lib/uc1'
import { Skeleton } from '@/components/ui/skeleton'
import { Chart } from '@/components/Chart'
import { Chip, Empty, InfoTip, Panel, Table, Tabs } from '@/components/kit'
import { fetchSummary, type Health, type Summary } from '@/lib/api'
import { useFilters, type WorkTab } from '@/lib/filters'
import { ago, dateTime, num, shortDate } from '@/lib/format'
import { chartTokens, statusColor, useTheme } from '@/lib/theme'
import { cn } from '@/lib/utils'

export function Home() {
  const { data, isLoading, error } = useQuery({ queryKey: ['summary'], queryFn: fetchSummary, refetchInterval: 30_000 })
  if (isLoading) return <HomeSkeleton />
  if (error || !data)
    return (
      <Panel className="p-6">
        <h2 className="font-semibold">Unable to reach the portal service</h2>
        <p className="mt-1 text-sm text-ink-3">{String(error ?? 'No data')}. Start it with `python -m portal serve`, then reload.</p>
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
      ? { findings: s.uc3.totals.total ?? 0, p1: s.uc3.totals.p1 ?? 0, kev: s.uc3.totals.kev ?? 0, ransomware: s.uc3.totals.ransomware ?? 0,
          fixed: s.uc3.totals.remediated ?? 0, fixedSince: s.uc3.totals.fixed_since ?? null }
      : { findings: ot?.findings ?? 0, p1: ot?.p1 ?? 0, kev: ot?.kev ?? 0, ransomware: ot?.ransomware ?? 0,
          fixed: ot?.fixed ?? 0, fixedSince: ot?.fixed_since ?? null }
    const trend = all
      ? s.uc3.trend.map((r) => ({ date: r.date, total: r.total }))
      : s.uc3.trend_opco.filter((r) => r.opco === opco).map((r) => ({ date: r.date, total: r.total }))

    const byApp = new Map<string, { app: string; findings: number; kev: number }>()
    for (const a of s.uc3.apps) {
      if (!all && a.opco !== opco) continue
      const row = byApp.get(a.software_name) ?? { app: a.app, findings: 0, kev: 0 }
      row.findings += a.findings
      row.kev = Math.max(row.kev, a.kev) // same CVEs on every VM: never add them twice
      byApp.set(a.software_name, row)
    }
    const apps = [...byApp.values()].sort((a, b) => b.findings - a.findings)
    const deviceOpco = new Map(s.devices.map((d) => [d.name, d.opco]))
    return {
      opco,
      totals,
      trend,
      apps,
      kevApps: apps.filter((a) => a.kev > 0).sort((a, b) => b.kev - a.kev),
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
type Section = 'summary' | WorkTab | 'agents'
const SECTIONS: [Section, string][] = [['summary', 'Summary'], ['fixes', 'Priority remediations'], ['threats', 'Threats'], ['devices', 'Devices'], ['agents', 'Agents']]
const SECTION_TARGET: Record<Section, string> = { summary: 'top', fixes: 'work', threats: 'work', devices: 'work', agents: 'pipelines' }

function HomeView({ s }: { s: Summary }) {
  const v = useView(s)
  const { setWorkTab } = useFilters()
  const [section, setSection] = useState<Section>('summary')
  const attack = useAttackHealth()
  const goTo = (t: Section) => {
    setSection(t)
    if (t === 'fixes' || t === 'threats' || t === 'devices') setWorkTab(t)
    document.getElementById(SECTION_TARGET[t])?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }
  return (
    <div className="flex flex-col gap-5">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Security overview</h1>
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

      <div id="work" className="grid scroll-mt-32 grid-cols-1 gap-5 xl:grid-cols-3">
        <WorkPanel s={s} v={v} />
        <RankingPanel s={s} v={v} />
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
        {h.name}: data as of {dateTime(h.data_as_of)}{h.quality ? ` · quality ${h.quality}` : ''}
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
        <h3 className="flex items-center gap-1.5 text-sm">Priority 1 findings <InfoTip text="Share of all findings that are highest priority: critical severity, or a vulnerability with a known exploit. The chip shows the count." /></h3>
        <Chip>{num(v.totals.p1)}</Chip>
      </div>
      <div className="mt-2 text-[34px] font-normal leading-none tracking-tight tabular">{pct.toFixed(1)}%</div>
      <div className="mt-auto pt-7">
        <div className="relative">
          <div className="mb-2 text-center text-xs text-ink-3">Priority 2–4</div>
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
        <h3 className="flex items-center gap-1.5 text-sm">Problems fixed <InfoTip text="Vulnerabilities Defender no longer reports on managed devices, counted since tracking began. The ring shows remediated against still open." /></h3>
        <Chip>{num(open)} still open</Chip>
      </div>
      <div className="mt-2 flex flex-1 items-end justify-between gap-4">
        <div className="flex min-w-0 flex-col">
          <div className="text-[34px] leading-none tracking-tight tabular" style={{ color: fixed ? statusColor.good : undefined }}>{num(fixed)}</div>
          {/* the start date needs the portal's newer summary; without it, show the count alone */}
          {(fixedSince || !fixed) && <div className="mt-2 text-xs text-ink-3">{fixed ? `since ${shortDate(fixedSince!)}` : 'nothing fixed yet'}</div>}
          <ul className="mt-4 flex flex-col gap-1.5 text-xs text-ink-2">
            <li className="flex items-center gap-1.5"><span className="size-1.5 rounded-full" style={{ background: statusColor.good }} />{pct}% of everything found is fixed</li>
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
                data: [{ name: 'Fixed', value: fixed, itemStyle: { color: statusColor.good } },
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
        <h3 className="flex items-center gap-1.5 text-sm">Open vulnerabilities <InfoTip text="Every vulnerability Defender reports, counted once per application per device. The line shows each daily snapshot." /></h3>
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

/* ───────────────────────── main work panel ───────────────────────── */

function WorkPanel({ s, v }: { s: Summary; v: View }) {
  const { workTab, setWorkTab } = useFilters()
  const [layout, setLayout] = useState<'list' | 'grid'>('list')
  return (
    <Panel className="min-w-0 p-6 xl:col-span-2">
      <div className="flex items-end gap-3">
        <div className="min-w-0 flex-1 overflow-x-auto">
          <Tabs<WorkTab>
            value={workTab}
            onChange={setWorkTab}
            tabs={[['fixes', `Priority remediations · ${v.fixes.length}`], ['threats', `Applicable threats · ${v.threats.length}`], ['devices', `Affected devices · ${v.devices.length}`]]}
          />
        </div>
        <div className="mb-2 flex shrink-0 rounded-lg bg-well p-0.5" role="group" aria-label="Layout">
          {([['list', List], ['grid', LayoutGrid]] as const).map(([id, Icon]) => (
            <button
              key={id}
              aria-label={`${id} view`}
              aria-pressed={layout === id}
              onClick={() => setLayout(id)}
              className={cn('grid size-7 place-items-center rounded-md text-ink-3', layout === id && 'bg-blue text-white')}
            >
              <Icon className="size-3.5" />
            </button>
          ))}
        </div>
      </div>
      <div className="mt-4">
        {workTab === 'fixes' && <FixesView s={s} v={v} layout={layout} />}
        {workTab === 'threats' && <ThreatsView v={v} layout={layout} />}
        {workTab === 'devices' && <DevicesView v={v} layout={layout} />}
      </div>
    </Panel>
  )
}


function UrgencyTag({ urgency }: { urgency: string }) {
  return <span className="whitespace-nowrap text-ink-2">{urgency.split(':')[0]}</span>
}

function CopyButton({ text }: { text: string }) {
  const [done, setDone] = useState(false)
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <button
          className="grid size-7 shrink-0 place-items-center rounded-md text-ink-3 hover:bg-well hover:text-ink"
          aria-label="Copy the update command"
          onClick={() => {
            navigator.clipboard?.writeText(text)
            setDone(true)
            setTimeout(() => setDone(false), 1400)
          }}
        >
          {done ? <CheckCircle2 className="size-3.5" style={{ color: statusColor.good }} /> : <Copy className="size-3.5" />}
        </button>
      </TooltipTrigger>
      <TooltipContent className="font-mono text-xs">{done ? 'Copied' : text}</TooltipContent>
    </Tooltip>
  )
}

/** App fixes open their card in Fix; security settings (no installed version) open the Security settings tab. */
const fixHref = (f: { app: string; installed_versions: string | null }) =>
  f.installed_versions ? `/fixes?app=${encodeURIComponent(f.app)}` : `/fixes/settings?q=${encodeURIComponent(f.app)}`

function FixesView({ s, v, layout }: { s: Summary; v: View; layout: 'list' | 'grid' }) {
  if (!v.fixes.length) return <Empty text="No remediations required for this filter." />
  if (layout === 'grid')
    return (
      <div className="grid gap-3 sm:grid-cols-2">
        {v.fixes.map((f) => (
          <div key={f.rank} className="rounded-xl border border-hairline p-4">
            <div className="flex items-start justify-between gap-3">
              <div>
                <div className="font-medium">{f.app}</div>
                <div className="text-xs text-ink-3">{f.installed_versions}</div>
              </div>
              <span className="tabular text-xs text-ink-3">#{f.rank}</span>
            </div>
            <div className="mt-3 flex items-center justify-between text-sm">
              <UrgencyTag urgency={f.urgency} />
              <span className="tabular text-ink-2">{num(f.cves)} CVEs</span>
            </div>
            <div className="mt-3 flex items-center gap-2 border-t border-hairline pt-3 text-sm text-ink-2">
              <span className="flex-1">{f.fix_action}</span>
              {f.command && <CopyButton text={f.command} />}
                <Link to={fixHref(f)} title="Open in Remediation" className="inline-flex shrink-0 items-center gap-1 rounded-md bg-blue/15 px-2 py-1 text-[11px] font-semibold text-sky transition-colors hover:bg-blue/25"><Zap className="size-3" /> Remediate</Link>
            </div>
          </div>
        ))}
      </div>
    )
  return (
    <>
      <Table head={[['#', 'left'], ['App', 'left'], ['Urgency', 'left'], ['CVEs', 'right'], ['Remediation', 'left']]}>
        {v.fixes.map((f) => (
          <tr key={f.rank} className="hover:bg-well/60">
            <td className="tabular w-10 text-ink-3">{f.rank}</td>
            <td>
              <div className="font-medium leading-snug [text-wrap:pretty]">{f.app}</div>
              <div className="max-w-[170px] truncate text-xs text-ink-3" title={f.installed_versions ?? undefined}>
                {f.devices} device{f.devices === 1 ? '' : 's'} · {f.installed_versions ?? 'security setting'}
              </div>
            </td>
            <td><UrgencyTag urgency={f.urgency} /></td>
            <td className="tabular text-right">{num(f.cves)}</td>
            <td className="min-w-[180px]">
              <div className="flex flex-col items-start gap-1.5 text-ink-2">
                <span className="leading-snug [text-wrap:pretty]">{f.fix_action}</span>
                <div className="flex items-center gap-1">
                {f.command && <CopyButton text={f.command} />}
                <Link to={fixHref(f)} title="Open in Remediation" className="inline-flex shrink-0 items-center gap-1 rounded-md bg-blue/15 px-2 py-1 text-[11px] font-semibold text-sky transition-colors hover:bg-blue/25"><Zap className="size-3" /> Remediate</Link>
                </div>
              </div>
            </td>
          </tr>
        ))}
      </Table>
      {s.uc3.ai_fixes?.model && (
        <p className="mt-3 text-xs text-ink-3">Remediation guidance generated by the agent and validated against Defender data. Review before acting.</p>
      )}
    </>
  )
}

function ThreatsView({ v, layout }: { v: View; layout: 'list' | 'grid' }) {
  if (!v.threats.length) return <Empty text="No applicable threats for this VM." />
  const title = (t: string) => t.replace(/^(Actively exploited|CISA alert): /, '')
  if (layout === 'grid')
    return (
      <div className="grid gap-3 sm:grid-cols-2">
        {v.threats.map((t) => (
          <div key={t.id} className="rounded-xl border border-hairline p-4">
            <div className="flex items-start justify-between gap-3">
              <Link to={threatHref(t.id)} className="text-sm font-medium leading-snug hover:underline">{title(t.title)}</Link>
              <span className="tabular rounded-md bg-well px-2 py-0.5 text-xs font-semibold">{t.score}</span>
            </div>
            <p className="mt-2 line-clamp-3 text-xs text-ink-3">{t.summary}</p>
          </div>
        ))}
      </div>
    )
  return (
    <Table head={[['Score', 'left'], ['Threat', 'left'], ['Source', 'left'], ['Devices exposed', 'left'], ['Action', 'left']]}>
      {v.threats.map((t) => (
        <tr key={t.id} className="hover:bg-well/60">
          <td className="tabular w-16 font-semibold">{t.score}</td>
          <td className="max-w-[300px]">
            <Link to={threatHref(t.id)} className="font-medium leading-snug hover:underline">{title(t.title)}</Link>
            <div className="mt-1 flex flex-wrap gap-1">
              {(t.chips ?? []).slice(1, 4).map((c) => <span key={c} className="rounded bg-well px-1.5 py-0.5 text-[11px] text-ink-2">{c}</span>)}
            </div>
          </td>
          <td className="whitespace-nowrap text-ink-2">
            {t.url ? (
              <a href={t.url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 underline-offset-4 hover:underline">
                {t.source} <ExternalLink className="size-3" />
              </a>
            ) : t.source}
          </td>
          <td className="text-ink-2">{t.devices}</td>
          <td className="max-w-[220px] text-ink-2">{t.action}</td>
        </tr>
      ))}
    </Table>
  )
}

function DevicesView({ v, layout }: { v: View; layout: 'list' | 'grid' }) {
  const { includeTests } = useFilters()
  if (!v.devices.length) return <Empty text="No affected devices for this filter." />
  const seen = (d?: string) => (d ? dateTime(d.replace(' ', 'T') + 'Z') : '–')
  if (layout === 'grid')
    return (
      <div className="grid gap-3 sm:grid-cols-2">
        {v.devices.map((d) => (
          <div key={d.name} className="rounded-xl border border-hairline p-4">
            <div className="font-medium">{d.name}</div>
            <div className="text-xs text-ink-3">last seen {seen(d.last_seen)}</div>
            <div className="mt-3 grid grid-cols-3 text-sm">
              <div><div className="tabular font-medium">{num(d.findings)}</div><div className="text-xs text-ink-3">findings</div></div>
              <div><div className="tabular font-medium">{num(d.p1)}</div><div className="text-xs text-ink-3">priority 1</div></div>
              <div><div className="tabular font-medium">{num(d.threats_exposed)}</div><div className="text-xs text-ink-3">threats</div></div>
            </div>
          </div>
        ))}
      </div>
    )
  return (
    <Table head={[['Device', 'left'], ['Findings', 'right'], ['Priority 1', 'right'], ['Threats exposed', 'right'], ['Hunt matches', 'right'], ['Last seen', 'left']]}>
      {v.devices.map((d) => (
        <tr key={d.name} className="hover:bg-well/60">
          <td className="font-medium">{d.name}</td>
          <td className="tabular text-right">{num(d.findings)}</td>
          <td className="tabular text-right">{num(d.p1)}</td>
          <td className="tabular text-right">{num(d.threats_exposed)}</td>
          <td className="tabular text-right">
            {num(d.hunt_hits)}
            {d.test_hits && includeTests ? <span className="text-ink-3"> (+{d.test_hits} test)</span> : null}
          </td>
          <td className="whitespace-nowrap text-ink-3">{seen(d.last_seen)}</td>
        </tr>
      ))}
    </Table>
  )
}


/* ───────────────────────── ranking panel ───────────────────────── */

const SEVERITIES = ['Critical', 'High', 'Medium', 'Low'] as const

function RankingPanel({ s, v }: { s: Summary; v: View }) {
  const [tab, setTab] = useState<'apps' | 'opco'>('apps')
  const { theme } = useTheme()
  const t = chartTokens[theme]
  const top = v.apps.slice(0, 14)
  const max = top[0]?.findings ?? 1
  const opcos = s.uc3.opco_totals
  const opcoMax = Math.max(...opcos.map((o) => o.findings), 1)
  return (
    <Panel className="p-6">
      <Tabs value={tab} onChange={setTab} tabs={[['apps', 'By app'], ['opco', 'By VM']]} />
      {tab === 'apps' ? (
        <>
          <h3 className="mt-5 font-semibold">Where the findings sit</h3>
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
        </>
      ) : (
        <>
          <h3 className="mt-5 font-semibold">Findings by VM</h3>
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
        </>
      )}
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
        <Stat value={num(u.affecting)} label="affect our devices" />
        <Stat value={num(u.urgent)} label="urgent, remediate first" />
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
        <Stat value={num(h?.vulnerabilities ?? h?.rows)} label="vulnerabilities in Defender" />
        <Stat value={`${Math.round((h?.coverage ?? 0) * 100)}%`} label="coverage, nothing missing" />
        <Stat value={num(s.uc3.totals.cves)} label="different CVEs" />
      </div>
      <div>
        <div className="flex items-center justify-between">
          <h4 className="text-sm font-medium">Data quality checks</h4>
          <span className="text-xs text-ink-3">{passed} of {q.length} passed · quality {h?.quality ?? '–'}</span>
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
        <Stat value={num(hits.length)} label={`found by agent hunts${computers ? `, on ${computers} computer${computers === 1 ? '' : 's'}` : ''}`} />
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
