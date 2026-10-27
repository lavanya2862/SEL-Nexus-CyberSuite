import { useMemo, useState, type ReactNode } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import {
  AlertTriangle, ArrowDownRight, ArrowUpRight, CheckCircle2, Clock, Copy, ExternalLink, HelpCircle, LayoutGrid, List,
  Play, ShieldAlert, XCircle,
} from 'lucide-react'
import ReactECharts from 'echarts-for-react'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { fetchSummary, type Health, type Summary } from '@/lib/api'
import { useFilters, type WorkTab } from '@/lib/filters'
import { ago, dateTime, num, shortDate } from '@/lib/format'
import { cn } from '@/lib/utils'
import { shortApp, useView, type View } from '@/pages/Home'
import { glassTip } from './GlassShell'

const barName = (app: string) => shortApp(app).replace('Visual Studio Code', 'VS Code').replace('Zoom Workplace', 'Zoom').replace('Thunderbird', 'Thunderbird').replace('Git for Windows', 'Git')

// Validated series order on the warm dark surface: ember, sky, emerald, violet, amber, rose.
const SERIES = ['#e8662a', '#3d8fe8', '#1fae7c', '#9085e9', '#c98500', '#d55181']
const STATUS = { good: '#3ee6a6', warning: '#fab219', serious: '#ec835a', critical: '#ff5a4f' }

export function GlassHome() {
  const { data, error, isLoading } = useQuery({ queryKey: ['summary'], queryFn: fetchSummary, refetchInterval: 30_000 })
  if (isLoading) return <div className="glass-panel h-80 animate-pulse" />
  if (error || !data)
    return (
      <div className="glass-panel p-6">
        <h2 className="font-semibold">The portal API is not answering</h2>
        <p className="mt-1 text-sm text-[var(--g-ink-3)]">{String(error ?? 'No data')}. Start it with `python -m portal serve`, then reload.</p>
      </div>
    )
  return <GlassView s={data} />
}

function GlassView({ s }: { s: Summary }) {
  const v = useView(s)
  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-end justify-between gap-4 px-1 pt-2">
        <div>
          <h1 className="text-[26px] font-semibold tracking-tight">Security overview</h1>
          <p className="mt-1 text-sm text-[var(--g-ink-3)]">
            {v.opco === 'all' ? 'All VMs' : v.opco} · Defender vulnerabilities  and threat intelligence 
          </p>
        </div>
        <div className="flex flex-wrap gap-2">{s.health.map((h) => <HealthPill key={h.key} h={h} />)}</div>
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <div className="grid grid-cols-1 gap-4 md:grid-cols-8 xl:col-span-8">
          <HeroChart s={s} />
          <EmberCta v={v} />
          <AppBars v={v} />
        </div>
        <ExposureColumn v={v} />
      </div>

      <div id="work" className="scroll-mt-40">
        <WorkPanel s={s} v={v} />
      </div>

      <div id="pipelines" className="grid scroll-mt-40 grid-cols-1 gap-4 lg:grid-cols-2">
        <Uc1Panel s={s} />
        <Uc3Panel s={s} />
      </div>
    </div>
  )
}

/* ───────── shared bits ───────── */

function Card({ className, children }: { className?: string; children: ReactNode }) {
  return <section className={cn('glass-panel p-5 md:p-6', className)}>{children}</section>
}

function Seg<T extends string>({ items, value, onChange, small }: { items: [T, ReactNode][]; value: T; onChange: (v: T) => void; small?: boolean }) {
  return (
    <div className="flex shrink-0 gap-1 rounded-full border border-[var(--g-line)] bg-white/[0.03] p-1" role="tablist">
      {items.map(([id, label]) => (
        <button
          key={id}
          role="tab"
          aria-selected={value === id}
          data-active={value === id}
          onClick={() => onChange(id)}
          className={cn('glass-seg flex items-center gap-1.5 rounded-full text-[var(--g-ink-3)] hover:text-[var(--g-ink)]', small ? 'px-3 py-1 text-xs' : 'px-3.5 py-1.5 text-sm')}
        >
          {label}
        </button>
      ))}
    </div>
  )
}

const HEALTH = {
  ok: { icon: CheckCircle2, color: STATUS.good, label: 'Up to date' },
  stale: { icon: Clock, color: STATUS.warning, label: 'Out of date' },
  error: { icon: XCircle, color: STATUS.critical, label: 'Last run failed' },
  missing: { icon: HelpCircle, color: STATUS.serious, label: 'No data yet' },
} as const

function HealthPill({ h }: { h: Health }) {
  const st = HEALTH[h.status]
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span className="glass-panel flex items-center gap-2 rounded-full py-1.5 pl-2.5 pr-3.5 text-xs">
          <st.icon className="size-3.5" style={{ color: st.color }} />
          <span className="font-semibold">{h.key.toUpperCase()}</span>
          <span className="text-[var(--g-ink-3)]">{st.label} · {ago(h.data_as_of)}</span>
        </span>
      </TooltipTrigger>
      <TooltipContent className={glassTip}>{h.name}: data as of {dateTime(h.data_as_of)}{h.quality ? ` · quality ${h.quality}` : ''}</TooltipContent>
    </Tooltip>
  )
}

function Delta({ value, suffix = '' }: { value: number; suffix?: string }) {
  const up = value >= 0
  return (
    <span className="tabular inline-flex items-center gap-0.5 text-sm font-medium" style={{ color: up ? 'var(--g-ember-hi)' : STATUS.good }}>
      {up ? <ArrowUpRight className="size-3.5" /> : <ArrowDownRight className="size-3.5" />}
      {num(Math.abs(value))}{suffix}
    </span>
  )
}

/* ───────── hero: threat intelligence area chart ───────── */

function HeroChart({ s }: { s: Summary }) {
  const [range, setRange] = useState<'15' | '7'>('15')
  const { days, series } = s.uc1.threat_trend
  const totals = days.map((_, i) => Object.values(series).reduce((a, arr) => a + (arr[i] ?? 0), 0))
  const n = Number(range)
  const shownDays = days.slice(-n)
  const shown = totals.slice(-n)
  const sum = shown.reduce((a, b) => a + b, 0)
  const prev = totals.slice(-2 * n, -n).reduce((a, b) => a + b, 0)
  const peak = shown.indexOf(Math.max(...shown))
  return (
    <Card className="md:col-span-8">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h3 className="text-sm text-[var(--g-ink-2)]">Threat intelligence collected</h3>
          <div className="mt-1 flex items-baseline gap-3">
            <span className="tabular text-[34px] font-medium leading-none tracking-tight">{num(sum)}</span>
            {range === '7' && prev > 0 ? <Delta value={sum - prev} suffix=" vs prior 7 days" /> : (
              <span className="text-sm text-[var(--g-ink-3)]">items in {n} days · {num(s.uc1.totals.new_threats)} in 30</span>
            )}
          </div>
        </div>
        <Seg items={[['15', '15 days'], ['7', '7 days']]} value={range} onChange={setRange} />
      </div>
      <ReactECharts
        style={{ height: 230 }}
        opts={{ renderer: 'svg' }}
        notMerge
        option={{
          backgroundColor: 'transparent',
          grid: { left: 4, right: 44, top: 46, bottom: 24 },
          tooltip: {
            trigger: 'axis',
            backgroundColor: 'rgba(29,20,15,0.92)',
            borderColor: 'rgba(255,236,222,0.16)',
            textStyle: { color: '#f6efe9', fontSize: 12 },
            axisPointer: { type: 'line', lineStyle: { color: 'rgba(255,236,222,0.25)', type: 'dashed' } },
            extraCssText: 'border-radius:12px;backdrop-filter:blur(12px);box-shadow:0 12px 30px rgba(0,0,0,.5)',
          },
          xAxis: {
            type: 'category', boundaryGap: false, data: shownDays.map(shortDate),
            axisLine: { show: false }, axisTick: { show: false }, axisLabel: { color: '#9a8b80', fontSize: 11 },
          },
          yAxis: {
            type: 'value', position: 'right', splitNumber: 4,
            axisLabel: { color: '#9a8b80', fontSize: 11 }, splitLine: { lineStyle: { color: 'rgba(255,236,222,0.06)' } },
          },
          series: [{
            name: 'Items collected', type: 'line', smooth: 0.35, symbol: 'circle', symbolSize: 6, showSymbol: false,
            data: shown,
            lineStyle: { width: 2, color: '#ff8a3d', shadowBlur: 14, shadowColor: 'rgba(255,138,61,0.55)' },
            itemStyle: { color: '#fff', borderColor: '#ff8a3d', borderWidth: 2 },
            areaStyle: {
              color: { type: 'linear', x: 0, y: 0, x2: 0, y2: 1, colorStops: [
                { offset: 0, color: 'rgba(232,102,42,0.55)' }, { offset: 1, color: 'rgba(232,102,42,0)' },
              ] },
            },
            markPoint: {
              symbol: 'circle', symbolSize: 10,
              itemStyle: { color: '#fff', borderColor: '#ff8a3d', borderWidth: 3, shadowBlur: 16, shadowColor: '#ff8a3d' },
              label: {
                show: true, position: 'top', distance: 10, color: '#1b0d06', fontSize: 12, fontWeight: 600, lineHeight: 16,
                backgroundColor: 'rgba(255,246,240,0.95)', borderRadius: 10, padding: [6, 10],
                formatter: () => `${shortDate(shownDays[peak])} · ${num(shown[peak])} items`,
              },
              data: [{ coord: [peak, shown[peak]] }],
            },
          }],
        }}
      />
      <div className="mt-1 flex flex-wrap gap-x-6 gap-y-1 text-xs text-[var(--g-ink-3)]">
        <span>Average a day <b className="tabular font-medium text-[var(--g-ink)]">{num(Math.round(sum / n))}</b></span>
        <span>Peak day <b className="font-medium text-[var(--g-ink)]">{shortDate(shownDays[peak])}</b></span>
        <span>Sources <b className="font-medium text-[var(--g-ink)]">{s.uc1.feeds.ok}/{s.uc1.feeds.total} feeds healthy</b></span>
      </div>
    </Card>
  )
}

/* ───────── ember call to action with radar ───────── */

function Radar() {
  return (
    <svg viewBox="0 0 200 200" className="pointer-events-none absolute -bottom-16 -right-14 size-64 opacity-80" aria-hidden>
      <defs>
        <radialGradient id="g-sweep" cx="50%" cy="50%" r="50%">
          <stop offset="0%" stopColor="rgba(255,230,210,0.0)" />
          <stop offset="100%" stopColor="rgba(255,230,210,0.35)" />
        </radialGradient>
      </defs>
      {[30, 55, 80, 98].map((r) => <circle key={r} cx="100" cy="100" r={r} fill="none" stroke="rgba(255,230,210,0.22)" strokeWidth="1" />)}
      <line x1="2" y1="100" x2="198" y2="100" stroke="rgba(255,230,210,0.14)" />
      <line x1="100" y1="2" x2="100" y2="198" stroke="rgba(255,230,210,0.14)" />
      <g className="glass-sweep">
        <path d="M100 100 L100 2 A98 98 0 0 1 184 50 Z" fill="url(#g-sweep)" />
      </g>
      <circle cx="146" cy="62" r="3.5" fill="#fff" />
      <circle cx="70" cy="132" r="2.5" fill="rgba(255,255,255,0.8)" />
    </svg>
  )
}

function EmberCta({ v }: { v: View }) {
  const { setWorkTab } = useFilters()
  const kevFixes = v.fixes.filter((f) => f.kev_cves > 0)
  const go = () => {
    setWorkTab('fixes')
    document.getElementById('work')?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }
  return (
    <section className="glass-ember relative overflow-hidden rounded-[22px] p-6 text-[#1b0d06] md:col-span-3">
      <Radar />
      <div className="relative flex h-full flex-col">
        <h3 className="text-[22px] font-semibold leading-tight tracking-tight">
          {kevFixes.length} updates fix every exploited vulnerability
        </h3>
        <p className="mt-2 max-w-[24ch] text-sm text-[#2b1309]/80">
          Attackers are known to use these flaws (CISA KEV list). Updating the apps below takes the list to zero.
        </p>
        <div className="mt-4 flex -space-x-2">
          {kevFixes.slice(0, 4).map((f) => (
            <span key={f.rank} title={f.app} className="grid size-8 place-items-center rounded-full border-2 border-[#f07a32] bg-[#2a120a] text-[11px] font-semibold text-[#ffd9c2]">
              {shortApp(f.app).slice(0, 2)}
            </span>
          ))}
          {kevFixes.length > 4 && (
            <span className="grid size-8 place-items-center rounded-full border-2 border-[#f07a32] bg-[#ffe9dc] text-[11px] font-semibold">+{kevFixes.length - 4}</span>
          )}
        </div>
        <div className="flex-1" />
        <button onClick={go} className="mt-6 w-full rounded-full bg-[#fff6f0] py-3 text-sm font-semibold text-[#1b0d06] shadow-[0_8px_20px_-8px_rgba(0,0,0,.5)] hover:bg-white">
          Show the fixes
        </button>
      </div>
    </section>
  )
}

/* ───────── selectable app bars ───────── */

function AppBars({ v }: { v: View }) {
  const [metric, setMetric] = useState<'findings' | 'kev'>('findings')
  const rows = useMemo(
    () => [...v.apps].filter((a) => (metric === 'kev' ? a.kev > 0 : true)).sort((a, b) => b[metric] - a[metric]).slice(0, 6),
    [v.apps, metric],
  )
  const [sel, setSel] = useState(0)
  const max = Math.max(...rows.map((r) => r[metric]), 1)
  const pick = Math.min(sel, rows.length - 1)
  return (
    <Card className="md:col-span-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h3 className="text-sm text-[var(--g-ink-2)]">Where the risk sits</h3>
          <div className="mt-1 flex items-baseline gap-2">
            <span className="tabular text-[26px] font-medium leading-none tracking-tight">{rows[pick] ? num(rows[pick][metric]) : '–'}</span>
            <span className="text-sm text-[var(--g-ink-3)]">{rows[pick] ? `${metric === 'kev' ? 'exploited vulnerabilities' : 'findings'} in ${shortApp(rows[pick].app)}` : ''}</span>
          </div>
        </div>
        <Seg small items={[['findings', 'Findings'], ['kev', 'Exploited']]} value={metric} onChange={(m) => { setMetric(m); setSel(0) }} />
      </div>
      <div className="mt-6 flex h-[190px] items-end gap-2.5">
        {rows.map((r, i) => {
          const h = Math.max(10, (r[metric] / max) * 100)
          const on = i === pick
          return (
            <button key={r.app} onClick={() => setSel(i)} className="group flex h-full flex-1 flex-col items-center justify-end gap-2" aria-pressed={on} aria-label={`${r.app}: ${r[metric]}`}>
              <span
                className={cn('tabular rounded-full px-2 py-0.5 text-[11px] font-semibold', on ? 'bg-[var(--g-emerald-hi)] text-[#04120c] shadow-[0_0_16px_rgba(62,230,166,.6)]' : 'text-[var(--g-ink-2)]')}
              >
                {num(r[metric])}
              </span>
              <span
                className={cn('w-full rounded-t-xl transition-all duration-300', on ? 'glass-glow-emerald' : 'bg-gradient-to-b from-white/[0.12] to-white/[0.02] group-hover:from-white/[0.18]')}
                style={{ height: `${h}%` }}
              />
            </button>
          )
        })}
      </div>
      <div className="mt-2 flex gap-2.5">
        {rows.map((r, i) => (
          <span key={r.app} className={cn('flex-1 truncate text-center text-[11px]', i === pick ? 'text-[var(--g-ink)]' : 'text-[var(--g-ink-3)]')}>{barName(r.app)}</span>
        ))}
      </div>
    </Card>
  )
}

/* ───────── right column: exploited stack + top threats ───────── */

function ExposureColumn({ v }: { v: View }) {
  const { setWorkTab } = useFilters()
  const back = v.kevApps.slice(0, 3)
  const goTab = (t: WorkTab) => {
    setWorkTab(t)
    document.getElementById('work')?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }
  const cve = (t: string) => t.match(/CVE-\d{4}-\d+/)?.[0] ?? t
  const what = (t: string) => (t.match(/\(([^)]+)\)/)?.[1] ?? '').replace(/ Vulnerability$/, '')
  return (
    <section className="glass-panel flex flex-col gap-5 p-5 md:p-6 xl:col-span-4">
      <div className="flex items-center justify-between">
        <h3 className="text-base font-medium">Known exploited</h3>
        <span className="rounded-full border border-[var(--g-line)] px-3 py-1 text-xs text-[var(--g-ink-3)]">CISA KEV</span>
      </div>

      {/* card stack: the apps behind the number */}
      <div className="relative pt-[78px]">
        {back.map((a, i) => (
          <div
            key={a.app}
            className="absolute inset-x-0 flex items-center justify-between rounded-2xl border border-[var(--g-line)] px-4 pt-2.5 text-xs backdrop-blur"
            style={{
              top: i * 26, height: 64, marginInline: (2 - i) * 14 + 6,
              background: `linear-gradient(180deg, rgba(255,${190 - i * 30},${140 - i * 30},${0.22 + i * 0.06}), rgba(60,30,18,0.6))`,
              zIndex: i,
            }}
          >
            <span className="self-start font-medium text-[var(--g-ink-2)]">{shortApp(a.app)}</span>
            <span className="tabular self-start text-[var(--g-ink-3)]">{a.kev} exploited</span>
          </div>
        ))}
        <div className="relative z-10 overflow-hidden rounded-2xl border border-[var(--g-line-2)] p-5 shadow-[0_20px_40px_-20px_rgba(0,0,0,.8)]"
          style={{ background: 'radial-gradient(120% 120% at 100% 0%, rgba(232,102,42,0.35), transparent 55%), linear-gradient(160deg, #2b1a12, #140c08)' }}>
          <div className="flex items-start justify-between">
            <span className="text-lg font-bold italic tracking-wide text-[var(--g-ink)]">KEV</span>
            <span className="grid size-10 place-items-center rounded-lg border border-[var(--g-line-2)] bg-white/10">
              <ShieldAlert className="size-5 text-[var(--g-ember-hi)]" />
            </span>
          </div>
          <div className="mt-6 text-sm text-[var(--g-ink-3)]">Exploited vulnerabilities on our devices</div>
          <div className="mt-1 flex items-end justify-between">
            <span className="tabular text-[32px] font-medium leading-none tracking-tight">{num(v.totals.kev)}</span>
            <span className="flex items-center gap-1 rounded-md bg-[var(--g-ember)]/20 px-2 py-1 text-xs font-medium text-[var(--g-ember-hi)]">
              <AlertTriangle className="size-3" /> {v.totals.ransomware} ransomware
            </span>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-3">
        <button onClick={() => goTab('fixes')} className="flex items-center justify-center gap-2 rounded-xl border border-[var(--g-line-2)] bg-white/[0.06] py-3 text-sm font-medium hover:bg-white/10">
          <ArrowDownRight className="size-4" /> Fix plan
        </button>
        <Link to="/glass/uc3" className="glass-btn-ember flex items-center justify-center gap-2 rounded-xl py-3 text-sm font-semibold">
          <ArrowUpRight className="size-4" /> Open the assistant
        </Link>
      </div>

      <div>
        <div className="flex items-center justify-between">
          <h3 className="text-base font-medium">Top threats</h3>
          <button onClick={() => goTab('threats')} className="text-xs text-[var(--g-ink-2)] hover:text-[var(--g-ink)]">View all</button>
        </div>
        <ul className="mt-3 flex flex-col gap-2">
          {v.threats.slice(0, 4).map((t) => (
            <li key={t.id} className="flex items-center gap-3 rounded-2xl border border-[var(--g-line)] bg-white/[0.03] p-3">
              <span className="grid size-10 shrink-0 place-items-center rounded-xl border border-[var(--g-line)] bg-white/[0.06]">
                <ShieldAlert className="size-[18px] text-[var(--g-ink-2)]" />
              </span>
              <div className="min-w-0 flex-1">
                <div className="tabular truncate text-sm font-medium">{cve(t.title)}</div>
                <div className="truncate text-xs text-[var(--g-ink-3)]">{what(t.title)}</div>
              </div>
              <span className="tabular text-sm font-semibold" style={{ color: t.score >= 90 ? 'var(--g-ember-hi)' : '#e9b44c' }}>{t.score}</span>
            </li>
          ))}
          {!v.threats.length && <li className="text-sm text-[var(--g-ink-3)]">No ranked threats for this VM.</li>}
        </ul>
      </div>
    </section>
  )
}

/* ───────── work panel ───────── */

function CopyButton({ text }: { text: string }) {
  const [done, setDone] = useState(false)
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <button
          className="grid size-7 shrink-0 place-items-center rounded-lg text-[var(--g-ink-3)] hover:bg-white/10 hover:text-[var(--g-ink)]"
          aria-label="Copy the update command"
          onClick={() => { navigator.clipboard?.writeText(text); setDone(true); setTimeout(() => setDone(false), 1400) }}
        >
          {done ? <CheckCircle2 className="size-3.5" style={{ color: STATUS.good }} /> : <Copy className="size-3.5" />}
        </button>
      </TooltipTrigger>
      <TooltipContent className={cn(glassTip, 'font-mono text-xs')}>{done ? 'Copied' : text}</TooltipContent>
    </Tooltip>
  )
}

function Urgency({ kev, urgency }: { kev: number; urgency: string }) {
  if (kev > 0)
    return (
      <span className="inline-flex items-center gap-1.5 whitespace-nowrap rounded-full bg-[var(--g-ember)]/15 px-2.5 py-1 text-xs font-medium text-[var(--g-ember-hi)]">
        <AlertTriangle className="size-3" /> {kev} known exploited
      </span>
    )
  return <span className="whitespace-nowrap rounded-full border border-[var(--g-line)] px-2.5 py-1 text-xs text-[var(--g-ink-2)]">{urgency.split(':')[0]}</span>
}

function GTable({ head, children }: { head: [string, 'left' | 'right'][]; children: ReactNode }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[680px] text-sm">
        <thead>
          <tr className="text-xs text-[var(--g-ink-3)]">
            {head.map(([h, a]) => <th key={h} className={cn('border-b border-[var(--g-line)] px-4 pb-3 font-normal', a === 'right' ? 'text-right' : 'text-left')}>{h}</th>)}
          </tr>
        </thead>
        <tbody className="[&_td]:px-4 [&_td]:py-3.5 [&_tr]:border-b [&_tr]:border-[var(--g-line)] [&_tr:last-child]:border-0">{children}</tbody>
      </table>
    </div>
  )
}

function WorkPanel({ s, v }: { s: Summary; v: View }) {
  const { workTab, setWorkTab } = useFilters()
  const [layout, setLayout] = useState<'list' | 'grid'>('list')
  return (
    <Card>
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="overflow-x-auto">
          <Seg<WorkTab>
            value={workTab}
            onChange={setWorkTab}
            items={[['fixes', <>Fix first <b className="font-medium opacity-60">{v.fixes.length}</b></>], ['threats', <>Threats <b className="font-medium opacity-60">{v.threats.length}</b></>], ['devices', <>Devices <b className="font-medium opacity-60">{v.devices.length}</b></>]]}
          />
        </div>
        <Seg small value={layout} onChange={setLayout} items={[['list', <List key="l" className="size-3.5" aria-label="List view" />], ['grid', <LayoutGrid key="g" className="size-3.5" aria-label="Grid view" />]]} />
      </div>
      <div className="mt-5">
        {workTab === 'fixes' && <Fixes s={s} v={v} layout={layout} />}
        {workTab === 'threats' && <Threats v={v} layout={layout} />}
        {workTab === 'devices' && <Devices v={v} layout={layout} />}
      </div>
    </Card>
  )
}

function Tile({ children }: { children: ReactNode }) {
  return <div className="rounded-2xl border border-[var(--g-line)] bg-white/[0.03] p-4">{children}</div>
}

function Fixes({ s, v, layout }: { s: Summary; v: View; layout: 'list' | 'grid' }) {
  if (layout === 'grid')
    return (
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        {v.fixes.map((f) => (
          <Tile key={f.rank}>
            <div className="flex items-start justify-between gap-2"><div className="font-medium">{f.app}</div><span className="tabular text-xs text-[var(--g-ink-3)]">#{f.rank}</span></div>
            <div className="mt-1 truncate text-xs text-[var(--g-ink-3)]">{f.installed_versions}</div>
            <div className="mt-3 flex items-center justify-between"><Urgency kev={f.kev_cves} urgency={f.urgency} /><span className="tabular text-xs text-[var(--g-ink-2)]">{num(f.cves)} CVEs</span></div>
            <div className="mt-3 flex items-center gap-2 border-t border-[var(--g-line)] pt-3 text-xs text-[var(--g-ink-2)]"><span className="flex-1">{f.fix_action}</span>{f.command && <CopyButton text={f.command} />}</div>
          </Tile>
        ))}
      </div>
    )
  return (
    <>
      <GTable head={[['#', 'left'], ['App', 'left'], ['Urgency', 'left'], ['CVEs', 'right'], ['Devices', 'right'], ['Fix', 'left']]}>
        {v.fixes.map((f) => (
          <tr key={f.rank} className="glass-row">
            <td className="tabular w-10 text-[var(--g-ink-3)]">{f.rank}</td>
            <td><div className="font-medium">{f.app}</div><div className="max-w-[220px] truncate text-xs text-[var(--g-ink-3)]">{f.installed_versions}</div></td>
            <td><Urgency kev={f.kev_cves} urgency={f.urgency} /></td>
            <td className="tabular text-right">{num(f.cves)}</td>
            <td className="tabular text-right">{f.devices}</td>
            <td><div className="flex items-center gap-1 text-[var(--g-ink-2)]"><span>{f.fix_action}</span>{f.command && <CopyButton text={f.command} />}</div></td>
          </tr>
        ))}
      </GTable>
      {s.uc3.ai_fixes?.model && <p className="mt-3 text-xs text-[var(--g-ink-3)]">Fix advice written by the AI assistant, checked against Defender data. Check before acting.</p>}
    </>
  )
}

function Threats({ v, layout }: { v: View; layout: 'list' | 'grid' }) {
  const title = (t: string) => t.replace(/^Actively exploited: /, '')
  if (layout === 'grid')
    return (
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
        {v.threats.map((t) => (
          <Tile key={t.id}>
            <div className="flex items-start justify-between gap-3"><div className="text-sm font-medium leading-snug">{title(t.title)}</div><span className="tabular font-semibold text-[var(--g-ember-hi)]">{t.score}</span></div>
            <p className="mt-2 line-clamp-3 text-xs text-[var(--g-ink-3)]">{t.summary}</p>
          </Tile>
        ))}
      </div>
    )
  return (
    <GTable head={[['Score', 'left'], ['Threat', 'left'], ['Source', 'left'], ['Devices exposed', 'left'], ['Action', 'left']]}>
      {v.threats.map((t) => (
        <tr key={t.id} className="glass-row">
          <td className="tabular w-16 font-semibold" style={{ color: t.score >= 90 ? 'var(--g-ember-hi)' : '#e9b44c' }}>{t.score}</td>
          <td className="max-w-[320px]">
            <div className="font-medium leading-snug">{title(t.title)}</div>
            <div className="mt-1.5 flex flex-wrap gap-1">{(t.chips ?? []).slice(1, 4).map((c) => <span key={c} className="rounded-full border border-[var(--g-line)] px-2 py-0.5 text-[11px] text-[var(--g-ink-2)]">{c}</span>)}</div>
          </td>
          <td className="whitespace-nowrap text-[var(--g-ink-2)]">
            {t.url ? <a href={t.url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 hover:text-[var(--g-ink)]">{t.source} <ExternalLink className="size-3" /></a> : t.source}
          </td>
          <td className="text-[var(--g-ink-2)]">{t.devices}</td>
          <td className="max-w-[240px] text-[var(--g-ink-2)]">{t.action}</td>
        </tr>
      ))}
    </GTable>
  )
}

function Devices({ v, layout }: { v: View; layout: 'list' | 'grid' }) {
  const seen = (d?: string) => (d ? dateTime(d.replace(' ', 'T') + 'Z') : '–')
  if (layout === 'grid')
    return (
      <div className="grid gap-3 sm:grid-cols-2">
        {v.devices.map((d) => (
          <Tile key={d.name}>
            <div className="font-medium">{d.name}</div>
            <div className="text-xs text-[var(--g-ink-3)]">last seen {seen(d.last_seen)}</div>
            <div className="mt-3 grid grid-cols-3 text-sm">
              {([[d.findings, 'findings'], [d.p1, 'priority 1'], [d.threats_exposed, 'threats']] as const).map(([n, l]) => (
                <div key={l}><div className="tabular font-medium">{num(n)}</div><div className="text-xs text-[var(--g-ink-3)]">{l}</div></div>
              ))}
            </div>
          </Tile>
        ))}
      </div>
    )
  return (
    <GTable head={[['Device', 'left'], ['Findings', 'right'], ['Priority 1', 'right'], ['Threats exposed', 'right'], ['Hunt hits', 'right'], ['Last seen', 'left']]}>
      {v.devices.map((d) => (
        <tr key={d.name} className="glass-row">
          <td className="font-medium">{d.name}</td>
          <td className="tabular text-right">{num(d.findings)}</td>
          <td className="tabular text-right">{num(d.p1)}</td>
          <td className="tabular text-right">{num(d.threats_exposed)}</td>
          <td className="tabular text-right">{num(d.hunt_hits)}{d.test_hits ? <span className="text-[var(--g-ink-3)]"> (+{d.test_hits} test)</span> : null}</td>
          <td className="whitespace-nowrap text-[var(--g-ink-3)]">{seen(d.last_seen)}</td>
        </tr>
      ))}
    </GTable>
  )
}

/* ───────── pipelines ───────── */

function PipeHead({ tag, tone, title, h }: { tag: string; tone: string; title: string; h?: Health }) {
  const st = HEALTH[h?.status ?? 'missing']
  return (
    <div className="flex flex-wrap items-center justify-between gap-3">
      <div className="flex items-center gap-3">
        <span className="grid size-10 place-items-center rounded-xl border border-[var(--g-line)]" style={{ background: `color-mix(in oklab, ${tone} 22%, transparent)`, boxShadow: `0 0 24px -6px ${tone}` }}>
          <span className="size-2.5 rounded-full" style={{ background: tone, boxShadow: `0 0 10px ${tone}` }} />
        </span>
        <div>
          <h3 className="text-lg font-semibold tracking-tight">{title} <span className="ml-1 text-xs font-medium text-[var(--g-ink-3)]">{tag}</span></h3>
          <div className="flex items-center gap-1.5 text-xs text-[var(--g-ink-3)]"><st.icon className="size-3.5" style={{ color: st.color }} />{st.label} · last run {ago(h?.last_run_at)}</div>
        </div>
      </div>
    </div>
  )
}

function Stat({ value, label }: { value: string; label: string }) {
  return (
    <div className="rounded-2xl border border-[var(--g-line)] bg-white/[0.03] p-3">
      <div className="tabular text-xl font-medium leading-none tracking-tight">{value}</div>
      <div className="mt-1.5 text-xs text-[var(--g-ink-3)]">{label}</div>
    </div>
  )
}

function PipeActions({ to, tag }: { to: string; tag: string }) {
  return (
    <div className="flex flex-wrap gap-2">
      <Link to={to} className="inline-flex items-center gap-2 rounded-full bg-[#fff6f0] px-5 py-2.5 text-sm font-semibold text-[#1b0d06] hover:bg-white">
        Open {tag} <ArrowUpRight className="size-4" />
      </Link>
      <Tooltip>
        <TooltipTrigger asChild>
          <span tabIndex={0}>
            <button disabled className="inline-flex items-center gap-2 rounded-full border border-[var(--g-line-2)] bg-white/[0.05] px-5 py-2.5 text-sm font-medium disabled:cursor-not-allowed disabled:opacity-60">
              <Play className="size-3.5" /> Run pipeline
            </button>
          </span>
        </TooltipTrigger>
        <TooltipContent className={glassTip}>Preview: starts the real {tag} pipeline in the next step</TooltipContent>
      </Tooltip>
    </div>
  )
}

function Uc1Panel({ s }: { s: Summary }) {
  const u = s.uc1.totals
  const { days, series } = s.uc1.threat_trend
  const names = Object.keys(series)
  return (
    <Card className="flex flex-col gap-5">
      <PipeHead tag="the assistant" tone="#9085e9" title="Threat Intel & Hunting" h={s.health.find((h) => h.key === 'uc1')} />
      <div className="grid grid-cols-3 gap-3">
        <Stat value={num(u.new_threats)} label="threats (30 days)" />
        <Stat value={num(u.affecting)} label="affect our devices" />
        <Stat value={num(u.urgent)} label="urgent, fix these first" />
      </div>
      <div>
        <div className="flex flex-wrap gap-3 text-xs text-[var(--g-ink-3)]">
          {names.map((n, i) => <span key={n} className="flex items-center gap-1.5"><span className="size-1.5 rounded-full" style={{ background: SERIES[i] }} />{n}</span>)}
        </div>
        <ReactECharts
          style={{ height: 130 }}
          opts={{ renderer: 'svg' }}
          option={{
            backgroundColor: 'transparent',
            grid: { left: 4, right: 4, top: 12, bottom: 4, containLabel: true },
            tooltip: { trigger: 'axis', backgroundColor: 'rgba(29,20,15,0.92)', borderColor: 'rgba(255,236,222,0.16)', textStyle: { color: '#f6efe9', fontSize: 12 }, axisPointer: { type: 'shadow', shadowStyle: { color: 'rgba(255,236,222,0.05)' } } },
            xAxis: { type: 'category', data: days.map(shortDate), axisLine: { show: false }, axisTick: { show: false }, axisLabel: { color: '#9a8b80', fontSize: 10, interval: 3 } },
            yAxis: { type: 'value', splitNumber: 3, axisLabel: { color: '#9a8b80', fontSize: 10 }, splitLine: { lineStyle: { color: 'rgba(255,236,222,0.06)' } } },
            series: names.map((n, i) => ({ name: n, type: 'bar', stack: 'a', barWidth: '55%', data: series[n], itemStyle: { color: SERIES[i], borderColor: '#1d1612', borderWidth: 1, borderRadius: i === names.length - 1 ? [4, 4, 0, 0] : 0 } })),
          }}
        />
      </div>
      <PipeActions to="/glass/uc1" tag="the assistant" />
    </Card>
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
    <Card className="flex flex-col gap-5">
      <PipeHead tag="the assistant" tone="#3d8fe8" title="Vulnerability Extraction" h={h} />
      <div className="grid grid-cols-3 gap-3">
        <Stat value={num(h?.rows)} label={h?.rows === h?.defender_count ? "rows = Defender's count" : `Defender: ${num(h?.defender_count)}`} />
        <Stat value={`${Math.round((h?.coverage ?? 0) * 100)}%`} label="coverage" />
        <Stat value={num(s.uc3.totals.cves)} label="different CVEs" />
      </div>
      <div>
        <div className="flex items-center justify-between text-xs text-[var(--g-ink-3)]">
          <span className="text-sm font-medium text-[var(--g-ink)]">Data quality</span>
          <span>{passed} of {q.length} passed · {h?.quality ?? '–'}</span>
        </div>
        <ul className="mt-3 grid grid-cols-1 gap-x-6 gap-y-2 text-sm sm:grid-cols-2">
          {q.slice(0, 8).map((c) => {
            const ok = c.status === 'PASS'
            const Icon = ok ? CheckCircle2 : c.status === 'INFO' ? HelpCircle : AlertTriangle
            const color = ok ? STATUS.good : c.status === 'INFO' ? 'var(--g-ink-3)' : c.status === 'WARN' ? STATUS.warning : STATUS.critical
            return (
              <Tooltip key={c.check_name}>
                <TooltipTrigger asChild>
                  <li className="flex items-center gap-2 text-[var(--g-ink-2)]"><Icon className="size-3.5 shrink-0" style={{ color }} /><span className="truncate">{label(c.check_name)}</span></li>
                </TooltipTrigger>
                <TooltipContent className={cn(glassTip, 'max-w-72')}>{c.message}</TooltipContent>
              </Tooltip>
            )
          })}
        </ul>
      </div>
      <div className="mt-auto"><PipeActions to="/glass/uc3" tag="the assistant" /></div>
    </Card>
  )
}

export function GlassSoon({ title }: { title: string }) {
  return (
    <div className="glass-panel mx-auto mt-10 max-w-xl p-8 text-center">
      <h2 className="text-lg font-semibold">{title}</h2>
      <p className="mt-1 text-sm text-[var(--g-ink-3)]">Being built in this design next.</p>
      <Link to="/glass" className="glass-btn-ember mt-5 inline-flex items-center gap-2 rounded-full px-5 py-2.5 text-sm font-semibold">Back to overview</Link>
    </div>
  )
}
