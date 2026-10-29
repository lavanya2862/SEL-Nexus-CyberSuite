import { useEffect, useMemo, useRef, useState } from 'react'
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { ArrowUpRight, Bug, CalendarX2, Download, Search, SlidersHorizontal, Zap } from 'lucide-react'
import { Chart, axisStyle } from '@/components/Chart'
import { Empty, Panel, SevTag, Tabs, Tag } from '@/components/kit'
import { dateTime, num, shortDate } from '@/lib/format'
import { chartTokens, inkOn, statusColor, useTheme } from '@/lib/theme'
import { cn } from '@/lib/utils'
import {
  BUCKETS, addDays, daysBetween, downloadCsv, findingHref, findingKey, groupBy, nearEos, pastEos, pretty, sumBy, useGroupAfter, useUc3Data, useUc3View,
  type Finding, type Uc3Data, type Uc3View,
} from '@/lib/uc3'
import { Card, DTable, Uc3Header, Uc3Loading, legendStyle, sevStack } from './common'
import { DataQuality } from './DataQuality'

type Tab = 'overview' | 'all' | 'age' | 'trends' | 'computers' | 'quality'
const TABS: [Tab, string][] = [
  ['overview', 'Overview'], ['all', 'All vulnerabilities'], ['age', 'Age & SLA'], ['trends', 'Trends'], ['computers', 'Devices'], ['quality', 'Data quality'],
]
const OLD_TABS: Record<string, Tab> = { opco: 'computers', devices: 'computers', risks: 'all' }   // old addresses still land somewhere

export function Vulnerabilities() {
  const { tab: param } = useParams()
  const raw = OLD_TABS[param ?? ''] ?? param
  const tab = (TABS.some(([t]) => t === raw) ? raw : 'overview') as Tab
  const navigate = useNavigate()
  const { data, error, isLoading } = useUc3Data()
  const view = useUc3View(data)
  if (isLoading || error || !data) return <Uc3Loading error={error} />
  return (
    <div className="flex flex-col gap-5">
      <Uc3Header
        title="Vulnerability management"
        description="Vulnerabilities, security misconfigurations and unsupported software reported by Microsoft Defender"
        data={data}
        view={view}
        actions={
          <button
            onClick={() => downloadCsv(view.rows, String(data.meta.snapshot), view.opco)}
            className="flex items-center gap-2 rounded-full border border-hairline bg-panel px-3.5 py-1.5 text-xs font-medium hover:bg-well"
          >
            <Download className="size-3.5" /> Export {num(view.rows.length)} software vulnerabilities (CSV)
          </button>
        }
      />
      <Tabs<Tab> tabs={TABS} value={tab} onChange={(t) => navigate(t === 'overview' ? '/uc3' : `/uc3/${t}`)} />
      {tab === 'overview' && <Overview data={data} v={view} />}
      {tab === 'all' && <AllVulns key={param} v={view} top={param === 'risks'} snap={String(data.meta.snapshot)} />}
      {tab === 'age' && <AgeSla data={data} v={view} />}
      {tab === 'trends' && <Trends data={data} v={view} />}
      {tab === 'computers' && <Computers data={data} v={view} />}
      {tab === 'quality' && <DataQuality data={data} />}
    </div>
  )
}

/* ───────── overview ───────── */

function useCountUp(to: number) {
  const [n, setN] = useState(0)
  const from = useRef(0)
  useEffect(() => {
    const start = from.current
    const t0 = performance.now()
    let raf = 0
    const step = (t: number) => {
      const p = Math.min(1, (t - t0) / 700)
      setN(Math.round(start + (to - start) * (1 - Math.pow(1 - p, 3))))
      if (p < 1) raf = requestAnimationFrame(step)
      else from.current = to
    }
    raf = requestAnimationFrame(step)
    return () => cancelAnimationFrame(raf)
  }, [to])
  return n
}

type Hue = 'blue' | 'red' | 'orange' | 'green' | 'violet'
/** A count card in a solid colour that matches what it counts (white text on every colour). */
function Kpi({ label, value, hint, hue }: { label: string; value: number; hint: string; hue: Hue }) {
  const n = useCountUp(value)
  return (
    <Panel className={cn('card-hero px-4 py-4', hue !== 'blue' && `card-hero-${hue}`)}>
      <div className="flex items-center gap-1.5 text-xs text-ink-2"><span className="size-1.5 shrink-0 rounded-full bg-white" aria-hidden />{label}</div>
      <div className="tabular mt-1 text-[28px] leading-none tracking-tight">{num(n)}</div>
      <div className="mt-1.5 text-xs leading-snug text-ink-3">{hint}</div>
    </Panel>
  )
}

function Overview({ data, v }: { data: Uc3Data; v: Uc3View }) {
  const rows = v.rows
  const crit = rows.filter((f) => f.sev === 'Critical').length
  const onboarded = data.devices.filter((d) => v.keepOpco(d.opco)).length
  const latest = data.changes.filter((c) => v.keepOpco(c[1]) && (c[3] === 'None' || v.sevs.has(c[3] as never)))
  const lastDay = latest.map((c) => c[0]).sort().at(-1)
  const changeCount = (st: string) => sumBy(latest.filter((c) => c[0] === lastDay && c[2] === st), (c) => c[4])

  return (
    <div className="flex flex-col gap-5">
      <RunFound data={data} v={v} />

      <div className="card-row gap-4 [--card-min:150px]">
        <Kpi hue="blue" label="Open findings" value={rows.length} hint="device × app × CVE" />
        <Kpi label="Critical" value={crit} hint={`${rows.length ? Math.round((crit / rows.length) * 100) : 0}% of findings`} hue="red" />
        <Kpi label="P1 · Remediate first" value={rows.filter((f) => f.pr === 'P1').length} hint="Critical, or High with an exploit" hue="orange" />
        <Kpi label="Devices affected" value={new Set(rows.map((f) => f.d)).size} hint={`of ${onboarded} onboarded`} hue="green" />
        <Kpi label="Apps to update" value={new Set(rows.map((f) => f.u)).size} hint="app versions with findings" hue="violet" />
      </div>

      <div className="grid grid-cols-1 gap-5 xl:grid-cols-12">
        <Card className="xl:col-span-7" title="Risk concentration by application" description="Box size = findings per app · darker = bigger share of Critical/High">
          {rows.length ? (
            <Chart
              height={330}
              build={(tk) => {
                const data2 = Object.entries(groupBy(rows, (f) => f.sw)).map(([sw, fs]) => {
                  const share = fs.filter((f) => f.sev === 'Critical' || f.sev === 'High').length / fs.length
                  const idx = Math.min(4, Math.floor(share * 5))
                  return { name: pretty(sw), value: fs.length, share, itemStyle: { color: tk.seq[idx] }, label: { color: inkOn(tk.seq[idx]) } }
                })
                return {
                  tooltip: { formatter: (p: { name: string; value: number; data: { share: number } }) => `<b>${p.name}</b><br>${num(p.value)} findings<br>${Math.round(p.data.share * 100)}% Critical/High` },
                  series: [{
                    type: 'treemap', data: data2, roam: false, nodeClick: false, breadcrumb: { show: false }, left: 0, right: 0, top: 0, bottom: 0,
                    itemStyle: { borderColor: tk.surface, borderWidth: 2, gapWidth: 2, borderRadius: 6 },
                    label: { show: true, formatter: (p: { name: string; value: number }) => `{n|${p.name}}\n${num(p.value)}`, fontSize: 11.5, rich: { n: { fontWeight: 600, fontSize: 12.5 } } },
                    upperLabel: { show: false },
                  }],
                }
              }}
            />
          ) : <Empty text="No findings for this filter." />}
        </Card>
        <div className="flex flex-col gap-5 xl:col-span-5">
        <Card title="Severity distribution (CVSS)" description="Findings per CVSS score band (0 = none, 10 = critical)">
          <Chart
            height={170}
            build={(tk) => {
              const bins = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
              return {
                grid: { left: 4, right: 8, top: 12, bottom: 4, containLabel: true },
                tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' }, formatter: (p: { name: string; value: number }[]) => `CVSS ${p[0].name}–${Number(p[0].name) + 0.9}<br><b>${num(p[0].value)}</b> findings` },
                xAxis: { type: 'category', data: bins.map(String), ...axisStyle(tk), splitLine: { show: false } },
                yAxis: { type: 'value', ...axisStyle(tk), axisLine: { show: false } },
                series: [{
                  type: 'bar', barWidth: '62%',
                  data: bins.map((b) => ({ value: rows.filter((f) => Math.min(9, Math.floor(f.cvss ?? 0)) === b).length, itemStyle: { color: b >= 9 ? tk.severity.Critical : b >= 7 ? tk.severity.High : b >= 4 ? tk.severity.Medium : tk.severity.Low } })),
                  itemStyle: { borderRadius: [4, 4, 0, 0] },
                }],
              }
            }}
          />
        </Card>
          <DefenderChanges data={data} fallback={(st) => changeCount(st)} fallbackDay={lastDay} />

        </div>
      </div>

    </div>
  )
}

/* ───────── what Defender itself changed since the last run (its own change list, downloaded with the full list) ───────── */

function DefenderChanges({ data, fallback, fallbackDay }: { data: Uc3Data; fallback: (st: string) => number; fallbackDay?: string }) {
  const { theme } = useTheme()
  const t = chartTokens[theme]
  const dl = data.download
  const c = dl?.counts ?? {}
  const known = dl && c.new !== undefined   // older data: no per-run counts, so fall back to the events of the last day
  const stale = known && c.defender_refreshed === false
  const count = (st: 'New' | 'Fixed' | 'Updated') => (known ? (stale ? 0 : c[st.toLowerCase() as 'new'] ?? 0) : fallback(st))
  const when = dl?.started_at ? dateTime(dl.started_at) : null
  return (
    <Card
      title="What Defender changed since the last run"
      description={known
        ? `From Defender’s own change list, downloaded ${when ?? shortDate(dl!.run_date)} · already applied to every page`
        : fallbackDay ? `Changes Defender recorded on ${shortDate(fallbackDay)}` : 'No change events yet'}
    >
      <div className="grid grid-cols-3 gap-3">
        {([['New', 'newly reported on managed devices', t.severity.High], ['Fixed', 'no longer reported on managed devices', statusColor.good], ['Updated', 'details changed (e.g. severity)', 'var(--sky)']] as const).map(([st, l, col]) => (
          <div key={st} className="rounded-xl bg-well p-4">
            <div className="tabular text-2xl leading-none" style={{ color: st === 'Fixed' && count(st) ? col : undefined }}>{num(count(st))}</div>
            <div className="mt-2 flex items-center gap-1.5 text-xs text-ink-3"><span className="size-1.5 rounded-full" style={{ background: col }} />{st === 'Fixed' ? 'Remediated' : st}</div>
            <div className="text-[11px] leading-snug text-ink-3">{l}</div>
          </div>
        ))}
      </div>
      <p className="mt-3 text-xs leading-relaxed text-ink-3">
        {stale ? <><b className="text-ink-2">No changes:</b> Defender has not refreshed its data since the last run. </>
          : known && !count('New') && !count('Fixed') && !count('Updated') ? <><b className="text-ink-2">No changes</b> in Defender since the last run. </> : null}
        {c.export_reused && <>Full list not downloaded again: Defender has not rebuilt it since the last run, so that copy was reused. </>}
        {known && 'Counts are for all devices and severities.'} The Trends tab shows every day.
      </p>
    </Card>
  )
}

/* ───────── what one Defender run brings in: three kinds of weakness, each fixed differently ───────── */

function RunFound({ data, v }: { data: Uc3Data; v: Uc3View }) {
  const inOpco = (opcos: string[]) => opcos.some(v.keepOpco)
  const apps = (data.fixes?.apps ?? []).filter((a) => inOpco(a.opcos))
  const settings = (data.fixes?.settings ?? []).filter((s) => inOpco(s.opcos))
  const ended = apps.filter((a) => pastEos(a).length).length
  const ending = apps.filter((a) => !pastEos(a).length && nearEos(a).length).length
  const noPatch = v.rows.filter((f) => f.ua === 0).length
  const tiles = [
    {
      icon: Bug, to: '/fixes', value: v.rows.length, label: 'Software vulnerabilities',
      text: `Known vulnerabilities in ${num(new Set(v.rows.map((f) => f.u)).size)} software versions. Remediated by updating the application or Windows.`,
      extra: noPatch ? `${num(noPatch)} have no security update available` : null,
    },
    {
      icon: SlidersHorizontal, to: '/fixes/settings', value: settings.length, label: 'Misconfigurations',
      text: 'Windows and Defender settings below Microsoft’s recommended baseline. Remediated by changing the setting.',
      extra: null,
    },
    {
      icon: CalendarX2, to: '/fixes?type=upgrade', value: ended + ending, label: 'Unsupported software',
      text: `${num(ended)} past end of support${ending ? `, ${num(ending)} ending soon` : ''}. No further security updates: upgrade or uninstall.`,
      extra: null,
    },
  ]
  return (
    <Panel className="p-5">
      <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
        <h2 className="font-semibold tracking-tight">What the last Defender run found</h2>
        <span className="text-xs text-ink-3">Three categories of finding, each remediated differently and counted separately</span>
      </div>
      <div className="mt-4 grid grid-cols-1 gap-3 md:grid-cols-3">
        {tiles.map((t) => (
          <Link key={t.label} to={t.to} className="group flex flex-col gap-1.5 rounded-xl bg-well p-4 transition-colors hover:bg-[color-mix(in_oklab,var(--well)_70%,var(--ink)_6%)]">
            <div className="flex items-center gap-2 text-xs font-medium text-ink-2">
              <t.icon className="size-3.5 text-ink-3" aria-hidden />{t.label}
              <ArrowUpRight className="ml-auto size-3.5 text-ink-3 opacity-0 transition-opacity group-hover:opacity-100" aria-hidden />
            </div>
            <div className="tabular text-[26px] leading-none tracking-tight">{data.fixes || t.to === '/fixes' ? num(t.value) : '–'}</div>
            <p className="text-xs leading-snug text-ink-3">{t.text}</p>
            {t.extra && <p className="text-xs font-medium" style={{ color: statusColor.warning }}>{t.extra}</p>}
          </Link>
        ))}
      </div>
    </Panel>
  )
}

/* ───────── all vulnerabilities: every finding, one row each ───────── */

const PRIO_ORDER: Record<string, number> = { P1: 1, P2: 2, P3: 3, P4: 4 }

/** Top risks: Priority 1 */
const isTopRisk = (f: Finding) => f.pr === 'P1'

/** "Added" = the day Defender first saw the finding; the quick picks count back from the data's own date, not today. */
const ADDED_PICKS: [number, string][] = [[0, 'Any time'], [1, 'Latest run'], [7, 'Last 7 days'], [30, 'Last 30 days']]

function AllVulns({ v, top: topAtStart, snap }: { v: Uc3View; top: boolean; snap: string }) {
  const navigate = useNavigate()
  const groupAfter = useGroupAfter()
  const [params] = useSearchParams()
  const [q, setQ] = useState(params.get('q') ?? '')   // ?q= comes from "Vulnerabilities" links on Threats and Fix
  const [top, setTop] = useState(topAtStart)
  const [limit, setLimit] = useState(100)
  const [from, setFrom] = useState('')
  const [to, setTo] = useState('')
  const sorted = useMemo(
    () => [...v.rows].sort((a, b) => (PRIO_ORDER[a.pr] ?? 9) - (PRIO_ORDER[b.pr] ?? 9) || (b.cvss ?? 0) - (a.cvss ?? 0) || b.age - a.age),
    [v.rows],
  )
  const firstDay = useMemo(() => v.all.map((f) => f.fs).filter(Boolean).sort()[0] ?? '', [v.all])
  const dated = useMemo(() => sorted.filter((f) => (!from || f.fs >= from) && (!to || f.fs <= to)), [sorted, from, to])
  const topCount = useMemo(() => dated.filter(isTopRisk).length, [dated])
  const ql = q.trim().toLowerCase()
  const shown = dated.filter((f) => (!top || isTopRisk(f))
    && (!ql || [f.cve, f.sw, pretty(f.sw), f.ver, f.dev?.name, f.o].some((s) => (s ?? '').toLowerCase().includes(ql))))
  const pick = (days: number) => { setFrom(days ? addDays(snap, 1 - days) : ''); setTo(''); setLimit(100) }
  const picked = (days: number) => !to && from === (days ? addDays(snap, 1 - days) : '')
  return (
    <Card
      title={top ? 'Top risks' : 'All vulnerabilities'}
      description={top
        ? 'P1 findings. Sorted by priority. Select a row for details.'
        : 'Every vulnerability Defender found: one row per vulnerability, app version and device. Sorted by priority. Select a row for details.'}
      action={
        <div className="flex flex-wrap items-center gap-2">
          <div className="flex items-center gap-1.5 text-xs">
            {([[false, 'All', dated.length], [true, 'Top risks', topCount]] as const).map(([on, label, n]) => (
              <button key={label} onClick={() => { setTop(on); setLimit(100) }} aria-pressed={top === on}
                className={cn('flex items-center gap-2 rounded-full border px-3 py-1', top === on ? 'pill-on' : 'border-hairline bg-panel hover:bg-well')}>
                {label} <span className="tabular opacity-60">{num(n)}</span>
              </button>
            ))}
          </div>
          <label className="flex items-center gap-2 rounded-lg border border-hairline-strong bg-field px-3 py-1.5 text-sm transition-[border-color,box-shadow] focus-within:border-blue/60 focus-within:ring-3 focus-within:ring-blue/15">
            <Search className="size-3.5 text-ink-3" />
            <input value={q} onChange={(e) => { setQ(e.target.value); setLimit(100) }} placeholder="CVE, app or device" className="w-44 bg-transparent outline-none placeholder:text-ink-3" />
          </label>
        </div>
      }
    >
      <div className="mb-3 flex flex-wrap items-center gap-2 text-xs">
        <span className="font-medium text-ink-2">Added</span>
        {ADDED_PICKS.map(([days, label]) => (
          <button key={label} onClick={() => pick(days)} aria-pressed={picked(days)}
            className={cn('rounded-full border px-3 py-1', picked(days) ? 'pill-on' : 'border-hairline bg-panel hover:bg-well')}>
            {label}
          </button>
        ))}
        <label className="ml-1 flex items-center gap-1.5 text-ink-3">
          from
          <input type="date" value={from} min={firstDay} max={to || snap} onChange={(e) => { setFrom(e.target.value); setLimit(100) }}
            className="tabular rounded-lg border border-hairline-strong bg-field px-2 py-1 text-ink outline-none focus:border-blue/60" />
        </label>
        <label className="flex items-center gap-1.5 text-ink-3">
          to
          <input type="date" value={to} min={from || firstDay} max={snap} onChange={(e) => { setTo(e.target.value); setLimit(100) }}
            className="tabular rounded-lg border border-hairline-strong bg-field px-2 py-1 text-ink outline-none focus:border-blue/60" />
        </label>
      </div>
      {shown.length ? (
        <>
          <DTable head={[['Vulnerability'], ['App'], ['Device'], ['Severity'], ['Priority'], ['Added'], ['Days open', 'right'], ['Deadline']]} minWidth={980} maxHeight={640}>
            {shown.slice(0, limit).map((f) => (
              <tr key={findingKey(f)} onClick={() => navigate(findingHref(f))} className="cursor-pointer hover:bg-well/60">
                <td className="tabular whitespace-nowrap font-medium">{f.cve}</td>
                <td className="max-w-[220px] truncate" title={`${pretty(f.sw)} ${f.ver}`}>{pretty(f.sw)} <span className="text-ink-3">{f.ver}</span></td>
                <td className="whitespace-nowrap">{f.dev?.name}<span className="text-xs text-ink-3">{groupAfter(f)}</span></td>
                <td><SevTag sev={f.sev} /></td>
                <td>{f.pr}</td>
                <td className="tabular whitespace-nowrap text-ink-2" title={f.fs}>{f.fs ? shortDate(f.fs) : '–'}</td>
                <td className="tabular text-right">{f.age}</td>
                <td>{f.br ? <Tag tone="bad">overdue</Tag> : <span className="text-ink-3">on time</span>}</td>
              </tr>
            ))}
          </DTable>
          <div className="mt-3 flex items-center justify-between text-xs text-ink-3">
            <span>Showing {num(Math.min(limit, shown.length))} of {num(shown.length)} vulnerabilities</span>
            {limit < shown.length && <button onClick={() => setLimit(limit + 200)} className="rounded-lg border border-hairline px-3 py-1.5 font-medium text-ink hover:bg-well">Show 200 more</button>}
          </div>
        </>
      ) : <Empty text="No vulnerabilities match." />}
    </Card>
  )
}

/* ───────── age & SLA ───────── */

function AgeSla({ data, v }: { data: Uc3Data; v: Uc3View }) {
  const { theme } = useTheme()
  const t = chartTokens[theme]
  const navigate = useNavigate()
  const rows = v.rows
  const sla = data.meta.sla
  const snap = String(data.meta.snapshot)
  const breached = rows.filter((f) => f.br).length
  const old = rows.filter((f) => f.sev === 'Critical' || f.sev === 'High').sort((a, b) => b.age - a.age).slice(0, 20)
  return (
    <div className="grid grid-cols-1 gap-5 xl:grid-cols-12">
      <Card className="xl:col-span-8" title="How long have findings been open?" description="Days since Defender first saw each finding, by severity">
        <Chart
          height={300}
          build={(tk) => ({
            legend: legendStyle(tk),
            grid: { left: 4, right: 16, top: 30, bottom: 4, containLabel: true },
            tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
            xAxis: { type: 'category', data: BUCKETS.map((b) => `${b} days`), ...axisStyle(tk), splitLine: { show: false } },
            yAxis: { type: 'value', ...axisStyle(tk), axisLine: { show: false } },
            series: sevStack(tk, v.activeSevs, [...BUCKETS], (b, s) => rows.filter((f) => f.bk === b && f.sev === s).length, false),
          })}
        />
      </Card>
      <Card className="xl:col-span-4" title="Within SLA vs breached" description={`${num(breached)} of ${num(rows.length)} findings are past their due date`}>
        <Chart
          height={270}
          build={(tk) => ({
            tooltip: { trigger: 'item', formatter: (p: { name: string; value: number; percent: number }) => `${p.name}<br><b>${num(p.value)}</b> (${p.percent}%)` },
            legend: { bottom: 0, left: 'center', icon: 'roundRect', itemWidth: 10, itemHeight: 10, textStyle: { color: tk.ink2, fontSize: 11.5 } },
            series: [{
              type: 'pie', radius: ['56%', '80%'], center: ['50%', '45%'], padAngle: 2, itemStyle: { borderRadius: 4 },
              label: { show: true, position: 'center', fontSize: 22, fontWeight: 600, color: tk.ink, formatter: () => (rows.length ? `${Math.round((breached / rows.length) * 100)}%\nbreached` : '–') },
              data: [
                { name: 'Within SLA', value: rows.length - breached, itemStyle: { color: tk.series[1] } },
                { name: 'Breached', value: breached, itemStyle: { color: tk.severity.High } },
              ],
            }],
          })}
        />
      </Card>
      <Card className="xl:col-span-6" title="SLA by severity" description="Remediation SLA in days (set by the SLA policy) and what is due next">
        <DTable head={[['Severity'], ['Remediation SLA (days)', 'right'], ['Open', 'right'], ['Breached', 'right'], ['Next due']]} minWidth={480}>
          {v.activeSevs.map((s) => {
            const fs = rows.filter((f) => f.sev === s)
            const open = fs.filter((f) => !f.br)
            const next = open.length && sla[s] != null ? open.map((f) => addDays(f.fs, sla[s])).sort()[0] : null // unrated: no deadline yet
            return (
              <tr key={s}>
                <td><SevTag sev={s} /></td>
                <td className="tabular text-right">{sla[s] != null ? `${sla[s]} days` : '–'}</td>
                <td className="tabular text-right">{num(fs.length)}</td>
                <td className="tabular text-right" style={{ color: fs.length - open.length ? t.severity.High : undefined }}>{num(fs.length - open.length)}</td>
                <td className="tabular whitespace-nowrap text-ink-2">{next ? `${shortDate(next)} (in ${daysBetween(snap, next)} days)` : '–'}</td>
              </tr>
            )
          })}
        </DTable>
      </Card>
      <Card className="xl:col-span-6" title="Oldest Critical and High findings" description="Highest-priority remediation targets">
        {old.length ? (
          <DTable head={[['Device'], ['App'], ['CVE'], ['Severity'], ['Age', 'right'], ['SLA']]} minWidth={520} maxHeight={330}>
            {old.map((f, i) => (
              <tr key={i} onClick={() => navigate(findingHref(f))} className="cursor-pointer hover:bg-well/60">
                <td className="whitespace-nowrap">{f.dev?.name}</td>
                <td className="max-w-[150px] truncate" title={pretty(f.sw) + ' ' + f.ver}>{pretty(f.sw)} {f.ver}</td>
                <td className="tabular whitespace-nowrap">{f.cve}</td>
                <td><SevTag sev={f.sev} /></td>
                <td className="tabular text-right">{f.age} d</td>
                <td>{f.br ? <Tag tone="bad">breached</Tag> : <span className="text-ink-3">within</span>}</td>
              </tr>
            ))}
          </DTable>
        ) : <Empty text="No Critical or High findings for this filter." />}
      </Card>
    </div>
  )
}

/* ───────── trends ───────── */

function Trends({ data, v }: { data: Uc3Data; v: Uc3View }) {
  const daily = data.daily.filter((r) => v.keepOpco(r[1]) && v.sevs.has(r[2] as never))
  const dates = [...new Set(data.daily.map((r) => String(r[0])))].sort()
  const ch = data.changes.filter((c) => v.keepOpco(c[1]) && (c[3] === 'None' || v.sevs.has(c[3] as never)))
  const days = [...new Set(ch.map((c) => String(c[0])))].sort()
  const rem = data.remed.filter((r) => v.keepOpco(r[1]) && v.sevs.has(r[2] as never))
  return (
    <div className="grid grid-cols-1 gap-5 xl:grid-cols-12">
      <Card
        className="xl:col-span-12"
        title="Open findings over time"
        description={dates.length > 1 ? `${dates.length} daily snapshots from ${shortDate(dates[0])} to ${shortDate(dates.at(-1)!)}` : 'History builds up with each daily run'}
      >
        <Chart
          height={300}
          build={(tk) => ({
            legend: legendStyle(tk),
            grid: { left: 4, right: 16, top: 30, bottom: 4, containLabel: true },
            tooltip: { trigger: 'axis' },
            xAxis: { type: 'category', boundaryGap: false, data: dates.map(shortDate), ...axisStyle(tk), splitLine: { show: false } },
            yAxis: { type: 'value', ...axisStyle(tk), axisLine: { show: false } },
            series: [...v.activeSevs].reverse().map((s) => ({
              name: s, type: 'line', stack: 't', smooth: true, symbol: 'circle', symbolSize: 6, areaStyle: { opacity: 0.85 },
              lineStyle: { width: 1.5, color: (tk.severity as Record<string, string>)[s] }, itemStyle: { color: (tk.severity as Record<string, string>)[s] },
              data: dates.map((d) => sumBy(daily.filter((r) => String(r[0]) === d && r[2] === s), (r) => r[4])),
            })),
          })}
        />
      </Card>
      <Card className="xl:col-span-8" title="New vs remediated" description="Change events from Defender's delta feed, per day">
        {days.length ? (
          <Chart
            height={280}
            build={(tk) => ({
              legend: legendStyle(tk),
              grid: { left: 4, right: 16, top: 30, bottom: 4, containLabel: true },
              tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
              xAxis: { type: 'category', data: days.map(shortDate), ...axisStyle(tk), splitLine: { show: false } },
              yAxis: { type: 'value', ...axisStyle(tk), axisLine: { show: false } },
              series: ([['New', tk.severity.High], ['Fixed', statusColor.good], ['Updated', tk.series[1]]] as const).map(([st, col]) => ({
                name: st === 'Fixed' ? 'Remediated' : st, type: 'bar', barMaxWidth: 26, itemStyle: { color: col, borderRadius: [4, 4, 0, 0] },
                data: days.map((d) => sumBy(ch.filter((c) => String(c[0]) === d && c[2] === st), (c) => c[4])),
              })),
            })}
          />
        ) : <Empty text="No change events yet." />}
      </Card>
      <Card className="xl:col-span-4" title="Mean time to remediate" description="Average days from first seen to remediated">
        <DTable head={[['Severity'], ['Remediated', 'right'], ['MTTR (days)', 'right']]} minWidth={300}>
          {v.activeSevs.map((s) => {
            const r = rem.filter((x) => x[2] === s)
            return (
              <tr key={s}>
                <td><SevTag sev={s} /></td>
                <td className="tabular text-right">{num(r.length)}</td>
                <td className="tabular text-right">{r.length ? (sumBy(r, (x) => x[3]) / r.length).toFixed(1) : '–'}</td>
              </tr>
            )
          })}
        </DTable>
        {rem.length < 20 && <p className="mt-3 text-xs leading-relaxed text-ink-3">Not enough remediation history yet. This metric fills in as remediations are verified.</p>}
      </Card>
    </div>
  )
}

/* ───────── computers ───────── */

function Computers({ data, v }: { data: Uc3Data; v: Uc3View }) {
  const [q, setQ] = useState('')
  const [sel, setSel] = useState<number | null>(null)
  const devs = data.devices.map((d, i) => ({ d, i })).filter(({ d }) => v.keepOpco(d.opco) && (!q || (d.name || '').toLowerCase().includes(q.toLowerCase())))
  const current = sel ?? devs[0]?.i ?? null
  const dev = current != null ? data.devices[current] : null
  const fs: Finding[] = dev ? v.rows.filter((f) => f.d === current) : []
  const bySw = Object.entries(groupBy(fs, (f) => pretty(f.sw))).map(([k, x]) => ({ k, fs: x, t: x.length })).sort((a, b) => a.t - b.t)
  const upd = Object.entries(groupBy(fs, (f) => f.u))
    .map(([u, x]) => ({ u, sw: x[0].sw, t: x.length, c: x.filter((f) => f.sev === 'Critical').length }))
    .sort((a, b) => b.t - a.t)
  return (
    <div className="grid grid-cols-1 gap-5 xl:grid-cols-12">
      <Card
        className="xl:col-span-12"
        title="Devices"
        description="Select a device to view its vulnerabilities and required updates"
        action={
          <label className="flex items-center gap-2 rounded-lg border border-hairline-strong bg-field px-3 py-1.5 text-sm transition-[border-color,box-shadow] focus-within:border-blue/60 focus-within:ring-3 focus-within:ring-blue/15">
            <Search className="size-3.5 text-ink-3" />
            <input value={q} onChange={(e) => { setQ(e.target.value); setSel(null) }} placeholder="Device name" className="w-36 bg-transparent outline-none placeholder:text-ink-3" />
          </label>
        }
      >
        {devs.length ? (
          <DTable head={[['Device'], ['Operating system'], ['Vulnerabilities', 'right'], ['Critical', 'right'], ['P1', 'right'], ['Overdue', 'right'], ['Last seen']]} minWidth={900}>
            {devs.map(({ d, i }) => {
              const x = v.rows.filter((f) => f.d === i)
              return (
                <tr key={d.id} onClick={() => setSel(i)} className={cn('cursor-pointer hover:bg-well/60', current === i && 'bg-well shadow-[inset_3px_0_0_var(--sky)]')}>
                  <td className="whitespace-nowrap"><span className="font-medium">{d.name}</span> {d.stale && <Tag>stale</Tag>}</td>
                  <td className="whitespace-nowrap text-ink-2">{[d.os, d.osv].filter(Boolean).join(' ')}</td>
                  <td className="tabular text-right">{num(x.length)}</td>
                  <td className="tabular text-right">{num(x.filter((f) => f.sev === 'Critical').length)}</td>
                  <td className="tabular text-right">{num(x.filter((f) => f.pr === 'P1').length)}</td>
                  <td className="tabular text-right">{num(x.filter((f) => f.br).length)}</td>
                  <td className="tabular whitespace-nowrap text-ink-3">{d.last_seen ?? '–'}</td>
                </tr>
              )
            })}
          </DTable>
        ) : <Empty text="No devices match." />}
      </Card>
      <Card className="xl:col-span-7" title={dev ? `Vulnerabilities by app on ${dev.name}` : 'Vulnerabilities by app'} description={dev ? `${num(fs.length)} vulnerabilities` : 'Select a device above'}>
        {bySw.length ? (
          <Chart
            height={Math.max(280, bySw.length * 26 + 40)}
            build={(tk) => ({
              legend: legendStyle(tk),
              grid: { left: 8, right: 48, top: 28, bottom: 4, containLabel: true },
              tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
              xAxis: { type: 'value', ...axisStyle(tk), axisLine: { show: false } },
              yAxis: { type: 'category', data: bySw.map((r) => r.k), ...axisStyle(tk), splitLine: { show: false }, axisLabel: { color: tk.ink2, fontSize: 11.5 } },
              series: sevStack(tk, v.activeSevs, bySw, (r, s) => r.fs.filter((f) => f.sev === s).length, true, bySw.map((r) => r.t)),
            })}
          />
        ) : <Empty text="No vulnerabilities for this device and filter." />}
      </Card>
      <Card className="xl:col-span-5" title="Updates required on this device" description="In order of impact">
        {upd.length ? (
          <DTable head={[['#', 'right'], ['Update'], ['Clears', 'right'], ['Critical', 'right'], ['']]} minWidth={340} maxHeight={Math.max(280, bySw.length * 26 + 40)}>
            {upd.map((r, i) => (
              <tr key={r.u}>
                <td className="tabular text-right text-ink-3">{i + 1}</td>
                <td>{r.u}</td>
                <td className="tabular text-right">{num(r.t)}</td>
                <td className="tabular text-right">{num(r.c)}</td>
                <td><Link to={`/fixes?sw=${encodeURIComponent(r.sw)}`} title="Open in Remediation" className="inline-flex shrink-0 items-center gap-1 rounded-md bg-blue/15 px-2 py-1 text-[11px] font-semibold text-sky transition-colors hover:bg-blue/25"><Zap className="size-3" /> Remediate</Link></td>
              </tr>
            ))}
          </DTable>
        ) : <Empty text="No updates required." />}
      </Card>
    </div>
  )
}
