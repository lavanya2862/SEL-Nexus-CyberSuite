import { ExpandableCard } from '@/components/DetailDialog'
import { useMemo, useState } from 'react'
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { ArrowRight, ExternalLink, Fingerprint, Monitor, Radar, Rss, Siren, Zap } from 'lucide-react'
import { Chart, axisStyle } from '@/components/Chart'
import {
  Card, DTable, DateFilter, Empty, FilterBar, FilterChoice, FilterSearch, Panel, SevTag, Tabs, choiceChip, dateChip, inDateRange, legendStyle,
  type ActiveFilter, type DateRange,
} from '@/components/kit'
import { Skeleton } from '@/components/ui/skeleton'
import { num, shortDate } from '@/lib/format'
import { chartTokens, statusColor, useTheme } from '@/lib/theme'
import { cn } from '@/lib/utils'
import {
  FEED_NAME, PERIODS, RATINGS, inPeriod, isClueBundle, isSign, periodData, periodLabel, threatHref, usePeriod, useThreat, useThreatIntelClues, useThreatIntelData,
  type ExplorerRow, type Rating, type ThreatIntelData,
} from '@/agents/threat-intel/data'
import { AiChip, Resolve, ScoreBar, ThreatIntelHeader, ThreatIntelLoading } from '@/agents/threat-intel/common'
import { StoryBadge, Timeline, storyOf, useDefenderDates, type Story } from '@/agents/threat-intel/timeline'

type Tab = 'overview' | 'affects' | 'explorer' | 'health'
const TABS: [Tab, string][] = [
  ['overview', 'Overview'], ['affects', 'Applicable threats'], ['explorer', 'Explorer'], ['health', 'Health & metrics'],
]
const OLD_TABS: Record<string, Tab> = { risks: 'affects', exposure: 'affects', landscape: 'overview' }   // old addresses still land somewhere
// tabs about what we collected get the period filter; "Affects us" and health are about right now
const PERIOD_TABS: Tab[] = ['overview', 'explorer']

export function ThreatNews() {
  const { tab: param } = useParams()
  const raw = OLD_TABS[param ?? ''] ?? param
  const tab = (TABS.some(([t]) => t === raw) ? raw : 'overview') as Tab
  const navigate = useNavigate()
  const [period, setPeriod] = usePeriod()
  const { data, error, isLoading } = useThreatIntelData()
  if (isLoading || error || !data) return <ThreatIntelLoading error={error} />
  const keep = period === 'all' ? '' : `?period=${period}`   // the period follows you from tab to tab
  return (
    <div className="flex flex-col gap-5">
      <ThreatIntelHeader title="Threats" description="Threat intelligence from 10 public feeds, correlated with managed devices" data={data} />
      <div className="flex flex-wrap items-end justify-between gap-x-4 gap-y-2">
        <Tabs<Tab> tabs={TABS} value={tab} onChange={(t) => navigate((t === 'overview' ? '/threat-intel' : `/threat-intel/${t}`) + keep)} />
        {PERIOD_TABS.includes(tab) && (
          <div className="mb-2 flex items-center gap-1 rounded-lg border border-hairline bg-panel p-0.5" role="group" aria-label="Period">
            {PERIODS.map(([p, label]) => (
              <button key={p} onClick={() => setPeriod(p)} aria-pressed={period === p}
                className={cn('rounded-md px-3 py-1 text-xs font-medium transition-colors', period === p ? 'bg-blue/20 text-sky' : 'text-ink-3 hover:text-ink')}>
                {label}
              </button>
            ))}
          </div>
        )}
      </div>
      {tab === 'overview' && <Overview d={data} />}
      {tab === 'affects' && <AffectsUs d={data} />}
      {tab === 'explorer' && <Explorer d={data} />}
      {tab === 'health' && <Health d={data} />}
    </div>
  )
}

/* ───────── overview: posture, funnel, the threat landscape, our computers ───────── */

function Overview({ d }: { d: ThreatIntelData }) {
  const { theme } = useTheme()
  const t = chartTokens[theme]
  const [period] = usePeriod()
  const w = periodData(d, period)
  const when = periodLabel(w, period)
  const max = Math.max(...w.funnel.map((f) => f.value), 1)
  return (
    <div className="flex flex-col gap-5">
      <Panel className="grid gap-6 p-6 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.6fr)]">
        <div>
          <div className="text-sm text-ink-3">Our threat posture</div>
          <div className="mt-2 flex items-center gap-3">
            <span className="size-3 rounded-full" style={{ background: d.posture.rating === 'Critical' ? statusColor.critical : statusColor.warning }} />
            <span className="text-[34px] font-medium leading-none tracking-tight">{d.posture.rating}</span>
          </div>
          <p className="mt-3 max-w-md text-sm leading-relaxed text-ink-2">
            <b>{d.posture.urgent}</b> critical or high threats currently apply to managed devices.
            In total <b>{num(d.posture.affecting)}</b> threats from collected news apply to managed devices (vulnerabilities in installed software, or indicators seen on a device).
          </p>
        </div>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
          {([
            [num(w.threats_collected), 'Threats Collected', `${when}: attack news, advisories and vulnerability lists`, 'var(--tint-blue)'],
            [num(Object.values(w.ioc_types).reduce((a, b) => a + b, 0)), 'Indicators Collected', `IPs, domains, URLs, file hashes · ${when} · ${num(d.ioc_hits)} observed on managed devices`, 'var(--tint-violet)'],
            [num(d.posture.affecting), 'Applicable Threats', `${num(d.posture.vulnerabilities ?? 0)} vulnerabilities in installed software · ${num(d.posture.indicators ?? 0)} with indicators seen on a device`, 'var(--tint-red)'],
          ] as const).map(([v, l, h, tint]) => (
            <div key={l} className="tint-box rounded-xl px-3.5 py-3" style={{ '--tint': tint } as React.CSSProperties}>
              <div className="tint-num tabular text-lg font-semibold leading-none">{v}</div>
              <div className="mt-1.5 text-[13px] font-medium leading-snug text-ink-2">{l}</div>
              <div className="mt-1 text-[11px] leading-snug text-ink-3">{h}</div>
            </div>
          ))}
        </div>
      </Panel>

      <Card title="Intelligence pipeline" description={`How all intelligence collected (${when}) is reduced to a prioritised list of updates`}>
        <ol className="flex flex-col gap-3">
          {w.funnel.filter((f) => !f.stage.toLowerCase().includes('assessed')).map((f, i) => (
            <li key={f.stage} className="grid grid-cols-[minmax(0,180px)_1fr] items-center gap-4">
              <div>
                <div className="text-sm font-medium">{f.stage}</div>
                <div className="text-[11px] text-ink-3">{f.note}</div>
              </div>
              <div className="flex items-center gap-3">
                <span className="h-7 rounded-md transition-[width] duration-700" style={{ width: `${Math.max(4, (f.value / max) * 100)}%`, background: t.seq[Math.min(4, i)] }} />
                <span className="tabular text-sm font-semibold">{num(f.value)}</span>
              </div>
            </li>
          ))}
        </ol>
      </Card>
      <Landscape d={d} />
      <Card title="Managed devices" description="Agent-collected context for each device">
        <DTable head={[['Device'], ['OS'], ['Vulnerabilities', 'right'], ['Applicable threats', 'right'], ['Indicators seen', 'right'], ['Last seen by Defender']]}>
          {d.devices.map((x) => (
            <tr key={x.device_name}>
              <td className="font-medium">{x.device_name}</td>
              <td className="text-ink-2">{x.os_platform}</td>
              <td className="tabular text-right">{num(x.vulns)}</td>
              <td className="tabular text-right">{num(x.exposed)}</td>
              <td className="tabular text-right">{num(x.indicators ?? 0)}</td>
              <td className="tabular text-ink-3">{x.last_seen?.slice(0, 16)}</td>
            </tr>
          ))}
        </DTable>
      </Card>
    </div>
  )
}

/* ───────── affects us: each threat that matches our computers, with the hole, where it is and how to fix it ───────── */

type Reach = 'all' | 'defender' | 'early' | 'indicator' | 'closed'
const REACH: [Reach, string, string][] = [
  ['all', 'All', 'Everything currently applicable to managed devices'],
  ['defender', 'Confirmed by Defender', 'Threat intelligence names a vulnerability Defender also reports on a managed device'],
  ['early', 'Pending Defender confirmation', 'Threat intelligence names a vulnerability in an installed version; Defender has not reported it yet'],
  ['indicator', 'Indicators seen', 'Collected indicators (IPs, domains, URLs, file hashes) observed on a managed device'],
  ['closed', 'Not reported by Defender', 'The installed version is affected, but Defender did not report it within 30 days (often legacy, unsupported applications)'],
]
/** How a news threat reaches us. Behaviour hits (and older output's 'sign') are the Attack Detection Agent's: null here. */
const reachOf = (e: ExplorerRow): Exclude<Reach, 'all'> | null => {
  if (isSign(e.kind) || e.kind === 'test' || e.match === 'behaviour' || e.match === 'sign') return null
  return e.match !== undefined ? e.match : e.hits ? 'indicator' : e.devices ? 'defender' : null
}

function AffectsUs({ d }: { d: ThreatIntelData }) {
  const [params, setParams] = useSearchParams()
  const dd = useDefenderDates()
  // Threats shows real threats only: lab tests (harmless activity made on purpose to prove the hunts work) stay out
  const real = d.explorer.filter((e) => reachOf(e) && !e.test)
  const show = REACH.find(([r]) => r === params.get('show'))?.[0] ?? 'all'
  const sev = RATINGS.find((r) => r === params.get('sev')) ?? 'All'
  const set = (key: string, value: string | null) => setParams((prev) => {   // kept in the address, other params untouched
    const next = new URLSearchParams(prev)
    if (value === null) next.delete(key)
    else next.set(key, value)
    return next
  }, { replace: true })
  const { theme } = useTheme()
  const [published, setPublished] = useState<DateRange>({ preset: 'any' })
  const inReach = (r: Reach) => real.filter((e) => (r === 'all' ? reachOf(e) !== 'closed' : reachOf(e) === r) && inDateRange(e.published ?? e.first_seen, published))
  const all = inReach(show)
  const rows = sev === 'All' ? all : all.filter((e) => e.rating === sev)
  const reachOptions = REACH.map(([r, label]) => ({ value: r, label, count: inReach(r).length }))
  const sevOptions = (['All', ...RATINGS] as const).map((r) => ({ value: r, label: r === 'All' ? 'All severities' : r,
    count: (r === 'All' ? all : all.filter((e) => e.rating === r)).length, dot: r === 'All' ? undefined : chartTokens[theme].severity[r] }))
  const chips: ActiveFilter[] = [
    ...dateChip(published, () => setPublished({ preset: 'any' })),
    ...choiceChip('show', reachOptions, show, () => set('show', null)),
    ...choiceChip('sev', sevOptions, sev, () => set('sev', null)),
  ]
  return (
    <div className="flex flex-col gap-3">
      <FilterBar chips={chips} onClear={() => { setPublished({ preset: 'any' }); setParams((prev) => { const n = new URLSearchParams(prev); n.delete('show'); n.delete('sev'); return n }, { replace: true }) }}
        count={`${num(rows.length)} threats`}>
        <DateFilter label="Published" value={published} onChange={setPublished} />
        <FilterChoice label="Exposure" icon={Radar} options={reachOptions} value={show} onChange={(r) => set('show', r === 'all' ? null : r)} />
        <FilterChoice label="Severity" icon={Siren} options={sevOptions} value={sev} onChange={(r) => set('sev', r === 'All' ? null : r)} />
      </FilterBar>
      <p className="text-sm text-ink-3">{REACH.find(([r]) => r === show)![2]}. Highest risk first; select a card to view the vulnerability, affected devices, timeline and remediation. Ratings are rule-based.</p>
      {rows.length
        ? <ul className="grid grid-cols-1 gap-3 md:grid-cols-2 2xl:grid-cols-3">{rows.map((e) => <li key={e.id}><AffectCard e={e} story={storyOf(e, dd)} /></li>)}</ul>
        : <Empty text={show === 'early' ? 'Nothing pending Defender confirmation: every vulnerability named in threat intelligence for installed versions is already reported by Defender.' : 'No items at present.'} />}
    </div>
  )
}

function AffectCard({ e, story }: { e: ExplorerRow; story: Story | null }) {
  const devices = e.devices || [...new Set((e.on_us ?? []).map((x) => x.device))].join(', ')
  const title = e.headline || e.title.replace(/^(TEST:\s*)?Hunt hit:\s*/, '').replace(/AI-drafted:\s*/, '')
  return (
    <ExpandableCard title={title} subtitle={`On ${devices || '–'}`}
      eyebrow={<><SevTag sev={e.rating} /><span className="text-ink-3">{e.headline ? `${e.source}: ${e.title}` : e.source}</span><StoryBadge s={story} /></>}
      summary={
        <>
          <div className="flex flex-wrap items-center gap-2 text-xs">
            <SevTag sev={e.rating} />
            <ScoreBar score={e.score} width={64} />
            <StoryBadge s={story} />
          </div>
          <div className="font-semibold leading-snug">{title}</div>
          <div className="line-clamp-1 text-xs text-ink-3">{e.headline ? `${e.source}: ${e.title}` : e.source}</div>
          <div className="line-clamp-2 text-xs text-ink-3">On {devices || '–'}{e.action && <> · <span className="text-ink-2">Do: {e.action}</span></>}</div>
        </>
      }>
      <AffectDetail e={e} story={story} />
    </ExpandableCard>
  )
}

const MATCH_NOTE: Record<string, string> = {
  early: 'Pending Defender confirmation: NVD lists this installed version as affected',
  closed: 'Not reported by Defender: NVD lists this installed version as affected',
  product: 'possible match by product name',
  watchlist: 'watch-list match, not checked in Defender',
}

function AffectDetail({ e, story }: { e: ExplorerRow; story: Story | null }) {
  const { data: t, isLoading } = useThreat(e.id)
  if (isLoading) return <div className="border-t border-hairline p-5"><Skeleton className="h-32 rounded-xl" /></div>
  if (!t) return <div className="border-t border-hairline p-5 text-sm text-ink-3">The details of this threat are not available yet.</div>
  const fixApp = t.exposure.map((x) => x.detail.match(/ via (\S+) /)?.[1]).find(Boolean)
  const exposed = new Set(t.exposure.map((x) => x.detail.split(' ')[0]))
  const cves = t.cves.filter((c) => exposed.has(c.id))
  const resolution = t.findings.find((f) => f.resolution)?.resolution
  return (
    <div className="grid grid-cols-1 gap-4 border-t border-hairline p-5 xl:grid-cols-3">
      {story && <div className="xl:col-span-3"><Timeline s={story} /></div>}
      <section>
        <h3 className="flex items-center gap-2 text-sm font-semibold">What it is {t.ai_status === 'done' && <AiChip origin="ai" />}</h3>
        <p className="mt-1.5 text-sm leading-relaxed text-ink-2">{t.summary || t.text.split('\n')[0]}</p>
        {/* no chip says a hole is exploited (older data still has "Public exploit") */}
        {e.chips.some((c) => !/exploit/i.test(c)) && <div className="mt-2 flex flex-wrap gap-1">{e.chips.filter((c) => !/exploit/i.test(c)).map((c) => <span key={c} className={cn('rounded-md px-2 py-0.5 text-[11px]', /Ransomware|Hunt/.test(c) ? 'bg-signal/15 text-signal' : 'bg-well text-ink-2')}>{c}</span>)}</div>}
      </section>

      <section>
        <h3 className="text-sm font-semibold">{t.exposure.length ? 'Vulnerability on managed devices' : 'Findings on managed devices'}</h3>
        <ul className="mt-1.5 flex flex-col gap-2">
          {t.exposure.map((x, i) => (
            <li key={i} className="rounded-lg bg-well px-3 py-2 text-sm">
              <div className="font-medium">{x.device_name}</div>
              <div className="text-ink-2">{x.detail}</div>
              {x.match_type !== 'cve' && <div className="text-[11px] text-ink-3">{MATCH_NOTE[x.match_type] ?? x.match_type}</div>}
            </li>
          ))}
          {!t.exposure.length && t.findings.filter((f) => !f.is_test).map((f, i) => (
            <li key={i} className="rounded-lg bg-well px-3 py-2 text-sm">
              <div className="font-medium">{f.device}</div>
              <div className="text-ink-2">{f.detail.replace(/^AI-drafted:\s*/, '')}</div>
              <div className="text-[11px] text-ink-3">first seen {f.first_hit?.slice(0, 16)}</div>
            </li>
          ))}
        </ul>
        {cves.length > 0 && (
          <div className="mt-2 flex flex-col gap-1 text-xs text-ink-3">
            {cves.slice(0, 4).map((c) => (
              <div key={c.id}>
                <span className="tabular font-medium text-ink-2">{c.id}</span>
                {c.cvss != null && <> · CVSS {c.cvss}</>}
              </div>
            ))}
          </div>
        )}
      </section>

      <section>
        {resolution ? <Resolve r={resolution} /> : (
          <>
            <h3 className="flex items-center gap-2 text-sm font-semibold">Remediation {t.ai_status === 'done' && <AiChip origin="ai" />}</h3>
            {t.actions.length
              ? <ol className="mt-1.5 list-decimal space-y-1 pl-5 text-sm text-ink-2 marker:text-ink-3">{t.actions.map((a) => <li key={a}>{a}</li>)}</ol>
              : <p className="mt-1.5 text-sm text-ink-3">No steps available yet; they will be generated in the next Threat Intel run.</p>}
            {t.ai_status === 'done' && <p className="mt-2 text-[11px] text-ink-3">The update comes from Defender; the remaining steps are agent-generated and validated against the data.</p>}
          </>
        )}
        <div className="mt-3 flex flex-wrap gap-2">
          {fixApp && (
            <Link to={`/fixes?sw=${encodeURIComponent(fixApp)}`} title="Open in Remediation" className="inline-flex items-center gap-1 rounded-md bg-blue/15 px-2.5 py-1.5 text-xs font-semibold text-sky transition-colors hover:bg-blue/25">
              <Zap className="size-3" /> Remediate
            </Link>
          )}
          <Link to={threatHref(e.id)} className="inline-flex items-center gap-1 rounded-md border border-hairline px-2.5 py-1.5 text-xs font-medium hover:bg-well">Full details <ArrowRight className="size-3" /></Link>
        </div>
      </section>
    </div>
  )
}

/* ───────── threat landscape (part of the overview) ───────── */

function Landscape({ d }: { d: ThreatIntelData }) {
  const [period] = usePeriod()
  const w = periodData(d, period)
  const when = periodLabel(w, period)
  const names = Object.keys(w.series)
  // per source, from Threat Intel (threats, clues, affect us); older Threat Intel output: counted here from the threat list
  const sources: Record<string, { threats: number; clues: number; affect: number }> = w.sources ?? {}
  d.explorer.filter((e) => !e.test && inPeriod(w, period, e.first_seen)).forEach((e) => {
    if (w.sources || isClueBundle(e.kind)) return
    const s = (sources[e.source] ??= { threats: 0, clues: 0, affect: 0 })
    s.threats += 1
    if (e.devices || e.hits) s.affect += 1
  })
  const tactics = w.tactics.filter((x) => x.threats > 0).sort((a, b) => a.threats - b.threats)
  const { theme } = useTheme()
  // collected in the period but published before it: one "Earlier" bar, so the bars add up to everything collected
  const hasEarlier = names.some((n) => (w.earlier[n] ?? 0) > 0)
  const labels = [...(hasEarlier ? ['Earlier'] : []), ...w.days.map(shortDate)]
  const series = Object.fromEntries(names.map((n) => [n, [...(hasEarlier ? [w.earlier[n] ?? 0] : []), ...w.series[n]]]))
  const dayTotals = labels.map((_, i) => names.reduce((a, n) => a + (series[n][i] || 0), 0))
  const total = dayTotals.reduce((a, b) => a + b, 0)
  const days = dayTotals.slice(hasEarlier ? 1 : 0)
  const busiest = days.indexOf(Math.max(...days))
  return (
    <div className="grid grid-cols-1 gap-5 xl:grid-cols-12">
      <Card className="xl:col-span-8" title="Threats by day and source type">
        <div className="mb-4 flex flex-wrap gap-x-6 gap-y-3">
          <div>
            <div className="tabular text-2xl font-semibold leading-none">{num(total)}</div>
            <div className="mt-1 text-[11px] text-ink-3">threats in total</div>
          </div>
          {names.map((n, i) => (
            <div key={n}>
              <div className="tabular text-2xl font-semibold leading-none">{num(series[n].reduce((a, b) => a + b, 0))}</div>
              <div className="mt-1 flex items-center gap-1.5 text-[11px] text-ink-3">
                <span className="size-2 rounded-sm" style={{ background: chartTokens[theme].series[i] }} />{n}
              </div>
            </div>
          ))}
          {days.some((n) => n > 0) && (
            <div>
              <div className="tabular text-2xl font-semibold leading-none">{num(days[busiest])}</div>
              <div className="mt-1 text-[11px] text-ink-3">busiest day · {shortDate(w.days[busiest])}</div>
            </div>
          )}
        </div>
        <Chart
          height={300}
          build={(tk) => ({
            legend: { ...legendStyle(tk), data: names },
            grid: { left: 4, right: 8, top: 40, bottom: 4, containLabel: true },
            tooltip: {
              trigger: 'axis', axisPointer: { type: 'shadow' },
              formatter: (ps: { seriesName: string; value: number; marker: string; dataIndex: number; axisValueLabel: string }[]) => {
                const rows = ps.filter((p) => names.includes(p.seriesName) && p.value > 0)
                  .map((p) => `${p.marker}${p.seriesName}<span style="float:right;margin-left:16px"><b>${num(p.value)}</b></span>`)
                return `${ps[0].axisValueLabel}<br><b>${num(dayTotals[ps[0].dataIndex])}</b> threats${rows.length ? '<br>' + rows.join('<br>') : ''}`
              },
            },
            xAxis: { type: 'category', data: labels, ...axisStyle(tk), splitLine: { show: false } },
            yAxis: { type: 'value', ...axisStyle(tk), axisLine: { show: false } },
            series: [
              ...names.map((n, i) => ({ name: n, type: 'bar', stack: 's', barWidth: '55%', data: series[n], itemStyle: { color: tk.series[i], borderColor: tk.surface, borderWidth: 1 } })),
              // zero-height bar on top of the stack that carries each day's total as its label
              { name: 'Total', type: 'bar', stack: 's', data: dayTotals.map(() => 0), silent: true,
                label: { show: true, position: 'top', color: tk.ink, fontSize: 11, fontWeight: 600, formatter: (p: { dataIndex: number }) => (dayTotals[p.dataIndex] ? num(dayTotals[p.dataIndex]) : '') } },
            ],
          })}
        />
      </Card>
      <Card className="xl:col-span-4" title="Risk ratings" description="Threat intelligence findings classified by evaluated risk severity">
        <Chart
          height={300}
          build={(tk) => ({
            tooltip: { trigger: 'item', formatter: (p: { name: string; value: number; percent: number }) => `${p.name}<br><b>${num(p.value)}</b> (${p.percent}%)` },
            legend: { bottom: 0, left: 'center', icon: 'roundRect', itemWidth: 10, itemHeight: 10, textStyle: { color: tk.ink2, fontSize: 11.5 } },
            series: [{
              type: 'pie', radius: ['52%', '78%'], center: ['50%', '44%'], padAngle: 2, itemStyle: { borderRadius: 4 },
              label: { show: true, position: 'center', fontSize: 20, fontWeight: 600, color: tk.ink, formatter: () => `${num(RATINGS.reduce((a, r) => a + (w.ratings[r] ?? 0), 0))}\nthreats` },
              data: RATINGS.map((r) => ({ name: r, value: w.ratings[r] ?? 0, itemStyle: { color: (tk.severity as Record<string, string>)[r] } })),
            }],
          })}
        />
      </Card>
      <Card className="xl:col-span-7" title="Attacker techniques (MITRE ATT&CK tactics)" description={`Which stage of an attack the threats collected ${when} are about`}>
        {tactics.length ? (
          <Chart
            height={Math.max(220, tactics.length * 28 + 30)}
            build={(tk) => ({
              grid: { left: 8, right: 40, top: 4, bottom: 4, containLabel: true },
              tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
              xAxis: { type: 'value', ...axisStyle(tk), axisLine: { show: false } },
              yAxis: { type: 'category', data: tactics.map((x) => x.tactic), ...axisStyle(tk), splitLine: { show: false }, axisLabel: { color: tk.ink2 } },
              series: [{ type: 'bar', barMaxWidth: 16, data: tactics.map((x) => x.threats), itemStyle: { color: tk.series[3], borderRadius: [0, 4, 4, 0] }, label: { show: true, position: 'right', color: tk.ink, fontSize: 11 } }],
            })}
          />
        ) : <Empty text="No techniques recorded yet." />}
      </Card>
      <Card className="xl:col-span-5" title="Sources" description={`What each source provided ${when}: threats, indicators (counted per source) and applicable threats`}>
        <DTable head={[['Source'], ['Threats', 'right'], ['Indicators', 'right'], ['Applicable', 'right']]} minWidth={340}>
          {Object.entries(sources).sort((a, b) => b[1].threats - a[1].threats || b[1].clues - a[1].clues).map(([s, n]) => (
            <tr key={s}>
              <td>{s}</td>
              <td className="tabular text-right">{n.threats ? num(n.threats) : <span className="text-ink-3">–</span>}</td>
              <td className="tabular text-right">{n.clues ? num(n.clues) : <span className="text-ink-3">–</span>}</td>
              <td className="tabular text-right font-medium">{n.affect ? num(n.affect) : <span className="font-normal text-ink-3">0</span>}</td>
            </tr>
          ))}
        </DTable>
      </Card>
    </div>
  )
}

/* ───────── explorer: everything we collected, threats and clues kept apart ───────── */

function Explorer({ d }: { d: ThreatIntelData }) {
  const [params, setParams] = useSearchParams()
  const view = params.get('view') === 'clues' ? 'clues' : 'threats'
  const [period] = usePeriod()
  const w = periodData(d, period)
  const when = periodLabel(w, period)
  const threats = d.explorer.filter((e) => !e.test && !isClueBundle(e.kind) && inPeriod(w, period, e.first_seen))
  const clueCount = Object.values(w.ioc_types).reduce((a, b) => a + b, 0)
  const from = period === 'all' ? null : w.start.replace('T', ' ').slice(0, 16)
  const show = (v: 'threats' | 'clues') => setParams((prev) => {   // keeps ?period
    const next = new URLSearchParams(prev)
    if (v === 'threats') next.delete('view')
    else next.set('view', v)
    return next
  }, { replace: true })
  return (
    <Panel className="p-6">
      <div className="flex flex-wrap items-center gap-2">
        {([['threats', 'Threats', threats.length, 'Threat reports, advisories and vulnerability lists'],
          ['clues', 'Indicators', clueCount, 'IPs, domains, URLs and file hashes searched by hunts']] as const).map(([v, label, n, hint]) => (
          <button key={v} onClick={() => show(v)} aria-pressed={view === v} title={hint}
            className={cn('flex items-center gap-2 rounded-lg border px-3.5 py-1.5 text-sm font-medium', view === v ? 'pill-on' : 'border-hairline bg-panel hover:bg-well')}>
            {label} <span className="tabular text-xs opacity-60">{num(n)}</span>
          </button>
        ))}
        <span className="text-xs text-ink-3">{view === 'threats' ? `Threat reports, advisories and vulnerability lists (${when})` : `IPs, domains, URLs and file hashes from the IOC feeds (${when})`}</span>
      </div>
      <div className="mt-4 border-t border-hairline pt-4">
        {view === 'threats' ? <ThreatList rows={threats} /> : <ClueList from={from} />}
      </div>
    </Panel>
  )
}

function ThreatList({ rows: all }: { rows: ExplorerRow[] }) {
  const [r, setR] = useState<'All' | Rating>('All')
  const [src, setSrc] = useState('All')
  const [q, setQ] = useState('')
  const [shown, setShown] = useState(40)
  const sources = useMemo(() => [...new Set(all.map((e) => e.source))].sort(), [all])
  const rows = all.filter((e) =>
    (r === 'All' || e.rating === r) && (src === 'All' || e.source === src) &&
    (!q || `${e.title} ${e.source} ${e.summary} ${e.devices} ${e.id}`.toLowerCase().includes(q.toLowerCase())))
  const reset = () => setShown(40)
  const { theme } = useTheme()
  const sevOptions = (['All', ...RATINGS] as const).map((x) => ({ value: x, label: x === 'All' ? 'All severities' : x,
    count: (x === 'All' ? all : all.filter((e) => e.rating === x)).length, dot: x === 'All' ? undefined : chartTokens[theme].severity[x] }))
  const srcOptions = [{ value: 'All', label: 'All sources' }, ...sources.map((x) => ({ value: x, label: x, count: all.filter((e) => e.source === x).length }))]
  const chips: ActiveFilter[] = [
    ...(q ? [{ key: 'q', label: `“${q}”`, onRemove: () => { setQ(''); reset() } }] : []),
    ...choiceChip('sev', sevOptions, r, () => { setR('All'); reset() }),
    ...choiceChip('src', srcOptions, src, () => { setSrc('All'); reset() }),
  ]
  return (
    <>
      <FilterBar chips={chips} onClear={() => { setR('All'); setSrc('All'); setQ(''); reset() }} count={`${num(rows.length)} threats`}>
        <FilterSearch value={q} onChange={(v) => { setQ(v); reset() }} placeholder="Search threats" />
        <FilterChoice label="Severity" icon={Siren} options={sevOptions} value={r} onChange={(v) => { setR(v as 'All' | Rating); reset() }} />
        <FilterChoice label="Source" icon={Rss} options={srcOptions} value={src} onChange={(v) => { setSrc(v); reset() }} />
      </FilterBar>
      <div className="mt-4">
        {rows.length ? (
          <DTable head={[['Rating'], ['Score'], ['Threat'], ['Affected devices'], ['Published'], ['First action']]} minWidth={980}>
            {rows.slice(0, shown).map((e) => (
              <tr key={e.id} className="align-top hover:bg-well/60">
                <td><SevTag sev={e.rating} /></td>
                <td><ScoreBar score={e.score} width={60} /></td>
                <td className="max-w-[420px]">
                  <div className="flex items-start gap-2">
                    <Link to={threatHref(e.id)} className="font-medium leading-snug hover:underline">{e.title}</Link>
                  </div>
                  <div className="mt-0.5 flex items-center gap-1 text-xs text-ink-3">
                    {e.source}
                    {e.url && <a href={e.url} target="_blank" rel="noopener noreferrer" className="hover:text-ink" aria-label="Open the source"><ExternalLink className="size-3" /></a>}
                  </div>
                  {e.chips.length > 0 && <div className="mt-1.5 flex flex-wrap gap-1">{e.chips.map((c) => <span key={c} className="rounded bg-well px-1.5 py-0.5 text-[11px] text-ink-2">{c}</span>)}</div>}
                </td>
                <td className="text-ink-2">{e.devices || <span className="text-ink-3">not found</span>}</td>
                <td className="tabular whitespace-nowrap text-ink-3">{e.published}</td>
                <td className="max-w-[240px] text-ink-2">{e.action}</td>
              </tr>
            ))}
          </DTable>
        ) : <Empty text="No threats match." />}
      </div>
      <div className="mt-3 flex items-center justify-between text-xs text-ink-3">
        <span>{num(Math.min(shown, rows.length))} of {num(rows.length)} shown</span>
        {rows.length > shown && <button onClick={() => setShown(shown + 60)} className="rounded-lg border border-hairline px-3 py-1.5 font-medium text-ink hover:bg-well">Show 60 more</button>}
      </div>
    </>
  )
}

const CLUE_KINDS: [string, string, string[]][] = [
  ['All', 'All', []], ['ip', 'IP addresses', ['ip']], ['domain', 'Domains', ['domain']], ['url', 'Web links', ['url']],
  ['file', 'Files', ['sha256', 'sha1', 'md5']],
]
const CLUE_TYPE: Record<string, string> = { ip: 'IP', domain: 'Domain', url: 'Web link', sha256: 'File (SHA-256)', sha1: 'File (SHA-1)', md5: 'File (MD5)' }

function ClueList({ from }: { from: string | null }) {   // from: start of the period ("YYYY-MM-DD HH:MM"), null = all time
  const { data, error, isLoading } = useThreatIntelClues()
  const [kind, setKind] = useState('All')
  const [src, setSrc] = useState('All')
  const [q, setQ] = useState('')
  const [seenOnly, setSeenOnly] = useState(false)
  const [shown, setShown] = useState(60)
  const all = useMemo(() => (data ?? []).filter((c) => !c.test && (!from || !c.collected || c.collected >= from)), [data, from])
  const sources = useMemo(() => [...new Set(all.map((c) => c.source))].sort(), [all])
  if (isLoading) return <Skeleton className="h-64 rounded-xl" />
  if (error || !data) return <Empty text={`The indicator list is not available: ${String((error as Error)?.message ?? 'run the Threat Intel Agent to build it')}`} />
  const types = CLUE_KINDS.find(([k]) => k === kind)![2]
  const seen = all.filter((c) => c.seen_on.length).length
  const ql = q.trim().toLowerCase()
  const rows = all.filter((c) =>
    (!types.length || types.includes(c.type)) && (src === 'All' || c.source === src) && (!seenOnly || c.seen_on.length) &&
    (!ql || `${c.value} ${c.malware} ${c.threat}`.toLowerCase().includes(ql)))
  const reset = () => setShown(60)
  const kindOptions = CLUE_KINDS.map(([k, label, ts]) => ({ value: k, label: k === 'All' ? 'All types' : label,
    count: ts.length ? all.filter((c) => ts.includes(c.type)).length : all.length }))
  const srcOptions = [{ value: 'All', label: 'All sources' }, ...sources.map((x) => ({ value: x, label: x, count: all.filter((c) => c.source === x).length }))]
  const seenOptions = [{ value: 'all', label: 'Observed or not', count: all.length },
    { value: 'seen', label: 'Observed on managed devices', count: seen, dot: statusColor.critical }]
  const chips: ActiveFilter[] = [
    ...(q ? [{ key: 'q', label: `“${q}”`, onRemove: () => { setQ(''); reset() } }] : []),
    ...choiceChip('kind', kindOptions, kind, () => { setKind('All'); reset() }),
    ...choiceChip('src', srcOptions, src, () => { setSrc('All'); reset() }),
    ...choiceChip('seen', seenOptions, seenOnly ? 'seen' : 'all', () => { setSeenOnly(false); reset() }),
  ]
  return (
    <>
      <FilterBar chips={chips} onClear={() => { setKind('All'); setSrc('All'); setSeenOnly(false); setQ(''); reset() }} count={`${num(rows.length)} indicators`}>
        <FilterSearch value={q} onChange={(v) => { setQ(v); reset() }} placeholder="Value or malware" />
        <FilterChoice label="Type" icon={Fingerprint} options={kindOptions} value={kind} onChange={(v) => { setKind(v); reset() }} />
        <FilterChoice label="Source" icon={Rss} options={srcOptions} value={src} onChange={(v) => { setSrc(v); reset() }} />
        <FilterChoice label="Observed" icon={Monitor} options={seenOptions} value={seenOnly ? 'seen' : 'all'} onChange={(v) => { setSeenOnly(v === 'seen'); reset() }} />
      </FilterBar>
      <p className="mt-3 text-xs text-ink-3">Indicators are defanged (hxxp, [.]) to prevent accidental access. Hunts search Defender for each one; a match shows the affected device.</p>
      <div className="mt-3">
        {rows.length ? (
          <DTable head={[['Type'], ['Indicator'], ['Malware'], ['Source'], ['First seen'], ['On managed devices'], ['Associated threat']]} minWidth={1040} maxHeight={640}>
            {rows.slice(0, shown).map((c) => (
              <tr key={`${c.type}|${c.value}`} className="align-top hover:bg-well/60">
                <td className="whitespace-nowrap text-ink-2">{CLUE_TYPE[c.type] ?? c.type}</td>
                <td className="max-w-[360px] break-all font-mono text-xs">{c.value}</td>
                <td className="whitespace-nowrap text-ink-2">{c.malware || <span className="text-ink-3">–</span>}</td>
                <td className="whitespace-nowrap text-ink-3">{c.source}</td>
                <td className="tabular whitespace-nowrap text-ink-3">{c.first_seen}</td>
                <td>{c.seen_on.length
                  ? <span className="font-medium" style={{ color: statusColor.critical }}>{c.seen_on.join(', ')}</span>
                  : <span className="text-ink-3">not seen</span>}</td>
                <td className="max-w-[220px] text-xs"><Link to={threatHref(c.threat_id)} className="text-ink-2 hover:underline">{c.threat}</Link></td>
              </tr>
            ))}
          </DTable>
        ) : <Empty text="No indicators match." />}
      </div>
      <div className="mt-3 flex items-center justify-between text-xs text-ink-3">
        <span>{num(Math.min(shown, rows.length))} of {num(rows.length)} shown</span>
        {rows.length > shown && <button onClick={() => setShown(shown + 100)} className="rounded-lg border border-hairline px-3 py-1.5 font-medium text-ink hover:bg-well">Show 100 more</button>}
      </div>
    </>
  )
}

/* ───────── health & metrics ───────── */

function Health({ d }: { d: ThreatIntelData }) {
  const m = d.metrics
  const mins = (v: unknown) => (v == null ? '–' : `${v} min`)
  const rows: [string, string, string][] = [
    ['Time to assess exploitability', mins(m.median_minutes_to_assess), 'median, first seen → analysed'],
    ['Time to publish the report', mins(m.median_minutes_to_report), 'median, first seen → report'],
    ['New threats assessed', `${num(Number(m.pct_assessed) || 0)}%`, 'analysed ÷ collected'],
    ['Threat hunts completed', `${num(Number(m.hunts_completed) || 0)} (≈${num(Number(m.hunts_per_month_projected) || 0)} a month)`, `${m.hunts_per_run} per run`],
    ['Proactive threats identified', num(Number(m.proactive_threats_identified) || 0), 'threats matched to managed devices'],
    ['Reports published', num(Number(m.reports_published) || 0), 'last 30 days'],
    ['Manual effort saved (estimate)', `${num(Number(m['manual_hours_equivalent (assumption)']) || 0)} h`, 'estimate based on standard analyst times'],
    ['Agent calls · corrected by checks', `${num(Number(m.ai_calls) || 0)} · ${m.ai_items_corrected_by_guard ?? '–'}`, 'automatic fact checks'],
  ]
  return (
    <div className="grid grid-cols-1 gap-5 xl:grid-cols-12">
      <Card className="xl:col-span-5" title="Feed health" description="Status of each source at its last run">
        <ul className="flex flex-col divide-y divide-hairline">
          {d.feeds.map((f) => {
            const color = f.last_status === 'ok' ? statusColor.good : f.last_status === 'skipped' ? 'var(--ink-3)' : statusColor.critical
            return (
              <li key={f.feed} className="flex items-center gap-3 py-2.5">
                <span className="size-2 shrink-0 rounded-full" style={{ background: color }} />
                <div className="min-w-0 flex-1">
                  <div className="text-sm font-medium">{FEED_NAME[f.feed] ?? f.feed}</div>
                  <div className="truncate text-xs text-ink-3" title={f.last_error ?? ''}>
                    {f.last_status}{f.last_success_at ? ` · last success ${f.last_success_at.slice(5, 16)}` : ''}
                    {f.last_error && f.last_status !== 'ok' ? ` · ${f.last_error.slice(0, 60)}` : ''}
                  </div>
                </div>
                <span className="tabular text-xs text-ink-2">{num(f.last_count)} new</span>
              </li>
            )
          })}
        </ul>
      </Card>
      <Card className="xl:col-span-7" title="Key metrics" description="Measured from agent timestamps; manual effort is an estimate">
        <DTable head={[['Metric'], ['Value', 'right'], ['How it is measured']]} minWidth={520}>
          {rows.map(([a, b, c]) => (
            <tr key={a}>
              <td className="font-medium">{a}</td>
              <td className="tabular whitespace-nowrap text-right">{b}</td>
              <td className="text-ink-3">{c}</td>
            </tr>
          ))}
        </DTable>
      </Card>
    </div>
  )
}
