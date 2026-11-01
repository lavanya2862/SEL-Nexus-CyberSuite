import { useMemo, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import {
  ArrowRight, BellRing, Bot, CheckCircle2, ChevronRight, CircleDot, ExternalLink, Play, Radar, Scale, Search, Siren, SlidersHorizontal,
  UserCheck, Wrench,
} from 'lucide-react'
import { Chart, axisStyle } from '@/components/Chart'
import { DetailDialog } from '@/components/DetailDialog'
import {
  Card, DateFilter, Empty, FilterChips, FilterMenu, InfoTip, Panel, Tabs, Tag, dateBounds, dateLabel, type ActiveFilter, type DateRange,
} from '@/components/kit'
import { Skeleton } from '@/components/ui/skeleton'
import { ago, num } from '@/lib/format'
import { useRuns } from '@/lib/runs'
import { statusColor } from '@/lib/theme'
import {
  NotFound, RULES, VERDICT, VERDICT_ORDER, isClosed, needsPerson, sourceNames, useTriageCase, useTriageQueue, utc,
  verdictMeta, type QueueRow, type Verdict,
} from '@/agents/alert-triage/data'
import { Decide, Thinks, ToDo } from '@/agents/alert-triage/RespondCase'
import { cn } from '@/lib/utils'

type Tab = 'overview' | 'incidents'
const TABS: [Tab, string][] = [['overview', 'Overview'], ['incidents', 'Incidents']]
type Filter = 'all' | 'likely_true_positive' | 'likely_false_positive' | 'needs_investigation'
type Who = 'agent' | 'person' | 'decided'
const iso = (s: string | null) => utc(s)?.toISOString() ?? null
// the analyst's or Defender's classification when one is made, else the agent's verdict (older verdicts may still
// say benign positive: that is filed as a false positive)
const outcome = (r: QueueRow): Verdict => r.outcome ?? (r.verdict === 'benign_positive' ? 'likely_false_positive' : r.verdict)
const SEV_ORDER = ['high', 'medium', 'low', 'informational']

/** Act › Triage (Alert Triage): the agent handles the clear calls; a person decides only the unclear ones. */
export function Respond() {
  const { data, error, isLoading } = useTriageQueue()
  const [params, setParams] = useSearchParams()
  const tab = TABS.find(([t]) => t === params.get('tab'))?.[0] ?? 'overview'
  const [filter, setFilter] = useState<Filter>('all')
  const rows = useMemo(() => data?.queue ?? [], [data])
  const auto = !!data?.automation?.auto_resolve
  const who = (r: QueueRow): Who =>
    !needsPerson(r, auto, r.last_action?.action === 'reopen') ? 'agent' : r.decision ? 'decided' : 'person'
  const setTab = (t: Tab) => setParams((p) => { const n = new URLSearchParams(p); if (t === 'overview') n.delete('tab'); else n.set('tab', t); return n }, { replace: true })
  // a tile on the overview opens the incidents tab with that verdict
  const [picked, setPicked] = useState(0)      // an Overview tile opens Incidents afresh with its classification
  const pick = (f: Filter) => { setFilter(f); setPicked((n) => n + 1); setTab('incidents') }

  return (
    <div className="flex flex-col gap-5">
      <Header lastRun={data?.last_run_detail?.finished_at ?? null} />
      <Tabs<Tab> tabs={TABS} value={tab} onChange={setTab} />
      {isLoading ? <Skeleton className="h-40 rounded-2xl" /> : error ? (
        <Panel className="p-6">
          <Empty text={error instanceof NotFound ? 'No incidents triaged yet. Select “Check for new incidents” above.' : `Could not load the queue: ${(error as Error).message}`} />
        </Panel>
      ) : data && (tab === 'overview'
        ? <Overview rows={rows} who={who} filter={filter} onPick={pick} />
        : <Incidents key={picked} rows={rows} who={who} filter={filter} />)}
    </div>
  )
}

function Header({ lastRun }: { lastRun: string | null }) {
  const { runs, start, openDrawer } = useRuns()
  const running = runs?.alert_triage?.status === 'running'
  return (
    <div className="flex flex-wrap items-end justify-between gap-4">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Alert triage</h1>
        <p className="mt-1 max-w-3xl text-sm text-ink-3">Agent-assisted triage of Microsoft Defender and Sentinel incidents: classification, severity and recommended response</p>
      </div>
      <div className="flex flex-wrap items-center gap-3">
        <span className="text-xs text-ink-3">Last checked {ago(iso(lastRun))}</span>
        <button
          onClick={() => (running ? openDrawer('alert_triage') : start('alert_triage'))}
          className="inline-flex items-center gap-2 rounded-lg btn-blue px-4 py-2 text-sm font-medium text-white"
        >
          {running ? <span className="size-2 animate-pulse rounded-full bg-sky" /> : <Play className="size-3.5" />}
          {running ? 'Checking… view progress' : 'Check for new incidents'}
        </button>
      </div>
    </div>
  )
}

/* ───────── overview ───────── */

function Overview({ rows, who, filter, onPick }: { rows: QueueRow[]; who: (r: QueueRow) => Who; filter: Filter; onPick: (f: Filter) => void }) {
  const waiting = rows.filter((r) => who(r) === 'person')
  const worst = [...waiting].sort((a, b) => SEV_ORDER.indexOf(a.severity.toLowerCase()) - SEV_ORDER.indexOf(b.severity.toLowerCase()))[0]
  const tone = waiting.length ? statusColor.warning : statusColor.good
  const bySource = new Map<string, number>()
  rows.forEach((r) => { const s = sourceNames(r.sources) || 'Unknown'; bySource.set(s, (bySource.get(s) ?? 0) + 1) })
  return (
    <div className="flex flex-col gap-5">
      <Panel className="flex items-start gap-4 p-6">
        <span className="grid size-12 shrink-0 place-items-center rounded-2xl" style={{ background: `color-mix(in oklab, ${tone} 16%, transparent)` }}>
          {waiting.length ? <UserCheck className="size-6" style={{ color: tone }} /> : <CheckCircle2 className="size-6" style={{ color: tone }} />}
        </span>
        <div className="min-w-0">
          <div className="text-sm text-ink-3">Triage queue</div>
          <div className="mt-1 text-2xl font-semibold tracking-tight">
            {waiting.length ? `${waiting.length} incident${waiting.length === 1 ? '' : 's'} need${waiting.length === 1 ? 's' : ''} an analyst decision` : 'Queue clear'}
          </div>
          <p className="mt-2 max-w-2xl text-sm leading-relaxed text-ink-2">
            {waiting.length
              ? <>Highest severity awaiting a decision: <b>{worst?.severity}</b>, “{worst?.title}”. The agent handled the remaining {num(rows.length - waiting.length)} incidents.</>
              : <>The agent classified all {num(rows.length)} incidents; none requires an analyst decision.</>}
          </p>
        </div>
      </Panel>

      <Kpis rows={rows} filter={filter} onPick={onPick} />

      <div className="grid grid-cols-1 gap-5 xl:grid-cols-12">
        <Card className="xl:col-span-5" title="Classification" description="Final classification per incident: the analyst's or Defender's when made, otherwise the agent's verdict">
          <Chart height={240} build={(tk) => ({
            grid: { left: 8, right: 32, top: 4, bottom: 4, containLabel: true },
            tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
            xAxis: { type: 'value', minInterval: 1, ...axisStyle(tk), axisLine: { show: false } },
            yAxis: { type: 'category', data: [...VERDICT_ORDER].reverse().map((v) => VERDICT[v].short), ...axisStyle(tk), splitLine: { show: false }, axisLabel: { color: tk.ink2 } },
            series: [{ type: 'bar', barMaxWidth: 16, name: 'Incidents', itemStyle: { borderRadius: [0, 4, 4, 0] },
              label: { show: true, position: 'right', color: tk.ink, fontSize: 11 },
              data: [...VERDICT_ORDER].reverse().map((v) => ({ value: rows.filter((r) => outcome(r) === v).length, itemStyle: { color: VERDICT[v].color } })) }],
          })} />
        </Card>
        <Card className="xl:col-span-7" title="Incidents over time" description="Incidents triaged per day, last 14 days, by source">
          <Chart height={240} build={(tk) => {
            const days = Array.from({ length: 14 }, (_, i) => new Date(Date.now() - (13 - i) * 86400000).toISOString().slice(0, 10))
            const sources = [...bySource.keys()]
            return {
              grid: { left: 8, right: 8, top: 28, bottom: 4, containLabel: true },
              legend: { top: 0, textStyle: { color: tk.ink2 } },
              tooltip: { trigger: 'axis' },
              xAxis: { type: 'category', data: days.map((x) => x.slice(5)), ...axisStyle(tk) },
              yAxis: { type: 'value', minInterval: 1, ...axisStyle(tk) },
              series: sources.map((s, i) => ({
                type: 'bar', stack: 'all', name: s, barMaxWidth: 18, itemStyle: { color: tk.series[i % tk.series.length] },
                data: days.map((day) => rows.filter((r) => (sourceNames(r.sources) || 'Unknown') === s && (iso(r.triaged_at) ?? '').slice(0, 10) === day).length),
              })),
            }
          }} />
        </Card>
      </div>

      <HowItWorks />
      <WhereItFits />
    </div>
  )
}

function Kpis({ rows, filter, onPick }: { rows: QueueRow[]; filter: Filter; onPick: (f: Filter) => void }) {
  const bySource = new Map<string, number>()
  rows.forEach((r) => { const s = sourceNames(r.sources) || 'Unknown'; bySource.set(s, (bySource.get(s) ?? 0) + 1) })
  const count = (v: Verdict) => rows.filter((r) => outcome(r) === v).length
  const closed = rows.filter((r) => isClosed(r.status)).length
  const tiles: { id: Filter; label: string; value: string; sub: string; dot?: string; tip: string; hue: string }[] = [
    { id: 'all', hue: '', label: 'Incidents triaged', value: num(rows.length), sub: `${num(rows.length - closed)} open · ${num(closed)} closed in Defender`,
      tip: `Every incident from Microsoft Defender and Sentinel the Alert Triage Agent has classified (${[...bySource].map(([s, n]) => `${n} ${s}`).join(', ')}). Defender's incident list may show fewer if it is filtered by last update time.` },
    { id: 'likely_true_positive', hue: 'card-hero-red', label: 'True positive', value: num(count('likely_true_positive')), sub: 'real attacks: escalated in Defender', dot: VERDICT.likely_true_positive.color, tip: `${VERDICT.likely_true_positive.help} Includes incidents an analyst classified as true positive.` },
    { id: 'likely_false_positive', hue: 'card-hero-green', label: 'False positive', value: num(count('likely_false_positive')), sub: 'harmless: closed in Defender', dot: VERDICT.likely_false_positive.color, tip: `${VERDICT.likely_false_positive.help} Includes incidents an analyst classified as false positive.` },
    { id: 'needs_investigation', hue: 'card-hero-amber', label: 'Needs review', value: num(count('needs_investigation')), sub: 'awaiting an analyst decision', dot: VERDICT.needs_investigation.color, tip: 'Incidents the agent could not classify and no analyst has classified yet, here or in Defender.' },
  ]
  return (
    <div className="card-row gap-4 [--card-min:175px]">
      {tiles.map((t) => (
        <Panel key={t.label} className={cn('card-hero p-0 transition-[transform,opacity] hover:-translate-y-0.5', t.hue, filter !== 'all' && filter !== t.id && 'opacity-60 hover:opacity-90')}>
          <div className="relative">
            <button
              type="button"
              onClick={() => onPick(t.id)}
              aria-pressed={filter === t.id}
              aria-label={`${t.label}: ${t.value}. Show these incidents`}
              className="absolute inset-0 rounded-[20px] focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-white"
            />
            <div className="pointer-events-none relative p-5">
              <div className="flex items-center justify-between gap-2 text-sm text-ink-2">
                <span className="flex items-center gap-2">{t.dot && <span className="size-2 rounded-full bg-white" />}{t.label}</span>
                <span className="pointer-events-auto"><InfoTip text={t.tip} /></span>
              </div>
              <div className="tabular mt-3 text-3xl font-semibold tracking-tight">{t.value}</div>
              <div className="mt-1 text-xs text-ink-3">{t.sub}</div>
            </div>
          </div>
        </Panel>
      ))}
    </div>
  )
}

const STEPS = [
  { icon: Siren, title: 'Defender or Sentinel raises it', text: 'A new or changed incident' },
  { icon: Search, title: 'Evidence', text: 'Searches around the time, threat intel, past cases' },
  { icon: Scale, title: 'Microsoft severity respected', text: 'Never closed if Microsoft rated it high or malicious' },
  { icon: Bot, title: 'Agent verdict, validated', text: 'Every claim must match the evidence' },
  { icon: UserCheck, title: 'Act', text: 'Clear verdicts are escalated or closed; analysts decide the rest' },
]

function HowItWorks() {
  return (
    <Panel className="px-5 py-4">
      <h2 className="mb-3 text-[15px] font-semibold tracking-[-0.01em]">How each incident is handled</h2>
      <ol className="card-row gap-x-5 gap-y-3 [--card-min:145px]">
        {STEPS.map((s, i) => (
          <li key={s.title} className="flex items-start gap-3">
            <span className="grid size-8 shrink-0 place-items-center rounded-lg bg-well"><s.icon className="size-4 text-ink-2" /></span>
            <span className="min-w-0">
              <span className="block text-sm font-medium"><span className="tabular text-ink-3">{i + 1}.</span> {s.title}</span>
              <span className="block text-xs leading-snug text-ink-3">{s.text}</span>
            </span>
          </li>
        ))}
      </ol>
    </Panel>
  )
}

export function VerdictPill({ verdict, large }: { verdict: string; large?: boolean }) {
  const m = verdictMeta(verdict)
  return (
    <span className={cn('inline-flex items-center gap-1.5 whitespace-nowrap rounded-lg border border-hairline bg-panel font-medium', large ? 'px-3 py-1.5 text-sm' : 'px-2 py-0.5 text-xs')}>
      <span className={cn('rounded-full', large ? 'size-2.5' : 'size-2')} style={{ background: m.color }} />
      {large ? m.label : m.short}
    </span>
  )
}

/* ───────── incidents: small cards, the case in a dialog ───────── */

// Defender's incident severities, most severe first, each with its own colour (as in Defender's portal)
const SEV_DOT: Record<string, string> = { high: statusColor.critical, medium: statusColor.warning, low: statusColor.good, informational: 'var(--sky)' }
const WHO_LABEL: Record<Who, string> = { person: 'Awaiting analyst decision', decided: 'Decided by an analyst or Defender', agent: 'Handled by the agent' }
const cap = (s: string) => s[0].toUpperCase() + s.slice(1)

function Incidents({ rows, who, filter }: { rows: QueueRow[]; who: (r: QueueRow) => Who; filter: Filter }) {
  const [cls, setCls] = useState<string[]>(filter === 'all' ? [] : [filter])
  const [sev, setSev] = useState<string[]>([])
  const [source, setSource] = useState<string[]>([])
  const [status, setStatus] = useState<string[]>([])
  const [date, setDate] = useState<DateRange>({ preset: 'any' })
  const [open, setOpen] = useState<QueueRow | null>(null)
  const bounds = dateBounds(date)
  // Defender's creation time of the incident (the triage time for incidents that have none)
  const when = (r: QueueRow) => utc(r.created_at ?? r.triaged_at)
  const shown = rows.filter((r) => (!cls.length || cls.includes(outcome(r))) && (!sev.length || sev.includes(r.severity.toLowerCase()))
    && (!source.length || source.includes(sourceNames(r.sources) || 'Unknown')) && (!status.length || status.includes(who(r)))
    && (!bounds || ((d) => !!d && d >= bounds[0] && d < bounds[1])(when(r))))
  const count = (test: (r: QueueRow) => boolean) => rows.filter(test).length
  const sevOptions = SEV_ORDER.filter((s) => rows.some((r) => r.severity.toLowerCase() === s))
    .map((s) => ({ value: s, label: cap(s), dot: SEV_DOT[s], count: count((r) => r.severity.toLowerCase() === s) }))
  const clsOptions = VERDICT_ORDER.map((v) => ({ value: v, label: VERDICT[v].short, dot: VERDICT[v].color, count: count((r) => outcome(r) === v) }))
  const sourceOptions = [...new Set(rows.map((r) => sourceNames(r.sources) || 'Unknown'))]
    .map((s) => ({ value: s, label: s, count: count((r) => (sourceNames(r.sources) || 'Unknown') === s) }))
  const statusOptions = (Object.keys(WHO_LABEL) as Who[]).map((w) => ({ value: w, label: WHO_LABEL[w], count: count((r) => who(r) === w) }))
  const drop = (list: string[], set: (v: string[]) => void, v: string) => () => set(list.filter((x) => x !== v))
  const chips: ActiveFilter[] = [
    ...cls.map((v) => ({ key: `c-${v}`, label: verdictMeta(v).short, dot: verdictMeta(v).color, onRemove: drop(cls, setCls, v) })),
    ...sev.map((v) => ({ key: `s-${v}`, label: cap(v), dot: SEV_DOT[v], onRemove: drop(sev, setSev, v) })),
    ...source.map((v) => ({ key: `o-${v}`, label: v, onRemove: drop(source, setSource, v) })),
    ...status.map((v) => ({ key: `w-${v}`, label: WHO_LABEL[v as Who], onRemove: drop(status, setStatus, v) })),
    ...(date.preset !== 'any' ? [{ key: 'date', label: dateLabel(date), onRemove: () => setDate({ preset: 'any' }) }] : []),
  ]
  const clearAll = () => { setCls([]); setSev([]); setSource([]); setStatus([]); setDate({ preset: 'any' }) }
  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-col gap-3 rounded-xl border border-hairline bg-panel px-4 py-3">
        <div className="flex flex-wrap items-center gap-2.5">
          <span className="mr-1 inline-flex items-center gap-1.5 text-sm font-medium text-ink-2"><SlidersHorizontal className="size-4" /> Filters</span>
          <DateFilter label="Created" value={date} onChange={setDate} />
          <FilterMenu label="Severity" icon={Siren} options={sevOptions} value={sev} onChange={setSev} />
          <FilterMenu label="Classification" icon={Scale} options={clsOptions} value={cls} onChange={setCls} />
          <FilterMenu label="Status" icon={UserCheck} options={statusOptions} value={status} onChange={setStatus} />
          <FilterMenu label="Source" icon={Radar} options={sourceOptions} value={source} onChange={setSource} />
          <span className="tabular ml-auto text-xs text-ink-3">{num(shown.length)} of {num(rows.length)} incidents</span>
        </div>
        {chips.length > 0 && <div className="border-t border-hairline pt-3"><FilterChips items={chips} onClear={clearAll} /></div>}
      </div>
      {shown.length ? (
        <ul className="grid grid-cols-1 gap-3 md:grid-cols-2 2xl:grid-cols-3">
          {shown.map((r) => <li key={r.incident_id}><IncidentCard r={r} who={who(r)} onOpen={() => setOpen(r)} /></li>)}
        </ul>
      ) : <Empty text={rows.length ? 'No incidents match these filters.' : 'No incidents to triage.'} />}
      {open && <IncidentDialog r={open} who={who(open)} onClose={() => setOpen(null)} />}
    </div>
  )
}

function StatusTags({ r, who }: { r: QueueRow; who: Who }) {
  return (
    <>
      {who === 'agent' ? (r.verdict === 'likely_true_positive'
        ? <Tag tone="bad">Escalated by the agent</Tag>
        : <Tag>Closed by the agent</Tag>)
        : who === 'person' ? <Tag tone="warn"><UserCheck className="size-3" /> Analyst decision needed</Tag>
        : r.decision?.by === 'defender' ? <Tag><UserCheck className="size-3" /> Classified in Defender</Tag>
        : <Tag><UserCheck className="size-3" /> Reviewed by {r.decision?.who || 'an analyst'}</Tag>}
      {/* Defender's status, always: open = still being worked on, closed = resolved */}
      {isClosed(r.status)
        ? <Tag><CheckCircle2 className="size-3" /> Closed in Defender</Tag>
        : <Tag tone={who === 'person' ? undefined : 'bad'}><CircleDot className="size-3" /> Open in Defender</Tag>}
    </>
  )
}

function IncidentCard({ r, who, onOpen }: { r: QueueRow; who: Who; onOpen: () => void }) {
  const accent = verdictMeta(outcome(r)).color
  return (
    <button onClick={onOpen} className="flex h-full w-full flex-col overflow-hidden rounded-xl border border-hairline bg-panel text-left transition-colors hover:border-hairline-strong hover:bg-well/40 focus-visible:outline-2 focus-visible:outline-blue">
      <span className="h-1 w-full" style={{ background: accent }} />
      <div className="flex flex-1 flex-col gap-2 p-4">
        <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
          <span className="flex items-center gap-2"><VerdictPill verdict={outcome(r)} /><span className="text-ink-3">{r.severity} · {r.confidence} confidence</span></span>
          <span className="text-ink-3">#{r.incident_id}</span>
        </div>
        <div className="line-clamp-2 font-semibold leading-snug">{r.title}</div>
        <div className="line-clamp-1 text-xs text-ink-3">
          {[r.devices.join(', '), r.accounts.join(', ')].filter(Boolean).join(' · ') || 'No device or account'} · {sourceNames(r.sources)}
        </div>
        {r.summary && <p className="line-clamp-2 text-xs leading-relaxed text-ink-2">{r.summary}</p>}
        <div className="mt-auto flex flex-wrap items-center gap-1.5 pt-1">
          <StatusTags r={r} who={who} />
          {r.guardrails.filter((g) => RULES[g]).slice(0, 1).map((g) => <Tag key={g} tone="warn">{RULES[g].label}</Tag>)}
        </div>
        <div className="flex items-center justify-between text-[11px] text-ink-3">
          <span>Triaged {ago(iso(r.triaged_at))}</span>
          <span className="inline-flex items-center gap-0.5 font-medium text-blue">Details <ChevronRight className="size-3.5" /></span>
        </div>
      </div>
    </button>
  )
}

function IncidentDialog({ r, who, onClose }: { r: QueueRow; who: Who; onClose: () => void }) {
  const { data: c, isLoading } = useTriageCase(r.incident_id)
  return (
    <DetailDialog onClose={onClose} title={r.title}
      eyebrow={<><VerdictPill verdict={outcome(r)} /><span className="text-ink-3">{r.severity} · {r.confidence} confidence</span><StatusTags r={r} who={who} /></>}
      subtitle={`Incident #${r.incident_id} · ${sourceNames(r.sources)} · triaged ${ago(iso(r.triaged_at))}`}
      footer={<>
        <span className="mr-auto text-xs text-ink-3">Nothing changes in Defender until you save a decision.</span>
        {r.web_url && <a href={r.web_url} target="_blank" rel="noreferrer noopener" className="inline-flex items-center gap-1.5 rounded-lg border border-hairline-strong bg-panel px-3.5 py-2 text-sm font-medium hover:bg-well">Open in Defender <ExternalLink className="size-3.5" /></a>}
        <Link to={`/alert-triage/${encodeURIComponent(r.incident_id)}`} className="btn-blue inline-flex items-center gap-1.5 rounded-lg px-3.5 py-2 text-sm font-semibold text-white">Open full case <ArrowRight className="size-4" /></Link>
      </>}>
      {isLoading || !c ? <Skeleton className="h-48 rounded-xl" /> : (
        <div className="grid grid-cols-1 gap-5 lg:grid-cols-5">
          <div className="flex min-w-0 flex-col gap-5 lg:col-span-3">
            <Thinks c={c} />
            <ToDo c={c} />
          </div>
          <div className="flex min-w-0 flex-col gap-5 lg:col-span-2">
            <Decide c={c} />
          </div>
        </div>
      )}
    </DetailDialog>
  )
}

function WhereItFits() {
  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
      {([
        [Wrench, 'Remediation', 'Prevent', 'Remediate vulnerable applications, unsupported software and weak settings. Planned work: days.', '/fixes'],
        [Radar, 'Attack detection', 'Hunt proactively', 'Identify attackers who gained access without triggering an alert.', '/attack-detection'],
        [BellRing, 'Triage', 'Respond', 'Defender has raised an incident: classify and respond. High-severity incidents: respond within minutes.', null],
      ] as const).map(([Icon, title, role, text, to]) => (
        <Panel key={title} className="flex flex-col gap-2 p-5">
          <div className="flex items-center gap-2">
            <Icon className="size-4 text-ink-2" />
            <span className="font-medium">{title}</span>
            <span className="ml-auto rounded-md bg-well px-2 py-0.5 text-[11px] text-ink-2">{role}</span>
          </div>
          <p className="text-sm leading-relaxed text-ink-3">{text}</p>
          {to ? <Link to={to} className="mt-auto inline-flex items-center gap-1 text-sm font-medium hover:underline">Open <ArrowRight className="size-3.5" /></Link>
            : <span className="mt-auto text-sm text-ink-3">You are here</span>}
        </Panel>
      ))}
    </div>
  )
}
