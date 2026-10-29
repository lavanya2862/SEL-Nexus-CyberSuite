import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  ArrowRight, BellRing, Bot, CheckCircle2, ChevronRight, CircleDot, Play, Radar, Scale, Search, Siren, UserCheck, Wrench,
} from 'lucide-react'
import { Card, Empty, InfoTip, Panel, Tag } from '@/components/kit'
import { Skeleton } from '@/components/ui/skeleton'
import { ago, num } from '@/lib/format'
import { useRuns } from '@/lib/runs'
import { statusColor } from '@/lib/theme'
import { NotFound, RULES, VERDICT, VERDICT_ORDER, isClosed, needsPerson, sourceNames, useUc4Quality, useUc4Queue, utc, verdictMeta, type QueueRow, type Verdict } from '@/lib/uc4'
import { cn } from '@/lib/utils'

type Filter = 'all' | 'likely_true_positive' | 'likely_false_positive' | 'needs_investigation'
type Who = 'agent' | 'person' | 'decided'
const iso = (s: string | null) => utc(s)?.toISOString() ?? null
// the analyst's or Defender's classification when one is made, else the agent's verdict (older verdicts may still
// say benign positive: that is filed as a false positive)
const outcome = (r: QueueRow): Verdict => r.outcome ?? (r.verdict === 'benign_positive' ? 'likely_false_positive' : r.verdict)

/** Act › Triage (UC4): the agent handles the clear calls; a person decides only the unclear ones. */
export function Respond() {
  const { data, error, isLoading } = useUc4Queue()
  const [filter, setFilter] = useState<Filter>('all')
  const rows = useMemo(() => data?.queue ?? [], [data])
  const auto = !!data?.automation?.auto_resolve
  const who = (r: QueueRow): Who =>
    !needsPerson(r, auto, r.last_action?.action === 'reopen') ? 'agent' : r.decision ? 'decided' : 'person'
  const shown = rows.filter((r) => filter === 'all' || outcome(r) === filter)
  // a tile on top filters the queue below and brings it into view
  const pick = (f: Filter) => {
    setFilter(f)
    document.getElementById('triage-queue')?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }

  return (
    <div className="flex flex-col gap-5">
      <Header lastRun={data?.last_run_detail?.finished_at ?? null} />

      {isLoading ? <Skeleton className="h-40 rounded-2xl" /> : error ? (
        <Panel className="p-6">
          <Empty text={error instanceof NotFound ? 'No incidents triaged yet. Select “Check for new incidents” above.' : `Could not load the queue: ${(error as Error).message}`} />
        </Panel>
      ) : data && (
        <>
          <Kpis rows={rows} filter={filter} onPick={pick} />
          <HowItWorks />
          <div className="grid grid-cols-1 gap-5 xl:grid-cols-3">
            <Card
              id="triage-queue"
              className="xl:col-span-2 scroll-mt-4"
              title="The queue"
              description="Most recent first. Open an incident to view the evidence."
              action={<span className="tabular whitespace-nowrap text-xs text-ink-3">{shown.length} of {rows.length}</span>}
            >
              <div className="mb-3 flex flex-wrap gap-1.5" role="tablist" aria-label="Filter the queue">
                {(['all', ...VERDICT_ORDER] as Filter[]).map((id) => (
                  <button
                    key={id}
                    role="tab"
                    aria-selected={filter === id}
                    onClick={() => setFilter(id)}
                    className={cn('tabular inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs', filter === id ? 'pill-on' : 'border-hairline text-ink-2 hover:bg-well')}
                  >
                    {id !== 'all' && <span className="size-1.5 rounded-full" style={{ background: VERDICT[id].color }} />}
                    {id === 'all' ? 'All' : VERDICT[id].short} · {id === 'all' ? rows.length : rows.filter((r) => outcome(r) === id).length}
                  </button>
                ))}
              </div>
              {shown.length ? (
                <ul className="flex flex-col divide-y divide-hairline rounded-xl border border-hairline">
                  {shown.map((r) => <QueueItem key={r.incident_id} r={r} who={who(r)} />)}
                </ul>
              ) : <Empty text={rows.length ? 'No incidents in this view.' : 'No incidents to triage.'} />}
            </Card>
            <Accuracy byVerdict={data.by_verdict} />
          </div>
        </>
      )}

      <WhereItFits />
    </div>
  )
}

function Header({ lastRun }: { lastRun: string | null }) {
  const { runs, start, openDrawer } = useRuns()
  const running = runs?.uc4?.status === 'running'
  return (
    <div className="flex flex-wrap items-end justify-between gap-4">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Alert triage</h1>
        <p className="mt-1 max-w-3xl text-sm text-ink-3">Agent-assisted triage of Microsoft Defender and Sentinel incidents: classification, severity and recommended response</p>
      </div>
      <div className="flex flex-wrap items-center gap-3">
        <span className="text-xs text-ink-3">Last checked {ago(iso(lastRun))}</span>
        <button
          onClick={() => (running ? openDrawer('uc4') : start('uc4'))}
          className="inline-flex items-center gap-2 rounded-lg btn-blue px-4 py-2 text-sm font-medium text-white"
        >
          {running ? <span className="size-2 animate-pulse rounded-full bg-sky" /> : <Play className="size-3.5" />}
          {running ? 'Checking… view progress' : 'Check for new incidents'}
        </button>
      </div>
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
              aria-label={`${t.label}: ${t.value}. Show these in the queue`}
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
    <span className={cn('inline-flex items-center gap-1.5 whitespace-nowrap rounded-full border border-hairline bg-panel font-medium', large ? 'px-3 py-1.5 text-sm' : 'px-2 py-0.5 text-xs')}>
      <span className={cn('rounded-full', large ? 'size-2.5' : 'size-2')} style={{ background: m.color }} />
      {large ? m.label : m.short}
    </span>
  )
}

function QueueItem({ r, who }: { r: QueueRow; who: Who }) {
  return (
    <li>
      <Link to={`/respond/${encodeURIComponent(r.incident_id)}`} className="group grid grid-cols-[auto_minmax(0,1fr)_auto] items-start gap-x-3 gap-y-1 px-4 py-3.5 hover:bg-well">
        <span className="pt-0.5"><VerdictPill verdict={r.outcome ?? r.verdict} /></span>
        <span className="min-w-0">
          <span className="block truncate text-sm font-medium group-hover:underline">{r.title}</span>
          <span className="mt-0.5 block truncate text-xs text-ink-3">
            #{r.incident_id} · {r.devices.join(', ') || 'no device'} · {sourceNames(r.sources)} · triaged {ago(iso(r.triaged_at))}
          </span>
          <span className="mt-1.5 flex flex-wrap items-center gap-1.5">
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
            {who === 'decided' && r.verdict !== outcome(r) && <Tag>Agent said: {verdictMeta(r.verdict).short.toLowerCase()}</Tag>}
            {r.guardrails.filter((g) => RULES[g]).map((g) => <Tag key={g} tone="warn">{RULES[g].label}</Tag>)}
            {r.ai_status !== 'ai' && <Tag tone="warn">rules only</Tag>}
          </span>
        </span>
        <ChevronRight className="mt-1 size-4 text-ink-3 group-hover:text-ink" />
      </Link>
    </li>
  )
}

function Accuracy({ byVerdict }: { byVerdict: Record<string, number> }) {
  const { data } = useUc4Quality()
  const g = data?.backtest?.sets?.guide
  const total = Object.values(byVerdict).reduce((a, b) => a + b, 0)
  const bars = g ? [
    ['Auto-classification rate', g.decided_pct],
    ['Precision (auto-classified)', g.accuracy_when_decided_pct],
    ['True positives retained for review', g.real_attacks_kept_for_humans_pct],
    ['False positives auto-closed', g.false_alarms_closable_pct],
  ] as const : []
  return (
    <Card title="Model accuracy (backtest on past incidents)" description={g ? `Tested on ${g.n} real incidents with expert-graded verdicts (Microsoft GUIDE)` : 'Run the backtest to populate this view'}>
      {g ? (
        <ul className="flex flex-col gap-3">
          {bars.map(([label, pct]) => (
            <li key={label}>
              <div className="flex items-baseline justify-between gap-2 text-sm"><span className="text-ink-2">{label}</span><span className="tabular font-medium">{Math.round(pct)}%</span></div>
              <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-well"><div className="h-full rounded-full bg-blue" style={{ width: `${pct}%` }} /></div>
            </li>
          ))}
          <li className="flex items-start gap-2 rounded-xl bg-well p-3 text-xs leading-relaxed text-ink-2">
            <CheckCircle2 className="mt-0.5 size-3.5 shrink-0" style={{ color: statusColor.good }} />
            {(() => {
              const attacks = Object.values(g.confusion?.TP ?? {}).reduce((a, b) => a + b, 0)
              const m = g.missed_true_positives
              return `Of ${attacks || 'the'} real attacks in the test, it called ${m} harmless${m ? ', so those would have been closed' : ''}. All others were escalated or routed for analyst review.`
            })()}
          </li>
        </ul>
      ) : <Empty text="No backtest yet" />}
      <div className="mt-5 border-t border-hairline pt-4">
        <div className="text-sm font-medium">Agent verdicts so far</div>
        <p className="mt-0.5 text-xs text-ink-3">Before any analyst decision</p>
        <ul className="mt-2 flex flex-col gap-1.5 text-sm">
          {VERDICT_ORDER.map((v) => (
            <li key={v} className="flex items-center gap-2">
              <span className="size-2 rounded-full" style={{ background: VERDICT[v].color }} />
              <span className="flex-1 text-ink-2">{VERDICT[v].short}</span>
              <span className="tabular text-ink-3">{byVerdict[v] ?? 0}{total ? ` · ${Math.round(((byVerdict[v] ?? 0) / total) * 100)}%` : ''}</span>
            </li>
          ))}
        </ul>
      </div>
    </Card>
  )
}

function WhereItFits() {
  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
      {([
        [Wrench, 'Remediation', 'Prevent', 'Remediate vulnerable applications, unsupported software and weak settings. Planned work: days.', '/fixes'],
        [Radar, 'Attack detection', 'Hunt proactively', 'Identify attackers who gained access without triggering an alert.', '/uc1/hunts'],
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
