import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  ArrowRight, BellRing, Bot, CheckCircle2, ChevronRight, Play, Radar, Scale, Search, Siren, UserCheck, Wrench,
} from 'lucide-react'
import { Card, Empty, InfoTip, Panel, Tag } from '@/components/kit'
import { Skeleton } from '@/components/ui/skeleton'
import { ago, num } from '@/lib/format'
import { useRuns } from '@/lib/runs'
import { statusColor } from '@/lib/theme'
import { NotFound, RULES, VERDICT, VERDICT_ORDER, needsPerson, sourceNames, useUc4Quality, useUc4Queue, utc, verdictMeta, type QueueRow } from '@/lib/uc4'
import { cn } from '@/lib/utils'

type Filter = 'all' | 'likely_true_positive' | 'likely_false_positive' | 'needs_investigation'
type Who = 'agent' | 'person' | 'decided'
const iso = (s: string | null) => utc(s)?.toISOString() ?? null
// older verdicts may still say benign positive: that is filed as a false positive
const outcome = (r: QueueRow) => (r.verdict === 'benign_positive' ? 'likely_false_positive' : r.verdict)

/** Act › Triage (UC4): the agent handles the clear calls; a person decides only the unclear ones. */
export function Respond() {
  const { data, error, isLoading } = useUc4Queue()
  const [filter, setFilter] = useState<Filter>('all')
  const rows = useMemo(() => data?.queue ?? [], [data])
  const auto = !!data?.automation?.auto_resolve
  const who = (r: QueueRow): Who =>
    !needsPerson(r, auto, r.last_action?.action === 'reopen') ? 'agent' : r.feedback ? 'decided' : 'person'
  const shown = rows.filter((r) => filter === 'all' || outcome(r) === filter)

  return (
    <div className="flex flex-col gap-5">
      <Header lastRun={data?.last_run_detail?.finished_at ?? null} />

      {isLoading ? <Skeleton className="h-40 rounded-2xl" /> : error ? (
        <Panel className="p-6">
          <Empty text={error instanceof NotFound ? 'Nothing triaged yet. Press “Check for new incidents” above.' : `Could not load the queue: ${(error as Error).message}`} />
        </Panel>
      ) : data && (
        <>
          <Kpis rows={rows} />
          <HowItWorks />
          <div className="grid grid-cols-1 gap-5 xl:grid-cols-3">
            <Card
              className="xl:col-span-2"
              title="The queue"
              description="Newest first. Open an incident to see the evidence."
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
              ) : <Empty text={rows.length ? 'Nothing in this view.' : 'No incidents yet. A quiet lab is a good lab.'} />}
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
        <p className="mt-1 max-w-3xl text-sm text-ink-3">Defender or Sentinel raised an alarm. True positive or false positive, how bad is it, and what should we do?</p>
      </div>
      <div className="flex flex-wrap items-center gap-3">
        <span className="text-xs text-ink-3">Last checked {ago(iso(lastRun))}</span>
        <button
          onClick={() => (running ? openDrawer('uc4') : start('uc4'))}
          className="inline-flex items-center gap-2 rounded-lg btn-blue px-4 py-2 text-sm font-medium text-white"
        >
          {running ? <span className="size-2 animate-pulse rounded-full bg-sky" /> : <Play className="size-3.5" />}
          {running ? 'Checking… watch' : 'Check for new incidents'}
        </button>
      </div>
    </div>
  )
}

function Kpis({ rows }: { rows: QueueRow[] }) {
  const bySource = new Map<string, number>()
  rows.forEach((r) => { const s = sourceNames(r.sources) || 'Unknown'; bySource.set(s, (bySource.get(s) ?? 0) + 1) })
  const count = (v: string) => rows.filter((r) => r.verdict === v).length
  const tiles: { label: string; value: string; sub: string; dot?: string; tip: string; hue: string }[] = [
    { hue: '', label: 'Incidents triaged', value: num(rows.length), sub: [...bySource].map(([s, n]) => `${n} ${s}`).join(' · '), tip: 'Incidents from Microsoft Defender and Sentinel that the AI has given a verdict.' },
    { hue: 'card-hero-red', label: 'True positive', value: num(count('likely_true_positive')), sub: 'escalated in Defender', dot: VERDICT.likely_true_positive.color, tip: VERDICT.likely_true_positive.help },
    { hue: 'card-hero-green', label: 'False positive', value: num(count('likely_false_positive') + count('benign_positive')), sub: 'closed in Defender', dot: VERDICT.likely_false_positive.color, tip: VERDICT.likely_false_positive.help },
    { hue: 'card-hero-amber', label: 'Needs review', value: num(count('needs_investigation')), sub: 'the AI could not decide: your decision', dot: VERDICT.needs_investigation.color, tip: 'The only incidents a person decides.' },
  ]
  return (
    <div className="card-row gap-4 [--card-min:175px]">
      {tiles.map((t) => (
        <Panel key={t.label} className={cn('card-hero p-5', t.hue)}>
          <div className="flex items-center justify-between gap-2 text-sm text-ink-2">
            <span className="flex items-center gap-2">{t.dot && <span className="size-2 rounded-full bg-white" />}{t.label}</span>
            <InfoTip text={t.tip} />
          </div>
          <div className="tabular mt-3 text-3xl font-semibold tracking-tight">{t.value}</div>
          <div className="mt-1 text-xs text-ink-3">{t.sub}</div>
        </Panel>
      ))}
    </div>
  )
}

const STEPS = [
  { icon: Siren, title: 'Defender or Sentinel raises it', text: 'A new or changed incident' },
  { icon: Search, title: 'Evidence', text: 'Searches around the time, threat intel, past cases' },
  { icon: Scale, title: 'Never overrule Microsoft', text: 'Not closed if Microsoft rated it high or malicious' },
  { icon: Bot, title: 'AI verdict, checked', text: 'Every claim must match the evidence' },
  { icon: UserCheck, title: 'Act', text: 'Clear calls are escalated or closed. You decide the unclear ones' },
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
        <span className="pt-0.5"><VerdictPill verdict={r.verdict} /></span>
        <span className="min-w-0">
          <span className="block truncate text-sm font-medium group-hover:underline">{r.title}</span>
          <span className="mt-0.5 block truncate text-xs text-ink-3">
            #{r.incident_id} · {r.devices.join(', ') || 'no device'} · {sourceNames(r.sources)} · triaged {ago(iso(r.triaged_at))}
          </span>
          <span className="mt-1.5 flex flex-wrap items-center gap-1.5">
            {who === 'agent' ? (r.verdict === 'likely_true_positive'
              ? <Tag tone="bad">Escalated</Tag>
              : <Tag>Closed</Tag>)
              : who === 'person' ? <Tag tone="warn"><UserCheck className="size-3" /> Your decision</Tag>
              : <Tag><UserCheck className="size-3" /> Decided by you</Tag>}
            {r.guardrails.filter((g) => RULES[g]).map((g) => <Tag key={g} tone="warn">{RULES[g].label}</Tag>)}
            {r.ai_status !== 'ai' && <Tag tone="warn">rules only (no AI)</Tag>}
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
    ['Made a call (did not hand to a person)', g.decided_pct],
    ['Right, when it made a call', g.accuracy_when_decided_pct],
    ['True positives kept for review', g.real_attacks_kept_for_humans_pct],
    ['False positives it could close', g.false_alarms_closable_pct],
  ] as const : []
  return (
    <Card title="Can we trust it?" description={g ? `Tested on ${g.n} real incidents that experts already graded (Microsoft GUIDE)` : 'Run the backtest  to fill this in'}>
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
              return `Of ${attacks || 'the'} real attacks in the test, it called ${m} harmless${m ? ', so those would have been closed' : ''}. Everything else it either escalated or handed to a person.`
            })()}
          </li>
        </ul>
      ) : <Empty text="No backtest yet" />}
      <div className="mt-5 border-t border-hairline pt-4">
        <div className="text-sm font-medium">Verdicts so far</div>
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
        [Wrench, 'Fix & protect', 'Prevent', 'Close the holes (old apps, unsupported software, weak settings) before anyone uses them. Planned work: days.', '/fixes'],
        [Radar, 'Attack detection', 'Detect quietly', 'Search for an attacker who got in without setting off an alarm.', '/uc1/hunts'],
        [BellRing, 'Triage', 'Respond', 'Defender has raised an alarm: decide and act. Urgent work: minutes.', null],
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
