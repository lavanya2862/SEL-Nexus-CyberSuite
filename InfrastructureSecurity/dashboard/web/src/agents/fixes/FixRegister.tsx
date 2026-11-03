// Remediation › history: the one standard list of every remediation, whatever its state, with the portal's filters.
// A row opens its full record (FixRecord). Quick views are the states people ask about most.
import { useMemo, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { Bot, CheckCircle2, Monitor, UserCheck, UserCog, Wrench } from 'lucide-react'
import { StatusPill } from '@/components/FixLoop'
import { RecordLink } from '@/components/FixRecord'
import {
  Card, DTable, DateFilter, Empty, FilterBar, FilterChoice, FilterMenu, FilterSearch, choiceChip, dateChip, inDateRange, menuChips,
  type ActiveFilter, type ChoiceOption, type DateRange,
} from '@/components/kit'
import { ACTION_LABEL, STATUS, agentCouldNotFix, isSetting, versionOf, type FixRow, type FixStatus } from '@/agents/fixes/data'
import { AGENT_NAME } from '@/lib/runs'
import { dateTime, num, utc } from '@/lib/format'
import { statusColor } from '@/lib/theme'
import { cn } from '@/lib/utils'

type ViewKey = 'acted' | 'couldnt' | 'person' | 'progress' | 'vendor' | 'completed' | 'verified' | 'problems' | 'proposed' | 'all'
const VIEWS: [ViewKey, string, FixStatus[] | null][] = [
  ['acted', 'All acted on', null],
  ['couldnt', 'Agent could not remediate', ['manual_required']],
  ['person', 'Waiting for manual remediation', ['manual_required']],
  ['progress', 'In progress', ['approved', 'queued', 'running']],
  ['vendor', 'Awaiting vendor', ['awaiting_vendor']],
  ['completed', 'Pending verification', ['done']],
  ['verified', 'Verified', ['verified', 'gone']],
  ['problems', 'Problems', ['failed', 'still_there']],
  ['proposed', 'Proposed', ['proposed', 'saved']],
  ['all', 'Everything', null],
]
const inView = (k: ViewKey, r: FixRow) => {
  if (r.status === 'info') return false
  if (k === 'all') return true
  if (k === 'acted') return r.status !== 'proposed' && r.status !== 'saved'
  if (k === 'couldnt' || k === 'person') return r.status === 'manual_required' && agentCouldNotFix(r) === (k === 'couldnt')
  return (VIEWS.find(([v]) => v === k)?.[2] ?? []).includes(r.status)
}
const TONE: Record<string, string> = { muted: 'var(--ink-3)', sky: 'var(--sky)', run: 'var(--sky)', teal: 'var(--teal)', good: statusColor.good, bad: statusColor.critical, warn: '#b37400' }
const TYPES: [string, string][] = [['upgrade', 'Update'], ['remove', 'Remove'], ['replace', 'Replace'], ['setting', 'Security setting'], ['respond', 'Attack or indicator response']]

/** The latest moment anything happened to a remediation (for sorting and the date filter). */
export function lastActivity(r: FixRow): string | null {
  return [r.verified_at, r.finished_at, r.started_at, r.approved_at, r.saved_at, r.manual?.at].filter((x): x is string => !!x).sort().at(-1) ?? null
}

export function FixRegister({ rows, opco }: { rows: FixRow[]; opco: string }) {
  const [params, setParams] = useSearchParams()
  const initial = VIEWS.find(([v]) => v === params.get('view'))?.[0] ?? 'acted'
  const [view, setView] = useState<ViewKey>(initial)
  const [q, setQ] = useState('')
  const [status, setStatus] = useState<string[]>([])
  const [device, setDevice] = useState('all')
  const [type, setType] = useState('all')
  const [agent, setAgent] = useState('all')
  const [approver, setApprover] = useState('all')
  const [when, setWhen] = useState<DateRange>({ preset: 'any' })
  const [limit, setLimit] = useState(100)

  const base = useMemo(() => rows.filter((r) => r.status !== 'info' && (opco === 'all' || r.opco === opco)), [rows, opco])
  const typeOf = (r: FixRow) => (isSetting(r) ? 'setting' : r.action)
  const term = q.trim().toLowerCase()
  const shown = base
    .filter((r) => inView(view, r) && (!status.length || status.includes(r.status)) && (device === 'all' || r.device_name === device)
      && (type === 'all' || typeOf(r) === type) && (agent === 'all' || agent in (r.found_by ?? {}))
      && (approver === 'all' || r.approved_by === approver || r.manual?.by === approver)
      && (!term || [r.app, r.device_name, r.fix_id, r.version, r.handover?.reason].some((x) => (x ?? '').toLowerCase().includes(term)))
      && inDateRange(utc(lastActivity(r)), when))
    .sort((a, b) => Number(b.status === 'manual_required') - Number(a.status === 'manual_required') || (lastActivity(b) ?? '').localeCompare(lastActivity(a) ?? ''))

  const statusOptions: ChoiceOption[] = (Object.keys(STATUS) as FixStatus[]).filter((s) => s !== 'info' && s !== 'saved' && base.some((r) => r.status === s))
    .map((s) => ({ value: s, label: STATUS[s].label, dot: TONE[STATUS[s].tone], count: base.filter((r) => r.status === s).length }))
  const deviceOptions = [{ value: 'all', label: 'All devices', count: base.length },
  ...[...new Set(base.map((r) => r.device_name))].sort().map((d) => ({ value: d, label: d, count: base.filter((r) => r.device_name === d).length }))]
  const typeOptions = [{ value: 'all', label: 'All types', count: base.length },
  ...TYPES.filter(([t]) => base.some((r) => typeOf(r) === t)).map(([t, l]) => ({ value: t, label: l, count: base.filter((r) => typeOf(r) === t).length }))]
  const agents = [...new Set(base.flatMap((r) => Object.keys(r.found_by ?? {})))]
  const agentOptions = [{ value: 'all', label: 'All agents', count: base.length },
  ...agents.map((a) => ({ value: a, label: AGENT_NAME[a as keyof typeof AGENT_NAME] ?? a, count: base.filter((r) => a in (r.found_by ?? {})).length }))]
  const people = [...new Set(base.flatMap((r) => [r.approved_by, r.manual?.by]).filter((x): x is string => !!x))].sort()
  const approverOptions = [{ value: 'all', label: 'Anyone', count: base.length },
  ...people.map((p) => ({ value: p, label: p, count: base.filter((r) => r.approved_by === p || r.manual?.by === p).length }))]
  const chips: ActiveFilter[] = [
    ...(q ? [{ key: 'q', label: `“${q}”`, onRemove: () => setQ('') }] : []),
    ...menuChips('st', statusOptions, status, setStatus),
    ...choiceChip('dev', deviceOptions, device, () => setDevice('all')),
    ...choiceChip('type', typeOptions, type, () => setType('all')),
    ...choiceChip('agent', agentOptions, agent, () => setAgent('all')),
    ...choiceChip('who', approverOptions, approver, () => setApprover('all')),
    ...dateChip(when, () => setWhen({ preset: 'any' })),
  ]
  const clear = () => { setQ(''); setStatus([]); setDevice('all'); setType('all'); setAgent('all'); setApprover('all'); setWhen({ preset: 'any' }) }
  const pickView = (k: ViewKey) => {
    setView(k); setLimit(100)
    const n = new URLSearchParams(params)
    if (k === 'acted') n.delete('view')
    else n.set('view', k)
    setParams(n, { replace: true })
  }
  const open = (id: string) => { const n = new URLSearchParams(params); n.set('record', id); setParams(n) }

  return (
    <Card title="All remediations" description="Every remediation CyberSuite knows, whatever its state. Select a row for its full record: who approved it, every attempt, the device's output and Defender's verification.">
      <div className="flex flex-col gap-3">
        <div className="flex flex-wrap gap-1.5" role="tablist" aria-label="Quick views">
          {VIEWS.map(([k, label]) => {
            const n = base.filter((r) => inView(k, r)).length
            if (!n && k !== 'acted' && k !== view) return null
            return (
              <button key={k} role="tab" aria-selected={view === k} onClick={() => pickView(k)}
                className={cn('inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-medium transition-colors',
                  view === k ? 'border-blue/60 bg-[color-mix(in_oklab,var(--blue)_12%,var(--panel))] text-ink' : 'border-hairline text-ink-2 hover:bg-well',
                  k === 'person' && n > 0 && view !== k && 'border-[#d03b3b]/50 text-[#d03b3b]')}>
                {k === 'person' && <UserCog className="size-3.5" />}{label}<span className="tabular text-ink-3">{num(n)}</span>
              </button>
            )
          })}
        </div>
        <FilterBar chips={chips} onClear={clear} count={`${num(shown.length)} of ${num(base.filter((r) => inView(view, r)).length)} remediations`}>
          <FilterSearch value={q} onChange={setQ} placeholder="App, device, owner or id" />
          <DateFilter label="Last activity" value={when} onChange={setWhen} />
          <FilterMenu label="Status" icon={CheckCircle2} options={statusOptions} value={status} onChange={setStatus} />
          <FilterChoice label="Device" icon={Monitor} value={device} onChange={setDevice} options={deviceOptions} />
          <FilterChoice label="Type" icon={Wrench} value={type} onChange={setType} options={typeOptions} />
          <FilterChoice label="Found by" icon={Bot} value={agent} onChange={setAgent} options={agentOptions} />
          <FilterChoice label="Approved or fixed by" icon={UserCheck} value={approver} onChange={setApprover} options={approverOptions} />
        </FilterBar>
        {shown.length ? (
          <DTable minWidth={900} head={[['Remediation'], ['Device'], ['Status'], ['Approved'], ['Agent'], ['Last activity'], ['', 'right']]}>
            {shown.slice(0, limit).map((r) => {
              const after = !isSetting(r) ? versionOf(r.result?.after) : undefined
              const tries = (r.agent ?? []).filter((m) => m.action !== 'stop').length
              return (
                <tr key={r.fix_id} onClick={() => open(r.fix_id)} className="cursor-pointer hover:bg-well/50">
                  <td className="max-w-[18rem]">
                    <div className="truncate font-medium">{ACTION_LABEL[r.action]} {r.app}</div>
                    <div className="truncate text-xs text-ink-3">{isSetting(r) ? 'Security setting' : <>{r.version}{after && after !== r.version ? <> → {after}</> : null}</>}{r.findings ? ` · ${num(r.findings)} findings` : ''}</div>
                  </td>
                  <td className="whitespace-nowrap">{r.device_name}</td>
                  <td>
                    <StatusPill r={r} />
                    {r.status === 'gone' && r.message && <div className="mt-0.5 line-clamp-2 max-w-md text-[11px] leading-snug text-ink-3">{r.message}</div>}

                    {r.manual && <div className="text-[11px] text-ink-3">Fixed by hand: {r.manual.by}</div>}
                  </td>
                  <td className="whitespace-nowrap text-xs">{r.approved_by ? <>{r.approved_by}<div className="text-ink-3">{dateTime(utc(r.approved_at))}</div></> : <span className="text-ink-3">–</span>}</td>
                  <td className="whitespace-nowrap text-xs">{tries ? <>{tries} attempt{tries === 1 ? '' : 's'}{r.result?.engine ? <div className="text-ink-3">via {r.result.engine}</div> : null}</> : <span className="text-ink-3">–</span>}</td>
                  <td className="tabular whitespace-nowrap text-xs text-ink-2">{dateTime(utc(lastActivity(r)))}</td>
                  <td className="text-right" onClick={(e) => e.stopPropagation()}><RecordLink id={r.fix_id}>Record</RecordLink></td>
                </tr>
              )
            })}
          </DTable>
        ) : <Empty text={base.length ? 'No remediations match these filters.' : 'No remediations yet.'} />}
        {shown.length > limit && (
          <button onClick={() => setLimit((n) => n + 100)} className="self-center rounded-lg border border-hairline px-3 py-1.5 text-xs font-medium hover:bg-well">
            Show {num(Math.min(100, shown.length - limit))} more of {num(shown.length - limit)}
          </button>
        )}
      </div>
    </Card>
  )
}
