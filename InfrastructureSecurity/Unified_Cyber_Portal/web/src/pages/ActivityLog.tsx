import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { Search } from 'lucide-react'
import { Choice, DTable, Empty, Panel } from '@/components/kit'
import { ago, num } from '@/lib/format'
import { cn } from '@/lib/utils'

// Activity log (GET /api/activity): who ran which agent or pipeline, and who acted on its results, with their name,
// email, date and time. Laid out like Application Security's Activity log, so both domains read the same.

interface ActivityEntry {
  id: string
  ts: string
  email: string
  name: string
  action: string
  label: string
  agent: string
  target: string
  outcome: 'success' | 'failed' | 'refused'
  detail: string
  run: string | null
  source: 'audit' | 'history'
}

type Tone = 'good' | 'warn' | 'bad' | 'info' | 'idle'
const ACTIONS: Record<string, { label: string; tone: Tone }> = {
  'run.start': { label: 'Started a pipeline run', tone: 'info' },
  'run.refused': { label: 'Pipeline run refused', tone: 'warn' },
  'run.finish': { label: 'Pipeline run completed', tone: 'good' },
  'fix.approve': { label: 'Approved a remediation', tone: 'good' },
  'fix.unapprove': { label: 'Withdrew an approval', tone: 'warn' },
  'fix.save': { label: 'Deferred a remediation', tone: 'idle' },
  'fix.unsave': { label: 'Returned a remediation to the queue', tone: 'idle' },
  'fix.run': { label: 'Executed a remediation', tone: 'info' },
  'fix.probe': { label: 'Verified a remediation', tone: 'info' },
  'triage.agree': { label: 'Confirmed a triage verdict', tone: 'good' },
  'triage.disagree': { label: 'Overrode a triage verdict', tone: 'warn' },
  'triage.reopen': { label: 'Reopened an incident', tone: 'warn' },
}
const TONE: Record<Tone, string> = { good: 'bg-teal', warn: 'bg-amber', bad: 'bg-rose', info: 'bg-sky', idle: 'bg-ink-3' }

const GROUPS = [
  { value: '', label: 'All actions' },
  { value: 'run', label: 'Pipeline runs' },
  { value: 'fix', label: 'Remediation' },
  { value: 'triage', label: 'Alert triage' },
  ...Object.entries(ACTIONS).map(([value, a]) => ({ value, label: a.label })),
]

const stamp = (iso: string) => new Date(iso).toLocaleString('en-GB', { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' })
const runUc = (ref: string | null) => ref?.match(/_(uc[134]|attack)$/)?.[1]

async function fetchActivity(action: string, q: string): Promise<{ items: ActivityEntry[]; total: number }> {
  const params = new URLSearchParams({ limit: '300' })
  if (action) params.set('action', action)
  if (q) params.set('q', q)
  const res = await fetch(`/api/activity?${params}`)
  if (!res.ok) throw new Error(`CyberSuite could not complete the request (error ${res.status})`)
  return res.json()
}

export function ActivityLog() {
  const [action, setAction] = useState('')
  const [text, setText] = useState('')
  const [q, setQ] = useState('')
  useEffect(() => {
    const t = setTimeout(() => setQ(text.trim()), 300)
    return () => clearTimeout(t)
  }, [text])
  const log = useQuery({ queryKey: ['activity', action, q], queryFn: () => fetchActivity(action, q), refetchInterval: 15_000 })
  const items = log.data?.items ?? []

  return (
    <div className="flex flex-col gap-5">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Activity log</h1>
        <p className="mt-1 max-w-3xl text-sm text-ink-3">
          A record of who started each agent pipeline and who approved, executed or verified its remediations and triage
          decisions, with name, email, date and time. Newest first.
        </p>
      </div>
      <Panel className="flex flex-col gap-3 p-5">
        <div className="flex flex-wrap items-center gap-2">
          <Choice label="Action" value={action} onChange={setAction} options={GROUPS} className="w-auto" />
          <label className="flex min-w-56 flex-1 items-center gap-2 rounded-lg border border-hairline-strong bg-field px-3 focus-within:border-blue/60 focus-within:ring-3 focus-within:ring-blue/15">
            <Search className="size-4 shrink-0 text-ink-3" />
            <input value={text} onChange={(e) => setText(e.target.value)} placeholder="Filter by person, email, agent or device…"
              className="h-9 min-w-0 flex-1 bg-transparent text-sm outline-none placeholder:text-ink-3" aria-label="Filter the activity log" />
          </label>
          {log.data && <span className="text-xs text-ink-3">{log.data.total > items.length ? `latest ${num(items.length)} of ${num(log.data.total)}` : `${num(log.data.total)} entries`}</span>}
        </div>
        {log.isLoading ? <div className="py-10 text-sm text-ink-3">Loading…</div>
          : log.error ? <Empty text={String((log.error as Error).message)} />
          : !items.length ? <Empty text={action || q ? 'No activity matches these filters.' : 'No activity recorded yet. Agent runs, remediation and triage actions appear here as soon as someone performs them.'} />
          : (
            <DTable head={[['When'], ['Who'], ['Action'], ['Agent'], ['Target'], ['Details']]} minWidth={1040}>
              {items.map((e) => {
                const known = ACTIONS[e.action] ?? { label: e.label || e.action, tone: 'idle' as const }
                const failed = e.outcome === 'failed' && (e.action === 'run.finish' || e.action === 'fix.run')
                const a = failed ? { ...known, label: e.action === 'run.finish' ? 'Pipeline run failed' : 'Remediation failed' } : known
                const tone: Tone = e.outcome === 'failed' ? 'bad' : e.outcome === 'refused' ? 'warn' : a.tone
                const uc = runUc(e.run)
                return (
                  <tr key={e.id}>
                    <td className="whitespace-nowrap"><div className="tabular text-xs">{stamp(e.ts)}</div><div className="text-xs text-ink-3">{ago(e.ts)}</div></td>
                    <td className="max-w-[240px]">
                      <div className={cn('truncate font-medium', e.name === 'Not recorded' ? 'text-ink-3' : 'text-ink')}
                        title={e.name === 'Not recorded' ? 'Started before CyberSuite recorded who starts each run' : undefined}>{e.name || e.email}</div>
                      {e.email && e.name !== e.email && <div className="truncate text-xs text-ink-3">{e.email}</div>}
                    </td>
                    <td className="whitespace-nowrap">
                      <span className="inline-flex items-center gap-1.5 rounded-full border border-hairline bg-well/60 py-0.5 pl-1.5 pr-2.5 text-xs font-medium text-ink-2">
                        <span className={cn('size-2 rounded-full', TONE[tone])} />{a.label}
                      </span>
                    </td>
                    <td className="whitespace-nowrap text-ink-2">{e.agent || '–'}</td>
                    <td className="max-w-[280px] text-ink-2">
                      <div className="line-clamp-2 break-words" title={e.target}>{e.target || '–'}</div>
                      {uc && <Link to={`/runs/${uc}`} className="text-xs text-sky hover:underline">open run</Link>}
                    </td>
                    <td className="max-w-[360px] text-xs text-ink-2">{e.detail || <span className="text-ink-3">–</span>}</td>
                  </tr>
                )
              })}
            </DTable>
          )}
      </Panel>
    </div>
  )
}
