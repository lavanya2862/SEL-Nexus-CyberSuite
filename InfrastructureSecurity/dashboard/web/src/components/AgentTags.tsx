import { useSearchParams } from 'react-router-dom'
import { X } from 'lucide-react'
import { fixTime, type FixRow, type FixSource } from '@/agents/fixes/data'
import { dateTime, num } from '@/lib/format'
import { AGENT_DOT, AGENT_NAME } from '@/lib/runs'
import { cn } from '@/lib/utils'

/**
 * Which agent gave a fix (Fix's Updates & upgrades and Security settings).
 * An app update or setting is the Vulnerability Agent's (Defender's vulnerability list); when a threat in the news
 * targets that app on that computer it also carries the Threat Intel Agent: one card, one decision for both.
 * ?agent=vulnerability|threat_intel filters by agent; ?since=<ISO time> keeps the fixes that agent proposed from then on (the run page
 * links here with its run's start time, so you see exactly that run's new fixes).
 */
export type TagAgent = 'vulnerability' | 'threat_intel'
const SOURCE: Record<TagAgent, FixSource> = { vulnerability: 'vulnerability', threat_intel: 'threat_intel' }

const isThreat = (r: FixRow) => (r.threats?.length ?? 0) > 0
export const belongs = (r: FixRow, a: TagAgent) => r.action !== 'respond' && (a === 'vulnerability' || isThreat(r))
/** When the agent's run proposed it (UTC ms); null = before this was recorded */
const foundAt = (r: FixRow, a: TagAgent) => {
  const t = fixTime(r.found_by?.[SOURCE[a]])
  return t ? new Date(t).getTime() : null
}

export function useAgentFilter() {
  const [params, setParams] = useSearchParams()
  const agent = (['vulnerability', 'threat_intel'] as const).find((a) => a === params.get('agent')) ?? null
  const sinceRaw = params.get('since')
  const since = sinceRaw && !Number.isNaN(Date.parse(sinceRaw)) ? Date.parse(sinceRaw) : null
  /** this row passes the agent filter (and, with ?since, was proposed by that agent since then) */
  const matches = (r: FixRow) => {
    if (!agent) return true
    if (!belongs(r, agent)) return false
    if (since == null) return true
    const at = foundAt(r, agent)
    return at != null && at >= since - 60_000
  }
  const set = (a: TagAgent | null) => {
    const next = new URLSearchParams(params)
    next.delete('since')
    if (a) next.set('agent', a)
    else next.delete('agent')
    setParams(next, { replace: true })
  }
  const clearSince = () => { const next = new URLSearchParams(params); next.delete('since'); setParams(next, { replace: true }) }
  return { agent, since, matches, set, clearSince, isNew: (r: FixRow) => since != null && !!agent && matches(r) }
}

/** The agent chips (with how many cards each has) and, from a run page link, which run is shown */
export function AgentFilterBar({ filter, counts, total, what }: {
  filter: ReturnType<typeof useAgentFilter>; counts: Record<TagAgent, number>; total: number; what: string
}) {
  const { agent } = filter
  return (
    <div className="flex flex-col gap-2">
      <div className="flex flex-wrap items-center gap-2 text-sm" role="group" aria-label="Proposed by agent">
        <span className="text-xs font-medium text-ink-3">Proposed by</span>
        <Chip on={!agent} onClick={() => filter.set(null)} label="All agents" n={total} />
        {(['vulnerability', 'threat_intel'] as const).map((a) => (
          <Chip key={a} on={agent === a} onClick={() => filter.set(a)} label={AGENT_NAME[a]} n={counts[a]} dot={AGENT_DOT[a]}
            title={a === 'threat_intel' ? 'Remediations for applications targeted by current threat intelligence' : "Everything in Defender's vulnerability list"} />
        ))}
      </div>
      <RunBanner filter={filter} what={what} />
    </div>
  )
}

/** From a run page link (?agent=…&since=…): which run's fixes are shown, with a way back to all of them */
export function RunBanner({ filter, what }: { filter: ReturnType<typeof useAgentFilter>; what: string }) {
  const { agent, since } = filter
  if (!agent || since == null) return null
  return (
    <div className="flex flex-wrap items-center gap-2 rounded-xl border border-signal/40 bg-signal/10 px-4 py-2.5 text-sm">
      <span className={cn('size-2 rounded-full', AGENT_DOT[agent])} />
      <span>Showing the {what} the <b>{AGENT_NAME[agent]}</b> proposed in its run of <b>{dateTime(new Date(since).toISOString())}</b>{' '}(new in that run).</span>
      <button onClick={filter.clearSince} className="ml-auto inline-flex items-center gap-1 rounded-lg px-2 py-1 text-xs font-medium hover:bg-panel">
        <X className="size-3.5" /> Show all from this agent
      </button>
    </div>
  )
}

function Chip({ on, onClick, label, n, dot, title }: { on: boolean; onClick: () => void; label: string; n: number; dot?: string; title?: string }) {
  return (
    <button onClick={onClick} aria-pressed={on} title={title}
      className={cn('flex items-center gap-2 rounded-full border px-3.5 py-1.5', on ? 'pill-on' : 'border-hairline bg-panel hover:bg-well')}>
      {dot && <span className={cn('size-2 rounded-full', dot)} />}{label} <span className="tabular opacity-60">{n}</span>
    </button>
  )
}

/** The tags on a card: which agents gave these fixes, when, and (Threat Intel) the threat in the news.
 *  inNews: how many of the app's vulnerabilities a threat in the news named before the Vulnerability Agent found them
 *  (all of them, not just the fix rows' top 3); 0 hides the Threat Intel tag. */
export function AgentTags({ rows, inNews }: { rows: FixRow[]; inNews?: number }) {
  const mine = rows.filter((r) => r.action !== 'respond')
  if (!mine.length) return null
  const latest = (a: TagAgent) => {
    const times = mine.filter((r) => belongs(r, a)).map((r) => foundAt(r, a)).filter((t): t is number => t != null)
    return times.length ? Math.max(...times) : null
  }
  const threats = [...new Map(mine.flatMap((r) => r.threats ?? []).map((t) => [t.id, t])).values()]
  const news = inNews ?? threats.length
  return (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs">
      <span className="text-ink-3">Found by</span>
      <Tag agent="vulnerability" at={latest('vulnerability')} />
      {news > 0 && (
        <Tag agent="threat_intel" at={latest('threat_intel')} note={inNews !== undefined ? `${num(inNews)} in threat intel` : undefined}
          title={threats.map((t) => t.title).join('\n') || undefined} />
      )}
    </div>
  )
}

/** One agent: its dot and name (the run time is in the tooltip, so the card stays short) */
function Tag({ agent, at, note, title }: { agent: TagAgent; at: number | null; note?: string; title?: string }) {
  const when = at ? `Proposed in the ${AGENT_NAME[agent]}'s run of ${dateTime(new Date(at).toISOString())}` : 'Proposed before agents were recorded'
  return (
    <span title={title ? `${when}\n\n${title}` : when} className="inline-flex max-w-full items-center gap-1.5 text-ink-2">
      <span className={cn('size-2 shrink-0 rounded-full', AGENT_DOT[agent])} />
      <span className="truncate font-medium">{AGENT_NAME[agent]}</span>
      {note && <span className="shrink-0 text-ink-3">· {note}</span>}
    </span>
  )
}

/** One computer's line: when it was proposed, and a "new in this run" mark when a run page linked here */
export function RowFound({ r, fresh }: { r: FixRow; fresh?: boolean }) {
  const at = r.action === 'respond' ? null : foundAt(r, 'vulnerability')
  if (!at && !fresh) return null
  return (
    <div className="mt-0.5 flex items-center gap-1.5 text-[11px] text-ink-3">
      {fresh && <span className="rounded bg-signal/15 px-1 font-semibold text-signal">New in this run</span>}
      {at && <span>proposed {dateTime(new Date(at).toISOString())}</span>}
    </div>
  )
}
