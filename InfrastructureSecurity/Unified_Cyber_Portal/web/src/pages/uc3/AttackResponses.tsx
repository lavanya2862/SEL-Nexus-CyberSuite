import { Link, useSearchParams } from 'react-router-dom'
import { ArrowRight, ShieldAlert, X, Zap } from 'lucide-react'
import { FixCardSmall } from '@/components/NewFixes'
import { Empty, Panel } from '@/components/kit'
import { BasketBar } from './FixCentre'
import { FixDown, canApprove, fixTime, useFix, useFixAction, type FixRow } from '@/lib/fix'
import { dateTime, num } from '@/lib/format'
import { UC_DOT, UC_NAME } from '@/lib/runs'
import { GettingReady, useAutoStart } from '@/lib/services'
import { statusColor } from '@/lib/theme'
import { cn } from '@/lib/utils'

type Show = 'open' | 'saved' | 'all'
const SHOWS: [Show, string][] = [['open', 'To decide'], ['saved', 'Saved for later'], ['all', 'Everything']]
const shown = (r: FixRow, show: Show) => show === 'all' || (show === 'open' ? r.status === 'proposed' : r.status === 'saved')
const foundAt = (r: FixRow) => fixTime(r.found_by?.attack_detection) ?? ''

/**
 * Fix › Attack responses: the Attack Detection Agent's fixes, one per sign of attack (a Defender update,
 * quick scan and clean-up of that computer), newest run first. ?since=<ISO time> (from the run page) keeps the
 * responses that run proposed; ?show=open|saved|all picks which ones to list.
 */
export function AttackResponses() {
  const [params, setParams] = useSearchParams()
  const show: Show = SHOWS.some(([s]) => s === params.get('show')) ? (params.get('show') as Show) : 'open'
  const sinceRaw = params.get('since')
  const since = sinceRaw && !Number.isNaN(Date.parse(sinceRaw)) ? Date.parse(sinceRaw) : null
  const view = useFix()
  const act = useFixAction()
  const down = view.error instanceof FixDown
  const auto = useAutoStart(down, 'fix')
  const v = view.data
  const set = (key: string, value: string | null) => {
    const next = new URLSearchParams(params)
    if (value) next.set(key, value)
    else next.delete(key)
    setParams(next, { replace: true })
  }

  if (!v) {
    return (
      <Panel className="p-6">
        {down ? <GettingReady what="The fix engine" {...auto} /> : view.error
          ? <p className="text-sm" style={{ color: statusColor.critical }}>Could not load the fixes: {(view.error as Error).message}</p>
          : <div className="h-40 animate-pulse" />}
      </Panel>
    )
  }

  const all = v.rows.filter((r) => r.action === 'respond')
  const inRun = all.filter((r) => since == null || (foundAt(r) && Date.parse(foundAt(r)) >= since - 60_000))
  const rows = inRun.filter((r) => shown(r, show))
  const count = (s: Show) => inRun.filter((r) => shown(r, s)).length
  // one group per run: a run proposes all its new responses at the same moment
  const groups = new Map<string, FixRow[]>()
  for (const r of rows) groups.set(foundAt(r), [...(groups.get(foundAt(r)) ?? []), r])
  const ordered = [...groups.entries()].sort((a, b) => b[0].localeCompare(a[0]))
  const busy = act.isPending
  const approve = (ids: string[]) => ids.length && act.mutate({ action: 'approve', ids, method: v.default_method })

  return (
    <div className="flex flex-col gap-5">
      <Panel className="grid gap-6 p-6 md:grid-cols-[auto_minmax(0,1fr)] md:items-center">
        <div className="flex items-baseline gap-3">
          <span className="tabular text-[40px] leading-none tracking-tight">{num(all.filter((r) => r.status === 'proposed').length)}</span>
          <span className="text-sm text-ink-3">responses<br />to decide</span>
        </div>
        <div className="text-sm text-ink-2">
          <p>
            For every sign of attack the <span className="inline-flex items-center gap-1.5 font-medium"><span className={cn('size-2 rounded-full', UC_DOT.attack)} />{UC_NAME.attack}</span> finds,
            it proposes one fixed response: <b>update Defender, run a quick scan and remove what it finds</b> on that computer. Nothing runs until you press Fix and then Run fixes.
          </p>
          <p className="mt-1.5 text-xs text-ink-3">
            Isolating a computer is not offered (the agent has no permission for it): do that in Defender itself. The evidence on each card comes from Defender, never from the AI.
          </p>
        </div>
      </Panel>

      {since != null && (
        <div className="flex flex-wrap items-center gap-2 rounded-xl border border-signal/40 bg-signal/10 px-4 py-2.5 text-sm">
          <span className={cn('size-2 rounded-full', UC_DOT.attack)} />
          <span>Showing the responses the <b>{UC_NAME.attack}</b> proposed in its run of <b>{dateTime(new Date(since).toISOString())}</b> (new in that run).</span>
          <button onClick={() => set('since', null)} className="ml-auto inline-flex items-center gap-1 rounded-lg px-2 py-1 text-xs font-medium hover:bg-panel">
            <X className="size-3.5" /> Show all responses
          </button>
        </div>
      )}

      <div className="flex flex-wrap gap-2 text-sm">
        {SHOWS.map(([s, label]) => (
          <button key={s} onClick={() => set('show', s === 'open' ? null : s)} aria-pressed={show === s}
            className={cn('flex items-center gap-2 rounded-full border px-3.5 py-1.5', show === s ? 'pill-on' : 'border-hairline bg-panel hover:bg-well')}>
            {label} <span className="tabular opacity-60">{count(s)}</span>
          </button>
        ))}
      </div>

      {act.error && <p className="text-sm" style={{ color: statusColor.critical }}>{(act.error as Error).message}</p>}

      {ordered.length === 0 && (
        <Empty text={show === 'open' ? 'Nothing to decide: every response has a decision.' : show === 'saved' ? 'No responses saved for later.' : 'No signs of attack, so no responses yet.'} />
      )}

      {ordered.map(([at, rs]) => {
        const fixable = rs.filter((r) => canApprove(r) && r.status !== 'failed')
        const toDecide = rs.filter((r) => r.status === 'proposed').length
        return (
          <Panel key={at || 'earlier'} className="p-5">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="flex min-w-0 items-center gap-2.5">
                <ShieldAlert className="size-5 shrink-0" style={{ color: statusColor.critical }} />
                <div className="min-w-0">
                  <div className="font-semibold tracking-tight">{at ? `Run of ${dateTime(at)}` : 'Earlier runs'}</div>
                  <div className="text-xs text-ink-3">
                    {num(rs.length)} response{rs.length === 1 ? '' : 's'} shown
                    {toDecide > 0 && <> · <b style={{ color: statusColor.warning }}>{toDecide} to decide</b></>}
                  </div>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <Link to="/runs/attack" className="inline-flex items-center gap-1 rounded-lg px-2.5 py-1.5 text-xs font-medium text-ink-2 hover:bg-well">
                  Open the agent <ArrowRight className="size-3.5" />
                </Link>
                {fixable.length > 0 && (
                  <button onClick={() => approve(fixable.map((r) => r.fix_id))} disabled={busy} className="btn-blue inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-semibold disabled:opacity-50">
                    <Zap className="size-3.5" /> Fix all {fixable.length}
                  </button>
                )}
              </div>
            </div>
            <ul className="mt-4 grid grid-cols-1 gap-3 md:grid-cols-2 2xl:grid-cols-3">
              {rs.map((r) => (
                <FixCardSmall key={r.fix_id} r={r} busy={busy} onFix={() => approve([r.fix_id])}
                  onSave={() => act.mutate({ action: 'save', ids: [r.fix_id] })}
                  onUndo={(action) => act.mutate({ action, ids: [r.fix_id] })} />
              ))}
            </ul>
          </Panel>
        )
      })}
      <BasketBar v={v} />
    </div>
  )
}
