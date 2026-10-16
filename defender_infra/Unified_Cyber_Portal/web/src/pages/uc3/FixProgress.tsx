import { Link } from 'react-router-dom'
import { ArrowLeft, Check, CheckCircle2, Clock, Loader2, Minus, Monitor, ShieldCheck, Wrench, X, XCircle } from 'lucide-react'
import { Empty, Panel } from '@/components/kit'
import { Skeleton } from '@/components/ui/skeleton'
import { ago, dateTime, num } from '@/lib/format'
import { ACTION_LABEL, FixDown, STATUS, isSetting, useFix, type FixRow, type FixView } from '@/lib/fix'
import { GettingReady, useAutoStart } from '@/lib/services'
import { statusColor } from '@/lib/theme'
import { cn } from '@/lib/utils'

// The four stops every fix passes, left to right
const STOPS = ['Waiting', 'Fixing', 'Fixed', 'Confirmed by Defender'] as const
type StopState = 'todo' | 'now' | 'done' | 'failed'

function stops(r: FixRow): StopState[] {
  switch (r.status) {
    case 'queued': return ['now', 'todo', 'todo', 'todo']
    case 'running': return ['done', 'now', 'todo', 'todo']
    case 'done': return ['done', 'done', 'done', 'now']
    case 'verified': return ['done', 'done', 'done', 'done']
    case 'failed': return ['done', 'failed', 'todo', 'todo']
    case 'still_there': return ['done', 'done', 'done', 'failed']
    default: return ['todo', 'todo', 'todo', 'todo']
  }
}

/** The fixes of the latest run: everything started within 2 hours of the newest start (a run takes minutes). */
function latestRun(v: FixView): FixRow[] {
  const started = v.rows.filter((r) => r.started_at)
  if (!started.length) return []
  const newest = Math.max(...started.map((r) => new Date(r.started_at!).getTime()))
  return started.filter((r) => newest - new Date(r.started_at!).getTime() < 2 * 3600_000)
}

/** Fix & protect › Fix progress: the whole run on one screen, one lane per computer. */
export function FixProgress() {
  const { data: v, error, isLoading } = useFix()
  const auto = useAutoStart(error instanceof FixDown, 'fix')
  return (
    <div className="flex flex-col gap-5">
      <Link to="/fixes" className="inline-flex w-fit items-center gap-1.5 text-sm text-ink-3 hover:text-ink"><ArrowLeft className="size-4" /> Fix & protect</Link>
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Fix progress</h1>
        <p className="mt-1 text-sm text-ink-3">Every fix moves forward as the computer reports back. You can leave this page; the fixes keep going.</p>
      </div>
      {isLoading ? <Skeleton className="h-64 rounded-2xl" /> : error ? (
        <Panel className="p-6">
          {error instanceof FixDown ? <GettingReady what="fix progress" {...auto} /> : <Empty text={`Could not load the fixes: ${(error as Error).message}`} />}
        </Panel>
      ) : v && <Body v={v} />}
    </div>
  )
}

function Body({ v }: { v: FixView }) {
  const rows = latestRun(v)
  const live = v.worker.running || v.worker.elsewhere || rows.some((r) => r.status === 'queued' || r.status === 'running')
  const finished = rows.filter((r) => !['queued', 'running'].includes(r.status)).length
  const pct = rows.length ? Math.round((finished / rows.length) * 100) : 0
  const devices = [...new Set(rows.map((r) => r.device_name))].sort()
  const count = (pred: (r: FixRow) => boolean) => rows.filter(pred).length
  const startedAt = rows.length ? rows.map((r) => r.started_at!).sort()[0] : null

  return (
    <>
      {/* status + bar */}
      <Panel className="p-6">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="flex items-start gap-3">
            {live ? <Loader2 className="mt-0.5 size-6 animate-spin text-sky" /> : <CheckCircle2 className="mt-0.5 size-6" style={{ color: statusColor.good }} />}
            <div>
              <h2 className="text-xl font-semibold tracking-tight">
                {live ? (v.worker.task === 'probe' ? 'Checking the computers…' : 'Fixing now…') : rows.length ? 'Last fix run finished' : 'No fixes have run yet'}
              </h2>
              <p key={v.worker.step || v.worker.message} className="mt-0.5 text-sm text-ink-3 animate-in fade-in slide-in-from-left-1 duration-300">
                {live ? v.worker.step || 'Starting' : v.worker.message || 'Put fixes in the basket on Fix & protect, then press Run fixes.'}
                {startedAt && <> · started {dateTime(startedAt)}</>}
              </p>
            </div>
          </div>
          {rows.length > 0 && (
            <div className="text-right">
              <div className="tabular text-3xl font-semibold tracking-tight">{pct}%</div>
              <div className="text-xs text-ink-3">{finished} of {rows.length} fixes finished</div>
            </div>
          )}
        </div>
        {rows.length > 0 && (
          <div className="mt-5 h-2 overflow-hidden rounded-full bg-well">
            <div className="relative h-full rounded-full bg-sky transition-[width] duration-700 ease-out" style={{ width: `${Math.max(pct, live ? 4 : 0)}%` }}>
              {live && <span className="absolute inset-0 animate-[portal-shimmer_1.4s_linear_infinite] bg-[linear-gradient(90deg,transparent,rgba(255,255,255,.55),transparent)] bg-[length:50%_100%] bg-no-repeat" />}
            </div>
          </div>
        )}
      </Panel>

      {rows.length > 0 && (
        <div className="card-row gap-4 [--card-min:170px]">
          {[
            { icon: Wrench, label: 'Fixed', value: count((r) => r.status === 'done' || r.status === 'verified'), color: 'var(--sky)' },
            { icon: ShieldCheck, label: 'Confirmed by Defender', value: count((r) => r.status === 'verified'), color: statusColor.good },
            { icon: XCircle, label: 'Failed', value: count((r) => r.status === 'failed' || r.status === 'still_there'), color: statusColor.critical },
            { icon: Clock, label: 'Still to do', value: count((r) => r.status === 'queued' || r.status === 'running'), color: 'var(--ink-3)' },
          ].map((t) => (
            <Panel key={t.label} className="p-5">
              <div className="flex items-center gap-2 text-sm text-ink-2"><t.icon className="size-4" style={{ color: t.color }} /> {t.label}</div>
              <div className="tabular mt-2 text-3xl font-semibold tracking-tight">{t.value}</div>
            </Panel>
          ))}
        </div>
      )}

      {/* one lane per computer, each fix a left-to-right track */}
      {devices.map((d) => (
        <Panel key={d} className="p-6">
          <div className="flex items-center gap-2">
            <Monitor className="size-4 text-ink-3" />
            <h3 className="font-semibold tracking-tight">{d}</h3>
            <span className="text-xs text-ink-3">· {rows.filter((r) => r.device_name === d).length === 1 ? '1 fix' : `${rows.filter((r) => r.device_name === d).length} fixes`}</span>
          </div>
          <ul className="mt-4 flex flex-col divide-y divide-hairline">
            {rows.filter((r) => r.device_name === d).map((r) => <FixTrack key={r.fix_id} r={r} />)}
          </ul>
        </Panel>
      ))}

      {!live && rows.some((r) => r.status === 'done') && (
        <Panel className="flex items-start gap-3 px-5 py-4 text-sm text-ink-2">
          <ShieldCheck className="mt-0.5 size-5 shrink-0" style={{ color: statusColor.good }} />
          <p><span className="font-medium text-ink">What happens next:</span> Defender rescans the computer and the vulnerability agent picks that up, usually within a few hours. Each fix then turns to “Confirmed by Defender”. Leave a switched-on computer running until then.</p>
        </Panel>
      )}

      {/* activity log */}
      <Panel className="p-6">
        <h3 className="font-semibold tracking-tight">Activity</h3>
        <p className="mt-1 text-sm text-ink-3">What the fixer did, newest first.</p>
        {v.events.length ? (
          <ol className="mt-4 flex max-h-[420px] flex-col gap-2 overflow-y-auto">
            {[...v.events].reverse().slice(0, 60).map((e, i) => (
              <li key={i} className="flex gap-3 text-sm">
                <span className="tabular w-28 shrink-0 text-xs text-ink-3">{ago(e.at)}</span>
                <span className="text-ink-2">{e.text}</span>
              </li>
            ))}
          </ol>
        ) : <p className="mt-4 text-sm text-ink-3">Nothing yet.</p>}
      </Panel>

      {v.impact && (
        <p className="text-xs text-ink-3">
          All fixes so far clear {num(v.impact.findings_cleared)} of {num(v.impact.findings_open + v.impact.findings_cleared)} findings and {v.impact.kev_cleared} known exploited holes.
        </p>
      )}
    </>
  )
}

function FixTrack({ r }: { r: FixRow }) {
  const st = stops(r)
  return (
    <li className="grid grid-cols-1 gap-3 py-4 md:grid-cols-[minmax(0,15rem)_minmax(0,1fr)] md:items-center">
      <div className="min-w-0">
        <div className="truncate text-sm font-medium">{ACTION_LABEL[r.action]} {r.app}</div>
        <div className="truncate text-xs text-ink-3">{isSetting(r) ? 'Security setting (not a vulnerability)' : <>{r.version} · clears {num(r.findings)} findings{r.kev ? ` · ${r.kev} exploited` : ''}</>}</div>
      </div>
      <div className="min-w-0">
        <ol className="flex items-start">
          {STOPS.map((label, i) => (
            <li key={label} className="relative flex flex-1 flex-col items-center text-center">
              {i > 0 && (
                <span className="absolute right-1/2 top-3 h-0.5 w-full -translate-y-1/2 overflow-hidden bg-hairline" aria-hidden>
                  <span className={cn('block h-full bg-sky transition-[width] duration-700 ease-out', st[i] === 'todo' ? 'w-0' : 'w-full')} />
                </span>
              )}
              <Stop s={st[i]} />
              <span className={cn('mt-1.5 text-[11px] leading-tight', st[i] === 'todo' ? 'text-ink-3' : 'text-ink-2', st[i] === 'now' && 'font-medium text-ink')}>{label}</span>
            </li>
          ))}
        </ol>
        {(r.message || r.status === 'failed') && (
          <p key={r.status} className="mt-2 text-xs text-ink-3 animate-in fade-in duration-300" style={r.status === 'failed' ? { color: statusColor.critical } : undefined}>
            {r.message ?? STATUS[r.status].label}
          </p>
        )}
      </div>
    </li>
  )
}

function Stop({ s }: { s: StopState }) {
  if (s === 'now')
    return (
      <span className="relative z-10 grid size-6 place-items-center rounded-full bg-panel">
        <span className="absolute inset-0 animate-ping rounded-full bg-sky/30" />
        <span className="size-3 rounded-full bg-sky" />
      </span>
    )
  if (s === 'done') return <span className="relative z-10 grid size-6 place-items-center rounded-full bg-sky text-white animate-in zoom-in-50 duration-300"><Check className="size-3.5" strokeWidth={3} /></span>
  if (s === 'failed') return <span className="relative z-10 grid size-6 place-items-center rounded-full text-white" style={{ background: statusColor.critical }}><X className="size-3.5" strokeWidth={3} /></span>
  return <span className="relative z-10 grid size-6 place-items-center rounded-full border-2 border-hairline bg-panel text-ink-3"><Minus className="size-3 opacity-0" /></span>
}
