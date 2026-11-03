// The notification bell in the top bar: enterprise notifications for pipeline events
// (initiated, completed, failed) with authenticated initiator details and live status.
import { useNavigate } from 'react-router-dom'
import { Bell, CheckCircle2, Clock, Loader2, XCircle } from 'lucide-react'
import { DropdownMenu, DropdownMenuContent, DropdownMenuTrigger } from '@/components/ui/dropdown-menu'
import { useJobs } from '@/lib/api'
import { ago, stamp } from '@/lib/format'
import { statusColor } from '@/lib/theme'
import type { Job } from '@/lib/types'

export function AttentionBell() {
  const navigate = useNavigate()
  const { data, isLoading, isError } = useJobs({ limit: 15 }, 4000)
  const items = data?.items ?? []
  const total = items.length

  const getEvent = (j: Job) => {
    const who = j.started_by?.name || j.started_by?.email || 'System'
    if (j.status === 'running') {
      return {
        title: 'Pipeline initiated',
        text: j.repo,
        by: `Initiated by ${who}`,
        when: j.started_at || j.created_at,
        icon: Loader2,
        animate: true,
        color: 'var(--sky)',
      }
    }
    if (j.status === 'completed') {
      return {
        title: 'Pipeline completed',
        text: j.repo,
        by: `Initiated by ${who}`,
        when: j.finished_at || j.created_at,
        icon: CheckCircle2,
        animate: false,
        color: statusColor.good,
      }
    }
    if (j.status === 'failed') {
      return {
        title: 'Pipeline failed',
        text: j.repo,
        by: `Initiated by ${who}`,
        when: j.finished_at || j.created_at,
        icon: XCircle,
        animate: false,
        color: statusColor.critical,
      }
    }
    if (j.status === 'queued') {
      return {
        title: 'Pipeline queued',
        text: j.repo,
        by: `Initiated by ${who}`,
        when: j.created_at,
        icon: Clock,
        animate: false,
        color: statusColor.warning,
      }
    }
    return {
      title: 'Pipeline cancelled',
      text: j.repo,
      by: `Initiated by ${who}`,
      when: j.finished_at || j.created_at,
      icon: Clock,
      animate: false,
      color: 'var(--ink-3)',
    }
  }

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <button
          className="relative grid size-9 place-items-center rounded-lg text-ink-2 hover:bg-well hover:text-ink transition-colors"
          aria-label={total ? `${total} notifications` : 'Notifications'}
        >
          <Bell className="size-[18px]" />
          {total > 0 && (
            <span className="tabular absolute -top-1 -right-1 flex h-4 min-w-4 items-center justify-center rounded-full bg-blue px-1 text-[10px] font-semibold text-white shadow-sm ring-2 ring-panel">
              {total > 99 ? '99+' : total}
            </span>
          )}
        </button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-[min(420px,calc(100vw-2rem))] p-0 max-h-[85vh] flex flex-col">
        <div className="flex items-center justify-between border-b border-hairline px-4 py-3 shrink-0">
          <div className="text-sm font-semibold text-ink">Notifications</div>
          <span className="text-xs text-ink-3">Pipeline activity</span>
        </div>
        <div className="overflow-y-auto py-1 divide-y divide-hairline">
          {isLoading && (
            <div className="flex items-center justify-center gap-2 px-4 py-8 text-sm text-ink-3">
              <Loader2 className="size-4 animate-spin" /> Loading notifications…
            </div>
          )}
          {isError && (
            <p className="px-4 py-6 text-sm text-ink-3">Unable to load notifications. Please try again shortly.</p>
          )}
          {!isLoading && !isError && items.length === 0 && (
            <p className="px-4 py-8 text-center text-sm text-ink-3">No recent pipeline activity.</p>
          )}
          {items.map((j) => {
            const ev = getEvent(j)
            const Icon = ev.icon
            return (
              <button
                key={j.id}
                onClick={() => navigate(`/runs/${j.id}`)}
                className="flex w-full items-start gap-3 px-4 py-3 text-left hover:bg-well transition-colors"
              >
                <span
                  className="grid size-8 shrink-0 place-items-center rounded-lg mt-0.5"
                  style={{ background: 'var(--well)' }}
                >
                  <Icon className={`size-4 ${ev.animate ? 'animate-spin' : ''}`} style={{ color: ev.color }} />
                </span>
                <span className="min-w-0 flex-1">
                  <span className="flex items-baseline justify-between gap-2">
                    <b className="text-sm font-medium text-ink">{ev.title}</b>
                    <span className="whitespace-nowrap text-[11px] text-ink-3" title={ev.when ? stamp(ev.when) : undefined}>
                      {ev.when ? ago(ev.when) : '–'}
                    </span>
                  </span>
                  <span className="block text-xs font-mono text-ink-2 truncate mt-0.5" title={j.repo}>
                    {ev.text}
                  </span>
                  <span className="block text-xs text-ink-3 mt-1">
                    {ev.by}
                  </span>
                </span>
              </button>
            )
          })}
        </div>
        <div className="border-t border-hairline p-2 text-center bg-panel shrink-0">
          <button
            onClick={() => navigate('/runs')}
            className="text-xs font-medium text-sky hover:underline py-1 px-2"
          >
            View all scans in scan history →
          </button>
        </div>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
