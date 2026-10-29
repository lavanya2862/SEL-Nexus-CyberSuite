import { useEffect, useState, type ComponentType } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { Bell, CheckCheck, Crosshair, Database, History, Siren, Wrench, Zap } from 'lucide-react'
import { DropdownMenu, DropdownMenuContent, DropdownMenuTrigger } from '@/components/ui/dropdown-menu'
import { ago } from '@/lib/format'
import { statusColor } from '@/lib/theme'
import { cn } from '@/lib/utils'

/* The bell: what the assistant raised or did, newest first (GET /api/notifications, refreshed every 15 s).
   "New" = after the last time this browser opened the bell (remembered per browser). */

interface Note {
  id: string; at: string; kind: 'threat' | 'incident' | 'action' | 'agent' | 'fix' | 'quality'
  level: 'critical' | 'high' | 'medium' | 'low' | 'info'; title: string; detail: string; link: string | null
}

const KIND_ICON: Record<Note['kind'], ComponentType<{ className?: string; style?: React.CSSProperties }>> = {
  threat: Crosshair, incident: Siren, action: Zap, agent: History, fix: Wrench, quality: Database,
}
const LEVEL_COLOR: Record<Note['level'], string> = {
  critical: statusColor.critical, high: statusColor.serious, medium: statusColor.warning, low: 'var(--ink-3)', info: 'var(--ink-3)',
}
const SEEN_KEY = 'portal-notes-seen'

function readSeen(): string {
  try {
    return localStorage.getItem(SEEN_KEY) ?? ''
  } catch {
    return ''
  }
}

export function NotificationBell() {
  const navigate = useNavigate()
  const [open, setOpen] = useState(false)
  const [seen, setSeen] = useState(readSeen)
  const { data, isError } = useQuery({
    queryKey: ['notifications'],
    queryFn: async () => {
      const res = await fetch('/api/notifications')
      if (!res.ok) throw new Error(`CyberSuite could not complete the request (error ${res.status})`)
      return (await res.json()) as { items: Note[] }
    },
    refetchInterval: 15_000,
  })
  const items = data?.items ?? []
  const unread = items.filter((n) => n.at > seen).length
  const newest = items[0]?.at ?? ''

  // Opening the bell marks everything up to now as read (the dots stay visible while it is open).
  useEffect(() => {
    if (!open || !newest || newest <= seen) return
    try {
      localStorage.setItem(SEEN_KEY, newest)
    } catch {
      /* not essential */
    }
  }, [open, newest, seen])
  const onOpenChange = (o: boolean) => {
    setOpen(o)
    if (!o && newest) setSeen(newest > seen ? newest : seen)
  }

  return (
    <DropdownMenu open={open} onOpenChange={onOpenChange}>
      <DropdownMenuTrigger asChild>
        <button className="relative grid size-9 place-items-center rounded-lg hover:bg-well" aria-label={unread ? `${unread} new notifications` : 'Notifications'}>
          <Bell className="size-[18px]" />
          {unread > 0 && (
            <span className="tabular absolute -right-0.5 -top-0.5 grid h-4 min-w-4 place-items-center rounded-full bg-signal px-1 text-[10px] font-semibold text-white">
              {unread > 99 ? '99+' : unread}
            </span>
          )}
        </button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-[min(400px,calc(100vw-2rem))] p-0">
        <div className="flex items-center justify-between border-b border-hairline px-4 py-3">
          <div>
            <div className="text-sm font-semibold text-ink">Notifications</div>
            <div className="text-xs text-ink-3">{unread ? `${unread} new` : 'No new notifications'} · updates by itself</div>
          </div>
          {unread > 0 && <CheckCheck className="size-4 text-ink-3" aria-hidden />}
        </div>
        <div className="max-h-[min(480px,70svh)] overflow-y-auto py-1">
          {isError && <p className="px-4 py-6 text-sm text-ink-3">Unable to load notifications.</p>}
          {!isError && !items.length && <p className="px-4 py-6 text-sm text-ink-3">No notifications. Alerts and automated actions will appear here.</p>}
          {items.map((n) => {
            const Icon = KIND_ICON[n.kind] ?? Bell
            const isNew = n.at > seen
            return (
              <button
                key={n.id}
                onClick={() => { onOpenChange(false); if (n.link) navigate(n.link) }}
                className={cn('flex w-full items-start gap-3 px-4 py-2.5 text-left hover:bg-well', isNew && 'bg-well/60')}
              >
                <span className="mt-0.5 grid size-7 shrink-0 place-items-center rounded-lg bg-well">
                  <Icon className="size-3.5" style={{ color: LEVEL_COLOR[n.level] }} />
                </span>
                <span className="min-w-0 flex-1">
                  <span className="flex items-start justify-between gap-2">
                    <span className={cn('text-sm leading-snug text-ink-2', isNew && 'font-medium text-ink')}>{n.title}</span>
                    {isNew && <span className="mt-1.5 size-2 shrink-0 rounded-full bg-signal" aria-label="new" />}
                  </span>
                  {n.detail && <span className="mt-0.5 line-clamp-2 block text-xs leading-snug text-ink-3">{n.detail}</span>}
                  <span className="mt-0.5 block text-[11px] text-ink-3">{ago(n.at)}</span>
                </span>
              </button>
            )
          })}
        </div>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
