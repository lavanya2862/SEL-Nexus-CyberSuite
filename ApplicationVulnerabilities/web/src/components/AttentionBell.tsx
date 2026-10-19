// The bell in the top bar: everything that is waiting for a person (approvals, open fixes, errors), from the Action
// center. Same look as the Defender & Infrastructure portal's notification bell.
import { useNavigate } from 'react-router-dom'
import { Bell, CircleAlert, ShieldCheck, Wrench } from 'lucide-react'
import { DropdownMenu, DropdownMenuContent, DropdownMenuTrigger } from '@/components/ui/dropdown-menu'
import { useAttention } from '@/lib/api'
import { statusColor } from '@/lib/theme'

export function AttentionBell() {
  const navigate = useNavigate()
  const { data, isError } = useAttention()
  const c = data?.counts
  const total = c ? c.approvals + c.errors : 0 // open fixes are a to-do list, not an alert, so they don't light the bell
  const rows = c ? [
    { n: c.approvals, icon: ShieldCheck, color: 'var(--sky)', title: 'Approvals waiting', text: c.approvals ? 'Fix sets ready for your decision' : 'Nothing is waiting for you', to: '/approvals' },
    { n: c.fixes_needed, icon: Wrench, color: statusColor.warning, title: 'Fixes needed', text: c.fixes_needed ? 'Issues the agents could not fix' : 'Every selected issue was fixed', to: '/fixes' },
    { n: c.errors, icon: CircleAlert, color: statusColor.critical, title: 'Errors', text: c.errors ? 'Problems with runs, scanners or setup' : 'No errors', to: '/errors' },
  ] : []
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <button className="relative grid size-9 place-items-center rounded-lg hover:bg-well" aria-label={total ? `${total} things need your attention` : 'Needs your attention'}>
          <Bell className="size-[18px]" />
          {total > 0 && (
            <span className="tabular absolute -right-0.5 -top-0.5 grid h-4 min-w-4 place-items-center rounded-full bg-signal px-1 text-[10px] font-semibold text-white">
              {total > 99 ? '99+' : total}
            </span>
          )}
        </button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-[min(360px,calc(100vw-2rem))] p-0">
        <div className="border-b border-hairline px-4 py-3">
          <div className="text-sm font-semibold text-ink">Needs your attention</div>
          <div className="text-xs text-ink-3">From the Action center · updates by itself</div>
        </div>
        <div className="py-1">
          {isError && <p className="px-4 py-6 text-sm text-ink-3">Couldn’t load this right now.</p>}
          {rows.map((r) => (
            <button key={r.to} onClick={() => navigate(r.to)} className="flex w-full items-center gap-3 px-4 py-2.5 text-left hover:bg-well">
              <span className="grid size-8 shrink-0 place-items-center rounded-lg bg-well"><r.icon className="size-4" style={{ color: r.color }} /></span>
              <span className="min-w-0 flex-1">
                <span className="block text-sm font-medium text-ink">{r.title}</span>
                <span className="block text-xs text-ink-3">{r.text}</span>
              </span>
              <span className="tabular text-lg font-medium" style={{ color: r.n ? r.color : 'var(--ink-3)' }}>{r.n}</span>
            </button>
          ))}
        </div>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
