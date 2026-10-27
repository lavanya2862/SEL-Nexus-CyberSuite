// Shared building blocks for every portal page (one look, no copies per page).
import type { ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { ArrowRight, Info } from 'lucide-react'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { chartTokens, useTheme, type ChartTokens } from '@/lib/theme'
import { cn } from '@/lib/utils'

/** "Follow this vulnerability": a small link to the same item on the next tab (Vulnerabilities → Threats → Fix). */
export function HopLink({ to, children, title }: { to: string; children: ReactNode; title?: string }) {
  return (
    <Link to={to} title={title} className="inline-flex shrink-0 items-center gap-1 whitespace-nowrap rounded-md border border-hairline px-2 py-1 text-[11px] font-semibold text-ink-2 hover:bg-well hover:text-ink">
      {children} <ArrowRight className="size-3" />
    </Link>
  )
}

export function Panel({ className, children, id }: { className?: string; children: ReactNode; id?: string }) {
  return <section id={id} className={cn('glass-card rounded-[20px]', className)}>{children}</section>
}

export function Chip({ children, tone }: { children: ReactNode; tone?: 'signal' }) {
  return (
    <span className={cn('tabular inline-flex items-center rounded-md border border-hairline bg-well px-2 py-1 text-xs font-medium text-ink-2', tone === 'signal' && 'text-signal')}>
      {children}
    </span>
  )
}

export function Tabs<T extends string>({ tabs, value, onChange }: { tabs: [T, string][]; value: T; onChange: (t: T) => void }) {
  return (
    <div role="tablist" className="flex gap-1 border-b border-hairline">
      {tabs.map(([id, label]) => (
        <button
          key={id}
          role="tab"
          aria-selected={value === id}
          onClick={() => onChange(id)}
          className={cn(
            'relative shrink-0 px-2 pb-3 pt-1 text-sm text-ink-3 transition-colors hover:text-ink',
            value === id && 'font-medium text-ink after:absolute after:inset-x-0 after:-bottom-px after:h-0.5 after:rounded-full after:bg-blue',
          )}
        >
          {label}
        </button>
      ))}
    </div>
  )
}

export function Table({ head, children }: { head: [string, 'left' | 'right'][]; children: ReactNode }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[640px] text-sm">
        <thead>
          <tr className="bg-well text-ink-3">
            {head.map(([h, align], i) => (
              <th key={h} className={cn('px-4 py-3 font-normal first:rounded-l-lg last:rounded-r-lg', align === 'right' ? 'text-right' : 'text-left', i === 0 && 'border-r border-hairline')}>
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="[&_td]:px-4 [&_td]:py-3.5 [&_td:first-child]:border-r [&_td:first-child]:border-hairline [&_tr]:border-b [&_tr]:border-hairline [&_tr:last-child]:border-0">
          {children}
        </tbody>
      </table>
    </div>
  )
}

export function Empty({ text }: { text: string }) {
  return <div className="grid h-40 place-items-center rounded-xl border border-dashed border-hairline text-sm text-ink-3">{text}</div>
}

export function InfoTip({ text }: { text: string }) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <button className="text-ink-3 hover:text-ink" aria-label="What this number means"><Info className="size-3.5" /></button>
      </TooltipTrigger>
      <TooltipContent className="max-w-64 leading-relaxed">{text}</TooltipContent>
    </Tooltip>
  )
}

export function SevTag({ sev }: { sev: string }) {
  const { theme } = useTheme()
  const color = (chartTokens[theme].severity as Record<string, string>)[sev] ?? chartTokens[theme].axis
  return (
    <span className="inline-flex items-center gap-1.5 whitespace-nowrap">
      <span className="size-2 rounded-full" style={{ background: color }} />
      {sev}
    </span>
  )
}

export function Tag({ children, tone }: { children: ReactNode; tone?: 'bad' | 'warn' }) {
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 whitespace-nowrap rounded-md border border-hairline px-1.5 py-0.5 text-[11px] text-ink-2',
        tone === 'bad' && 'border-[#d03b3b]/40 text-[#d03b3b]',
        tone === 'warn' && 'border-[#b37400]/40 text-[#b37400]',
      )}
    >
      {children}
    </span>
  )
}

export const legendStyle = (t: ChartTokens) => ({
  top: 0, right: 0, icon: 'roundRect', itemWidth: 10, itemHeight: 10, textStyle: { color: t.ink2, fontSize: 11.5 },
})

export function Card({ title, description, children, className, action }: { title: ReactNode; description?: ReactNode; children: ReactNode; className?: string; action?: ReactNode }) {
  return (
    <Panel className={cn('flex min-w-0 flex-col p-6', className)}>
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <h3 className="text-base font-semibold tracking-[-0.01em]">{title}</h3>
          {description && <p className="mt-1 text-sm text-ink-3">{description}</p>}
        </div>
        {action}
      </div>
      <div className="mt-4 min-w-0 flex-1">{children}</div>
    </Panel>
  )
}
/** Wide data tables share one style: grey header row, hairline rows, numbers right-aligned. */
export function DTable({ head, children, minWidth = 720, maxHeight }: { head: [string, ('left' | 'right')?][]; children: ReactNode; minWidth?: number; maxHeight?: number }) {
  return (
    <div className="overflow-auto rounded-xl border border-hairline" style={{ maxHeight }}>
      <table className="w-full text-sm" style={{ minWidth }}>
        <thead className="sticky top-0 z-[1]">
          <tr className="bg-well text-xs text-ink-3">
            {head.map(([h, a]) => <th key={h} className={cn('whitespace-nowrap px-3 py-2.5 font-medium', a === 'right' ? 'text-right' : 'text-left')}>{h}</th>)}
          </tr>
        </thead>
        <tbody className="[&_td]:px-3 [&_td]:py-2.5 [&_tr]:border-t [&_tr]:border-hairline">{children}</tbody>
      </table>
    </div>
  )
}
