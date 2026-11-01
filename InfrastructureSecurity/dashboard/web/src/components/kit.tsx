// Shared building blocks for every portal page (one look, no copies per page).
import type { ComponentType, ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { ArrowRight, CalendarDays, ChevronDown, Info, Search, SlidersHorizontal, X } from 'lucide-react'
import {
  DropdownMenu, DropdownMenuCheckboxItem, DropdownMenuContent, DropdownMenuRadioGroup, DropdownMenuRadioItem, DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { num } from '@/lib/format'
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
    // scrolls sideways on a phone instead of making the whole page wider
    <div role="tablist" className="flex gap-1 overflow-x-auto border-b border-hairline [scrollbar-width:none]">
      {tabs.map(([id, label]) => (
        <button
          key={id}
          role="tab"
          aria-selected={value === id}
          onClick={() => onChange(id)}
          className={cn(
            'relative shrink-0 px-2 pb-3 pt-1 text-sm text-ink-3 transition-colors hover:text-ink',
            value === id && 'font-medium text-ink after:absolute after:inset-x-0 after:bottom-0 after:h-0.5 after:rounded-full after:bg-blue',
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

export function Card({ title, description, children, className, action, id }: { title: ReactNode; description?: ReactNode; children: ReactNode; className?: string; action?: ReactNode; id?: string }) {
  return (
    <Panel id={id} className={cn('flex min-w-0 flex-col p-6', className)}>
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

export interface ChoiceOption { value: string; label: string; count?: number; dot?: string }

/** The portal's dropdown (themed, not the browser's): the chosen option with its count; it turns blue while it filters
 *  (anything but the first option). dot = a colour shown before the label. */
export function Choice({ value, onChange, options, label, icon: Icon, className }: {
  value: string; onChange: (v: string) => void; options: ChoiceOption[]; label: string; icon?: ComponentType<{ className?: string }>; className?: string
}) {
  const cur = options.find((o) => o.value === value) ?? options[0]
  const on = value !== options[0]?.value
  const dot = (o: ChoiceOption) => o.dot && <span className="size-2 shrink-0 rounded-full" style={{ background: o.dot }} />
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <button aria-label={label}
          className={cn('inline-flex min-w-0 items-center gap-2 rounded-lg border bg-field px-3 py-1.5 text-left text-sm transition-[border-color,box-shadow] hover:border-blue/50 focus-visible:outline-none focus-visible:ring-3 focus-visible:ring-blue/15 data-[state=open]:border-blue/60 data-[state=open]:ring-3 data-[state=open]:ring-blue/15',
            on ? 'border-blue/60 text-ink' : 'border-hairline-strong text-ink-2', className)}>
          {Icon && <Icon className="size-4 shrink-0 text-ink-3" />}
          {dot(cur)}
          <span className="min-w-0 truncate">{cur?.label}</span>
          {cur?.count != null && <span className="tabular text-xs text-ink-3">{num(cur.count)}</span>}
          <ChevronDown className="size-4 shrink-0 text-ink-3" />
        </button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" className="min-w-48 rounded-xl border border-hairline bg-panel p-1.5 shadow-xl">
        <DropdownMenuRadioGroup value={value} onValueChange={onChange}>
          {options.map((o) => (
            <DropdownMenuRadioItem key={o.value} value={o.value}
              className="gap-2 rounded-lg py-2 pl-2.5 text-ink-2 focus:bg-well focus:text-ink data-[state=checked]:font-medium data-[state=checked]:text-ink">
              {dot(o)}
              <span className="min-w-0 flex-1 truncate">{o.label}</span>
              {o.count != null && <span className={cn('tabular text-xs', o.count ? 'text-ink-3' : 'text-ink-3/50')}>{num(o.count)}</span>}
            </DropdownMenuRadioItem>
          ))}
        </DropdownMenuRadioGroup>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}

const PILL = 'inline-flex items-center gap-2 rounded-lg border bg-field px-3 py-1.5 text-sm transition-[border-color,box-shadow] hover:border-blue/50 ' +
  'focus-visible:outline-none focus-visible:ring-3 focus-visible:ring-blue/15 data-[state=open]:border-blue/60 data-[state=open]:ring-3 data-[state=open]:ring-blue/15'
const MENU = 'min-w-56 rounded-xl border border-hairline bg-panel p-1.5 shadow-xl'
const ITEM = 'gap-2 rounded-lg py-2 pl-2.5 text-ink-2 focus:bg-well focus:text-ink data-[state=checked]:font-medium data-[state=checked]:text-ink'
const dotOf = (o: ChoiceOption) => o.dot && <span className="size-2.5 shrink-0 rounded-full" style={{ background: o.dot }} />

/** A filter pill with a themed multi-select menu: icon, name, how many values are picked, and the menu stays open
 *  while picking. Nothing picked = no filter. The picked values show as FilterChips below the bar. */
export function FilterMenu({ label, icon: Icon, options, value, onChange }: {
  label: string; icon: ComponentType<{ className?: string }>; options: ChoiceOption[]; value: string[]; onChange: (v: string[]) => void
}) {
  const toggle = (v: string) => onChange(value.includes(v) ? value.filter((x) => x !== v) : [...value, v])
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <button aria-label={`Filter by ${label}`} className={cn(PILL, value.length ? 'border-blue/60 text-ink' : 'border-hairline-strong text-ink-2')}>
          <Icon className="size-4 text-ink-3" />
          <span>{label}</span>
          {value.length > 0 && <span className="tabular grid min-w-5 place-items-center rounded-md bg-well px-1 text-xs font-semibold text-ink">{value.length}</span>}
          <ChevronDown className="size-4 text-ink-3" />
        </button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" className={MENU}>
        {options.map((o) => (
          <DropdownMenuCheckboxItem key={o.value} checked={value.includes(o.value)} onSelect={(e) => e.preventDefault()}
            onCheckedChange={() => toggle(o.value)} className={ITEM}>
            {dotOf(o)}
            <span className="min-w-0 flex-1 truncate">{o.label}</span>
            {o.count != null && <span className={cn('tabular text-xs', o.count ? 'text-ink-3' : 'text-ink-3/50')}>{num(o.count)}</span>}
          </DropdownMenuCheckboxItem>
        ))}
        {value.length > 0 && <>
          <DropdownMenuSeparator className="my-1 bg-hairline" />
          <button onClick={() => onChange([])} className="w-full rounded-lg px-2.5 py-1.5 text-left text-xs text-ink-3 hover:bg-well hover:text-ink">Clear {label.toLowerCase()}</button>
        </>}
      </DropdownMenuContent>
    </DropdownMenu>
  )
}

export interface ActiveFilter { key: string; label: string; dot?: string; onRemove: () => void }

/** The filters in use as removable chips, with one "Clear all". */
export function FilterChips({ items, onClear }: { items: ActiveFilter[]; onClear: () => void }) {
  if (!items.length) return null
  return (
    <div className="flex flex-wrap items-center gap-2">
      {items.map((f) => (
        <span key={f.key} className="inline-flex items-center gap-2 rounded-lg border border-hairline bg-well py-1 pr-1.5 pl-2.5 text-sm text-ink">
          {f.dot && <span className="size-2.5 rounded-full" style={{ background: f.dot }} />}
          {f.label}
          <button onClick={f.onRemove} aria-label={`Remove ${f.label}`} className="grid size-5 place-items-center rounded-md text-ink-3 hover:bg-panel hover:text-ink">
            <X className="size-3.5" />
          </button>
        </span>
      ))}
      <button onClick={onClear} className="px-1 text-xs font-medium text-blue hover:underline">Clear all</button>
    </div>
  )
}

export type DateRange = { preset: 'any' | 'today' | 'yesterday' | '7d' | '30d' | 'custom'; from?: string; to?: string }
export const DATE_PRESETS: [DateRange['preset'], string][] = [
  ['any', 'Any time'], ['today', 'Today'], ['yesterday', 'Yesterday'], ['7d', 'Last 7 days'], ['30d', 'Last 30 days'], ['custom', 'Custom range'],
]

/** [start, end) in local time for a date filter, or null for "any time". from/to are yyyy-mm-dd, both days included. */
export function dateBounds(r: DateRange, now = new Date()): [Date, Date] | null {
  const day = (d: Date, add = 0) => new Date(d.getFullYear(), d.getMonth(), d.getDate() + add)
  const today = day(now)
  switch (r.preset) {
    case 'today': return [today, day(now, 1)]
    case 'yesterday': return [day(now, -1), today]
    case '7d': return [day(now, -6), day(now, 1)]
    case '30d': return [day(now, -29), day(now, 1)]
    case 'custom': {
      const parse = (s?: string) => (s ? new Date(`${s}T00:00:00`) : null)
      const from = parse(r.from), to = parse(r.to)
      return [from ?? new Date(0), to ? day(to, 1) : day(now, 1)]
    }
    default: return null
  }
}

export function dateLabel(r: DateRange): string {
  if (r.preset !== 'custom') return DATE_PRESETS.find(([p]) => p === r.preset)?.[1] ?? 'Any time'
  const f = (s?: string) => (s ? new Date(`${s}T00:00:00`).toLocaleDateString(undefined, { day: 'numeric', month: 'short' }) : '…')
  return `${f(r.from)} – ${f(r.to)}`
}

/** A date filter pill: quick ranges, or a custom from/to (both days included). */
export function DateFilter({ label = 'Date', value, onChange }: { label?: string; value: DateRange; onChange: (v: DateRange) => void }) {
  const on = value.preset !== 'any'
  const input = 'w-full rounded-lg border border-hairline-strong bg-field px-2.5 py-1.5 text-sm text-ink [color-scheme:light_dark] focus-visible:outline-none focus-visible:border-blue/60'
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <button aria-label={`Filter by ${label.toLowerCase()}`} className={cn(PILL, on ? 'border-blue/60 text-ink' : 'border-hairline-strong text-ink-2')}>
          <CalendarDays className="size-4 text-ink-3" />
          <span>{on ? dateLabel(value) : label}</span>
          <ChevronDown className="size-4 text-ink-3" />
        </button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" className={MENU}>
        <DropdownMenuRadioGroup value={value.preset} onValueChange={(p) => onChange({ ...value, preset: p as DateRange['preset'] })}>
          {DATE_PRESETS.map(([p, l]) => (
            <DropdownMenuRadioItem key={p} value={p} className={ITEM} onSelect={(e) => { if (p === 'custom') e.preventDefault() }}>
              <span className="flex-1">{l}</span>
            </DropdownMenuRadioItem>
          ))}
        </DropdownMenuRadioGroup>
        {value.preset === 'custom' && (
          <div className="mt-1 grid grid-cols-2 gap-2 border-t border-hairline px-1 pt-2.5 pb-1" onKeyDown={(e) => e.stopPropagation()}>
            <label className="flex flex-col gap-1 text-[11px] text-ink-3">From
              <input type="date" value={value.from ?? ''} max={value.to} onChange={(e) => onChange({ ...value, from: e.target.value || undefined })} className={input} />
            </label>
            <label className="flex flex-col gap-1 text-[11px] text-ink-3">To
              <input type="date" value={value.to ?? ''} min={value.from} onChange={(e) => onChange({ ...value, to: e.target.value || undefined })} className={input} />
            </label>
          </div>
        )}
      </DropdownMenuContent>
    </DropdownMenu>
  )
}

/** Is `when` inside the date filter? Always true for "any time"; false for a row with no time once a range is set. */
export function inDateRange(when: Date | string | null | undefined, r: DateRange, now?: Date): boolean {
  const b = dateBounds(r, now)
  if (!b) return true
  const d = typeof when === 'string' ? new Date(when) : when
  return !!d && !Number.isNaN(d.getTime()) && d >= b[0] && d < b[1]
}

/** A single-choice filter pill (same look as FilterMenu): options[0] is "no filter"; the pill shows the name, and
 *  the chosen value once it filters. Its chip comes from choiceChip. */
export function FilterChoice({ label, icon: Icon, options, value, onChange }: {
  label: string; icon?: ComponentType<{ className?: string }>; options: ChoiceOption[]; value: string; onChange: (v: string) => void
}) {
  const cur = options.find((o) => o.value === value)
  const on = !!cur && value !== options[0]?.value
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <button aria-label={`Filter by ${label}`} className={cn(PILL, on ? 'border-blue/60 text-ink' : 'border-hairline-strong text-ink-2')}>
          {Icon && <Icon className="size-4 text-ink-3" />}
          <span>{label}</span>
          {on && <span className="max-w-40 truncate rounded-md bg-well px-1.5 text-xs font-semibold text-ink">{cur.label}</span>}
          <ChevronDown className="size-4 text-ink-3" />
        </button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" className={MENU}>
        <DropdownMenuRadioGroup value={value} onValueChange={onChange}>
          {options.map((o) => (
            <DropdownMenuRadioItem key={o.value} value={o.value} className={ITEM}>
              {dotOf(o)}
              <span className="min-w-0 flex-1 truncate">{o.label}</span>
              {o.count != null && <span className={cn('tabular text-xs', o.count ? 'text-ink-3' : 'text-ink-3/50')}>{num(o.count)}</span>}
            </DropdownMenuRadioItem>
          ))}
        </DropdownMenuRadioGroup>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}

/** The chip for a FilterChoice that filters (none for options[0]). */
export function choiceChip(key: string, options: ChoiceOption[], value: string, reset: () => void): ActiveFilter[] {
  const cur = options.find((o) => o.value === value)
  return cur && value !== options[0]?.value ? [{ key, label: cur.label, dot: cur.dot, onRemove: reset }] : []
}

/** The chips of a FilterMenu's picked values. */
export function menuChips(key: string, options: ChoiceOption[], value: string[], set: (v: string[]) => void): ActiveFilter[] {
  return value.map((v) => {
    const o = options.find((x) => x.value === v)
    return { key: `${key}-${v}`, label: o?.label ?? v, dot: o?.dot, onRemove: () => set(value.filter((x) => x !== v)) }
  })
}

/** The date filter's chip (none for "any time"). */
export function dateChip(value: DateRange, reset: () => void): ActiveFilter[] {
  return value.preset === 'any' ? [] : [{ key: 'date', label: dateLabel(value), onRemove: reset }]
}

/** The search box of a filter bar. */
export function FilterSearch({ value, onChange, placeholder, label }: { value: string; onChange: (v: string) => void; placeholder: string; label?: string }) {
  return (
    <label className="flex items-center gap-2 rounded-lg border border-hairline-strong bg-field px-3 py-1.5 text-sm transition-[border-color,box-shadow] focus-within:border-blue/60 focus-within:ring-3 focus-within:ring-blue/15">
      <Search className="size-3.5 text-ink-3" />
      <input value={value} onChange={(e) => onChange(e.target.value)} placeholder={placeholder} aria-label={label ?? placeholder}
        className="w-36 bg-transparent outline-none placeholder:text-ink-3 sm:w-44" />
      {value && <button onClick={() => onChange('')} aria-label="Clear search" className="text-ink-3 hover:text-ink"><X className="size-3.5" /></button>}
    </label>
  )
}

/** Every filter bar in the portal: "Filters", the pills, a count on the right, and the chips of what filters below. */
export function FilterBar({ children, chips, onClear, count, className }: {
  children: ReactNode; chips: ActiveFilter[]; onClear: () => void; count?: ReactNode; className?: string
}) {
  return (
    <div className={cn('flex flex-col gap-3 rounded-xl border border-hairline bg-panel px-4 py-3', className)}>
      <div className="flex flex-wrap items-center gap-2.5">
        <span className="mr-1 inline-flex items-center gap-1.5 text-sm font-medium text-ink-2"><SlidersHorizontal className="size-4" /> Filters</span>
        {children}
        {count != null && <span className="tabular ml-auto text-xs text-ink-3">{count}</span>}
      </div>
      {chips.length > 0 && <div className="border-t border-hairline pt-3"><FilterChips items={chips} onClear={onClear} /></div>}
    </div>
  )
}

/** A small number box on a card (the same look on every remediation card): value, label, optional colour. */
export function StatBox({ value, label, color }: { value: ReactNode; label: string; color?: string }) {
  return (
    <div className="min-w-0 rounded-xl bg-well px-3 py-2">
      <div className="tabular truncate text-lg font-semibold leading-tight tracking-tight" style={{ color }}>{typeof value === 'number' ? num(value) : value}</div>
      <div className="mt-0.5 truncate text-[11px] text-ink-3">{label}</div>
    </div>
  )
}

/** The small buttons on a card: one primary (Approve), the rest quiet (Defer, Withdraw). */
export function CardButton({ onClick, disabled, primary, children }: { onClick: () => void; disabled?: boolean; primary?: boolean; children: ReactNode }) {
  return (
    <button type="button" onClick={onClick} disabled={disabled}
      className={cn('inline-flex items-center gap-1 rounded-lg px-2.5 py-1 text-xs font-semibold disabled:opacity-50',
        primary ? 'btn-blue text-white' : 'border border-hairline-strong text-ink-2 hover:bg-well hover:text-ink')}>
      {children}
    </button>
  )
}
