// Shared building blocks for every page (one look, no copies per page). The first half is the Infrastructure
// Vulnerabilities portal's kit unchanged, so both modules of the CyberSuite look and behave the same.
import { Children, isValidElement, useEffect, useRef, useState, type ComponentType, type CSSProperties, type ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { AlertTriangle, ArrowRight, CheckCircle2, ChevronDown, Info, Loader2, XCircle } from 'lucide-react'
import { DropdownMenu, DropdownMenuContent, DropdownMenuRadioGroup, DropdownMenuRadioItem, DropdownMenuTrigger } from '@/components/ui/dropdown-menu'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { AGENT_STATUS, FIX_STATUS, JOB_STATUS, VERDICT, sevLabel } from '@/lib/labels'
import { chartTokens, statusColor, useTheme } from '@/lib/theme'
import type { Job } from '@/lib/types'
import { cn } from '@/lib/utils'

/** "Follow this hole": a small link to the same item on the next page. */
export function HopLink({ to, children, title }: { to: string; children: ReactNode; title?: string }) {
  return (
    <Link to={to} title={title} className="inline-flex shrink-0 items-center gap-1 whitespace-nowrap rounded-md border border-hairline px-2 py-1 text-[11px] font-semibold text-ink-2 hover:bg-well hover:text-ink">
      {children} <ArrowRight className="size-3" />
    </Link>
  )
}

export function Panel({ className, children, id, style }: { className?: string; children: ReactNode; id?: string; style?: CSSProperties }) {
  return <section id={id} style={style} className={cn('glass-card rounded-[20px]', className)}>{children}</section>
}

export function Chip({ children, tone, title }: { children: ReactNode; tone?: 'signal'; title?: string }) {
  return (
    <span title={title} className={cn('tabular inline-flex items-center rounded-md border border-hairline bg-well px-2 py-1 text-xs font-medium text-ink-2', tone === 'signal' && 'text-signal')}>
      {children}
    </span>
  )
}

export function Tabs<T extends string>({ tabs, value, onChange }: { tabs: [T, ReactNode][]; value: T; onChange: (t: T) => void }) {
  return (
    <div role="tablist" className="flex gap-1 overflow-x-auto border-b border-hairline">
      {tabs.map(([id, label]) => (
        <button
          key={id}
          role="tab"
          aria-selected={value === id}
          onClick={() => onChange(id)}
          className={cn(
            'relative flex shrink-0 items-center gap-1.5 whitespace-nowrap px-2 pb-3 pt-1 text-sm text-ink-3 transition-colors hover:text-ink',
            value === id && 'font-medium text-ink after:absolute after:inset-x-0 after:-bottom-px after:h-0.5 after:rounded-full after:bg-blue',
          )}
        >
          {label}
        </button>
      ))}
    </div>
  )
}

export function Empty({ text, children }: { text: string; children?: ReactNode }) {
  return (
    <div className="grid min-h-40 place-items-center rounded-xl border border-dashed border-hairline p-6 text-center text-sm text-ink-3">
      <div>{text}{children && <div className="mt-3">{children}</div>}</div>
    </div>
  )
}

export function InfoTip({ text }: { text: string }) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <button className="text-ink-3 hover:text-ink" aria-label="What this means"><Info className="size-3.5" /></button>
      </TooltipTrigger>
      <TooltipContent className="max-w-64 leading-relaxed">{text}</TooltipContent>
    </Tooltip>
  )
}

export function sevColor(theme: 'light' | 'dark', sev: string): string {
  return (chartTokens[theme].severity as Record<string, string>)[sevLabel(sev)] ?? chartTokens[theme].axis
}

export function SevTag({ sev }: { sev: string }) {
  const { theme } = useTheme()
  return (
    <span className="inline-flex items-center gap-1.5 whitespace-nowrap">
      <span className="size-2 rounded-full" style={{ background: sevColor(theme, sev) }} />
      {sevLabel(sev)}
    </span>
  )
}

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
            {head.map(([h, a], i) => <th key={h || i} className={cn('whitespace-nowrap px-3 py-2.5 font-medium', a === 'right' ? 'text-right' : 'text-left')}>{h}</th>)}
          </tr>
        </thead>
        <tbody className="[&_td]:px-3 [&_td]:py-2.5 [&_td]:align-top [&_tr]:border-t [&_tr]:border-hairline">{children}</tbody>
      </table>
    </div>
  )
}

/* ───────── Application Security additions, in the same style ───────── */

/** Every page opens the same way: a title, one line on what the page is for, and its actions on the right. */
export function PageHeader({ title, description, children }: { title: ReactNode; description: ReactNode; children?: ReactNode }) {
  return (
    <div className="flex flex-wrap items-end justify-between gap-4">
      <div className="min-w-0">
        <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
        <p className="mt-1 max-w-3xl text-sm text-ink-3">{description}</p>
      </div>
      {children && <div className="flex flex-wrap items-center gap-2">{children}</div>}
    </div>
  )
}

type Tone = 'good' | 'warn' | 'bad' | 'info' | 'idle'
const TONE_COLOR: Record<Tone, string> = {
  good: statusColor.good, warn: statusColor.warning, bad: statusColor.critical, info: 'var(--sky)', idle: 'var(--ink-3)',
}
const TONE_ICON: Record<Tone, ComponentType<{ className?: string; style?: CSSProperties }>> = {
  good: CheckCircle2, warn: AlertTriangle, bad: XCircle, info: Info, idle: Info,
}

/** A status with a coloured dot (or a spinner while working) and a word, as in the portal's tables. */
export function StatusTag({ tone, label, spin, title }: { tone: Tone; label: ReactNode; spin?: boolean; title?: string }) {
  return (
    <span title={title} className="inline-flex items-center gap-1.5 whitespace-nowrap rounded-full border border-hairline bg-well/60 py-0.5 pl-1.5 pr-2.5 text-xs font-medium text-ink-2">
      {spin ? <Loader2 className="size-3 animate-spin" style={{ color: TONE_COLOR[tone] }} /> : <span className="size-2 rounded-full" style={{ background: TONE_COLOR[tone] }} />}
      {label}
    </span>
  )
}

export const JobStatusTag = ({ job }: { job: Pick<Job, 'status'> }) => {
  const s = JOB_STATUS[job.status] ?? { label: job.status, tone: 'idle' as const }
  return <StatusTag tone={s.tone} label={s.label} spin={job.status === 'running'} />
}

export function VerdictTag({ v }: { v?: string | null }) {
  if (!v) return <span className="text-ink-3">–</span>
  const s = VERDICT[v] ?? { label: v, tone: 'idle' as const }
  return <StatusTag tone={s.tone} label={s.label} title={v === 'flagged' ? 'A validation check failed. The pull request is raised as a draft for investigation.' : undefined} />
}

export function FixStatusTag({ s }: { s: string }) {
  const f = FIX_STATUS[s] ?? { label: s.replace('_', ' '), tone: 'idle' as const, hint: '' }
  return <StatusTag tone={f.tone} label={f.label} title={f.hint} />
}

export function AgentStatusTag({ status }: { status: string }) {
  const a = AGENT_STATUS[status] ?? { label: status, tone: 'idle' as const }
  return <StatusTag tone={a.tone} label={a.label} spin={status === 'running'} />
}

/** Risk score 0–10 with a small bar, coloured like severity. */
export function RiskScore({ score }: { score: number | null | undefined }) {
  const s = Number(score ?? 0)
  const color = s >= 8 ? statusColor.critical : s >= 6 ? statusColor.serious : s >= 4 ? statusColor.warning : 'var(--ink-3)'
  return (
    <span className="tabular inline-flex items-center gap-2 font-medium" title={`Risk ${s.toFixed(1)} of 10`}>
      {s.toFixed(1)}
      <span className="h-1.5 w-12 overflow-hidden rounded-full bg-well"><span className="block h-full rounded-full" style={{ width: `${s * 10}%`, background: color }} /></span>
    </span>
  )
}

/** A message box: what is going on and, usually, what to do about it. */
export function Notice({ tone = 'info', title, children, action }: { tone?: Tone; title: ReactNode; children?: ReactNode; action?: ReactNode }) {
  const Icon = TONE_ICON[tone]
  const tint = tone === 'good' ? 'var(--teal)' : tone === 'warn' ? 'var(--amber)' : tone === 'bad' ? 'var(--rose)' : 'var(--blue)'
  return (
    <div className="tint-box flex flex-wrap items-start gap-3 rounded-xl p-4" style={{ '--tint': tint } as CSSProperties}>
      <Icon className="mt-0.5 size-4 shrink-0" style={{ color: TONE_COLOR[tone] }} />
      <div className="min-w-0 flex-1 text-sm">
        <div className="font-semibold text-ink">{title}</div>
        {children && <div className="mt-0.5 leading-relaxed text-ink-2">{children}</div>}
      </div>
      {action}
    </div>
  )
}

/** Buttons: the portal's solid blue primary and a quiet outlined secondary. */
export function Btn({ children, onClick, kind = 'primary', disabled, type = 'button', className, title }: {
  children: ReactNode; onClick?: () => void; kind?: 'primary' | 'quiet' | 'good' | 'warn'; disabled?: boolean; type?: 'button' | 'submit'; className?: string; title?: string
}) {
  return (
    <button
      type={type}
      title={title}
      onClick={onClick}
      disabled={disabled}
      className={cn(
        'inline-flex h-9 items-center justify-center gap-2 whitespace-nowrap rounded-lg px-3.5 text-sm font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50',
        kind === 'primary' && 'btn-blue',
        kind === 'quiet' && 'border border-hairline-strong text-ink-2 hover:bg-well hover:text-ink',
        kind === 'good' && 'bg-[#15803d] text-white hover:bg-[#137236]',
        kind === 'warn' && 'bg-[#b45309] text-white hover:bg-[#a14a08]',
        className,
      )}
    >
      {children}
    </button>
  )
}

/** The same look as Btn, for links (internal pages or downloads). */
export function LinkBtn({ to, href, children, kind = 'quiet', external, className }: {
  to?: string; href?: string; children: ReactNode; kind?: 'primary' | 'quiet' | 'good'; external?: boolean; className?: string
}) {
  const cls = cn(
    'inline-flex h-9 items-center justify-center gap-2 whitespace-nowrap rounded-lg px-3.5 text-sm font-medium transition-colors',
    kind === 'primary' && 'btn-blue',
    kind === 'quiet' && 'border border-hairline-strong text-ink-2 hover:bg-well hover:text-ink',
    kind === 'good' && 'bg-[#15803d] text-white hover:bg-[#137236]',
    className,
  )
  if (to) return <Link to={to} className={cls}>{children}</Link>
  return <a href={href} className={cls} {...(external ? { target: '_blank', rel: 'noopener noreferrer' } : {})}>{children}</a>
}

/** A headline number in a small card: label with an explanation, the number, and a hint underneath. */
export function Stat({ label, value, hint, info, icon: Icon, tone, to }: {
  label: string; value: ReactNode; hint?: ReactNode; info?: string; icon?: ComponentType<{ className?: string }>; tone?: string; to?: string
}) {
  const body = (
    <>
      <div className="flex items-start justify-between gap-2">
        <h3 className="flex items-center gap-1.5 text-sm text-ink-2">{label}{info && <InfoTip text={info} />}</h3>
        {Icon && <span className="grid size-8 place-items-center rounded-[9px] bg-well" style={{ color: tone ?? 'var(--sky)' }}><Icon className="size-4" /></span>}
      </div>
      <div className="mt-2 text-[34px] font-normal leading-none tracking-tight tabular">{value}</div>
      {hint && <div className="mt-3 text-xs text-ink-3">{hint}</div>}
    </>
  )
  return to ? (
    <Link to={to} className="glass-card block rounded-[20px] p-5 transition-colors hover:border-hairline-strong">{body}</Link>
  ) : (
    <Panel className="p-5">{body}</Panel>
  )
}

export function Field({ label, hint, children }: { label: ReactNode; hint?: ReactNode; children: ReactNode }) {
  return (
    <label className="flex flex-col gap-1.5 text-sm">
      <span className="flex flex-wrap items-center gap-2 font-medium text-ink-2">{label}</span>
      {children}
      {hint && <span className="text-xs text-ink-3">{hint}</span>}
    </label>
  )
}

export const inputCls = 'h-10 w-full rounded-[10px] border border-hairline-strong bg-field px-3 text-sm text-ink outline-none transition-[border-color,box-shadow] placeholder:text-ink-3 focus:border-blue/60 focus:ring-3 focus:ring-blue/15 disabled:opacity-60'

export interface ChoiceOption { value: string; label: ReactNode; hint?: ReactNode }

/** The suite's own dropdown (themed, never the browser's). As a filter (the default) it turns blue while it filters,
 *  that is on anything but the first option; as a form field it fills the width like an input. */
export function Choice({ value, onChange, options, label, field, placeholder, className }: {
  value: string; onChange: (v: string) => void; options: ChoiceOption[]; label: string; field?: boolean; placeholder?: string; className?: string
}) {
  const cur = options.find((o) => o.value === value)
  const on = !field && value !== options[0]?.value
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <button type="button" aria-label={label}
          className={cn('flex min-w-0 items-center gap-2 rounded-[10px] border bg-field px-3 text-left text-sm transition-[border-color,box-shadow] hover:border-blue/50 focus-visible:outline-none focus-visible:ring-3 focus-visible:ring-blue/15 data-[state=open]:border-blue/60 data-[state=open]:ring-3 data-[state=open]:ring-blue/15',
            field ? 'h-10 w-full border-hairline-strong text-ink' : 'h-9 w-auto max-w-[260px]',
            !field && (on ? 'border-blue/60 text-ink' : 'border-hairline-strong text-ink-2'), className)}>
          <span className={cn('min-w-0 flex-1 truncate', !cur && 'text-ink-3')}>{cur?.label ?? placeholder ?? value}</span>
          <ChevronDown className="size-4 shrink-0 text-ink-3" />
        </button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start"
        className="max-h-80 min-w-[var(--radix-dropdown-menu-trigger-width)] overflow-y-auto rounded-xl border border-hairline bg-panel p-1.5 shadow-xl">
        <DropdownMenuRadioGroup value={value} onValueChange={onChange}>
          {options.map((o) => (
            <DropdownMenuRadioItem key={o.value} value={o.value}
              className="gap-2 rounded-lg py-2 pl-2.5 text-ink-2 focus:bg-well focus:text-ink data-[state=checked]:font-medium data-[state=checked]:text-ink">
              <span className="min-w-0 flex-1">
                <span className="block truncate">{o.label}</span>
                {o.hint && <span className="block text-xs font-normal text-ink-3">{o.hint}</span>}
              </span>
            </DropdownMenuRadioItem>
          ))}
        </DropdownMenuRadioGroup>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}

/** Filter row: dropdowns and a search box in one line, as on the portal's tables. Takes <option> children for brevity
 *  and shows them in the suite's own dropdown. */
export function Select({ value, onChange, children, label }: { value: string; onChange: (v: string) => void; children: ReactNode; label: string }) {
  const options = Children.toArray(children).filter(isValidElement).map((el) => {
    const p = el.props as { value?: string; children?: ReactNode }
    return { value: String(p.value ?? ''), label: p.children }
  })
  return <Choice label={label} value={value} onChange={onChange} options={options} />
}

export function Search({ value, onChange, placeholder }: { value: string; onChange: (v: string) => void; placeholder: string }) {
  return <input type="search" value={value} onChange={(e) => onChange(e.target.value)} placeholder={placeholder} aria-label={placeholder} className={cn(inputCls, 'h-9 min-w-48 flex-1')} />
}

export function Loading({ text = 'Loading…' }: { text?: string }) {
  return <div className="flex items-center gap-2 py-10 text-sm text-ink-3"><Loader2 className="size-4 animate-spin" /> {text}</div>
}

export function ErrorBox({ error }: { error: unknown }) {
  return <Notice tone="bad" title="Unable to complete the request">{String((error as Error)?.message ?? error)}</Notice>
}

function useCountUp(to: number) {
  const [n, setN] = useState(0)
  const from = useRef(0)
  useEffect(() => {
    const start = from.current
    const t0 = performance.now()
    let raf = 0
    const step = (t: number) => {
      const p = Math.min(1, (t - t0) / 700)
      setN(Math.round(start + (to - start) * (1 - Math.pow(1 - p, 3))))
      if (p < 1) raf = requestAnimationFrame(step)
      else from.current = to
    }
    raf = requestAnimationFrame(step)
    return () => cancelAnimationFrame(raf)
  }, [to])
  return n
}

export type Hue = 'blue' | 'red' | 'orange' | 'amber' | 'green' | 'violet'
/** A count card in a solid colour that matches what it counts (white text on every colour), as on the Infrastructure
 *  Vulnerabilities pages. With `to` it opens that page; with `onClick` it is a filter button (`on` = selected). */
export function HeroTile({ label, value, hint, hue, to, onClick, on, className }: {
  label: ReactNode; value: number; hint?: ReactNode; hue: Hue; to?: string; onClick?: () => void; on?: boolean; className?: string
}) {
  const n = useCountUp(value)
  const cls = cn('glass-card card-hero flex flex-col rounded-[20px] px-4 py-4 text-left', hue !== 'blue' && `card-hero-${hue}`,
    (to || onClick) && 'transition-transform hover:-translate-y-0.5', on && 'outline outline-[3px] outline-offset-2 outline-blue', className)
  const body = (
    <>
      <div className="flex items-center gap-1.5 text-xs text-ink-2"><span className="size-1.5 shrink-0 rounded-full bg-white" aria-hidden />{label}</div>
      <div className="tabular mt-1 text-[28px] leading-none tracking-tight">{n.toLocaleString('en-GB')}</div>
      {hint && <div className="mt-1.5 text-xs leading-snug text-ink-3">{hint}</div>}
    </>
  )
  if (to) return <Link to={to} className={cls}>{body}</Link>
  if (onClick) return <button type="button" onClick={onClick} aria-pressed={on} className={cls}>{body}</button>
  return <section className={cls}>{body}</section>
}
