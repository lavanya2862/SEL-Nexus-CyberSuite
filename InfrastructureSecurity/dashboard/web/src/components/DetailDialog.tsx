import { useEffect, useRef, useState, type ReactNode } from 'react'
import { createPortal } from 'react-dom'
import { ChevronRight, X } from 'lucide-react'
import { cn } from '@/lib/utils'

/**
 * The detail dialog every list of cards opens (Attack detection, Applicable threats, Remediation): a wide panel with
 * a header (eyebrow, title, subtitle, close), a scrolling body and an optional footer of actions. Esc, the close
 * button or a click outside closes it; focus stays inside while it is open and returns to the card afterwards.
 * Full-screen sheet on a phone.
 */
export function DetailDialog({ eyebrow, title, subtitle, children, footer, onClose, wide = true }: {
  eyebrow?: ReactNode; title: ReactNode; subtitle?: ReactNode; children: ReactNode; footer?: ReactNode
  onClose: () => void; wide?: boolean
}) {
  const box = useRef<HTMLDivElement>(null)
  const close = useRef(onClose)
  close.current = onClose
  useEffect(() => {
    const before = document.activeElement as HTMLElement | null
    box.current?.querySelector<HTMLElement>('[data-close]')?.focus()
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') close.current()
      if (e.key === 'Tab' && box.current) {
        const f = [...box.current.querySelectorAll<HTMLElement>('button:not([disabled]), a[href], summary, input, select, [tabindex]:not([tabindex="-1"])')]
        if (!f.length) return
        if (e.shiftKey && document.activeElement === f[0]) { e.preventDefault(); f[f.length - 1].focus() }
        else if (!e.shiftKey && document.activeElement === f[f.length - 1]) { e.preventDefault(); f[0].focus() }
      }
    }
    document.addEventListener('keydown', onKey)
    const overflow = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    return () => { document.removeEventListener('keydown', onKey); document.body.style.overflow = overflow; before?.focus() }
  }, [])
  // in a portal: a card's animated (transformed) parent would otherwise trap the fixed overlay inside it
  return createPortal(
    <div className="fixed inset-0 z-50 flex items-end justify-center bg-black/40 sm:items-center sm:p-6" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div ref={box} role="dialog" aria-modal="true" aria-labelledby="detail-title"
        className={cn('flex max-h-[100dvh] w-full flex-col overflow-hidden bg-panel shadow-2xl sm:max-h-[90vh] sm:rounded-2xl sm:border sm:border-hairline', wide ? 'max-w-5xl' : 'max-w-2xl')}>
        <header className="flex items-start gap-3 border-b border-hairline px-6 py-4">
          <div className="min-w-0 flex-1">
            {eyebrow && <div className="flex flex-wrap items-center gap-2 text-xs">{eyebrow}</div>}
            <h2 id="detail-title" className="mt-1.5 text-xl font-semibold leading-snug tracking-tight">{title}</h2>
            {subtitle && <div className="mt-1 text-sm text-ink-3">{subtitle}</div>}
          </div>
          <button data-close onClick={onClose} aria-label="Close" className="rounded-lg p-1.5 text-ink-3 hover:bg-well hover:text-ink"><X className="size-5" /></button>
        </header>
        <div className="flex flex-col gap-6 overflow-y-auto px-6 py-5 text-sm">{children}</div>
        {footer && <footer className="flex flex-wrap items-center justify-end gap-2 border-t border-hairline bg-well/40 px-6 py-3">{footer}</footer>}
      </div>
    </div>,
    document.body,
  )
}

/** A titled block inside a DetailDialog: a small uppercase heading, a rule, then the content. */
export function DialogSection({ title, children, aside }: { title: string; children: ReactNode; aside?: ReactNode }) {
  return (
    <section>
      <div className="flex items-baseline justify-between gap-3 border-b border-hairline pb-1.5">
        <h3 className="text-[11px] font-semibold uppercase tracking-[0.08em] text-ink-3">{title}</h3>
        {aside && <div className="text-xs text-ink-3">{aside}</div>}
      </div>
      <div className="mt-2.5">{children}</div>
    </section>
  )
}

/**
 * A compact card in a grid that opens the full, unchanged card in a DetailDialog. `summary` is the small card's
 * content; `children` is the full card, shown as it is inside the dialog.
 */
export function ExpandableCard({ summary, title, eyebrow, subtitle, accent, children, className, id, highlight, defaultOpen, footer, actions }: {
  summary: ReactNode; title: ReactNode; eyebrow?: ReactNode; subtitle?: ReactNode; accent?: string
  children: ReactNode; className?: string; id?: string; highlight?: boolean; defaultOpen?: boolean; footer?: ReactNode
  /** quick actions on the card itself (e.g. Approve, Defer): they act without opening the details */
  actions?: ReactNode
}) {
  const [open, setOpen] = useState(!!defaultOpen)
  return (
    <>
      <div id={id} role="button" tabIndex={0} onClick={() => setOpen(true)}
        onKeyDown={(e) => { if (e.target === e.currentTarget && (e.key === 'Enter' || e.key === ' ')) { e.preventDefault(); setOpen(true) } }}
        className={cn('flex h-full w-full cursor-pointer scroll-mt-28 flex-col overflow-hidden rounded-xl border border-hairline bg-panel text-left transition-colors hover:border-hairline-strong hover:bg-well/40 focus-visible:outline-2 focus-visible:outline-blue', highlight && 'ring-2 ring-signal ring-offset-2 ring-offset-canvas', className)}>
        {accent && <span className="h-1 w-full shrink-0" style={{ background: accent }} />}
        <div className="flex flex-1 flex-col gap-2.5 p-4">
          {summary}
          <div className="mt-auto flex flex-wrap items-center justify-between gap-2 pt-1">
            {/* the actions act on their own: a click there never opens the details */}
            <span className="flex flex-wrap items-center gap-1.5" onClick={(e) => e.stopPropagation()} onKeyDown={(e) => e.stopPropagation()}>{actions}</span>
            <span className="ml-auto inline-flex items-center gap-0.5 text-xs font-medium text-blue">Details <ChevronRight className="size-3.5" /></span>
          </div>
        </div>
      </div>
      {open && (
        <DetailDialog eyebrow={eyebrow} title={title} subtitle={subtitle} footer={footer} onClose={() => setOpen(false)}>
          <div className="[&>li]:list-none [&>section]:rounded-xl [&>li]:rounded-xl">{children}</div>
        </DetailDialog>
      )}
    </>
  )
}
