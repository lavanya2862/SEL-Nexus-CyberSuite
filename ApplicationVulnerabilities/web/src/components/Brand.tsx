import { ShieldCheck } from 'lucide-react'
import { cn } from '@/lib/utils'

export const SUITE_NAME = 'SEL Nexus CyberSuite'
export const APP_NAME = 'Application Vulnerabilities'

/** The module wordmark: shield mark in a signal tile, "SEL NEXUS" and "Application Vulnerabilities" (this module of
    the CyberSuite; the Defender & Infrastructure portal shows its own name in the same place). */
export function Wordmark({ className, compact }: { className?: string; compact?: boolean }) {
  return (
    <div className={cn('flex items-center gap-2.5', className)} aria-label={`${SUITE_NAME}: ${APP_NAME}`}>
      <span className="tile-signal grid size-8 shrink-0 place-items-center rounded-[10px]">
        <ShieldCheck className="size-[17px]" strokeWidth={2.1} />
      </span>
      <span className="flex items-baseline gap-2 whitespace-nowrap">
        <span className="text-[13.5px] font-bold tracking-[0.2em] text-ink">SEL NEXUS</span>
        <span className={cn('text-sm font-medium text-sky', compact && 'hidden sm:inline')}>{APP_NAME}</span>
      </span>
    </div>
  )
}
