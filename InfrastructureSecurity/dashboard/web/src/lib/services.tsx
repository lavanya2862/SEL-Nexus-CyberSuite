import { useEffect, useRef } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Loader2, RotateCw } from 'lucide-react'
import { statusColor } from '@/lib/theme'
import { cn } from '@/lib/utils'

/* The portal keeps its background services running by itself (src/portal/services.py). If a page still finds one
   not answering (for example right after a restart), it starts it once on its own and says "Getting ready…".
   There is no switch for the user to press. */

const START = {
  fix: { url: '/api/fix/start-service', header: 'fix', refresh: ['fix'] },
  triage: { url: '/api/alert-triage/start-site', header: 'feedback', refresh: ['alert_triage'] },
} as const

export function useAutoStart(down: boolean, service: keyof typeof START) {
  const qc = useQueryClient()
  const tried = useRef(false)
  const start = useMutation({
    mutationFn: async () => {
      const s = START[service]
      const res = await fetch(s.url, { method: 'POST', headers: { 'X-Portal': s.header } })
      const out = await res.json().catch(() => ({}))
      if (!res.ok) throw new Error(out.error ?? 'it did not answer in time')
      return out
    },
    onSettled: () => qc.invalidateQueries({ queryKey: [...START[service].refresh] }),
  })
  useEffect(() => {
    if (!down) {
      tried.current = false
      return
    }
    if (!tried.current && !start.isPending) {
      tried.current = true
      start.mutate()
    }
  }, [down, start])
  return { starting: down && !start.isError, failed: down && start.isError, retry: () => start.mutate() }
}

/** "Getting X ready…" while a service starts; a quiet "Try again" if it didn't come up. */
export function GettingReady({ what, starting, failed, retry, fallback, off, retryLabel = 'Try again', className }: {
  what: string; starting: boolean; failed: boolean; retry: () => void; fallback?: string
  /** replaces the "isn't available" sentence; retryLabel replaces "Try again" */
  off?: string; retryLabel?: string; className?: string
}) {
  if (!starting && !failed) return null
  return (
    <div className={cn('flex flex-wrap items-center gap-3 text-sm', className)}>
      {starting ? (
        <>
          <Loader2 className="size-4 animate-spin text-sky" />
          <span className="text-ink-2">Getting {what} ready… this takes a few seconds.</span>
        </>
      ) : (
        <>
          <span className="text-ink-2" style={off ? undefined : { color: statusColor.serious }}>
            {off ?? `${what[0].toUpperCase() + what.slice(1)} isn’t available right now.${fallback ? ` ${fallback}` : ''}`}
          </span>
          <button onClick={retry} className="inline-flex items-center gap-1.5 rounded-lg border border-hairline px-2.5 py-1 text-xs font-medium hover:bg-well">
            <RotateCw className="size-3.5" /> {retryLabel}
          </button>
        </>
      )}
    </div>
  )
}
