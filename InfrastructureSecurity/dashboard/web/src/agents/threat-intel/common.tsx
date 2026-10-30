import type { ReactNode } from 'react'
import { AlertTriangle } from 'lucide-react'
import { Panel } from '@/components/kit'
import { Skeleton } from '@/components/ui/skeleton'
import { ago } from '@/lib/format'
import { useRuns } from '@/lib/runs'
import { statusColor } from '@/lib/theme'
import type { Resolution, ThreatIntelData } from '@/agents/threat-intel/data'

export function ThreatIntelHeader({ title, description, data, actions }: { title: string; description: string; data: ThreatIntelData; actions?: ReactNode }) {
  const { openDrawer } = useRuns()
  const hours = (Date.now() - new Date(data.generated.replace(' ', 'T') + (data.generated.endsWith('Z') || data.generated.includes('+') ? '' : 'Z')).getTime()) / 3600000
  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
          <p className="mt-1 text-sm text-ink-3">
            {description} · data from {ago(data.generated + (data.generated.includes('+') ? '' : 'Z'))}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">{actions}</div>
      </div>
      {hours > 24 && (
        <div className="flex items-start gap-2.5 rounded-xl border px-4 py-3 text-sm" style={{ borderColor: statusColor.warning }}>
          <AlertTriangle className="mt-0.5 size-4 shrink-0" style={{ color: statusColor.warning }} />
          <span>
            This data is {Math.round(hours / 24)} days old.{' '}
            <button onClick={() => openDrawer('threat_intel')} className="font-medium underline underline-offset-4">Run Threat Intel Agent now</button>
          </span>
        </div>
      )}
    </div>
  )
}

export function ThreatIntelLoading({ error }: { error?: unknown }) {
  if (error)
    return (
      <Panel className="p-6">
        <h2 className="font-semibold">Threat data is not available</h2>
        <p className="mt-1 text-sm text-ink-3">{String((error as Error)?.message ?? error)}</p>
      </Panel>
    )
  return (
    <div className="flex flex-col gap-5">
      <Skeleton className="h-16 w-96 rounded-xl" />
      <Skeleton className="h-40 rounded-2xl" />
      <Skeleton className="h-80 rounded-2xl" />
    </div>
  )
}

/** Score 0-100 as a thin bar + number (Threat Intel's fixed-rule risk score). */
export function ScoreBar({ score, width = 96 }: { score: number; width?: number }) {
  const color = score >= 90 ? 'var(--signal)' : score >= 70 ? '#e8a317' : 'var(--sky)'
  return (
    <span className="inline-flex items-center gap-2">
      <span className="h-1.5 overflow-hidden rounded-full bg-well" style={{ width }}>
        <span className="block h-full rounded-full" style={{ width: `${score}%`, background: color }} />
      </span>
      <b className="tabular text-xs">{score}</b>
    </span>
  )
}

export function AiChip({ origin }: { origin: string }) {
  return origin === 'ai'
    ? <span className="rounded-md bg-violet/15 px-1.5 py-0.5 text-[10px] font-medium text-violet">Agent</span>
    : <span className="rounded-md bg-well px-1.5 py-0.5 text-[10px] text-ink-3">{origin || 'source'}</span>
}

/** The steps to resolve one sign of attack (Threat Intel's resolve step). */
export function Resolve({ r, title = 'How to resolve' }: { r: Pick<Resolution, 'steps' | 'done_when' | 'source'>; title?: string }) {
  return (
    <div className="mt-3 rounded-lg bg-well p-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="text-sm font-semibold">{title}</div>
        {r.source === 'ai' ? <AiChip origin="ai" /> : <span className="text-[11px] text-ink-3">Standard steps</span>}
      </div>
      <ol className="mt-2 list-decimal space-y-1 pl-5 text-sm marker:text-ink-3">
        {r.steps.map((s, i) => <li key={i}>{s}</li>)}
      </ol>
      <div className="mt-2 text-xs text-ink-2"><b>Done when:</b> {r.done_when}</div>
      {r.source === 'ai' && <div className="mt-1 text-[11px] text-ink-3">Agent-generated and validated against the data. Review before acting.</div>}
    </div>
  )
}
