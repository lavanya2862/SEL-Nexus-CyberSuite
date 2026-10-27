// The six steps of a run, left to right, with each step's live status. Click a step to see what it did.
import type { CSSProperties } from 'react'
import { AlertTriangle, Check, Circle, Loader2, Minus, X } from 'lucide-react'
import { AgentStatusTag, Chip } from '@/components/kit'
import { AGENTS, STAGES, dur } from '@/lib/labels'
import { statusColor } from '@/lib/theme'
import type { Stage, Step } from '@/lib/types'
import { cn } from '@/lib/utils'

const STATUS_COLOR: Record<string, string> = {
  completed: statusColor.good, warning: statusColor.warning, failed: statusColor.critical, running: 'var(--blue)', pending: 'var(--ink-3)', skipped: 'var(--ink-3)',
}

export function stageStatusText(s: Stage) {
  if (s.status === 'running') return 'Running…'
  if (s.status === 'pending') return 'Waiting'
  if (s.status === 'skipped') return 'Skipped'
  return `${s.status[0].toUpperCase()}${s.status.slice(1)}${s.duration_seconds != null ? ' · ' + dur(s.duration_seconds) : ''}`
}

function metricChips(s: Stage): string[] {
  const m = s.metrics ?? {}
  const out: string[] = []
  if (s.id === 'analysis' && m.unique != null) out.push(`${m.unique} findings`, `${m.critical ?? 0} crit · ${m.high ?? 0} high`)
  if (s.id === 'remediation' && m.fixes != null) out.push(`${m.fixes} fixes`, `${m.ai_fixes ?? 0} code fixes`)
  if (s.id === 'validation' && m.verdict) out.push(String(m.verdict), `${m.verified ?? 0} confirmed`)
  if (s.id === 'ingest' && m.commit) out.push(String(m.commit).slice(0, 8))
  if (s.id === 'reporting' && m.artifacts) out.push(`${m.artifacts} files`)
  if (s.id === 'approval' && m.pull_request) out.push('PR opened')
  return out
}

export function PipelineFlow({ stages, selected, onSelect }: { stages: Stage[]; selected?: string | null; onSelect?: (id: string) => void }) {
  return (
    <ol className="grid grid-cols-2 gap-2 sm:grid-cols-3 xl:grid-cols-6" aria-label="Pipeline steps">
      {stages.map((s, i) => {
        const meta = STAGES.find((d) => d.id === s.id)!
        const Icon = s.status === 'running' ? Loader2 : s.status === 'completed' ? Check : s.status === 'failed' ? X : s.status === 'warning' ? AlertTriangle : s.status === 'skipped' ? Minus : meta.icon
        const color = STATUS_COLOR[s.status] ?? 'var(--ink-3)'
        const active = s.id === selected
        const chips = metricChips(s)
        const Tag = onSelect ? 'button' : 'div'
        return (
          <li key={s.id} className="relative">
            <Tag
              {...(onSelect ? { onClick: () => onSelect(s.id), 'aria-pressed': active, type: 'button' as const } : {})}
              title={s.description}
              className={cn(
                'flex h-full w-full flex-col items-start gap-2 rounded-xl border p-3 text-left transition-colors',
                active ? 'border-blue bg-blue/10' : 'border-hairline bg-well/40',
                onSelect && !active && 'hover:border-hairline-strong hover:bg-well',
              )}
            >
              <div className="flex w-full items-center gap-2">
                <span
                  className={cn('grid size-8 shrink-0 place-items-center rounded-[9px] border', s.status === 'pending' && 'border-hairline bg-well')}
                  style={s.status !== 'pending' ? ({ color, background: `color-mix(in oklab, ${color} 16%, transparent)`, borderColor: `color-mix(in oklab, ${color} 40%, transparent)` } as CSSProperties) : { color }}
                >
                  <Icon className={cn('size-4', s.status === 'running' && 'animate-spin')} />
                </span>
                <span className="text-[11px] font-semibold uppercase tracking-[0.1em] text-ink-3">Step {i + 1}</span>
              </div>
              <div className="min-w-0">
                <div className="text-sm font-semibold leading-snug text-ink">{meta.short}</div>
                {/* the agent doing this step stands out in the signal colour; the pipeline's own steps and "You" stay plain */}
                {s.agent && s.id in AGENTS
                  ? <div className="text-xs font-semibold text-[var(--signal)]">{s.agent}</div>
                  : <div className="text-xs text-ink-3">{s.agent ?? (s.id === 'approval' ? 'You' : 'Pipeline')}</div>}
              </div>
              <div className="text-xs font-medium" style={{ color: s.status === 'pending' || s.status === 'skipped' ? 'var(--ink-3)' : color }}>{stageStatusText(s)}</div>
              {chips.length > 0 && <div className="flex flex-wrap gap-1">{chips.map((c) => <span key={c} className="rounded-md border border-hairline px-1.5 py-0.5 text-[11px] text-ink-2">{c}</span>)}</div>}
            </Tag>
          </li>
        )
      })}
    </ol>
  )
}

export function StepList({ steps }: { steps: Step[] }) {
  return (
    <ul className="flex flex-col gap-2">
      {steps.map((st, i) => {
        const Icon = st.status === 'completed' ? Check : st.status === 'failed' ? X : st.status === 'warning' ? AlertTriangle : st.status === 'skipped' ? Minus : st.status === 'running' ? Loader2 : Circle
        return (
          <li key={i} className="flex items-start gap-2.5 text-sm">
            <Icon className={cn('mt-0.5 size-4 shrink-0', st.status === 'running' && 'animate-spin')} style={{ color: STATUS_COLOR[st.status] ?? 'var(--ink-3)' }} />
            <div className="min-w-0">
              <div className="text-ink">{st.name}</div>
              {st.detail && <div className="text-xs leading-relaxed text-ink-3">{st.detail}</div>}
            </div>
          </li>
        )
      })}
    </ul>
  )
}

export function StageDetail({ stage }: { stage?: Stage }) {
  if (!stage) return null
  const meta = STAGES.find((d) => d.id === stage.id)!
  return (
    <div className="mt-4 rounded-xl border border-hairline bg-well/40 p-4">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-semibold">{stage.name}</span>
        {stage.agent && <Chip>{stage.agent}</Chip>}
        <AgentStatusTag status={stage.status} />
      </div>
      <p className="mt-1 text-sm text-ink-3">{stage.summary || meta.description}</p>
      <div className="mt-3">
        {stage.steps?.length ? <StepList steps={stage.steps} />
          : <p className="text-sm text-ink-3">{stage.status === 'pending' ? 'This step has not started yet.' : stage.status === 'running' ? 'Working on it; its steps appear here as they finish.' : 'No step details.'}</p>}
      </div>
    </div>
  )
}
