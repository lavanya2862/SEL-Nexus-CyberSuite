// How the four agents are shown everywhere: a compact card (dashboard, run summary), a full panel (agent pages and the
// run's agent tabs) with inputs → outputs → what it learned, and the run's story in plain English.
import type { CSSProperties } from 'react'
import { Link } from 'react-router-dom'
import { AlertTriangle, ArrowRight, CheckCircle2, ExternalLink, Info, XCircle } from 'lucide-react'
import { AgentStatusTag, LinkBtn, Panel } from '@/components/kit'
import { StepList } from '@/components/Pipeline'
import { ago } from '@/lib/format'
import { AGENTS, dur } from '@/lib/labels'
import { statusColor } from '@/lib/theme'
import type { AgentId, AgentView, Job, KV, Story } from '@/lib/types'
import { cn } from '@/lib/utils'

export function AgentTile({ id, size = 'md' }: { id: AgentId; size?: 'sm' | 'md' }) {
  const a = AGENTS[id]
  return (
    <span
      className={cn('grid shrink-0 place-items-center rounded-[10px] border', size === 'sm' ? 'size-8' : 'size-10')}
      style={{ color: a.tone, background: `color-mix(in oklab, ${a.tone} 16%, transparent)`, borderColor: `color-mix(in oklab, ${a.tone} 40%, transparent)` } as CSSProperties}
    >
      <a.icon className={size === 'sm' ? 'size-4' : 'size-5'} />
    </span>
  )
}

function KVList({ items }: { items: KV[] }) {
  return (
    <dl className="grid grid-cols-[minmax(0,1fr)_auto] gap-x-4 gap-y-1.5 text-sm">
      {items.map((i) => (
        <div key={i.label} className="contents">
          <dt className="truncate text-ink-3" title={i.label}>{i.label}</dt>
          <dd className="tabular text-right font-medium" style={{ color: i.tone === 'good' ? statusColor.good : i.tone === 'warn' ? statusColor.warning : i.tone === 'bad' ? statusColor.critical : undefined }}>{i.value}</dd>
        </div>
      ))}
    </dl>
  )
}

const LEARN_ICON = { good: CheckCircle2, warn: AlertTriangle, bad: XCircle, info: Info }
const LEARN_COLOR = { good: statusColor.good, warn: statusColor.warning, bad: statusColor.critical, info: 'var(--sky)' }

export function AgentCard({ id, view, to }: { id: AgentId; view?: AgentView | null; to?: string }) {
  const a = AGENTS[id]
  const outs = view?.outputs.length ? view.outputs.slice(0, 3) : null
  const lead = view?.learnings[0]?.text ?? (view ? view.role : a.short)
  return (
    <Link to={to ?? `/agents/${id}`} className="glass-card group flex flex-col gap-3 rounded-[20px] p-5 transition-colors hover:border-hairline-strong">
      <div className="flex items-center gap-3">
        <AgentTile id={id} size="sm" />
        <div className="min-w-0 flex-1">
          <div className="text-[11px] font-semibold uppercase tracking-[0.1em] text-ink-3">Agent {a.n}</div>
          <div className="truncate font-semibold">{a.name}</div>
        </div>
        {view && <AgentStatusTag status={view.status} />}
      </div>
      {outs ? <KVList items={outs} /> : <p className="text-sm text-ink-3">{view?.status === 'running' ? 'In progress…' : view ? 'Awaiting the previous agent.' : 'No scans have been run yet.'}</p>}
      <p className="mt-auto line-clamp-2 border-t border-hairline pt-3 text-xs leading-relaxed text-ink-2">{lead}</p>
      <span className="flex items-center gap-1 text-xs font-medium text-sky">Open {a.name} <ArrowRight className="size-3 transition-transform group-hover:translate-x-0.5" /></span>
    </Link>
  )
}

export function AgentPanel({ view, job }: { view: AgentView; job?: Job }) {
  const a = AGENTS[view.id]
  return (
    <Panel className="flex flex-col gap-5 p-6">
      <div className="flex flex-wrap items-center gap-3">
        <AgentTile id={view.id} />
        <div className="min-w-[200px] flex-1">
          <h3 className="text-base font-semibold">{view.name}</h3>
          <p className="text-sm text-ink-3">{view.role}</p>
        </div>
        <AgentStatusTag status={view.status} />
        {view.duration != null && <span className="text-xs text-ink-3">{dur(view.duration)}</span>}
        {job && <LinkBtn to={`/runs/${job.id}/${view.id}`}>Open in scan <ArrowRight className="size-3.5" /></LinkBtn>}
      </div>
      {job && <p className="-mt-2 text-xs text-ink-3">Scan of <b className="text-ink-2">{job.repo}</b> · {job.status} {ago(job.finished_at ?? job.started_at ?? job.created_at)}</p>}
      {view.summary && <p className="text-sm text-ink-2">{view.summary}</p>}

      <div className="grid grid-cols-1 items-stretch gap-3 md:grid-cols-[1fr_auto_1fr]">
        <div className="rounded-xl border border-hairline bg-well/40 p-4">
          <h4 className="mb-3 text-xs font-semibold uppercase tracking-[0.1em] text-ink-3">1 · Inputs</h4>
          <KVList items={view.inputs} />
        </div>
        <div className="hidden place-items-center text-ink-3 md:grid"><ArrowRight className="size-5" /></div>
        <div className="tint-box rounded-xl p-4" style={{ '--tint': a.tone } as CSSProperties}>
          <h4 className="mb-3 text-xs font-semibold uppercase tracking-[0.1em] text-ink-3">2 · Outputs</h4>
          {view.outputs.length ? <KVList items={view.outputs} /> : (
            <>
              <p className="text-sm text-ink-3">{view.status === 'running' ? 'In progress.' : 'No outputs yet.'} On completion it delivers:</p>
              <ul className="mt-2 list-disc pl-5 text-sm text-ink-2">{view.contract_out.map((x) => <li key={x}>{x}</li>)}</ul>
            </>
          )}
        </div>
      </div>

      <div>
        <h4 className="mb-2 text-xs font-semibold uppercase tracking-[0.1em] text-ink-3">3 · Conclusions</h4>
        {view.learnings.length ? (
          <ul className="flex flex-col gap-2">
            {view.learnings.map((l, i) => {
              const Icon = LEARN_ICON[l.tone] ?? Info
              return (
                <li key={i} className="flex items-start gap-2.5 text-sm text-ink-2">
                  <Icon className="mt-0.5 size-4 shrink-0" style={{ color: LEARN_COLOR[l.tone] ?? 'var(--sky)' }} />
                  <span>{l.text}</span>
                </li>
              )
            })}
          </ul>
        ) : <p className="text-sm text-ink-3">Conclusions appear here on completion.</p>}
      </div>

      {view.steps.length > 0 && (
        <details className="group rounded-xl border border-hairline p-4">
          <summary className="cursor-pointer text-sm font-medium text-ink-2">How it worked: {view.steps.length} step(s)</summary>
          <div className="mt-3"><StepList steps={view.steps} /></div>
        </details>
      )}
    </Panel>
  )
}

/** The run in plain English, ending with what the person needs to decide. */
export function StoryCard({ story, job, linkToRun }: { story: Story; job: Job; linkToRun?: boolean }) {
  const d = story.decision
  const tint = d?.kind === 'pr' ? 'var(--teal)' : d?.kind === 'investigate' || d?.kind === 'retry' ? 'var(--amber)' : 'var(--blue)'
  return (
    <div>
      <div className="text-[11px] font-semibold uppercase tracking-[0.12em] text-ink-3">Summary</div>
      <p className="mt-1 text-lg font-semibold leading-snug tracking-tight">{story.headline}</p>
      {story.lines.filter(Boolean).length > 0 && (
        <ol className="mt-3 flex list-decimal flex-col gap-1.5 pl-5 text-sm text-ink-2">
          {story.lines.filter(Boolean).map((l, i) => <li key={i}>{l}</li>)}
        </ol>
      )}
      {d && (
        <div className="tint-box mt-4 flex flex-wrap items-center gap-3 rounded-xl p-4" style={{ '--tint': tint } as CSSProperties}>
          <div className="min-w-0 flex-1 text-sm">
            <div className="font-semibold text-ink">{d.kind === 'pr' ? 'Next step' : 'Decision required'}</div>
            <div className="text-ink-2">{d.text}</div>
          </div>
          {d.url ? <LinkBtn href={d.url} external kind="good">Open pull request <ExternalLink className="size-3.5" /></LinkBtn>
            : linkToRun ? <LinkBtn to={`/runs/${job.id}`} kind="primary">Review and decide <ArrowRight className="size-3.5" /></LinkBtn> : null}
        </div>
      )}
    </div>
  )
}
