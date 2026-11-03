// The handover when the Remediation Agent cannot remediate something itself, and the record once a person did it by
// hand. One component for every page that shows a remediation (Fix Centre, progress, attack responses, run pages), so
// the same fix reads the same everywhere.
import { useState } from 'react'
import { ChevronDown, ClipboardCheck, Hand, UserCog } from 'lucide-react'
import { useFixAction, type FixRow } from '@/agents/fixes/data'
import { ago } from '@/lib/format'
import { statusColor } from '@/lib/theme'
import { cn } from '@/lib/utils'

const MOVE: Record<string, string> = {
  winget: 'Install with winget', choco: 'Install with Chocolatey', uninstall: 'Uninstall', apply: 'Apply setting',
  quick_scan: 'Quick scan', full_scan: 'Full scan',
}

/** Who remediated it by hand, when, and their note. */
function DoneByHand({ m }: { m: NonNullable<FixRow['manual']> }) {
  return (
    <div className="mt-2 flex items-start gap-2 rounded-lg border border-hairline bg-well/50 px-3 py-2 text-xs text-ink-2">
      <Hand className="mt-0.5 size-3.5 shrink-0 text-ink-3" />
      <span>Remediated manually by <b className="text-ink">{m.by}</b> · {ago(m.at)}{m.note && <> · <span className="text-ink-3">{m.note}</span></>}
        <span className="block text-ink-3">Microsoft Defender verifies it on its next scan.</span></span>
    </div>
  )
}

/** When the next re-check of an update awaiting its vendor's package is due (the plan re-queues it a day after). */
export const nextVendorCheck = (r: FixRow) => (r.finished_at ? new Date(new Date(r.finished_at.replace(' ', 'T') +
  (/[zZ]|[+-]\d\d:?\d\d$/.test(r.finished_at) ? '' : 'Z')).getTime() + 24 * 3600_000) : null)

/** The Remediation Agent's one-line reason for a remediation it cannot run, or that the AI could not write it. */
export function noFixReason(r: FixRow): string {
  if (r.brief?.reason) return r.brief.reason
  if (r.brief?.unavailable) return `AI ${r.brief.unavailable}`
  return ''
}

export function PersonLine({ r, short }: { r?: FixRow | null; short?: boolean }) {
  if (r?.status === 'gone') return <span className="line-clamp-2 text-xs text-ink-3" title={r.message ?? undefined}>{short ? 'Updated or removed outside CyberSuite before it ran' : r.message}</span>
  if (r?.status === 'info') return noFixReason(r) ? <span className="truncate text-xs text-ink-3" title={r.brief?.cause || undefined}>{noFixReason(r)}</span> : null
  if (short) {                              // one quiet line for a small card; the details carry the rest
    if (r?.status === 'manual_required') return r.handover?.reason ? <span className="truncate text-xs text-ink-3">{r.handover.reason}</span> : null
    if (r?.status === 'awaiting_vendor') {
      const next = nextVendorCheck(r)
      return <span className="truncate text-xs text-ink-3">{next && next.getTime() > Date.now() ? `Re-checked ${next.toLocaleString(undefined, { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' })}` : 'Re-checked with the next run'}</span>
    }
    return null
  }
  if (r?.status === 'manual_required') {
    return (
      <div className="mt-1 rounded-md px-2 py-1.5 text-[11px]" style={{ background: `${statusColor.critical}14` }}>
        <span className="inline-flex items-center gap-1 font-semibold" style={{ color: statusColor.critical }}><UserCog className="size-3.5" /> Awaiting manual remediation</span>
        
        {r.handover?.cause && <span className="mt-0.5 line-clamp-2 block text-ink-3">{r.handover.cause}</span>}
      </div>
    )
  }
  if (r?.status === 'awaiting_vendor') {
    const next = nextVendorCheck(r)
    return (
      <div className="mt-1 rounded-md bg-well px-2 py-1.5 text-[11px] text-ink-2">
        No newer version published yet{next ? <> · checked again {next.getTime() > Date.now() ? `around ${next.toLocaleString(undefined, { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' })}` : 'with the next remediation run'}</> : null}
      </div>
    )
  }
  return null
}

/** Awaiting manual remediation: the Remediation Agent's cause and steps (or that the AI was not available), what it
 *  tried, the evidence, and "Mark as fixed manually". */
export function ManualAction({ r, compact }: { r: FixRow; compact?: boolean }) {
  const [open, setOpen] = useState(!compact)
  const [note, setNote] = useState('')
  const act = useFixAction()
  if (r.manual && r.status !== 'manual_required') return <DoneByHand m={r.manual} />
  const h = r.handover
  if (r.status !== 'manual_required' || !h) return null
  const tries = (r.agent ?? []).filter((m) => m.action !== 'stop')
  return (
    <div className="mt-2 overflow-hidden rounded-xl border text-left" style={{ borderColor: `${statusColor.critical}55` }}>
      <button type="button" onClick={() => setOpen((o) => !o)} aria-expanded={open}
        className="flex w-full items-center gap-2 px-3 py-2 text-left text-xs" style={{ background: `${statusColor.critical}14` }}>
        <UserCog className="size-4 shrink-0" style={{ color: statusColor.critical }} />
        <span className="font-semibold" style={{ color: statusColor.critical }}>Awaiting manual remediation</span>
        
        <span className="ml-auto shrink-0 text-ink-3">{ago(h.at)}</span>
        <ChevronDown className={cn('size-4 shrink-0 text-ink-3 transition-transform', open && 'rotate-180')} />
      </button>
      {!open && <p className="line-clamp-2 px-3 pb-2 pt-1.5 text-xs text-ink-2">{h.cause || (h.ai_unavailable ? `AI ${h.ai_unavailable}` : h.result)}</p>}
      {open && (
        <div className="flex flex-col gap-3 px-3 py-3 text-xs">
          {h.ai_unavailable && (
            <p className="rounded-lg bg-well px-2.5 py-2 text-ink-2"><b className="text-ink">AI {h.ai_unavailable}.</b> The Remediation Agent could not write the cause and steps for this remediation.</p>
          )}
          {h.cause && (
            <div>
              <div className="mb-0.5 font-medium text-ink-3">Cause</div>
              <p className="text-ink">{h.cause}</p>
            </div>
          )}
          {h.result && (
            <div>
              <div className="mb-0.5 font-medium text-ink-3">Result on the computer</div>
              <p className="text-ink-2">{h.result}</p>
            </div>
          )}
          {h.steps.length > 0 && (
            <div>
              <div className="mb-1 font-medium text-ink-3">Steps (Remediation Agent{h.model ? ` · ${h.model}` : ''})</div>
              <ol className="flex list-decimal flex-col gap-1 pl-4 text-ink">{h.steps.map((s, i) => <li key={i}>{s}</li>)}</ol>
            </div>
          )}
          {tries.length > 0 && (
            <div>
              <div className="mb-1 font-medium text-ink-3">What the agent tried</div>
              <ol className="flex flex-col gap-1">
                {tries.map((m, i) => (
                  <li key={i} className="flex gap-2">
                    <span className="tabular text-ink-3">{i + 1}.</span>
                    <span><b className="font-medium text-ink">{MOVE[m.action] ?? m.action}</b>
                      <span style={{ color: m.status === 'done' ? statusColor.good : statusColor.critical }}> · {m.status === 'done' ? 'succeeded' : 'did not succeed'}</span>
                      <span className="block text-ink-3">{m.result}</span></span>
                  </li>
                ))}
              </ol>
            </div>
          )}
          {h.evidence.length > 0 && (
            <details className="group">
              <summary className="cursor-pointer font-medium text-ink-3 hover:text-ink">Evidence from the computer</summary>
              <ul className="mt-1 flex flex-col gap-0.5 rounded-lg bg-well px-2.5 py-2 font-mono text-[11px] text-ink-2">
                {h.evidence.map((e, i) => <li key={i} className="break-words">{e}</li>)}
              </ul>
            </details>
          )}
          <form className="flex flex-col gap-2 border-t border-hairline pt-3"
            onSubmit={(e) => { e.preventDefault(); act.mutate({ action: 'manual', ids: [r.fix_id], note }) }}>
            <label htmlFor={`manual-${r.fix_id}`} className="font-medium text-ink-3">What you did (saved in the audit log)</label>
            <textarea id={`manual-${r.fix_id}`} value={note} onChange={(e) => setNote(e.target.value)} rows={2} maxLength={500}
              placeholder="e.g. Removed with the vendor's installer (/uninstall) and deleted the leftover folder"
              className="w-full resize-y rounded-lg border border-hairline-strong bg-field px-2.5 py-2 text-xs text-ink placeholder:text-ink-3 focus-visible:border-blue/60 focus-visible:outline-none" />
            <div className="flex flex-wrap items-center gap-2">
              <button type="submit" disabled={act.isPending}
                className="btn-blue inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-semibold text-white disabled:opacity-60">
                <ClipboardCheck className="size-3.5" /> {act.isPending ? 'Saving…' : 'Mark as fixed manually'}
              </button>
              <span className="text-ink-3">Defender verifies it on its next scan.</span>
              {act.error && <span style={{ color: statusColor.critical }}>{String((act.error as Error).message)}</span>}
            </div>
          </form>
        </div>
      )}
    </div>
  )
}
