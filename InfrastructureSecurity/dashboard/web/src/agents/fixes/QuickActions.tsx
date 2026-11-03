// The decision buttons on a remediation card (every Remediation tab): approve or withdraw without opening it.
// Approve only where the agent has an automated fix. No automated fix gets "Hand over to IT"; one already with a person
// (handed over, or the agent could not remediate it) gets no button: its steps and "Mark as fixed" are in the details.
import { RotateCcw, Undo2, UserCog, Zap } from 'lucide-react'
import { CardButton } from '@/components/kit'
import { agentCouldNotFix, canApprove, type FixRow } from '@/agents/fixes/data'

export function QuickActions({ rows, busy, onApprove, onWithdraw, onHandOver }: {
  rows: FixRow[]; busy: boolean; onApprove: (ids: string[]) => void; onWithdraw: (ids: string[]) => void
  /** no automatic fix (status info): hand it to the people who must do it by hand */
  onHandOver?: (ids: string[]) => void
}) {
  const ids = (list: FixRow[]) => list.map((r) => r.fix_id)
  const real = rows.filter((r) => r.fix_id.startsWith('fx_'))          // only remediations the fix engine knows
  const can = real.filter(canApprove)
  const retry = can.length > 0 && can.every((r) => r.status === 'failed' || r.status === 'still_there')
  const approved = real.filter((r) => r.status === 'approved')
  const noFix = real.filter((r) => r.status === 'info')
  const withPerson = real.filter((r) => r.status === 'manual_required')
  const many = rows.length > 1
  return (
    <>
      {can.length > 0 && (
        <CardButton primary disabled={busy} onClick={() => onApprove(ids(can))}>
          {retry ? <RotateCcw className="size-3.5" /> : <Zap className="size-3.5" />} {retry ? 'Retry' : 'Approve'}{many ? ` ${can.length}` : ''}
        </CardButton>
      )}
      {onHandOver && noFix.length > 0 && (
        <CardButton disabled={busy} onClick={() => onHandOver(ids(noFix))}><UserCog className="size-3.5" /> Hand over to IT{many ? ` ${noFix.length}` : ''}</CardButton>
      )}
      {can.length === 0 && noFix.length === 0 && withPerson.length > 0 && (
        <span className="inline-flex items-center gap-1 text-xs text-ink-3">
          <UserCog className="size-3.5" /> {withPerson.some(agentCouldNotFix) ? 'Manual steps ready' : 'With IT'} · mark as fixed in Details
        </span>
      )}
      {approved.length > 0 && (
        <CardButton disabled={busy} onClick={() => onWithdraw(ids(approved))}><Undo2 className="size-3.5" /> Withdraw{many ? ` ${approved.length}` : ''}</CardButton>
      )}
    </>
  )
}
