// The decision buttons on a remediation card (every Remediation tab): approve, defer or withdraw without opening it.
// A remediation waiting for a person gets none: only the owner's manual fix (in the details) closes it.
import { Bookmark, RotateCcw, Undo2, UserCog, Zap } from 'lucide-react'
import { CardButton } from '@/components/kit'
import { canApprove, type FixRow } from '@/agents/fixes/data'

export function QuickActions({ rows, busy, onApprove, onWithdraw, onSave, onHandOver }: {
  rows: FixRow[]; busy: boolean; onApprove: (ids: string[]) => void; onWithdraw: (ids: string[]) => void; onSave?: (ids: string[]) => void
  /** no automatic fix (status info): hand it to the people who must do it by hand */
  onHandOver?: (ids: string[]) => void
}) {
  const ids = (list: FixRow[]) => list.map((r) => r.fix_id)
  const can = rows.filter(canApprove)
  const retry = can.length > 0 && can.every((r) => r.status === 'failed' || r.status === 'still_there')
  const proposed = rows.filter((r) => r.status === 'proposed')
  const approved = rows.filter((r) => r.status === 'approved')
  const noFix = rows.filter((r) => r.status === 'info')
  const many = rows.length > 1
  return (
    <>
      {can.length > 0 && (
        <CardButton primary disabled={busy} onClick={() => onApprove(ids(can))}>
          {retry ? <RotateCcw className="size-3.5" /> : <Zap className="size-3.5" />} {retry ? 'Retry' : 'Approve'}{many ? ` ${can.length}` : ''}
        </CardButton>
      )}
      {onSave && proposed.length > 0 && (
        <CardButton disabled={busy} onClick={() => onSave(ids(proposed))}><Bookmark className="size-3.5" /> Defer</CardButton>
      )}
      {onHandOver && noFix.length > 0 && (
        <CardButton primary disabled={busy} onClick={() => onHandOver(ids(noFix))}><UserCog className="size-3.5" /> Hand over{many ? ` ${noFix.length}` : ''}</CardButton>
      )}
      {approved.length > 0 && (
        <CardButton disabled={busy} onClick={() => onWithdraw(ids(approved))}><Undo2 className="size-3.5" /> Withdraw{many ? ` ${approved.length}` : ''}</CardButton>
      )}
    </>
  )
}
