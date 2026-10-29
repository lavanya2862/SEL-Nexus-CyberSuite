import { useMemo, useState } from 'react'
import { AlertTriangle, Check, CheckCircle2, Loader2, Minus, Play, RefreshCw, ShieldCheck, Undo2, X } from 'lucide-react'
import { Dialog, DialogContent, DialogDescription, DialogTitle } from '@/components/ui/dialog'
import { GettingReady, useAutoStart } from '@/lib/services'
import { Choice, Empty, Panel, Tag } from '@/components/kit'
import { ago, dateTime, num } from '@/lib/format'
import { UC_NAME } from '@/lib/runs'
import { statusColor } from '@/lib/theme'
import { cn } from '@/lib/utils'
import {
  ACTION_LABEL, FixDown, METHOD_LABEL, SOURCE_UC, STATUS, canApprove, canWithdraw, fixTime, useFix, useFixAction,
  type FixMethod, type FixRow, type FixSource, type FixStatus, type FixView,
} from '@/lib/fix'

const utc = (s: string | null | undefined) => (s ? s.replace(' ', 'T') + (s.endsWith('Z') || s.includes('+') ? '' : 'Z') : null)
/** Stage names in Defender's words; plans saved before the rename still carry the old names in v.stages */
const STAGE_NAME: Record<number, string> = { 2: 'End of support', 3: 'Routine update', 4: 'No action needed' }

/** "Fix automatically": approve, run and verify fixes on the lab VMs with UC1's fix engine. */
export function FixLoop() {
  const { data, error, isLoading } = useFix()
  const auto = useAutoStart(error instanceof FixDown, 'fix')
  if (isLoading) return <Panel className="h-64 animate-pulse">{null}</Panel>
  if (error instanceof FixDown || (error && !data)) {
    return (
      <Panel className="p-6">
        {error instanceof FixDown
          ? <GettingReady what="automated remediation" {...auto} />
          : <p className="text-sm" style={{ color: statusColor.critical }}>Could not load remediation tasks: {String((error as Error).message)}</p>}
      </Panel>
    )
  }
  return <Loop v={data!} />
}

function Loop({ v }: { v: FixView }) {
  const act = useFixAction()
  const [sel, setSel] = useState<Set<string>>(new Set())
  const [method, setMethod] = useState<FixMethod>(v.default_method)
  const [confirm, setConfirm] = useState<null | 'run' | 'all'>(null)
  const busy = v.worker.running || v.worker.elsewhere
  const fixable = v.rows.filter((r) => r.action !== 'none')
  const approved = v.rows.filter((r) => r.status === 'approved')
  const inFlight = v.rows.filter((r) => r.status === 'queued' || r.status === 'running')
  const urgent = fixable.filter((r) => r.stage === 1 && canApprove(r))
  const byDevice = useMemo(() => {
    const m = new Map<string, FixRow[]>()
    for (const r of v.rows) m.set(r.device_name, [...(m.get(r.device_name) ?? []), r])
    return [...m.entries()].sort()
  }, [v.rows])
  const selected = v.rows.filter((r) => sel.has(r.fix_id))
  const toggle = (id: string) => setSel((s) => { const n = new Set(s); if (n.has(id)) n.delete(id); else n.add(id); return n })
  const run = (action: 'approve' | 'unapprove' | 'run' | 'probe', ids: string[] = []) =>
    act.mutate({ action, ids, method }, { onSuccess: () => setSel(new Set()) })

  return (
    <div className="flex flex-col gap-5">
      {/* what this is + the impact so far */}
      <Panel className="grid gap-6 p-6 lg:grid-cols-[minmax(0,1.3fr)_minmax(0,1fr)]">
        <div>
          <h2 className="text-lg font-semibold tracking-tight">Automated remediation</h2>
          <p className="mt-1 max-w-2xl text-sm leading-relaxed text-ink-2">
            You approve; the agent updates or removes the old app on the device (winget, through {METHOD_LABEL[v.default_method]}),
            checks the installed version before and after, and the next threat check asks Defender to confirm the vulnerability is gone.
            Commands come only from the approved remediation catalogue. Nothing runs without your approval.
          </p>
          <ol className="mt-4 grid grid-cols-2 gap-2 text-xs sm:grid-cols-4">
            {['1 · Plan', '2 · You approve', '3 · Remediate', '4 · Defender verifies'].map((s) => (
              <li key={s} className="rounded-lg bg-well px-3 py-2 font-medium text-ink-2">{s}</li>
            ))}
          </ol>
        </div>
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
          {([
            [v.totals.approved, 'approved, waiting to run'],
            [(v.totals.done ?? 0) + (v.totals.running ?? 0) + (v.totals.queued ?? 0), 'remediated or in progress'],
            [v.totals.verified, 'verified by Defender'],
            [v.totals.failed, 'failed'],
            [v.impact.findings_cleared, 'findings cleared'],
          ] as const).map(([n, l]) => (
            <div key={l} className="rounded-xl bg-well px-3.5 py-3">
              <div className="tabular text-lg font-semibold leading-none" style={{ color: l === 'failed' && n ? statusColor.critical : undefined }}>{num(n ?? 0)}</div>
              <div className="mt-1.5 text-[11px] leading-snug text-ink-3">{l}</div>
            </div>
          ))}
        </div>
      </Panel>

      {/* computers: read-only check results */}
      <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
        {byDevice.map(([device]) => <ProbeCard key={device} device={device} p={v.probes[device]} />)}
      </div>

      {/* actions */}
      <Panel className="flex flex-wrap items-center gap-2 p-4">
        <div className="flex items-center gap-2 text-sm text-ink-2">
          How
          <Choice label="Remediation method" value={method} onChange={(v) => setMethod(v as FixMethod)} className="w-auto py-1.5"
            options={[{ value: 'runcommand', label: 'Azure Run Command (Azure VMs)' }, { value: 'liveresponse', label: 'Defender Live Response (any Defender device)' }]} />
        </div>
        <span className="mx-1 h-6 w-px bg-hairline" />
        <Btn onClick={() => run('approve', selected.filter(canApprove).map((r) => r.fix_id))} disabled={!selected.some(canApprove) || act.isPending}>
          <Check className="size-4" /> Approve selected
        </Btn>
        <Btn onClick={() => run('approve', urgent.map((r) => r.fix_id))} disabled={!urgent.length || act.isPending}>
          <AlertTriangle className="size-4" /> Approve all high priority ({urgent.length})
        </Btn>
        <Btn onClick={() => setConfirm('all')} disabled={!fixable.some(canApprove) || act.isPending}>Approve everything</Btn>
        <Btn onClick={() => run('unapprove', selected.filter(canWithdraw).map((r) => r.fix_id))} disabled={!selected.some(canWithdraw) || act.isPending}>
          <Undo2 className="size-4" /> Withdraw selected
        </Btn>
        <span className="flex-1" />
        <Btn onClick={() => run('probe')} disabled={busy || act.isPending}>
          <RefreshCw className="size-4" /> Check devices (read-only)
        </Btn>
        <button
          onClick={() => setConfirm('run')}
          disabled={busy || !approved.length || act.isPending}
          className="inline-flex items-center gap-2 rounded-lg btn-blue px-4 py-2 text-sm font-medium text-white disabled:cursor-not-allowed disabled:opacity-40"
        >
          <Play className="size-4" /> Run approved remediations ({approved.length})
        </button>
      </Panel>
      {act.error && (
        <div className="-mt-3 rounded-xl border px-4 py-2.5 text-sm" style={{ borderColor: statusColor.critical }}>{String((act.error as Error).message)}</div>
      )}

      {(busy || inFlight.length > 0 || v.worker.message) && <Progress v={v} />}

      {/* the plan, per computer */}
      {byDevice.length ? byDevice.map(([device, rows]) => (
        <DevicePlan key={device} device={device} rows={rows} stages={v.stages} sel={sel} toggle={toggle}
          setMany={(ids, on) => setSel((s) => { const n = new Set(s); ids.forEach((i) => (on ? n.add(i) : n.delete(i))); return n })} />
      )) : <Empty text="No remediation plan yet: it is built on every Threat Intel run." />}

      <Panel className="p-6">
        <h3 className="font-semibold tracking-tight">Activity</h3>
        <p className="mt-1 text-sm text-ink-3">Every approval, remediation and Defender verification, most recent first</p>
        <ul className="mt-4 flex max-h-80 flex-col divide-y divide-hairline overflow-auto">
          {v.events.slice(0, 60).map((e, i) => (
            <li key={i} className="flex gap-3 py-2 text-sm">
              <span className="tabular w-20 shrink-0 text-xs text-ink-3">{ago(utc(e.at))}</span>
              <span className="text-ink-2 [overflow-wrap:anywhere]">{e.text}</span>
            </li>
          ))}
          {!v.events.length && <li className="py-2 text-sm text-ink-3">Nothing yet.</li>}
        </ul>
      </Panel>

      <ConfirmDialog
        open={confirm !== null}
        onClose={() => setConfirm(null)}
        title={confirm === 'run' ? `Execute ${approved.length} approved remediations?` : `Approve all ${fixable.filter(canApprove).length} remediations?`}
        body={confirm === 'run'
          ? `On ${[...new Set(approved.map((r) => r.device_name))].join(' and ')}, the agent will power on each device if needed, close the applications and update or remove them. This changes the devices and the vulnerability figures on every page. Keep powered-on VMs running for about 6 hours so Defender can verify the changes.`
          : 'Every application on every device in the plan is approved, including removal of end-of-support applications. Nothing runs until execution is started.'}
        confirmLabel={confirm === 'run' ? 'Execute remediation' : 'Approve everything'}
        onConfirm={() => {
          if (confirm === 'run') run('run')
          else run('approve', fixable.filter(canApprove).map((r) => r.fix_id))
          setConfirm(null)
        }}
      />
    </div>
  )
}

function Btn({ children, ...p }: React.ButtonHTMLAttributes<HTMLButtonElement>) {
  return <button {...p} className="inline-flex items-center gap-2 rounded-lg border border-hairline bg-panel px-3 py-2 text-sm font-medium hover:bg-well disabled:cursor-not-allowed disabled:opacity-40">{children}</button>
}

export function ProbeCard({ device, p }: { device: string; p?: FixView['probes'][string] }) {
  const ok = p && !p.error
  const off = p?.error?.includes('switched off')
  const color = ok ? statusColor.good : off ? statusColor.warning : p ? statusColor.critical : 'var(--ink-3)'
  return (
    <Panel className="flex items-start gap-3 p-4">
      <span className="mt-1 size-2.5 shrink-0 rounded-full" style={{ background: color }} />
      <div className="min-w-0 flex-1">
        <div className="flex items-baseline justify-between gap-2">
          <span className="font-medium">{device}</span>
          <span className="text-xs text-ink-3">{p?.checked_at ? `checked ${ago(utc(p.checked_at))}` : 'not checked yet'}</span>
        </div>
        <p className="mt-0.5 text-xs leading-relaxed text-ink-3">
          {!p ? 'Select “Check devices” to confirm the agent can reach it (read-only; never powers on a VM).'
            : ok ? `Reachable · winget ${p.winget || 'not found'}${p.reboot_pending ? ' · restart pending' : ''} · ${p.apps?.length ?? 0} catalogue apps found`
              : off ? 'Azure access confirmed · the VM is powered off. A remediation run powers it on.'
                : p.error}
        </p>
      </div>
    </Panel>
  )
}

/* live progress: one lane per computer, each fix steps forward queued → running → fixed */
export function Progress({ v }: { v: FixView }) {
  const runRows = v.rows.filter((r) => ['queued', 'running'].includes(r.status) || (r.started_at && v.worker.running))
  const lanes = [...new Set(runRows.map((r) => r.device_name))].sort()
  const finished = runRows.filter((r) => !['queued', 'running'].includes(r.status)).length
  const pct = runRows.length ? (finished / runRows.length) * 100 : 0
  const live = v.worker.running || v.worker.elsewhere
  return (
    <Panel className="overflow-hidden p-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2.5">
          {live ? <Loader2 className="size-5 animate-spin text-sky" /> : <CheckCircle2 className="size-5" style={{ color: statusColor.good }} />}
          <div>
            <h3 className="font-semibold tracking-tight">
              {live ? (v.worker.task === 'probe' ? 'Checking device connectivity…' : 'Remediating…') : 'Last remediation task'}
            </h3>
            <p key={v.worker.step || v.worker.message} className="text-sm text-ink-3 animate-in fade-in slide-in-from-left-1 duration-300">
              {live ? v.worker.step || 'Starting' : v.worker.message}
            </p>
          </div>
        </div>
        {runRows.length > 0 && <span className="tabular text-sm text-ink-2">{finished} of {runRows.length} done</span>}
      </div>
      {runRows.length > 0 && (
        <>
          <div className="mt-4 h-1.5 overflow-hidden rounded-full bg-well">
            <div className="relative h-full rounded-full bg-sky transition-[width] duration-700 ease-out" style={{ width: `${Math.max(pct, live ? 4 : 0)}%` }}>
              {live && <span className="absolute inset-0 animate-[portal-shimmer_1.4s_linear_infinite] bg-[linear-gradient(90deg,transparent,rgba(255,255,255,.55),transparent)] bg-[length:50%_100%] bg-no-repeat" />}
            </div>
          </div>
          <div className="mt-5 grid grid-cols-1 gap-5 md:grid-cols-2">
            {lanes.map((dev) => (
              <div key={dev}>
                <div className="mb-2 text-sm font-medium">{dev}</div>
                <ol>
                  {runRows.filter((r) => r.device_name === dev).map((r, i, arr) => (
                    <li key={r.fix_id} className="relative flex gap-3 pb-4 last:pb-0">
                      {i < arr.length - 1 && (
                        <span className="absolute left-[11px] top-7 h-[calc(100%-24px)] w-0.5 overflow-hidden rounded-full bg-hairline" aria-hidden>
                          <span className={cn('block w-full bg-sky transition-[height] duration-700 ease-out', ['queued', 'running'].includes(r.status) ? 'h-0' : 'h-full')} />
                        </span>
                      )}
                      <StepIcon s={r.status} />
                      <div className="min-w-0 flex-1">
                        <div className="text-sm">{ACTION_LABEL[r.action]} {r.app} <span className="text-ink-3">{r.version}</span></div>
                        <div key={r.status} className="text-xs text-ink-3 animate-in fade-in duration-300">{r.message ?? STATUS[r.status].label}</div>
                      </div>
                    </li>
                  ))}
                </ol>
              </div>
            ))}
          </div>
        </>
      )}
    </Panel>
  )
}

function StepIcon({ s }: { s: FixStatus }) {
  if (s === 'running')
    return (
      <span className="relative z-10 grid size-6 shrink-0 place-items-center rounded-full bg-panel">
        <span className="absolute inset-0 animate-ping rounded-full bg-sky/30" />
        <Loader2 className="size-5 animate-spin text-sky" />
      </span>
    )
  if (s === 'queued') return <span className="relative z-10 size-6 shrink-0 rounded-full border-2 border-hairline bg-panel" />
  if (s === 'failed')
    return <span className="relative z-10 grid size-6 shrink-0 place-items-center rounded-full text-white animate-in zoom-in-50 duration-300" style={{ background: statusColor.critical }}><X className="size-3.5" strokeWidth={3} /></span>
  if (s === 'done' || s === 'verified')
    return <span className="relative z-10 grid size-6 shrink-0 place-items-center rounded-full bg-sky text-white animate-in zoom-in-50 duration-300"><Check className="size-3.5" strokeWidth={3} /></span>
  return <span className="relative z-10 grid size-6 shrink-0 place-items-center rounded-full bg-well text-ink-3"><Minus className="size-3" /></span>
}

export function StatusPill({ r }: { r: FixRow }) {
  const s = STATUS[r.status]
  const color = { muted: 'var(--ink-3)', sky: 'var(--sky)', run: 'var(--sky)', teal: 'var(--teal)', good: statusColor.good, bad: statusColor.critical, warn: '#b37400' }[s.tone]
  return (
    <span className="inline-flex items-center gap-1.5 whitespace-nowrap text-xs font-medium" style={{ color }}>
      {r.status === 'running' ? <Loader2 className="size-3 animate-spin" /> : r.status === 'verified' ? <ShieldCheck className="size-3" /> : <span className="size-1.5 rounded-full" style={{ background: color }} />}
      {s.label}
    </span>
  )
}

function DevicePlan({ device, rows, stages, sel, toggle, setMany }: {
  device: string; rows: FixRow[]; stages: Record<string, string>; sel: Set<string>; toggle: (id: string) => void
  setMany: (ids: string[], on: boolean) => void
}) {
  const selectable = rows.filter((r) => canApprove(r) || canWithdraw(r)).map((r) => r.fix_id)
  const allOn = selectable.length > 0 && selectable.every((i) => sel.has(i))
  return (
    <Panel className="p-6">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h3 className="font-semibold tracking-tight">{device}</h3>
          <p className="text-sm text-ink-3">
            {rows.filter((r) => r.status === 'approved').length} approved · {rows.filter((r) => r.status === 'verified').length} verified · {num(rows.reduce((a, r) => a + r.findings, 0))} findings in the plan
          </p>
        </div>
        <label className="flex items-center gap-2 text-sm text-ink-2">
          <input type="checkbox" className="size-4 accent-[var(--blue)]" checked={allOn} disabled={!selectable.length} onChange={(e) => setMany(selectable, e.target.checked)} />
          Select all on this device
        </label>
      </div>
      <div className="mt-4 overflow-x-auto rounded-xl border border-hairline">
        <table className="w-full min-w-[820px] text-sm">
          <thead>
            <tr className="bg-well text-left text-xs text-ink-3">
              <th className="w-10 px-3 py-2.5" />
              <th className="px-3 py-2.5 font-medium">Stage</th>
              <th className="px-3 py-2.5 font-medium">App</th>
              <th className="px-3 py-2.5 font-medium">Action</th>
              <th className="px-3 py-2.5 text-right font-medium">Findings</th>
              <th className="px-3 py-2.5 font-medium">Status</th>
              <th className="px-3 py-2.5 font-medium">Result</th>
            </tr>
          </thead>
          <tbody className="[&_td]:px-3 [&_td]:py-2.5 [&_tr]:border-t [&_tr]:border-hairline">
            {rows.map((r) => {
              const on = canApprove(r) || canWithdraw(r)
              return (
                <tr key={r.fix_id} className={cn('align-top', sel.has(r.fix_id) && 'bg-well/70', r.status === 'running' && 'bg-sky/5')}>
                  <td><input type="checkbox" className="size-4 accent-[var(--blue)]" aria-label={`Select ${r.app}`} disabled={!on} checked={sel.has(r.fix_id)} onChange={() => toggle(r.fix_id)} /></td>
                  <td className="whitespace-nowrap text-xs text-ink-2">{r.stage === 1 ? <Tag tone="bad">High priority</Tag> : STAGE_NAME[r.stage] ?? stages[String(r.stage)] ?? r.stage}</td>
                  <td>
                    <div className="font-medium">{r.app}</div>
                    <div className="text-xs text-ink-3">{r.version}{r.note ? ` · ${r.note}` : ''}</div>
                    {Object.keys(r.found_by ?? {}).length > 0 && (
                      <div className="mt-0.5 text-[11px] text-ink-3">
                        from {(Object.entries(r.found_by ?? {}) as [FixSource, string | null][]).map(([s, at]) => `${UC_NAME[SOURCE_UC[s]]}${at ? ` · ${dateTime(fixTime(at))}` : ''}`).join(' and ')}
                      </div>
                    )}
                  </td>
                  <td className="whitespace-nowrap text-ink-2">{ACTION_LABEL[r.action]}</td>
                  <td className="tabular text-right">{num(r.findings)}</td>
                  <td><StatusPill r={r} />{r.approved_by && r.status === 'approved' && <div className="mt-0.5 text-[11px] text-ink-3">by {r.approved_by} · {r.method === 'liveresponse' ? 'Live Response' : 'Run Command'}</div>}</td>
                  <td className="max-w-[300px] text-xs text-ink-2 [overflow-wrap:anywhere]">{r.message ?? ''}</td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </Panel>
  )
}

export function ConfirmDialog({ open, onClose, title, body, confirmLabel, onConfirm }: {
  open: boolean; onClose: () => void; title: string; body: string; confirmLabel: string; onConfirm: () => void
}) {
  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="max-w-md border-hairline bg-panel">
        <DialogTitle className="flex items-center gap-2"><AlertTriangle className="size-5" style={{ color: statusColor.warning }} />{title}</DialogTitle>
        <DialogDescription className="text-sm leading-relaxed text-ink-2">{body}</DialogDescription>
        <div className="mt-2 flex justify-end gap-2">
          <button onClick={onClose} className="rounded-lg border border-hairline px-4 py-2 text-sm hover:bg-well">Cancel</button>
          <button onClick={onConfirm} className="rounded-lg btn-blue px-4 py-2 text-sm font-medium text-white">{confirmLabel}</button>
        </div>
      </DialogContent>
    </Dialog>
  )
}
