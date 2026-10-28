import { Link } from 'react-router-dom'
import { ArrowRight, Bookmark, CheckCircle2, ShieldAlert, ShieldCheck, Undo2, Wrench, Zap } from 'lucide-react'
import { StatusPill } from '@/components/FixLoop'
import { Panel } from '@/components/kit'
import { BasketBar } from '@/pages/uc3/FixCentre'
import { FixDown, canApprove, isSetting, settingChange, useFix, useFixAction, type FixRow } from '@/lib/fix'
import { num } from '@/lib/format'
import { UC_NAME, type RunFix, type UcKey } from '@/lib/runs'
import { GettingReady, useAutoStart } from '@/lib/services'
import { statusColor } from '@/lib/theme'
import { cn } from '@/lib/utils'

/** The fix engine's stages (UC1 fix plan): 1 urgent, 2 end of life, 3 other updates. Settings are stage 3. */
const STAGE = {
  1: { label: 'Urgent', color: statusColor.critical },
  2: { label: 'End of life', color: statusColor.warning },
  3: { label: 'Update', color: 'var(--sky)' },
} as const

const isResponse = (r: FixRow) => r.action === 'respond'
const stageOf = (r: FixRow) =>
  isResponse(r) ? { label: r.category || 'Detection', color: statusColor.critical }
    : isSetting(r) ? { label: 'Security setting', color: 'var(--violet)' } : STAGE[(r.stage as 1 | 2 | 3)] ?? STAGE[3]

function whatItDoes(r: FixRow) {
  if (r.action === 'respond') return 'Scans the computer with Defender and removes what it finds'
  if (r.action === 'setting') return settingChange(r)
  if (r.action === 'remove') return 'Removes this version from the computer'
  if (r.action === 'replace') return 'Replaces it with the current version'
  return 'Updates it to the latest version'
}

/**
 * The human-in-the-loop part of an agent's Fix stage: one card per fix this run proposed (for the Attack Detection
 * Agent: a Defender scan-and-clean per new sign of attack). The run's Fix stage ends when every card has a decision.
 * Fix puts it in the basket (nothing runs until Run fixes is pressed and confirmed); Save for later keeps it in
 * Fix without fixing it. Fixes come only from the fix catalogue, never from the AI.
 */
export function NewFixes({ fix, uc, since }: { fix: RunFix; uc: UcKey; since: string }) {
  const attack = uc === 'attack'
  const links = fixLinks(uc, fix.new > 0 ? since : null, fix)
  const view = useFix()
  const act = useFixAction()
  const down = view.error instanceof FixDown
  const auto = useAutoStart(down, 'fix')
  const v = view.data
  const byId = new Map((v?.rows ?? []).map((r) => [r.fix_id, r]))
  const rows = fix.new_ids.map((id) => byId.get(id)).filter((r): r is FixRow => !!r)
  const open = rows.filter((r) => canApprove(r) && r.status !== 'failed')
  const fresh = rows.filter((r) => r.status === 'proposed')
  const decided = rows.length - fresh.length
  const urgent = rows.filter((r) => r.stage === 1 && !isSetting(r) && !isResponse(r)).length
  const attacks = rows.filter(isResponse).length
  const settings = rows.filter(isSetting).length
  const busy = act.isPending || !v
  const approve = (ids: string[]) => v && ids.length && act.mutate({ action: 'approve', ids, method: v.default_method })
  const allDecided = !!v && rows.length > 0 && fresh.length === 0

  return (
    <>
    <Panel id="new-fixes" className="overflow-hidden animate-in fade-in slide-in-from-bottom-2 duration-500">
      <span className="block h-1 bg-signal" />
      <div className="p-6">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="flex min-w-0 items-start gap-3">
            <span className="grid size-10 shrink-0 place-items-center rounded-xl bg-signal/15">
              {allDecided ? <CheckCircle2 className="size-5" style={{ color: statusColor.good }} /> : attack ? <ShieldAlert className="size-5 text-signal" /> : <Wrench className="size-5 text-signal" />}
            </span>
            <div className="min-w-0">
              <h2 className="text-lg font-semibold tracking-tight">
                {allDecided ? `All ${rows.length} new remediation${rows.length === 1 ? '' : 's'} reviewed: the Remediation stage is complete`
                  : fix.new ? `${fix.new} new fix${fix.new === 1 ? '' : 'es'} proposed in this run${fresh.length < rows.length ? ` · ${fresh.length} left to decide` : ''}`
                  : 'No new remediations in this run'}
              </h2>
              <p className="mt-1 max-w-[70ch] text-sm text-ink-3">
                {attack && fix.new > 0 && <>For every new detection: a Defender update, quick scan and clean-up of the affected device. Device isolation is outside this agent's scope; perform it in Microsoft Defender. </>}
                {fix.new
                  ? <>Review each item. <b className="text-ink-2">Approve</b> adds it to the remediation queue; no device is changed until you select <b className="text-ink-2">Execute remediation</b> and confirm. <b className="text-ink-2">Defer</b> keeps it in Remediation for later.</>
                  : attack ? 'No new detections; no response required.' : 'Defender reported no new findings since the last run.'}
              </p>
            </div>
          </div>
          {open.length > 0 && (
            <div className="flex flex-wrap gap-2">
              {fresh.length > 0 && (
                <button
                  onClick={() => act.mutate({ action: 'save', ids: fresh.map((r) => r.fix_id) })}
                  disabled={busy}
                  className="inline-flex items-center gap-2 rounded-xl border border-hairline px-4 py-2.5 text-sm font-medium hover:bg-well disabled:opacity-50"
                >
                  <Bookmark className="size-4" /> Save all for later
                </button>
              )}
              <button
                onClick={() => approve(open.map((r) => r.fix_id))}
                disabled={busy}
                className="inline-flex items-center gap-2 rounded-xl btn-blue px-4 py-2.5 text-sm font-medium text-white disabled:opacity-50"
              >
                <Zap className="size-4" /> Fix all {open.length}
              </button>
            </div>
          )}
        </div>

        {fix.new > 0 && (
          <div className="mt-5 flex flex-wrap gap-2 text-xs">
            <Count n={fix.new} label="new this run" strong />
            {urgent > 0 && <Count n={urgent} label="urgent" color={statusColor.critical} />}
            {attacks > 0 && <Count n={attacks} label={`sign${attacks === 1 ? '' : 's'} of attack to respond to`} color={statusColor.critical} />}
            {settings > 0 && <Count n={settings} label={`security setting${settings === 1 ? '' : 's'}`} />}
            {decided > 0 && <Count n={decided} label="already decided" />}
          </div>
        )}

        <GettingReady what="The fix engine" starting={auto.starting} failed={auto.failed} retry={auto.retry} className="mt-5" />
        {view.error && !down && <p className="mt-5 text-sm" style={{ color: statusColor.critical }}>{(view.error as Error).message}</p>}
        {act.error && <p className="mt-3 text-sm" style={{ color: statusColor.critical }}>{(act.error as Error).message}</p>}

        {rows.length > 0 && (
          <ul className="mt-5 grid grid-cols-1 gap-3 md:grid-cols-2 2xl:grid-cols-3">
            {rows.map((r) => <FixCardSmall key={r.fix_id} r={r} busy={busy} onFix={() => approve([r.fix_id])}
              onSave={() => act.mutate({ action: 'save', ids: [r.fix_id] })}
              onUndo={(action) => act.mutate({ action, ids: [r.fix_id] })} />)}
          </ul>
        )}
        {v && rows.length < fix.new_ids.length && (
          <p className="mt-3 text-xs text-ink-3">
            {fix.new_ids.length - rows.length} of this run's fixes are no longer in the fix plan (Defender stopped listing them, or a newer run replaced the plan).
          </p>
        )}

        <div className="mt-5 flex flex-wrap items-center justify-between gap-3 border-t border-hairline pt-4 text-sm">
          <span className="text-ink-3">
            {fix.waiting > 0 ? <><b className="tabular text-ink-2">{num(fix.waiting)}</b> older fix{fix.waiting === 1 ? ' is' : 'es are'} still waiting from earlier runs</> : 'No earlier remediations pending'}
            {fix.saved > 0 && <> · <b className="tabular text-ink-2">{num(fix.saved)}</b> saved for later</>}
          </span>
          <span className="flex flex-wrap gap-x-4 gap-y-1">
            {links.map(([to, label]) => (
              <Link key={to} to={to} className="inline-flex items-center gap-1.5 font-medium hover:underline">
                {label} <ArrowRight className="size-4" />
              </Link>
            ))}
          </span>
        </div>
      </div>
    </Panel>
    {/* outside the panel so it stays pinned to the bottom of the screen while scrolling */}
    {v && <BasketBar v={v} />}
    </>
  )
}

/**
 * Where this run's fixes live in Fix: attack responses have their own tab; app updates and security
 * settings are filtered to the agent and, with fixes new in this run, to this run (since = when the run started).
 */
function fixLinks(uc: UcKey, since: string | null, fix: RunFix): [string, string][] {
  const q = (tab: string, agent?: string) => {
    const p = new URLSearchParams({ ...(agent ? { agent } : {}), ...(since ? { since } : {}) }).toString()
    return `/fixes${tab}${p ? `?${p}` : ''}`
  }
  if (uc === 'attack') return [[q('/attacks'), since ? "This run's responses in Remediation" : 'All attack responses in Remediation']]
  if (uc === 'uc1') return [[q('', 'uc1'), since ? "This run's remediations in Remediation" : `All ${UC_NAME.uc1} remediations in Remediation`]]
  // the Vulnerability Agent proposes app updates and security settings: one link per tab that has some
  const label = since ? 'in Remediation' : `from the ${UC_NAME.uc3}`
  const apps = (fix.new_apps ?? 1) > 0 || !since, settings = (fix.new_settings ?? 1) > 0 || !since
  return [
    ...(apps ? [[q('', 'uc3'), `${since ? "This run's app updates" : 'App updates'} ${label}`] as [string, string]] : []),
    ...(settings ? [[q('/settings', 'uc3'), `${since ? "This run's security settings" : 'Security settings'} ${label}`] as [string, string]] : []),
  ]
}

function Count({ n, label, color, strong }: { n: number; label: string; color?: string; strong?: boolean }) {
  return (
    <span className={cn('inline-flex items-center gap-1.5 rounded-full border border-hairline px-3 py-1', strong && 'bg-well')}>
      <b className="tabular text-sm" style={{ color }}>{num(n)}</b> <span className="text-ink-3">{label}</span>
    </span>
  )
}

export function FixCardSmall({ r, busy, onFix, onSave, onUndo }: {
  r: FixRow; busy: boolean; onFix: () => void; onSave: () => void; onUndo: (action: 'unapprove' | 'unsave') => void
}) {
  const stage = stageOf(r)
  return (
    <li className={cn('flex flex-col overflow-hidden rounded-xl border border-hairline bg-panel transition-opacity', r.status === 'saved' && 'opacity-70')}>
      <span className="h-1" style={{ background: stage.color }} />
      <div className="flex flex-1 flex-col gap-2 p-4">
        <div className="flex items-center justify-between gap-2 text-[11px] font-medium">
          <span style={{ color: stage.color }}>{stage.label}</span>
          <span className="truncate rounded-md bg-well px-1.5 py-0.5 text-ink-2">{r.device_name}</span>
        </div>
        <div className="text-sm font-semibold leading-snug">
          {r.app} {r.version && <span className="font-normal text-ink-3">{r.version}</span>}
        </div>
        <div className="text-xs text-ink-2">{whatItDoes(r)}</div>
        {isResponse(r) && r.note && <div className="line-clamp-2 break-all rounded-md bg-well px-2 py-1 font-mono text-[11px] text-ink-3" title={r.note}>{r.note}</div>}
        {!isSetting(r) && r.findings > 0 && (
          <div className="text-xs text-ink-3">
            {num(r.findings)} vulnerabilit{r.findings === 1 ? 'y' : 'ies'}
          </div>
        )}
        <div className="mt-auto flex flex-wrap items-center justify-between gap-2 pt-2">
          {r.status === 'proposed' ? (
            <>
              <button onClick={onSave} disabled={busy} className="inline-flex items-center gap-1.5 rounded-lg border border-hairline px-3 py-1.5 text-xs font-medium hover:bg-well disabled:opacity-50">
                <Bookmark className="size-3.5" /> Defer
              </button>
              <button onClick={onFix} disabled={busy} className="btn-blue inline-flex items-center gap-1.5 rounded-lg px-3.5 py-1.5 text-xs font-semibold disabled:opacity-50">
                <Zap className="size-3.5" /> Approve
              </button>
            </>
          ) : (
            <>
              <StatusPill r={r} />
              {r.status === 'saved' ? (
                <span className="flex gap-1.5">
                  <button onClick={() => onUndo('unsave')} disabled={busy} className="inline-flex items-center gap-1 rounded-lg px-2 py-1 text-xs font-medium text-ink-2 hover:bg-well disabled:opacity-50"><Undo2 className="size-3.5" /> Undo</button>
                  <button onClick={onFix} disabled={busy} className="btn-blue inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-semibold disabled:opacity-50"><Zap className="size-3.5" /> Approve</button>
                </span>
              ) : r.status === 'approved' ? (
                <button onClick={() => onUndo('unapprove')} disabled={busy} className="inline-flex items-center gap-1 rounded-lg px-2 py-1 text-xs font-medium text-ink-2 hover:bg-well disabled:opacity-50"><Undo2 className="size-3.5" /> Remove</button>
              ) : r.status === 'failed' ? (
                <button onClick={onFix} disabled={busy} className="btn-blue inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-semibold disabled:opacity-50"><Zap className="size-3.5" /> Try again</button>
              ) : r.status === 'verified' ? (
                <ShieldCheck className="size-4" style={{ color: statusColor.good }} />
              ) : null}
            </>
          )}
        </div>
      </div>
    </li>
  )
}
