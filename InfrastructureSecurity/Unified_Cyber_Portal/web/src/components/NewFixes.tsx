import { useMemo, useState, type ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { AlertTriangle, ArrowRight, Bookmark, Bot, CheckCircle2, ChevronDown, ListChecks, Newspaper, ShieldAlert, ShieldCheck, Sparkles, Undo2, Wrench, Zap } from 'lucide-react'
import { StatusPill } from '@/components/FixLoop'
import { Panel, SevTag } from '@/components/kit'
import { VulnList } from '@/components/VulnList'
import { BasketBar } from '@/pages/uc3/FixCentre'
import { FixDown, autoFix, canApprove, isSetting, settingChange, useFix, useFixAction, type FixRow } from '@/lib/fix'
import { num, shortDate } from '@/lib/format'
import { UC_NAME, type RunFix, type UcKey } from '@/lib/runs'
import { GettingReady, useAutoStart } from '@/lib/services'
import { statusColor } from '@/lib/theme'
import { PRIORITY, daysBetween, fixKind, useUc3Data, vmDetails, vmKey, type FixKind, type Uc3Data, type Uc3FixApp, type Uc3FixSetting, type VmCve } from '@/lib/uc3'
import { cn } from '@/lib/utils'

/** The fix engine's stages (UC1 fix plan): 1 urgent, 2 end of life, 3 other updates. Settings are stage 3. */
const STAGE = {
  1: { label: 'High priority', color: statusColor.critical },
  2: { label: 'End of support', color: statusColor.warning },
  3: { label: 'Routine update', color: 'var(--sky)' },
} as const

const KIND_LABEL: Record<FixKind, string> = {
  update: 'Software update', os: 'OS security update', upgrade: 'Software upgrade', none: 'Attention required: no security update available',
}

const isResponse = (r: FixRow) => r.action === 'respond'
const stageOf = (r: FixRow) =>
  isResponse(r) ? { label: r.category || 'Detection', color: statusColor.critical }
    : isSetting(r) ? { label: 'Misconfiguration', color: 'var(--violet)' } : STAGE[(r.stage as 1 | 2 | 3)] ?? STAGE[3]

function whatItDoes(r: FixRow) {
  if (r.action === 'respond') return 'Scans the device with Defender and removes what it finds'
  if (r.action === 'setting') return settingChange(r)
  if (r.action === 'remove') return 'Removes this version from the device'
  if (r.action === 'replace') return 'Replaces it with the current version'
  return 'Updates it to the latest version'
}

/** One vulnerability on the card's computer and app version (Defender's list, as on the Vulnerabilities page) */
/**
 * What a run card shows beyond the fix engine's row: the Remediation card's advice and the vulnerabilities behind it.
 * firstSeen / due are this card's own (this computer and version), not the app-wide ones on the Remediation card:
 * due = the earliest first seen by Defender + the SLA days for that severity; today = the data's snapshot day.
 */
export interface CardDetail {
  software: string; app?: Uc3FixApp; setting?: Uc3FixSetting; cves: VmCve[]
  firstSeen: string | null; due: string | null; today: string
}


/** Per fix id: its Remediation advice and its vulnerabilities, worst first (from the Vulnerability Agent's data). */
function cardDetails(data: Uc3Data | undefined, rows: FixRow[]): Map<string, CardDetail> {
  const out = new Map<string, CardDetail>()
  if (!data) return out
  const apps = new Map((data.fixes?.apps ?? []).map((a) => [a.key.split(':').pop() ?? '', a]))
  const settings = new Map((data.fixes?.settings ?? []).map((s) => [s.config_id, s]))
  const vms = vmDetails(data)
  const today = String(data.meta.snapshot).slice(0, 10)
  for (const r of rows) {
    const vm = vms.get(vmKey(r.device_name, r.software_name, r.version))
    out.set(r.fix_id, {
      software: r.software_name, cves: vm?.cves ?? [], firstSeen: vm?.firstSeen ?? null, due: vm?.due ?? null, today,
      app: isSetting(r) || isResponse(r) ? undefined : apps.get(r.software_name),
      setting: r.config_id ? settings.get(r.config_id) : undefined,
    })
  }
  return out
}

/**
 * The human-in-the-loop part of an agent's Fix stage: one card per fix this run proposed (for the Attack Detection
 * Agent: a Defender scan-and-clean per new sign of attack). The run's Fix stage ends when every card has a decision.
 * Fix puts it in the basket (nothing runs until Run fixes is pressed and confirmed); Save for later keeps it in
 * Fix without fixing it. Fixes come only from the fix catalogue, never from the AI.
 *
 * Everything here acts on this run's fixes only: Approve all approves the new ones, and Execute remediation runs only
 * what this run approved. Fixes from earlier runs stay as they are; the ones that gained vulnerabilities in this run
 * are listed apart, since updating the app clears the earlier and the new vulnerabilities together.
 */
export function NewFixes({ fix, uc, since }: { fix: RunFix; uc: UcKey; since: string }) {
  const attack = uc === 'attack'
  const links = fixLinks(uc, fix.new > 0 ? since : null, fix)
  const view = useFix()
  const act = useFixAction()
  const uc3 = useUc3Data()
  const down = view.error instanceof FixDown
  const auto = useAutoStart(down, 'fix')
  const v = view.data
  const byId = new Map((v?.rows ?? []).map((r) => [r.fix_id, r]))
  const rows = fix.new_ids.map((id) => byId.get(id)).filter((r): r is FixRow => !!r)
  const grew = fix.grew ?? {}
  const grewRows = Object.keys(grew).map((id) => byId.get(id)).filter((r): r is FixRow => !!r && !fix.new_ids.includes(r.fix_id))
  const scope = useMemo(() => [...fix.new_ids, ...Object.keys(grew)], [fix.new_ids, grew])
  const detail = useMemo(() => (attack ? new Map<string, CardDetail>() : cardDetails(uc3.data, [...rows, ...grewRows])),
    [attack, uc3.data, v]) // eslint-disable-line react-hooks/exhaustive-deps
  const [list, setList] = useState<{ app: Uc3FixApp; software: string; device: string } | null>(null)
  const open = rows.filter((r) => canApprove(r) && r.status !== 'failed')
  const grewOpen = grewRows.filter((r) => canApprove(r) && r.status !== 'failed')
  const fresh = rows.filter((r) => r.status === 'proposed')
  const decided = rows.length - fresh.length
  const urgent = rows.filter((r) => r.stage === 1 && !isSetting(r) && !isResponse(r)).length
  const attacks = rows.filter(isResponse).length
  const settings = rows.filter(isSetting).length
  const busy = act.isPending || !v
  const approve = (ids: string[]) => v && ids.length && act.mutate({ action: 'approve', ids, method: v.default_method })
  const allDecided = !!v && rows.length > 0 && fresh.length === 0
  const card = (r: FixRow) => {
    const d = detail.get(r.fix_id)
    return (
      <FixCardSmall key={r.fix_id} r={r} busy={busy} detail={d} added={grew[r.fix_id]} onFix={() => approve([r.fix_id])}
        onAutoFix={v ? () => autoFix(act, [r.fix_id], v.default_method) : undefined}
        onSave={() => act.mutate({ action: 'save', ids: [r.fix_id] })}
        onUndo={(action) => act.mutate({ action, ids: [r.fix_id] })}
        onList={d?.app ? () => setList({ app: d.app!, software: d.software, device: r.device_name }) : undefined} />
    )
  }

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
                  : fix.new ? `${fix.new} new remediation${fix.new === 1 ? '' : 's'} proposed in this run${fresh.length < rows.length ? ` · ${fresh.length} left to decide` : ''}`
                  : 'No new remediations in this run'}
              </h2>
              <p className="mt-1 max-w-[70ch] text-sm text-ink-3">
                {attack && fix.new > 0 && <>For every new detection: a Defender update, quick scan and clean-up of the affected device. Device isolation is outside this agent's scope; perform it in Microsoft Defender. </>}
                {attack && fix.new > 0 && v?.attack_auto_fix
                  ? <>Auto-fix is on: the agent approved and ran these itself. Check each result below; <b className="text-ink-2">Approve</b> again retries one that failed.</>
                  : fix.new
                  ? <>Review each item. <b className="text-ink-2">Approve</b> adds it to the remediation queue; no device is changed until you select <b className="text-ink-2">Execute remediation</b> and confirm. <b className="text-ink-2">Defer</b> keeps it in Remediation for later.</>
                  : attack ? 'No new detections; no response required.' : 'Defender reported no new findings since the last run.'}
              </p>
              {fix.new > 0 && fix.waiting > 0 && (
                <p className="mt-1.5 max-w-[70ch] text-sm text-ink-3">
                  These buttons act on <b className="text-ink-2">this run's {num(fix.new)} only</b>. The {num(fix.waiting)} remediations from earlier runs are not approved or executed from here.
                  {grewRows.length > 0 && <> {grewRows.length} of them gained new vulnerabilities in this run, so they are listed below with their full count.</>}
                </p>
              )}
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
                  <Bookmark className="size-4" /> Defer all {fresh.length}
                </button>
              )}
              <button
                onClick={() => approve(open.map((r) => r.fix_id))}
                disabled={busy}
                title={`Adds this run's ${open.length} to the remediation queue. Nothing from earlier runs is added.`}
                className="inline-flex items-center gap-2 rounded-xl btn-blue px-4 py-2.5 text-sm font-medium text-white disabled:opacity-50"
              >
                <Zap className="size-4" /> Approve all {open.length} from this run
              </button>
            </div>
          )}
        </div>

        {(fix.new > 0 || grewRows.length > 0) && (
          <div className="mt-5 flex flex-wrap gap-2 text-xs">
            {fix.new > 0 && <Count n={fix.new} label="new this run" strong />}
            {urgent > 0 && <Count n={urgent} label="high priority" color={statusColor.critical} />}
            {attacks > 0 && <Count n={attacks} label={`sign${attacks === 1 ? '' : 's'} of attack to respond to`} color={statusColor.critical} />}
            {settings > 0 && <Count n={settings} label={`security setting${settings === 1 ? '' : 's'}`} />}
            {decided > 0 && <Count n={decided} label="already decided" />}
            {grewRows.length > 0 && <Count n={fix.grew_vulns ?? 0} label={`new vulnerabilities on ${grewRows.length} earlier remediation${grewRows.length === 1 ? '' : 's'}`} color={statusColor.warning} />}
          </div>
        )}

        <GettingReady what="The remediation engine" starting={auto.starting} failed={auto.failed} retry={auto.retry} className="mt-5" />
        {view.error && !down && <p className="mt-5 text-sm" style={{ color: statusColor.critical }}>{(view.error as Error).message}</p>}
        {act.error && <p className="mt-3 text-sm" style={{ color: statusColor.critical }}>{(act.error as Error).message}</p>}

        {rows.length > 0 && (
          <ul className="mt-5 grid grid-cols-1 gap-3 md:grid-cols-2 2xl:grid-cols-3">
            {rows.map(card)}
          </ul>
        )}
        {v && rows.length < fix.new_ids.length && (
          <p className="mt-3 text-xs text-ink-3">
            {fix.new_ids.length - rows.length} of this run's remediations are no longer in the remediation plan (Defender stopped listing them, or a newer run replaced the plan).
          </p>
        )}

        {grewRows.length > 0 && (
          <div className="mt-6 border-t border-hairline pt-5">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div className="min-w-0">
                <h3 className="font-semibold tracking-tight">Earlier remediations with new vulnerabilities from this run</h3>
                <p className="mt-1 max-w-[75ch] text-sm text-ink-3">
                  This run found {num(fix.grew_vulns ?? 0)} new vulnerabilit{fix.grew_vulns === 1 ? 'y' : 'ies'} in app versions that already had a remediation.
                  A remediation updates the whole app on that device, so it cannot clear only the new ones: approving one of these clears every
                  vulnerability on it, from earlier runs too. That is why they join the existing remediation instead of making a new one. They do not hold up this run.
                </p>
              </div>
              {grewOpen.length > 0 && (
                <button onClick={() => approve(grewOpen.map((r) => r.fix_id))} disabled={busy}
                  className="inline-flex items-center gap-2 rounded-xl border border-hairline px-4 py-2.5 text-sm font-medium hover:bg-well disabled:opacity-50">
                  <Zap className="size-4" /> Approve these {grewOpen.length}
                </button>
              )}
            </div>
            <ul className="mt-4 grid grid-cols-1 gap-3 md:grid-cols-2 2xl:grid-cols-3">
              {grewRows.map(card)}
            </ul>
          </div>
        )}

        <div className="mt-5 flex flex-wrap items-center justify-between gap-3 border-t border-hairline pt-4 text-sm">
          <span className="text-ink-3">
            {fix.waiting > 0 ? <><b className="tabular text-ink-2">{num(fix.waiting)}</b> older remediation{fix.waiting === 1 ? ' is' : 's are'} still waiting from earlier runs (review them in Remediation)</> : 'No earlier remediations pending'}
            {fix.saved > 0 && <> · <b className="tabular text-ink-2">{num(fix.saved)}</b> deferred</>}
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
    {list && uc3.data && (
      <VulnList app={list.app} software={list.software} data={uc3.data} fixRows={v?.rows ?? []} engine={!!v}
        startDevice={list.device} onClose={() => setList(null)} />
    )}
    {/* outside the panel so it stays pinned to the bottom of the screen while scrolling; runs only this run's fixes */}
    {v && <BasketBar v={v} scope={scope} />}
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
    ...(settings ? [[q('/settings', 'uc3'), `${since ? "This run's security settings" : 'Security configuration'} ${label}`] as [string, string]] : []),
  ]
}

function Count({ n, label, color, strong }: { n: number; label: string; color?: string; strong?: boolean }) {
  return (
    <span className={cn('inline-flex items-center gap-1.5 rounded-full border border-hairline px-3 py-1', strong && 'bg-well')}>
      <b className="tabular text-sm" style={{ color }}>{num(n)}</b> <span className="text-ink-3">{label}</span>
    </span>
  )
}

function Stat({ n, label, color }: { n: number; label: string; color?: string }) {
  return (
    <div className="rounded-lg bg-well px-2.5 py-1.5">
      <div className="tabular text-base font-semibold leading-tight" style={{ color }}>{num(n)}</div>
      <div className="text-[11px] text-ink-3">{label}</div>
    </div>
  )
}

function More({ title, children }: { title: ReactNode; children: ReactNode }) {
  const [open, setOpen] = useState(false)
  return (
    <div className="rounded-lg border border-hairline">
      <button onClick={() => setOpen(!open)} aria-expanded={open} className="flex w-full items-center justify-between gap-2 px-3 py-2 text-left text-xs font-medium text-ink-2 hover:bg-well">
        {title} <ChevronDown className={cn('size-3.5 transition-transform', open && 'rotate-180')} />
      </button>
      {open && <div className="border-t border-hairline px-3 py-2.5 animate-in fade-in duration-200">{children}</div>}
    </div>
  )
}

const MOVE_LABEL = { quick_scan: 'Quick scan', full_scan: 'Full scan', stop: 'Finished' } as const

/** What the Remediation Agent did on this device, move by move, while it runs and after. */
function AgentMoves({ r }: { r: FixRow }) {
  const moves = r.agent ?? []
  const running = r.status === 'running' || r.status === 'queued'
  if (!moves.length && !running && !(r.message && r.status !== 'proposed' && r.status !== 'saved')) return null
  return (
    <div className="rounded-lg border border-violet/30 bg-violet/5 px-2.5 py-2 text-[11px]">
      <div className="mb-1 flex items-center gap-1.5 font-semibold text-violet">
        <Bot className="size-3.5" /> Remediation Agent
        {running && <span className="font-normal text-ink-3">· working on the device…</span>}
      </div>
      {moves.length > 0 ? (
        <ol className="flex flex-col gap-1">
          {moves.map((m, i) => (
            <li key={i} className="text-ink-2">
              <b className="text-ink">{i + 1}. {MOVE_LABEL[m.action] ?? m.action}</b>
              {m.reason && <span className="text-ink-3"> · {m.reason}</span>}
              {m.result && <div className="mt-0.5" style={m.status ? { color: m.status === 'done' ? statusColor.good : statusColor.critical } : undefined}>{m.result}</div>}
            </li>
          ))}
        </ol>
      ) : r.message && !running ? <p className="text-ink-2">{r.message}</p> : null}
    </div>
  )
}

/**
 * One fix as a card. With `detail` (a run page) it carries what the Remediation card says: urgency and deadline,
 * the vulnerabilities behind it (worst first, all of them one click away), threats in the news, and the advice.
 * `added`: vulnerabilities this run added to an earlier fix.
 */
export function FixCardSmall({ r, busy, onFix, onAutoFix, onSave, onUndo, detail, added, onList }: {
  r: FixRow; busy: boolean; onFix: () => void; onSave: () => void; onUndo: (action: 'unapprove' | 'unsave') => void
  /** approve and run this one now */
  onAutoFix?: () => void
  detail?: CardDetail; added?: number; onList?: () => void
}) {
  const auto = onAutoFix && (
    <button onClick={onAutoFix} disabled={busy} title="Approve and run this remediation now"
      className="btn-blue inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-semibold disabled:opacity-50">
      <Sparkles className="size-3.5" /> Auto-fix
    </button>
  )
  const stage = stageOf(r)
  const app = detail?.app
  const setting = detail?.setting
  const cves = detail?.cves ?? []
  const severe = cves.filter((c) => c.sev === 'Critical' || c.sev === 'High').length
  // this card's own deadline (falls back to the app-wide one before the Vulnerability Agent's data has loaded)
  const due = detail?.due ?? app?.fix_by ?? null
  const left = due && detail ? daysBetween(detail.today, due) : null
  const late = left != null && left < 0
  const noFix = cves.filter((c) => c.nofix).length
  const total = cves.length || r.findings
  const advice = app?.ai ?? setting?.ai ?? null
  const remediationLink = setting ? '/fixes/settings' : isResponse(r) ? '/fixes/attacks' : `/fixes?sw=${encodeURIComponent(r.software_name)}`
  return (
    <li className={cn('flex flex-col overflow-hidden rounded-xl border border-hairline bg-panel transition-opacity', r.status === 'saved' && 'opacity-70')}>
      <span className="h-1" style={{ background: stage.color }} />
      <div className="flex flex-1 flex-col gap-2 p-4">
        <div className="flex items-center justify-between gap-2 text-[11px] font-medium">
          <span className="flex items-center gap-1.5" style={{ color: stage.color }}>
            {r.stage === 1 && !isSetting(r) && !isResponse(r) && <AlertTriangle className="size-3.5" />}{stage.label}
            {app && <span className="font-normal text-ink-3">· {PRIORITY[app.urgency.level]} priority</span>}
          </span>
          <span className="truncate rounded-md bg-well px-1.5 py-0.5 text-ink-2">{r.device_name}</span>
        </div>
        <div className="text-sm font-semibold leading-snug">
          {r.app} {r.version && <span className="font-normal text-ink-3">{r.version}</span>}
        </div>
        {app && (
          <div className="text-[11px] text-ink-3">
            {KIND_LABEL[fixKind(app)]}
            {due && (late
              ? <> · <b className="font-medium" style={{ color: statusColor.critical }}>overdue since {shortDate(due)}</b></>
              : <> · due <b className="font-medium text-ink-2">{shortDate(due)}</b></>)}
          </div>
        )}
        {detail?.firstSeen && !isSetting(r) && !isResponse(r) && (
          <div className="text-[11px] text-ink-3" title="The deadline counts from the day Defender first found the vulnerability on this device, plus the patching rule's days for its severity. The agent proposing it in this run does not restart that clock.">
            Defender first found these on this device on <b className="font-medium text-ink-2">{shortDate(detail.firstSeen)}</b>
          </div>
        )}
        <div className="text-xs text-ink-2">{whatItDoes(r)}</div>
        {isResponse(r) && r.note && <div className="line-clamp-2 break-all rounded-md bg-well px-2 py-1 font-mono text-[11px] text-ink-3" title={r.note}>{r.note}</div>}
        {isResponse(r) && <AgentMoves r={r} />}

        {added ? (
          <div className="rounded-md px-2 py-1 text-[11px] font-medium" style={{ color: statusColor.warning, background: `color-mix(in oklab, ${statusColor.warning} 12%, transparent)` }}>
            +{num(added)} new vulnerabilit{added === 1 ? 'y' : 'ies'} found in this run
            {total > added && (
              <div className="mt-0.5 font-normal text-ink-2">
                Same update for all of them: approving clears all <b>{num(total)}</b> ({num(total - added)} from earlier runs + {num(added)} new).
              </div>
            )}
          </div>
        ) : null}

        {detail && !isSetting(r) && !isResponse(r) && total > 0 ? (
          <>
            <div className="grid grid-cols-3 gap-1.5">
              <Stat n={total} label="Vulnerabilities" />
              <Stat n={severe} label="Critical / high" color={severe ? statusColor.critical : undefined} />
              {left != null ? (
                <div className="rounded-lg bg-well px-2.5 py-1.5">
                  <div className="tabular text-base font-semibold leading-tight" style={{ color: late ? statusColor.critical : undefined }}>{num(Math.abs(left))}</div>
                  <div className="text-[11px] text-ink-3">{late ? `day${left === -1 ? '' : 's'} overdue` : `day${left === 1 ? '' : 's'} left`}</div>
                </div>
              ) : <Stat n={cves.filter((c) => c.nofix).length} label="No update yet" />}
            </div>
            {cves.length > 0 && (
              <ul className="divide-y divide-hairline rounded-lg border border-hairline text-[11px]">
                {cves.slice(0, 3).map((c) => (
                  <li key={c.cve} className="flex items-center gap-2 px-2.5 py-1.5">
                    <span className="font-mono text-ink">{c.cve}</span>
                    <span className="ml-auto flex items-center gap-1.5 text-ink-2">
                      <SevTag sev={c.sev} />{c.cvss != null && <span className="tabular text-ink-3">{c.cvss}</span>}
                    </span>
                  </li>
                ))}
              </ul>
            )}
            {noFix > 0 && (
              <div className="text-[11px]" style={{ color: statusColor.warning }}>
                {noFix >= cves.length ? 'No security update available for any of these' : `No security update available for ${num(noFix)} of them (the update remediates the rest)`}
              </div>
            )}
            {/* one update or removal clears the whole version, whichever agent reported each vulnerability */}
            {r.threats?.length && !added ? (
              <div className="rounded-md bg-well px-2 py-1 text-[11px] text-ink-2">
                Approving clears <b>all {num(total)}</b> vulnerabilities on {r.app} {r.version} on {r.device_name}, not only the ones in threat intelligence.
              </div>
            ) : null}
          </>
        ) : !isSetting(r) && r.findings > 0 ? (
          <div className="text-xs text-ink-3">{num(r.findings)} vulnerabilit{r.findings === 1 ? 'y' : 'ies'}</div>
        ) : null}

        {setting && (
          <div className="text-[11px] text-ink-3">
            {setting.category}{setting.subcategory && ` · ${setting.subcategory}`}{setting.impact ? ` · impact ${setting.impact}` : ''}
            {setting.user_impact && <span style={{ color: statusColor.warning }}> · users may notice the change</span>}
          </div>
        )}

        {r.threats && r.threats.length > 0 && (
          <div className="flex items-start gap-1.5 text-[11px] text-violet" title={r.threats.map((t) => t.title).join('\n')}>
            <Newspaper className="mt-0.5 size-3.5 shrink-0" />
            <span className="line-clamp-2">In the news: {r.threats[0].title}{r.threats.length > 1 && ` +${r.threats.length - 1} more`}</span>
          </div>
        )}

        {(advice?.what_is_wrong || setting?.microsoft.risk) && (
          <p className="line-clamp-3 text-xs leading-relaxed text-ink-2">{advice?.what_is_wrong || setting?.microsoft.risk}</p>
        )}
        {advice && (advice.why_now || advice.side_effects) && (
          <More title="Why now and user impact">
            {advice.why_now && <p className="text-xs leading-relaxed text-ink-2">{advice.why_now}</p>}
            {advice.worst_case && <p className="mt-1.5 text-xs text-ink-2"><b className="text-ink">Potential impact: </b>{advice.worst_case}</p>}
            {advice.side_effects && <p className="mt-1.5 text-xs text-ink-2"><b className="text-ink">User impact: </b>{advice.side_effects}</p>}
          </More>
        )}

        {detail && (
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs">
            {onList && (
              <button onClick={onList} className="inline-flex items-center gap-1.5 font-semibold text-sky hover:underline">
                <ListChecks className="size-3.5" /> {total === 1 ? 'View the vulnerability' : `View all ${num(total)} vulnerabilities`}
              </button>
            )}
            <Link to={remediationLink} className="ml-auto inline-flex items-center gap-1 font-medium text-ink-2 hover:text-ink hover:underline">
              Full card in Remediation <ArrowRight className="size-3.5" />
            </Link>
          </div>
        )}

        <div className="mt-auto flex flex-wrap items-center justify-between gap-2 pt-2">
          {r.status === 'proposed' ? (
            <>
              <button onClick={onSave} disabled={busy} className="inline-flex items-center gap-1.5 rounded-lg border border-hairline px-3 py-1.5 text-xs font-medium hover:bg-well disabled:opacity-50">
                <Bookmark className="size-3.5" /> Defer
              </button>
              <span className="flex gap-1.5">
                <button onClick={onFix} disabled={busy} className={cn('inline-flex items-center gap-1.5 rounded-lg px-3.5 py-1.5 text-xs font-semibold disabled:opacity-50', auto ? 'border border-hairline hover:bg-well' : 'btn-blue')}>
                  <Zap className="size-3.5" /> Approve
                </button>
                {auto}
              </span>
            </>
          ) : (
            <>
              <StatusPill r={r} />
              {r.status === 'saved' ? (
                <span className="flex gap-1.5">
                  <button onClick={() => onUndo('unsave')} disabled={busy} className="inline-flex items-center gap-1 rounded-lg px-2 py-1 text-xs font-medium text-ink-2 hover:bg-well disabled:opacity-50"><Undo2 className="size-3.5" /> Undo</button>
                  {auto || <button onClick={onFix} disabled={busy} className="btn-blue inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-semibold disabled:opacity-50"><Zap className="size-3.5" /> Approve</button>}
                </span>
              ) : r.status === 'approved' ? (
                <button onClick={() => onUndo('unapprove')} disabled={busy} className="inline-flex items-center gap-1 rounded-lg px-2 py-1 text-xs font-medium text-ink-2 hover:bg-well disabled:opacity-50"><Undo2 className="size-3.5" /> Remove</button>
              ) : r.status === 'failed' ? (
                onAutoFix
                  ? <button onClick={onAutoFix} disabled={busy} className="btn-blue inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-semibold disabled:opacity-50"><Sparkles className="size-3.5" /> Auto-fix again</button>
                  : <button onClick={onFix} disabled={busy} className="btn-blue inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-semibold disabled:opacity-50"><Zap className="size-3.5" /> Try again</button>
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
