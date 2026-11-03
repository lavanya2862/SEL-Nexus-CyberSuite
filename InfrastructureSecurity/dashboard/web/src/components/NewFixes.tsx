import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { AlertTriangle, ArrowRight, Bot, CheckCircle2, ListChecks, Newspaper, ShieldAlert, ShieldCheck, Sparkles, Undo2, Wrench, Zap } from 'lucide-react'
import { StatusPill } from '@/components/FixLoop'
import { Panel, SevTag } from '@/components/kit'
import { VulnList } from '@/components/VulnList'
import { BasketBar } from '@/agents/fixes/FixCentre'
import { FixDown, autoFix, isIndicatorResponse, isSetting, settingChange, useFix, useFixAction, type FixRow } from '@/agents/fixes/data'
import { ManualAction } from '@/components/ManualAction'
import { RecordLink } from '@/components/FixRecord'
import { num, shortDate } from '@/lib/format'
import { type RunFix, type AgentKey } from '@/lib/runs'
import { GettingReady, useAutoStart } from '@/lib/services'
import { chartTokens, statusColor, useTheme } from '@/lib/theme'
import { PRIORITY, daysBetween, useVulnData, vmDetails, vmKey, type VulnData, type VulnFixApp, type VulnFixSetting, type VmCve } from '@/agents/vulnerability/data'
import { cn } from '@/lib/utils'
import { useAttackDetectionData } from '@/agents/attack-detection/data'

/** The fix engine's stages (Threat Intel fix plan): 1 urgent, 2 end of life, 3 other updates. Settings are stage 3. */
const STAGE = {
  1: { label: 'High priority', color: statusColor.critical },
  2: { label: 'End of support', color: statusColor.warning },
  3: { label: 'Routine update', color: 'var(--sky)' },
} as const


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
  software: string; app?: VulnFixApp; setting?: VulnFixSetting; cves: VmCve[]
  firstSeen: string | null; due: string | null; today: string
}


/** Per fix id: its Remediation advice and its vulnerabilities, worst first (from the Vulnerability Agent's data). */
function cardDetails(data: VulnData | undefined, rows: FixRow[]): Map<string, CardDetail> {
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
export function NewFixes({ fix, uc, since }: { fix: RunFix; uc: AgentKey; since: string }) {
  const attack = uc === 'attack_detection'
  const links = fixLinks(uc, fix.new > 0 ? since : null, fix)
  const view = useFix()
  const act = useFixAction()
  const vulnerability = useVulnData()
  const down = view.error instanceof FixDown
  const auto = useAutoStart(down, 'fix')
  const v = view.data
  const byId = new Map((v?.rows ?? []).map((r) => [r.fix_id, r]))
  const rows = fix.new_ids.map((id) => byId.get(id)).filter((r): r is FixRow => !!r)
  const grew = fix.grew ?? {}
  const grewRows = Object.keys(grew).map((id) => byId.get(id)).filter((r): r is FixRow => !!r && !fix.new_ids.includes(r.fix_id))
  const scope = useMemo(() => [...fix.new_ids, ...Object.keys(grew)], [fix.new_ids, grew])
  const detail = useMemo(() => (attack ? new Map<string, CardDetail>() : cardDetails(vulnerability.data, [...rows, ...grewRows])),
    [attack, vulnerability.data, v]) // eslint-disable-line react-hooks/exhaustive-deps
  const [list, setList] = useState<{ app: VulnFixApp; software: string; device: string } | null>(null)
  // a run page only asks about what is still undecided: approved, deferred or resolved ones live in Remediation
  const open = rows.filter((r) => r.status === 'proposed')
  const grewOpen = grewRows.filter((r) => r.status === 'proposed')
  const decided = rows.length - open.length
  const fresh = rows.filter((r) => r.status === 'proposed')
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
              {fix.new > 0 && (
                <p className="mt-1 max-w-[70ch] text-sm text-ink-3">
                  Review each item. <b className="text-ink-2">Approve</b> adds it to the remediation queue; no device is changed until you select <b className="text-ink-2">Execute remediation</b> and confirm. Anything not approved stays in Remediation.
                </p>
              )}
            </div>
          </div>
          {open.length > 0 && (
            <div className="flex flex-wrap gap-2">
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

        {(urgent > 0 || attacks > 0 || settings > 0 || grewRows.length > 0) && (
          <div className="mt-5 flex flex-wrap gap-2 text-xs">
            {urgent > 0 && <Count n={urgent} label="high priority" color={statusColor.critical} />}
            {attacks > 0 && <Count n={attacks} label={`sign${attacks === 1 ? '' : 's'} of attack to respond to`} color={statusColor.critical} />}
            {settings > 0 && <Count n={settings} label={`security setting${settings === 1 ? '' : 's'}`} />}
            {grewRows.length > 0 && <Count n={fix.grew_vulns ?? 0} label={`new vulnerabilities on ${grewRows.length} earlier remediation${grewRows.length === 1 ? '' : 's'}`} color={statusColor.warning} />}
          </div>
        )}

        <GettingReady what="The remediation engine" starting={auto.starting} failed={auto.failed} retry={auto.retry} className="mt-5" />
        {view.error && !down && <p className="mt-5 text-sm" style={{ color: statusColor.critical }}>{(view.error as Error).message}</p>}
        {act.error && <p className="mt-3 text-sm" style={{ color: statusColor.critical }}>{(act.error as Error).message}</p>}

        {open.length > 0 && (
          <ul className="mt-5 grid grid-cols-1 gap-3 md:grid-cols-2 2xl:grid-cols-3">
            {open.map(card)}
          </ul>
        )}
        {decided > 0 && (
          <p className="mt-3 text-xs text-ink-3">{decided} of this run's remediations already have a decision (approved, deferred or resolved): <Link to="/fixes/history" className="text-blue hover:underline">see Remediation</Link>.</p>
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
              {grewOpen.map(card)}
            </ul>
          </div>
        )}

        <div className="mt-5 flex flex-wrap items-center justify-end gap-3 border-t border-hairline pt-4 text-sm">
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
    {list && vulnerability.data && (
      <VulnList app={list.app} software={list.software} data={vulnerability.data} fixRows={v?.rows ?? []} engine={!!v}
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
function fixLinks(uc: AgentKey, since: string | null, _fix: RunFix): [string, string][] {
  const q = (tab: string, agent?: string) => {
    const p = new URLSearchParams({ ...(agent ? { agent } : {}), ...(since ? { since } : {}) }).toString()
    return `/fixes${tab}${p ? `?${p}` : ''}`
  }
  if (uc === 'attack_detection') return [[q('/attacks'), 'Go to remediations']]
  if (uc === 'threat_intel') return [[q('', 'threat_intel'), 'Go to remediations']]
  return [[q('', 'vulnerability'), 'Go to remediations']]
}

function Count({ n, label, color, strong }: { n: number; label: string; color?: string; strong?: boolean }) {
  return (
    <span className={cn('inline-flex items-center gap-1.5 rounded-lg border border-hairline px-3 py-1', strong && 'bg-well')}>
      <b className="tabular text-sm" style={{ color }}>{num(n)}</b> <span className="text-ink-3">{label}</span>
    </span>
  )
}

const MOVE_LABEL = { quick_scan: 'Quick scan', full_scan: 'Full scan', winget: 'Install with winget', choco: 'Install with Chocolatey',
  uninstall: 'Uninstall', apply: 'Apply setting', stop: 'Finished' } as const

/** What the Remediation Agent did on this device, move by move, while it runs and after. */
export function AgentMoves({ r }: { r: FixRow }) {
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
  if (isResponse(r)) return <ResponseCard r={r} busy={busy} onFix={onFix} onAutoFix={onAutoFix} onSave={onSave} onUndo={onUndo} />
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
  const remediationLink = setting ? '/fixes/settings' : isResponse(r) ? (isIndicatorResponse(r) ? '/fixes/indicators' : '/fixes/attacks') : `/fixes?sw=${encodeURIComponent(r.software_name)}`
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
        {/* one line to decide on; everything else (CVEs, AI advice, first seen) is on the Remediation card */}
        <div className="text-xs text-ink-2">{whatItDoes(r)}</div>
        {isResponse(r) && <AgentMoves r={r} />}
        {!isSetting(r) && !isResponse(r) && total > 0 && (
          <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1 text-[11px] text-ink-3">
            <span><b className="tabular font-semibold text-ink">{num(total)}</b> vulnerabilit{total === 1 ? 'y' : 'ies'}</span>
            {severe > 0 && <span style={{ color: statusColor.critical }}><b className="tabular font-semibold">{num(severe)}</b> critical / high</span>}
            {due && <span style={late ? { color: statusColor.critical } : undefined}>{late ? `${num(-left!)} d overdue` : left != null ? `due in ${num(left)} d` : `due ${shortDate(due)}`}</span>}
            {noFix > 0 && <span style={{ color: statusColor.warning }}>{num(noFix)} without update</span>}
          </div>
        )}
        {setting && (
          <div className="text-[11px] text-ink-3">
            {setting.category}{setting.impact ? ` · impact ${setting.impact}/10` : ''}
            {setting.user_impact && <span style={{ color: statusColor.warning }}> · users may notice</span>}
          </div>
        )}
        {(added || (r.threats && r.threats.length > 0)) ? (
          <div className="flex items-center gap-1.5 text-[11px] font-medium" style={{ color: added ? statusColor.warning : 'var(--violet)' }}>
            {added ? <>+{num(added)} new in this run</> : <><Newspaper className="size-3.5 shrink-0" /><span className="truncate" title={r.threats!.map((t) => t.title).join('\n')}>In the news: {r.threats![0].title}</span></>}
          </div>
        ) : null}

        <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs">
          {onList && detail && !isSetting(r) && (
            <button onClick={onList} className="inline-flex items-center gap-1 font-medium text-sky hover:underline">
              <ListChecks className="size-3.5" /> View {total === 1 ? 'it' : 'all'}
            </button>
          )}
          <Link to={remediationLink} className="ml-auto inline-flex items-center gap-1 font-medium text-ink-2 hover:text-ink hover:underline">
            Details in Remediation <ArrowRight className="size-3.5" />
          </Link>
        </div>

        <ManualAction r={r} compact />
        {r.started_at && <RecordLink id={r.fix_id} />}

        <div className="mt-auto flex flex-wrap items-center justify-between gap-2 pt-2">
          {r.status === 'proposed' ? (
            <>
              <span />
              <span className="flex gap-1.5">
                <button onClick={onFix} disabled={busy} className="btn-blue inline-flex items-center gap-1.5 rounded-lg px-3.5 py-1.5 text-xs font-semibold disabled:opacity-50">
                  <Zap className="size-3.5" /> Approve
                </button>
              </span>
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

/**
 * A response to a detection, as a decision card: what was found and where, in a few readable lines, the latest
 * result once it has run, and the decision buttons. The evidence, hunt results and full agent log stay on the
 * Attack detection and Remediation pages, one click away.
 */
function ResponseCard({ r, busy, onFix, onAutoFix, onUndo }: {
  r: FixRow; busy: boolean; onFix: () => void; onAutoFix?: () => void; onSave: () => void; onUndo: (action: 'unapprove' | 'unsave') => void
}) {
  const { theme } = useTheme()
  const detections = useAttackDetectionData().data
  const h = detections?.hits.find((x) => `response:${x.finding_id}` === r.software_name)
  const indicator = isIndicatorResponse(r)
  const sevColor = h ? (chartTokens[theme].severity as Record<string, string>)[h.severity] ?? statusColor.warning : statusColor.critical
  const last = (r.agent ?? []).filter((m) => m.result).slice(-1)[0]
  const result = last?.result ?? (r.status !== 'proposed' && r.status !== 'saved' ? r.message : null)
  const ok = last?.status === 'done' || r.status === 'done' || r.status === 'verified'
  const what = h ? (h.resolution?.what_happened || h.detail) : indicator ? 'A collected indicator of compromise was observed on this device.' : r.app
  const link = indicator ? '/fixes/indicators' : `/fixes/attacks?show=all&fix=${encodeURIComponent(r.fix_id)}`
  const btn = 'inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-semibold disabled:opacity-50'
  return (
    <li className={cn('flex flex-col overflow-hidden rounded-xl border border-hairline bg-panel', r.status === 'saved' && 'opacity-70')}>
      <span className="h-1" style={{ background: sevColor }} />
      <div className="flex flex-1 flex-col gap-2 p-4">
        <div className="flex items-center justify-between gap-2 text-[11px] font-medium">
          <span className="flex min-w-0 items-center gap-2">
            {h ? <><SevTag sev={h.severity} /><span className="truncate font-normal text-ink-3">{h.attack_name}</span></>
              : <span className="font-normal text-ink-3">{indicator ? 'Indicator seen on the device' : 'Detection'}</span>}
          </span>
          <span className="shrink-0 rounded-md bg-well px-1.5 py-0.5 text-ink-2">{r.device_name}</span>
        </div>
        <div className="font-semibold leading-snug">{h ? h.resolution?.title || h.search_name : r.app}</div>
        <p className="line-clamp-3 text-xs leading-relaxed text-ink-2">{what}</p>
        <div className="text-[11px] text-ink-3">
          Response: Defender scan and clean
          {h?.first_hit ? <> · first seen {shortDate(h.first_hit.slice(0, 10))}</> : null}
        </div>
        {result && (
          <div className="flex items-start gap-1.5 rounded-lg px-2.5 py-1.5 text-xs" style={{ color: ok ? statusColor.good : statusColor.critical, background: `color-mix(in oklab, ${ok ? statusColor.good : statusColor.critical} 10%, transparent)` }}>
            {ok ? <CheckCircle2 className="mt-0.5 size-3.5 shrink-0" /> : <AlertTriangle className="mt-0.5 size-3.5 shrink-0" />}
            <span className="line-clamp-2">{result}</span>
          </div>
        )}
        <Link to={link} className="inline-flex items-center gap-1 self-start text-xs font-medium text-blue hover:underline">
          Evidence and full details <ArrowRight className="size-3.5" />
        </Link>
        <div className="mt-auto flex flex-wrap items-center justify-between gap-2 pt-2">
          {r.status === 'proposed' ? (
            <>
              <span />
              <span className="flex gap-1.5">
                <button onClick={onFix} disabled={busy} className={cn(btn, 'btn-blue')}><Zap className="size-3.5" /> Approve</button>
              </span>
            </>
          ) : (
            <>
              <StatusPill r={r} />
              {r.status === 'saved' ? <button onClick={() => onUndo('unsave')} disabled={busy} className={cn(btn, 'font-medium text-ink-2 hover:bg-well')}><Undo2 className="size-3.5" /> Undo</button>
                : r.status === 'approved' ? <button onClick={() => onUndo('unapprove')} disabled={busy} className={cn(btn, 'font-medium text-ink-2 hover:bg-well')}><Undo2 className="size-3.5" /> Remove</button>
                : r.status === 'failed' || r.status === 'still_there' ? <button onClick={onAutoFix ?? onFix} disabled={busy} className={cn(btn, 'btn-blue')}><Sparkles className="size-3.5" /> Try again</button>
                : null}
            </>
          )}
        </div>
      </div>
    </li>
  )
}