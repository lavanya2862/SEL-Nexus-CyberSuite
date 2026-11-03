import { Link, useSearchParams } from 'react-router-dom'
import { useState } from 'react'
import { ArrowRight, Gauge, ListChecks, Monitor, ShieldAlert, Sparkles, Undo2, X, Zap } from 'lucide-react'
import { AgentMoves } from '@/components/NewFixes'
import { DialogSection, ExpandableCard } from '@/components/DetailDialog'
import { useAttackDetectionData, type Finding } from '@/agents/attack-detection/data'
import { StatusPill } from '@/components/FixLoop'
import { DateFilter, Empty, FilterBar, FilterChoice, Panel, SevTag, StatBox, choiceChip, dateChip, inDateRange, type ActiveFilter, type DateRange } from '@/components/kit'
import { BasketBar } from '@/agents/fixes/FixCentre'
import { FixDown, autoFix, canApprove, fixTime, isIndicatorResponse, useFix, useFixAction, type FixRow, type FixStatus } from '@/agents/fixes/data'
import { ManualAction, PersonLine } from '@/components/ManualAction'
import { QuickActions } from '@/agents/fixes/QuickActions'
import { RecordLink } from '@/components/FixRecord'
import { ago, dateTime, num } from '@/lib/format'
import { AGENT_DOT, AGENT_NAME } from '@/lib/runs'
import { GettingReady, useAutoStart } from '@/lib/services'
import { chartTokens, statusColor, useTheme } from '@/lib/theme'
import { cn } from '@/lib/utils'

// where a response stands, in the order a person works through them
type Show = 'open' | 'progress' | 'manual' | 'closed' | 'all'
const SHOWS: [Show, string, string, FixStatus[] | null][] = [
  ['open', 'To decide', 'var(--ink-3)', ['proposed', 'saved']],
  ['progress', 'Approved or running', 'var(--sky)', ['approved', 'queued', 'running']],
  ['manual', 'Needs a person', statusColor.critical, ['manual_required', 'failed', 'still_there']],
  ['closed', 'Remediated', statusColor.good, ['done', 'verified', 'gone']],
  ['all', 'All responses', '', null],
]
const shown = (r: FixRow, show: Show) => (SHOWS.find(([s]) => s === show)?.[3] ?? null)?.includes(r.status) ?? true
const SEVS = ['Critical', 'High', 'Medium', 'Low']
type Owner = 'attack_detection' | 'threat_intel'

/**
 * Fix › Attack responses (the Attack Detection Agent's behaviour hits) or Indicator responses (the Threat Intel
 * Agent's collected indicators seen on a device): one per finding (a Defender update, quick scan and clean-up of that
 * computer), newest run first. ?since=<ISO time> (from the run page) keeps the responses that run proposed;
 * ?show=open|saved|all picks which ones to list.
 */
export function AttackResponses({ owner = 'attack_detection' }: { owner?: Owner }) {
  const foundAt = (r: FixRow) => fixTime(r.found_by?.[owner]) ?? ''
  const [params, setParams] = useSearchParams()
  const show: Show = SHOWS.some(([s]) => s === params.get('show')) ? (params.get('show') as Show) : 'open'
  const focus = params.get('fix')            // one response, opened from a finding's Remediate button
  const sinceRaw = params.get('since')
  const since = sinceRaw && !Number.isNaN(Date.parse(sinceRaw)) ? Date.parse(sinceRaw) : null
  const view = useFix()
  const { theme } = useTheme()
  const sevColor = (s: string) => (chartTokens[theme].severity as Record<string, string>)[s] ?? statusColor.warning
  // the detection behind each response (Attack Detection Agent's own data; response rows carry software_name 'response:<finding_id>')
  const detections = useAttackDetectionData().data
  const attacks = detections?.attacks ?? []
  const hitOf = (r: FixRow): Finding | undefined => detections?.hits.find((h) => `response:${h.finding_id}` === r.software_name)
  const act = useFixAction()
  const down = view.error instanceof FixDown
  const auto = useAutoStart(down, 'fix')
  const v = view.data
  const set = (key: string, value: string | null) => {
    const next = new URLSearchParams(params)
    if (value) next.set(key, value)
    else next.delete(key)
    setParams(next, { replace: true })
  }
  const [proposed, setProposed] = useState<DateRange>({ preset: 'any' })
  const [sev, setSev] = useState('all')
  const [attackNo, setAttackNo] = useState('all')
  const [device, setDevice] = useState('all')

  if (!v) {
    return (
      <Panel className="p-6">
        {down ? <GettingReady what="The remediation engine" {...auto} /> : view.error
          ? <p className="text-sm" style={{ color: statusColor.critical }}>Could not load remediation tasks: {(view.error as Error).message}</p>
          : <div className="h-40 animate-pulse" />}
      </Panel>
    )
  }

  const all = v.rows.filter((r) => r.action === 'respond' && isIndicatorResponse(r) === (owner === 'threat_intel'))
  const inRun = all.filter((r) => since == null || (foundAt(r) && Date.parse(foundAt(r)) >= since - 60_000))
  const sevOf = (r: FixRow) => hitOf(r)?.severity ?? ''
  const attackOf = (r: FixRow) => String(hitOf(r)?.attack ?? '')
  // every filter but the one being counted, so each menu's numbers match what picking it would show
  const keep = (r: FixRow, skip?: string) => inDateRange(fixTime(foundAt(r)), proposed)
    && (skip === 'sev' || sev === 'all' || sevOf(r) === sev) && (skip === 'attack' || attackNo === 'all' || attackOf(r) === attackNo)
    && (skip === 'device' || device === 'all' || r.device_name === device) && (skip === 'show' || shown(r, show))
  const rows = inRun.filter((r) => (focus ? r.fix_id === focus : keep(r)))
  const pool = (skip: string) => inRun.filter((r) => keep(r, skip))
  const showOptions = SHOWS.map(([s, label, dot]) => ({ value: s, label, dot: dot || undefined, count: pool('show').filter((r) => shown(r, s)).length }))
  const sevOptions = [{ value: 'all', label: 'All severities', count: pool('sev').length },
    ...SEVS.filter((s) => inRun.some((r) => sevOf(r) === s)).map((s) => ({ value: s, label: s, dot: sevColor(s), count: pool('sev').filter((r) => sevOf(r) === s).length }))]
  const attackOptions = [{ value: 'all', label: 'All attacks', count: pool('attack').length },
    ...attacks.filter((a) => inRun.some((r) => attackOf(r) === String(a.attack))).map((a) => ({ value: String(a.attack), label: a.name, count: pool('attack').filter((r) => attackOf(r) === String(a.attack)).length }))]
  const deviceOptions = [{ value: 'all', label: 'All devices', count: pool('device').length },
    ...[...new Set(inRun.map((r) => r.device_name))].sort().map((d) => ({ value: d, label: d, count: pool('device').filter((r) => r.device_name === d).length }))]
  const chips: ActiveFilter[] = [
    ...choiceChip('show', showOptions, show, () => set('show', null)),
    ...choiceChip('sev', sevOptions, sev, () => setSev('all')),
    ...choiceChip('attack', attackOptions, attackNo, () => setAttackNo('all')),
    ...choiceChip('device', deviceOptions, device, () => setDevice('all')),
    ...dateChip(proposed, () => setProposed({ preset: 'any' })),
  ]
  const clearAll = () => { setProposed({ preset: 'any' }); setSev('all'); setAttackNo('all'); setDevice('all'); set('show', null) }
  // one group per run: a run proposes all its new responses at the same moment
  const groups = new Map<string, FixRow[]>()
  for (const r of rows) groups.set(foundAt(r), [...(groups.get(foundAt(r)) ?? []), r])
  const ordered = [...groups.entries()].sort((a, b) => b[0].localeCompare(a[0]))
  const busy = act.isPending
  const approve = (ids: string[]) => ids.length && act.mutate({ action: 'approve', ids, method: v.default_method })

  return (
    <div className="flex flex-col gap-5">
      <Panel className="grid gap-6 p-6 md:grid-cols-[auto_minmax(0,1fr)] md:items-center">
        <div className="flex items-baseline gap-3">
          <span className="tabular text-[40px] leading-none tracking-tight">{num(all.filter((r) => r.status === 'proposed').length)}</span>
          <span className="text-sm text-ink-3">responses<br />to decide</span>
        </div>
        <div className="text-sm text-ink-2 text-justify">
          <p>
            For every {owner === 'threat_intel' ? 'collected indicator (a bad IP, domain, URL or file hash from the news) seen on a managed device' : 'suspicious behaviour'} the <span className="inline-flex items-center gap-1.5 font-medium"><span className={cn('size-2 rounded-full', AGENT_DOT[owner])} />{AGENT_NAME[owner]}</span> finds,
            it proposes a standard response: <b>update Defender, scan and remove any threats found</b> on the affected device, repeating with a full scan until Defender lists no active threat.{' '}
            Nothing runs until you approve it: <b>Approve</b> then Execute remediation.
          </p>
          <p className="mt-1.5 text-xs text-ink-3">
            Device isolation is outside this agent's scope; perform it in Microsoft Defender. The evidence on each card comes directly from Defender.
          </p>
        </div>
      </Panel>

      {focus && (
        <div className="flex flex-wrap items-center gap-2 rounded-xl border border-signal/40 bg-signal/10 px-4 py-2.5 text-sm">
          <span className={cn('size-2 rounded-full', AGENT_DOT[owner])} />
          <span>Showing the response proposed for the selected detection. Approve it to run the scan-and-clean on the device.</span>
          <button onClick={() => set('fix', null)} className="ml-auto inline-flex items-center gap-1 rounded-lg px-2 py-1 text-xs font-medium hover:bg-panel">
            <X className="size-3.5" /> Show all responses
          </button>
        </div>
      )}

      {since != null && (
        <div className="flex flex-wrap items-center gap-2 rounded-xl border border-signal/40 bg-signal/10 px-4 py-2.5 text-sm">
          <span className={cn('size-2 rounded-full', AGENT_DOT[owner])} />
          <span>Showing the responses the <b>{AGENT_NAME[owner]}</b> proposed in its run of <b>{dateTime(new Date(since).toISOString())}</b> (new in that run).</span>
          <button onClick={() => set('since', null)} className="ml-auto inline-flex items-center gap-1 rounded-lg px-2 py-1 text-xs font-medium hover:bg-panel">
            <X className="size-3.5" /> Show all responses
          </button>
        </div>
      )}

      <FilterBar chips={chips} onClear={clearAll} count={`${num(rows.length)} of ${num(inRun.length)} responses`}>
        <FilterChoice label="Status" icon={ListChecks} options={showOptions} value={show} onChange={(s) => set('show', s === 'open' ? null : s)} />
        {owner === 'attack_detection' && sevOptions.length > 1 && <FilterChoice label="Severity" icon={Gauge} options={sevOptions} value={sev} onChange={setSev} />}
        {owner === 'attack_detection' && attackOptions.length > 1 && <FilterChoice label="Attack" icon={ShieldAlert} options={attackOptions} value={attackNo} onChange={setAttackNo} />}
        <FilterChoice label="Device" icon={Monitor} options={deviceOptions} value={device} onChange={setDevice} />
        <DateFilter label="Proposed" value={proposed} onChange={setProposed} />
      </FilterBar>

      {act.error && <p className="text-sm" style={{ color: statusColor.critical }}>{(act.error as Error).message}</p>}

      {ordered.length === 0 && (
        <Empty text={inRun.length ? 'No responses match these filters.' : 'No detections, so no responses are required.'} />
      )}

      {ordered.map(([at, rs]) => {
        const fixable = rs.filter((r) => canApprove(r) && r.status !== 'failed')
        const toDecide = rs.filter((r) => r.status === 'proposed').length
        return (
          <Panel key={at || 'earlier'} className="p-5">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="flex min-w-0 items-center gap-2.5">
                <ShieldAlert className="size-5 shrink-0" style={{ color: statusColor.critical }} />
                <div className="min-w-0">
                  <div className="font-semibold tracking-tight">{at ? `Run of ${dateTime(at)}` : 'Earlier runs'}</div>
                  <div className="text-xs text-ink-3">
                    {num(rs.length)} response{rs.length === 1 ? '' : 's'} shown
                    {toDecide > 0 && <> · <b style={{ color: statusColor.warning }}>{toDecide} to decide</b></>}
                  </div>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <Link to={owner === 'threat_intel' ? '/runs/threat_intel' : '/runs/attack'} className="inline-flex items-center gap-1 rounded-lg px-2.5 py-1.5 text-xs font-medium text-ink-2 hover:bg-well">
                  Open the agent <ArrowRight className="size-3.5" />
                </Link>
                {fixable.length > 0 && (
                  <button onClick={() => autoFix(act, fixable.map((r) => r.fix_id), v.default_method)} disabled={busy} className="btn-blue inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-semibold disabled:opacity-50">
                    <Sparkles className="size-3.5" /> Approve and run all ({fixable.length})
                  </button>
                )}
              </div>
            </div>
            <ul className="mt-4 grid grid-cols-1 gap-3 md:grid-cols-2 2xl:grid-cols-3">
              {rs.map((r) => (
                <li key={r.fix_id}>
                  {(() => {
                    const h = owner === 'attack_detection' ? hitOf(r) : undefined
                    const attack = h && attacks.find((a) => a.attack === h.attack)
                    return (
                      <ExpandableCard defaultOpen={focus === r.fix_id} highlight={focus === r.fix_id}
                        accent={h ? sevColor(h.severity) : statusColor.critical}
                        title={h ? h.resolution?.title || h.search_name : r.app}
                        subtitle={`${r.device_name}${h ? ` · first seen ${dateTime(utc(h.first_hit))}` : ''}`}
                        eyebrow={<>{h ? <><SevTag sev={h.severity} /><span className="text-ink-3">{h.attack_name}</span></> : <span className="text-ink-3">Indicator seen on the device</span>}<StatusPill r={r} /></>}
                        footer={<ResponseActions r={r} busy={busy} onApprove={() => approve([r.fix_id])} onRun={() => autoFix(act, [r.fix_id], v.default_method)}
                          onUndo={() => act.mutate({ action: 'unapprove', ids: [r.fix_id] })} />}
                        actions={<QuickActions rows={[r]} busy={busy} onApprove={approve} onWithdraw={(ids) => act.mutate({ action: 'unapprove', ids })} />}
                        summary={
                          <>
                            <div className="flex items-center justify-between gap-2 text-[11px] font-medium">
                              <span className="truncate font-normal text-ink-3">{h ? h.attack_name : 'Indicator seen on the device'}</span>
                              <span className="shrink-0 rounded-md bg-well px-1.5 py-0.5 text-ink-2">{r.device_name}</span>
                            </div>
                            <div className="line-clamp-2 font-semibold leading-snug">{h ? h.resolution?.title || h.search_name : r.app}</div>
                            <div className="grid grid-cols-3 gap-2">
                              <StatBox value={h ? h.severity : 'Indicator'} label="Severity" color={h ? sevColor(h.severity) : undefined} />
                              <StatBox value={h?.first_hit ? ago(utc(h.first_hit)) : '–'} label="First seen" />
                              <StatBox value={h?.technique ?? '–'} label="Technique" />
                            </div>
                            <div className="flex min-w-0 items-center gap-2"><StatusPill r={r} /><PersonLine r={r} short /></div>
                          </>
                        }>
                        <DialogSection title="What was detected" aside={h && <Link to="/attack-detection?tab=detected" className="text-blue hover:underline">Open in Attack detection</Link>}>
                          <p className="leading-relaxed">{h ? h.resolution?.what_happened || h.detail : r.app}</p>
                          {r.note && <p className="mt-2 break-all rounded-lg bg-well px-3 py-2 font-mono text-xs text-ink-3">{r.note}</p>}
                        </DialogSection>
                        {attack && <DialogSection title="Why this matters"><p className="leading-relaxed text-ink-2">{h?.resolution?.why_it_matters || attack.description}</p></DialogSection>}
                        {r.status !== 'proposed' && (r.agent?.length || r.message || r.status === 'running' || r.status === 'queued')
                          ? <DialogSection title="Remediation activity"><AgentMoves r={r} /><ManualAction r={r} /><RecordLink id={r.fix_id} className="mt-2" /></DialogSection> : null}
                      </ExpandableCard>
                    )
                  })()}
                </li>
              ))}
            </ul>
          </Panel>
        )
      })}
      <BasketBar v={v} />
    </div>
  )
}

const utc = (t: string) => (/[+Z]/.test(t.slice(10)) ? t : t.replace(' ', 'T') + 'Z')

/** The decision buttons for one response, in the dialog footer (the same actions as the Remediation cards). */
function ResponseActions({ r, busy, onApprove, onRun, onUndo }: {
  r: FixRow; busy: boolean; onApprove: () => void; onRun: () => void; onUndo: () => void
}) {
  const ghost = 'inline-flex items-center gap-1.5 rounded-lg border border-hairline-strong bg-panel px-3.5 py-2 text-sm font-medium hover:bg-well disabled:opacity-50'
  const primary = 'btn-blue inline-flex items-center gap-1.5 rounded-lg px-3.5 py-2 text-sm font-semibold text-white disabled:opacity-50'
  const note = (text: string) => <span className="mr-auto text-xs text-ink-3">{text}</span>
  if (r.status === 'proposed' || r.status === 'saved') return <>{note('Approval runs a Microsoft Defender scan on the device and removes active threats. Nothing runs before that.')}<button onClick={onApprove} disabled={busy} className={ghost}><Zap className="size-4" /> Approve</button><button onClick={onRun} disabled={busy} className={primary}><Sparkles className="size-4" /> Approve and run now</button></>
  if (r.status === 'approved') return <>{note('Approved: runs with the next Execute remediation.')}<button onClick={onUndo} disabled={busy} className={ghost}><Undo2 className="size-4" /> Remove approval</button></>
  if (r.status === 'failed' || r.status === 'still_there') return <>{note('The last attempt did not finish cleanly.')}<button onClick={onRun} disabled={busy} className={primary}><Sparkles className="size-4" /> Try again</button></>
  if (r.status === 'manual_required') return note('The agent could not remediate this. Follow the steps above, then select Mark as fixed manually.')
  return null
}
