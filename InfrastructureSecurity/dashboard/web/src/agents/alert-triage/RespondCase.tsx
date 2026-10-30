import { Fragment, useState, type ReactNode } from 'react'
import { Link, useParams } from 'react-router-dom'
import {
  AlertTriangle, ArrowLeft, Bot, Undo2, Zap, CheckCircle2, CircleDot, ExternalLink, Hand, Loader2, ScanSearch,
} from 'lucide-react'
import { GettingReady, useAutoStart } from '@/lib/services'
import { Card, Empty, Panel, Tabs, Tag } from '@/components/kit'
import { Skeleton } from '@/components/ui/skeleton'
import { ago, dateTime } from '@/lib/format'
import { statusColor } from '@/lib/theme'
import {
  ACTION_WORDS, CLASSIFICATION_WORDS, CONTAINMENT, DECISION_EFFECT, DETERMINATION_WORDS, NotFound, RULES, STATUS_WORDS, VERDICT, isClosed, mitreLink, needsPerson, ruleMeta, sourceNames, useAsk, useDecide, useReopen, useTriageCase, utc, verdictMeta, type TriageCase,
} from '@/agents/alert-triage/data'
import { cn } from '@/lib/utils'
import { VerdictPill } from '@/agents/alert-triage/Respond'

const iso = (s: string | null | undefined) => utc(s)?.toISOString() ?? null
const pretty = (id: string) => id.replace(/^Q\d+_/i, '').replace(/_/g, ' ')

/** Act › Triage › one incident: the agent's verdict, the evidence behind it, and the analyst's decision. */
export function RespondCase() {
  const { id = '' } = useParams()
  const { data, error, isLoading } = useTriageCase(id)
  if (isLoading) return <Skeleton className="h-64 rounded-2xl" />
  if (error || !data) {
    return (
      <div className="flex flex-col gap-4">
        <BackLink />
        <Panel className="p-6"><Empty text={error instanceof NotFound ? `Incident ${id} has not been triaged (or does not exist).` : `Could not load the incident: ${(error as Error)?.message}`} /></Panel>
      </div>
    )
  }
  const { packet: p, verdict: v } = data
  return (
    <div className="flex flex-col gap-5">
      <BackLink />
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <VerdictPill verdict={data.outcome ?? v.verdict} large />
            {data.decision && data.outcome !== v.verdict && <Tag>Agent said: {verdictMeta(v.verdict).short.toLowerCase()}</Tag>}
            <DefenderStatus status={data.defender_state?.status ?? p.status} />
            <Tag>{v.confidence} confidence</Tag>
            {v.escalate && <Tag tone="bad">Escalate</Tag>}
          </div>
          <h1 className="mt-3 text-2xl font-semibold tracking-tight">{p.title}</h1>
          <p className="mt-1 text-sm text-ink-3">
            Incident #{p.incident_id} · {sourceNames(p.services)} · raised {ago(iso(p.created_at))} · Defender says <b className="font-medium text-ink-2">{p.severity}</b>, agent suggests <b className="font-medium text-ink-2">{v.recommended_severity}</b>
          </p>
        </div>
        {p.web_url && (
          <a href={p.web_url} target="_blank" rel="noreferrer noopener" className="inline-flex items-center gap-2 rounded-lg border border-hairline px-4 py-2 text-sm font-medium hover:bg-well">
            Open in Defender <ExternalLink className="size-3.5" />
          </a>
        )}
      </div>

      <div className="grid grid-cols-1 gap-5 xl:grid-cols-3">
        <div className="flex min-w-0 flex-col gap-5 xl:col-span-2">
          <Thinks c={data} />
          <Basis c={data} />
          <ToDo c={data} />
          <EvidenceTabs c={data} />
        </div>
        <div className="flex min-w-0 flex-col gap-5">
          <Decide c={data} />
          <Ask c={data} />
          <DidByItself c={data} />
          <Timeline c={data} />
        </div>
      </div>
    </div>
  )
}

/** Defender's status (open = still being worked on, closed = resolved), with Defender's own word on hover. */
function DefenderStatus({ status }: { status: string | null | undefined }) {
  const words = status ? STATUS_WORDS[status] ?? status : 'unknown'
  return isClosed(status)
    ? <span title={`Defender status: ${words}`}><Tag><CheckCircle2 className="size-3" /> Closed in Defender</Tag></span>
    : <span title={`Defender status: ${words}`}><Tag><CircleDot className="size-3" /> Open in Defender · {words.toLowerCase()}</Tag></span>
}

function BackLink() {
  return <Link to="/alert-triage" className="inline-flex w-fit items-center gap-1.5 text-sm text-ink-3 hover:text-ink"><ArrowLeft className="size-4" /> Alert triage</Link>
}

function Thinks({ c }: { c: TriageCase }) {
  const v = c.verdict
  return (
    <Card title={<span className="flex items-center gap-2"><Bot className="size-4" /> Agent assessment</span>} description={verdictMeta(v.verdict).help}>
      <p className="text-[15px] leading-relaxed">{v.summary}</p>
      {v.evidence.length > 0 && (
        <>
          <h4 className="mt-5 text-sm font-medium">Why: the evidence it used</h4>
          <ul className="mt-2 flex flex-col gap-2">
            {v.evidence.map((e, i) => (
              <li key={i} className="flex items-start gap-3 rounded-xl bg-well px-3 py-2.5 text-sm">
                <span className="mt-0.5 shrink-0 rounded-md bg-panel px-1.5 py-0.5 text-[11px] font-medium text-ink-2">{pretty(e.query_id || e.source)}</span>
                <span className="text-ink-2">{e.finding}</span>
              </li>
            ))}
          </ul>
          <p className="mt-2 text-xs text-ink-3">Every point was checked against the searches below; points the evidence did not support were removed before you saw this.</p>
        </>
      )}
      {v.would_change_verdict_if && (
        <div className="mt-4 rounded-xl border border-dashed border-hairline p-3 text-sm">
          <span className="font-medium">Verdict would change if: </span><span className="text-ink-2">{v.would_change_verdict_if}</span>
        </div>
      )}
      {v.mitre_techniques.length > 0 && (
        <div className="mt-4 flex flex-wrap items-center gap-1.5 text-xs text-ink-3">Attack techniques (MITRE): {v.mitre_techniques.map((t) => <Tag key={t}>{t}</Tag>)}</div>
      )}
    </Card>
  )
}

function ToDo({ c }: { c: TriageCase }) {
  const v = c.verdict
  if (!v.recommended_actions.length && !v.containment_options.length) return null
  return (
    <Card title="What to do" description="Recommendations only. An analyst performs them in Defender.">
      {v.recommended_actions.length > 0 && (
        <ol className="flex flex-col gap-2 text-sm">
          {v.recommended_actions.map((a, i) => (
            <li key={i} className="flex gap-3"><span className="tabular grid size-5 shrink-0 place-items-center rounded-full bg-well text-[11px] font-medium">{i + 1}</span><span className="text-ink-2">{a}</span></li>
          ))}
        </ol>
      )}
      {v.containment_options.length > 0 && (
        <div className="mt-4 rounded-xl border border-hairline p-3">
          <div className="flex items-center gap-2 text-sm font-medium"><Hand className="size-4" style={{ color: statusColor.serious }} /> Containment to consider</div>
          <ul className="mt-2 flex flex-col gap-1 text-sm text-ink-2">
            {v.containment_options.map((o) => <li key={o}>• {CONTAINMENT[o] ?? o}</li>)}
          </ul>
          <p className="mt-2 text-xs text-ink-3">CyberSuite never performs containment. Only options from the approved list appear here.</p>
        </div>
      )}
    </Card>
  )
}

/* ───────── basis for the classification ───────── */

const INVESTIGATION_WORDS: Record<string, string> = {
  pendingApproval: 'waiting for approval', running: 'running', successfullyRemediated: 'remediated by Defender', benign: 'found nothing harmful',
  failed: 'failed', partiallyRemediated: 'partially remediated by Defender', terminatedByUser: 'stopped by a person', queued: 'queued',
  partiallyInvestigated: 'partly investigated', terminatedBySystem: 'stopped by Defender', innerFailure: 'failed',
}
const VERDICT_TONE: Record<string, 'bad' | 'warn' | undefined> = { malicious: 'bad', suspicious: 'warn' }
// the first table a search reads: Defender's advanced-hunting tables (Device*, Alert*, Email*, Identity*...) vs Sentinel's
const tableOf = (kql?: string) => (kql ?? '').split('\n').map((l) => l.trim()).find((l) => l && !l.startsWith('//'))?.split(/[\s|(]/)[0] ?? ''
const cleanLines = (text: string) => text.split(/\r?\n/).map((l) => l.replace(/^[^A-Za-z0-9]+/, '').trim()).filter(Boolean)

function Basis({ c }: { c: TriageCase }) {
  const v = c.verdict
  const tables = [...new Set(c.queries.map((q) => tableOf(q.query)).filter(Boolean))]
  const groups = new Map<string, TriageCase['packet']['alerts']>()
  for (const a of c.packet.alerts) {
    const key = [a.product, a.title, a.sentinel_rule?.name, a.detection_source].join('|')
    groups.set(key, [...(groups.get(key) ?? []), a])
  }
  return (
    <Card title="Basis for this classification" description="Everything the verdict rests on, with a link to each source.">
      <BasisHeading n={1} title="What Microsoft said" note={`Sentinel and Defender raised it. Microsoft rated it ${c.packet.severity}.`} />
      <ul className="flex flex-col gap-3">
        {[...groups.values()].map((same) => {
          const a = same[0]
          const rule = a.sentinel_rule
          const evidence = same.flatMap((x) => x.evidence_verdicts ?? [])
            .filter((e, i, all) => all.findIndex((o) => o.kind === e.kind && o.name === e.name && o.verdict === e.verdict) === i)
          const links = same.filter((x) => x.web_url)
          const sentinel = !!rule || (a.service_source ?? '').toLowerCase().includes('sentinel')
          const actions = cleanLines(a.recommended_actions ?? '')
          const inv = a.investigation_state && a.investigation_state !== 'unsupportedAlertType' ? INVESTIGATION_WORDS[a.investigation_state] ?? a.investigation_state : null
          return (
            <li key={a.id} className="rounded-xl border border-hairline p-4 text-sm">
              <div className="flex flex-wrap items-start justify-between gap-2">
                <div className="min-w-0">
                  <span className="mr-2 rounded-md bg-well px-1.5 py-0.5 text-[11px] font-medium text-ink-2">{a.product || sourceNames(a.service_source)}</span>
                  <span className="font-medium">{a.title}</span>
                  {same.length > 1 && <span className="ml-2 text-xs text-ink-3">{same.length} alerts</span>}
                </div>
                {links.length === 1 && (
                  <a href={links[0].web_url} target="_blank" rel="noreferrer noopener" className="inline-flex shrink-0 items-center gap-1 text-xs font-medium hover:underline">
                    Open the alert in Microsoft Defender <ExternalLink className="size-3" />
                  </a>
                )}
              </div>
              {links.length > 1 && (
                <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs">
                  <span className="text-ink-3">Open in Microsoft Defender:</span>
                  {links.map((x, i) => (
                    <a key={x.id} href={x.web_url} target="_blank" rel="noreferrer noopener" className="inline-flex items-center gap-1 font-medium hover:underline">
                      Alert {i + 1} <ExternalLink className="size-3" />
                    </a>
                  ))}
                </div>
              )}
              <dl className="mt-2 grid grid-cols-[auto_minmax(0,1fr)] gap-x-3 gap-y-1 text-xs">
                {sentinel ? (
                  <>
                    <dt className="text-ink-3">Raised by</dt>
                    <dd className="text-ink-2">Sentinel analytics rule <b className="font-medium text-ink">{rule?.name || a.title}</b>{rule?.template_id ? ' (from a Microsoft rule template)' : ''}</dd>
                    {rule?.results && <><dt className="text-ink-3">Rule matched</dt><dd className="text-ink-2">{rule.results} result{rule.results === '1' ? '' : 's'}{rule.trigger ? ` (fires when ${rule.trigger.replace('GreaterThan', 'more than')})` : ''}</dd></>}
                    {!!rule?.data_sources.length && <><dt className="text-ink-3">Data searched</dt><dd className="text-ink-2">Your Sentinel workspace (Log Analytics)</dd></>}
                    {!!rule?.ids.length && <><dt className="text-ink-3">Rule ID</dt><dd className="break-all font-mono text-[11px] text-ink-3">{rule.ids.join(', ')}</dd></>}
                  </>
                ) : (
                  <>
                    <dt className="text-ink-3">Detected by</dt>
                    <dd className="text-ink-2">{pretty(a.detection_source) || 'Defender'}{a.threat_name ? <> · threat <b className="font-medium text-ink">{a.threat_name}</b></> : null}</dd>
                  </>
                )}
                {inv && <><dt className="text-ink-3">Automated investigation</dt><dd className="text-ink-2">{inv}</dd></>}
                {a.techniques.length > 0 && <><dt className="text-ink-3">MITRE</dt><dd className="flex flex-wrap gap-1">{a.techniques.map((t) => <a key={t} href={mitreLink(t)} target="_blank" rel="noreferrer noopener" className="inline-flex items-center gap-1 rounded-md border border-hairline px-1.5 py-0.5 text-[11px] text-ink-2 hover:bg-well">{t} <ExternalLink className="size-3" /></a>)}</dd></>}
              </dl>
              {evidence.length > 0 && (
                <div className="mt-3">
                  <div className="flex flex-wrap items-center gap-x-2 text-xs text-ink-3">
                    {sentinel ? 'Evidence' : 'Defender’s verdict on the evidence'}
                    <a href={RULES.microsoft_malicious_evidence.link} target="_blank" rel="noreferrer noopener" className="inline-flex items-center gap-1 hover:underline">what the verdicts mean <ExternalLink className="size-3" /></a>
                  </div>
                  <div className="mt-1 flex flex-wrap gap-1.5">
                    {evidence.map((e, i) => (
                      <Tag key={i} tone={VERDICT_TONE[e.verdict]}>
                        {e.kind}{e.name ? ` ${e.name}` : ''}: {e.verdict || 'unknown'}{e.remediation && e.remediation !== 'none' ? ` · ${e.remediation}` : ''}
                      </Tag>
                    ))}
                  </div>
                </div>
              )}
              {actions.length > 0 && (
                <details className="mt-3 text-xs">
                  <summary className="cursor-pointer text-ink-3">Microsoft’s recommended actions ({actions.length})</summary>
                  <ul className="mt-1.5 flex flex-col gap-1 text-ink-2">{actions.map((x, i) => <li key={i}>• {x}</li>)}</ul>
                </details>
              )}
            </li>
          )
        })}
      </ul>

      <BasisHeading n={2} title="Evidence used by the agent" note={v.ai_status === 'ai'
        ? `The agent reached its verdict from ${v.evidence.length} evidence point${v.evidence.length === 1 ? '' : 's'}, listed under “Agent assessment”, each from a search in these logs:`
        : 'The agent model was not used for this verdict (unavailable, or its output was rejected). It is based on the rules below only.'} />
      {tables.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {tables.map((t) => <Tag key={t}>{t} · {/^(Device|Alert|Email|Identity|CloudApp|UrlClick)/.test(t) ? 'Defender' : 'Sentinel'}</Tag>)}
        </div>
      )}

      <BasisHeading n={3} title="Rules applied" note={v.guardrails.length ? 'These can only make the verdict more careful.' : 'No rule changed the agent’s verdict.'} />
      {v.guardrails.length > 0 && (
        <ul className="flex flex-col gap-2 text-sm">
          {v.guardrails.map((id, i) => {
            const r = ruleMeta(id)
            return (
              <li key={id} className="rounded-xl bg-well px-3 py-2.5">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="font-medium">{r.label}</span>
                  <span className="rounded-md bg-panel px-1.5 py-0.5 text-[11px] text-ink-2">{r.basis}</span>
                </div>
                {v.guardrail_reasons[i] && <p className="mt-0.5 text-xs text-ink-3">{v.guardrail_reasons[i]}</p>}
                {r.link && <a href={r.link} target="_blank" rel="noreferrer noopener" className="mt-1 inline-flex items-center gap-1 text-xs font-medium hover:underline">{r.linkText} <ExternalLink className="size-3" /></a>}
              </li>
            )
          })}
        </ul>
      )}

      <BasisHeading n={4} title="Validation of the agent’s verdict" note="Every point the agent made must match a search result; unsupported points were removed." />
      <ul className="flex flex-col gap-2 text-sm">
        {v.checker_notes.map((n, i) => <li key={i} className="flex items-start gap-2"><ScanSearch className="mt-0.5 size-4 shrink-0" style={{ color: statusColor.serious }} /><span className="text-ink-2">{n}</span></li>)}
        {c.injection.length > 0 && <li className="flex items-start gap-2"><AlertTriangle className="mt-0.5 size-4 shrink-0" style={{ color: statusColor.critical }} /><span className="text-ink-2">Text attempting to instruct the agent was found in {c.injection.map((x) => x.where).join(', ')}. It was not obeyed.</span></li>}
        {!v.checker_notes.length && !c.injection.length && <li className="flex items-start gap-2 text-ink-2"><CheckCircle2 className="mt-0.5 size-4 shrink-0" style={{ color: statusColor.good }} /> All points matched the evidence, and no attacker text attempted to instruct the agent.</li>}
      </ul>
    </Card>
  )
}

function BasisHeading({ n, title, note }: { n: number; title: string; note: string }) {
  return (
    <div className={cn('mb-2', n > 1 && 'mt-6 border-t border-hairline pt-5')}>
      <h4 className="text-sm font-semibold"><span className="tabular text-ink-3">{n}.</span> {title}</h4>
      <p className="mt-0.5 text-xs text-ink-3">{note}</p>
    </div>
  )
}

/* ───────── your decision ───────── */

type Final = keyof typeof DECISION_EFFECT

function Decide({ c }: { c: TriageCase }) {
  const decide = useDecide()
  const auto = useAutoStart(!c.site_up, 'triage')
  const [right, setRight] = useState<Final | null>(null)
  const [why, setWhy] = useState('')
  const [reason, setReason] = useState('')
  const { packet: p, verdict: v } = c
  const reopened = c.actions.some((a) => a.action === 'reopen' && a.status === 'done')
  const pick = (x: Final) => { setRight(x); setWhy(DECISION_EFFECT[x].reasons[0][0]) }
  const send = () => right && decide.mutate({ incident_id: p.incident_id, verdict: right, determination: why, reason })

  if (!needsPerson({ verdict: v.verdict, ai_status: v.ai_status, is_lab: p.is_lab }, c.automation.auto_resolve, reopened)) {
    const tp = v.verdict === 'likely_true_positive'
    return (
      <Panel className="flex flex-col gap-2 p-6">
        <h3 className="flex items-center gap-2 font-semibold tracking-tight"><Zap className="size-4" style={{ color: statusColor.warning }} /> Handled by the agent</h3>
        <p className="text-sm text-ink-3">
          {tp ? 'The agent classified this as a true positive, so it was escalated: it is open in Defender as In progress for the response. No analyst decision required.'
            : `The agent classified this as ${verdictMeta(v.verdict).short.toLowerCase()}, so it was closed in Defender. No analyst decision required. If this is incorrect, reopen it below.`}
        </p>
      </Panel>
    )
  }

  // classified already (here or in Defender): show the decision, never the choice again
  if (c.decision) return <Decided c={c} />

  return (
    <Panel className="flex flex-col gap-4 p-6">
      <div>
        <h3 className="font-semibold tracking-tight">Analyst decision</h3>
        <p className="mt-1 text-sm text-ink-3">
          {reopened ? 'This incident was reopened and is awaiting analyst review.' : v.ai_status !== 'ai' ? 'The agent model was not used for this verdict.' : 'The agent could not classify this incident.'} Your decision is written into Defender.
        </p>
      </div>
      {!c.site_up ? (
        <GettingReady what="the decision buttons" {...auto} className="rounded-xl bg-well p-3" />
      ) : (
        <div className="flex flex-col gap-3">
          <fieldset>
            <legend className="sr-only">What is it?</legend>
            <div className="flex flex-col gap-1.5">
              {(Object.keys(DECISION_EFFECT) as Final[]).map((x) => (
                <label key={x} className={cn('flex cursor-pointer items-start gap-2.5 rounded-xl border px-3 py-2 text-sm', right === x ? 'pill-on' : 'border-hairline hover:bg-well')}>
                  <input type="radio" name="right" className="mt-1" checked={right === x} onChange={() => pick(x)} />
                  <span><span className="flex items-center gap-1.5 font-medium"><span className="size-2 rounded-full" style={{ background: VERDICT[x].color }} />{VERDICT[x].label}</span>
                    <span className="block text-xs text-ink-3">{VERDICT[x].help}</span>
                    <span className="mt-1 block text-xs font-medium text-ink-2">In Defender: {DECISION_EFFECT[x].effect}</span></span>
                </label>
              ))}
            </div>
          </fieldset>
          {right && (
            <label className="text-sm">
              <span className="font-medium">Determination <span className="font-normal text-ink-3">(recorded in Defender)</span></span>
              <select value={why} onChange={(e) => setWhy(e.target.value)} className="mt-1 w-full rounded-lg border border-hairline bg-field px-3 py-2 text-sm outline-none focus:border-blue/60 focus:ring-3 focus:ring-blue/15">
                {DECISION_EFFECT[right].reasons.map(([id, label]) => <option key={id} value={id}>{label}</option>)}
              </select>
            </label>
          )}
          <label className="text-sm">
            <span className="font-medium">Reason <span className="font-normal text-ink-3">(optional, added as a comment in Defender)</span></span>
            <textarea value={reason} onChange={(e) => setReason(e.target.value.slice(0, 500))} rows={2} className="mt-1 w-full rounded-lg border border-hairline bg-field px-3 py-2 text-sm outline-none transition-[border-color,box-shadow] focus:border-blue/60 focus:ring-3 focus:ring-blue/15" placeholder="For example: authorised administrative activity" />
          </label>
          <button onClick={send} disabled={!right || decide.isPending || decide.isSuccess} className="inline-flex items-center justify-center gap-2 rounded-lg btn-blue px-3 py-2 text-sm font-medium text-white disabled:opacity-40">
            {decide.isPending && <Loader2 className="size-4 animate-spin" />}
            {decide.isPending ? 'Writing to Defender…' : right ? DECISION_EFFECT[right].button : 'Save my decision'}
          </button>
        </div>
      )}
      {decide.isError && <p className="text-xs" style={{ color: statusColor.critical }}>Not saved: {(decide.error as Error).message}</p>}
      {decide.isSuccess && <p className="flex items-center gap-1.5 text-xs text-ink-2"><Loader2 className="size-3.5 animate-spin" /> Written to Defender. Updating…</p>}
    </Panel>
  )
}

/** The decision already made: by an analyst in CyberSuite (written into Defender), or the classification Defender holds. */
function Decided({ c }: { c: TriageCase }) {
  const d = c.decision!
  const closed = isClosed(d.status)
  const note = [...c.feedback].reverse().find((f) => f.analyst_verdict)
  const det = d.determination && d.determination !== 'unknown' ? ` (${DETERMINATION_WORDS[d.determination] ?? d.determination})` : ''
  const rows: [string, ReactNode][] = [
    ['Classification', <>{CLASSIFICATION_WORDS[d.classification ?? ''] ?? verdictMeta(d.outcome).label}{det}</>],
    ['In Defender', <b className="font-medium text-ink">{closed ? 'Closed' : 'Open'}{d.status ? ` · ${STATUS_WORDS[d.status] ?? d.status}` : ''}</b>],
    ['Decided', d.by === 'analyst' ? `by ${d.who || 'an analyst'} in CyberSuite${d.at ? `, ${ago(d.at)}` : ''}` : 'in Microsoft Defender'],
    ['The agent had said', verdictMeta(c.verdict.verdict).label],
  ]
  return (
    <Panel className="flex flex-col gap-3 p-6">
      <h3 className="flex items-center gap-2 font-semibold tracking-tight">
        <CheckCircle2 className="size-4" style={{ color: statusColor.good }} /> Reviewed · {closed ? 'closed' : 'open'} in Defender
      </h3>
      <div><VerdictPill verdict={d.outcome} large /></div>
      <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-3 gap-y-1.5 text-sm">
        {rows.map(([k, val]) => <Fragment key={k}><dt className="text-ink-3">{k}</dt><dd className="text-ink-2">{val}</dd></Fragment>)}
      </dl>
      {d.by === 'analyst' && note?.reason && <p className="rounded-xl bg-well p-3 text-sm text-ink-2">“{note.reason}”</p>}
      <p className="text-xs text-ink-3">
        {closed ? 'Nothing more to do.' : 'Continue the response in Defender; close the incident there when it is dealt with.'}
        {' '}To change the classification, update the incident in Defender. CyberSuite picks it up on the next check.
      </p>
    </Panel>
  )
}

/* ───────── ask about this incident ───────── */

const PART_WORDS: Record<string, string> = {
  verdict: 'the verdict', evidence: 'the evidence', alerts: 'the alerts', entities: 'entities', searches: 'the searches',
  threat_intel: 'threat intelligence', history: 'history', context: 'background', defender: 'what Defender did', actions: 'actions taken',
}
const STARTERS = ['Summarise this incident', 'Why this verdict?', 'What would make it a true positive?', 'What should I check in Defender?']

function Ask({ c }: { c: TriageCase }) {
  const ask = useAsk()
  const auto = useAutoStart(!c.site_up, 'triage')
  const [question, setQuestion] = useState('')
  const turns = (c.questions ?? []).slice(-6)
  const id = c.packet.incident_id
  const send = (q?: string) => {
    const text = (q ?? question).trim()
    if (!text || ask.isPending) return
    setQuestion(text)
    ask.mutate({ incident_id: id, question: text }, { onSuccess: () => setQuestion('') })
  }
  return (
    <Card
      title={<span className="flex items-center gap-2"><Bot className="size-4" /> Ask about this incident</span>}
      description="The agent answers from this incident's evidence only. It cannot make changes; the decision is yours."
    >
      {turns.length > 0 && (
        <ul className="mb-4 flex flex-col gap-3">
          {turns.map((t) => (
            <li key={t.ask_id} className="text-sm">
              <p className="font-medium">{t.question}</p>
              <p className="mt-1.5 whitespace-pre-line rounded-xl bg-well px-3 py-2.5 leading-relaxed text-ink-2">{t.answer}</p>
              <p className="mt-1 text-xs text-ink-3">
                {t.based_on.length ? `Based on ${t.based_on.map((b) => PART_WORDS[b] ?? b).join(', ')} · ` : ''}{ago(iso(t.created_at))}
              </p>
            </li>
          ))}
        </ul>
      )}
      {!c.site_up ? (
        <GettingReady what="questions" {...auto} className="rounded-xl bg-well p-3" />
      ) : (
        <div className="flex flex-col gap-2">
          {turns.length === 0 && (
            <div className="flex flex-wrap gap-1.5">
              {STARTERS.map((s) => (
                <button key={s} onClick={() => send(s)} disabled={ask.isPending} className="rounded-full border border-hairline px-2.5 py-1 text-xs text-ink-2 hover:bg-well disabled:opacity-50">{s}</button>
              ))}
            </div>
          )}
          <textarea
            value={question}
            onChange={(e) => setQuestion(e.target.value.slice(0, 500))}
            onKeyDown={(e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send() } }}
            rows={2}
            aria-label="Your question"
            placeholder="For example: why is this not a true positive?"
            className="w-full rounded-lg border border-hairline bg-field px-3 py-2 text-sm outline-none transition-[border-color,box-shadow] focus:border-blue/60 focus:ring-3 focus:ring-blue/15"
          />
          <div className="flex items-center gap-3">
            <button onClick={() => send()} disabled={!question.trim() || ask.isPending} className="inline-flex items-center gap-2 rounded-lg btn-blue px-3 py-2 text-sm font-medium text-white disabled:opacity-40">
              {ask.isPending && <Loader2 className="size-4 animate-spin" />} Ask
            </button>
            {ask.isPending && <span className="text-xs text-ink-3">Analysing…</span>}
          </div>
          {ask.isError && <p className="text-xs" style={{ color: statusColor.critical }}>{(ask.error as Error).message}</p>}
        </div>
      )}
    </Card>
  )
}

/* ───────── what Alert Triage did by itself ───────── */

function DidByItself({ c }: { c: TriageCase }) {
  const acts = c.actions.filter((a) => a.status === 'done' || a.status === 'failed')
  if (!acts.length && !c.automation.auto_resolve) return null
  const reopen = useReopen()
  const [sure, setSure] = useState(false)
  return (
    <Card
      title={<span className="flex items-center gap-2"><Zap className="size-4" style={{ color: statusColor.warning }} /> Automated actions taken</span>}
      description={c.automation.auto_resolve ? 'Automatic handling is on.' : 'Automatic handling is off now; earlier actions stay listed.'}
    >
      {acts.length ? (
        <ul className="flex flex-col gap-2">
          {[...acts].reverse().map((a, i) => (
            <li key={a.action_id ?? i} className="rounded-xl bg-well px-3 py-2.5 text-sm">
              <div className="flex items-center justify-between gap-2">
                <span className="font-medium">{ACTION_WORDS[a.action] ?? a.action}{a.status === 'failed' ? ' (failed)' : ''}</span>
                <span className="text-xs text-ink-3">{ago(a.done_at ?? a.requested_at)}</span>
              </div>
              {a.detail && <p className="mt-0.5 text-xs leading-relaxed text-ink-3">Why: {a.detail.split(' -> ')[0]}</p>}
            </li>
          ))}
        </ul>
      ) : <p className="text-sm text-ink-3">None: this incident did not meet the criteria for automated handling.</p>}
      {acts.some((a) => a.action === 'auto_resolve') && (
        <div className="mt-3 flex flex-wrap items-center gap-2 text-sm">
          {reopen.isSuccess ? (
            <span className="text-ink-2"><CheckCircle2 className="mr-1 inline size-4" style={{ color: statusColor.good }} />Reopened in Defender and awaiting analyst review.</span>
          ) : !sure ? (
            <button onClick={() => setSure(true)} className="inline-flex items-center gap-2 rounded-lg border border-hairline px-3 py-1.5 font-medium hover:bg-well">
              <Undo2 className="size-3.5" /> Undo: reopen it
            </button>
          ) : (
            <>
              <span className="text-ink-2">Reopen this incident in Defender?</span>
              <button onClick={() => reopen.mutate(c.packet.incident_id)} disabled={reopen.isPending} className="inline-flex items-center gap-2 rounded-lg btn-blue px-3 py-1.5 font-medium text-white disabled:opacity-50">
                {reopen.isPending ? <Loader2 className="size-3.5 animate-spin" /> : <Undo2 className="size-3.5" />} Yes, reopen
              </button>
              <button onClick={() => setSure(false)} className="rounded-lg px-2 py-1.5 text-ink-3 hover:text-ink">Cancel</button>
            </>
          )}
          {reopen.isError && <p className="w-full text-xs" style={{ color: statusColor.critical }}>{(reopen.error as Error).message}</p>}
        </div>
      )}
    </Card>
  )
}

type Moment = { label: string; at: string | null; note?: string; who: 'defender' | 'agent' | 'person' }
const MOMENT_DOT: Record<Moment['who'], string> = { defender: 'bg-rose', agent: 'bg-blue', person: 'bg-[#16a34a]' }

/** Everything that happened to the incident, oldest first: Defender's events, the agent's verdict and actions,
 *  analysts' decisions and reopens, and Defender's latest change when nothing here explains it. */
function moments(c: TriageCase): Moment[] {
  const p = c.packet
  const list: Moment[] = [
    { label: 'Activity started', at: iso(p.first_activity), who: 'defender' },
    { label: 'Defender raised it', at: iso(p.created_at), who: 'defender' },
    { label: 'Agent verdict ready', at: iso(c.triaged_at), note: `Agent said: ${verdictMeta(c.verdict.verdict).label}`, who: 'agent' },
  ]
  for (const a of c.actions) {
    if (a.status !== 'done' && a.status !== 'failed') continue
    const at = iso(a.done_at ?? a.requested_at)
    if (a.action === 'close_incident' || a.action === 'escalate_incident') {
      // "resolved / falsePositive / notMalicious by Lavanya" (Alert Triage close.act)
      const [head, by] = (a.detail ?? '').split(' by ')
      const [status, cls, det] = head.split(' / ')
      list.push({
        label: `Decided by ${by?.trim() || 'an analyst'}: ${CLASSIFICATION_WORDS[cls] ?? cls ?? ''}${a.status === 'failed' ? ' (not saved)' : ''}`,
        at, who: 'person',
        note: a.status === 'failed' ? a.detail : `${isClosed(status) ? 'Closed' : 'Kept open'} in Defender${det ? ` · ${DETERMINATION_WORDS[det] ?? det}` : ''}`,
      })
    } else if (a.action === 'reopen') {
      list.push({ label: 'Reopened in Defender', at, who: 'person', note: a.detail?.split(':').slice(1).join(':').trim() || undefined })
    } else {
      list.push({ label: `${ACTION_WORDS[a.action] ?? a.action}${a.status === 'failed' ? ' (failed)' : ''}`, at, who: 'agent',
        note: a.detail ? a.detail.split(' -> ')[0] : undefined })
    }
  }
  // Defender's newest change, when it is later than everything above (an analyst working in Defender)
  const st = c.defender_state
  const changed = iso(st.updated_at)
  const latest = list.reduce((m, x) => (x.at && x.at > m ? x.at : m), '')
  if (changed && changed > latest) {
    const cls = st.classification && st.classification !== 'unknown' ? CLASSIFICATION_WORDS[st.classification] ?? st.classification : 'Not classified'
    list.push({ label: 'Last updated in Defender', at: changed, who: 'defender', note: `${cls} · ${isClosed(st.status) ? 'closed' : 'open'}` })
  }
  return list.sort((x, y) => (x.at ?? '').localeCompare(y.at ?? ''))
}

function Timeline({ c }: { c: TriageCase }) {
  const rows = moments(c)
  return (
    <Card title="Timeline" description="Newest at the bottom. Updated after every check of Defender and every decision.">
      <ol className="relative flex flex-col gap-4 border-l border-hairline pl-4">
        {rows.map((m, i) => (
          <li key={i} className="relative">
            <span className={cn('absolute -left-[21px] top-1.5 size-2.5 rounded-full border-2 border-panel', MOMENT_DOT[m.who])} />
            <div className="text-sm font-medium">{m.label}</div>
            <div className="text-xs text-ink-3">{m.at ? dateTime(m.at) : '–'}{m.note ? ` · ${m.note}` : ''}</div>
          </li>
        ))}
      </ol>
      <div className="mt-3 flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-ink-3">
        {(Object.keys(MOMENT_DOT) as Moment['who'][]).map((k) => (
          <span key={k} className="flex items-center gap-1.5"><span className={cn('size-2 rounded-full', MOMENT_DOT[k])} />{{ defender: 'Defender', agent: 'Agent', person: 'Analyst' }[k]}</span>
        ))}
      </div>
      {c.seconds != null && <p className="mt-3 text-xs text-ink-3">The agent took {Math.round(c.seconds)} s, running {c.queries.length} searches{c.ti.length ? ` and ${c.ti.length} threat-intel look-ups` : ''}.</p>}
    </Card>
  )
}

/* ───────── evidence tabs ───────── */

type ETab = 'alerts' | 'things' | 'searches' | 'background'

function EvidenceTabs({ c }: { c: TriageCase }) {
  const [tab, setTab] = useState<ETab>('alerts')
  const things = Object.entries(c.packet.entities).filter(([, list]) => list?.length)
  return (
    <Panel className="flex min-w-0 flex-col gap-4 p-6">
      <div>
        <h3 className="font-semibold tracking-tight">The evidence</h3>
        <p className="mt-1 text-sm text-ink-3">All evidence collected by the agent, exactly as returned by Defender.</p>
      </div>
      {/* the tab row scrolls sideways on a phone instead of widening the page */}
      <div className="overflow-x-auto pb-px">
        <Tabs<ETab>
          tabs={[['alerts', `Alerts · ${c.packet.alerts.length}`], ['things', `Entities · ${things.reduce((n, [, l]) => n + l.length, 0)}`], ['searches', `Searches run · ${c.queries.length}`], ['background', 'Background']]}
          value={tab}
          onChange={setTab}
        />
      </div>
      {tab === 'alerts' && (
        <ul className="flex flex-col gap-3">
          {c.packet.alerts.map((a) => (
            <li key={a.id} className="rounded-xl border border-hairline p-4">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="font-medium">{a.title}</span>
                {a.web_url && <a href={a.web_url} target="_blank" rel="noreferrer noopener" className="inline-flex items-center gap-1 text-xs text-ink-3 hover:text-ink">Defender <ExternalLink className="size-3" /></a>}
              </div>
              <div className="mt-1 flex flex-wrap gap-1.5">
                <Tag>{a.severity}</Tag><Tag>{a.category}</Tag><Tag>{sourceNames(a.detection_source)}</Tag>
                {a.threat_family && <Tag>{a.threat_family}</Tag>}
                {a.techniques.map((t) => <Tag key={t}>{t}</Tag>)}
              </div>
              <div className="mt-2 text-xs text-ink-3">First activity {dateTime(iso(a.first_activity))} · raised {dateTime(iso(a.created))}</div>
              {a.untrusted?.description && (
                <details className="mt-3 rounded-lg bg-well p-3 text-xs">
                  <summary className="cursor-pointer font-medium text-ink-2">Alert description (untrusted input)</summary>
                  <p className="mt-2 whitespace-pre-line leading-relaxed text-ink-3">{a.untrusted.description}</p>
                </details>
              )}
            </li>
          ))}
        </ul>
      )}
      {tab === 'things' && (things.length ? (
        <div className="flex flex-col gap-4">
          {things.map(([kind, list]) => (
            <div key={kind}>
              <div className="mb-1.5 text-[13px] font-semibold text-ink-2">{kind}</div>
              <ul className="flex flex-col gap-1.5">
                {list.map((e, i) => <EntityRow key={i} e={e} />)}
              </ul>
            </div>
          ))}
        </div>
      ) : <Empty text="No devices, accounts or files listed." />)}
      {tab === 'searches' && (
        <div className="flex flex-col gap-2">
          {c.queries.map((q) => <QueryBlock key={q.id} q={q} />)}
          {c.ti.length > 0 && (
            <div className="mt-2">
              <div className="mb-1.5 text-[13px] font-semibold text-ink-2">Threat intelligence</div>
              <ul className="flex flex-col gap-1.5 text-sm">
                {c.ti.map((t) => <li key={t.indicator} className="rounded-lg bg-well px-3 py-2"><b className="font-medium">{t.verdict}</b> · {t.type} <code className="break-all text-xs text-ink-3">{t.indicator}</code>{t.detail && <span className="block text-xs text-ink-3">{t.detail}</span>}</li>)}
              </ul>
            </div>
          )}
        </div>
      )}
      {tab === 'background' && <Background c={c} />}
    </Panel>
  )
}

function EntityRow({ e }: { e: Record<string, unknown> }) {
  const name = String(e.name ?? e.upn ?? e.address ?? e.url ?? e.domain ?? e.sha256 ?? e.id ?? '–')
  const extra = Object.entries(e).filter(([k, v]) => !['name', 'id', 'untrusted', 'roles'].includes(k) && v !== '' && v != null && !(Array.isArray(v) && !v.length)).slice(0, 5)
  return (
    <li className="rounded-lg border border-hairline px-3 py-2 text-sm">
      <span className="break-all font-medium">{name}</span>
      {e.untrusted === true && <span className="ml-2 text-[11px] text-ink-3">(name from the attacker side, not trusted)</span>}
      <span className="mt-0.5 flex flex-wrap gap-x-3 gap-y-0.5 text-xs text-ink-3">
        {extra.map(([k, v]) => <span key={k} className="break-all">{k}: <span className="text-ink-2">{String(v)}</span></span>)}
      </span>
    </li>
  )
}

function QueryBlock({ q }: { q: TriageCase['queries'][number] }) {
  const cols = q.rows.length ? Object.keys(q.rows[0]).slice(0, 7) : []
  const ok = q.status === 'ok'
  return (
    <details className="rounded-xl border border-hairline">
      <summary className="flex cursor-pointer flex-wrap items-center gap-2 px-4 py-3 text-sm">
        <span className="size-2 rounded-full" style={{ background: ok ? statusColor.good : statusColor.warning }} />
        <span className="font-medium capitalize">{pretty(q.id)}</span>
        <span className="text-xs text-ink-3">{ok ? `${q.row_count} row${q.row_count === 1 ? '' : 's'} found` : q.status}</span>
      </summary>
      <div className="border-t border-hairline p-3">
        {q.rows.length ? (
          <div className="overflow-auto rounded-lg border border-hairline" style={{ maxHeight: 320 }}>
            <table className="w-full text-xs" style={{ minWidth: 640 }}>
              <thead className="sticky top-0 bg-well text-ink-3"><tr>{cols.map((k) => <th key={k} className="whitespace-nowrap px-2.5 py-2 text-left font-medium">{k}</th>)}</tr></thead>
              <tbody className="[&_tr]:border-t [&_tr]:border-hairline">
                {q.rows.map((r, i) => (
                  <tr key={i}>{cols.map((k) => <td key={k} className="max-w-[260px] truncate px-2.5 py-1.5 align-top text-ink-2" title={String(r[k] ?? '')}>{k === 'Timestamp' ? dateTime(String(r[k])) : String(r[k] ?? '')}</td>)}</tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : <p className="text-sm text-ink-3">{q.error ?? 'No results returned.'}</p>}
        {q.rows_total < q.row_count && <p className="mt-2 text-xs text-ink-3">Showing the {q.rows_total} rows the agent kept of {q.row_count}.</p>}
        {q.query && <details className="mt-2 text-xs"><summary className="cursor-pointer text-ink-3">The search (KQL)</summary><pre className="mt-1 overflow-auto rounded-lg bg-well p-3 text-[11px] leading-relaxed">{q.query}</pre></details>}
      </div>
    </details>
  )
}

function Background({ c }: { c: TriageCase }) {
  const devices = c.context.devices ?? []
  return (
    <div className="flex flex-col gap-4 text-sm">
      {devices.map((d) => (
        <div key={d.name} className="rounded-xl border border-hairline p-4">
          <div className="font-medium">{d.name}</div>
          <div className="mt-1 flex flex-wrap gap-x-4 gap-y-1 text-xs text-ink-3">
            {[['OS', d.os], ['Defender risk', d.risk], ['Exposure', d.exposure], ['Health', d.health], ['Admin account involved', d.admin_account ? 'yes' : 'no']].map(([k, v]) => v && <span key={k}>{k}: <span className="text-ink-2">{v}</span></span>)}
          </div>
        </div>
      ))}
      <div className="rounded-xl bg-well p-4">
        <div className="font-medium">History</div>
        <p className="mt-1 text-ink-2">{c.history.note ?? 'No history recorded.'}</p>
      </div>
      <div className="rounded-xl bg-well p-4">
        <div className="font-medium">Watchlists</div>
        <p className="mt-1 text-ink-2">{Object.keys(c.context.watchlist_hits ?? {}).length ? Object.keys(c.context.watchlist_hits ?? {}).join(', ') : 'Not on any watchlist (privileged accounts, approved admin tools, VIPs).'}</p>
      </div>
    </div>
  )
}
