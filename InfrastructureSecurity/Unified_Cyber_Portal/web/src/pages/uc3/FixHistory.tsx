import { useMemo, useState } from 'react'
import { CheckCircle2, ChevronDown, Search, ShieldCheck, Terminal } from 'lucide-react'
import { StatusPill } from '@/components/FixLoop'
import { Card, DTable, Empty, Panel, SevTag, Tag } from '@/components/kit'
import { METHOD_LABEL, isSetting, useFix, versionOf, type FixRow } from '@/lib/fix'
import { useFilters } from '@/lib/filters'
import { dateTime, num, shortDate } from '@/lib/format'
import { statusColor } from '@/lib/theme'
import { cn } from '@/lib/utils'
import { groupBy, pretty, sumBy, useFixedFindings, useGroupAfter, useUc3Data, type FixedFinding } from '@/lib/uc3'
import { Uc3Loading } from './common'

// the fix engine writes UTC times without a zone
const utc = (s: string | null | undefined) => (s ? s.replace(' ', 'T') + (s.endsWith('Z') || s.includes('+') ? '' : 'Z') : null)
const keyOf = (device: string, sw: string, ver: string) => `${device}|${sw}|${ver}`.toLowerCase()

/** Fix › Fixed history: what the portal fixed (with the computer's own output) and everything Defender reported fixed. */
export function FixHistory() {
  const { data, error, isLoading } = useUc3Data()
  const fix = useFix()
  const { opco } = useFilters()
  const fixed = useFixedFindings(data)

  const runs = useMemo(
    () => (fix.data?.rows ?? [])
      .filter((r) => r.started_at && (opco === 'all' || r.opco === opco))
      .sort((a, b) => (b.finished_at ?? b.started_at ?? '').localeCompare(a.finished_at ?? a.started_at ?? '')),
    [fix.data, opco],
  )
  // Defender's fixed rows per (computer, app, version): links a portal fix to what Defender then stopped reporting
  const byApp = useMemo(() => groupBy(fixed, (f) => keyOf(f.dev?.name ?? '', f.sw, f.ver)), [fixed])
  const portalKeys = useMemo(() => new Set(runs.filter((r) => r.status === 'verified').map((r) => keyOf(r.device_name, r.software_name, r.version))), [runs])

  if (isLoading || error || !data) return <Uc3Loading error={error} />
  if (!data.fixed) return <Empty text="Remediation history will appear after the next Vulnerability Agent run." />

  const byPortal = fixed.filter((f) => portalKeys.has(keyOf(f.dev?.name ?? '', f.sw, f.ver))).length
  const first = fixed.map((f) => f.fixed).sort()[0]
  const withDays = fixed.filter((f) => f.days != null)
  const avgDays = withDays.length ? sumBy(withDays, (f) => f.days ?? 0) / withDays.length : null

  return (
    <div className="flex flex-col gap-5">
      <Panel className="grid gap-6 p-6 md:grid-cols-[auto_minmax(0,1fr)] md:items-center">
        <div className="flex items-baseline gap-3">
          <span className="tabular text-[40px] leading-none tracking-tight" style={{ color: statusColor.good }}>{num(fixed.length)}</span>
          <span className="text-sm text-ink-3">vulnerabilities fixed<br />{first ? `since ${shortDate(first)}` : ''}</span>
        </div>
        <div className="text-sm text-ink-2">
          <p>
            <b>{num(byPortal)}</b> of them were fixed by Cyber Command ({num(runs.filter((r) => r.status === 'verified' && !isSetting(r)).length)} app updates), and Defender confirmed each one.
            The other <b>{num(fixed.length - byPortal)}</b> were resolved outside the portal, for example through automatic application updates or manual patching.
          </p>
          <p className="mt-1.5 text-xs text-ink-3">
            {avgDays != null && <>On average a vulnerability was open {avgDays.toFixed(1)} days before it was fixed. </>}
            Source: Microsoft Defender’s change feed. A vulnerability counts as fixed when Defender stops finding it on that computer.
          </p>
        </div>
      </Panel>

      <Card title="Remediations executed by the portal" description="Each remediation executed by the portal: approver, device response and Defender verification">
        {fix.isLoading ? <div className="h-24 animate-pulse rounded-xl bg-well" />
          : runs.length ? <div className="flex flex-col gap-3">{runs.map((r) => <RunCard key={r.fix_id} r={r} cleared={byApp[keyOf(r.device_name, r.software_name, r.version)]?.length ?? 0} events={fix.data?.events ?? []} />)}</div>
          : <Empty text={fix.error ? 'Automated remediation is disabled, so portal-executed remediations cannot be shown.' : 'No remediations have been executed by the portal yet.'} />}
      </Card>

      <DefenderLog fixed={fixed} portalKeys={portalKeys} />
    </div>
  )
}

/* ───────── one portal fix: approved → ran → computer's answer → Defender confirms ───────── */

function RunCard({ r, cleared, events }: { r: FixRow; cleared: number; events: { at: string; fix_id: string | null; text: string }[] }) {
  const [open, setOpen] = useState(false)
  const res = r.result
  const setting = isSetting(r)
  const before = setting ? '' : versionOf(res?.before) ?? r.version
  const after = setting ? undefined : versionOf(res?.after)
  const what = setting ? 'Changed setting:' : r.action === 'respond' ? 'Scanned and cleaned after:' : r.action === 'remove' ? 'Removed' : r.action === 'replace' ? 'Replaced' : 'Updated'
  const mine = events.filter((e) => e.fix_id === r.fix_id).sort((a, b) => a.at.localeCompare(b.at))
  const steps: [string, string | null, React.ReactNode][] = [
    ['Approved', r.approved_at, <>by {r.approved_by ?? 'someone'}{r.method ? ` · ${METHOD_LABEL[r.method]}` : ''}</>],
    ['Executed on device', r.started_at, <>{r.device_name}</>],
    ['Device response', r.finished_at, r.message ?? (r.status === 'failed' ? 'Remediation failed' : '')],
    ['Defender confirmed', r.verified_at, r.verified_at
      ? setting ? <>Defender no longer lists this setting as wrong</> : <>No longer listed as vulnerable{cleared ? <>: <b>{num(cleared)} vulnerabilities</b> cleared</> : ''}</>
      : r.status === 'still_there' ? 'Defender still lists it' : setting ? 'Waiting for Defender’s next settings check (usually within a day)' : 'Waiting for Defender’s next scan (2–6 hours)'],
  ]
  return (
    <div className="rounded-xl border border-hairline">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2 px-4 py-3">
        <CheckCircle2 className="size-5 shrink-0" style={{ color: r.status === 'verified' ? statusColor.good : r.status === 'failed' ? statusColor.critical : 'var(--ink-3)' }} />
        <div className="min-w-0 flex-1">
          <div className="font-medium">
            {what} {r.app} <span className="tabular text-ink-3">{before}</span>{after && <> → <span className="tabular">{after}</span></>}
          </div>
          <div className="text-xs text-ink-3">{r.device_name} · {dateTime(utc(r.finished_at ?? r.started_at))}</div>
        </div>
        <StatusPill r={r} />
      </div>
      <ol className="grid gap-px border-t border-hairline bg-hairline sm:grid-cols-4">
        {steps.map(([label, at, text]) => (
          <li key={label} className="bg-panel px-4 py-3">
            <div className={cn('text-xs font-semibold', at ? 'text-ink' : 'text-ink-3')}>{at ? '✓ ' : ''}{label}</div>
            <div className="tabular text-[11px] text-ink-3">{at ? dateTime(utc(at)) : '–'}</div>
            <div className="mt-1 text-xs leading-relaxed text-ink-2">{text}</div>
          </li>
        ))}
      </ol>
      {(res?.log?.length || mine.length > 0) && (
        <div className="border-t border-hairline px-4 py-2.5">
          <button onClick={() => setOpen(!open)} className="flex items-center gap-1.5 text-xs font-medium text-ink-2 hover:text-ink" aria-expanded={open}>
            <Terminal className="size-3.5" /> {open ? 'Hide' : 'Show'} the full record
            <ChevronDown className={cn('size-3.5 transition-transform', open && 'rotate-180')} />
          </button>
          {open && (
            <div className="mt-2.5 grid gap-3 lg:grid-cols-2 animate-in fade-in duration-200">
              {res?.log?.length ? (
                <div>
                  <div className="mb-1 text-xs font-semibold text-ink-2">Command output</div>
                  <pre className="overflow-x-auto rounded-lg bg-well p-3 font-mono text-[11px] leading-relaxed text-ink-2">
                    {res.log.join('\n')}{res.exit != null ? `\n(exit code ${res.exit}${res.reboot ? ', restart needed' : ''})` : ''}
                  </pre>
                </div>
              ) : null}
              {mine.length > 0 && (
                <div>
                  <div className="mb-1 text-xs font-semibold text-ink-2">Timeline</div>
                  <ul className="space-y-1 text-xs text-ink-2">
                    {mine.map((e, i) => <li key={i}><span className="tabular text-ink-3">{dateTime(utc(e.at))}</span> · {e.text}</li>)}
                  </ul>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

/* ───────── Defender's fixed list, day by day ───────── */

function DefenderLog({ fixed, portalKeys }: { fixed: FixedFinding[]; portalKeys: Set<string> }) {
  const [q, setQ] = useState('')
  const ql = q.trim().toLowerCase()
  const shown = ql ? fixed.filter((f) => [f.cve, f.sw, pretty(f.sw), f.ver, f.dev?.name, f.o].some((s) => (s ?? '').toLowerCase().includes(ql))) : fixed
  const days = Object.entries(groupBy(shown, (f) => f.fixed)).sort((a, b) => b[0].localeCompare(a[0]))
  return (
    <Card
      title="All findings Defender reported as resolved, by day"
      description="Grouped by application and device. Expand a group to view each vulnerability."
      action={
        <label className="flex items-center gap-2 rounded-lg border border-hairline-strong bg-field px-3 py-1.5 text-sm transition-[border-color,box-shadow] focus-within:border-blue/60 focus-within:ring-3 focus-within:ring-blue/15">
          <Search className="size-3.5 text-ink-3" />
          <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="CVE, app or computer" className="w-44 bg-transparent outline-none placeholder:text-ink-3" />
        </label>
      }
    >
      {days.length ? (
        <div className="flex flex-col gap-5">
          {days.map(([day, fs]) => {
            const groups = Object.entries(groupBy(fs, (f) => keyOf(f.dev?.name ?? '', f.sw, f.ver))).sort((a, b) => b[1].length - a[1].length)
            return (
              <section key={day}>
                <div className="mb-2 flex items-baseline gap-2">
                  <h3 className="font-semibold">{new Date(day).toLocaleDateString('en-GB', { weekday: 'short', day: 'numeric', month: 'short' })}</h3>
                  <span className="text-sm text-ink-3">{num(fs.length)} vulnerabilities fixed</span>
                </div>
                <div className="flex flex-col gap-2">
                  {groups.map(([k, g]) => <FixedGroup key={k} rows={g} byPortal={portalKeys.has(k)} />)}
                </div>
              </section>
            )
          })}
        </div>
      ) : <Empty text={ql ? 'No remediated items match.' : 'Defender has not reported any resolved findings yet.'} />}
    </Card>
  )
}

function FixedGroup({ rows, byPortal }: { rows: FixedFinding[]; byPortal: boolean }) {
  const [open, setOpen] = useState(false)
  const [limit, setLimit] = useState(50)
  const groupAfter = useGroupAfter()
  const f = rows[0]
  const crit = rows.filter((x) => x.sev === 'Critical').length
  return (
    <div className="rounded-xl border border-hairline">
      <button onClick={() => setOpen(!open)} className="flex w-full flex-wrap items-center gap-x-3 gap-y-1 px-4 py-2.5 text-left hover:bg-well/60" aria-expanded={open}>
        <span className="font-medium">{pretty(f.sw)} <span className="tabular font-normal text-ink-3">{f.ver}</span></span>
        <span className="text-sm text-ink-3">on {f.dev?.name}{groupAfter(f)}</span>
        {byPortal && <Tag><ShieldCheck className="mr-1 inline size-3" />fixed by Cyber Command</Tag>}
        <span className="ml-auto flex items-center gap-3 text-sm">
          {crit > 0 && <span className="text-xs text-ink-3">{num(crit)} critical</span>}
          <b className="tabular">{num(rows.length)}</b>
          <ChevronDown className={cn('size-4 text-ink-3 transition-transform', open && 'rotate-180')} />
        </span>
      </button>
      {open && (
        <div className="border-t border-hairline p-3 animate-in fade-in duration-200">
          <DTable head={[['Vulnerability'], ['Severity'], ['First seen'], ['Days open', 'right']]} minWidth={420} maxHeight={360}>
            {rows.slice(0, limit).map((x) => (
              <tr key={x.cve}>
                <td className="tabular whitespace-nowrap font-medium">{x.cve}</td>
                <td><SevTag sev={x.sev} /></td>
                <td className="tabular whitespace-nowrap text-ink-3">{x.fs ? shortDate(x.fs) : '–'}</td>
                <td className="tabular text-right">{x.days ?? '–'}</td>
              </tr>
            ))}
          </DTable>
          {limit < rows.length && (
            <button onClick={() => setLimit(limit + 200)} className="mt-2 rounded-lg border border-hairline px-3 py-1.5 text-xs font-medium hover:bg-well">
              Show more ({num(rows.length - limit)} left)
            </button>
          )}
        </div>
      )}
    </div>
  )
}
