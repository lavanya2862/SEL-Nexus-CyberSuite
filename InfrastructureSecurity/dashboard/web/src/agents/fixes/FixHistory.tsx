import { useMemo, useState } from 'react'
import { ChevronDown, ShieldCheck } from 'lucide-react'
import { Card, DTable, DateFilter, Empty, FilterBar, FilterSearch, Panel, SevTag, Tag, dateChip, inDateRange, type DateRange } from '@/components/kit'
import { isSetting, useFix } from '@/agents/fixes/data'
import { FixRegister } from '@/agents/fixes/FixRegister'
import { useFilters } from '@/lib/filters'
import { num, shortDate } from '@/lib/format'
import { statusColor } from '@/lib/theme'
import { cn } from '@/lib/utils'
import { groupBy, pretty, sumBy, useFixedFindings, useGroupAfter, useVulnData, type FixedFinding } from '@/agents/vulnerability/data'
import { VulnLoading } from '@/agents/vulnerability/common'

// the fix engine writes UTC times without a zone
const keyOf = (device: string, sw: string, ver: string) => `${device}|${sw}|${ver}`.toLowerCase()

/** Fix › Fixed history: what the portal fixed (with the computer's own output) and everything Defender reported fixed. */
export function FixHistory() {
  const { data, error, isLoading } = useVulnData()
  const fix = useFix()
  const { opco } = useFilters()
  const fixed = useFixedFindings(data)

  const runs = useMemo(
    () => (fix.data?.rows ?? [])
      .filter((r) => r.started_at && (opco === 'all' || r.opco === opco))
      .sort((a, b) => (b.finished_at ?? b.started_at ?? '').localeCompare(a.finished_at ?? a.started_at ?? '')),
    [fix.data, opco],
  )
  const portalKeys = useMemo(() => new Set(runs.filter((r) => r.status === 'verified').map((r) => keyOf(r.device_name, r.software_name, r.version))), [runs])

  if (isLoading || error || !data) return <VulnLoading error={error} />
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
          <span className="text-sm text-ink-3">vulnerabilities remediated<br />{first ? `since ${shortDate(first)}` : ''}</span>
        </div>
        <div className="text-sm text-ink-2 text-justify">
          <p>
            <b>{num(byPortal)}</b> of them were remediated by CyberSuite ({num(runs.filter((r) => r.status === 'verified' && !isSetting(r)).length)} app updates), and Defender confirmed each one.
            The other <b>{num(fixed.length - byPortal)}</b> were resolved outside the portal, for example through automatic application updates or manual patching.
          </p>
          <p className="mt-1.5 text-xs text-ink-3">
            {avgDays != null && <>On average a vulnerability was open {avgDays.toFixed(1)} days before it was remediated. </>}
            Source: Microsoft Defender’s change feed. A vulnerability counts as remediated when Defender stops finding it on that device.
          </p>
        </div>
      </Panel>

      {fix.isLoading ? <div className="h-24 animate-pulse rounded-xl bg-well" />
        : fix.data ? <FixRegister rows={fix.data.rows} opco={opco} />
        : <Empty text="Automated remediation is disabled, so remediations executed by CyberSuite cannot be shown." />}

      <DefenderLog fixed={fixed} portalKeys={portalKeys} />
    </div>
  )
}

/* ───────── Defender's fixed list, day by day ───────── */

function DefenderLog({ fixed, portalKeys }: { fixed: FixedFinding[]; portalKeys: Set<string> }) {
  const [q, setQ] = useState('')
  const [when, setWhen] = useState<DateRange>({ preset: 'any' })
  const ql = q.trim().toLowerCase()
  const shown = fixed.filter((f) => (!ql || [f.cve, f.sw, pretty(f.sw), f.ver, f.dev?.name, f.o].some((s) => (s ?? '').toLowerCase().includes(ql)))
    && inDateRange(f.fixed ? new Date(`${f.fixed.slice(0, 10)}T12:00:00`) : null, when))
  const days = Object.entries(groupBy(shown, (f) => f.fixed)).sort((a, b) => b[0].localeCompare(a[0]))
  return (
    <Card
      title="All findings Defender reported as resolved, by day"
      description="Grouped by application and device. Expand a group to view each vulnerability."
    >
      <FilterBar className="mb-4" chips={[...(q ? [{ key: 'q', label: `“${q}”`, onRemove: () => setQ('') }] : []), ...dateChip(when, () => setWhen({ preset: 'any' }))]}
        onClear={() => { setQ(''); setWhen({ preset: 'any' }) }} count={`${num(shown.length)} remediated`}>
        <FilterSearch value={q} onChange={setQ} placeholder="CVE, app or device" />
        <DateFilter label="Remediated" value={when} onChange={setWhen} />
      </FilterBar>
      {days.length ? (
        <div className="flex flex-col gap-5">
          {days.map(([day, fs]) => {
            const groups = Object.entries(groupBy(fs, (f) => keyOf(f.dev?.name ?? '', f.sw, f.ver))).sort((a, b) => b[1].length - a[1].length)
            return (
              <section key={day}>
                <div className="mb-2 flex items-baseline gap-2">
                  <h3 className="font-semibold">{new Date(day).toLocaleDateString('en-GB', { weekday: 'short', day: 'numeric', month: 'short' })}</h3>
                  <span className="text-sm text-ink-3">{num(fs.length)} vulnerabilities remediated</span>
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
        {byPortal && <Tag><ShieldCheck className="mr-1 inline size-3" />remediated by CyberSuite</Tag>}
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
