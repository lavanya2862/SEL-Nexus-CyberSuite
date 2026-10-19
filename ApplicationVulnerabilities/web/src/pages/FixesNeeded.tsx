import { useMemo, useState, type CSSProperties } from 'react'
import { Card, DTable, Empty, ErrorBox, Loading, PageHeader, RiskScore, Search, Select, SevTag, StatusTag } from '@/components/kit'
import { useAttention } from '@/lib/api'
import { SEVERITIES, sevLabel } from '@/lib/labels'
import { usePanels } from '@/lib/panels'
import { cn } from '@/lib/utils'

export function FixesNeeded() {
  const att = useAttention()
  const { openFinding } = usePanels()
  const [reason, setReason] = useState('')
  const [repo, setRepo] = useState('')
  const [sev, setSev] = useState('')
  const [q, setQ] = useState('')
  const items = useMemo(() => att.data?.fixes_needed ?? [], [att.data])
  const reasons = useMemo(() => {
    const m: Record<string, { n: number; action: string }> = {}
    items.forEach((f) => { (m[f.reason] ??= { n: 0, action: f.action }).n++ })
    return Object.entries(m).sort((a, b) => b[1].n - a[1].n)
  }, [items])
  if (att.isLoading) return <Loading />
  if (att.error) return <ErrorBox error={att.error} />

  const repos = [...new Set(items.map((f) => f.repo))].sort()
  const ql = q.toLowerCase()
  const rows = items.filter((f) => (!reason || f.reason === reason) && (!repo || f.repo === repo) && (!sev || f.severity === sev)
    && (!ql || `${f.title} ${f.location}`.toLowerCase().includes(ql)))

  return (
    <div className="flex flex-col gap-5">
      <PageHeader title="Fixes needed" description="Issues the agents could not fix automatically, grouped by why, with what to do about each. Pick a reason to see only those issues." />
      {items.length ? (
        <>
          <section className="flex flex-col gap-3">
            <h2 className="text-lg font-semibold tracking-tight">Why they are still open</h2>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-3">
              {reasons.map(([label, x]) => (
                <button key={label} onClick={() => setReason(reason === label ? '' : label)} aria-pressed={reason === label}
                  className={cn('tint-box flex flex-col gap-1 rounded-xl p-4 text-left transition-transform hover:-translate-y-0.5', reason === label && 'ring-2 ring-blue')}
                  style={{ '--tint': 'var(--amber)' } as CSSProperties}>
                  <span className="tint-num tabular text-2xl leading-none">{x.n}</span>
                  <span className="font-semibold text-ink">{label}</span>
                  <span className="text-xs leading-relaxed text-ink-2">{x.action}</span>
                </button>
              ))}
            </div>
          </section>
          <Card title="Issues" description="Highest risk first. Click a row for the full details and the code.">
            <div className="mb-3 flex flex-wrap items-center gap-2">
              <Select label="Repository" value={repo} onChange={setRepo}><option value="">All repositories</option>{repos.map((r) => <option key={r} value={r}>{r}</option>)}</Select>
              <Select label="Severity" value={sev} onChange={setSev}><option value="">All severities</option>{SEVERITIES.map((s) => <option key={s} value={s}>{sevLabel(s)}</option>)}</Select>
              <Search value={q} onChange={setQ} placeholder="Search issue or location…" />
              {reason && <button onClick={() => setReason('')} className="rounded-full border border-hairline px-3 py-1 text-xs text-ink-2 hover:bg-well">Reason: {reason} ✕</button>}
            </div>
            {rows.length ? (
              <>
                <DTable head={[['Risk'], ['Severity'], ['Issue'], ['Repository'], ['Where'], ['Why it is open'], ['What to do']]} minWidth={1100} maxHeight={720}>
                  {rows.slice(0, 400).map((f) => (
                    <tr key={`${f.job_id}:${f.finding_id}`} className="cursor-pointer hover:bg-well/60" onClick={() => openFinding(f.job_id, f.finding_id)}>
                      <td><RiskScore score={f.score} /></td>
                      <td><SevTag sev={f.severity} /></td>
                      <td className="max-w-[320px] font-medium">{f.title}</td>
                      <td className="text-xs text-ink-2">{f.repo}</td>
                      <td className="min-w-[160px] max-w-[260px] font-mono [overflow-wrap:anywhere] text-xs text-ink-2">{f.location}</td>
                      <td><StatusTag tone="warn" label={f.reason} /></td>
                      <td className="max-w-[300px] text-xs text-ink-2">{f.action}</td>
                    </tr>
                  ))}
                </DTable>
                <p className="mt-2 text-xs text-ink-3">{rows.length > 400 ? `Showing 400 of ${rows.length}.` : `${rows.length} issue(s).`}</p>
              </>
            ) : <Empty text="No issues match the filters." />}
          </Card>
        </>
      ) : <Empty text="Nothing left to fix: every selected issue was fixed automatically." />}
    </div>
  )
}
