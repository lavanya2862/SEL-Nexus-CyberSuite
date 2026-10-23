import { useMemo, useState } from 'react'
import { Card, DTable, Empty, ErrorBox, HeroTile, Loading, PageHeader, Panel, RiskScore, Search, Select, SevTag, StatusTag, type Hue } from '@/components/kit'
import { useAttention } from '@/lib/api'
import { num } from '@/lib/format'
import { SEVERITIES, sevLabel } from '@/lib/labels'
import { usePanels } from '@/lib/panels'

/** The colour of each kind of reason (remediation/insights.py REASONS): who has to act. */
const REASON_HUE: Record<string, Hue> = {
  partial: 'red', reverted: 'red', secret: 'red',                                   // the code is still at risk: act first
  transitive: 'orange', no_upstream: 'orange', vendored: 'orange',                  // depends on someone else's package
  llm_quota: 'violet', llm_unavailable: 'violet', llm_rejected: 'violet', ai_off: 'violet', needs_llm: 'violet',
  ai_failed: 'violet', ai_declined: 'violet', budget: 'violet',                     // the Remediation Agent was held back
  below_threshold: 'blue', tests: 'blue',                                           // left out on purpose
}
const hueOf = (key?: string): Hue => REASON_HUE[key ?? ''] ?? 'amber'

export function FixesNeeded() {
  const att = useAttention()
  const { openFinding } = usePanels()
  const [reason, setReason] = useState('')
  const [repo, setRepo] = useState('')
  const [sev, setSev] = useState('')
  const [q, setQ] = useState('')
  const items = useMemo(() => att.data?.fixes_needed ?? [], [att.data])
  const reasons = useMemo(() => {
    const m: Record<string, { n: number; action: string; key?: string }> = {}
    items.forEach((f) => { (m[f.reason] ??= { n: 0, action: f.action, key: f.reason_key }).n++ })
    return Object.entries(m).sort((a, b) => b[1].n - a[1].n)
  }, [items])
  if (att.isLoading) return <Loading />
  if (att.error) return <ErrorBox error={att.error} />

  const repos = [...new Set(items.map((f) => f.repo))].sort()
  const ql = q.toLowerCase()
  const rows = items.filter((f) => (!reason || f.reason === reason) && (!repo || f.repo === repo) && (!sev || f.severity === sev)
    && (!ql || `${f.title} ${f.location}`.toLowerCase().includes(ql)))
  const urgent = items.filter((f) => f.severity === 'critical' || f.severity === 'high').length
  const agentHeld = items.filter((f) => hueOf(f.reason_key) === 'violet').length
  const external = items.filter((f) => hueOf(f.reason_key) === 'orange').length

  return (
    <div className="flex flex-col gap-5">
      <PageHeader title="Fixes needed" description="Vulnerabilities our agents could not fix on their own, grouped by why, with what to do about each. Pick a coloured tile to see only those." />
      {items.length ? (
        <>
          <div className="card-row gap-4 [--card-min:170px]">
            <HeroTile hue="blue" label="Need a person" value={items.length} hint={`in ${repos.length} ${repos.length === 1 ? 'repository' : 'repositories'}`} />
            <HeroTile hue="red" label="Critical or high" value={urgent} hint={`${items.length ? Math.round((urgent / items.length) * 100) : 0}% of them · fix these first`} />
            <HeroTile hue="violet" label="Remediation Agent held back" value={agentHeld} hint="Set up or re-run, and the agent fixes them" />
            <HeroTile hue="orange" label="Waiting on other packages" value={external} hint="Indirect dependencies or no patched release" />
          </div>

          <Panel className="p-5">
            <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
              <h2 className="font-semibold tracking-tight">Why they are still open</h2>
              <span className="text-xs text-ink-3">Red: still at risk · orange: depends on another package · violet: the Remediation Agent was held back · blue: left out on purpose</span>
            </div>
            <div className="mt-4 grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-3">
              {reasons.map(([label, x]) => (
                <HeroTile key={label} hue={hueOf(x.key)} label={label} value={x.n} hint={x.action}
                  onClick={() => setReason(reason === label ? '' : label)} on={reason === label} />
              ))}
            </div>
          </Panel>

          <Card title="Vulnerabilities" description="Highest risk first. Click a row for the problem, the code and what to do.">
            <div className="mb-3 flex flex-wrap items-center gap-2">
              <Select label="Repository" value={repo} onChange={setRepo}><option value="">All repositories</option>{repos.map((r) => <option key={r} value={r}>{r}</option>)}</Select>
              <Select label="Severity" value={sev} onChange={setSev}><option value="">All severities</option>{SEVERITIES.map((s) => <option key={s} value={s}>{sevLabel(s)}</option>)}</Select>
              <Search value={q} onChange={setQ} placeholder="Search vulnerability or location…" />
              {reason && <button onClick={() => setReason('')} className="rounded-full border border-hairline px-3 py-1 text-xs text-ink-2 hover:bg-well">Reason: {reason} ✕</button>}
            </div>
            {rows.length ? (
              <>
                <DTable head={[['Risk'], ['Severity'], ['Vulnerability'], ['Repository'], ['Where'], ['Why it is open'], ['What to do']]} minWidth={1100} maxHeight={720}>
                  {rows.slice(0, 400).map((f) => (
                    <tr key={`${f.job_id}:${f.finding_id}`} className="cursor-pointer hover:bg-well/60" onClick={() => openFinding(f.job_id, f.finding_id)}>
                      <td><RiskScore score={f.score} /></td>
                      <td><SevTag sev={f.severity} /></td>
                      <td className="max-w-[320px] font-medium">{f.title}</td>
                      <td className="text-xs text-ink-2">{f.repo}</td>
                      <td className="min-w-[160px] max-w-[260px] font-mono [overflow-wrap:anywhere] text-xs text-ink-2">{f.location}</td>
                      <td><StatusTag tone={hueOf(f.reason_key) === 'red' ? 'bad' : hueOf(f.reason_key) === 'blue' ? 'idle' : 'warn'} label={f.reason} /></td>
                      <td className="max-w-[300px] text-xs text-ink-2">{f.action}</td>
                    </tr>
                  ))}
                </DTable>
                <p className="mt-2 text-xs text-ink-3">{rows.length > 400 ? `Showing 400 of ${num(rows.length)}.` : `${num(rows.length)} vulnerabilit${rows.length === 1 ? 'y' : 'ies'}.`}</p>
              </>
            ) : <Empty text="No vulnerabilities match the filters." />}
          </Card>
        </>
      ) : <Empty text="Nothing left to fix: our agents fixed every selected vulnerability." />}
    </div>
  )
}
