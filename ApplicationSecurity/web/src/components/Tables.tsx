// The two tables several pages share: scans, and findings (with filters).
import { useMemo, useState, type ReactNode } from 'react'
import { useNavigate } from 'react-router-dom'
import { ExternalLink } from 'lucide-react'
import { DTable, Empty, FixStatusTag, JobStatusTag, RiskScore, Search, Select, SevTag, StatusTag, VerdictTag } from '@/components/kit'
import { ago } from '@/lib/format'
import { FINDING_TYPES, FIX_STATUS, SEVERITIES, detectedBy, findingType, sevLabel, where } from '@/lib/labels'
import { usePanels } from '@/lib/panels'
import type { Finding, Job } from '@/lib/types'

export function RunsTable({ items, empty = 'No scans yet.' }: { items: Job[]; empty?: string }) {
  const navigate = useNavigate()
  if (!items.length) return <Empty text={empty} />
  return (
    <DTable head={[['Repository'], ['Status'], ['Step'], ['Findings', 'right'], ['Fixes', 'right'], ['Validation'], ['Pull request'], ['Started']]} minWidth={900}>
      {items.map((j) => {
        const s = j.summary ?? {}
        return (
          <tr key={j.id} className="cursor-pointer hover:bg-well/60" onClick={(e) => { if (!(e.target as HTMLElement).closest('a')) navigate(`/runs/${j.id}`) }}>
            <td><div className="font-medium">{j.repo}</div>{j.ref && <div className="font-mono text-xs text-ink-3">{j.ref}</div>}</td>
            <td><JobStatusTag job={j} /></td>
            <td className="text-xs text-ink-2">{j.status === 'running' ? `${j.stage} · ${j.progress}%` : j.status === 'completed' ? 'done' : j.stage}</td>
            <td className="tabular text-right">
              {s.findings ?? '–'}
              {s.severity_counts && <div className="text-xs text-ink-3">{s.severity_counts.critical ?? 0} crit · {s.severity_counts.high ?? 0} high</div>}
            </td>
            <td className="tabular text-right">{s.fixes_applied ?? '–'}{s.verified_fixed != null && <div className="text-xs text-ink-3">{s.verified_fixed} confirmed</div>}</td>
            <td><VerdictTag v={s.validation_status} /></td>
            <td>
              {s.pull_request_url ? (
                <a href={s.pull_request_url} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-sky hover:underline">{s.pull_request_draft ? 'Draft PR' : 'Open PR'} <ExternalLink className="size-3" /></a>
              ) : s.approval_status === 'awaiting_approval' ? <StatusTag tone="warn" label="Awaiting approval" /> : <span className="text-ink-3">–</span>}
            </td>
            <td className="whitespace-nowrap text-xs text-ink-3">{ago(j.created_at)}</td>
          </tr>
        )
      })}
    </DTable>
  )
}

type Filters = { repo: string; sev: string; type: string; status: string; scanner: string; q: string }

/** Findings with filters (severity, type, fix status, scanner, text). Click a row for the full details. */
export function FindingsTable({ items, jobId, showRepo, extra }: { items: Finding[]; jobId?: string; showRepo?: boolean; extra?: ReactNode }) {
  const { openFinding } = usePanels()
  const [f, setF] = useState<Filters>({ repo: '', sev: '', type: '', status: '', scanner: '', q: '' })
  const set = (k: keyof Filters) => (v: string) => setF((x) => ({ ...x, [k]: v }))
  const repos = useMemo(() => [...new Set(items.map((x) => x.repo ?? ''))].filter(Boolean).sort(), [items])
  const scanners = useMemo(() => [...new Set(items.flatMap((x) => [x.scanner, ...(x.also_reported_by ?? [])]))].sort(), [items])
  const q = f.q.toLowerCase()
  const rows = items.filter((x) => (!f.repo || x.repo === f.repo) && (!f.sev || x.severity === f.sev) && (!f.type || findingType(x) === f.type)
    && (!f.status || x.fix_status === f.status) && (!f.scanner || [x.scanner, ...(x.also_reported_by ?? [])].includes(f.scanner))
    && (!q || [x.title, x.file_path, x.package_name, x.rule_id, x.advisory_id, ...(x.aliases ?? []), x.category].join(' ').toLowerCase().includes(q)))
  const shown = rows.slice(0, 400)

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center gap-2">
        {showRepo && repos.length > 1 && (
          <Select label="Repository" value={f.repo} onChange={set('repo')}><option value="">All repositories</option>{repos.map((r) => <option key={r} value={r}>{r}</option>)}</Select>
        )}
        <Select label="Severity" value={f.sev} onChange={set('sev')}><option value="">All severities</option>{SEVERITIES.map((s) => <option key={s} value={s}>{sevLabel(s)}</option>)}</Select>
        <Select label="Type" value={f.type} onChange={set('type')}><option value="">All types</option>{FINDING_TYPES.map(([k, l]) => <option key={k} value={k}>{l}</option>)}</Select>
        <Select label="Fix status" value={f.status} onChange={set('status')}><option value="">Any fix status</option>{Object.entries(FIX_STATUS).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}</Select>
        <Select label="Scanner" value={f.scanner} onChange={set('scanner')}><option value="">All scanners</option>{scanners.map((s) => <option key={s} value={s}>{s}</option>)}</Select>
        <Search value={f.q} onChange={set('q')} placeholder="Search title, file, package, CVE…" />
        {extra}
      </div>
      {rows.length ? (
        <>
          <DTable head={[['#'], ['Risk'], ['Severity'], ['Finding'], ...(showRepo ? [['Repository'] as [string]] : []), ['Where'], ['Found by'], ['Fix']]} minWidth={showRepo ? 1040 : 920} maxHeight={720}>
            {shown.map((x) => (
              <tr key={`${x.job_id ?? jobId}:${x.finding_id}`} className="cursor-pointer hover:bg-well/60" onClick={() => openFinding(x.job_id ?? jobId!, x.finding_id)}>
                <td className="tabular text-ink-3">{x.priority_rank ?? ''}</td>
                <td><RiskScore score={x.priority_score} /></td>
                <td><SevTag sev={x.severity} /></td>
                <td className="max-w-[420px]">
                  <div className="font-medium leading-snug">{x.title}</div>
                  <div className="text-xs text-ink-3">{FINDING_TYPES.find(([k]) => k === findingType(x))?.[1]} · {x.category.replace(/_/g, ' ')}{x.advisory_id ? ` · ${x.advisory_id}` : x.rule_id ? ` · ${x.rule_id}` : ''}</div>
                  {x.package_name && <div className="font-mono text-xs text-ink-2">{x.package_name}@{x.installed_version} {x.fixed_version ? `→ ${x.fixed_version}` : <span className="text-ink-3">(no fix yet)</span>}</div>}
                </td>
                {showRepo && <td className="text-xs text-ink-2">{x.repo}</td>}
                <td className="min-w-[160px] max-w-[280px] font-mono text-xs text-ink-2 [overflow-wrap:anywhere]">{where(x)}</td>
                <td className="text-xs text-ink-2">{detectedBy(x)}</td>
                <td><FixStatusTag s={x.fix_status} /></td>
              </tr>
            ))}
          </DTable>
          <p className="text-xs text-ink-3">{rows.length > 400 ? `Showing 400 of ${rows.length}. ` : `${rows.length} of ${items.length} findings. `}Click a row for the full details, the code and the fix.</p>
        </>
      ) : <Empty text={items.length ? 'No findings match the filters.' : 'No findings: the repository is clean.'} />}
    </div>
  )
}
