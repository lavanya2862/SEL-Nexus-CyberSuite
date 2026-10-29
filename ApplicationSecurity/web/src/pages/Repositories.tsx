import { Link, useNavigate } from 'react-router-dom'
import { ExternalLink, RefreshCw } from 'lucide-react'
import { Btn, DTable, Empty, ErrorBox, JobStatusTag, LinkBtn, Loading, PageHeader, Panel, StatusTag, VerdictTag } from '@/components/kit'
import { post, useCaps, useRepositories } from '@/lib/api'
import { ago } from '@/lib/format'
import { useToast } from '@/lib/toast'
import type { Job } from '@/lib/types'
import { useState } from 'react'

export function Repositories() {
  const repos = useRepositories()
  const caps = useCaps()
  const navigate = useNavigate()
  const toast = useToast()
  const [busy, setBusy] = useState<string | null>(null)
  if (repos.isLoading) return <Loading />
  if (repos.error || !repos.data) return <ErrorBox error={repos.error} />

  const rescan = async (url: string) => {
    setBusy(url)
    try {
      const r = await post<{ job: Job }>('/api/v1/jobs', { repo_url: url, options: { use_cache: false, create_pr: !!caps.data?.github_token_configured } })
      navigate(`/runs/${r.job.id}`)
    } catch (e) {
      toast((e as Error).message, true)
      setBusy(null)
    }
  }

  return (
    <div className="flex flex-col gap-5">
      <PageHeader title="Repositories" description="The security posture of each scanned repository and the trend of its findings over time. Re-scan a repository to assess new code." />
      <Panel className="p-6">
        {repos.data.items.length ? (
          <DTable head={[['Repository'], ['Last scan'], ['Open findings', 'right'], ['Remediated / verified', 'right'], ['Validation'], ['Pull request'], ['Findings trend'], ['Scans', 'right'], ['']]} minWidth={1100}>
            {repos.data.items.map((r) => {
              const c = r.latest_completed
              const s = c?.summary ?? {}
              return (
                <tr key={r.repo}>
                  <td><a href={r.repo_url} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 font-medium hover:underline">{r.repo} <ExternalLink className="size-3 text-ink-3" /></a></td>
                  <td><JobStatusTag job={r.latest} /><div className="mt-1 text-xs text-ink-3">{ago(r.latest.created_at)}</div></td>
                  <td className="tabular text-right">{s.findings ?? '–'}{s.severity_counts && <div className="text-xs text-ink-3">{s.severity_counts.critical ?? 0} crit · {s.severity_counts.high ?? 0} high</div>}</td>
                  <td className="tabular text-right">{s.fixes_applied ?? '–'}{s.verified_fixed != null && ` / ${s.verified_fixed}`}</td>
                  <td><VerdictTag v={s.validation_status} /></td>
                  <td>{s.pull_request_url ? <a href={s.pull_request_url} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-sky hover:underline">{s.pull_request_draft ? 'Draft' : 'Open'} <ExternalLink className="size-3" /></a>
                    : s.fixes_applied ? <Link to="/approvals"><StatusTag tone="warn" label="Awaiting approval" /></Link> : <span className="text-ink-3">–</span>}</td>
                  <td><Sparkline values={r.history.map((h) => h.findings)} /></td>
                  <td className="tabular text-right">{r.runs}</td>
                  <td>
                    <div className="flex flex-nowrap gap-2">
                      <Btn kind="quiet" disabled={busy === r.repo_url} onClick={() => rescan(r.repo_url)}><RefreshCw className="size-3.5" /> Re-scan</Btn>
                      {c && <LinkBtn to={`/runs/${c.id}`}>Latest scan</LinkBtn>}
                    </div>
                  </td>
                </tr>
              )
            })}
          </DTable>
        ) : <Empty text="No repositories have been scanned yet."><LinkBtn to="/scan" kind="primary">Start a scan</LinkBtn></Empty>}
      </Panel>
    </div>
  )
}

function Sparkline({ values }: { values: number[] }) {
  if (values.length < 2) return <span className="text-xs text-ink-3">–</span>
  const max = Math.max(...values, 1), w = 110, h = 30
  const pts = values.map((v, i) => [Math.round((i / (values.length - 1)) * w), Math.round(h - (v / max) * (h - 4) - 2)])
  const last = pts[pts.length - 1]
  return (
    <svg viewBox={`0 0 ${w} ${h}`} width={w} height={h} role="img" aria-label={`Findings over the last ${values.length} scans: ${values.join(', ')}`}>
      <polyline points={pts.map((p) => p.join(',')).join(' ')} fill="none" stroke="var(--blue-hi)" strokeWidth={2} strokeLinejoin="round" />
      <circle cx={last[0]} cy={last[1]} r={2.5} fill="var(--blue-hi)" />
    </svg>
  )
}
