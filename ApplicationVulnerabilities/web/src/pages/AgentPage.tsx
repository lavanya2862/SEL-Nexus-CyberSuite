import { useState, type CSSProperties } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { ArrowRight, Download, ExternalLink } from 'lucide-react'
import { AgentPanel, AgentTile } from '@/components/Agents'
import { AgentStatusTag, Card, DTable, Empty, ErrorBox, FixStatusTag, LinkBtn, Loading, PageHeader, Panel, RiskScore, SevTag, StatusTag, VerdictTag, inputCls } from '@/components/kit'
import { PDF_FILES, TOOL_FILES, artifactUrl, isLive, useAgentHistory, useJob, useJobAgents, useJobResults, useJobs } from '@/lib/api'
import { ago } from '@/lib/format'
import { AGENTS, METHOD, detectedBy, splitFixTitle, where } from '@/lib/labels'
import { usePanels } from '@/lib/panels'
import type { AgentId, Job } from '@/lib/types'
import { cn } from '@/lib/utils'

export function AgentPage() {
  const { agent } = useParams()
  const id = agent as AgentId
  if (!(id in AGENTS)) return <Empty text="Unknown agent." />
  return <AgentView key={id} id={id} />
}

function AgentView({ id }: { id: AgentId }) {
  const meta = AGENTS[id]
  const hist = useAgentHistory(id)
  const jobs = useJobs({ limit: 40 }, 8_000)
  const navigate = useNavigate()
  const choices = (jobs.data?.items ?? []).filter((j) => j.status !== 'cancelled')
  const [picked, setPick] = useState<string>()
  // until someone picks a run: the one working now, else the latest completed one
  const pick = picked ?? (choices.find((j) => isLive(j)) ?? choices.find((j) => j.status === 'completed') ?? choices[0])?.id

  if (hist.isLoading) return <Loading />
  if (hist.error || !hist.data) return <ErrorBox error={hist.error} />
  const a = hist.data.agent

  return (
    <div className="flex flex-col gap-5">
      <PageHeader title={meta.name} description={`Agent ${meta.n} of 4 · ${meta.short}. See what it received, what it produced and what it concluded, for any run.`} />

      <Panel className="flex flex-col gap-4 p-6">
        <div className="flex items-center gap-3">
          <AgentTile id={id} />
          <div><h3 className="font-semibold">{a.name}</h3><p className="text-sm text-ink-3">{a.role}</p></div>
        </div>
        <div className="grid grid-cols-1 items-stretch gap-3 md:grid-cols-[1fr_auto_1fr]">
          <div className="rounded-xl border border-hairline bg-well/40 p-4">
            <h4 className="mb-2 text-xs font-semibold uppercase tracking-[0.1em] text-ink-3">It needs</h4>
            <ul className="list-disc pl-5 text-sm text-ink-2">{a.contract_in.map((x) => <li key={x}>{x}</li>)}</ul>
          </div>
          <div className="hidden place-items-center text-ink-3 md:grid"><ArrowRight className="size-5" /></div>
          <div className="tint-box rounded-xl p-4" style={{ '--tint': meta.tone } as CSSProperties}>
            <h4 className="mb-2 text-xs font-semibold uppercase tracking-[0.1em] text-ink-3">It delivers</h4>
            <ul className="list-disc pl-5 text-sm text-ink-2">{a.contract_out.map((x) => <li key={x}>{x}</li>)}</ul>
          </div>
        </div>
      </Panel>

      <section className="flex flex-col gap-3">
        <div className="flex flex-wrap items-center gap-3">
          <h2 className="text-lg font-semibold tracking-tight">Results for one run</h2>
          <select aria-label="Pick a run" value={pick ?? ''} onChange={(e) => setPick(e.target.value)} className={cn(inputCls, 'ml-auto h-9 w-auto max-w-full')}>
            {choices.map((j) => <option key={j.id} value={j.id}>{j.repo} · {j.status} · {ago(j.created_at)}</option>)}
          </select>
        </div>
        {choices.length ? (pick && <RunResults id={id} jobId={pick} />) : <Empty text="No runs yet."><LinkBtn to="/scan" kind="primary">Start a scan</LinkBtn></Empty>}
      </section>

      <Card title="Across recent runs" description="Its key outputs and main conclusion in each completed run. Click a row to open that run.">
        {hist.data.runs.length ? (
          <DTable head={[['Repository'], ['When'], ['Status'], ['Key outputs'], ['Main conclusion']]} minWidth={900}>
            {hist.data.runs.map((h) => (
              <tr key={h.job_id} className="cursor-pointer hover:bg-well/60" onClick={() => navigate(`/runs/${h.job_id}/${id}`)}>
                <td className="font-medium">{h.repo}</td>
                <td className="whitespace-nowrap text-xs text-ink-3">{ago(h.when)}</td>
                <td><AgentStatusTag status={h.status} /></td>
                <td className="text-xs text-ink-2">{h.outputs.slice(0, 3).map((o) => <div key={o.label}>{o.label}: <b className="text-ink">{o.value}</b></div>)}</td>
                <td className="max-w-[380px] text-xs text-ink-2">{h.learnings[0]?.text ?? '–'}</td>
              </tr>
            ))}
          </DTable>
        ) : <Empty text="No completed runs yet." />}
      </Card>
    </div>
  )
}

function RunResults({ id, jobId }: { id: AgentId; jobId: string }) {
  const job = useJob(jobId)
  const ag = useJobAgents(jobId, isLive(job.data))
  if (!job.data || !ag.data) return <Loading />
  return (
    <>
      <AgentPanel view={ag.data.agents[id]} job={job.data} />
      {job.data.status === 'completed' && <AgentDetail id={id} job={job.data} />}
    </>
  )
}

/** The agent's main output for a completed run, in full. */
function AgentDetail({ id, job }: { id: AgentId; job: Job }) {
  const { report, findings } = useJobResults(job.id, true)
  const { openFinding } = usePanels()
  const link = (tab: string, label: string) => <LinkBtn to={`/runs/${job.id}/${tab}`}>{label} <ArrowRight className="size-3.5" /></LinkBtn>
  if (report.isLoading || findings.isLoading) return <Loading />

  if (id === 'analysis') {
    const f = findings.data ?? []
    return (
      <Card title="Top risks it found" description="Ranked by risk. Click a row for the details." action={link('findings', `All ${f.length} findings`)}>
        {f.length ? (
          <DTable head={[['Risk'], ['Severity'], ['Finding'], ['Found by'], ['Fix']]}>
            {f.slice(0, 10).map((x) => (
              <tr key={x.finding_id} className="cursor-pointer hover:bg-well/60" onClick={() => openFinding(job.id, x.finding_id)}>
                <td><RiskScore score={x.priority_score} /></td><td><SevTag sev={x.severity} /></td>
                <td><div className="font-medium">{x.title}</div><div className="font-mono text-xs text-ink-3">{where(x)}</div></td>
                <td className="text-xs text-ink-2">{detectedBy(x)}</td><td><FixStatusTag s={x.fix_status} /></td>
              </tr>
            ))}
          </DTable>
        ) : <Empty text="No findings." />}
      </Card>
    )
  }
  const rep = report.data
  if (!rep) return null
  if (id === 'remediation') {
    return (
      <Card title="Fixes it made" description="One commit per fix on the separate branch." action={link('remediation', 'See every diff')}>
        {rep.fixes.length ? (
          <DTable head={[['#'], ['How'], ['Change'], ['Files'], ['Rescan'], ['Validation']]} minWidth={900}>
            {rep.fixes.map((x, i) => {
              const [title, extra] = splitFixTitle(x.summary)
              return (
                <tr key={i}>
                  <td className="tabular text-ink-3">{i + 1}</td>
                  <td><StatusTag tone="info" label={METHOD[x.method]?.label ?? x.method} /></td>
                  <td className="max-w-[380px]"><div className="font-medium">{title}</div>{extra && <div className="text-xs text-ink-3">{extra}</div>}{x.explanation && <div className="mt-1 text-xs text-ink-2">{x.explanation.slice(0, 220)}</div>}</td>
                  <td className="min-w-[140px] max-w-[220px] font-mono [overflow-wrap:anywhere] text-xs text-ink-2">{x.files.join(', ')}</td>
                  <td>{x.verified === true ? <StatusTag tone="good" label="Resolved" /> : x.verified === false ? <StatusTag tone="warn" label="Still reported" /> : '–'}</td>
                  <td><VerdictTag v={x.validation_status} /></td>
                </tr>
              )
            })}
          </DTable>
        ) : <Empty text="No fixes in this run." />}
      </Card>
    )
  }
  if (id === 'validation') {
    const order = { failed: 0, warning: 1, passed: 2, skipped: 3 }
    const checks = [...rep.validation_checks].sort((a, b) => order[a.status] - order[b.status])
    const tone = { passed: 'good', failed: 'bad', warning: 'warn', skipped: 'idle' } as const
    return (
      <Card title="Every check it ran" description="Failures first." action={link('validation', 'Open in run')}>
        {checks.length ? (
          <DTable head={[['Result'], ['Check'], ['Fix'], ['Evidence']]} maxHeight={600}>
            {checks.slice(0, 120).map((c, i) => (
              <tr key={i}>
                <td><StatusTag tone={tone[c.status]} label={c.status} /></td>
                <td><div className="font-medium">{c.name}</div><div className="text-xs text-ink-3">{c.category}</div></td>
                <td className="text-xs">{c.fix_index != null ? `#${c.fix_index + 1}` : 'whole run'}</td>
                <td className="max-w-[460px] text-xs text-ink-2">{c.detail}</td>
              </tr>
            ))}
          </DTable>
        ) : <Empty text="No checks (no fixes to validate)." />}
      </Card>
    )
  }
  const s = job.summary ?? {}
  return (
    <Card title="What it handed over" description="Files to download, and the pull request." action={link('reporting', 'Read the report')}>
      <div className="flex flex-wrap gap-2">
        {PDF_FILES.map(([n]) => <LinkBtn key={n} href={artifactUrl(job.id, n)}><Download className="size-3.5" /> {n}</LinkBtn>)}
        {(job.artifacts ?? []).filter((x) => TOOL_FILES.some(([n]) => n === x.name)).map((x) => (
          <LinkBtn key={x.name} href={artifactUrl(job.id, x.name)}><Download className="size-3.5" /> {x.name} <span className="text-ink-3">{Math.max(1, Math.round(x.size / 1024))} KB</span></LinkBtn>
        ))}
      </div>
      <div className="mt-4">
        {s.pull_request_url ? <LinkBtn href={s.pull_request_url} external kind="good">{s.pull_request_draft ? 'Draft pull request' : 'Pull request'} <ExternalLink className="size-3.5" /></LinkBtn>
          : s.fixes_applied ? <Link to="/approvals" className="text-sm font-medium text-sky">Waiting for approval →</Link> : <span className="text-sm text-ink-3">No pull request needed.</span>}
      </div>
    </Card>
  )
}
