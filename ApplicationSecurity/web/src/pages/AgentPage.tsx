import { useState, type CSSProperties } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { ArrowRight, Download, ExternalLink } from 'lucide-react'
import { AgentPanel, AgentTile } from '@/components/Agents'
import { AgentStatusTag, Card, Choice, DTable, Empty, ErrorBox, FixStatusTag, LinkBtn, Loading, PageHeader, Panel, RiskScore, SevTag, StatusTag, VerdictTag } from '@/components/kit'
import { PDF_FILES, TOOL_FILES, artifactUrl, isLive, useAgentHistory, useJob, useJobAgents, useJobResults, useJobs } from '@/lib/api'
import { ago } from '@/lib/format'
import { problemOf } from '@/components/FixStory'
import { AGENTS, JOB_STATUS, METHOD, detectedBy, splitFixTitle, where } from '@/lib/labels'
import { usePanels } from '@/lib/panels'
import type { AgentId, Job } from '@/lib/types'
import { cn } from '@/lib/utils'

export function AgentPage() {
  const { agent } = useParams()
  const id = agent as AgentId
  if (!(id in AGENTS)) return <Empty text="This agent does not exist." />
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
      <PageHeader title={meta.name} description={`${meta.short}. Review its inputs, outputs and conclusions for any scan.`} />

      <Panel className="flex flex-col gap-4 p-6">
        <div className="flex items-center gap-3">
          <AgentTile id={id} />
          <div><h3 className="font-semibold">{a.name}</h3><p className="text-sm text-ink-3">{a.role}</p></div>
        </div>
        <div className="grid grid-cols-1 items-stretch gap-3 md:grid-cols-[1fr_auto_1fr]">
          <div className="rounded-xl border border-hairline bg-well/40 p-4">
            <h4 className="mb-2 text-xs font-semibold uppercase tracking-[0.1em] text-ink-3">Inputs</h4>
            <ul className="list-disc pl-5 text-sm text-ink-2">{a.contract_in.map((x) => <li key={x}>{x}</li>)}</ul>
          </div>
          <div className="hidden place-items-center text-ink-3 md:grid"><ArrowRight className="size-5" /></div>
          <div className="tint-box rounded-xl p-4" style={{ '--tint': meta.tone } as CSSProperties}>
            <h4 className="mb-2 text-xs font-semibold uppercase tracking-[0.1em] text-ink-3">Outputs</h4>
            <ul className="list-disc pl-5 text-sm text-ink-2">{a.contract_out.map((x) => <li key={x}>{x}</li>)}</ul>
          </div>
        </div>
      </Panel>

      <section className="flex flex-col gap-3">
        <div className="flex flex-wrap items-center gap-3">
          <h2 className="text-lg font-semibold tracking-tight">Results by scan</h2>
          {choices.length > 0 && (
            <Choice field label="Select a scan" value={pick ?? ''} onChange={setPick} className="ml-auto h-9 w-auto max-w-full"
              options={choices.map((j) => ({ value: j.id, label: `${j.repo} · ${JOB_STATUS[j.status]?.label ?? j.status} · ${ago(j.created_at)}` }))} />
          )}
        </div>
        {choices.length ? (pick && <RunResults id={id} jobId={pick} />) : <Empty text="No scans have been run yet."><LinkBtn to="/scan" kind="primary">Start a scan</LinkBtn></Empty>}
      </section>

      <Card title="Recent scans" description="Key outputs and the principal conclusion from each completed scan. Select a row to open the scan.">
        {hist.data.runs.length ? (
          <DTable head={[['Repository'], ['When'], ['Status'], ['Key outputs'], ['Principal conclusion']]} minWidth={900}>
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
        ) : <Empty text="No completed scans yet." />}
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
      <Card title="Highest-risk findings" description="Ranked by risk score. Select a row for full details." action={link('findings', `All ${f.length} findings`)}>
        {f.length ? (
          <DTable head={[['Risk'], ['Severity'], ['Finding'], ['Detected by'], ['Remediation']]}>
            {f.slice(0, 10).map((x) => (
              <tr key={x.finding_id} className="cursor-pointer hover:bg-well/60" onClick={() => openFinding(job.id, x.finding_id)}>
                <td><RiskScore score={x.priority_score} /></td><td><SevTag sev={x.severity} /></td>
                <td><div className="font-medium">{x.title}</div><div className="font-mono text-xs text-ink-3">{where(x)}</div></td>
                <td className="text-xs text-ink-2">{detectedBy(x)}</td><td><FixStatusTag s={x.fix_status} /></td>
              </tr>
            ))}
          </DTable>
        ) : <Empty text="No findings were identified." />}
      </Card>
    )
  }
  const rep = report.data
  if (!rep) return null
  if (id === 'remediation') {
    return (
      <Card title="Remediations applied" description="For each remediation: the vulnerability identified by the Analysis Agent, the change made by the Remediation Agent (one commit on the remediation branch), and the Validation Agent's verdict." action={link('remediation', 'View all diffs')}>
        {rep.fixes.length ? (
          <DTable head={[['#'], ['Vulnerability'], ['Remediation applied'], ['Confirmation scan'], ['Validation']]} minWidth={980}>
            {rep.fixes.map((x, i) => {
              const [title, extra] = splitFixTitle(x.summary)
              const p = problemOf(x, findings.data ?? [])
              const first = p.findings[0]
              return (
                <tr key={i} className={cn(first && 'cursor-pointer hover:bg-well/60')} onClick={() => first && openFinding(job.id, first.finding_id)}>
                  <td className="tabular text-ink-3">{i + 1}</td>
                  <td className="max-w-[340px]">
                    <div className="flex items-start gap-2">{p.severity !== 'unknown' && <SevTag sev={p.severity} />}<span className="font-medium leading-snug">{p.headline}</span></div>
                    <div className="mt-0.5 break-all font-mono text-xs text-ink-3">{p.where}</div>
                    {p.why && <div className="mt-1 line-clamp-2 text-xs text-ink-2">{p.why}</div>}
                  </td>
                  <td className="max-w-[360px]">
                    <StatusTag tone="info" label={METHOD[x.method]?.label ?? x.method} />
                    <div className="mt-1 font-medium">{title}</div>{extra && <div className="text-xs text-ink-3">{extra}</div>}
                    {x.explanation && <div className="mt-1 line-clamp-3 text-xs text-ink-2">{x.explanation}</div>}
                    <div className="mt-1 break-all font-mono text-[11px] text-ink-3">{x.files.join(', ')}</div>
                  </td>
                  <td>{x.verified === true ? <StatusTag tone="good" label="Resolved" /> : x.verified === false ? <StatusTag tone="warn" label="Still reported" /> : '–'}</td>
                  <td><VerdictTag v={x.validation_status} /></td>
                </tr>
              )
            })}
          </DTable>
        ) : <Empty text="No remediations were applied in this scan." />}
      </Card>
    )
  }
  if (id === 'validation') {
    const order = { failed: 0, warning: 1, passed: 2, skipped: 3 }
    const checks = [...rep.validation_checks].sort((a, b) => order[a.status] - order[b.status])
    const tone = { passed: 'good', failed: 'bad', warning: 'warn', skipped: 'idle' } as const
    return (
      <Card title="Validation checks" description="All checks performed, failures first." action={link('validation', 'Open in scan')}>
        {checks.length ? (
          <DTable head={[['Result'], ['Check'], ['Remediation'], ['Evidence']]} maxHeight={600}>
            {checks.slice(0, 120).map((c, i) => (
              <tr key={i}>
                <td><StatusTag tone={tone[c.status]} label={c.status} /></td>
                <td><div className="font-medium">{c.name}</div><div className="text-xs text-ink-3">{c.category}</div></td>
                <td className="text-xs">{c.fix_index != null ? `#${c.fix_index + 1}` : 'Entire scan'}</td>
                <td className="max-w-[460px] text-xs text-ink-2">{c.detail}</td>
              </tr>
            ))}
          </DTable>
        ) : <Empty text="No checks were required (no remediations to validate)." />}
      </Card>
    )
  }
  const s = job.summary ?? {}
  return (
    <Card title="Deliverables" description="Downloadable reports and the pull request." action={link('reporting', 'View the report')}>
      <div className="flex flex-wrap gap-2">
        {PDF_FILES.map(([n]) => <LinkBtn key={n} href={artifactUrl(job.id, n)}><Download className="size-3.5" /> {n}</LinkBtn>)}
        {(job.artifacts ?? []).filter((x) => TOOL_FILES.some(([n]) => n === x.name)).map((x) => (
          <LinkBtn key={x.name} href={artifactUrl(job.id, x.name)}><Download className="size-3.5" /> {x.name} <span className="text-ink-3">{Math.max(1, Math.round(x.size / 1024))} KB</span></LinkBtn>
        ))}
      </div>
      <div className="mt-4">
        {s.pull_request_url ? <LinkBtn href={s.pull_request_url} external kind="good">{s.pull_request_draft ? 'Draft pull request' : 'Pull request'} <ExternalLink className="size-3.5" /></LinkBtn>
          : s.fixes_applied ? <Link to="/approvals" className="text-sm font-medium text-sky">Awaiting approval →</Link> : <span className="text-sm text-ink-3">No pull request required.</span>}
      </div>
    </Card>
  )
}
