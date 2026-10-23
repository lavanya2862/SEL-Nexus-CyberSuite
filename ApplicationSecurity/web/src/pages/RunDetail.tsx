import { useEffect, useRef, useState, type CSSProperties } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Check, Download, ExternalLink, GitPullRequestArrow, Loader2, RotateCcw, Sparkles, Square } from 'lucide-react'
import { AgentCard, AgentPanel, StoryCard } from '@/components/Agents'
import { Chart } from '@/components/Chart'
import { Diff, Markdown } from '@/components/Code'
import { ChecksList } from '@/components/FindingDrawer'
import { FixStory } from '@/components/FixStory'
import {
  Btn, Card, Chip, DTable, Empty, ErrorBox, FixStatusTag, JobStatusTag, LinkBtn, Loading, Notice, Panel, RiskScore, SevTag, StatusTag,
  Tabs, VerdictTag, sevColor,
} from '@/components/kit'
import { PipelineFlow, StageDetail } from '@/components/Pipeline'
import { FindingsTable } from '@/components/Tables'
import { RunTestsButton, TestsTab } from '@/components/TestLoop'
import { PDF_FILES, TOOL_FILES, api, artifactUrl, isLive, post, testsActive, useCaps, useJob, useJobAgents, useJobEvents, useJobResults } from '@/lib/api'
import { ago } from '@/lib/format'
import { AGENT_IDS, METHOD, SEVERITIES, dur, mergedStages, sevLabel, where } from '@/lib/labels'
import { useApprove, usePanels } from '@/lib/panels'
import { useTheme } from '@/lib/theme'
import { useToast } from '@/lib/toast'
import type { AgentId, AgentView, Finding, Job, Report } from '@/lib/types'

type Tab = 'summary' | AgentId | 'tests' | 'findings' | 'logs'
const TABS: [Tab, string][] = [['summary', 'Summary'], ['analysis', '① Analysis'], ['remediation', '② Remediation'], ['validation', '③ Validation'],
  ['reporting', '④ Reporting'], ['tests', '⑤ GitHub tests'], ['findings', 'All findings'], ['logs', 'Activity log']]

export function RunDetail() {
  const { id, tab } = useParams()
  const job = useJob(id)
  if (job.isLoading) return <Loading text="Loading the scan…" />
  if (job.error || !job.data) return <ErrorBox error={job.error ?? 'Scan not found'} />
  return <RunView job={job.data} urlTab={tab as Tab | undefined} />
}

function RunView({ job, urlTab }: { job: Job; urlTab?: Tab }) {
  const navigate = useNavigate()
  const live = isLive(job)
  const completed = job.status === 'completed'
  const agents = useJobAgents(job.id, live)
  const { report, findings } = useJobResults(job.id, completed, job.summary?.approval_status)
  const { setChatContext } = usePanels()
  const [picked, setPicked] = useState<string | null>(null)

  useEffect(() => {
    setChatContext({ type: 'run', jobId: job.id, label: job.repo })
    return () => setChatContext({ type: 'general' })
  }, [job.id, job.repo, setChatContext])

  const stages = mergedStages(job.stages)
  const running = stages.find((s) => s.status === 'running')
  const lastDone = [...stages].reverse().find((s) => !['pending', 'skipped'].includes(s.status)) ?? stages[0]
  const selected = picked ?? (running ?? lastDone).id

  // Without a tab in the address: the summary once finished; while running, the agent that is working (else the log).
  const runningAgent = running && (AGENT_IDS as string[]).includes(running.id) ? (running.id as AgentId) : null
  const available = completed ? TABS : TABS.filter(([k]) => k !== 'summary' && k !== 'findings' && k !== 'tests')
  const tab: Tab = urlTab && available.some(([k]) => k === urlTab) ? urlTab : completed ? 'summary' : runningAgent ?? 'logs'
  const failedChecks = report.data?.validation_checks.filter((c) => c.status === 'failed').length ?? 0
  const tabs: [Tab, React.ReactNode][] = available.map(([k, l]) => [k, (
    <>{l}{k === 'findings' && findings.data ? <Chip>{findings.data.length}</Chip> : null}
      {k === 'remediation' && report.data?.fixes.length ? <Chip>{report.data.fixes.length}</Chip> : null}
      {k === 'validation' && failedChecks ? <span className="rounded-md bg-[#d03b3b] px-1.5 py-0.5 text-[11px] font-semibold text-white">{failedChecks}</span> : null}
      {k === 'tests' && job.summary?.tests ? <TestsBadge status={job.summary.tests.status} /> : null}</>
  )])

  return (
    <div className="flex flex-col gap-5">
      <RunHeader job={job} report={report.data} />
      {completed && agents.data?.story && <Panel className="p-6"><StoryCard story={agents.data.story} job={job} /></Panel>}
      <Card title="Pipeline" description="The six steps of this scan. Click a step to see what it did.">
        <PipelineFlow stages={stages} selected={selected} onSelect={setPicked} />
        <StageDetail stage={stages.find((s) => s.id === selected)} />
      </Card>
      <ApprovalBox job={job} />

      <div className="flex flex-col gap-5">
        <Tabs<Tab> tabs={tabs} value={tab} onChange={(t) => navigate(`/runs/${job.id}/${t}`, { replace: true })} />
        {completed && (report.error || findings.error) ? <ErrorBox error={report.error ?? findings.error} />
          : tab === 'logs' ? <LogTab job={job} />
          : tab === 'tests' ? <TestsTab job={job} />
            : tab === 'summary' ? (report.data && findings.data ? <SummaryTab job={job} report={report.data} findings={findings.data} agents={agents.data?.agents} /> : <Loading />)
              : tab === 'findings' ? (findings.data ? <Card title="All findings" description="Every unique issue in this scan, highest risk first."><FindingsTable items={findings.data} jobId={job.id} /></Card> : <Loading />)
                : <AgentTab id={tab} job={job} view={agents.data?.agents[tab]} report={report.data} findings={findings.data} />}
      </div>
    </div>
  )
}

/* ───────── header ───────── */

function RunHeader({ job, report }: { job: Job; report?: Report }) {
  const s = job.summary ?? {}
  const done = !isLive(job)
  const { openChat } = usePanels()
  const toast = useToast()
  const qc = useQueryClient()
  const act = async (what: 'cancel' | 'retry') => {
    try {
      await post(`/api/v1/jobs/${job.id}/${what}`)
      toast(what === 'cancel' ? 'Cancellation requested' : 'Queued again')
      qc.invalidateQueries({ queryKey: ['job', job.id] })
    } catch (e) {
      toast((e as Error).message, true)
    }
  }
  return (
    <Panel className="flex flex-col gap-4 p-6">
      <div className="flex flex-wrap items-start gap-4">
        <div className="min-w-[260px] flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <JobStatusTag job={job} />
            <VerdictTag v={s.validation_status} />
            {job.cached_from && <Chip>reused earlier results</Chip>}
          </div>
          <h1 className="mt-2 text-2xl font-semibold tracking-tight"><a href={job.repo_url} target="_blank" rel="noopener noreferrer" className="hover:underline">{job.repo}</a></h1>
          <div className="mt-1 flex flex-wrap gap-x-4 gap-y-1 text-xs text-ink-3">
            <span className="font-mono">{job.ref || 'default branch'}{job.commit ? ` @ ${job.commit.slice(0, 12)}` : ''}</span>
            {s.branch && <span>fix branch <span className="font-mono text-ink-2">{s.branch}</span></span>}
            <span>started {ago(job.started_at ?? job.created_at)}</span>
            {report && <span>took {dur(report.duration_seconds)}</span>}
          </div>
        </div>
        <div className="flex flex-wrap gap-2">
          {s.pull_request_url && <LinkBtn href={s.pull_request_url} external kind="good"><GitPullRequestArrow className="size-4" /> {s.pull_request_draft ? 'View draft PR' : 'View pull request'}</LinkBtn>}
          <RunTestsButton job={job} />
          <Btn kind="quiet" onClick={() => openChat({ type: 'run', jobId: job.id, label: job.repo })}><Sparkles className="size-4" /> Ask the Security Assistant</Btn>
          {!done && <Btn kind="quiet" onClick={() => act('cancel')}><Square className="size-3.5" /> Cancel</Btn>}
          {done && <Btn kind="quiet" onClick={() => act('retry')}><RotateCcw className="size-3.5" /> Re-run</Btn>}
        </div>
      </div>
      {!done && (
        <div>
          <div className="h-1.5 overflow-hidden rounded-full bg-well"><div className="h-full rounded-full bg-blue transition-[width] duration-500" style={{ width: `${job.progress}%` }} /></div>
          <p className="mt-1.5 text-xs text-ink-3">{job.stage} · {job.progress}% · this page updates by itself</p>
        </div>
      )}
      {job.error && <Notice tone="bad" title={`Run ${job.status}`}>{job.error}</Notice>}
    </Panel>
  )
}

/* ───────── the human decision ───────── */

function ApprovalBox({ job }: { job: Job }) {
  const s = job.summary ?? {}
  const caps = useCaps()
  const approve = useApprove()
  const tests = s.tests
  const testFixes = (tests?.runs ?? []).filter((r) => r.fix).length
  if (job.status !== 'completed' || (!s.fixes_applied && !testFixes)) return null
  const flagged = s.validation_status === 'flagged'
  if (s.pull_request_url) {
    return (
      <Notice tone={flagged ? 'warn' : 'good'} title={s.pull_request_draft ? 'Draft pull request opened: flagged for investigation' : 'Pull request opened: waiting for human review'}
        action={<LinkBtn href={s.pull_request_url} external kind="good">Open on GitHub <ExternalLink className="size-3.5" /></LinkBtn>}>
        The fixes are on branch <span className="font-mono">{s.branch}</span>. Review and merge on GitHub; nothing is merged automatically.
      </Notice>
    )
  }
  const token = !!caps.data?.github_token_configured
  const publishing = s.approval_status === 'publishing' || approve.isPending
  const testing = testsActive(job)
  return (
    <Notice tone={flagged ? 'warn' : 'info'} title={flagged ? 'Your decision: validation flagged this change set' : 'Your decision: approve the fixes'}
      action={
        <div className="flex flex-wrap gap-2">
          <LinkBtn href={artifactUrl(job.id, 'fixes.pdf')}><Download className="size-3.5" /> Fixes (PDF)</LinkBtn>
          <LinkBtn href={artifactUrl(job.id, 'fixes.patch')}><Download className="size-3.5" /> Patch</LinkBtn>
          <Btn kind={flagged ? 'warn' : 'good'} disabled={!token || publishing || testing} onClick={() => approve.mutate(job.id)}
            title={testing ? 'Wait for the GitHub tests to finish' : undefined}>
            {publishing ? <><Loader2 className="size-4 animate-spin" /> Publishing…</> : flagged ? 'Approve & open draft PR' : <><Check className="size-4" /> Approve &amp; open PR</>}
          </Btn>
        </div>
      }>
      {s.fixes_applied ?? 0} fix commit(s) are ready{flagged ? '; a validation check failed (see ③ Validation). Approving opens a draft pull request labelled needs-investigation.' : ' and validated. Review them under ② Remediation, then approve to push the branch and open a pull request.'}
      {tests && <div className="mt-1">{testing ? 'The tests are running on GitHub; approve when they have finished.'
        : tests.status === 'passed' ? `GitHub tests pass on ${tests.branch}${testFixes ? ` after ${testFixes} Remediation Agent fix(es)` : ''}: approving opens the pull request from that branch.`
          : tests.status === 'failed' ? 'GitHub tests still fail: approving opens a draft pull request for investigation.' : null}</div>}
      {!tests && <div className="mt-1">Tip: <b>Run tests on GitHub</b> first to check the fixes against the repository’s own tests.</div>}
      {s.approval_status === 'failed' && s.publish_error && <div className="mt-1 text-[#d03b3b]">Last attempt failed: {s.publish_error}</div>}
      {!token && <div className="mt-1">A GitHub token is required: <Link to="/settings" className="text-sky underline">add one in Settings</Link>.</div>}
    </Notice>
  )
}

/* ───────── tabs ───────── */

function SummaryTab({ job, report: r, findings, agents }: { job: Job; report: Report; findings: Finding[]; agents?: Record<AgentId, AgentView> }) {
  const { theme } = useTheme()
  const sev = SEVERITIES.filter((s) => r.severity_counts[s]).map((s) => ({ name: sevLabel(s), value: r.severity_counts[s] ?? 0, itemStyle: { color: sevColor(theme, s) } }))
  const funnel: [string, number][] = [['Issues found', r.findings_input], ['Selected to fix', r.findings_selected], ['Fix attempts', r.patches_proposed], ['Fixes applied', r.patches_applied], ['Confirmed resolved', r.verified_fixed]]
  const max = Math.max(1, ...funnel.map((x) => x[1]))
  const statusCounts: Record<string, number> = {}
  findings.forEach((f) => { statusCounts[f.fix_status] = (statusCounts[f.fix_status] ?? 0) + 1 })
  return (
    <div className="flex flex-col gap-5">
      <div className="grid grid-cols-1 gap-5 xl:grid-cols-3">
        <Card title="What was found" description={`${findings.length} unique issues, by severity.`}>
          {sev.length ? (
            <div className="flex items-center gap-4">
              <div className="relative size-[150px] shrink-0">
                <Chart height={150} build={() => ({ tooltip: { trigger: 'item', formatter: '{b}: {c}' }, series: [{ type: 'pie', radius: ['68%', '92%'], padAngle: 2, label: { show: false }, data: sev }] })} />
                <div className="pointer-events-none absolute inset-0 grid place-items-center text-center"><div><div className="tabular text-2xl font-semibold">{findings.length}</div><div className="text-xs text-ink-3">issues</div></div></div>
              </div>
              <ul className="flex flex-1 flex-col gap-2 text-sm">{sev.map((x) => <li key={x.name} className="flex items-center gap-2"><span className="size-2.5 rounded-full" style={{ background: x.itemStyle.color }} /><span className="flex-1 text-ink-2">{x.name}</span><b className="tabular font-medium">{x.value}</b></li>)}</ul>
            </div>
          ) : <p className="text-sm text-ink-3">No findings: the repository is clean.</p>}
        </Card>
        <Card title="From issue to fix" description="How many made it through each step.">
          <div className="flex flex-col gap-2.5">
            {funnel.map(([l, n]) => (
              <div key={l} className="grid grid-cols-[130px_1fr_40px] items-center gap-3 text-sm">
                <span className="text-ink-2">{l}</span>
                <span className="h-2 overflow-hidden rounded-full bg-well"><span className="rank-bar block h-full rounded-full bg-blue" style={{ width: `${(n / max) * 100}%` }} /></span>
                <b className="tabular text-right font-medium">{n}</b>
              </div>
            ))}
          </div>
          <div className="mt-4 flex flex-wrap gap-1.5">{Object.entries(statusCounts).map(([k, n]) => <span key={k} className="inline-flex items-center gap-1"><FixStatusTag s={k} /><span className="text-xs text-ink-3">{n}</span></span>)}</div>
        </Card>
        <Card title="Validation verdict" description="Did the fixes prove themselves?"><Verdict report={r} /></Card>
      </div>
      <div className="grid grid-cols-1 gap-5 sm:grid-cols-2 xl:grid-cols-4">
        {AGENT_IDS.map((id) => <AgentCard key={id} id={id} view={agents?.[id]} to={`/runs/${job.id}/${id}`} />)}
      </div>
      {r.notes.length > 0 && <Card title="Notes from the agents"><ul className="list-disc pl-5 text-sm text-ink-2">{r.notes.map((n, i) => <li key={i}>{n}</li>)}</ul></Card>}
    </div>
  )
}

function Verdict({ report: r }: { report: Report }) {
  const checks = r.validation_checks ?? []
  const c = (st: string) => checks.filter((x) => x.status === st).length
  const text: Record<string, [string, string]> = {
    passed: ['All validation checks passed', 'The fixes still compile, add no security regressions and are confirmed by the rescan.'],
    flagged: ['Flagged for investigation', 'One or more checks failed. The changes are not merged automatically: they go to a draft pull request.'],
    not_run: ['Not validated', 'There were no fixes to validate.'],
  }
  const [title, body] = text[r.validation_status] ?? [r.validation_status, '']
  return (
    <div className="flex flex-col gap-3">
      <Notice tone={r.validation_status === 'passed' ? 'good' : r.validation_status === 'flagged' ? 'warn' : 'info'} title={title}>{body}</Notice>
      <div className="flex flex-wrap gap-1.5">
        <StatusTag tone="good" label={`${c('passed')} passed`} />
        <StatusTag tone="bad" label={`${c('failed')} failed`} />
        <StatusTag tone="warn" label={`${c('warning')} warnings`} />
        <StatusTag tone="idle" label={`${c('skipped')} skipped`} />
      </div>
    </div>
  )
}

function AgentTab({ id, job, view, report, findings }: { id: AgentId; job: Job; view?: AgentView; report?: Report; findings?: Finding[] }) {
  return (
    <div className="flex flex-col gap-5">
      {view ? <AgentPanel view={view} /> : <Loading text="Loading the agent’s results…" />}
      {report && findings && (
        id === 'analysis' ? <AnalysisExtra job={job} report={report} findings={findings} />
          : id === 'remediation' ? <RemediationExtra job={job} report={report} findings={findings} />
            : id === 'validation' ? <ValidationExtra report={report} />
              : <ReportingExtra job={job} />
      )}
    </div>
  )
}

function Bars({ rows, color }: { rows: [string, number][]; color?: (k: string) => string }) {
  const max = Math.max(1, ...rows.map((r) => r[1]))
  if (!rows.length) return <p className="text-sm text-ink-3">–</p>
  return (
    <div className="flex flex-col gap-2">
      {rows.map(([k, n]) => (
        <div key={k} className="grid grid-cols-[minmax(0,160px)_1fr_36px] items-center gap-3 text-sm">
          <span className="truncate text-ink-2" title={k}>{k.replace(/_/g, ' ')}</span>
          <span className="h-2 overflow-hidden rounded-full bg-well"><span className="rank-bar block h-full rounded-full" style={{ width: `${(n / max) * 100}%`, background: color?.(k) ?? 'var(--blue)' }} /></span>
          <b className="tabular text-right font-medium">{n}</b>
        </div>
      ))}
    </div>
  )
}

function AnalysisExtra({ job, report: r, findings }: { job: Job; report: Report; findings: Finding[] }) {
  const { openFinding } = usePanels()
  const navigate = useNavigate()
  const cats = Object.entries(r.category_counts ?? {}).sort((a, b) => b[1] - a[1]).slice(0, 8)
  const scanners = Object.entries(r.scanner_counts ?? {}).sort((a, b) => b[1] - a[1])
  return (
    <div className="grid grid-cols-1 gap-5 xl:grid-cols-2">
      <Card title="Top risks it ranked" action={<Btn kind="quiet" onClick={() => navigate(`/runs/${job.id}/findings`, { replace: true })}>All {findings.length} findings</Btn>}>
        {findings.length ? (
          <DTable head={[['Risk'], ['Severity'], ['Finding'], ['Fix']]} minWidth={520}>
            {findings.slice(0, 10).map((f) => (
              <tr key={f.finding_id} className="cursor-pointer hover:bg-well/60" onClick={() => openFinding(job.id, f.finding_id)}>
                <td><RiskScore score={f.priority_score} /></td><td><SevTag sev={f.severity} /></td>
                <td><div className="font-medium">{f.title}</div><div className="font-mono text-xs text-ink-3">{where(f)}</div></td>
                <td><FixStatusTag s={f.fix_status} /></td>
              </tr>
            ))}
          </DTable>
        ) : <Empty text="No findings." />}
      </Card>
      <div className="flex flex-col gap-5">
        <Card title="Kinds of vulnerability"><Bars rows={cats} /></Card>
        <Card title="Which scanner found what" description="Including findings two scanners agreed on.">
          <Bars rows={scanners} color={(k) => (k === 'CodeQL' ? 'var(--violet)' : k === 'Trivy' ? 'var(--teal)' : 'var(--blue)')} />
          <div className="mt-4 flex flex-wrap gap-1.5">
            {r.scanners.map((x) => <span key={x.name} title={x.message}><StatusTag tone={x.status === 'ok' ? 'good' : x.status === 'failed' ? 'bad' : 'idle'} label={`${x.name}: ${x.status}`} /></span>)}
          </div>
        </Card>
      </div>
    </div>
  )
}

function RemediationExtra({ job, report: r, findings }: { job: Job; report: Report; findings: Finding[] }) {
  const { openFinding } = usePanels()
  const [open, setOpen] = useState<Record<number, boolean>>({})
  if (!r.fixes.length) {
    const skipped = findings.filter((f) => f.fix_status === 'skipped').length
    return (
      <Empty text="No fixes were applied in this scan.">
        {skipped > 0 && !r.llm_enabled && <span>{skipped} code finding(s) are waiting for the Remediation Agent: <Link to="/settings" className="text-sky underline">connect the AI model it uses</Link> and re-run.</span>}
      </Empty>
    )
  }
  const by = (m: string) => r.fixes.filter((f) => f.method === m).length
  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center gap-2">
        <StatusTag tone="info" label={`${by('dependency')} dependency upgrades`} />
        <StatusTag tone="good" label={`${by('rule')} safe rewrites`} />
        <StatusTag tone="info" label={`${by('llm')} code fixes`} />
        <span className="text-xs text-ink-3">Separate branch <span className="font-mono text-ink-2">{r.branch}</span> · based on <span className="font-mono">{(r.base_commit ?? '').slice(0, 10)}</span></span>
        <LinkBtn href={artifactUrl(job.id, 'fixes.pdf')} className="ml-auto"><Download className="size-3.5" /> Fixes (PDF)</LinkBtn>
        <LinkBtn href={artifactUrl(job.id, 'fixes.patch')}><Download className="size-3.5" /> Full patch</LinkBtn>
      </div>
      {r.fixes.map((fix, i) => {
        const checks = r.validation_checks.filter((c) => c.fix_index === i)
        const m = METHOD[fix.method]
        return (
          <Panel key={i} className="p-5">
            <div className="flex flex-wrap items-start gap-4">
              <span className="grid size-9 shrink-0 place-items-center rounded-[10px] text-sm font-semibold" style={{ color: m?.tone, background: `color-mix(in oklab, ${m?.tone ?? 'var(--blue)'} 16%, transparent)` } as CSSProperties}>{i + 1}</span>
              <div className="min-w-[240px] flex-1">
                <FixStory fix={fix} findings={findings} onOpenFinding={(fid) => openFinding(job.id, fid)} />
                {fix.commit && <div className="mt-2 font-mono text-[11px] text-ink-3">commit {fix.commit.slice(0, 10)}</div>}
              </div>
              <Btn kind="quiet" onClick={() => setOpen((o) => ({ ...o, [i]: !o[i] }))}>{open[i] ? 'Hide diff' : 'Show diff'}</Btn>
            </div>
            {open[i] && <div className="mt-4">{checks.length > 0 && <ChecksList checks={checks} />}<div className="mt-3"><Diff diff={fix.diff} /></div></div>}
          </Panel>
        )
      })}
    </div>
  )
}

const CHECK_CATS: [string, string, string][] = [
  ['static', 'Static checks', 'Edited files still parse; dependency files stay valid.'],
  ['security-regression', 'Security-regression guard', 'Fixes must not add suppressions, disable TLS, skip tests or remove controls.'],
  ['functional', 'Functional tests', 'The project’s tests, before vs. after, in the sandbox.'],
  ['security-rescan', 'Security rescan', 'Scanners re-run on the fix branch: findings must be gone and nothing new introduced.'],
  ['policy', 'Change policy', 'Risky changes such as major-version upgrades.'],
]

function ValidationExtra({ report: r }: { report: Report }) {
  const checks = r.validation_checks ?? []
  const count = (cat: string, st: string) => checks.filter((c) => c.category === cat && c.status === st).length
  const tone = { passed: 'good', failed: 'bad', warning: 'warn', skipped: 'idle' } as const
  return (
    <div className="flex flex-col gap-5">
      <Panel className="p-6"><Verdict report={r} /></Panel>
      <div className="card-row gap-4 [--card-min:200px]">
        {CHECK_CATS.map(([k, l, d]) => {
          const p = count(k, 'passed'), f = count(k, 'failed'), w = count(k, 'warning'), s = count(k, 'skipped')
          return (
            <Panel key={k} className="flex flex-col gap-2 p-5">
              <h3 className="font-semibold">{l}</h3>
              <p className="min-h-10 text-xs text-ink-3">{d}</p>
              <div className="mt-auto flex flex-wrap gap-1.5">
                {p + f + w + s === 0 ? <StatusTag tone="idle" label="not run" /> : <>
                  {p > 0 && <StatusTag tone="good" label={`${p} passed`} />}{f > 0 && <StatusTag tone="bad" label={`${f} failed`} />}
                  {w > 0 && <StatusTag tone="warn" label={`${w} warn`} />}{s > 0 && <StatusTag tone="idle" label={`${s} skipped`} />}
                </>}
              </div>
            </Panel>
          )
        })}
      </div>
      <Card title="All checks">
        {checks.length ? (
          <DTable head={[['Result'], ['Check'], ['Category'], ['Fix'], ['Detail']]} minWidth={900} maxHeight={640}>
            {checks.map((c, i) => (
              <tr key={i}>
                <td><StatusTag tone={tone[c.status]} label={c.status} /></td>
                <td className="font-medium">{c.name}</td>
                <td className="text-xs text-ink-2">{c.category}</td>
                <td className="text-xs">{c.fix_index != null ? <>#{c.fix_index + 1} <span className="text-ink-3">{(r.fixes[c.fix_index]?.summary ?? '').slice(0, 60)}</span></> : <span className="text-ink-3">whole scan</span>}</td>
                <td className="max-w-[420px] text-xs text-ink-2">{c.detail}</td>
              </tr>
            ))}
          </DTable>
        ) : <Empty text="No checks were run (no fixes)." />}
      </Card>
      {r.validation.length > 0 && (
        <Card title="Functional test runs">
          <div className="flex flex-col gap-2">
            {r.validation.map((v, i) => (
              <details key={i} className="rounded-xl border border-hairline p-3">
                <summary className="cursor-pointer text-sm"><b>{v.name}</b> · {v.skipped ? 'skipped' : v.passed ? 'passed' : 'FAILED'} <span className="font-mono text-xs text-ink-3">{v.command}</span></summary>
                <pre className="codebox mt-3"><span>{(v.stdout + '\n' + v.stderr).trim().slice(-6000) || '(no output)'}</span></pre>
              </details>
            ))}
          </div>
        </Card>
      )}
    </div>
  )
}

function ReportingExtra({ job }: { job: Job }) {
  const md = useQuery({ queryKey: ['job', job.id, 'report.md', job.summary?.approval_status], queryFn: () => api<string>(artifactUrl(job.id, 'report.md', false)) })
  return (
    <div className="flex flex-col gap-5">
      <Card title="Downloads" description="PDF reports to read and share. findings.sarif uploads to GitHub code scanning; fixes.patch applies with git apply.">
        <div className="flex flex-wrap items-center gap-2">
          {PDF_FILES.map(([n]) => <LinkBtn key={n} href={artifactUrl(job.id, n)} kind="primary"><Download className="size-3.5" /> {n}</LinkBtn>)}
          <span className="mx-1 h-6 w-px bg-hairline-strong" />
          {TOOL_FILES.map(([n]) => <LinkBtn key={n} href={artifactUrl(job.id, n)}><Download className="size-3.5" /> {n}</LinkBtn>)}
        </div>
      </Card>
      <Panel className="p-6">{md.isLoading ? <Loading text="Loading the report…" /> : md.error ? <ErrorBox error={md.error} /> : <Markdown text={md.data ?? ''} />}</Panel>
    </div>
  )
}

function LogTab({ job }: { job: Job }) {
  const ev = useJobEvents(job.id, isLive(job) || job.summary?.approval_status === 'publishing')
  const ref = useRef<HTMLPreElement>(null)
  const items = ev.data?.items ?? []
  useEffect(() => {
    const el = ref.current
    if (el && el.scrollHeight - el.scrollTop - el.clientHeight < 80) el.scrollTop = el.scrollHeight
  }, [items.length])
  return (
    <Card title="Agent activity log" description={`${items.length} events · newest at the bottom${isLive(job) ? ' · live' : ''}`}>
      <pre ref={ref} className="codebox" style={{ maxHeight: 560 }}>
        {items.length ? items.map((e) => (
          <span key={e.id} className={e.level}><span className="ln" style={{ width: '6.5em' }}>{new Date(e.ts).toLocaleTimeString()}</span>{e.message}</span>
        )) : <span>Waiting for the first event…</span>}
      </pre>
    </Card>
  )
}


function TestsBadge({ status }: { status: string }) {
  const color = status === 'passed' ? '#15803d' : status === 'failed' || status === 'error' ? '#d03b3b' : status === 'running' || status === 'starting' ? 'var(--blue)' : 'var(--ink-3)'
  const label = status === 'passed' ? 'pass' : status === 'failed' ? 'fail' : status === 'running' || status === 'starting' ? 'running' : status.replace('_', ' ')
  return <span className="rounded-md px-1.5 py-0.5 text-[11px] font-semibold text-white" style={{ background: color }}>{label}</span>
}
