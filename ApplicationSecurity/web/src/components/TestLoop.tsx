// The Test & Fix loop on a run (remediation/testloop.py): push the fix branch, GitHub Actions runs every test,
// the Remediation Agent fixes failures and pushes again, up to three times. The button starts it; the tab follows it live.
import type { CSSProperties } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import {
  ArrowDown, Bot, CheckCircle2, ExternalLink, FlaskConical, GitBranch, Loader2, Play, RotateCcw, Square, Upload, XCircle,
} from 'lucide-react'
import { Btn, Card, Chip, Empty, Notice, Panel, StatusTag } from '@/components/kit'
import { post, testsActive, useCaps } from '@/lib/api'
import { ago } from '@/lib/format'
import { statusColor } from '@/lib/theme'
import { useToast } from '@/lib/toast'
import type { Job, TestLoop, TestRun } from '@/lib/types'

function useTestActions(job: Job) {
  const qc = useQueryClient()
  const toast = useToast()
  const refresh = () => qc.invalidateQueries({ queryKey: ['job', job.id] })
  const start = useMutation({
    mutationFn: () => post<{ status: string }>(`/api/v1/jobs/${job.id}/tests`),
    onSuccess: (r) => { toast(r.status === 'running' ? 'CI test validation is already in progress.' : 'CI test validation started. Pushing the remediation branch to GitHub Actions…'); refresh() },
    onError: (e) => toast((e as Error).message, true),
  })
  const stop = useMutation({
    mutationFn: () => post(`/api/v1/jobs/${job.id}/tests/cancel`),
    onSuccess: () => { toast('Stopping after the current step…'); refresh() },
  })
  return { start, stop }
}

/** "Run tests on GitHub" for the run header. */
export function RunTestsButton({ job }: { job: Job }) {
  const { start } = useTestActions(job)
  const caps = useCaps()
  const active = testsActive(job)
  if (job.status !== 'completed' || job.can_act === false) return null
  return (
    <Btn kind="quiet" disabled={active || start.isPending || !caps.data?.github_token_configured} onClick={() => start.mutate()}
      title={caps.data?.github_token_configured ? 'Run the full test suite on GitHub Actions; the Remediation Agent resolves failures' : 'Requires a GitHub token (Settings)'}>
      {active ? <><Loader2 className="size-4 animate-spin" /> Tests in progress…</> : <><FlaskConical className="size-4" /> Run tests on GitHub</>}
    </Btn>
  )
}

const STATUS: Record<TestLoop['status'], { tone: 'good' | 'warn' | 'bad' | 'info' | 'idle'; title: string }> = {
  starting: { tone: 'info', title: 'Starting CI test validation' },
  running: { tone: 'info', title: 'CI tests in progress' },
  passed: { tone: 'good', title: 'All tests passed' },
  failed: { tone: 'bad', title: 'Tests are still failing: manual investigation required' },
  no_tests: { tone: 'warn', title: 'No tests found' },
  error: { tone: 'bad', title: 'The test run could not complete' },
  cancelled: { tone: 'warn', title: 'Stopped' },
  interrupted: { tone: 'warn', title: 'Interrupted' },
}

const HOW = [
  { icon: Upload, title: 'Push the remediation branch', text: 'Together with a workflow that runs the repository’s full test suite.' },
  { icon: FlaskConical, title: 'GitHub Actions runs the tests', text: 'On GitHub-hosted runners, as the repository’s own CI would.' },
  { icon: Bot, title: 'Remediation Agent resolves failures', text: 'It analyses each failure, corrects the code (or a defective test) and pushes, triggering a new test run.' },
  { icon: CheckCircle2, title: 'Until all tests pass, or 3 attempts', text: 'The branch is then ready for approval as a pull request.' },
]

/** The "GitHub tests" tab of a run. */
export function TestsTab({ job }: { job: Job }) {
  const t = job.summary?.tests
  const caps = useCaps()
  const { start, stop } = useTestActions(job)
  const active = testsActive(job)
  const tokenOk = !!caps.data?.github_token_configured

  return (
    <div className="flex flex-col gap-5">
      <Card title="CI test validation on GitHub Actions" description="The repository’s full test suite runs on the remediation branch; the Remediation Agent resolves failing tests and re-runs them."
        action={job.can_act === false ? undefined : active ? <Btn kind="quiet" onClick={() => stop.mutate()} disabled={stop.isPending}><Square className="size-3.5" /> Stop</Btn>
          : <Btn onClick={() => start.mutate()} disabled={!tokenOk || start.isPending}>{t ? <><RotateCcw className="size-4" /> Re-run</> : <><Play className="size-4" /> Run tests on GitHub</>}</Btn>}>
        <ol className="grid grid-cols-1 gap-2 sm:grid-cols-2 xl:grid-cols-4">
          {HOW.map((s, i) => (
            <li key={s.title} className="flex items-start gap-3 rounded-xl border border-hairline bg-well/40 p-3">
              <span className="grid size-8 shrink-0 place-items-center rounded-[9px] bg-panel text-sky"><s.icon className="size-4" /></span>
              <span className="min-w-0 text-sm">
                <span className="block text-[11px] font-semibold uppercase tracking-[0.1em] text-ink-3">Step {i + 1}</span>
                <span className="block font-medium">{s.title}</span>
                <span className="block text-xs text-ink-3">{s.text}</span>
              </span>
            </li>
          ))}
        </ol>
        {!tokenOk && <div className="mt-4"><Notice tone="warn" title="A GitHub token is required">CI test validation pushes the remediation branch and requires Contents and Workflows (read &amp; write) and Actions (read) on the repository. <Link to="/settings" className="text-sky underline">Open Settings</Link></Notice></div>}
        {tokenOk && caps.data && !caps.data.llm.enabled && <div className="mt-4"><Notice tone="warn" title="No AI model connected">Tests will run, but failures must be resolved manually. <Link to="/settings" className="text-sky underline">Configure a model in Settings</Link>.</Notice></div>}
      </Card>

      {!t ? <Empty text="CI test validation has not been run for this scan yet." /> : <Progress job={job} t={t} />}
    </div>
  )
}

function Progress({ job, t }: { job: Job; t: TestLoop }) {
  const s = STATUS[t.status] ?? { tone: 'idle' as const, title: t.status }
  const active = t.status === 'starting' || t.status === 'running'
  const branchUrl = t.branch && t.branch_pushed ? `${job.repo_url}/tree/${t.branch}` : null
  return (
    <>
      <Notice tone={s.tone} title={<span className="flex items-center gap-2">{active && <Loader2 className="size-4 animate-spin" />}{s.title}</span>}>
        {active ? `${t.phase || 'In progress…'} · this page updates automatically` : t.message}
      </Notice>
      <div className="flex flex-wrap items-center gap-2 text-sm">
        {t.branch && (branchUrl
          ? <a href={branchUrl} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1.5 rounded-md border border-hairline px-2 py-1 text-xs text-ink-2 hover:bg-well"><GitBranch className="size-3.5" /> {t.branch} <ExternalLink className="size-3" /></a>
          : <Chip><GitBranch className="mr-1.5 size-3.5" /> {t.branch}</Chip>)}
        {t.test_command && <Chip>Command <span className="ml-1 font-mono">{t.test_command}</span></Chip>}
        <Chip>Remediation Agent attempt {t.attempt} of {t.max_attempts}</Chip>
        {t.started_at && <span className="text-xs text-ink-3">started {ago(t.started_at)}</span>}
      </div>
      {t.runs.length > 0 && (
        <ol className="flex flex-col gap-2">
          {t.runs.map((r, i) => <RunStep key={r.n} run={r} last={i === t.runs.length - 1} />)}
        </ol>
      )}
    </>
  )
}

function RunStep({ run, last }: { run: TestRun; last: boolean }) {
  const done = run.status === 'completed'
  const ok = run.conclusion === 'success'
  const color = !done ? 'var(--blue)' : ok ? statusColor.good : statusColor.critical
  const Icon = !done ? Loader2 : ok ? CheckCircle2 : XCircle
  return (
    <li className="flex flex-col gap-2">
      <Panel className="p-5">
        <div className="flex flex-wrap items-center gap-3">
          <span className="grid size-9 place-items-center rounded-[10px]" style={{ color, background: `color-mix(in oklab, ${color} 16%, transparent)` } as CSSProperties}>
            <Icon className={`size-4 ${!done ? 'animate-spin' : ''}`} />
          </span>
          <div className="min-w-0 flex-1">
            <div className="font-semibold">Test run {run.n}</div>
            <div className="text-xs text-ink-3">{!done ? `${run.status === 'queued' ? 'Queued on GitHub Actions' : 'Running on GitHub Actions'}…` : ok ? 'All tests passed' : `${run.failed.length || 'Some'} test(s) failed`} · commit <span className="font-mono">{run.sha.slice(0, 8)}</span></div>
          </div>
          {done && <StatusTag tone={ok ? 'good' : 'bad'} label={run.conclusion ?? '?'} />}
          {run.url && <a href={run.url} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-sm font-medium text-sky hover:underline">Open on GitHub <ExternalLink className="size-3.5" /></a>}
        </div>
        {run.failed.length > 0 && (
          <ul className="mt-3 flex flex-col gap-1 rounded-lg bg-well/60 p-3 font-mono text-xs text-ink-2">
            {run.failed.slice(0, 8).map((f) => <li key={f} className="[overflow-wrap:anywhere]">✕ {f}</li>)}
            {run.failed.length > 8 && <li className="text-ink-3">+{run.failed.length - 8} more</li>}
          </ul>
        )}
        {run.fix_error && <div className="mt-3"><Notice tone="bad" title="The Remediation Agent could not resolve this failure">{run.fix_error}</Notice></div>}
      </Panel>
      {run.fix && (
        <>
          <ArrowDown className="mx-auto size-4 text-ink-3" />
          <Panel className="p-5" style={{ '--tint': 'var(--violet)' } as CSSProperties}>
            <div className="flex flex-wrap items-center gap-3">
              <span className="grid size-9 place-items-center rounded-[10px]" style={{ color: 'var(--violet)', background: 'color-mix(in oklab, var(--violet) 16%, transparent)' }}><Bot className="size-4" /></span>
              <div className="min-w-0 flex-1">
                <div className="font-semibold">Remediation Agent correction {run.n}</div>
                <div className="text-xs text-ink-3">Committed <span className="font-mono">{(run.fix.commit ?? '').slice(0, 8)}</span> and pushed, triggering test run {run.n + 1}</div>
              </div>
              {run.fix.touched_tests && <StatusTag tone="warn" label="Test modified: review required" />}
            </div>
            <p className="mt-3 text-sm text-ink-2">{run.fix.explanation}</p>
            <div className="mt-2 flex flex-wrap gap-1.5">{run.fix.files.map((f) => <Chip key={f}><span className="font-mono">{f}</span></Chip>)}</div>
          </Panel>
          {last && <ArrowDown className="mx-auto size-4 text-ink-3" />}
        </>
      )}
    </li>
  )
}
