import { useState, type FormEvent, type ReactNode } from 'react'
import { useNavigate } from 'react-router-dom'
import { ArrowRight, Check, Loader2 } from 'lucide-react'
import { AgentTile } from '@/components/Agents'
import { Btn, Card, Field, Notice, PageHeader, Panel, inputCls } from '@/components/kit'
import { post, useCaps } from '@/lib/api'
import { SEVERITIES, sevLabel } from '@/lib/labels'
import { useToast } from '@/lib/toast'
import type { Job } from '@/lib/types'
import { cn } from '@/lib/utils'
import { Link } from 'react-router-dom'

export function NewScan() {
  const caps = useCaps()
  const c = caps.data
  const navigate = useNavigate()
  const toast = useToast()
  const [repo, setRepo] = useState('')
  const [ref, setRef] = useState('')
  const [minSev, setMinSev] = useState('low')
  const [autoFix, setAutoFix] = useState(true)
  const [useLlm, setUseLlm] = useState<boolean | null>(null)
  const [createPr, setCreatePr] = useState<boolean | null>(null)
  const [runTests, setRunTests] = useState<boolean | null>(null)
  const [maxF, setMaxF] = useState('')
  const [onFlag, setOnFlag] = useState('draft')
  const [testCmd, setTestCmd] = useState('')
  const [scanners, setScanners] = useState('')
  const [busy, setBusy] = useState(false)

  // Switches default to on when the server can do them, off (and locked) when it can't.
  const llm = useLlm ?? !!c?.llm.enabled
  const pr = createPr ?? !!c?.github_token_configured
  const tests = runTests ?? !!c?.sandbox.available

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setBusy(true)
    const options: Record<string, unknown> = { min_severity: minSev, auto_fix: autoFix, use_llm: llm, create_pr: pr, pr_on_flagged: onFlag }
    if (ref.trim()) options.ref = ref.trim()
    if (maxF) options.max_findings = Number(maxF)
    if (testCmd.trim()) options.test_command = testCmd.trim()
    if (tests) options.run_tests = true
    const list = scanners.split(',').map((s) => s.trim()).filter(Boolean)
    if (list.length) options.scanners = list
    try {
      const r = await post<{ job: Job; deduplicated: boolean }>('/api/v1/jobs', { repo_url: repo.trim(), options })
      if (r.deduplicated) toast('An identical run is already in progress: opening it.')
      navigate(`/runs/${r.job.id}`)
    } catch (err) {
      toast((err as Error).message, true)
      setBusy(false)
    }
  }

  const sc = c?.scanners ?? {}
  return (
    <div className="flex flex-col gap-5">
      <PageHeader title="New scan" description="Paste a GitHub repository link: that is the only thing you need. The four agents do the rest, and nothing is merged without your approval." />

      <div className="grid grid-cols-1 gap-5 xl:grid-cols-[minmax(0,1.5fr)_minmax(0,1fr)]">
        <Panel className="p-6">
          <form onSubmit={submit} autoComplete="off" className="flex flex-col gap-5">
            <Field label="GitHub repository" hint="For example https://github.com/owner/repository. Private repositories need a GitHub token (Settings).">
              <input autoFocus required value={repo} onChange={(e) => setRepo(e.target.value)} placeholder="https://github.com/owner/repository" className={cn(inputCls, 'h-12 text-[15px]')} />
            </Field>
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <Field label="Branch, tag or commit"><input value={ref} onChange={(e) => setRef(e.target.value)} placeholder="default branch" className={inputCls} /></Field>
              <Field label="Fix issues from this severity up">
                <select value={minSev} onChange={(e) => setMinSev(e.target.value)} className={inputCls}>
                  {SEVERITIES.slice(0, 5).map((s) => <option key={s} value={s}>{sevLabel(s)}</option>)}
                </select>
              </Field>
            </div>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <Switch on={autoFix} set={setAutoFix} title="Apply fixes" text="The Remediation Agent fixes findings on a separate branch." />
              <Switch on={llm} set={setUseLlm} disabled={!c?.llm.enabled} title="AI-written code fixes"
                text={c?.llm.enabled ? `Uses ${c.llm.model}.` : <>Needs an AI model: <Link to="/settings" className="text-sky underline">Settings</Link>.</>} />
              <Switch on={pr} set={setCreatePr} disabled={!c?.github_token_configured} title="Open the pull request by itself"
                text={c?.github_token_configured ? 'Off = you approve first in Approvals. Flagged runs become draft PRs.' : <>Needs a GitHub token: <Link to="/settings" className="text-sky underline">Settings</Link>.</>} />
              <Switch on={tests} set={setRunTests} disabled={!c?.sandbox.available} title="Run the project’s tests"
                text={c?.sandbox.available ? 'Before vs. after, in an isolated sandbox.' : 'Needs SANDBOX_MODE=docker on the server.'} />
            </div>
            <details className="rounded-xl border border-hairline p-4">
              <summary className="cursor-pointer text-sm font-medium text-ink-2">More options</summary>
              <div className="mt-4 grid grid-cols-1 gap-4 sm:grid-cols-2">
                <Field label="Max AI fixes per run"><input type="number" min={1} max={200} value={maxF} onChange={(e) => setMaxF(e.target.value)} placeholder="server default" className={inputCls} /></Field>
                <Field label="When validation is flagged">
                  <select value={onFlag} onChange={(e) => setOnFlag(e.target.value)} className={inputCls}>
                    <option value="draft">Open a draft PR (needs-investigation)</option>
                    <option value="skip">Hold until approved by hand</option>
                  </select>
                </Field>
                <Field label="Test command"><input value={testCmd} onChange={(e) => setTestCmd(e.target.value)} placeholder="detected automatically" className={inputCls} /></Field>
                <Field label="Scanners (comma-separated)"><input value={scanners} onChange={(e) => setScanners(e.target.value)} placeholder="all available" className={inputCls} /></Field>
              </div>
            </details>
            <div className="flex items-center gap-3">
              <Btn type="submit" disabled={busy || !repo.trim()} className="h-11 px-5 text-[15px]">
                {busy ? <><Loader2 className="size-4 animate-spin" /> Starting…</> : <>Run pipeline <ArrowRight className="size-4" /></>}
              </Btn>
              <span className="text-xs text-ink-3">You’ll go straight to the live run.</span>
            </div>
          </form>
        </Panel>

        <div className="flex flex-col gap-5">
          <Card title="What will happen" description="With the current setup on this server:">
            <ol className="flex flex-col gap-3">
              <Step id="analysis" title="Analysis Agent" text={`${sc.codeql?.available ? 'CodeQL' : 'Built-in code rules'} + ${sc.trivy?.available ? 'Trivy' : 'OSV'} + supporting scanners, then remove duplicates and rank by risk.`} />
              <Step id="remediation" title="Remediation Agent" text={c?.llm.enabled ? 'Dependency upgrades, safe rewrites and AI-written fixes: one commit per fix.' : 'Dependency upgrades and safe rewrites (AI fixes need a model).'} />
              <Step id="validation" title="Validation Agent" text={`Syntax checks, security-regression guard${c?.sandbox.available ? ', the project’s tests' : ''} and a fresh security scan.`} />
              <Step id="reporting" title="Reporting Agent" text="Report, SARIF file, one diff per fix and the validation verdict." />
              <li className="flex items-start gap-3">
                <span className="tile-signal grid size-8 shrink-0 place-items-center rounded-[10px]"><Check className="size-4" /></span>
                <div className="text-sm"><div className="font-medium">You approve</div><div className="text-ink-3">{c?.github_token_configured ? 'A pull request opens for review (draft if flagged).' : 'Download the patch, or add a GitHub token to open pull requests.'}</div></div>
              </li>
            </ol>
          </Card>
          {c && !sc.codeql?.available && <Notice tone="warn" title="CodeQL is not installed on this server">Code analysis falls back to Semgrep, Bandit and the built-in rules. Run <code className="font-mono">scripts/install-codeql.ps1</code> to install it.</Notice>}
          {c && !c.llm.enabled && <Notice tone="warn" title="No AI model: AI-written fixes are off">Dependency upgrades and safe rewrites still run. <Link to="/settings" className="text-sky underline">Add a model in Settings</Link>.</Notice>}
          {c && !c.github_token_configured && <Notice tone="warn" title="No GitHub token: fixes cannot be pushed">You can still download the patch. <Link to="/settings" className="text-sky underline">Add a token in Settings</Link>.</Notice>}
        </div>
      </div>
    </div>
  )
}

function Step({ id, title, text }: { id: 'analysis' | 'remediation' | 'validation' | 'reporting'; title: string; text: string }) {
  return (
    <li className="flex items-start gap-3">
      <AgentTile id={id} size="sm" />
      <div className="text-sm"><div className="font-medium">{title}</div><div className="text-ink-3">{text}</div></div>
    </li>
  )
}

function Switch({ on, set, disabled, title, text }: { on: boolean; set: (v: boolean) => void; disabled?: boolean; title: string; text: ReactNode }) {
  return (
    <label className={cn('flex cursor-pointer items-start gap-3 rounded-xl border p-3 transition-colors', on && !disabled ? 'border-blue/50 bg-blue/8' : 'border-hairline', disabled && 'cursor-not-allowed opacity-60')}>
      <input type="checkbox" className="peer sr-only" checked={on && !disabled} disabled={disabled} onChange={(e) => set(e.target.checked)} />
      <span className={cn('mt-0.5 flex h-5 w-9 shrink-0 items-center rounded-full p-0.5 transition-colors peer-focus-visible:ring-2 peer-focus-visible:ring-sky', on && !disabled ? 'bg-blue' : 'bg-hairline-strong')}>
        <span className={cn('size-4 rounded-full bg-white shadow transition-transform', on && !disabled && 'translate-x-4')} />
      </span>
      <span className="text-sm"><span className="block font-medium text-ink">{title}</span><span className="block text-xs text-ink-3">{text}</span></span>
    </label>
  )
}
