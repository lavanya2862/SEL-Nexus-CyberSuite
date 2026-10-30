import { useState, type FormEvent, type ReactNode } from 'react'
import { useNavigate } from 'react-router-dom'
import { ArrowRight, Check, FlaskConical, Loader2 } from 'lucide-react'
import { AgentTile } from '@/components/Agents'
import { Btn, Card, Choice, Field, Notice, PageHeader, Panel, inputCls } from '@/components/kit'
import { post, useCaps } from '@/lib/api'
import { useToast } from '@/lib/toast'
import type { Job } from '@/lib/types'
import { cn } from '@/lib/utils'
import { Link } from 'react-router-dom'

// Which findings the agents remediate: the chosen severity and everything more severe
const SCOPES = [
  { value: 'critical', label: 'Critical only' },
  { value: 'high', label: 'Critical and high' },
  { value: 'medium', label: 'Critical, high and medium' },
  { value: 'low', label: 'All severities (critical to low)' },
  { value: 'info', label: 'All, including informational' },
]

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
  const [ghTests, setGhTests] = useState<boolean | null>(null)
  const [maxF, setMaxF] = useState('')
  const [onFlag, setOnFlag] = useState('draft')
  const [scanners, setScanners] = useState('')
  const [busy, setBusy] = useState(false)

  // Switches default to on when the server can do them, off (and locked) when it can't.
  const llm = useLlm ?? !!c?.llm.enabled
  const pr = createPr ?? !!c?.github_token_configured
  const github = ghTests ?? !!c?.github_token_configured

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setBusy(true)
    const options: Record<string, unknown> = { min_severity: minSev, auto_fix: autoFix, use_llm: llm, create_pr: pr, pr_on_flagged: onFlag,
      github_tests: github && !!c?.github_token_configured }
    if (ref.trim()) options.ref = ref.trim()
    if (maxF) options.max_findings = Number(maxF)
    const list = scanners.split(',').map((s) => s.trim()).filter(Boolean)
    if (list.length) options.scanners = list
    try {
      const r = await post<{ job: Job; deduplicated: boolean }>('/api/v1/jobs', { repo_url: repo.trim(), options })
      if (r.deduplicated) toast('An identical scan is already in progress. Opening it now.')
      navigate(`/runs/${r.job.id}`)
    } catch (err) {
      toast((err as Error).message, true)
      setBusy(false)
    }
  }

  const sc = c?.scanners ?? {}
  return (
    <div className="flex flex-col gap-5">
      <PageHeader title="New scan" description="Initiate an application security assessment of a GitHub repository. The four agents detect, remediate, validate and report on vulnerabilities end to end." />

      <div className="grid grid-cols-1 gap-5 xl:grid-cols-[minmax(0,1.5fr)_minmax(0,1fr)]">
        <Panel className="p-6">
          <form onSubmit={submit} autoComplete="off" className="flex flex-col gap-5">
            <Field label="GitHub repository URL" hint="For example https://github.com/owner/repository. Private repositories require a GitHub token in Settings.">
              <input autoFocus required value={repo} onChange={(e) => setRepo(e.target.value)} placeholder="https://github.com/owner/repository" className={cn(inputCls, 'h-12 text-[15px]')} />
            </Field>
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <Field label="Branch, tag or commit"><input value={ref} onChange={(e) => setRef(e.target.value)} placeholder="Default branch" className={inputCls} /></Field>
              <Field label="Remediation scope" hint="Every finding in the chosen severities is remediated.">
                <Choice field label="Remediation scope" value={minSev} onChange={setMinSev} options={SCOPES} />
              </Field>
            </div>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <Switch on={autoFix} set={setAutoFix} title="Automated remediation" text="The Remediation Agent remediates findings on an isolated branch." />
              <Switch on={llm} set={setUseLlm} disabled={!c?.llm.enabled} title="AI-assisted remediation"
                text={c?.llm.enabled ? `Uses the organisation’s model (${c.llm.model}).` : 'Ask your administrator to configure the organisation’s AI model.'} />
              <Switch on={pr} set={setCreatePr} disabled={!c?.github_token_configured} title="Raise the pull request automatically"
                text={c?.github_token_configured ? 'When off, remediations wait for approval in Approvals. Scans that require review are raised as draft pull requests.' : <>Requires a GitHub token. Configure one in <Link to="/settings" className="text-sky underline">Settings</Link>.</>} />
              <Switch on={github} set={setGhTests} disabled={!c?.github_token_configured} title="CI test validation on GitHub Actions"
                text={c?.github_token_configured ? 'After the scan, the full test suite runs on GitHub Actions. The Remediation Agent resolves failing tests and re-runs them, up to 3 times.' : <>Requires a GitHub token. Configure one in <Link to="/settings" className="text-sky underline">Settings</Link>.</>} />
            </div>
            <details className="rounded-xl border border-hairline p-4">
              <summary className="cursor-pointer text-sm font-medium text-ink-2">Advanced options</summary>
              <div className="mt-4 grid grid-cols-1 gap-4 sm:grid-cols-2">
                <Field label="Maximum AI-assisted remediations (optional)"><input type="number" min={1} max={200} value={maxF} onChange={(e) => setMaxF(e.target.value)} placeholder="All findings in scope" className={inputCls} /></Field>
                <Field label="When validation requires review">
                  <Choice field label="When validation requires review" value={onFlag} onChange={setOnFlag} options={[
                    { value: 'draft', label: 'Raise a draft pull request for investigation' },
                    { value: 'skip', label: 'Hold until manually approved' },
                  ]} />
                </Field>
                <Field label="Scanners (comma-separated)"><input value={scanners} onChange={(e) => setScanners(e.target.value)} placeholder="All available scanners" className={inputCls} /></Field>
              </div>
            </details>
            <div className="flex items-center gap-3">
              <Btn type="submit" disabled={busy || !repo.trim()} className="h-11 px-5 text-[15px]">
                {busy ? <><Loader2 className="size-4 animate-spin" /> Initiating…</> : <>Start scan <ArrowRight className="size-4" /></>}
              </Btn>
              <span className="text-xs text-ink-3">You will be taken to the live scan view.</span>
            </div>
          </form>
        </Panel>

        <div className="flex flex-col gap-5">
          <Card title="Assessment workflow" description="Based on the current configuration of this environment:">
            <ol className="flex flex-col gap-3">
              <Step id="analysis" title="Analysis Agent" text={`${sc.codeql?.available ? 'CodeQL' : 'Built-in SAST rules'}, ${sc.trivy?.available ? 'Trivy' : 'OSV'} and supporting scanners; findings are consolidated and prioritised by risk.`} />
              <Step id="remediation" title="Remediation Agent" text={c?.llm.enabled ? 'Dependency upgrades, rule-based and AI-assisted remediations, one commit per remediation.' : 'Dependency upgrades and rule-based remediations (AI-assisted remediation requires an AI model).'} />
              <Step id="validation" title="Validation Agent" text="Syntax checks, a security-regression guard and a confirmation scan." />
              <Step id="reporting" title="Reporting Agent" text="Assessment report, SARIF file, a diff per remediation and the validation verdict." />
              {github && (
                <li className="flex items-start gap-3">
                  <span className="grid size-8 shrink-0 place-items-center rounded-[10px] bg-well text-sky"><FlaskConical className="size-4" /></span>
                  <div className="text-sm"><div className="font-medium">CI test validation</div><div className="text-ink-3">The remediation branch is pushed and GitHub Actions runs the full test suite. The Remediation Agent resolves failures and re-runs them, up to 3 times.</div></div>
                </li>
              )}
              <li className="flex items-start gap-3">
                <span className="tile-signal grid size-8 shrink-0 place-items-center rounded-[10px]"><Check className="size-4" /></span>
                <div className="text-sm"><div className="font-medium">Human approval</div><div className="text-ink-3">{c?.github_token_configured ? 'A pull request is raised for review (as a draft when a validation check fails).' : 'Download the patch, or configure a GitHub token to raise pull requests.'}</div></div>
              </li>
            </ol>
          </Card>
          {c && !sc.codeql?.available && <Notice tone="warn" title="CodeQL is not installed in this environment">Code analysis falls back to Semgrep, Bandit and the built-in SAST rules. Run <code className="font-mono">scripts/install-codeql.ps1</code> to install it.</Notice>}
          {c && !c.llm.enabled && <Notice tone="warn" title="AI-assisted remediation is unavailable">No AI model is configured on this server. Dependency upgrades and rule-based remediations still apply. Ask your administrator to configure the organisation’s AI model.</Notice>}
          {c && !c.github_token_configured && <Notice tone="warn" title="Remediations cannot be pushed to GitHub">No GitHub token is configured. The patch remains available for download. <Link to="/settings" className="text-sky underline">Configure a token in Settings</Link>.</Notice>}
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
