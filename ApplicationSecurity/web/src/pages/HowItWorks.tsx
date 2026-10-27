import type { CSSProperties, ReactNode } from 'react'
import { AgentTile } from '@/components/Agents'
import { Card, DTable, Notice, PageHeader, Panel, StatusTag } from '@/components/kit'
import { PipelineFlow } from '@/components/Pipeline'
import { useCaps } from '@/lib/api'
import { AGENTS, mergedStages } from '@/lib/labels'
import type { AgentId } from '@/lib/types'

export function HowItWorks() {
  const caps = useCaps()
  const c = caps.data
  const sc = c?.scanners ?? {}
  const tool = (name: string, ok?: boolean) => <StatusTag key={name} tone={ok ? 'good' : 'warn'} label={`${name}${ok ? '' : ' (fallback)'}`} />
  const agents: { id: AgentId; title: string; items: string[]; tools: ReactNode }[] = [
    { id: 'analysis', title: 'Vulnerability Analysis & Prioritization Agent', items: [
      'Runs CodeQL as the main scanner for vulnerabilities in the source code',
      'Runs Trivy for vulnerable libraries, leaked secrets and Docker / infrastructure misconfigurations',
      'Puts every result in one format and removes duplicates found by several scanners',
      'Gives each finding a risk score and ranks them; keeps the surrounding code for context',
    ], tools: <>{tool('CodeQL', sc.codeql?.available)}{tool('Trivy', sc.trivy?.available)}{tool('Semgrep', sc.semgrep?.available)}{tool('Bandit', sc.bandit?.available)}<StatusTag tone="good" label="OSV.dev" /><StatusTag tone="good" label="Built-in rules" /></> },
    { id: 'remediation', title: 'Remediation Agent', items: [
      'Works on a separate ai-remediation/* Git branch: the original code is never touched',
      'Safe, predictable fixes first: library upgrades, lockfile refresh, safe rewrites, secrets moved to environment variables',
      'Code fixes it writes (with its AI model) for findings that need reasoning, corrected by itself when a fix does not apply',
      'One commit per fix, so each change can be reviewed or reverted on its own',
    ], tools: <><StatusTag tone={c?.llm.enabled ? 'good' : 'warn'} label={`AI model: ${c?.llm.enabled ? c.llm.model : 'not connected'}`} /><StatusTag tone="good" label="Git" /><StatusTag tone="good" label="npm" /></> },
    { id: 'validation', title: 'Testing & Validation Agent', items: [
      'Static checks: every edited file must still parse',
      'Security-regression guard: rejects suppressions, disabled TLS, skipped tests or removed security controls',
      'Security rescan: the findings must be gone and nothing new may appear',
      'The project’s own tests run on GitHub Actions (Run tests on GitHub); the Remediation Agent fixes failing tests',
    ], tools: <><StatusTag tone={c?.github_token_configured ? 'good' : 'warn'} label="GitHub Actions tests" /><StatusTag tone="good" label="Rescan" /><StatusTag tone="good" label="Diff guard" /></> },
    { id: 'reporting', title: 'Reporting Agent', items: [
      'A report of what was found, the fixes proposed and applied, and the test results',
      'The final verdict: validated, or needs review',
      'A SARIF file for GitHub code scanning, the full patch and one diff per fix',
      'The pull request description with the evidence reviewers need',
    ], tools: <><StatusTag tone="good" label="Markdown" /><StatusTag tone="good" label="SARIF 2.1.0" /><StatusTag tone="good" label="JSON" /></> },
  ]
  return (
    <div className="flex flex-col gap-5">
      <PageHeader title="How it works" description="How the four security agents find, fix, validate and report the vulnerabilities in a repository, and where a person decides." />
      <Card title="From GitHub link to pull request" description="Every scan goes through these six steps, in this order.">
        <PipelineFlow stages={mergedStages([]).map((s) => ({ ...s, status: 'completed' }))} />
        <div className="mt-4"><Notice tone="info" title="Optional: test on GitHub, failures fixed by the Remediation Agent">Press <b>Run tests on GitHub</b> on a run (or tick it on New scan). The fix branch is pushed with a test workflow, GitHub Actions runs every test in the repository, and when a test fails the Remediation Agent reads the failure, fixes the code (or a test that is itself wrong), and pushes again, which runs the tests again. It stops when everything passes or after 3 fixes. Fixes that skip or delete tests are rejected.</Notice></div>
        <div className="mt-3"><Notice tone="info" title="A person always decides">Validated fixes become a pull request only after you approve them. If validation fails, the change set needs review: it opens as a draft pull request labelled <span className="font-mono">needs-investigation</span> (or is held back).</Notice></div>
      </Card>
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
        {agents.map((a) => (
          <Panel key={a.id} className="flex flex-col gap-4 p-6" style={{ '--tint': AGENTS[a.id].tone } as CSSProperties}>
            <div className="flex items-center gap-3">
              <AgentTile id={a.id} />
              <div><div className="text-[11px] font-semibold uppercase tracking-[0.1em] text-ink-3">Agent {AGENTS[a.id].n}</div><h3 className="font-semibold">{a.title}</h3></div>
            </div>
            <ul className="flex list-disc flex-col gap-1 pl-5 text-sm text-ink-2">{a.items.map((i) => <li key={i}>{i}</li>)}</ul>
            <div className="mt-auto flex flex-wrap gap-1.5 border-t border-hairline pt-4">{a.tools}</div>
          </Panel>
        ))}
      </div>
      <div className="grid grid-cols-1 gap-5 xl:grid-cols-2">
        <Card title="Behind the scenes">
          <ul className="flex list-disc flex-col gap-1.5 pl-5 text-sm text-ink-2">
            <li><b className="text-ink">Python</b> runs the agents in order and records each step live.</li>
            <li><b className="text-ink">FastAPI</b> service: submit a GitHub link, follow progress, download reports, approve pull requests, chat.</li>
            <li><b className="text-ink">Workers</b> take jobs from a database queue (SQLite or PostgreSQL) and can be scaled out.</li>
            <li><b className="text-ink">GitHub Actions</b>: <span className="font-mono">examples/github-actions/ai-remediation.yml</span> runs CodeQL and Trivy in CI and feeds them in.</li>
            <li><b className="text-ink">SEL Nexus CyberSuite</b>: you sign in once on the suite’s sign-in page; this site checks that sign-in.</li>
          </ul>
        </Card>
        <Card title="Scanners on this server" description="Ready = installed and switched on.">
          <DTable head={[['Scanner'], ['State']]} minWidth={420}>
            {Object.entries(sc).map(([k, v]) => (
              <tr key={k}>
                <td><div className="font-medium">{k} {v.primary && <StatusTag tone="info" label="main" />}</div><div className="text-xs text-ink-3">{v.description}</div></td>
                <td>{v.available && v.enabled ? <StatusTag tone="good" label="Ready" /> : v.enabled ? <StatusTag tone="warn" label="Not installed" /> : <StatusTag tone="idle" label="Switched off" />}</td>
              </tr>
            ))}
          </DTable>
        </Card>
      </div>
    </div>
  )
}
