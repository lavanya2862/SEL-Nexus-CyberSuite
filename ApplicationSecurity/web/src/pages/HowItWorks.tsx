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
      'Runs CodeQL as the primary static analysis (SAST) engine for source code vulnerabilities',
      'Runs Trivy for vulnerable dependencies, exposed secrets and Docker and infrastructure misconfigurations',
      'Normalises all results to a single format and consolidates duplicates reported by multiple scanners',
      'Assigns each finding a risk score and prioritises accordingly, retaining surrounding code for context',
    ], tools: <>{tool('CodeQL', sc.codeql?.available)}{tool('Trivy', sc.trivy?.available)}{tool('Semgrep', sc.semgrep?.available)}{tool('Bandit', sc.bandit?.available)}<StatusTag tone="good" label="OSV.dev" /><StatusTag tone="good" label="Built-in SAST rules" /></> },
    { id: 'remediation', title: 'Remediation Agent', items: [
      'Operates on an isolated ai-remediation/* Git branch; the source branch is never modified',
      'Applies deterministic remediations first: dependency upgrades, lockfile refresh, rule-based rewrites and externalised secrets',
      'Applies AI-assisted remediations to findings that require reasoning, and self-corrects when a change does not apply cleanly',
      'Creates one commit per remediation, so each change can be reviewed or reverted independently',
    ], tools: <><StatusTag tone={c?.llm.enabled ? 'good' : 'warn'} label={`AI model: ${c?.llm.enabled ? c.llm.model : 'Not connected'}`} /><StatusTag tone="good" label="Git" /><StatusTag tone="good" label="npm" /></> },
    { id: 'validation', title: 'Testing & Validation Agent', items: [
      'Static checks: every modified file must still parse',
      'Security-regression guard: rejects suppressions, disabled TLS, skipped tests and removed security controls',
      'Confirmation scan: remediated findings must be resolved and no new findings introduced',
      'CI test validation: the project’s test suite runs on GitHub Actions and the Remediation Agent resolves failing tests',
    ], tools: <><StatusTag tone={c?.github_token_configured ? 'good' : 'warn'} label="GitHub Actions tests" /><StatusTag tone="good" label="Confirmation scan" /><StatusTag tone="good" label="Diff guard" /></> },
    { id: 'reporting', title: 'Reporting Agent', items: [
      'An assessment report covering findings, remediations proposed and applied, and test results',
      'The final verdict: validated, or review required',
      'A SARIF file for GitHub code scanning, the full patch and a diff per remediation',
      'A pull request description with the evidence reviewers require',
    ], tools: <><StatusTag tone="good" label="Markdown" /><StatusTag tone="good" label="SARIF 2.1.0" /><StatusTag tone="good" label="JSON" /></> },
  ]
  return (
    <div className="flex flex-col gap-5">
      <PageHeader title="How it works" description="How the four security agents detect, remediate, validate and report on vulnerabilities in a repository, and where human approval is required." />
      <Card title="From repository to pull request" description="Every scan proceeds through these six stages, in order.">
        <PipelineFlow stages={mergedStages([]).map((s) => ({ ...s, status: 'completed' }))} />
        <div className="mt-4"><Notice tone="info" title="Optional: CI test validation on GitHub Actions">Select <b>Run tests on GitHub</b> on a scan, or enable it on New scan. The remediation branch is pushed with a test workflow and GitHub Actions runs the full test suite. When a test fails, the Remediation Agent analyses the failure, corrects the code (or a defective test) and pushes again, triggering a new test run. The cycle ends when all tests pass or after 3 attempts. Changes that skip or delete tests are rejected.</Notice></div>
        <div className="mt-3"><Notice tone="info" title="Human approval is always required">Validated remediations are raised as a pull request only after approval. If validation fails, the change set requires review and is raised as a draft pull request labelled <span className="font-mono">needs-investigation</span>, or held.</Notice></div>
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
        <Card title="Architecture">
          <ul className="flex list-disc flex-col gap-1.5 pl-5 text-sm text-ink-2">
            <li><b className="text-ink">Python</b> orchestrates the agents in sequence and records each stage in real time.</li>
            <li><b className="text-ink">FastAPI</b> service: submit repositories, monitor progress, download reports, approve pull requests and query the Security Assistant.</li>
            <li><b className="text-ink">Workers</b> process jobs from a database queue (SQLite or PostgreSQL) and scale horizontally.</li>
            <li><b className="text-ink">GitHub Actions</b>: <span className="font-mono">examples/github-actions/ai-remediation.yml</span> runs CodeQL and Trivy in CI and submits the results.</li>
            <li><b className="text-ink">SEL Nexus CyberSuite</b>: single sign-on through the suite’s sign-in page, verified by this application.</li>
          </ul>
        </Card>
        <Card title="Scanners in this environment" description="Ready: installed and enabled.">
          <DTable head={[['Scanner'], ['State']]} minWidth={420}>
            {Object.entries(sc).map(([k, v]) => (
              <tr key={k}>
                <td><div className="font-medium">{k} {v.primary && <StatusTag tone="info" label="Primary" />}</div><div className="text-xs text-ink-3">{v.description}</div></td>
                <td>{v.available && v.enabled ? <StatusTag tone="good" label="Ready" /> : v.enabled ? <StatusTag tone="warn" label="Not installed" /> : <StatusTag tone="idle" label="Disabled" />}</td>
              </tr>
            ))}
          </DTable>
        </Card>
      </div>
    </div>
  )
}
