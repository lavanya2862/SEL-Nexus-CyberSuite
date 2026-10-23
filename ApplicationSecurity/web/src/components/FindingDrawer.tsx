// The details of one finding, in a drawer from the right: first the problem (what it is, where, the code, why it ranks
// where it does), then what our agents did about it (the Remediation Agent's fix and diff, the Validation Agent's
// checks). Opened from any table on any page.
import { ExternalLink, Sparkles } from 'lucide-react'
import { Sheet, SheetContent, SheetDescription, SheetTitle } from '@/components/ui/sheet'
import { CodeView, Diff, Markdown } from '@/components/Code'
import { Chip, FixStatusTag, Loading, Notice, RiskScore, SevTag, StatusTag, VerdictTag } from '@/components/kit'
import { useJob, useJobResults } from '@/lib/api'
import { FIX_STATUS, METHOD, detectedBy, findingType } from '@/lib/labels'
import { usePanels } from '@/lib/panels'
import type { Check, Finding } from '@/lib/types'

export function FindingDrawer() {
  const { finding, closeFinding } = usePanels()
  return (
    <Sheet open={!!finding} onOpenChange={(o) => !o && closeFinding()}>
      <SheetContent side="right" className="w-full gap-0 overflow-y-auto border-hairline bg-panel p-0 sm:max-w-[640px]">
        {finding && <Body jobId={finding.jobId} findingId={finding.findingId} />}
      </SheetContent>
    </Sheet>
  )
}

function Body({ jobId, findingId }: { jobId: string; findingId: string }) {
  const { openChat } = usePanels()
  const job = useJob(jobId)
  const { report, findings } = useJobResults(jobId, true)
  const f = findings.data?.find((x) => x.finding_id === findingId)
  if (findings.isLoading || report.isLoading) return <div className="p-6"><SheetTitle className="sr-only">Finding</SheetTitle><Loading /></div>
  if (!f) return <div className="p-6"><SheetTitle>Finding not found</SheetTitle><SheetDescription>It may belong to an older scan.</SheetDescription></div>

  const fixes = report.data?.fixes ?? []
  const idx = fixes.findIndex((x) => x.finding_ids.includes(findingId))
  const fix = idx >= 0 ? fixes[idx] : null
  const checks: Check[] = fix ? (report.data?.validation_checks ?? []).filter((c) => c.fix_index === idx) : []
  const refs = (f.references ?? []).filter((u) => /^https?:\/\//.test(u))
  const j = job.data
  const fixInfo = FIX_STATUS[f.fix_status]

  return (
    <div className="flex flex-col">
      <div className="sticky top-0 z-10 border-b border-hairline bg-panel px-6 pb-4 pt-6 pr-14">
        <div className="flex flex-wrap items-center gap-2">
          <SevTag sev={f.severity} />
          <Chip>risk <span className="ml-1"><RiskScore score={f.priority_score} /></span></Chip>
          <Chip>#{f.priority_rank ?? '?'} in this scan</Chip>
          <FixStatusTag s={f.fix_status} />
          <Chip>{findingType(f)}</Chip>
        </div>
        <SheetTitle className="mt-3 text-lg leading-snug">{f.title}</SheetTitle>
        <SheetDescription className="mt-1">{j ? `${j.repo} · found by ${detectedBy(f)}` : `Found by ${detectedBy(f)}`}</SheetDescription>
        <div className="mt-3 flex flex-wrap gap-2">
          <button onClick={() => openChat({ type: 'finding', jobId, findingId, label: f.title })} className="btn-blue inline-flex h-8 items-center gap-1.5 rounded-lg px-3 text-xs font-medium">
            <Sparkles className="size-3.5" /> Ask the Security Assistant
          </button>
          {f.file_path && j?.repo_url && j.commit && (
            <a target="_blank" rel="noopener noreferrer" href={`${j.repo_url}/blob/${j.commit}/${f.file_path}${f.line ? `#L${f.line}` : ''}`}
              className="inline-flex h-8 items-center gap-1.5 rounded-lg border border-hairline-strong px-3 text-xs font-medium text-ink-2 hover:bg-well">
              View on GitHub <ExternalLink className="size-3.5" />
            </a>
          )}
        </div>
      </div>

      <div className="flex flex-col gap-6 px-6 py-5">


        {f.package_name && (
          <Section title="The problem: a vulnerable dependency">
            <dl className="grid grid-cols-[140px_minmax(0,1fr)] gap-x-4 gap-y-2 text-sm">
              <Row k="Package" v={<span className="font-mono">{f.package_name} <span className="text-ink-3">({f.ecosystem})</span></span>} />
              <Row k="Installed" v={<span className="font-mono">{f.installed_version}</span>} />
              <Row k="Fixed in" v={<span className="font-mono">{f.fixed_version || 'no patched release published'}</span>} />
              <Row k="Manifest" v={<span className="font-mono">{f.file_path}</span>} />
            </dl>
          </Section>
        )}

        {f.description && <Section title={f.package_name ? 'What the vulnerability allows' : 'The problem'}><Markdown text={f.description.slice(0, 4000)} className="text-[13px]" /></Section>}
        {f.code_context && (
          <Section title="Where it is in the code">
            <CodeView code={f.code_context} start={f.context_start_line ?? 1} from={f.line ?? 0} to={f.end_line ?? f.line ?? 0} />
          </Section>
        )}
        {!!f.priority_reasons?.length && (
          <Section title="Why it is ranked this high">
            <div className="flex flex-wrap gap-1.5">{f.priority_reasons.map((r) => <Chip key={r}>{r}</Chip>)}</div>
          </Section>
        )}
        <Section title="What our agents did about it">
          <Notice tone={fixInfo?.tone === 'good' ? 'good' : fixInfo?.tone === 'warn' || fixInfo?.tone === 'bad' ? 'warn' : 'info'} title={fixInfo?.label ?? f.fix_status}>
            {f.fix_note || fixInfo?.hint || 'Not attempted.'}
          </Notice>
          {fix && (
            <div className="mt-3 rounded-xl border border-hairline p-4">
              <div className="text-[11px] font-semibold uppercase tracking-[0.1em] text-ink-3">Fix #{idx + 1} · made by the Remediation Agent</div>
              <div className="mt-1 text-sm font-semibold">{fix.summary}</div>
              <div className="mt-2 flex flex-wrap items-center gap-2 text-xs">
                <StatusTag tone="info" label={METHOD[fix.method]?.label ?? fix.method} />
                <VerdictTag v={fix.validation_status} />
                <span className="font-mono text-ink-3">{(fix.commit ?? '').slice(0, 10)}</span>
              </div>
              {fix.explanation && <p className="mt-2 text-sm text-ink-2">{fix.explanation}</p>}
              {checks.length > 0 && <><div className="mt-3 text-[11px] font-semibold uppercase tracking-[0.1em] text-ink-3">Checked by the Validation Agent</div><ChecksList checks={checks} /></>}
              <div className="mt-3"><Diff diff={fix.diff} /></div>
            </div>
          )}
        </Section>

        <Section title="Details">
          <dl className="grid grid-cols-[140px_minmax(0,1fr)] gap-x-4 gap-y-2 text-sm">
            <Row k="Detected by" v={detectedBy(f)} />
            <Row k="Category" v={f.category.replace(/_/g, ' ')} />
            {f.rule_id && <Row k="Rule" v={<span className="font-mono">{f.rule_id}</span>} />}
            {!!f.cwe?.length && <Row k="CWE" v={f.cwe.map((c) => <a key={c} className="mr-2 text-sky underline" target="_blank" rel="noopener noreferrer" href={`https://cwe.mitre.org/data/definitions/${encodeURIComponent(c)}.html`}>CWE-{c}</a>)} />}
            {f.advisory_id && <Row k="Advisory" v={<span className="font-mono">{[f.advisory_id, ...(f.aliases ?? [])].join(', ')}</span>} />}
            {f.file_path && <Row k="Location" v={<span className="font-mono">{f.file_path}{f.line ? `:${f.line}` : ''}</span>} />}
            {f.confidence && <Row k="Confidence" v={f.confidence} />}
          </dl>
        </Section>
        {refs.length > 0 && (
          <Section title="References">
            <ul className="flex flex-col gap-1 text-sm">{refs.slice(0, 10).map((u) => <li key={u}><a className="break-all text-sky underline" href={u} target="_blank" rel="noopener noreferrer">{u}</a></li>)}</ul>
          </Section>
        )}
        <p className="font-mono text-[11px] text-ink-3">Finding ID {f.finding_id}</p>
      </div>
    </div>
  )
}

export function ChecksList({ checks }: { checks: Check[] }) {
  const tone = { passed: 'good', failed: 'bad', warning: 'warn', skipped: 'idle' } as const
  return (
    <ul className="mt-3 flex flex-col gap-1.5">
      {checks.map((c, i) => (
        <li key={i} className="flex flex-wrap items-start gap-2 text-sm">
          <StatusTag tone={tone[c.status]} label={c.status} />
          <span className="min-w-0 flex-1"><b className="font-medium">{c.name}</b> <span className="text-ink-3">{c.detail}</span></span>
        </li>
      ))}
    </ul>
  )
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section>
      <h4 className="mb-2 text-xs font-semibold uppercase tracking-[0.1em] text-ink-3">{title}</h4>
      {children}
    </section>
  )
}

function Row({ k, v }: { k: string; v: React.ReactNode }) {
  return <><dt className="text-ink-3">{k}</dt><dd className="min-w-0 break-words">{v}</dd></>
}

export type { Finding }
