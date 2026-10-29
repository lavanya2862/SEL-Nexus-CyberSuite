// How a fix is told everywhere: first the gap (the vulnerability the Analysis Agent found, where it is and why it
// matters), then what the Remediation Agent changed, then what the Validation Agent concluded.
import type { ReactNode } from 'react'
import { ScanSearch, ShieldCheck, Wrench } from 'lucide-react'
import { SevTag, StatusTag, VerdictTag } from '@/components/kit'
import { METHOD, SEVERITIES, splitFixTitle, where } from '@/lib/labels'
import type { Finding, Fix } from '@/lib/types'

/** Markdown and advisory text as one plain sentence or two. */
export function plain(text: string | null | undefined, max = 260): string {
  const s = String(text ?? '')
    .replace(/```[\s\S]*?```/g, ' ')
    .replace(/!?\[([^\]]*)\]\([^)]*\)/g, '$1')
    .replace(/[#>*_`|]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
  if (s.length <= max) return s
  const cut = s.slice(0, max)
  const end = Math.max(cut.lastIndexOf('. '), cut.lastIndexOf('; '))
  return (end > max * 0.5 ? cut.slice(0, end + 1) : cut.replace(/\s+\S*$/, '')) + (end > max * 0.5 ? '' : '…')
}

const worst = (fs: Finding[]) => fs.reduce((a, f) => (SEVERITIES.indexOf(f.severity) < SEVERITIES.indexOf(a) ? f.severity : a), fs[0]?.severity ?? 'unknown')

export interface Problem {
  severity: string
  headline: string
  where: string
  why: string
  findings: Finding[]
}

/** The gap a fix closes, in plain words, from the findings it targets. */
export function problemOf(fix: Fix, all: Finding[]): Problem {
  const fs = fix.finding_ids.map((id) => all.find((f) => f.finding_id === id)).filter(Boolean) as Finding[]
  if (!fs.length) {
    const [title] = splitFixTitle(fix.summary)
    return { severity: 'unknown', headline: `The vulnerability behind “${title}”`, where: fix.files.join(', '), why: plain(fix.detail), findings: [] }
  }
  const first = [...fs].sort((a, b) => (b.priority_score ?? 0) - (a.priority_score ?? 0))[0]
  if (first.package_name) {
    const ids = [...new Set(fs.flatMap((f) => [f.advisory_id, ...(f.aliases ?? [])]).filter((x): x is string => !!x && /^(CVE|GHSA)-/.test(x)))]
    return {
      severity: worst(fs),
      headline: fs.length === 1
        ? `${first.package_name} ${first.installed_version ?? ''} has a known vulnerability: ${first.title}`
        : `${first.package_name} ${first.installed_version ?? ''} has ${fs.length} known vulnerabilities`,
      where: `${first.file_path ?? 'dependency file'}${first.ecosystem ? ` · ${first.ecosystem}` : ''}`,
      why: fs.length === 1 ? plain(first.description) : `Including ${first.title}${ids.length ? ` (${ids.slice(0, 4).join(', ')}${ids.length > 4 ? ', …' : ''})` : ''}. ${plain(first.description, 180)}`,
      findings: fs,
    }
  }
  return {
    severity: worst(fs),
    headline: fs.length === 1 ? first.title : `${first.title}, and ${fs.length - 1} more of the same kind`,
    where: where(first),
    why: plain(first.description),
    findings: fs,
  }
}

function Step({ icon: Icon, tone, label, children }: { icon: typeof Wrench; tone: string; label: string; children: ReactNode }) {
  return (
    <div className="rounded-xl border p-3.5" style={{ borderColor: `color-mix(in oklab, ${tone} 35%, var(--hairline))`, background: `color-mix(in oklab, ${tone} 7%, transparent)` }}>
      <div className="mb-1.5 flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-[0.1em]" style={{ color: tone }}>
        <Icon className="size-3.5" /> {label}
      </div>
      {children}
    </div>
  )
}

/** One fix as three steps: the problem found, the change made, the check result. */
export function FixStory({ fix, findings, onOpenFinding, compact }: {
  fix: Fix; findings: Finding[]; onOpenFinding?: (id: string) => void; compact?: boolean
}) {
  const p = problemOf(fix, findings)
  const [title, extra] = splitFixTitle(fix.summary)
  const m = METHOD[fix.method]
  return (
    <div className="flex flex-col gap-2.5">
      <Step icon={ScanSearch} tone="var(--rose)" label="Vulnerability · identified by the Analysis Agent">
        <div className="flex flex-wrap items-start gap-x-2 gap-y-1">
          {p.severity !== 'unknown' && <SevTag sev={p.severity} />}
          <span className="font-semibold leading-snug">{p.headline}</span>
        </div>
        {p.where && <div className="mt-1 break-all font-mono text-xs text-ink-3">{p.where}</div>}
        {p.why && !compact && <p className="mt-1.5 text-sm leading-relaxed text-ink-2">{p.why}</p>}
        {onOpenFinding && p.findings.length > 0 && (
          <div className="mt-2 flex flex-wrap gap-1.5">
            {p.findings.slice(0, 10).map((f) => (
              <button key={f.finding_id} onClick={() => onOpenFinding(f.finding_id)} className="rounded-md border border-hairline px-1.5 py-0.5 text-[11px] text-ink-2 hover:bg-well hover:text-ink">
                {(f.advisory_id || f.rule_id || f.title).slice(0, 40)}
              </button>
            ))}
            {p.findings.length > 10 && <span className="text-xs text-ink-3">+{p.findings.length - 10} more</span>}
          </div>
        )}
      </Step>
      <Step icon={Wrench} tone="var(--blue)" label="Remediation · applied by the Remediation Agent">
        <div className="font-semibold leading-snug">{title}</div>
        {extra && <div className="text-xs text-ink-3">{extra}</div>}
        {fix.explanation ? <p className="mt-1.5 text-sm leading-relaxed text-ink-2">{compact ? plain(fix.explanation, 220) : fix.explanation}</p>
          : fix.detail && !compact ? <p className="mt-1.5 text-sm text-ink-3">{plain(fix.detail, 400)}</p> : null}
        <div className="mt-2 flex flex-wrap items-center gap-1.5 text-xs">
          <StatusTag tone="info" label={m?.label ?? fix.method} />
          <StatusTag tone={fix.risk === 'high' ? 'bad' : fix.risk === 'medium' ? 'warn' : 'good'} label={`${fix.risk[0].toUpperCase()}${fix.risk.slice(1)}-risk change`} />
          {fix.status !== 'applied' && <StatusTag tone="bad" label={fix.status} />}
          <span className="break-all font-mono text-ink-3">{fix.files.join(', ')}</span>
        </div>
      </Step>
      <Step icon={ShieldCheck} tone="var(--teal)" label="Verification · by the Validation Agent">
        <div className="flex flex-wrap items-center gap-1.5 text-xs">
          {fix.verified === true ? <StatusTag tone="good" label="Confirmation scan: resolved" />
            : fix.verified === false ? <StatusTag tone="warn" label="Confirmation scan: still reported" /> : <StatusTag tone="idle" label="Not verified by scan" />}
          <VerdictTag v={fix.validation_status} />
          <span className="text-ink-3">
            {fix.verified === true ? 'A fresh scan of the fix branch no longer reports it.'
              : fix.verified === false ? 'A fresh scan still reports it: a person should look at it.' : ''}
          </span>
        </div>
      </Step>
    </div>
  )
}
