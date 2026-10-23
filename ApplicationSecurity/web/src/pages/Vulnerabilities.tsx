import { Bug, FileCog, KeyRound, Package } from 'lucide-react'
import { Card, ErrorBox, HeroTile, Loading, PageHeader, Panel } from '@/components/kit'
import { FindingsTable } from '@/components/Tables'
import { useVulnerabilities } from '@/lib/api'
import { num } from '@/lib/format'
import { findingType, type FindingType } from '@/lib/labels'
import { statusColor } from '@/lib/theme'
import type { Finding } from '@/lib/types'

const FIXED = new Set(['verified', 'fixed'])

export function Vulnerabilities() {
  const v = useVulnerabilities()
  if (v.isLoading) return <Loading />
  if (v.error || !v.data) return <ErrorBox error={v.error} />
  const all = v.data.items
  const count = (sev: string) => all.filter((f) => f.severity === sev).length
  const fixed = all.filter((f) => FIXED.has(f.fix_status)).length
  const repos = new Set(all.map((f) => f.repo)).size
  return (
    <div className="flex flex-col gap-5">
      <PageHeader title="Vulnerabilities" description="Everything the Analysis Agent found in the latest scan of each repository, highest risk first. Click one to see the problem, the code, and what our agents did about it." />
      <AnalysisFound all={all} />
      <div className="card-row gap-4 [--card-min:150px]">
        <HeroTile hue="blue" label="Vulnerabilities found" value={all.length} hint={`in ${repos} ${repos === 1 ? 'repository' : 'repositories'}`} />
        <HeroTile hue="red" label="Critical" value={count('critical')} hint={`${all.length ? Math.round((count('critical') / all.length) * 100) : 0}% of findings`} />
        <HeroTile hue="orange" label="High" value={count('high')} hint="Fixed right after the critical ones" />
        <HeroTile hue="green" label="Fixed by our agents" value={fixed} hint="Remediation Agent fix, on a safe branch" />
        <HeroTile hue="violet" label="Medium & low" value={count('medium') + count('low')} hint="Fixed when they are above your threshold" />
      </div>
      <Card title="All vulnerabilities" description={`${num(all.length)} in total across every repository.`}>
        <FindingsTable items={all} showRepo />
      </Card>
    </div>
  )
}

/* ───────── what the Analysis Agent brings in: four kinds of weakness, each fixed differently ───────── */

const KINDS: { type: FindingType; icon: typeof Bug; label: string; text: string }[] = [
  { type: 'code', icon: Bug, label: 'Flaws in our own code',
    text: 'Injection, cross-site scripting, weak crypto and similar. The Remediation Agent writes a code fix for each.' },
  { type: 'dependency', icon: Package, label: 'Vulnerable dependencies',
    text: 'Open-source packages with known holes (CVEs). The Remediation Agent upgrades them to a safe version.' },
  { type: 'secret', icon: KeyRound, label: 'Exposed secrets',
    text: 'Passwords and keys written in the code. The Remediation Agent moves them out; a person rotates them.' },
  { type: 'config', icon: FileCog, label: 'Misconfigurations',
    text: 'Unsafe settings in Docker, CI or framework files. The Remediation Agent applies the safe setting.' },
]

function AnalysisFound({ all }: { all: Finding[] }) {
  return (
    <Panel className="p-5">
      <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
        <h2 className="font-semibold tracking-tight">What the Analysis Agent found</h2>
        <span className="text-xs text-ink-3">Four different kinds of weakness, each fixed a different way, so each is counted on its own</span>
      </div>
      <div className="mt-4 grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
        {KINDS.map((k) => {
          const rows = all.filter((f) => findingType(f) === k.type)
          const open = rows.filter((f) => !FIXED.has(f.fix_status)).length
          return (
            <div key={k.type} className="flex flex-col gap-1.5 rounded-xl bg-well p-4">
              <div className="flex items-center gap-2 text-xs font-medium text-ink-2"><k.icon className="size-3.5 text-ink-3" aria-hidden />{k.label}</div>
              <div className="tabular text-[26px] leading-none tracking-tight">{num(rows.length)}</div>
              <p className="text-xs leading-snug text-ink-3">{k.text}</p>
              {rows.length > 0 && (
                <p className="text-xs font-medium" style={{ color: open ? statusColor.warning : statusColor.good }}>
                  {open ? `${num(open)} still open` : 'All fixed by our agents'}
                </p>
              )}
            </div>
          )
        })}
      </div>
    </Panel>
  )
}
