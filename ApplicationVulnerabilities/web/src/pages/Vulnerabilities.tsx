import { Card, ErrorBox, Loading, PageHeader, Panel, sevColor } from '@/components/kit'
import { FindingsTable } from '@/components/Tables'
import { useVulnerabilities } from '@/lib/api'
import { num } from '@/lib/format'
import { SEVERITIES, sevLabel } from '@/lib/labels'
import { useTheme } from '@/lib/theme'

export function Vulnerabilities() {
  const v = useVulnerabilities()
  const { theme } = useTheme()
  if (v.isLoading) return <Loading />
  if (v.error || !v.data) return <ErrorBox error={v.error} />
  const all = v.data.items
  const bySev: Record<string, number> = {}
  all.forEach((f) => { bySev[f.severity] = (bySev[f.severity] ?? 0) + 1 })
  return (
    <div className="flex flex-col gap-5">
      <PageHeader title="Vulnerabilities" description="Every issue in the latest scan of each repository, highest risk first. Click one to see the code, why it ranks where it does, and what the agents did about it." />
      <div className="card-row gap-4 [--card-min:150px]">
        {SEVERITIES.slice(0, 5).map((s) => (
          <Panel key={s} className="p-5">
            <div className="flex items-center gap-2 text-sm text-ink-2"><span className="size-2.5 rounded-full" style={{ background: sevColor(theme, s) }} />{sevLabel(s)}</div>
            <div className="mt-2 text-[30px] leading-none tracking-tight tabular">{num(bySev[s] ?? 0)}</div>
          </Panel>
        ))}
      </div>
      <Card title="All issues" description={`${num(all.length)} in total across every repository.`}>
        <FindingsTable items={all} showRepo />
      </Card>
    </div>
  )
}
