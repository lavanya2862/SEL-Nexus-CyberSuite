import { Download, FileText } from 'lucide-react'
import { DTable, Empty, ErrorBox, LinkBtn, Loading, PageHeader, Panel, VerdictTag } from '@/components/kit'
import { artifactUrl, useJobs } from '@/lib/api'
import { ago } from '@/lib/format'

const FILES: [string, string][] = [
  ['report.md', 'The full report, readable by anyone'],
  ['findings.sarif', 'For GitHub code scanning'],
  ['fixes.patch', 'All changes; apply with git apply'],
]

export function Reports() {
  const jobs = useJobs({ status: 'completed', limit: 100 }, 30_000)
  return (
    <div className="flex flex-col gap-5">
      <PageHeader title="Reports" description="The evidence for every completed run, ready to share or upload. Newest first." />
      <div className="card-row gap-4 [--card-min:220px]">
        {FILES.map(([name, text]) => (
          <Panel key={name} className="flex items-center gap-3 p-4">
            <span className="grid size-9 place-items-center rounded-[10px] bg-well text-sky"><FileText className="size-4" /></span>
            <div className="min-w-0"><div className="font-mono text-sm font-medium">{name}</div><div className="text-xs text-ink-3">{text}</div></div>
          </Panel>
        ))}
      </div>
      <Panel className="p-6">
        {jobs.isLoading ? <Loading /> : jobs.error ? <ErrorBox error={jobs.error} /> : jobs.data?.items.length ? (
          <DTable head={[['Repository'], ['Finished'], ['Validation'], ['Findings', 'right'], ['Fixes', 'right'], ['Downloads'], ['']]} minWidth={1000}>
            {jobs.data.items.map((j) => {
              const s = j.summary ?? {}
              return (
                <tr key={j.id}>
                  <td><div className="font-medium">{j.repo}</div><div className="font-mono text-xs text-ink-3">{(j.commit ?? '').slice(0, 10)}</div></td>
                  <td className="whitespace-nowrap text-xs text-ink-3">{ago(j.finished_at)}</td>
                  <td><VerdictTag v={s.validation_status} /></td>
                  <td className="tabular text-right">{s.findings ?? '–'}</td>
                  <td className="tabular text-right">{s.fixes_applied ?? '–'}</td>
                  <td><div className="flex flex-nowrap gap-1.5">{FILES.map(([n]) => <LinkBtn key={n} href={artifactUrl(j.id, n)} className="h-8 px-2.5 text-xs"><Download className="size-3.5" /> {n}</LinkBtn>)}</div></td>
                  <td><LinkBtn to={`/runs/${j.id}/reporting`} kind="primary" className="h-8 px-3 text-xs">Read report</LinkBtn></td>
                </tr>
              )
            })}
          </DTable>
        ) : <Empty text="No completed runs yet." />}
      </Panel>
    </div>
  )
}
