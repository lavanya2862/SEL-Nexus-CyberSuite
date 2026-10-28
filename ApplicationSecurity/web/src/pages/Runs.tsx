import { useEffect, useState } from 'react'
import { CirclePlus } from 'lucide-react'
import { ErrorBox, LinkBtn, Loading, PageHeader, Panel, Search, Select } from '@/components/kit'
import { RunsTable } from '@/components/Tables'
import { useJobs } from '@/lib/api'
import { JOB_STATUS } from '@/lib/labels'
import type { JobStatus } from '@/lib/types'

export function Runs() {
  const [status, setStatus] = useState<JobStatus | ''>('')
  const [text, setText] = useState('')
  const [repo, setRepo] = useState('')
  useEffect(() => {
    const t = setTimeout(() => setRepo(text.trim()), 300)
    return () => clearTimeout(t)
  }, [text])
  const jobs = useJobs({ status, repo, limit: 100 })
  return (
    <div className="flex flex-col gap-5">
      <PageHeader title="Scan history" description="All scans across all repositories, newest first, including scans in progress. Open a scan to monitor it live, review its remediations and approve them.">
        <LinkBtn to="/scan" kind="primary"><CirclePlus className="size-4" /> New scan</LinkBtn>
      </PageHeader>
      <Panel className="flex flex-col gap-3 p-6">
        <div className="flex flex-wrap items-center gap-2">
          <Select label="Status" value={status} onChange={(v) => setStatus(v as JobStatus | '')}>
            <option value="">All statuses</option>
            {Object.entries(JOB_STATUS).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
          </Select>
          <Search value={text} onChange={setText} placeholder="Filter by repository…" />
        </div>
        {jobs.isLoading ? <Loading /> : jobs.error ? <ErrorBox error={jobs.error} /> : <RunsTable items={jobs.data?.items ?? []} empty="No scans match the selected filters." />}
      </Panel>
    </div>
  )
}
