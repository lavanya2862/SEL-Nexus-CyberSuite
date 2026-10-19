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
      <PageHeader title="Pipeline runs" description="Every repository the agents processed, newest first. Open a run to watch it live, review its fixes and approve them.">
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
        {jobs.isLoading ? <Loading /> : jobs.error ? <ErrorBox error={jobs.error} /> : <RunsTable items={jobs.data?.items ?? []} empty="No runs match." />}
      </Panel>
    </div>
  )
}
