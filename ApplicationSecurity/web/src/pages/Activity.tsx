import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { ExternalLink } from 'lucide-react'
import { DTable, Empty, ErrorBox, Loading, PageHeader, Panel, Search, Select, StatusTag } from '@/components/kit'
import { Who } from '@/components/Tables'
import { useActivity } from '@/lib/api'
import { ago, stamp } from '@/lib/format'
import { ACTIVITY } from '@/lib/labels'

/** Who started, re-ran or cancelled a scan, approved its fixes, opened a pull request or ran the tests, and when. */
export function Activity() {
  const [action, setAction] = useState('')
  const [text, setText] = useState('')
  const [q, setQ] = useState('')
  useEffect(() => {
    const t = setTimeout(() => setQ(text.trim()), 300)
    return () => clearTimeout(t)
  }, [text])
  const log = useActivity({ action, q, limit: 300 })
  const items = log.data?.items ?? []
  return (
    <div className="flex flex-col gap-5">
      <PageHeader title="Activity log" description="Who started each scan, who approved the fixes and opened the pull request, who ran the tests on GitHub, with their name, email, date and time. Newest first." />
      <Panel className="flex flex-col gap-3 p-6">
        <div className="flex flex-wrap items-center gap-2">
          <Select label="Action" value={action} onChange={setAction}>
            <option value="">All actions</option>
            {Object.entries(ACTIVITY).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
          </Select>
          <Search value={text} onChange={setText} placeholder="Filter by person, email or repository…" />
          {log.data && <span className="text-xs text-ink-3">{log.data.total > items.length ? `latest ${items.length} of ${log.data.total}` : `${log.data.total} entries`}</span>}
        </div>
        {log.isLoading ? <Loading /> : log.error ? <ErrorBox error={log.error} /> : !items.length ? <Empty text={action || q ? 'No activity matches.' : 'Nothing has happened yet. Start a scan and it shows up here.'} /> : (
          <DTable head={[['When'], ['Who'], ['Action'], ['Repository'], ['Details']]} minWidth={980} maxHeight={720}>
            {items.map((e) => {
              const a = ACTIVITY[e.action] ?? { label: e.action, tone: 'idle' as const }
              const url = e.detail.match(/https?:\/\/\S+/)?.[0]
              return (
                <tr key={e.id}>
                  <td className="whitespace-nowrap"><div className="tabular text-xs">{stamp(e.ts)}</div><div className="text-xs text-ink-3">{ago(e.ts)}</div></td>
                  <td className="max-w-[240px]"><Who p={{ email: e.email, name: e.name }} /></td>
                  <td className="whitespace-nowrap"><StatusTag tone={a.tone} label={a.label} /></td>
                  <td>
                    {e.repo ? <div className="font-medium">{e.repo}</div> : <span className="text-ink-3">–</span>}
                    {e.job_id && <Link to={`/runs/${e.job_id}`} className="text-xs text-sky hover:underline">open scan</Link>}
                  </td>
                  <td className="max-w-[360px] text-xs text-ink-2">
                    {url ? (
                      <>
                        <a href={url} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 break-all text-sky hover:underline">{url} <ExternalLink className="size-3 shrink-0" /></a>
                        {e.detail.replace(url, '').trim() && <div>{e.detail.replace(url, '').trim()}</div>}
                      </>
                    ) : e.detail || <span className="text-ink-3">–</span>}
                  </td>
                </tr>
              )
            })}
          </DTable>
        )}
      </Panel>
    </div>
  )
}
