import { Link } from 'react-router-dom'
import { Check, Download, ExternalLink, Loader2 } from 'lucide-react'
import { Btn, Card, DTable, Empty, ErrorBox, LinkBtn, Loading, Notice, PageHeader, Panel, StatusTag, VerdictTag } from '@/components/kit'
import { artifactUrl, useAttention, useCaps, useJobs } from '@/lib/api'
import { ago } from '@/lib/format'
import { useApprove } from '@/lib/panels'

export function Approvals() {
  const att = useAttention()
  const jobs = useJobs({ limit: 100 }, 10_000)
  const caps = useCaps()
  const approve = useApprove()
  const token = !!caps.data?.github_token_configured
  if (att.isLoading) return <Loading />
  if (att.error || !att.data) return <ErrorBox error={att.error} />
  const waiting = att.data.approvals
  const prs = (jobs.data?.items ?? []).filter((j) => j.summary?.pull_request_url)

  return (
    <div className="flex flex-col gap-5">
      <PageHeader title="Approvals" description="Fix sets waiting for a person’s decision. Approving pushes the fix branch and opens a pull request for review. Nothing is ever merged without you." />
      {!token && <Notice tone="warn" title="Add a GitHub token to approve" action={<LinkBtn to="/settings">Open Settings</LinkBtn>}>Approving needs a token that can push branches and open pull requests. Until then, you can download each patch and apply it yourself.</Notice>}

      <section className="flex flex-col gap-3">
        <h2 className="text-lg font-semibold tracking-tight">Waiting for your approval <span className="text-ink-3">· {waiting.length}</span></h2>
        {waiting.length ? waiting.map((j) => {
          const s = j.summary ?? {}
          const flagged = s.validation_status === 'flagged'
          const publishing = s.approval_status === 'publishing' || (approve.isPending && approve.variables === j.id)
          return (
            <Panel key={j.id} className="flex flex-col gap-4 p-6">
              <div className="flex flex-wrap items-center gap-2">
                <h3 className="text-base font-semibold">{j.repo}</h3>
                <VerdictTag v={s.validation_status} />
                <span className="text-xs text-ink-3">scanned {ago(j.finished_at)}</span>
                <span className="flex-1" />
                <Link to={`/runs/${j.id}`} className="text-sm font-medium text-sky hover:underline">Open run →</Link>
              </div>
              <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
                <Mini label="Fix commits" value={s.fixes_applied ?? 0} />
                <Mini label="Written by AI" value={s.ai_fixes ?? 0} />
                <Mini label="Confirmed resolved" value={s.verified_fixed ?? 0} />
                <Mini label="Found in total" value={s.findings ?? 0} />
              </div>
              <Notice tone={flagged ? 'warn' : 'good'} title={flagged ? 'Validation flagged this change set' : 'All validation checks passed'}>
                {flagged ? (
                  <>
                    <ul className="list-disc pl-5">{j.failed_checks.map((c) => <li key={c.name}><b>{c.name}:</b> {c.detail}</li>)}</ul>
                    <p className="mt-1">Approving opens a <b>draft</b> pull request labelled needs-investigation.</p>
                  </>
                ) : 'Approving pushes the branch and opens a pull request for review.'}
              </Notice>
              {s.approval_status === 'failed' && s.publish_error && <Notice tone="bad" title="The last attempt failed">{s.publish_error}</Notice>}
              <div className="flex flex-wrap items-center gap-2">
                <LinkBtn to={`/runs/${j.id}/remediation`}>Review the fixes</LinkBtn>
                <LinkBtn href={artifactUrl(j.id, 'fixes.patch')}><Download className="size-3.5" /> Download patch</LinkBtn>
                <Btn kind={flagged ? 'warn' : 'good'} disabled={!token || publishing} onClick={() => approve.mutate(j.id)}>
                  {publishing ? <><Loader2 className="size-4 animate-spin" /> Publishing…</> : flagged ? 'Approve & open draft PR' : <><Check className="size-4" /> Approve &amp; open PR</>}
                </Btn>
              </div>
            </Panel>
          )
        }) : <Empty text="Nothing is waiting for your approval." />}
      </section>

      <Card title={`Pull requests opened · ${prs.length}`} description="After approval. Review and merge them on GitHub.">
        {prs.length ? (
          <DTable head={[['Repository'], ['Pull request'], ['Type'], ['Validation'], ['Fixes', 'right'], ['When']]}>
            {prs.map((j) => (
              <tr key={j.id}>
                <td className="font-medium"><Link to={`/runs/${j.id}`} className="hover:underline">{j.repo}</Link></td>
                <td><a href={j.summary!.pull_request_url!} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-sky hover:underline">{j.summary!.pull_request_url!.replace('https://github.com/', '')} <ExternalLink className="size-3" /></a></td>
                <td>{j.summary!.pull_request_draft ? <StatusTag tone="warn" label="Draft · needs investigation" /> : <StatusTag tone="good" label="Ready for review" />}</td>
                <td><VerdictTag v={j.summary!.validation_status} /></td>
                <td className="tabular text-right">{j.summary!.fixes_applied}</td>
                <td className="text-xs text-ink-3">{ago(j.finished_at)}</td>
              </tr>
            ))}
          </DTable>
        ) : <Empty text="No pull requests yet." />}
      </Card>
    </div>
  )
}

function Mini({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-xl border border-hairline bg-well/40 px-3 py-2.5">
      <div className="text-xs text-ink-3">{label}</div>
      <div className="tabular text-xl font-medium">{value}</div>
    </div>
  )
}
