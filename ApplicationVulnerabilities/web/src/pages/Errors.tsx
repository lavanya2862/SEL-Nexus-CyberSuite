import { Link } from 'react-router-dom'
import { ArrowRight, CircleAlert } from 'lucide-react'
import { Empty, ErrorBox, Loading, PageHeader, Panel, StatusTag } from '@/components/kit'
import { useAttention } from '@/lib/api'
import { ago } from '@/lib/format'
import { statusColor } from '@/lib/theme'
import type { ErrorItem } from '@/lib/types'

export function Errors() {
  const att = useAttention()
  if (att.isLoading) return <Loading />
  if (att.error || !att.data) return <ErrorBox error={att.error} />
  const { config_errors: setup, errors } = att.data
  return (
    <div className="flex flex-col gap-5">
      <PageHeader title="Errors" description="What went wrong with the setup, the scanners or a run, and how to fix each one. Vulnerabilities themselves are under Results." />
      <section className="flex flex-col gap-3">
        <h2 className="text-lg font-semibold tracking-tight">Setup <span className="text-ink-3">· {setup.length}</span></h2>
        {setup.length ? setup.map((e, i) => <ErrorCard key={i} e={e} />) : <Empty text="Setup is complete: AI model, GitHub token and scanners are all ready." />}
      </section>
      <section className="flex flex-col gap-3">
        <h2 className="text-lg font-semibold tracking-tight">Pipeline runs <span className="text-ink-3">· {errors.length}</span></h2>
        {errors.length ? errors.map((e, i) => <ErrorCard key={i} e={e} />) : <Empty text="No errors in the latest runs." />}
      </section>
    </div>
  )
}

function ErrorCard({ e }: { e: ErrorItem }) {
  const color = e.severity === 'high' ? statusColor.critical : statusColor.warning
  return (
    <Panel className="flex items-start gap-4 p-5">
      <span className="grid size-9 shrink-0 place-items-center rounded-[10px]" style={{ color, background: `color-mix(in oklab, ${color} 16%, transparent)` }}><CircleAlert className="size-4" /></span>
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2">
          <b className="font-semibold">{e.kind}</b>
          <StatusTag tone={e.severity === 'high' ? 'bad' : 'warn'} label={e.severity} />
          {e.repo && e.job_id && <Link to={`/runs/${e.job_id}`} className="text-xs text-sky hover:underline">{e.repo}</Link>}
          {e.when && <span className="ml-auto text-xs text-ink-3">{ago(e.when)}</span>}
        </div>
        <p className="mt-1 break-words text-sm text-ink-2">{e.message}</p>
        <p className="mt-2 rounded-lg bg-well px-3 py-2 text-sm"><b>How to fix:</b> {e.action}{' '}
          {e.link && <Link to={e.link.replace(/^#/, '')} className="inline-flex items-center gap-1 font-medium text-sky">Open <ArrowRight className="size-3" /></Link>}
        </p>
      </div>
    </Panel>
  )
}
