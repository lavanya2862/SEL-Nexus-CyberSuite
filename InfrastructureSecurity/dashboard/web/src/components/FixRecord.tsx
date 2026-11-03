// One remediation's full record, the same on every page: what it is, every step with its time and who, what the
// Remediation Agent tried, the earlier attempts, the device's own output and what the script was allowed to run.
// Opened from anywhere with ?record=<fix id> (FixRecordHost, mounted once in the app shell) or a RecordLink.
import type { ReactNode } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useSearchParams } from 'react-router-dom'
import { FileText } from 'lucide-react'
import { DetailDialog, DialogSection } from '@/components/DetailDialog'
import { StatusPill } from '@/components/FixLoop'
import { ManualAction, PersonLine } from '@/components/ManualAction'
import { Skeleton } from '@/components/ui/skeleton'
import { ACTION_LABEL, METHOD_LABEL, STATUS, isSetting, versionOf, type FixRow } from '@/agents/fixes/data'
import { AGENT_NAME } from '@/lib/runs'
import { dateTime, num, utc } from '@/lib/format'
import { cn } from '@/lib/utils'

export interface FixDetail {
  row: FixRow
  output: string
  requeued_at: string | null
  next_check_at: string | null
  trail: { at: string; text: string }[]
  attempts: (Partial<FixRow> & { status: FixRow['status'] })[]
  allowed: { action?: string; winget?: string; choco?: string; allow_choco?: boolean; kind?: string; target?: string; value?: number
    check?: string[]; remove?: string[]; procs?: string[] }
}

export function useFixDetail(id: string | null) {
  return useQuery<FixDetail>({
    queryKey: ['fix', 'detail', id],
    enabled: !!id,
    queryFn: async () => {
      const res = await fetch(`/api/fix/detail?id=${encodeURIComponent(id ?? '')}`)
      const out = await res.json().catch(() => ({}))
      if (!res.ok) throw new Error(out.error ?? `CyberSuite could not load this remediation (error ${res.status})`)
      return out
    },
  })
}

/** "Full record": opens the record drawer for this remediation (keeps the page and its filters underneath). */
export function RecordLink({ id, className, children }: { id: string; className?: string; children?: ReactNode }) {
  const [params, setParams] = useSearchParams()
  return (
    <button type="button" onClick={(e) => { e.stopPropagation(); const n = new URLSearchParams(params); n.set('record', id); setParams(n) }}
      className={cn('inline-flex items-center gap-1 text-xs font-medium text-blue hover:underline', className)}>
      <FileText className="size-3.5" /> {children ?? 'Full record'}
    </button>
  )
}

/** Mounted once in the app shell: shows the record named by ?record= on whichever page is open. */
export function FixRecordHost() {
  const [params, setParams] = useSearchParams()
  const id = params.get('record')
  if (!id) return null
  const close = () => { const n = new URLSearchParams(params); n.delete('record'); setParams(n) }
  return <FixRecord id={id} onClose={close} />
}

const when = (s: string | null | undefined) => (s ? dateTime(utc(s)) : '–')

function Fact({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="text-[11px] text-ink-3">{label}</dt>
      <dd className="mt-0.5 break-words text-sm text-ink">{children}</dd>
    </div>
  )
}

const MOVE: Record<string, string> = {
  winget: 'Install with winget', choco: 'Install with Chocolatey', uninstall: 'Uninstall', apply: 'Apply setting',
  quick_scan: 'Quick scan', full_scan: 'Full scan', stop: 'Agent stopped',
}

function FixRecord({ id, onClose }: { id: string; onClose: () => void }) {
  const { data: d, error, isLoading } = useFixDetail(id)
  const r = d?.row
  const res = r?.result
  const setting = r ? isSetting(r) : false
  const before = res && !setting ? versionOf(res.before) : undefined
  const after = res && !setting ? versionOf(res.after) : undefined
  const available = (res as { available?: string } | null | undefined)?.available
  const found = Object.entries(r?.found_by ?? {}).map(([a, t]) => `${AGENT_NAME[a as keyof typeof AGENT_NAME] ?? a}${t ? ` (${when(t)})` : ''}`)
  return (
    <DetailDialog onClose={onClose}
      title={r ? `${ACTION_LABEL[r.action]} ${r.app}${!setting && r.version ? ` ${r.version}` : ''}` : 'Remediation record'}
      eyebrow={r && <><StatusPill r={r} /><span className="text-ink-3">Full record</span></>}
      subtitle={r ? `${r.device_name}${r.opco ? ` · ${r.opco}` : ''} · ${id}` : id}>
      {isLoading ? <Skeleton className="h-64 rounded-xl" /> : error || !d || !r ? (
        <p className="text-sm text-ink-3">{(error as Error)?.message ?? 'This remediation could not be found.'}</p>
      ) : (
        <div className="flex flex-col gap-6">
          <PersonLine r={r} />
          <DialogSection title="Summary">
            <dl className="grid grid-cols-2 gap-x-6 gap-y-3 md:grid-cols-3">
              <Fact label="Status">{STATUS[r.status]?.label ?? r.status}</Fact>
              {r.message && ['gone', 'done', 'failed', 'awaiting_vendor', 'still_there'].includes(r.status) && <div className="col-span-full"><Fact label="Result">{r.message}</Fact></div>}
              <Fact label="Found by">{found.length ? found.join(', ') : '–'}</Fact>
              <Fact label="Vulnerabilities it clears">{setting ? 'Security setting' : `${num(r.findings)}${r.cves ? ` (${num(r.cves)} CVEs)` : ''}`}</Fact>
              <Fact label="Approved">{r.approved_by ? `${r.approved_by} · ${when(r.approved_at)}` : '–'}{r.method ? ` · ${METHOD_LABEL[r.method]}` : ''}</Fact>
              <Fact label="Ran on the device">{when(r.started_at)}{r.finished_at ? ` → ${when(r.finished_at)}` : ''}</Fact>
              <Fact label="Verified by Defender">{when(r.verified_at)}</Fact>
              {!setting && <Fact label="Version">{before ?? r.version}{after && after !== before ? ` → ${after}` : ''}</Fact>}
              {res?.engine && <Fact label="Installed with">{res.engine}{res.reboot ? ' · restart needed' : ''}</Fact>}
              {available && <Fact label="Newest version in winget">{available}</Fact>}
              {d.next_check_at && <Fact label="Next vendor check">{when(d.next_check_at)}</Fact>}
              {d.requeued_at && <Fact label="Re-queued (original approval)">{when(d.requeued_at)}</Fact>}
              {r.saved_by && <Fact label="Deferred">{r.saved_by} · {when(r.saved_at)}</Fact>}
            </dl>
          </DialogSection>

          {(r.status === 'manual_required' || r.manual) && (
            <DialogSection title="Manual action"><ManualAction r={r} /></DialogSection>
          )}

          {(r.agent?.length ?? 0) > 0 && (
            <DialogSection title="What the Remediation Agent did">
              <ol className="flex flex-col gap-2 text-sm">
                {r.agent!.map((m, i) => (
                  <li key={i} className="flex gap-2">
                    <span className="tabular text-ink-3">{i + 1}.</span>
                    <span className="min-w-0"><b className="font-medium">{MOVE[m.action] ?? m.action}</b>
                      {m.status && <span className={m.status === 'done' ? 'text-[#0ca30c]' : 'text-[#d03b3b]'}> · {m.status === 'done' ? 'succeeded' : 'did not succeed'}</span>}
                      {m.reason && <span className="block text-xs text-ink-3">Why: {m.reason}</span>}
                      {m.result && <span className="block text-xs text-ink-2">{m.result}</span>}</span>
                  </li>
                ))}
              </ol>
            </DialogSection>
          )}

          <DialogSection title="Timeline" aside={`${d.trail.length} event${d.trail.length === 1 ? '' : 's'}`}>
            {d.trail.length ? (
              <ol className="flex flex-col gap-1.5 border-l border-hairline pl-4 text-xs">
                {[...d.trail].sort((a, b) => a.at.localeCompare(b.at)).map((e, i) => (
                  <li key={i} className="relative">
                    <span className="absolute -left-[21px] top-1.5 size-2 rounded-full bg-hairline-strong" />
                    <span className="tabular text-ink-3">{when(e.at)}</span> · <span className="text-ink-2">{e.text}</span>
                  </li>
                ))}
              </ol>
            ) : <p className="text-xs text-ink-3">Nothing has happened to this remediation yet.</p>}
          </DialogSection>

          {d.attempts.length > 0 && (
            <DialogSection title="Earlier attempts">
              <ul className="flex flex-col gap-2 text-xs">
                {[...d.attempts].reverse().map((a, i) => (
                  <li key={i} className="rounded-lg border border-hairline px-3 py-2">
                    <div className="font-medium text-ink">{STATUS[a.status]?.label ?? a.status} · {when(a.finished_at ?? a.started_at)}</div>
                    <div className="text-ink-3">{a.approved_by ? `Approved by ${a.approved_by} · ${when(a.approved_at)}` : ''}{a.manual ? ` · remediated manually by ${a.manual.by}` : ''}</div>
                    {a.message && <div className="mt-0.5 text-ink-2">{a.message}</div>}
                  </li>
                ))}
              </ul>
            </DialogSection>
          )}

          {(res?.log?.length || d.output) && (
            <DialogSection title="Device output" aside={res?.exit != null ? `exit code ${res.exit}` : undefined}>
              <pre className="max-h-72 overflow-auto whitespace-pre-wrap break-words rounded-lg bg-well p-3 font-mono text-[11px] leading-relaxed text-ink-2">
                {d.output || res?.log?.join('\n')}
              </pre>
            </DialogSection>
          )}

          {Object.keys(d.allowed).length > 0 && (
            <DialogSection title="What the script was allowed to run">
              <dl className="grid grid-cols-2 gap-x-6 gap-y-3 md:grid-cols-3">
                {d.allowed.winget && <Fact label="winget package">{d.allowed.winget}</Fact>}
                {d.allowed.choco && <Fact label="Chocolatey package">{d.allowed.choco}{d.allowed.allow_choco === false ? ' (Chocolatey off at approval)' : ''}</Fact>}
                {d.allowed.kind === 'scan_clean' && <Fact label="Response">Update Microsoft Defender's signatures, run a Defender scan and remove the active threats it finds</Fact>}
                {d.allowed.kind && d.allowed.kind !== 'scan_clean' && <Fact label="Setting">{d.allowed.kind === 'asr' ? 'Attack surface reduction rule' : d.allowed.kind === 'defender' ? 'Defender Antivirus option' : 'Registry value'} · {d.allowed.target} = {d.allowed.value}</Fact>}
                {d.allowed.check?.length ? <Fact label="Apps it looks for">{d.allowed.check.join(', ')}</Fact> : null}
                {d.allowed.remove?.length ? <Fact label="Apps it may remove">{d.allowed.remove.join(', ')}</Fact> : null}
                {d.allowed.procs?.length ? <Fact label="Processes it closes first">{d.allowed.procs.join(', ')}</Fact> : null}
              </dl>
              <p className="mt-2 text-[11px] text-ink-3">The device runs one fixed script with only these values; nothing else can run.</p>
            </DialogSection>
          )}
        </div>
      )}
    </DetailDialog>
  )
}
