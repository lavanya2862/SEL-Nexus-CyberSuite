import { useMemo, useState } from 'react'
import { ChevronRight, ExternalLink, Lock, Play, Search, ShieldAlert, ShieldCheck, ShieldX, Siren, User } from 'lucide-react'
import { Chart, axisStyle } from '@/components/Chart'
import { Card, DTable, Empty, HopLink, Panel } from '@/components/kit'
import { dateTime, num } from '@/lib/format'
import { useRuns } from '@/lib/runs'
import { statusColor } from '@/lib/theme'
import { cn } from '@/lib/utils'
import { sourceNames, useUc4Queue, utc as uc4Time, type QueueRow } from '@/lib/uc4'
import { IOC_NAME, attackType, decoded, evidenceOf, threatHref, useUc1Data, wasBlocked, type ExplorerRow, type Hit } from '@/lib/uc1'
import { AiChip, Resolve, Uc1Header, Uc1Loading } from './common'

// The output of the Attack Detection Agent (UC1's attack-check run), in plain words.
// Every finding counts as a sign of attack; the search details sit under "Technical details".

const utc = (t: string) => t.replace(' ', 'T') + 'Z'

export function Hunting() {
  const { data, error, isLoading } = useUc1Data()
  const { runs, start, starting } = useRuns()
  const threats = useMemo(() => new Map((data?.explorer ?? []).map((e) => [e.id, e])), [data])
  // incidents Defender or Sentinel raised that the triage agent judged a true positive
  const { data: triage } = useUc4Queue()
  const caught = (triage?.queue ?? []).filter((r) => r.verdict === 'likely_true_positive')
  if (isLoading || error || !data) return <Uc1Loading error={error} />

  // every sign of attack is shown here, whatever the portal-wide "Include lab tests" filter says
  const hits = data.hits
  const computers = new Set(hits.map((h) => h.device_name)).size
  const iocTotal = Object.values(data.ioc_types).reduce((a, b) => a + b, 0)
  const errors = data.hunts.filter((h) => h.status !== 'ok').length
  const run = runs?.attack
  const checking = run?.status === 'running' || starting === 'attack'
  const took = run?.status !== 'running' && run?.finished_at ? Math.round((Date.parse(run.finished_at) - Date.parse(run.started_at)) / 1000) : null
  const total = hits.length + caught.length
  const found = total > 0
  const tone = found ? statusColor.critical : statusColor.good

  return (
    <div className="flex flex-col gap-5">
      <Uc1Header
        title="Attack detection"
        description="Proactive hunting for active compromise across managed devices, plus incidents confirmed by Microsoft detections"
        data={data}
        actions={
          <button onClick={() => start('attack')} disabled={checking}
            className="inline-flex items-center gap-2 rounded-xl btn-blue px-4 py-2 text-sm font-medium text-white disabled:cursor-not-allowed disabled:opacity-50">
            <Play className="size-4" /> {checking ? 'Checking…' : 'Check now'}
          </button>
        }
      />

      {/* 1. the answer */}
      <Panel className="flex items-center gap-4 p-6">
        <span className="grid size-14 shrink-0 place-items-center rounded-2xl" style={{ background: `color-mix(in oklab, ${tone} 16%, transparent)` }}>
          {found ? <ShieldAlert className="size-7" style={{ color: tone }} /> : <ShieldCheck className="size-7" style={{ color: tone }} />}
        </span>
        <div>
          <div className="text-2xl font-semibold tracking-tight">
            {found ? `${total} detection${total === 1 ? '' : 's'} found` : 'No detections found'}
          </div>
          <div className="text-sm text-ink-3">
            {hits.length ? `${hits.length} on ${computers} device${computers === 1 ? '' : 's'} · ` : ''}
            {caught.length ? `${caught.length} detected by Microsoft · ` : ''}
            Checked {dateTime(utc(data.generated.replace(/[+Z].*$/, '')))}{took != null ? ` (took ${took} s)` : ''}
          </div>
          {hits.length > 0 && (
            <div className="mt-2 flex flex-wrap gap-1.5">
              {Object.entries(hits.reduce<Record<string, number>>((a, h) => {
                const label = attackType(h.kind, h.detail).label
                return { ...a, [label]: (a[label] ?? 0) + 1 }
              }, {})).sort((a, b) => b[1] - a[1]).map(([label, n]) => (
                <span key={label} className="rounded-md bg-well px-2 py-0.5 text-xs text-ink-2"><b className="tabular text-ink">{n}</b> {label}</span>
              ))}
            </div>
          )}
        </div>
      </Panel>

      {/* 2. one card per sign of attack */}
      {found && (
        <Card title="Findings" description="Each detection, where it occurred and the recommended next steps">
          <div className="flex flex-col gap-3">{hits.map((h) => <SignCard key={h.finding_id} h={h} threat={threats.get(h.threat_id)} />)}</div>
        </Card>
      )}

      {caught.length > 0 && (
        <Card
          title={<span className="flex items-center gap-2"><Siren className="size-4" /> Detected by Microsoft</span>}
          description="Incidents raised by Microsoft Defender or Sentinel and classified as true positives by the Alert Triage Agent. Each is escalated to the security team."
        >
          <div className="flex flex-col gap-3">{caught.map((r) => <CaughtCard key={r.incident_id} r={r} />)}</div>
        </Card>
      )}

      {/* 3. what was checked */}
      <Panel className="p-5 text-sm text-ink-2">
        <b className="text-ink">Hunt coverage.</b> The last 30 days of activity on {num(data.devices.length)} devices were searched for{' '}
        {num(iocTotal)} indicators from threat intelligence (malicious domains, IP addresses and files), plus known attacker techniques.
        {errors > 0 && <> Some searches could not run; view the technical details.</>}
        <div className="mt-1 text-ink-3">Remediating vulnerabilities prevents new intrusions; hunting identifies any existing compromise.</div>
      </Panel>

      {/* 4. for the security team */}
      <TechnicalDetails data={data} errors={errors} iocFound={hits.filter((h) => h.kind === 'ioc_hit').length} />
    </div>
  )
}

function CaughtCard({ r }: { r: QueueRow }) {
  const by = sourceNames(r.sources) || 'Microsoft'
  const when = uc4Time(r.created_at)
  const tone = statusColor.critical
  return (
    <div className="rounded-xl border p-4" style={{ borderColor: `color-mix(in oklab, ${tone} 45%, transparent)` }}>
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="rounded-md bg-well px-1.5 py-0.5 text-[11px] font-medium text-ink-2">Detected by {by}</span>
            <span className="inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-[11px] font-semibold" style={{ color: tone, background: `color-mix(in oklab, ${tone} 14%, transparent)` }}>
              <ShieldAlert className="size-3" /> True positive · escalated
            </span>
          </div>
          <div className="mt-1.5 text-base font-semibold leading-snug">{r.title}</div>
          <div className="text-xs text-ink-3">
            {(r.devices.join(', ') || r.accounts.slice(0, 2).join(', ') || 'no computer named')}{when ? ` · ${dateTime(when.toISOString())}` : ''}
          </div>
        </div>
        <HopLink to={`/respond/${encodeURIComponent(r.incident_id)}`}>View incident</HopLink>
      </div>
      <dl className="mt-3 grid grid-cols-[auto_minmax(0,1fr)] gap-x-3 gap-y-1 text-sm">
        <dt className="text-ink-3">What happened</dt>
        <dd>{r.summary.split(/(?<=\.)\s/)[0]}</dd>
        <dt className="text-ink-3">Microsoft rated it</dt>
        <dd className="capitalize">{r.severity}</dd>
        <dt className="text-ink-3">Where it is now</dt>
        <dd>
          With the security team in Defender (incident #{r.incident_id}).{' '}
          {r.web_url && <a href={r.web_url} target="_blank" rel="noreferrer noopener" className="inline-flex items-center gap-1 font-medium hover:underline">Open in Defender <ExternalLink className="size-3" /></a>}
        </dd>
      </dl>
    </div>
  )
}

function SignCard({ h, threat }: { h: Hit; threat?: ExplorerRow }) {
  const hidden = h.timeline.map((e) => decoded(e.what)).find(Boolean)
  const users = h.users.map((u) => u.split('\\').pop())
  const type = attackType(h.kind, h.detail)
  const blocked = wasBlocked(type, h.alerts)
  const evidence = evidenceOf(h.timeline)
  const tone = blocked ? statusColor.good : statusColor.critical
  return (
    <div className="rounded-xl border p-4" style={{ borderColor: `color-mix(in oklab, ${blocked ? statusColor.warning : statusColor.critical} 45%, transparent)` }}>
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="rounded-md bg-well px-1.5 py-0.5 text-[11px] font-medium text-ink-2">{type.category}</span>
            <span className="inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-[11px] font-semibold" style={{ color: tone, background: `color-mix(in oklab, ${tone} 14%, transparent)` }}>
              {blocked ? <><ShieldCheck className="size-3" /> Blocked by Defender</> : <><ShieldX className="size-3" /> Not blocked</>}
            </span>
          </div>
          <div className="mt-1.5 text-base font-semibold leading-snug">{type.label}</div>
          <div className="text-xs text-ink-3">{h.device_name} · {dateTime(utc(h.first_hit))}</div>
        </div>
        {threat && <HopLink to={threatHref(h.threat_id)}>View details</HopLink>}
      </div>
      <dl className="mt-3 grid grid-cols-[auto_minmax(0,1fr)] gap-x-3 gap-y-1 text-sm">
        <dt className="text-ink-3">What happened</dt>
        <dd>{h.resolution?.what_happened || type.what}</dd>
        {evidence.length > 0 && (
          <>
            <dt className="text-ink-3">Evidence</dt>
            <dd className="font-mono text-xs leading-relaxed [overflow-wrap:anywhere]">{evidence.join(' · ')}</dd>
          </>
        )}
        {users.length > 0 && (
          <>
            <dt className="text-ink-3">Logged in</dt>
            <dd className="flex flex-wrap gap-1.5">{users.map((u) => <span key={u} className="inline-flex items-center gap-1 rounded-md bg-well px-2 py-0.5 text-xs"><User className="size-3" />{u}</span>)}</dd>
          </>
        )}
        {h.alerts.length > 0 && (
          <>
            <dt className="text-ink-3">Defender said</dt>
            <dd>{h.alerts.join('; ')}</dd>
          </>
        )}
        {!h.resolution && (
          <>
            <dt className="text-ink-3">What to do</dt>
            <dd className="font-medium">
              {threat?.action || `Confirm with ${users[0] ?? 'the user'} that this activity was expected; if not, escalate to the security team to isolate ${h.device_name}.`}
            </dd>
          </>
        )}
      </dl>
      {h.resolution && <Resolve r={h.resolution} />}
      {hidden && (
        <div className="mt-3 flex items-start gap-2 rounded-lg bg-signal/10 p-2.5 text-xs">
          <Lock className="mt-0.5 size-3.5 shrink-0 text-signal" />
          <span><b>Decoded command:</b> <code className="break-all font-mono">{hidden}</code></span>
        </div>
      )}
      {h.timeline.length > 0 && (
        <details className="group mt-3">
          <summary className="flex cursor-pointer list-none items-center gap-1 text-xs font-medium text-ink-2 hover:text-ink">
            <ChevronRight className="size-3.5 transition-transform group-open:rotate-90" /> Step by step ({h.timeline.length})
          </summary>
          <ol className="mt-2 border-l border-hairline pl-3">
            {h.timeline.map((e, i) => (
              <li key={i} className="relative pb-2 text-xs last:pb-0">
                <span className="absolute -left-[16.5px] top-1 size-2 rounded-full bg-hairline ring-2 ring-panel" />
                <span className="tabular text-ink-3">{e.time.slice(5, 16)}</span> <span className="text-ink-2 [overflow-wrap:anywhere]">{e.what.split(' | decoded command: ')[0].slice(0, 220)}</span>
              </li>
            ))}
          </ol>
        </details>
      )}
    </div>
  )
}

function TechnicalDetails({ data, errors, iocFound }: { data: NonNullable<ReturnType<typeof useUc1Data>['data']>; errors: number; iocFound: number }) {
  const [q, setQ] = useState('')
  const [only, setOnly] = useState<'all' | 'hits' | 'ai' | 'errors'>('all')
  const hunts = data.hunts.filter((h) =>
    (only === 'all' || (only === 'hits' && h.row_count > 0) || (only === 'ai' && h.origin === 'ai') || (only === 'errors' && h.status !== 'ok')) &&
    (!q || `${h.name} ${h.technique ?? ''}`.toLowerCase().includes(q.toLowerCase())))
  return (
    <details className="group">
      <summary className="flex cursor-pointer list-none items-center gap-1.5 text-sm font-medium text-ink-2 hover:text-ink">
        <ChevronRight className="size-4 transition-transform group-open:rotate-90" /> Technical details (for the security team)
      </summary>
      <div className="mt-4 flex flex-col gap-5">
        <div className="grid grid-cols-1 gap-5 xl:grid-cols-12">
          <Card className="xl:col-span-5" title="Indicators searched" description={`${num(iocFound)} found on managed devices`}>
            <div className="card-row gap-3 [--card-min:120px]">
              {Object.entries(data.ioc_types).sort((a, b) => b[1] - a[1]).map(([k, n]) => (
                <div key={k} className="rounded-xl bg-well px-3 py-2.5">
                  <div className="tabular font-semibold leading-none">{num(n)}</div>
                  <div className="mt-1.5 text-[11px] leading-snug text-ink-3">{IOC_NAME[k] ?? k}</div>
                </div>
              ))}
            </div>
          </Card>
          <Card className="xl:col-span-7" title="Searches by attacker technique" description="How many searches cover each technique (MITRE ATT&CK)">
            <Chart
              height={Math.max(240, new Set(data.hunts.map((h) => h.technique)).size * 26 + 40)}
              build={(tk) => {
                const by: Record<string, { n: number; rows: number }> = {}
                data.hunts.forEach((h) => {
                  const k = h.technique ?? 'other'
                  by[k] = by[k] ?? { n: 0, rows: 0 }
                  by[k].n += 1
                  by[k].rows += h.row_count
                })
                const list = Object.entries(by).sort((a, b) => a[1].n - b[1].n)
                return {
                  grid: { left: 8, right: 36, top: 4, bottom: 4, containLabel: true },
                  tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' }, formatter: (p: { name: string; value: number; dataIndex: number }[]) => `<b>${p[0].name}</b><br>${p[0].value} search(es) · ${list[p[0].dataIndex][1].rows} row(s) found` },
                  xAxis: { type: 'value', minInterval: 1, ...axisStyle(tk), axisLine: { show: false } },
                  yAxis: { type: 'category', data: list.map(([k]) => k), ...axisStyle(tk), splitLine: { show: false }, axisLabel: { color: tk.ink2 } },
                  series: [{
                    type: 'bar', barMaxWidth: 14,
                    data: list.map(([, v]) => ({ value: v.n, itemStyle: { color: v.rows ? tk.severity.High : tk.series[3] } })),
                    itemStyle: { borderRadius: [0, 4, 4, 0] }, label: { show: true, position: 'right', color: tk.ink, fontSize: 11 },
                  }],
                }
              }}
            />
            <p className="mt-2 text-xs text-ink-3">Highlighted techniques returned matches.</p>
          </Card>
        </div>

        <Card
          title="Searches in the latest run"
          description="Template searches run every time; agent-drafted searches are validated before they run"
          action={
            <label className="flex items-center gap-2 rounded-lg border border-hairline-strong bg-field px-3 py-1.5 text-sm transition-[border-color,box-shadow] focus-within:border-blue/60 focus-within:ring-3 focus-within:ring-blue/15">
              <Search className="size-3.5 text-ink-3" />
              <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search or technique" className="w-40 bg-transparent outline-none placeholder:text-ink-3" />
            </label>
          }
        >
          <div className="mb-3 flex flex-wrap gap-1.5 text-xs">
            {([['all', `All ${data.hunts.length}`], ['hits', 'Returned matches'], ['ai', 'Agent-drafted'], ['errors', `Errors ${errors}`]] as const).map(([k, l]) => (
              <button key={k} onClick={() => setOnly(k)} aria-pressed={only === k}
                className={cn('rounded-full border px-3 py-1', only === k ? 'pill-on' : 'border-hairline hover:bg-well')}>{l}</button>
            ))}
          </div>
          {hunts.length ? (
            <DTable head={[['Search'], ['Technique'], ['Made by'], ['Status'], ['Matches', 'right']]} minWidth={640} maxHeight={480}>
              {hunts.map((h, i) => (
                <tr key={i}>
                  <td className="font-medium">{h.name}</td>
                  <td className="tabular text-ink-2">{h.technique ?? '–'}</td>
                  <td><AiChip origin={h.origin === 'ai' ? 'ai' : 'template'} /></td>
                  <td title={h.error ?? ''}>
                    <span className="inline-flex items-center gap-1.5"><span className="size-2 rounded-full" style={{ background: h.status === 'ok' ? statusColor.good : statusColor.critical }} />{h.status}</span>
                  </td>
                  <td className="tabular text-right" style={{ fontWeight: h.row_count ? 600 : undefined }}>{num(h.row_count)}</td>
                </tr>
              ))}
            </DTable>
          ) : <Empty text="No searches match." />}
        </Card>
      </div>
    </details>
  )
}
