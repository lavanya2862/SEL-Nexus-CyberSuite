import { AlertTriangle, CheckCircle2, Info, XCircle } from 'lucide-react'
import { Chart, axisStyle } from '@/components/Chart'
import { Panel, Tag } from '@/components/kit'
import { dateTime, num, shortDate } from '@/lib/format'
import { statusColor } from '@/lib/theme'
import { CHECK_LABEL, useUc3Data } from '@/lib/uc3'
import { Card, DTable, Uc3Header, Uc3Loading } from './common'

const ICON = {
  PASS: { icon: CheckCircle2, color: statusColor.good, label: 'Passed' },
  WARN: { icon: AlertTriangle, color: statusColor.warning, label: 'Warning' },
  FAIL: { icon: XCircle, color: statusColor.critical, label: 'Failed' },
  INFO: { icon: Info, color: 'var(--ink-3)', label: 'Info' },
} as const

export function DataQuality() {
  const { data, error, isLoading } = useUc3Data()
  if (isLoading || error || !data) return <Uc3Loading error={error} />
  const r = data.run
  const counts = (s: string) => data.dq.filter((c) => c.status === s).length
  const worst = counts('FAIL') ? 'FAIL' : counts('WARN') ? 'WARN' : 'PASS'
  const W = ICON[worst]
  const exportAge = r?.export_generated_time ? ((new Date(r.started_at).getTime() - new Date(r.export_generated_time).getTime()) / 3600000).toFixed(1) + ' h' : '–'
  const facts: [string, string][] = r
    ? [
        [num(r.vulnerability_rows), 'rows exported'],
        [r.defender_count == null ? '–' : num(r.defender_count), 'rows in Defender (its own count)'],
        [r.coverage == null ? '–' : `${(r.coverage * 100).toFixed(1)}%`, 'coverage'],
        [num(r.machines), 'devices'],
        [`${r.duration_seconds} s`, 'run time'],
        [num(r.retries), 'retries needed'],
        [exportAge, 'export age at run'],
        [num(r.change_rows), 'change events'],
      ]
    : []
  return (
    <div className="flex flex-col gap-5">
      <Uc3Header title="Data quality" description="Can we trust these numbers? Automatic checks on every run" data={data} />

      <Panel className="grid gap-6 p-6 lg:grid-cols-[minmax(0,0.8fr)_minmax(0,2fr)] lg:items-center">
        <div className="flex items-center gap-4">
          <span className="grid size-14 place-items-center rounded-2xl" style={{ background: `color-mix(in oklab, ${W.color} 16%, transparent)` }}>
            <W.icon className="size-7" style={{ color: W.color }} />
          </span>
          <div>
            <div className="text-2xl font-semibold tracking-tight">Quality {worst}</div>
            <div className="text-sm text-ink-3">{counts('PASS')} passed · {counts('WARN')} warnings · {counts('FAIL')} failed</div>
            {r && <div className="text-xs text-ink-3">Run of {r.run_date}, started {dateTime(r.started_at)}</div>}
          </div>
        </div>
        <div className="card-row gap-3 [--card-min:120px]">
          {facts.map(([v, l]) => (
            <div key={l} className="rounded-xl bg-well px-3.5 py-3">
              <div className="tabular text-lg font-semibold leading-none">{v}</div>
              <div className="mt-1.5 text-[11px] leading-snug text-ink-3">{l}</div>
            </div>
          ))}
        </div>
      </Panel>

      <div className="grid grid-cols-1 gap-5 xl:grid-cols-12">
        <Card className="xl:col-span-6" title="The checks" description="What each automatic test found on the latest run">
          <ul className="flex flex-col divide-y divide-hairline">
            {data.dq.map((c) => {
              const s = ICON[c.status as keyof typeof ICON] ?? ICON.INFO
              return (
                <li key={c.name} className="flex gap-3 py-3 first:pt-0 last:pb-0">
                  <s.icon className="mt-0.5 size-4 shrink-0" style={{ color: s.color }} />
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-baseline justify-between gap-x-3">
                      <span className="text-sm font-medium">{CHECK_LABEL[c.name] ?? c.name}</span>
                      <span className="text-xs text-ink-3">{c.value}</span>
                    </div>
                    <p className="mt-0.5 text-xs leading-relaxed text-ink-3">{c.message} <span className="whitespace-nowrap">(expected {c.expected})</span></p>
                  </div>
                </li>
              )
            })}
          </ul>
        </Card>
        <div className="flex flex-col gap-5 xl:col-span-6">
          <Card title="Coverage on every run" description="Rows we captured compared with Defender's own count">
            <Chart
              height={200}
              build={(tk) => ({
                grid: { left: 4, right: 8, top: 16, bottom: 4, containLabel: true },
                tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
                legend: { top: 0, right: 0, icon: 'roundRect', itemWidth: 10, itemHeight: 10, textStyle: { color: tk.ink2, fontSize: 11.5 } },
                xAxis: { type: 'category', data: data.runs.map((h) => shortDate(h.run_date)), ...axisStyle(tk), splitLine: { show: false } },
                yAxis: { type: 'value', ...axisStyle(tk), axisLine: { show: false } },
                series: [
                  { name: 'Rows captured', type: 'bar', barMaxWidth: 28, data: data.runs.map((h) => h.vulnerability_rows), itemStyle: { color: tk.series[1], borderRadius: [4, 4, 0, 0] } },
                  { name: 'Defender count', type: 'line', symbol: 'circle', symbolSize: 8, data: data.runs.map((h) => h.defender_count), lineStyle: { width: 2, color: tk.ink2, type: 'dashed' }, itemStyle: { color: tk.ink2 } },
                ],
              })}
            />
          </Card>
          <Card title="Run history" description="Every run and how much of Defender it captured">
            <DTable head={[['Date'], ['Rows', 'right'], ['Defender count', 'right'], ['Coverage', 'right'], ['Devices', 'right'], ['Run time', 'right'], ['Quality']]} minWidth={560}>
              {[...data.runs].reverse().map((h) => (
                <tr key={h.run_date}>
                  <td className="tabular whitespace-nowrap">{h.run_date}</td>
                  <td className="tabular text-right">{num(h.vulnerability_rows)}</td>
                  <td className="tabular text-right">{h.defender_count == null ? '–' : num(h.defender_count)}</td>
                  <td className="tabular text-right">{h.coverage == null ? '–' : `${(h.coverage * 100).toFixed(1)}%`}</td>
                  <td className="tabular text-right">{num(h.machines)}</td>
                  <td className="tabular text-right">{h.duration_seconds} s</td>
                  <td>{h.quality ? <Tag tone={h.quality === 'FAIL' ? 'bad' : h.quality === 'WARN' ? 'warn' : undefined}>{h.quality}</Tag> : '–'}</td>
                </tr>
              ))}
            </DTable>
          </Card>
        </div>
      </div>

      <Card title="Devices and VM mapping" description="Each computer gets its VM from its Defender tag, or from its name; otherwise it shows as UNMAPPED. Adding a tag in Defender makes it explicit.">
        <DTable head={[['Device'], ['VM'], ['Device group'], ['Tags'], ['Advice']]} minWidth={680}>
          {data.devices.map((d) => (
            <tr key={d.id}>
              <td className="font-medium">{d.name}</td>
              <td>{d.opco}</td>
              <td className="text-ink-2">{d.rbac_group_name || 'Unassigned'}</td>
              <td>{d.tags?.length ? d.tags.map((t) => <Tag key={t}>{t}</Tag>) : '–'}</td>
              <td className="text-ink-2">
                {d.opco === 'UNMAPPED' ? 'Add a VM tag in Defender or a rule in config/opco_mapping.csv' : d.tags?.length ? 'OK' : 'Mapped by name; a VM tag in Defender would make it explicit'}
              </td>
            </tr>
          ))}
        </DTable>
      </Card>
    </div>
  )
}
