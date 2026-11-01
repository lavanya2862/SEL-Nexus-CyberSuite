import { useMemo, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { ChevronRight, FlaskConical, ListChecks, Lock, Monitor, Play, ShieldAlert, ShieldCheck, Siren, User, Wrench } from 'lucide-react'
import { DetailDialog, DialogSection } from '@/components/DetailDialog'
import { useShownName } from '@/lib/deviceNames'
import { Chart, axisStyle } from '@/components/Chart'
import {
  Card, DTable, DateFilter, Empty, FilterBar, FilterChoice, FilterMenu, FilterSearch, Panel, SevTag, Tabs, choiceChip, dateChip, inDateRange,
  menuChips, type ActiveFilter, type DateRange,
} from '@/components/kit'
import { dateTime, num } from '@/lib/format'
import { useRuns } from '@/lib/runs'
import { chartTokens, statusColor, useTheme } from '@/lib/theme'
import { decoded } from '@/agents/threat-intel/data'
import { Resolve, ThreatIntelHeader, ThreatIntelLoading } from '@/agents/threat-intel/common'
import {
  SEVERITIES, remediationLabel, sevRank, useAttackDetectionData, type AttackData, type Finding,
} from '@/agents/attack-detection/data'

// The Attack Detection Agent's page: what its searches for the 12 attacks found, from its own data/out/findings.json.

type Tab = 'overview' | 'detected' | 'coverage' | 'health'
const TABS: [Tab, string][] = [['overview', 'Overview'], ['detected', 'Attacks detected'], ['coverage', 'Attack coverage'], ['health', 'Search health']]

const utc = (t: string) => (/[+Z]/.test(t.slice(10)) ? t : t.replace(' ', 'T') + 'Z')
const TONE = { bad: statusColor.critical, warn: statusColor.warning, good: statusColor.good, none: 'var(--color-ink-3)' }

export function Hunting() {
  const { data, error, isLoading } = useAttackDetectionData()
  const { runs, start, starting } = useRuns()
  const [params, setParams] = useSearchParams()
  const tab = TABS.find(([t]) => t === params.get('tab'))?.[0] ?? 'overview'
  if (isLoading || error || !data) return <ThreatIntelLoading error={error} />

  const run = runs?.attack_detection
  const checking = run?.status === 'running' || starting === 'attack_detection'
  const took = run?.status !== 'running' && run?.finished_at ? Math.round((Date.parse(run.finished_at) - Date.parse(run.started_at)) / 1000) : null
  const setTab = (t: Tab) => setParams((p) => { const n = new URLSearchParams(p); if (t === 'overview') n.delete('tab'); else n.set('tab', t); return n }, { replace: true })

  return (
    <div className="flex flex-col gap-5">
      <ThreatIntelHeader
        title="Attack detection"
        description={`Advanced Hunting across managed devices for the 12 attacks${took != null ? ` · last check took ${took} s` : ''}`}
        data={data}
        actions={
          <button onClick={() => start('attack_detection')} disabled={checking}
            className="inline-flex items-center gap-2 rounded-xl btn-blue px-4 py-2 text-sm font-medium text-white disabled:cursor-not-allowed disabled:opacity-50">
            <Play className="size-4" /> {checking ? 'Checking…' : 'Run attack check'}
          </button>
        }
      />
      <Tabs<Tab> tabs={TABS} value={tab} onChange={setTab} />
      {tab === 'overview' ? <Overview d={data} onOpen={() => setTab('detected')} />
        : tab === 'detected' ? <Detected d={data} />
        : tab === 'coverage' ? <Coverage d={data} />
        : <Health d={data} />}
    </div>
  )
}

/* ───────── overview ───────── */

function Overview({ d, onOpen }: { d: AttackData; onOpen: () => void }) {
  const real = d.hits.filter((h) => !h.is_test)
  const devices = new Set(real.map((h) => h.device_name))
  const worst = real.map((h) => h.severity).sort((a, b) => sevRank(a) - sevRank(b))[0]
  const ok = d.hunts.filter((h) => h.status === 'ok').length
  const skipped = d.hunts.filter((h) => h.status === 'skipped').length
  const failed = d.hunts.length - ok - skipped
  const searches = d.attacks.reduce((n, a) => n + a.searches.length, 0)
  const tone = real.length ? statusColor.critical : statusColor.good
  const perDevice = d.devices.map((x) => {
    const mine = real.filter((h) => h.device_name === x.device_name)
    return { ...x, n: mine.length, worst: mine.map((h) => h.severity).sort((a, b) => sevRank(a) - sevRank(b))[0] }
  }).sort((a, b) => b.n - a.n || a.device_name.localeCompare(b.device_name))

  return (
    <div className="flex flex-col gap-5">
      <Panel className="grid gap-6 p-6 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.6fr)]">
        <div className="flex items-start gap-4">
          <span className="grid size-12 shrink-0 place-items-center rounded-2xl" style={{ background: `color-mix(in oklab, ${tone} 16%, transparent)` }}>
            {real.length ? <ShieldAlert className="size-6" style={{ color: tone }} /> : <ShieldCheck className="size-6" style={{ color: tone }} />}
          </span>
          <div>
            <div className="text-sm text-ink-3">Attack posture</div>
            <div className="mt-1 text-2xl font-semibold tracking-tight">
              {real.length ? `${real.length} detection${real.length === 1 ? '' : 's'} on ${devices.size} device${devices.size === 1 ? '' : 's'}` : 'No attacks detected'}
            </div>
            <p className="mt-2 max-w-md text-sm leading-relaxed text-ink-2">
              {real.length
                ? <>Highest severity: <b>{worst}</b>. Each detection has response steps and a proposed scan-and-clean awaiting approval in Remediation.</>
                : <>{num(d.hunts.length)} searches ran across {num(d.devices.length)} devices in Microsoft Defender Advanced Hunting; none returned a sign of attack.</>}
            </p>
            {real.length > 0 && <button onClick={onOpen} className="mt-3 inline-flex items-center gap-1 text-sm font-medium text-blue hover:underline">Review detections <ChevronRight className="size-4" /></button>}
          </div>
        </div>
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          {([
            [num(real.length), 'Attacks detected', 'open findings', 'var(--tint-red)'],
            [num(devices.size), 'Devices affected', `of ${num(d.devices.length)} in Defender`, 'var(--tint-violet)'],
            [num(d.attacks.length), 'Attacks covered', `${num(searches)} searches`, 'var(--tint-blue)'],
            [`${num(ok)}/${num(d.hunts.length)}`, 'Searches completed', `${num(skipped)} skipped · ${num(failed)} failed`, failed ? 'var(--tint-red)' : 'var(--tint-blue)'],
          ] as const).map(([v, l, h, tint]) => (
            <div key={l} className="tint-box rounded-xl px-3.5 py-3" style={{ '--tint': tint } as React.CSSProperties}>
              <div className="tint-num tabular text-lg font-semibold leading-none">{v}</div>
              <div className="mt-1.5 text-[13px] font-medium leading-snug text-ink-2">{l}</div>
              <div className="mt-1 text-[11px] leading-snug text-ink-3">{h}</div>
            </div>
          ))}
        </div>
      </Panel>

      <div className="grid grid-cols-1 gap-5 xl:grid-cols-12">
        <Card className="xl:col-span-7" title="Detections by attack" description="Open findings for each of the 12 attacks; attacks without a detection are shown for coverage">
          <Chart height={330} build={(tk) => {
            const rows = [...d.attacks].sort((a, b) => b.attack - a.attack)
            return {
              grid: { left: 8, right: 28, top: 4, bottom: 4, containLabel: true },
              tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
              xAxis: { type: 'value', minInterval: 1, ...axisStyle(tk), axisLine: { show: false } },
              yAxis: { type: 'category', data: rows.map((a) => `${a.attack}  ${a.name}`), ...axisStyle(tk), splitLine: { show: false }, axisLabel: { color: tk.ink2 } },
              series: [{
                type: 'bar', barMaxWidth: 14, name: 'Detections',
                data: rows.map((a) => {
                  const n = real.filter((h) => h.attack === a.attack).length
                  return { value: n || 0.08, itemStyle: { color: n ? (tk.severity as Record<string, string>)[a.severity] ?? tk.severity.High : tk.series[3] } }
                }),
                itemStyle: { borderRadius: [0, 4, 4, 0] },
                label: { show: true, position: 'right', color: tk.ink, fontSize: 11, formatter: (p: { value: number }) => (p.value >= 1 ? String(p.value) : '') },
              }],
            }
          }} />
        </Card>
        <Card className="xl:col-span-5" title="Detections over time" description="First seen per day, last 14 days">
          <Chart height={330} build={(tk) => {
            const days = Array.from({ length: 14 }, (_, i) => new Date(Date.now() - (13 - i) * 86400000).toISOString().slice(0, 10))
            return {
              grid: { left: 8, right: 8, top: 12, bottom: 4, containLabel: true },
              tooltip: { trigger: 'axis' },
              xAxis: { type: 'category', data: days.map((x) => x.slice(5)), ...axisStyle(tk) },
              yAxis: { type: 'value', minInterval: 1, ...axisStyle(tk) },
              series: [{ type: 'bar', barMaxWidth: 16, name: 'Detections', itemStyle: { color: tk.severity.High, borderRadius: [4, 4, 0, 0] },
                         data: days.map((day) => real.filter((h) => utc(h.first_hit).slice(0, 10) === day).length) }],
            }
          }} />
        </Card>
      </div>

      <Card title="Managed devices" description="Devices listed in Microsoft Defender and their open detections">
        {perDevice.length ? (
          <DTable head={[['Device'], ['Device group (OpCo)'], ['OS'], ['Detections', 'right'], ['Highest severity'], ['Last seen by Defender']]}>
            {perDevice.map((x) => (
              <tr key={x.device_name}>
                <td className="font-medium">{x.device_name}</td>
                <td className="text-ink-2">{x.opco}</td>
                <td className="text-ink-2">{x.os_platform}</td>
                <td className="tabular text-right" style={{ fontWeight: x.n ? 600 : undefined }}>{num(x.n)}</td>
                <td>{x.worst ? <SevTag sev={x.worst} /> : <span className="text-ink-3">–</span>}</td>
                <td className="tabular text-ink-3">{x.last_seen?.slice(0, 16)}</td>
              </tr>
            ))}
          </DTable>
        ) : <Empty text="No devices loaded yet. Run the attack check to load the device list from Microsoft Defender." />}
      </Card>
    </div>
  )
}

/* ───────── attacks detected: small cards, details in a dialog ───────── */

function Detected({ d }: { d: AttackData }) {
  const { theme } = useTheme()
  const [sev, setSev] = useState<string[]>([])
  const [attack, setAttack] = useState('All')
  const [device, setDevice] = useState('All')
  const [tests, setTests] = useState(false)
  const [detected, setDetected] = useState<DateRange>({ preset: 'any' })
  const [open, setOpen] = useState<Finding | null>(null)
  const pool = d.hits.filter((h) => (tests || !h.is_test) && inDateRange(utc(h.first_hit), detected))
  const rows = pool
    .filter((h) => (!sev.length || sev.includes(h.severity)) && (attack === 'All' || String(h.attack) === attack) && (device === 'All' || h.device_name === device))
    .sort((a, b) => sevRank(a.severity) - sevRank(b.severity) || utc(b.first_hit).localeCompare(utc(a.first_hit)))
  const sevOptions = SEVERITIES.map((s) => ({ value: s, label: s, dot: chartTokens[theme].severity[s], count: pool.filter((h) => h.severity === s).length }))
  const attackOptions = [{ value: 'All', label: 'All attacks' },
    ...d.attacks.map((a) => ({ value: String(a.attack), label: `${a.attack}. ${a.name}`, count: pool.filter((h) => String(h.attack) === String(a.attack)).length }))]
  const deviceOptions = [{ value: 'All', label: 'All devices' },
    ...[...new Set(pool.map((h) => h.device_name))].sort().map((x) => ({ value: x, label: x, count: pool.filter((h) => h.device_name === x).length }))]
  const testOptions = [{ value: 'no', label: 'Real detections only' }, { value: 'yes', label: 'Include lab tests', count: d.hits.filter((h) => h.is_test).length }]
  const chips: ActiveFilter[] = [
    ...dateChip(detected, () => setDetected({ preset: 'any' })),
    ...menuChips('sev', sevOptions, sev, setSev),
    ...choiceChip('attack', attackOptions, attack, () => setAttack('All')),
    ...choiceChip('device', deviceOptions, device, () => setDevice('All')),
    ...choiceChip('tests', testOptions, tests ? 'yes' : 'no', () => setTests(false)),
  ]
  return (
    <div className="flex flex-col gap-4">
      <FilterBar chips={chips} onClear={() => { setSev([]); setAttack('All'); setDevice('All'); setTests(false); setDetected({ preset: 'any' }) }}
        count={`${num(rows.length)} of ${num(pool.length)} detections`}>
        <DateFilter label="Detected" value={detected} onChange={setDetected} />
        <FilterMenu label="Severity" icon={Siren} options={sevOptions} value={sev} onChange={setSev} />
        <FilterChoice label="Attack" icon={ShieldAlert} options={attackOptions} value={attack} onChange={setAttack} />
        <FilterChoice label="Device" icon={Monitor} options={deviceOptions} value={device} onChange={setDevice} />
        <FilterChoice label="Lab tests" icon={FlaskConical} options={testOptions} value={tests ? 'yes' : 'no'} onChange={(v) => setTests(v === 'yes')} />
      </FilterBar>
      {rows.length ? (
        <ul className="grid grid-cols-1 gap-3 md:grid-cols-2 2xl:grid-cols-3">
          {rows.map((h) => <li key={h.finding_id}><FindingCard h={h} onOpen={() => setOpen(h)} /></li>)}
        </ul>
      ) : <Empty text={pool.length ? 'No detections match these filters.' : `No attacks detected. ${num(d.hunts.length)} searches ran across ${num(d.devices.length)} devices.`} />}
      {open && <FindingDialog h={open} d={d} onClose={() => setOpen(null)} />}
    </div>
  )
}

function headline(h: Finding) {
  return (h.search_name || h.detail || 'Sign of attack').replace(/^(TEST:\s*)?Hunt hit:\s*/, '')
}

function RemediationChip({ h }: { h: Finding }) {
  const r = remediationLabel(h.remediation)
  return (
    <span className="inline-flex items-center gap-1.5 rounded-md px-1.5 py-0.5 text-[11px] font-medium" style={{ color: TONE[r.tone], background: `color-mix(in oklab, ${TONE[r.tone]} 12%, transparent)` }}>
      <Wrench className="size-3" /> {r.label}
    </span>
  )
}

function FindingCard({ h, onOpen }: { h: Finding; onOpen: () => void }) {
  return (
    <button onClick={onOpen} className="flex h-full w-full flex-col gap-2 rounded-xl border border-hairline bg-panel p-4 text-left transition-colors hover:border-hairline-strong hover:bg-well/40 focus-visible:outline-2 focus-visible:outline-blue">
      <div className="flex flex-wrap items-center gap-2 text-xs">
        <SevTag sev={h.severity} />
        <span className="text-ink-3">Attack {h.attack} · {h.attack_name}</span>
        {h.is_test && <span className="rounded bg-well px-1.5 py-0.5 text-[10px] font-semibold text-ink-2">LAB TEST</span>}
      </div>
      <div className="font-semibold leading-snug">{headline(h)}</div>
      <div className="text-xs text-ink-3">
        {h.device_name} · first seen {dateTime(utc(h.first_hit))}{h.technique ? ` · ${h.technique}` : ''}
      </div>
      <div className="mt-auto flex items-center justify-between gap-2 pt-1">
        <RemediationChip h={h} />
        <span className="inline-flex items-center gap-0.5 text-xs font-medium text-blue">Details <ChevronRight className="size-3.5" /></span>
      </div>
    </button>
  )
}

/** A hunt result value for reading: JSON text is expanded to "key: value" lines, lists joined. */
function readable(v: unknown): string {
  if (Array.isArray(v)) return v.filter((x) => x !== '' && x != null).join(', ')
  if (typeof v === 'string' && /^\s*[{[]/.test(v)) {
    try {
      const o = JSON.parse(v)
      if (o && typeof o === 'object') return Object.entries(o).map(([k, x]) => `${k}: ${typeof x === 'object' ? JSON.stringify(x) : String(x)}`).join('\n')
    } catch { /* not JSON: shown as it is */ }
  }
  return String(v)
}
/** Hunt column names in plain words (Advanced Hunting's own names are kept for the rest). */
const COLUMN: Record<string, string> = {
  ActionType: 'Action', FileName: 'File', FolderPath: 'Folder', SHA256: 'SHA-256', SHA1: 'SHA-1', MD5: 'MD5',
  ProcessCommandLine: 'Command line / details', InitiatingProcessFileName: 'Started by (process)',
  InitiatingProcessCommandLine: 'Parent command line', InitiatingProcessAccountName: 'Account', InitiatingProcessFolderPath: 'Process folder',
  RegistryKey: 'Registry key', RegistryValueName: 'Registry value', RegistryValueData: 'Value data', RemoteIP: 'Remote IP',
  RemotePort: 'Remote port', RemoteUrl: 'Remote URL', LocalIP: 'Local IP', AccountName: 'Account', LogonType: 'Logon type',
  CVEs: 'Vulnerabilities (CVE)', Software: 'Vulnerable software', Updates: 'Recommended updates', AdditionalFields: 'Details',
}

function Fact({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="min-w-0 rounded-lg bg-well px-3 py-2">
      <div className="text-[11px] text-ink-3">{label}</div>
      <div className="mt-0.5 text-sm font-medium [overflow-wrap:anywhere]">{children}</div>
    </div>
  )
}

function FindingDialog({ h, d, onClose }: { h: Finding; d: AttackData; onClose: () => void }) {
  const navigate = useNavigate()
  const shown = useShownName()
  const attack = d.attacks.find((a) => a.attack === h.attack)
  const search = attack?.searches.find((s) => s.key === h.search)
  const device = d.devices.find((x) => x.device_name === h.device_name)
  const others = d.hits.filter((x) => x.search === h.search && x.device_name !== h.device_name && x.is_test === h.is_test)
  const events = h.events ?? []
  const hidden = h.timeline.map((e) => decoded(e.what)).find(Boolean)
  const opco = h.opco && shown(h.opco) !== shown(h.device_name) ? h.opco : null
  const remediate = () => navigate(h.remediation ? `/fixes/attacks?show=all&fix=${encodeURIComponent(h.remediation.fix_id)}` : '/fixes/attacks')
  const technique = h.technique?.match(/^T\d{4}(\.\d{3})?$/) ? h.technique : null
  return (
    <DetailDialog onClose={onClose} title={headline(h)}
      eyebrow={<><SevTag sev={h.severity} /><span className="text-ink-3">Attack {h.attack} · {h.attack_name}</span><RemediationChip h={h} />{h.is_test && <span className="rounded bg-well px-1.5 py-0.5 text-[10px] font-semibold text-ink-2">LAB TEST</span>}</>}
      subtitle={`${h.device_name}${opco ? ` · ${opco}` : ''} · first seen ${dateTime(utc(h.first_hit))}`}
      footer={<>
        <span className="mr-auto text-xs text-ink-3">Remediation runs only after approval in the Remediation tab.</span>
        <button onClick={onClose} className="rounded-lg border border-hairline-strong bg-panel px-3.5 py-2 text-sm font-medium hover:bg-well">Close</button>
        <button onClick={remediate} className="btn-blue inline-flex items-center gap-1.5 rounded-lg px-3.5 py-2 text-sm font-semibold text-white"><Wrench className="size-4" /> Remediate</button>
      </>}>

      <div className="grid grid-cols-2 gap-2 md:grid-cols-3 xl:grid-cols-6">
        <Fact label="Device">{h.device_name}</Fact>
        <Fact label="Device group (OpCo)">{opco ?? '–'}</Fact>
        <Fact label="Operating system">{device?.os_platform ?? '–'}</Fact>
        <Fact label="First seen">{dateTime(utc(h.first_hit))}</Fact>
        <Fact label="Last seen">{h.last_hit ? dateTime(utc(h.last_hit)) : '–'}</Fact>
        <Fact label="Matching events">{num(h.event_count ?? events.length)}</Fact>
      </div>

      <DialogSection title="What happened">
        <p className="leading-relaxed">{h.resolution?.what_happened || h.detail}</p>
        {hidden && (
          <div className="mt-2.5 flex items-start gap-2 rounded-lg bg-signal/10 p-2.5 text-xs">
            <Lock className="mt-0.5 size-3.5 shrink-0 text-signal" />
            <span><b>Decoded command:</b> <code className="break-all font-mono">{hidden}</code></span>
          </div>
        )}
      </DialogSection>

      <DialogSection title="What the search looked for" aside={technique && <a className="text-blue hover:underline" href={`https://attack.mitre.org/techniques/${technique.replace('.', '/')}/`} target="_blank" rel="noreferrer">MITRE ATT&CK {technique}</a>}>
        <p className="font-medium">{h.search_name}</p>
        {attack && <p className="mt-1 leading-relaxed text-ink-2">Part of attack {attack.attack}, {attack.name.toLowerCase()}: {attack.description} <span className="text-ink-3">Tactics: {attack.tactics}.</span></p>}
        {search?.query && (
          <details className="group mt-2">
            <summary className="flex cursor-pointer list-none items-center gap-1 text-xs font-medium text-ink-2 hover:text-ink">
              <ChevronRight className="size-3.5 transition-transform group-open:rotate-90" /> Show the Advanced Hunting query
            </summary>
            <pre className="mt-2 max-h-72 overflow-auto rounded-lg bg-well p-3 font-mono text-[11px] leading-relaxed text-ink-2">{search.query.replace(/\{\{LOOKBACK\}\}/g, '30')}</pre>
          </details>
        )}
      </DialogSection>

      <DialogSection title="What it found" aside={events.length < (h.event_count ?? 0) ? `latest ${events.length} of ${num(h.event_count ?? 0)}` : `${num(events.length)} event${events.length === 1 ? '' : 's'}`}>
        {events.length ? (
          <ol className="flex flex-col gap-2.5">
            {events.map((e, i) => (
              <li key={i} className="rounded-lg border border-hairline p-3">
                <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-ink-3">
                  <span className="tabular font-medium text-ink-2">{e.time ? dateTime(utc(e.time)) : 'Time not recorded'}</span>
                  {e.account && <span className="inline-flex items-center gap-1"><User className="size-3" />{e.account}</span>}
                </div>
                <dl className="mt-2 grid grid-cols-1 gap-x-4 gap-y-1.5 sm:grid-cols-[minmax(0,180px)_minmax(0,1fr)]">
                  {Object.entries(e.columns).map(([k, v]) => (
                    <div key={k} className="contents">
                      <dt className="text-xs text-ink-3">{COLUMN[k] ?? k}</dt>
                      <dd className="whitespace-pre-wrap font-mono text-xs leading-relaxed [overflow-wrap:anywhere]">{readable(v)}</dd>
                    </div>
                  ))}
                </dl>
              </li>
            ))}
          </ol>
        ) : <p className="text-ink-3">The search results behind this finding are no longer stored; the timeline below summarises them.</p>}
      </DialogSection>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <DialogSection title="Accounts signed in to the device">
          {h.sign_ins?.length ? (
            <ul className="flex flex-col gap-1.5">
              {h.sign_ins.map((u) => (
                <li key={u.account} className="flex flex-wrap items-center gap-x-2 text-sm">
                  <User className="size-3.5 text-ink-3" /><span className="font-medium">{u.account}</span>
                  <span className="text-xs text-ink-3">{[u.logon_types?.join(', '), u.logons != null ? `${u.logons} sign-ins` : '', u.last_logon ? `last ${dateTime(utc(u.last_logon))}` : ''].filter(Boolean).join(' · ')}</span>
                </li>
              ))}
            </ul>
          ) : <p className="text-ink-3">No sign-ins recorded by Defender for this device.</p>}
        </DialogSection>
        <DialogSection title="Defender alerts on the device (±24 h)">
          {h.alerts.length ? <ul className="flex flex-col gap-1">{h.alerts.map((a) => <li key={a}>{a}</li>)}</ul>
            : <p className="text-ink-3">None. Microsoft Defender raised no alert for this activity; only the hunt found it.</p>}
        </DialogSection>
      </div>

      {others.length > 0 && (
        <DialogSection title="Same finding on other devices">
          <div className="flex flex-wrap gap-1.5">{others.map((x) => <span key={x.finding_id} className="rounded-md bg-well px-2 py-0.5 text-xs">{x.device_name} · first seen {dateTime(utc(x.first_hit))}</span>)}</div>
        </DialogSection>
      )}

      {h.timeline.length > 0 && (
        <DialogSection title="Timeline" aside={`${h.timeline.length} entr${h.timeline.length === 1 ? 'y' : 'ies'}`}>
          <ol className="border-l border-hairline pl-3">
            {h.timeline.map((e, i) => (
              <li key={i} className="relative pb-2 text-xs last:pb-0">
                <span className="absolute -left-[16.5px] top-1 size-2 rounded-full bg-hairline ring-2 ring-panel" />
                <span className="tabular text-ink-3">{e.time.slice(5, 16)}</span> <span className="text-ink-2 [overflow-wrap:anywhere]">{e.what.split(' | decoded command: ')[0].slice(0, 300)}</span>
              </li>
            ))}
          </ol>
        </DialogSection>
      )}

      <DialogSection title="Response steps">
        {h.resolution ? <Resolve r={h.resolution} title="" />
          : <p>Confirm with the device owner whether this activity was expected. If not, isolate {h.device_name} in Microsoft Defender and escalate to the SOC.</p>}
      </DialogSection>
    </DetailDialog>
  )
}

/* ───────── attack coverage: the 12 attacks ───────── */

function Coverage({ d }: { d: AttackData }) {
  const status = useMemo(() => new Map(d.hunts.map((h) => [h.name, h.status])), [d])
  const real = d.hits.filter((h) => !h.is_test)
  return (
    <div className="flex flex-col gap-4">
      <p className="max-w-3xl text-sm text-ink-2">
        Every run executes {num(d.attacks.reduce((n, a) => n + a.searches.length, 0))} Advanced Hunting queries in Microsoft Defender, grouped by the 12 attacks below.
        Each attack has a lab test that produces harmless activity of that kind, so a detection can be confirmed on purpose.
      </p>
      <ul className="grid grid-cols-1 gap-3 md:grid-cols-2 2xl:grid-cols-3">
        {d.attacks.map((a) => {
          const hits = real.filter((h) => h.attack === a.attack).length
          const skipped = a.searches.filter((s) => status.get(s.name) === 'skipped').length
          const tone = hits ? statusColor.critical : statusColor.good
          return (
            <li key={a.attack}>
              <Panel className="flex h-full flex-col gap-2 p-4">
                <div className="flex items-start justify-between gap-2">
                  <div className="flex items-center gap-2.5">
                    <span className="grid size-8 shrink-0 place-items-center rounded-lg bg-well text-sm font-semibold tabular">{a.attack}</span>
                    <div>
                      <div className="font-semibold leading-tight">{a.name}</div>
                      <div className="text-[11px] text-ink-3">{a.tactics}</div>
                    </div>
                  </div>
                  <SevTag sev={a.severity} />
                </div>
                <p className="text-sm leading-relaxed text-ink-2">{a.description}</p>
                <div className="flex flex-wrap items-center gap-2 text-xs">
                  <span className="inline-flex items-center gap-1.5 font-medium" style={{ color: tone }}>
                    <span className="size-2 rounded-full" style={{ background: tone }} />
                    {hits ? `${hits} detection${hits === 1 ? '' : 's'}` : 'No detection in 30 days'}
                  </span>
                  {skipped > 0 && <span className="text-ink-3">· {skipped} skipped: needs a domain-joined device</span>}
                </div>
                <details className="group mt-auto">
                  <summary className="flex cursor-pointer list-none items-center gap-1 text-xs font-medium text-ink-2 hover:text-ink">
                    <ChevronRight className="size-3.5 transition-transform group-open:rotate-90" /> {a.searches.length} searches · lab test {a.lab_test}
                  </summary>
                  <ul className="mt-2 flex flex-col gap-1 text-xs">
                    {a.searches.map((s) => (
                      <li key={s.key} className="flex items-start justify-between gap-3">
                        <span className="text-ink-2">{s.name}</span>
                        <span className="tabular shrink-0 text-ink-3">{s.technique}</span>
                      </li>
                    ))}
                  </ul>
                </details>
              </Panel>
            </li>
          )
        })}
      </ul>
    </div>
  )
}

/* ───────── search health: every query of the latest run ───────── */

function Health({ d }: { d: AttackData }) {
  const [q, setQ] = useState('')
  const [only, setOnly] = useState<'all' | 'hits' | 'skipped' | 'errors'>('all')
  const errors = d.hunts.filter((h) => h.status !== 'ok' && h.status !== 'skipped').length
  const hunts = d.hunts.filter((h) =>
    (only === 'all' || (only === 'hits' && h.row_count > 0) || (only === 'skipped' && h.status === 'skipped') || (only === 'errors' && h.status !== 'ok' && h.status !== 'skipped')) &&
    (!q || `${h.name} ${h.technique ?? ''}`.toLowerCase().includes(q.toLowerCase())))
  const onlyOptions = [{ value: 'all', label: 'All queries', count: d.hunts.length },
    { value: 'hits', label: 'Returned results', count: d.hunts.filter((h) => h.row_count > 0).length, dot: statusColor.critical },
    { value: 'skipped', label: 'Skipped', count: d.hunts.filter((h) => h.status === 'skipped').length, dot: statusColor.warning },
    { value: 'errors', label: 'Failed', count: errors, dot: statusColor.critical }]
  return (
    <div className="flex flex-col gap-5">
      <Card title="Queries by MITRE ATT&CK technique" description="Number of Advanced Hunting queries per technique; highlighted techniques returned results">
        <Chart
          height={Math.max(240, new Set(d.hunts.map((h) => h.technique)).size * 26 + 40)}
          build={(tk) => {
            const by: Record<string, { n: number; rows: number }> = {}
            d.hunts.forEach((h) => {
              const k = h.technique ?? 'other'
              by[k] = by[k] ?? { n: 0, rows: 0 }
              by[k].n += 1
              by[k].rows += h.row_count
            })
            const list = Object.entries(by).sort((a, b) => a[1].n - b[1].n)
            return {
              grid: { left: 8, right: 36, top: 4, bottom: 4, containLabel: true },
              tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' }, formatter: (p: { name: string; value: number; dataIndex: number }[]) => `<b>${p[0].name}</b><br>${p[0].value} quer${p[0].value === 1 ? 'y' : 'ies'} · ${list[p[0].dataIndex][1].rows} result row(s)` },
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
      </Card>
      <Card
        title="Queries in the latest run"
        description="Every query runs on each check; the five that need Active Directory are skipped when no device is domain-joined"
      >
        <FilterBar className="mb-3" chips={[
          ...(q ? [{ key: 'q', label: `“${q}”`, onRemove: () => setQ('') }] : []),
          ...choiceChip('only', onlyOptions, only, () => setOnly('all')),
        ]} onClear={() => { setQ(''); setOnly('all') }} count={`${num(hunts.length)} queries`}>
          <FilterSearch value={q} onChange={setQ} placeholder="Query or technique" />
          <FilterChoice label="Result" icon={ListChecks} options={onlyOptions} value={only} onChange={(v) => setOnly(v as typeof only)} />
        </FilterBar>
        {hunts.length ? (
          <DTable head={[['Query'], ['Technique'], ['Status'], ['Results', 'right']]} minWidth={640} maxHeight={480}>
            {hunts.map((h, i) => (
              <tr key={i}>
                <td className="font-medium">{h.name}</td>
                <td className="tabular text-ink-2">{h.technique ?? '–'}</td>
                <td title={h.error ?? ''}>
                  <span className="inline-flex items-center gap-1.5"><span className="size-2 rounded-full" style={{ background: h.status === 'ok' ? statusColor.good : h.status === 'skipped' ? statusColor.warning : statusColor.critical }} />{h.status === 'ok' ? 'Completed' : h.status === 'skipped' ? 'Skipped' : 'Failed'}</span>
                </td>
                <td className="tabular text-right" style={{ fontWeight: h.row_count ? 600 : undefined }}>{num(h.row_count)}</td>
              </tr>
            ))}
          </DTable>
        ) : <Empty text="No queries match." />}
      </Card>
    </div>
  )
}
