import { Fragment, useMemo, useState, type ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { ChevronDown, ChevronRight, Download, Search, ShieldAlert, ShieldCheck } from 'lucide-react'
import { Choice, DTable, Empty, Panel } from '@/components/kit'
import { num } from '@/lib/format'
import { cn } from '@/lib/utils'

// The Audit log (src/portal/audit.py): who ran a pipeline, approved or ran a remediation, or answered a triage
// verdict, and when. Read-only; the hash chain is checked on the server every time the page loads.

interface Entry {
  seq?: number
  at: string
  user_email: string
  user_name: string
  ip: string | null
  action: string
  label: string
  agent: string
  target: string
  outcome: 'success' | 'failed' | 'refused'
  detail: string
  ref: string | null
  hash?: string
  prev?: string
  source: 'audit' | 'signin'
}

interface Integrity { ok: boolean; count: number; broken_at: number | null; last_hash?: string | null; message: string }

async function fetchAudit(): Promise<{ entries: Entry[]; integrity: Integrity }> {
  const res = await fetch('/api/audit')
  if (!res.ok) throw new Error(`Portal API answered ${res.status}`)
  return res.json()
}

const KINDS: [string, string][] = [['all', 'All activity'], ['run', 'Pipeline runs'], ['fix', 'Remediation'], ['triage', 'Alert triage'], ['auth', 'Sign-ins']]
const OUTCOMES: [string, string][] = [['all', 'Any outcome'], ['success', 'Succeeded'], ['problem', 'Failed or refused']]
const PERIODS: [string, string, number][] = [['7d', 'Last 7 days', 7], ['24h', 'Last 24 hours', 1], ['30d', 'Last 30 days', 30], ['all', 'All time', 0]]
const PAGE = 100

const when = (iso: string) => new Date(iso).toLocaleString('en-GB', { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' })
const runUc = (ref: string | null) => ref?.match(/_(uc[134]|attack)$/)?.[1]

export function AuditLog() {
  const { data, error } = useQuery({ queryKey: ['audit'], queryFn: fetchAudit, refetchInterval: 30_000 })
  const [kind, setKind] = useState('all')
  const [person, setPerson] = useState('all')
  const [outcome, setOutcome] = useState('all')
  const [period, setPeriod] = useState('7d')
  const [q, setQ] = useState('')
  const [shown, setShown] = useState(PAGE)
  const [open, setOpen] = useState<string | null>(null)

  const entries = useMemo(() => data?.entries ?? [], [data])
  const people = useMemo(() => {
    const m = new Map<string, string>()
    entries.forEach((e) => m.set(e.user_email, e.user_name))
    return [...m].sort((a, b) => a[1].localeCompare(b[1]))
  }, [entries])

  const rows = useMemo(() => {
    const days = PERIODS.find((p) => p[0] === period)?.[2] ?? 0
    const since = days ? Date.now() - days * 86_400_000 : 0
    const needle = q.trim().toLowerCase()
    return entries.filter((e) =>
      (kind === 'all' || e.action.startsWith(kind + '.'))
      && (person === 'all' || e.user_email === person)
      && (outcome === 'all' || (outcome === 'success' ? e.outcome === 'success' : e.outcome !== 'success'))
      && (!since || new Date(e.at).getTime() >= since)
      && (!needle || [e.user_name, e.user_email, e.label, e.agent, e.target, e.detail, e.ref].some((v) => v?.toLowerCase().includes(needle))))
  }, [entries, kind, person, outcome, period, q])

  const stats = useMemo(() => {
    const day = Date.now() - 86_400_000
    const actions = rows.filter((e) => e.source === 'audit')
    return {
      actions: actions.length,
      people: new Set(actions.map((e) => e.user_email)).size,
      problems: actions.filter((e) => e.outcome !== 'success').length,
      today: actions.filter((e) => new Date(e.at).getTime() >= day).length,
    }
  }, [rows])

  const reset = (f: (v: string) => void) => (v: string) => { f(v); setShown(PAGE) }

  return (
    <div className="flex flex-col gap-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Audit log</h1>
          <p className="mt-1 text-sm text-ink-3">Every pipeline run, remediation action and triage decision made in the portal, with who did it and when.</p>
        </div>
        <button
          onClick={() => exportCsv(rows, data?.integrity)}
          disabled={!rows.length}
          className="flex h-9 items-center gap-2 rounded-lg border border-hairline-strong bg-panel px-3 text-sm font-medium text-ink transition-colors hover:bg-well disabled:opacity-50"
        >
          <Download className="size-4" /> Export CSV
        </button>
      </div>

      {error && <Empty text={String((error as Error).message)} />}
      {data && <IntegrityBanner integrity={data.integrity} />}

      {data && (
        <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
          <Stat label="Actions in view" value={stats.actions} />
          <Stat label="In the last 24 hours" value={stats.today} />
          <Stat label="People" value={stats.people} />
          <Stat label="Failed or refused" value={stats.problems} tone={stats.problems ? 'warn' : undefined} />
        </div>
      )}

      {data && (
        <Panel className="flex flex-col gap-4 p-5">
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 xl:grid-cols-[minmax(220px,1.4fr)_repeat(4,minmax(0,1fr))]">
            <label className="flex items-center gap-2 rounded-lg border border-hairline-strong bg-field px-3 focus-within:border-blue/60 focus-within:ring-3 focus-within:ring-blue/15">
              <Search className="size-4 shrink-0 text-ink-3" />
              <input value={q} onChange={(e) => { setQ(e.target.value); setShown(PAGE) }} placeholder="Search person, device, incident…"
                className="h-9 min-w-0 flex-1 bg-transparent text-sm outline-none placeholder:text-ink-3" aria-label="Search the audit log" />
            </label>
            <Choice label="Activity" value={kind} onChange={reset(setKind)} options={KINDS.map(([value, label]) => ({ value, label }))} />
            <Choice label="Person" value={person} onChange={reset(setPerson)}
              options={[{ value: 'all', label: 'Everyone' }, ...people.map(([value, label]) => ({ value, label }))]} />
            <Choice label="Outcome" value={outcome} onChange={reset(setOutcome)} options={OUTCOMES.map(([value, label]) => ({ value, label }))} />
            <Choice label="Period" value={period} onChange={reset(setPeriod)} options={PERIODS.map(([value, label]) => ({ value, label }))} />
          </div>

          {rows.length ? (
            <>
              <DTable head={[['', 'left'], ['When'], ['Person'], ['Action'], ['Agent'], ['Target'], ['Outcome']]} minWidth={980}>
                {rows.slice(0, shown).map((e) => {
                  const key = e.source + (e.seq ?? e.at + e.user_email + e.action)
                  const isOpen = open === key
                  return (
                    <Fragment key={key}>
                      <tr onClick={() => setOpen(isOpen ? null : key)} className={cn('cursor-pointer hover:bg-well/60', isOpen && 'bg-well/60')}>
                        <td className="w-8 text-ink-3">{isOpen ? <ChevronDown className="size-4" /> : <ChevronRight className="size-4" />}</td>
                        <td className="tabular whitespace-nowrap text-ink-2">{when(e.at)}</td>
                        <td className="max-w-48">
                          <div className="truncate font-medium text-ink">{e.user_name}</div>
                          <div className="truncate text-xs text-ink-3">{e.user_email}</div>
                        </td>
                        <td className="whitespace-nowrap">{e.label}</td>
                        <td className="whitespace-nowrap text-ink-2">{e.agent || '–'}</td>
                        <td className="min-w-40 text-ink-2"><div className="line-clamp-2 break-words" title={e.target}>{e.target || '–'}</div></td>
                        <td><Outcome value={e.outcome} /></td>
                      </tr>
                      {isOpen && (
                        <tr className="bg-well/40">
                          <td />
                          <td colSpan={6}><Details e={e} /></td>
                        </tr>
                      )}
                    </Fragment>
                  )
                })}
              </DTable>
              <div className="flex items-center justify-between text-xs text-ink-3">
                <span>Showing {num(Math.min(shown, rows.length))} of {num(rows.length)} entries · times in your local time zone</span>
                {shown < rows.length && (
                  <button onClick={() => setShown((s) => s + PAGE)} className="rounded-lg border border-hairline-strong px-3 py-1.5 text-sm font-medium text-ink hover:bg-well">
                    Show {num(Math.min(PAGE, rows.length - shown))} more
                  </button>
                )}
              </div>
            </>
          ) : (
            <Empty text={entries.length ? 'Nothing matches these filters.' : 'Nothing recorded yet. Runs, remediation and triage actions appear here as people use the portal.'} />
          )}
        </Panel>
      )}
    </div>
  )
}

function IntegrityBanner({ integrity }: { integrity: Integrity }) {
  const ok = integrity.ok
  const Icon = ok ? ShieldCheck : ShieldAlert
  return (
    <Panel className={cn('flex items-start gap-4 p-5', !ok && 'border border-rose/50')}>
      <span className={cn('grid size-11 shrink-0 place-items-center rounded-xl', ok ? 'bg-teal/12 text-teal' : 'bg-rose/12 text-rose')}>
        <Icon className="size-6" />
      </span>
      <div className="min-w-0 flex-1">
        <div className="font-semibold">{ok ? 'Log verified: no entry has been altered' : 'Warning: the audit log has been altered'}</div>
        <p className="mt-0.5 text-sm text-ink-3">
          {integrity.message}. Each entry is sealed with a SHA-256 fingerprint that includes the entry before it, so changing,
          deleting or reordering any entry is detected.{ok ? ' Sign-ins come from the sign-in log and are shown alongside.' : ''}
        </p>
        {ok && integrity.last_hash && (
          <p className="mt-2 truncate font-mono text-[11px] text-ink-3" title={integrity.last_hash}>Latest fingerprint · {integrity.last_hash}</p>
        )}
      </div>
    </Panel>
  )
}

function Stat({ label, value, tone }: { label: string; value: number; tone?: 'warn' }) {
  return (
    <Panel className="px-5 py-4">
      <div className="text-xs font-medium text-ink-3">{label}</div>
      <div className={cn('tabular mt-1 text-2xl font-semibold tracking-tight', tone === 'warn' && 'text-amber')}>{num(value)}</div>
    </Panel>
  )
}

function Outcome({ value }: { value: Entry['outcome'] }) {
  const s = { success: ['Succeeded', 'bg-teal'], failed: ['Failed', 'bg-rose'], refused: ['Refused', 'bg-amber'] }[value] ?? [value, 'bg-ink-3']
  return (
    <span className="inline-flex items-center gap-1.5 whitespace-nowrap text-ink-2">
      <span className={cn('size-2 rounded-full', s[1])} /> {s[0]}
    </span>
  )
}

function Details({ e }: { e: Entry }) {
  const uc = runUc(e.ref)
  const items: [string, ReactNode][] = [
    ['Details', e.detail || '–'],
    ['Target', e.target || '–'],
    ['Exact time (UTC)', e.at],
    ['From', e.ip || '–'],
  ]
  if (e.ref) items.push(['Run', uc ? <Link to={`/runs/${uc}`} className="text-sky hover:underline">{e.ref}</Link> : e.ref])
  if (e.source === 'audit') {
    items.push(['Entry', `#${e.seq}`])
    items.push(['Fingerprint', <span className="break-all font-mono text-[11px]">{e.hash}</span>])
  } else {
    items.push(['Source', 'Sign-in log'])
  }
  return (
    <dl className="grid grid-cols-1 gap-x-8 gap-y-2 py-1 text-sm sm:grid-cols-[max-content_1fr]">
      {items.map(([k, v]) => (
        <Fragment key={k}>
          <dt className="text-xs font-medium text-ink-3 sm:pt-0.5">{k}</dt>
          <dd className="min-w-0 break-words text-ink-2">{v}</dd>
        </Fragment>
      ))}
    </dl>
  )
}

/** The rows in view (filters applied), with the fingerprints, as a CSV an auditor can open in Excel. */
function exportCsv(rows: Entry[], integrity?: Integrity) {
  const cell = (v: unknown) => {
    let s = String(v ?? '')
    if (/^[=+\-@]/.test(s)) s = "'" + s              // never let Excel read a cell as a formula
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s
  }
  const head = ['Time (UTC)', 'Person', 'Email', 'Action', 'Agent', 'Target', 'Outcome', 'Details', 'From', 'Run', 'Entry', 'Fingerprint', 'Previous fingerprint']
  const lines = rows.map((e) => [e.at, e.user_name, e.user_email, e.label, e.agent, e.target, e.outcome, e.detail, e.ip, e.ref,
    e.seq ?? 'sign-in log', e.hash, e.prev].map(cell).join(','))
  // the last line says when it was exported and whether the chain checked out at that moment
  const note = integrity ? cell(`Exported ${new Date().toISOString()}: ${integrity.ok ? 'chain verified' : 'CHAIN BROKEN'}. ${integrity.message}`) : ''
  const blob = new Blob(['﻿' + [head.join(','), ...lines, '', note].join('\r\n')], { type: 'text/csv;charset=utf-8' })
  const a = document.createElement('a')
  a.href = URL.createObjectURL(blob)
  a.download = `Audit_Log_${new Date().toISOString().slice(0, 10)}.csv`
  a.click()
  setTimeout(() => URL.revokeObjectURL(a.href), 1000)
}
