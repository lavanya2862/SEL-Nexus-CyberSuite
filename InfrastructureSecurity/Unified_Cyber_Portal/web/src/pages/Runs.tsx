import { useEffect, useMemo, useRef, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import {
  AlertTriangle, ArrowRight, BellRing, Check, CheckCircle2, ChevronDown, Clock, Download, Hand, Minus, Play, Radar, ShieldAlert, Terminal, WifiOff, X, XCircle,
} from 'lucide-react'
import { Panel } from '@/components/kit'
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from '@/components/ui/dropdown-menu'
import { NewFixes } from '@/components/NewFixes'
import { dateTime } from '@/lib/format'
import { statusColor } from '@/lib/theme'
import { cn } from '@/lib/utils'
import {
  PLANNED_STEPS, UC_DOT, UC_KEYS, UC_NAME, fmtSeconds, typicalLabel, useElapsed, useRuns, type RunFinding, type RunState, type StepStatus, type UcKey,
} from '@/lib/runs'

type ViewStep = { label: string; description: string; status: StepStatus; detail: string; started_at: string | null; finished_at: string | null }

const RESULTS: Record<UcKey, { to: string; label: string }> = {
  uc3: { to: '/uc3', label: 'View vulnerabilities' },
  uc1: { to: '/uc1', label: 'View threat intelligence' },
  uc4: { to: '/respond', label: 'View alert queue' },
  attack: { to: '/uc1/hunts', label: 'View detections' },
}

export function Runs() {
  const params = useParams()
  const navigate = useNavigate()
  const { runs, offline, start, starting, refused } = useRuns()
  // default tab: whichever pipeline is running, else UC3
  const uc: UcKey = UC_KEYS.includes(params.uc as UcKey)
    ? (params.uc as UcKey)
    : UC_KEYS.find((k) => runs?.[k]?.status === 'running') ?? 'uc3'
  const run = runs?.[uc] ?? null
  const running = run?.status === 'running' || starting === uc
  const live = run?.status === 'running' && !offline
  const elapsed = useElapsed(run?.started_at, run?.finished_at, live)
  const steps: ViewStep[] = run?.steps ?? PLANNED_STEPS[uc].map((p) => ({ ...p, status: 'pending' as StepStatus, detail: '', started_at: null, finished_at: null }))
  const finished = steps.filter((s) => ['done', 'skipped', 'error'].includes(s.status)).length
  // the Fix stage is waiting for a person: the run is not over until every new fix has a decision
  const waiting = !!run?.waiting_for_you && run.status !== 'running'
  const pct = !run ? 0 : run.status === 'running' || waiting ? Math.round((finished / steps.length) * 100) : 100
  const current = steps.findIndex((s) => s.status === 'running')

  return (
    <div className="flex flex-col gap-5">
      {/* header */}
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Agents</h1>
          <p className="mt-1 text-sm text-ink-3">Run an agent on demand and track each stage in real time. Runs continue in the background if you leave this page.</p>
        </div>
        <div className="flex rounded-xl border border-hairline bg-panel p-1" role="tablist" aria-label="Agent">
          {UC_KEYS.map((k) => {
            const r = runs?.[k]
            return (
              <button
                key={k}
                role="tab"
                aria-selected={uc === k}
                onClick={() => navigate(`/runs/${k}`)}
                className={cn('flex items-center gap-2 rounded-lg px-3.5 py-2 text-sm', uc === k ? 'bg-blue/15 text-ink ring-1 ring-inset ring-blue/45' : 'text-ink-2 hover:bg-well')}
              >
                <span className={cn('size-2 rounded-full', UC_DOT[k], r?.status === 'running' && 'animate-pulse')} />
                <span className="font-medium">{UC_NAME[k]}</span>
              </button>
            )
          })}
        </div>
      </div>

      {offline && (
        <div className="flex items-start gap-3 rounded-xl border px-4 py-3 text-sm animate-in fade-in" style={{ borderColor: statusColor.warning }}>
          <WifiOff className="mt-0.5 size-4 shrink-0" style={{ color: statusColor.warning }} />
          <span>
            <b>Connection to the portal service was lost.</b> A run keeps going in the background and is recorded; this page catches up as soon as the
            portal answers again. The timer is paused until then.
          </span>
        </div>
      )}

      {refused?.uc === uc && refused.message !== 'already running' && (
        <div className="flex items-start gap-3 rounded-xl border px-4 py-3 text-sm animate-in fade-in" style={{ borderColor: statusColor.warning }}>
          <AlertTriangle className="mt-0.5 size-4 shrink-0" style={{ color: statusColor.warning }} />
          <span><b>Not started.</b> {refused.message}</span>
        </div>
      )}

      {/* status + horizontal pipeline */}
      <Panel className="overflow-hidden">
        <div className="flex flex-wrap items-center justify-between gap-4 px-6 pt-6">
          <StatusHeadline run={run} uc={uc} elapsed={elapsed} running={running} current={current} total={steps.length} offline={offline} waiting={waiting} />
          <div className="flex items-center gap-4">
            <div className="text-right">
              <div className="tabular text-3xl font-semibold leading-none tracking-tight">{pct}%</div>
              <div className="mt-1 text-xs text-ink-3">{finished} of {steps.length} steps</div>
            </div>
            <button
              onClick={() => start(uc)}
              disabled={running || waiting}
              title={waiting ? 'Paused: approve or defer every new remediation below to run again' : undefined}
              className="inline-flex items-center gap-2 rounded-xl btn-blue px-5 py-3 text-sm font-medium text-white disabled:cursor-not-allowed disabled:opacity-50"
            >
              {waiting ? <Hand className="size-4" /> : <Play className="size-4" />}
              {running ? 'Running…' : waiting ? 'Paused: awaiting remediation approval' : run ? 'Run again' : `Run ${UC_NAME[uc].toLowerCase()} now`}
            </button>
          </div>
        </div>

        <div className="mx-6 mt-5 h-2 overflow-hidden rounded-full bg-well">
          <div
            className="relative h-full rounded-full bg-sky transition-[width] duration-700 ease-out"
            style={{ width: `${Math.max(pct, running ? 3 : 0)}%`, background: run?.status === 'failed' ? statusColor.critical : undefined }}
          >
            {live && <span className="absolute inset-0 animate-[portal-shimmer_1.4s_linear_infinite] bg-[linear-gradient(90deg,transparent,rgba(255,255,255,.6),transparent)] bg-[length:40%_100%] bg-no-repeat" />}
          </div>
        </div>

        <HorizontalSteps steps={steps} live={live} />
      </Panel>

      {run && run.status !== 'running' && <ResultPanel run={run} uc={uc} seconds={elapsed} />}

      {/* the Fix stage's human approval: the fixes this run proposed, to fix now or save for later */}
      {run?.fix && run.status !== 'running' && <NewFixes fix={run.fix} uc={uc} since={run.started_at} />}

      <div className="grid grid-cols-1 gap-5 xl:grid-cols-12">
        <LogPanel uc={uc} run={run} live={live} />
        <History uc={uc} />
      </div>
    </div>
  )
}

/* ───────── headline ───────── */

function StatusHeadline({ run, uc, elapsed, running, current, total, offline, waiting }: {
  run: RunState | null; uc: UcKey; elapsed: number; running: boolean; current: number; total: number; offline: boolean; waiting: boolean
}) {
  const typical = typicalLabel(uc, run?.typical_seconds)
  let icon = <Clock className="size-5 text-ink-3" />
  let title = 'Ready to run'
  let sub = `${total} steps · ${typical}`
  if (running && run) {
    icon = <span className="relative grid size-5 place-items-center"><span className="absolute size-5 animate-ping rounded-full bg-sky/40" /><span className="size-2.5 rounded-full bg-sky" /></span>
    title = current >= 0 ? `Step ${current + 1} of ${total}: ${run.steps[current].label}` : 'Starting…'
    sub = `Started ${dateTime(run.started_at)} · ${fmtSeconds(elapsed)} so far${offline ? ' (paused: portal service unavailable)' : ''} · ${typical}`
  } else if (running) {
    title = 'Starting…'
  } else if (run) {
    const map = {
      ok: { i: <CheckCircle2 className="size-5" style={{ color: statusColor.good }} />, t: `Finished in ${fmtSeconds(elapsed)}` },
      partial: { i: <AlertTriangle className="size-5" style={{ color: statusColor.warning }} />, t: `Finished with problems in ${fmtSeconds(elapsed)}` },
      skipped: { i: <AlertTriangle className="size-5" style={{ color: statusColor.warning }} />, t: 'Skipped: another run was already in progress' },
      failed: { i: <XCircle className="size-5" style={{ color: statusColor.critical }} />, t: 'The run stopped' },
      running: { i: icon, t: title },
    } as const
    icon = map[run.status].i
    title = map[run.status].t
    sub = `${dateTime(run.started_at)}${run.finished_at ? ` → ${dateTime(run.finished_at)}` : ''} · ${typical}`
    if (waiting) {
      const open = run.fix?.open ?? 0
      icon = <Hand className="size-5 animate-pulse" style={{ color: statusColor.warning }} />
      title = `Action required: ${open} new remediation${open === 1 ? '' : 's'} awaiting approval`
      sub = `The agent finished in ${fmtSeconds(elapsed)}. Approve or defer each remediation below to complete the run.`
    }
  }
  return (
    <div className="flex min-w-0 items-start gap-3">
      <span className="mt-1">{icon}</span>
      <div className="min-w-0">
        <div className="flex items-center gap-2 text-xs font-medium text-ink-3">
          <span className={cn('size-2 rounded-full', UC_DOT[uc])} /> Agent · {UC_NAME[uc]}
        </div>
        <h2 className="mt-0.5 text-xl font-semibold tracking-tight">{title}</h2>
        <p className="text-sm text-ink-3">{sub}</p>
      </div>
    </div>
  )
}

/* ───────── the pipeline, left to right ───────── */

function HorizontalSteps({ steps, live }: { steps: ViewStep[]; live: boolean }) {
  return (
    <div className="overflow-x-auto px-6 pb-7 pt-8">
      <ol className="grid min-w-[760px]" style={{ gridTemplateColumns: `repeat(${steps.length}, minmax(0, 1fr))` }}>
        {steps.map((s, i) => (
          <StepColumn key={s.label} step={s} index={i} first={i === 0} last={i === steps.length - 1} prevDone={i > 0 && isFinished(steps[i - 1].status)} live={live} />
        ))}
      </ol>
    </div>
  )
}

const isFinished = (s: StepStatus) => s === 'done' || s === 'skipped' || s === 'error'   // not 'waiting': a person still has to decide

function StepColumn({ step, index, first, last, prevDone, live }: { step: ViewStep; index: number; first: boolean; last: boolean; prevDone: boolean; live: boolean }) {
  const secs = useElapsed(step.started_at, step.finished_at, live && step.status === 'running')
  const done = isFinished(step.status)
  return (
    <li className="relative flex flex-col items-center px-2 text-center">
      {/* track to the left of this node (fills when the previous step is done) */}
      {!first && <Track filled={prevDone} side="left" />}
      {!last && <Track filled={done} side="right" />}
      <Node status={step.status} n={index + 1} />
      <div className={cn('mt-4 text-sm font-medium leading-snug transition-colors', step.status === 'pending' ? 'text-ink-3' : 'text-ink')}>{step.label}</div>
      <p key={step.detail || step.description} className={cn('mt-1 line-clamp-3 max-w-[22ch] text-xs leading-relaxed animate-in fade-in slide-in-from-bottom-1 duration-300', step.status === 'waiting' ? 'font-medium text-ink' : 'text-ink-3')}>
        {step.status === 'skipped' ? 'Not required for this run' : step.detail || step.description}
      </p>
      <div className="tabular mt-2 h-4 text-[11px] font-medium" style={{ color: step.status === 'running' ? 'var(--sky)' : 'var(--ink-3)' }}>
        {step.status === 'running' ? fmtSeconds(secs) : done && step.status !== 'skipped' && step.started_at ? fmtSeconds(secs) : ''}
      </div>
    </li>
  )
}

function Track({ filled, side }: { filled: boolean; side: 'left' | 'right' }) {
  return (
    <span className={cn('absolute top-[19px] h-1 w-1/2 overflow-hidden bg-hairline', side === 'left' ? 'left-0 rounded-l-full' : 'right-0 rounded-r-full')} aria-hidden>
      <span
        className="block h-full bg-sky transition-[width] duration-500 ease-out"
        style={{ width: filled ? '100%' : '0%', transitionDelay: side === 'left' && filled ? '450ms' : '0ms' }}
      />
    </span>
  )
}

function Node({ status, n }: { status: StepStatus; n: number }) {
  const ring = 'relative z-10 grid size-10 shrink-0 place-items-center rounded-full shadow-[0_0_0_6px_var(--panel)]'
  if (status === 'done')
    return <span className={cn(ring, 'bg-sky text-white animate-in zoom-in-50 duration-300')}><Check className="size-5" strokeWidth={3} /></span>
  if (status === 'error')
    return <span className={cn(ring, 'text-white animate-in zoom-in-50 duration-300')} style={{ background: statusColor.critical }}><X className="size-5" strokeWidth={3} /></span>
  if (status === 'skipped')
    return <span className={cn(ring, 'border border-hairline bg-well text-ink-3')}><Minus className="size-4" /></span>
  if (status === 'waiting')
    return (
      <span className={cn(ring, 'text-white')} style={{ background: statusColor.warning }}>
        <span className="absolute inset-0 animate-ping rounded-full" style={{ background: statusColor.warning, opacity: 0.3 }} />
        <Hand className="relative size-5" strokeWidth={2.5} />
      </span>
    )
  if (status === 'running')
    return (
      <span className={cn(ring, 'bg-panel')}>
        <span className="absolute inset-0 animate-ping rounded-full bg-sky/25" />
        <svg viewBox="0 0 40 40" className="absolute inset-0 size-10 animate-spin" aria-hidden>
          <circle cx="20" cy="20" r="17" fill="none" stroke="var(--hairline)" strokeWidth="3" />
          <path d="M20 3 a17 17 0 0 1 17 17" fill="none" stroke="var(--sky)" strokeWidth="3" strokeLinecap="round" />
        </svg>
        <span className="tabular relative text-sm font-semibold text-sky">{n}</span>
      </span>
    )
  return <span className={cn(ring, 'tabular border-2 border-hairline bg-panel text-sm font-medium text-ink-3')}>{n}</span>
}

/* ───────── results ───────── */

function ResultPanel({ run, uc, seconds }: { run: RunState; uc: UcKey; seconds: number }) {
  const navigate = useNavigate()
  const { startedHere } = useRuns()
  const good = run.status === 'ok' || run.status === 'partial'
  const target = RESULTS[uc]
  // jump to the results only for a run started from this tab that has just finished, and never away from new fixes
  // that are waiting for a decision on this page
  const [count, setCount] = useState<number | null>(() =>
    good && !run.fix?.new && startedHere.has(uc) && run.finished_at && Date.now() - new Date(run.finished_at).getTime() < 15_000 ? 10 : null)
  useEffect(() => {
    if (count == null) return
    if (count <= 0) {
      startedHere.delete(uc)
      navigate(target.to)
      return
    }
    const id = setTimeout(() => setCount(count - 1), 1000)
    return () => clearTimeout(id)
  }, [count, navigate, target.to, startedHere, uc])

  const tone = run.status === 'ok' ? statusColor.good : run.status === 'failed' ? statusColor.critical : statusColor.warning
  return (
    <Panel className="overflow-hidden animate-in fade-in slide-in-from-bottom-2 duration-500">
      <span className="block h-1" style={{ background: tone }} />
      <div className="p-6">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <h2 className="text-lg font-semibold tracking-tight">
              {good ? 'What this run found' : run.status === 'skipped' ? 'Nothing was run' : 'Why it stopped'}
            </h2>
            <p className="mt-1 text-sm text-ink-3">
              {good ? `${UC_NAME[uc]} finished in ${fmtSeconds(seconds)}. Every page in the portal now shows these results.` : run.message}
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            {good && (
              <Link to={target.to} className="inline-flex items-center gap-2 rounded-xl btn-blue px-4 py-2.5 text-sm font-medium text-white">
                {target.label} <ArrowRight className="size-4" />
              </Link>
            )}
            <Link to="/" className="inline-flex items-center gap-2 rounded-xl border border-hairline px-4 py-2.5 text-sm font-medium hover:bg-well">Open the Dashboard</Link>
            <ReportButton run={run} />
          </div>
        </div>

        {count != null && (
          <div className="mt-4 flex items-center justify-between gap-3 rounded-xl bg-well px-4 py-2.5 text-sm">
            <span>Opening the results in <b className="tabular">{count} s</b>…</span>
            <button onClick={() => setCount(null)} className="font-medium underline underline-offset-4">Stay on this page</button>
          </div>
        )}

        {run.facts.length > 0 && (
          <div className="card-row mt-5 gap-3 [--card-min:150px]">
            {run.facts.map((f, i) => (
              <div key={f.label} className="rounded-xl border border-hairline p-4 animate-in fade-in slide-in-from-bottom-1 fill-mode-both duration-500" style={{ animationDelay: `${i * 70}ms` }}>
                <div className="tabular text-2xl leading-none tracking-tight">{f.value}</div>
                <div className="mt-2 text-sm font-medium">{f.label}</div>
                {f.hint && <div className="mt-0.5 text-xs text-ink-3">{f.hint}</div>}
              </div>
            ))}
          </div>
        )}

        {good && !!run.findings?.length && <Findings items={run.findings} />}
      </div>
    </Panel>
  )
}

const FORMAT: Record<string, string> = { xlsx: 'Excel', docx: 'Word', pdf: 'PDF' }

/** One "Download report" button; with several formats (Word, PDF, Excel) it opens a small menu to pick one */
function ReportButton({ run }: { run: RunState }) {
  const files = run.report_files?.length ? run.report_files : run.report_file ? [run.report_file] : []
  if (!files.length) return null
  const href = (name: string) => `/api/files/${run.files_from ?? 'uc1'}/${encodeURIComponent(name)}`
  const label = (name: string) => FORMAT[name.split('.').pop() ?? ''] ?? 'File'
  const cls = 'inline-flex items-center gap-2 rounded-xl border border-hairline px-4 py-2.5 text-sm font-medium hover:bg-well'
  if (files.length === 1)
    return <a href={href(files[0])} className={cls}><Download className="size-4" /> Download report</a>
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <button className={cls}><Download className="size-4" /> Download report <ChevronDown className="size-3.5 text-ink-3" /></button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-44">
        {files.map((name) => (
          <DropdownMenuItem key={name} asChild>
            <a href={href(name)}>{label(name)}</a>
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  )
}

const FINDING_KIND = {
  threat: { label: 'Threat affecting us', icon: ShieldAlert },
  attack: { label: 'Detection', icon: Radar },
  alert: { label: 'Alert sent', icon: BellRing },
} as const

const RATING_COLOR: Record<string, string> = {
  Critical: statusColor.critical, High: statusColor.warning, Medium: 'var(--sky)', Low: 'var(--ink-3)',
}

/** The run's new threats, signs of attack and alerts by name: what it is, why it matters, where, and what to do */
function Findings({ items }: { items: RunFinding[] }) {
  return (
    <div className="mt-6">
      <h3 className="text-sm font-semibold tracking-tight">Found in this run</h3>
      <ul className="mt-3 flex flex-col divide-y divide-hairline rounded-xl border border-hairline">
        {items.map((f) => {
          const K = FINDING_KIND[f.kind]
          return (
            <li key={`${f.kind}:${f.id}`}>
              <Link to={f.to} className="group flex gap-3 px-4 py-3.5 hover:bg-well">
                <K.icon className="mt-0.5 size-4 shrink-0 text-ink-3" />
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-ink-3">
                    <span>{K.label}</span>
                    {f.rating && <span className="font-semibold" style={{ color: RATING_COLOR[f.rating] }}>{f.rating}</span>}
                  </div>
                  <div className="mt-0.5 text-sm font-medium group-hover:underline">{f.title}</div>
                  {f.why && <p className="mt-1 text-xs leading-relaxed text-ink-2"><b className="font-medium">Why: </b>{f.why}</p>}
                  {(f.where || f.action) && (
                    <p className="mt-0.5 text-xs leading-relaxed text-ink-3">
                      {f.where && <>On <b className="font-medium text-ink-2">{f.where}</b>. </>}
                      {f.action && <>First step: {f.action}</>}
                    </p>
                  )}
                </div>
                <ArrowRight className="mt-0.5 size-4 shrink-0 text-ink-3 opacity-0 transition-opacity group-hover:opacity-100" />
              </Link>
            </li>
          )
        })}
      </ul>
    </div>
  )
}

/* ───────── live log ───────── */

type LogFilter = 'all' | 'steps' | 'problems'
const STEP_RE = /Step \w+ (ok|failed|skipped)|uc3\.pipeline:|Daily run finished|Run started/
const PROBLEM_RE = /WARNING|ERROR|FAILED|Traceback|failed|Error/

function LogPanel({ uc, run, live }: { uc: UcKey; run: RunState | null; live: boolean }) {
  const [lines, setLines] = useState<string[]>([])
  const [filter, setFilter] = useState<LogFilter>('all')
  const [follow, setFollow] = useState(true)
  const next = useRef(0)
  const runId = useRef<string | null>(null)
  const box = useRef<HTMLDivElement>(null)

  useQuery({
    queryKey: ['run-log', uc, run?.run_id],
    enabled: !!run,
    refetchInterval: live ? 1000 : false,
    queryFn: async () => {
      if (runId.current !== run?.run_id) {
        runId.current = run?.run_id ?? null
        next.current = 0
        setLines([])
      }
      const res = await fetch(`/api/runs/${uc}/log?after=${next.current}${run ? `&run=${run.run_id}` : ''}`)
      const data = await res.json()
      if (data.lines?.length) {
        next.current = data.next
        setLines((cur) => [...cur, ...data.lines].slice(-3000))
      }
      return data.next ?? 0
    },
  })

  const shown = useMemo(() => lines.filter((l) => filter === 'all' || (filter === 'steps' ? STEP_RE.test(l) : PROBLEM_RE.test(l))), [lines, filter])
  useEffect(() => {
    if (follow && box.current) box.current.scrollTop = box.current.scrollHeight
  }, [shown, follow])

  return (
    <Panel className="flex min-w-0 flex-col overflow-hidden xl:col-span-8">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-hairline px-5 py-3.5">
        <div className="flex items-center gap-2">
          <Terminal className="size-4 text-ink-3" />
          <h3 className="font-semibold tracking-tight">Live log</h3>
          <span className="tabular text-xs text-ink-3">{lines.length} lines{live ? ' · updating' : ''}</span>
        </div>
        <div className="flex items-center gap-2 text-xs">
          {(['all', 'steps', 'problems'] as const).map((f) => (
            <button key={f} onClick={() => setFilter(f)} className={cn('rounded-full border px-3 py-1', filter === f ? 'pill-on' : 'border-hairline hover:bg-well')}>
              {f === 'steps' ? 'Steps only' : f === 'problems' ? 'Problems' : 'All'}
            </button>
          ))}
          <label className="ml-1 flex cursor-pointer items-center gap-1.5 text-ink-2">
            <input type="checkbox" checked={follow} onChange={(e) => setFollow(e.target.checked)} className="size-3.5 accent-[var(--sky)]" /> Follow
          </label>
        </div>
      </div>
      <div ref={box} className="h-[420px] overflow-auto bg-[#0f1115] px-4 py-3 font-mono text-[12px] leading-[1.65] text-[#c9ced6]">
        {!run && <div className="text-[#7d8590]">No runs yet. Start an agent to stream its output here.</div>}
        {shown.map((l, i) => <LogLine key={i} line={l} />)}
        {live && <div className="mt-1 flex items-center gap-2 text-[#7d8590]"><span className="size-1.5 animate-pulse rounded-full bg-[#58a6ff]" /> waiting for the next line…</div>}
      </div>
    </Panel>
  )
}

function LogLine({ line }: { line: string }) {
  const m = line.match(/^(\d{4}-\d{2}-\d{2} )?(\d{2}:\d{2}:\d{2})(?:[,.]\d+)? (\w+) ([\w.]+): (.*)$/)
  if (!m) return <div className="whitespace-pre-wrap break-words text-[#8b949e]">{line}</div>
  const [, , time, level, source, msg] = m
  const step = /Step \w+ ok/.test(msg)
  const color = level === 'ERROR' || /failed/.test(msg) ? '#ff7b72' : level === 'WARNING' ? '#e3b341' : step ? '#7ee787' : '#c9ced6'
  return (
    <div className="whitespace-pre-wrap break-words">
      <span className="text-[#6e7681]">{time}</span>{' '}
      <span className="text-[#79c0ff]">{source.replace(/^uc\d\./, '')}</span>{' '}
      <span style={{ color }}>{step ? '✓ ' : ''}{msg}</span>
    </div>
  )
}

/* ───────── recent runs ───────── */

function History({ uc }: { uc: UcKey }) {
  const { data } = useQuery({
    queryKey: ['run-history'],
    queryFn: async (): Promise<RunState[]> => (await fetch('/api/runs/history')).json(),
    refetchInterval: 10_000,
  })
  const rows = (data ?? []).filter((r) => r.uc === uc)
  const icon = { ok: CheckCircle2, partial: AlertTriangle, skipped: AlertTriangle, failed: XCircle, running: Clock } as const
  const color = { ok: statusColor.good, partial: statusColor.warning, skipped: statusColor.warning, failed: statusColor.critical, running: 'var(--sky)' } as const
  return (
    <Panel className="flex flex-col p-5 xl:col-span-4">
      <h3 className="font-semibold tracking-tight">Recent runs from the portal</h3>
      <p className="mt-1 text-xs text-ink-3">Scheduled runs are listed in each agent’s own log.</p>
      <ul className="mt-4 flex flex-col divide-y divide-hairline">
        {rows.length ? rows.map((r) => {
          const I = icon[r.status]
          const secs = r.finished_at ? Math.round((new Date(r.finished_at).getTime() - new Date(r.started_at).getTime()) / 1000) : null
          return (
            <li key={r.run_id} className="flex items-center gap-3 py-2.5 text-sm">
              <I className="size-4 shrink-0" style={{ color: color[r.status] }} />
              <span className="flex-1">{dateTime(r.started_at)}</span>
              <span className="tabular text-xs text-ink-3">{secs != null ? fmtSeconds(secs) : r.status === 'running' ? 'running' : '–'}</span>
            </li>
          )
        }) : <li className="py-3 text-sm text-ink-3">No runs started from the portal yet.</li>}
      </ul>
    </Panel>
  )
}
