import { useState, type CSSProperties } from 'react'
import { Link } from 'react-router-dom'
import {
  ArrowRight, CheckCircle2, CircleAlert, CirclePlus, Clock, GitPullRequestArrow, ScanSearch, ShieldCheck, Wrench, XCircle,
} from 'lucide-react'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { Skeleton } from '@/components/ui/skeleton'
import { AgentCard, StoryCard } from '@/components/Agents'
import { Chart } from '@/components/Chart'
import { Card, Chip, ErrorBox, InfoTip, JobStatusTag, LinkBtn, PageHeader, Panel, Stat, VerdictTag } from '@/components/kit'
import { PipelineFlow, StageDetail } from '@/components/Pipeline'
import { RunsTable } from '@/components/Tables'
import { isLive, useAttention, useCaps, useDashboard, useJob, useJobAgents, useJobs } from '@/lib/api'
import { ago, num } from '@/lib/format'
import { AGENT_IDS, SEVERITIES, mergedStages, plural, sevLabel } from '@/lib/labels'
import { statusColor, useTheme } from '@/lib/theme'
import { sevColor } from '@/components/kit'
import type { Attention, Capabilities, Dashboard as DashboardData } from '@/lib/types'

export function Dashboard() {
  const dash = useDashboard()
  const att = useAttention()
  if (dash.isLoading || att.isLoading) return <DashboardSkeleton />
  if (dash.error || !dash.data) return <ErrorBox error={dash.error ?? 'No data'} />
  return <DashboardView d={dash.data} att={att.data} />
}

function DashboardView({ d, att }: { d: DashboardData; att?: Attention }) {
  const caps = useCaps()
  return (
    <div className="flex flex-col gap-5">
      <PageHeader
        title="Application security overview"
        description="Your repositories’ code vulnerabilities, what the four AI agents fixed, and what is waiting for your decision."
      >
        {caps.data && <SetupPills c={caps.data} />}
        <LinkBtn to="/scan" kind="primary"><CirclePlus className="size-4" /> New scan</LinkBtn>
      </PageHeader>

      <YourPath att={att} />

      <div className="card-row gap-5 [--card-min:240px]">
        <OpenFindingsCard d={d} />
        <Stat label="Fixes applied" value={num(d.fixes_applied)} icon={Wrench} tone="var(--blue)" to="/runs"
          info="Code changes the Remediation Agent made on a separate branch, across all runs."
          hint={`${num(d.ai_fixes)} written by AI · the rest are dependency upgrades and safe rewrites`} />
        <Stat label="Confirmed resolved" value={num(d.verified_fixed)} icon={ShieldCheck} tone={statusColor.good} to="/vulnerabilities"
          info="Findings that a fresh scan of the fix branch no longer reports. Strong evidence the fix worked."
          hint="Verified by the security rescan" />
        <Stat label="Pull requests" value={num(d.pull_requests)} icon={GitPullRequestArrow} tone="var(--violet)" to="/approvals"
          info="Pull requests opened after a person approved the fixes. Nothing is ever merged automatically."
          hint={d.validation_pass_rate == null ? 'No validated runs yet' : `${d.validation_pass_rate}% of runs passed validation`} />
      </div>

      <div className="grid grid-cols-1 gap-5 xl:grid-cols-3">
        <LivePipeline />
        <AttentionPanel att={att} />
      </div>

      <AgentsRow />

      <div className="grid grid-cols-1 gap-5 xl:grid-cols-3">
        <SeverityCard d={d} />
        <Card title="Recent runs" description="Every repository the agents processed, newest first. Click a row to open it."
          className="xl:col-span-2" action={<LinkBtn to="/runs">All runs <ArrowRight className="size-3.5" /></LinkBtn>}>
          <RunsTable items={d.recent.slice(0, 6)} empty="No runs yet. Start with New scan." />
        </Card>
      </div>

      <p className="pb-2 text-center text-xs text-ink-3">
        {plural(d.runs, 'pipeline run')} · {plural(d.repositories, 'repository')} · refreshes by itself · fixes are never merged without a person
      </p>
    </div>
  )
}

/* ───────── header pills: is everything set up? ───────── */

function SetupPills({ c }: { c: Capabilities }) {
  const pills = [
    { label: 'AI model', ok: c.llm.enabled, text: c.llm.enabled ? c.llm.model ?? 'connected' : 'not connected', tip: 'Writes code fixes and answers chat questions. Set it in Settings.' },
    { label: 'GitHub', ok: c.github_token_configured, text: c.github_token_configured ? 'connected' : 'no token', tip: 'Needed to push the fix branch and open pull requests. Set it in Settings.' },
    { label: 'CodeQL', ok: !!c.scanners.codeql?.available, text: c.scanners.codeql?.available ? 'ready' : 'fallback', tip: 'The main code scanner. Without it, simpler built-in rules are used.' },
  ]
  return (
    <>
      {pills.map((p) => (
        <Tooltip key={p.label}>
          <TooltipTrigger asChild>
            <Link to="/settings" className="flex items-center gap-2 rounded-full border border-hairline bg-panel py-1.5 pl-2.5 pr-3.5 text-xs hover:border-hairline-strong">
              {p.ok ? <CheckCircle2 className="size-3.5" style={{ color: statusColor.good }} /> : <Clock className="size-3.5" style={{ color: statusColor.warning }} />}
              <span className="font-medium">{p.label}</span>
              <span className="max-w-[140px] truncate text-ink-3">{p.text}</span>
            </Link>
          </TooltipTrigger>
          <TooltipContent className="max-w-64">{p.tip}</TooltipContent>
        </Tooltip>
      ))}
    </>
  )
}

/* ───────── the path through the site, with where each step lives ───────── */

function YourPath({ att }: { att?: Attention }) {
  const steps = [
    { n: 1, icon: CirclePlus, title: 'Scan a repository', text: 'Paste a GitHub link', to: '/scan', cta: 'New scan', tint: 'var(--blue)' },
    { n: 2, icon: ScanSearch, title: 'Agents find & fix', text: 'Analysis → Remediation → Validation → Report', to: '/runs', cta: 'Watch runs', tint: 'var(--violet)' },
    { n: 3, icon: ShieldCheck, title: 'You approve', text: att?.counts.approvals ? `${att.counts.approvals} waiting for you` : 'Nothing waiting right now', to: '/approvals', cta: 'Approvals', tint: 'var(--teal)' },
    { n: 4, icon: Wrench, title: 'Handle the rest', text: att?.counts.fixes_needed ? `${att.counts.fixes_needed} issues need a person` : 'No manual fixes left', to: '/fixes', cta: 'Fixes needed', tint: 'var(--amber)' },
  ]
  return (
    <Panel className="p-4">
      <div className="mb-3 flex items-center gap-2 px-1 text-xs font-semibold uppercase tracking-[0.12em] text-ink-3">
        Your path <InfoTip text="The four things you do on this site, in order. Each box opens the page for that step." />
      </div>
      <ol className="grid grid-cols-1 gap-2 sm:grid-cols-2 xl:grid-cols-4">
        {steps.map((s) => (
          <li key={s.n}>
            <Link to={s.to} className="tint-box group flex h-full items-center gap-3 rounded-xl p-3 transition-transform hover:-translate-y-0.5" style={{ '--tint': s.tint } as CSSProperties}>
              <span className="grid size-10 shrink-0 place-items-center rounded-[10px] bg-panel" style={{ color: s.tint }}><s.icon className="size-5" /></span>
              <span className="min-w-0 flex-1">
                <span className="block text-[11px] font-semibold uppercase tracking-[0.1em] text-ink-3">Step {s.n}</span>
                <span className="block font-semibold leading-snug text-ink">{s.title}</span>
                <span className="block truncate text-xs text-ink-2">{s.text}</span>
              </span>
              <ArrowRight className="size-4 shrink-0 text-ink-3 transition-transform group-hover:translate-x-0.5" />
            </Link>
          </li>
        ))}
      </ol>
    </Panel>
  )
}

/* ───────── KPI: the hero card ───────── */

function OpenFindingsCard({ d }: { d: DashboardData }) {
  const total = SEVERITIES.reduce((a, s) => a + (d.severity[s] ?? 0), 0)
  const crit = (d.severity.critical ?? 0) + (d.severity.high ?? 0)
  return (
    <Link to="/vulnerabilities" className="glass-card card-hero flex flex-col rounded-[20px] p-6">
      <div className="flex items-start justify-between">
        <h3 className="flex items-center gap-1.5 text-sm">Open findings <InfoTip text="Security issues in the latest scan of each repository. Critical and high ones are fixed first." /></h3>
        <Chip>{num(d.repositories)} repos</Chip>
      </div>
      <div className="mt-2 text-[34px] leading-none tracking-tight tabular">{num(d.open_findings)}</div>
      <div className="mt-auto pt-6">
        <div className="mb-2 flex justify-between text-xs text-ink-3"><span>{num(crit)} critical or high</span><span>by severity</span></div>
        <div className="flex h-2 overflow-hidden rounded-full bg-white/15">
          {total > 0 && SEVERITIES.filter((s) => d.severity[s]).map((s, i) => (
            <span key={s} title={`${sevLabel(s)}: ${d.severity[s]}`} style={{ width: `${((d.severity[s] ?? 0) / total) * 100}%`, background: `rgb(255 255 255 / ${0.95 - i * 0.17})` }} />
          ))}
        </div>
      </div>
    </Link>
  )
}

/* ───────── the run that is working now (or the latest) ───────── */

function LivePipeline() {
  const running = useJobs({ status: 'running', limit: 1 }, 3_000)
  const latest = useJobs({ limit: 1 }, 5_000)
  const pick = running.data?.items[0] ?? latest.data?.items[0]
  const job = useJob(pick?.id)
  const live = isLive(job.data)
  const agents = useJobAgents(pick?.id, live)
  const [picked, setPicked] = useState<string | null>(null)

  if (!pick) {
    return (
      <Panel className="flex flex-col justify-center gap-3 p-6 xl:col-span-2">
        <h3 className="text-lg font-semibold">No pipeline has run yet</h3>
        <p className="text-sm text-ink-3">Paste a GitHub link and the four agents will analyse, fix, validate and report, then ask for your approval.</p>
        <div><LinkBtn to="/scan" kind="primary">Start a scan <ArrowRight className="size-3.5" /></LinkBtn></div>
      </Panel>
    )
  }
  const j = job.data ?? pick
  const stages = mergedStages(job.data?.stages)
  const active = stages.find((s) => s.status === 'running') ?? [...stages].reverse().find((s) => !['pending', 'skipped'].includes(s.status)) ?? stages[0]
  const selected = live ? active.id : picked ?? active.id

  return (
    <Panel className="flex min-w-0 flex-col gap-4 p-6 xl:col-span-2">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-[11px] font-semibold uppercase tracking-[0.12em] text-ink-3">{live ? 'Live pipeline' : 'Latest pipeline run'}</span>
        {live && <span className="size-2 animate-pulse rounded-full bg-sky" />}
        <span className="flex-1" />
        <LinkBtn to={`/runs/${j.id}`}>Open full run <ArrowRight className="size-3.5" /></LinkBtn>
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <h3 className="text-lg font-semibold tracking-tight">{j.repo}</h3>
        <JobStatusTag job={j} />
        <VerdictTag v={j.summary?.validation_status} />
        <span className="text-xs text-ink-3">{live ? `started ${ago(j.started_at ?? j.created_at)}` : `finished ${ago(j.finished_at ?? j.created_at)}`}</span>
      </div>
      {live && (
        <div>
          <div className="h-1.5 overflow-hidden rounded-full bg-well"><div className="h-full rounded-full bg-blue transition-[width] duration-500" style={{ width: `${j.progress}%` }} /></div>
          <p className="mt-1.5 text-xs text-ink-3">Now: {j.stage} · {j.progress}%</p>
        </div>
      )}
      <PipelineFlow stages={stages} selected={selected} onSelect={setPicked} />
      <StageDetail stage={stages.find((s) => s.id === selected)} />
      {!live && agents.data?.story && <div className="border-t border-hairline pt-4"><StoryCard story={agents.data.story} job={j} linkToRun /></div>}
    </Panel>
  )
}

/* ───────── what needs a person ───────── */

function AttentionPanel({ att }: { att?: Attention }) {
  if (!att) return <Panel className="p-6"><Skeleton className="h-64" /></Panel>
  const reasons: Record<string, number> = {}
  att.fixes_needed.forEach((f) => { reasons[f.reason] = (reasons[f.reason] ?? 0) + 1 })
  const top = Object.entries(reasons).sort((a, b) => b[1] - a[1]).slice(0, 3)
  const errors = [...att.config_errors, ...att.errors]
  const boxes = [
    { to: '/approvals', icon: ShieldCheck, n: att.counts.approvals, label: 'Approvals waiting', tint: att.counts.approvals ? 'var(--blue)' : 'var(--teal)',
      text: att.counts.approvals ? 'Fix sets ready for your decision' : 'Nothing is waiting for you',
      list: att.approvals.slice(0, 3).map((a) => `${a.repo}: ${a.summary?.fixes_applied ?? 0} fixes${a.summary?.validation_status === 'flagged' ? ' (flagged)' : ''}`) },
    { to: '/fixes', icon: Wrench, n: att.counts.fixes_needed, label: 'Fixes needed', tint: att.counts.fixes_needed ? 'var(--amber)' : 'var(--teal)',
      text: att.counts.fixes_needed ? 'Issues the agents could not fix' : 'Every selected issue was fixed', list: top.map(([r, n]) => `${n} · ${r}`) },
    { to: '/errors', icon: errors.length ? XCircle : CircleAlert, n: errors.length, label: 'Errors', tint: errors.length ? 'var(--rose)' : 'var(--teal)',
      text: errors.length ? 'Problems with runs, scanners or setup' : 'No errors', list: errors.slice(0, 3).map((e) => e.kind) },
  ]
  return (
    <Panel className="flex flex-col gap-3 p-6">
      <div>
        <h3 className="text-base font-semibold tracking-[-0.01em]">Needs your attention</h3>
        <p className="mt-1 text-sm text-ink-3">The Action center: what only a person can do.</p>
      </div>
      {boxes.map((b) => (
        <Link key={b.to} to={b.to} className="tint-box group rounded-xl p-4 transition-transform hover:-translate-y-0.5" style={{ '--tint': b.tint } as CSSProperties}>
          <div className="flex items-center gap-3">
            <b.icon className="size-4 shrink-0" style={{ color: b.tint }} />
            <span className="flex-1 text-sm font-semibold">{b.label}</span>
            <span className="tint-num tabular text-2xl leading-none">{b.n}</span>
          </div>
          <p className="mt-1 text-xs text-ink-2">{b.text}</p>
          {b.list.length > 0 && <ul className="mt-2 flex flex-col gap-0.5 text-xs text-ink-3">{b.list.map((l) => <li key={l} className="truncate">• {l}</li>)}</ul>}
        </Link>
      ))}
    </Panel>
  )
}

/* ───────── the four agents ───────── */

function AgentsRow() {
  const latest = useJobs({ limit: 1 }, 5_000)
  const pick = latest.data?.items[0]
  const agents = useJobAgents(pick?.id, isLive(pick))
  return (
    <section className="flex flex-col gap-3">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h2 className="text-lg font-semibold tracking-tight">The four agents</h2>
        <p className="text-sm text-ink-3">{pick ? `${isLive(pick) ? 'Working on' : 'Last run on'} ${pick.repo} · click one to see its inputs, outputs and conclusions` : 'They start when you run a scan'}</p>
      </div>
      <div className="grid grid-cols-1 gap-5 sm:grid-cols-2 xl:grid-cols-4">
        {AGENT_IDS.map((id) => <AgentCard key={id} id={id} view={agents.data?.agents[id]} />)}
      </div>
    </section>
  )
}

/* ───────── severity ───────── */

function SeverityCard({ d }: { d: DashboardData }) {
  const { theme } = useTheme()
  const data = SEVERITIES.filter((s) => d.severity[s]).map((s) => ({ name: sevLabel(s), value: d.severity[s] ?? 0, itemStyle: { color: sevColor(theme, s) } }))
  const total = data.reduce((a, x) => a + x.value, 0)
  return (
    <Card title="Open findings by severity" description="Latest scan of each repository." action={<LinkBtn to="/vulnerabilities">All <ArrowRight className="size-3.5" /></LinkBtn>}>
      {total ? (
        <div className="flex items-center gap-4">
          <div className="relative size-[170px] shrink-0">
            <Chart height={170} build={() => ({
              tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)' },
              series: [{ type: 'pie', radius: ['68%', '92%'], padAngle: 2, label: { show: false }, data }],
            })} />
            <div className="pointer-events-none absolute inset-0 grid place-items-center text-center">
              <div><div className="tabular text-2xl font-semibold">{num(total)}</div><div className="text-xs text-ink-3">findings</div></div>
            </div>
          </div>
          <ul className="flex flex-1 flex-col gap-2 text-sm">
            {data.map((x) => (
              <li key={x.name} className="flex items-center gap-2">
                <span className="size-2.5 rounded-full" style={{ background: x.itemStyle.color }} />
                <span className="flex-1 text-ink-2">{x.name}</span>
                <span className="tabular font-medium">{num(x.value)}</span>
              </li>
            ))}
          </ul>
        </div>
      ) : <p className="text-sm text-ink-3">No data yet.</p>}
    </Card>
  )
}

function DashboardSkeleton() {
  return (
    <div className="flex flex-col gap-5">
      <Skeleton className="h-14 w-96" />
      <Skeleton className="h-24" />
      <div className="grid grid-cols-4 gap-5">{[0, 1, 2, 3].map((i) => <Skeleton key={i} className="h-36 rounded-[20px]" />)}</div>
      <Skeleton className="h-96 rounded-[20px]" />
    </div>
  )
}
