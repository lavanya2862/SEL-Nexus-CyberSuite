// The overview: built like the Infrastructure Security overview (status pills and filter, three headline cards,
// a work panel, a ranking panel, then one panel per agent), with what matters for our application source code.
import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  AlertTriangle, ArrowRight, CheckCircle2, Clock, HelpCircle, Info, LayoutGrid, List, ShieldCheck, SlidersHorizontal,
  X, XCircle,
} from 'lucide-react'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuLabel, DropdownMenuRadioGroup, DropdownMenuRadioItem, DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { Skeleton } from '@/components/ui/skeleton'
import { AgentTile } from '@/components/Agents'
import { Chart } from '@/components/Chart'
import { Chip, DTable, Empty, ErrorBox, FixStatusTag, InfoTip, LinkBtn, Panel, RiskScore, SevTag, StatusTag, Tabs, VerdictTag, sevColor } from '@/components/kit'
import { useAgentHistory, useAttention, useDashboard, useRepositories, useVulnerabilities } from '@/lib/api'
import { ago, num, shortDate } from '@/lib/format'
import { AGENTS, AGENT_IDS, AGENT_STATUS, FINDING_TYPES, findingType, plural, sevLabel, where } from '@/lib/labels'
import { usePanels } from '@/lib/panels'
import { chartTokens, statusColor, useTheme } from '@/lib/theme'
import type { AgentId, Attention, Dashboard as DashboardData, Finding, Learning, NeededFix, Repository } from '@/lib/types'
import { cn } from '@/lib/utils'

export function Dashboard() {
  const dash = useDashboard()
  const att = useAttention()
  const vulns = useVulnerabilities()
  const repos = useRepositories()
  if (dash.isLoading || att.isLoading || vulns.isLoading || repos.isLoading) return <DashboardSkeleton />
  if (dash.error || !dash.data) return <ErrorBox error={dash.error ?? 'No data'} />
  return <DashboardView d={dash.data} att={att.data} findings={vulns.data?.items ?? []} repos={repos.data?.items ?? []} />
}

/* ───────────────────────── derived, filter-aware view model ───────────────────────── */

const FIXED = new Set(['verified', 'fixed'])
const isFixed = (f: Finding) => FIXED.has(f.fix_status)
const shortRepo = (repo?: string) => (repo ?? '').split('/').pop() ?? ''
/** Readable names for the scanners' categories (the rest: dashes and underscores become spaces). */
const KIND_NAME: Record<string, string> = {
  dependency_vulnerability: 'Vulnerable dependency', xss: 'Cross-site scripting', 'sql-injection': 'SQL injection', ssrf: 'Server-side request forgery',
  'source-code': 'Other code weaknesses', 'template-injection': 'Template injection', 'command-injection': 'Command injection',
  'weak-crypto': 'Weak cryptography', 'weak-random': 'Weak randomness', 'missing-auth': 'Missing authentication',
  'information-exposure': 'Information exposure', 'code-injection': 'Code injection', misconfiguration: 'Misconfiguration', secret: 'Exposed secret',
}
const kindName = (c: string) => KIND_NAME[c] ?? (c.charAt(0).toUpperCase() + c.slice(1)).replace(/[-_]/g, ' ')
const repoCount = (n: number) => `${num(n)} ${n === 1 ? 'repository' : 'repositories'}`

/** Findings per scan over time: each repository's latest count on every day any repository was scanned. */
function findingsTrend(repos: Repository[]) {
  const per = repos.map((r) => r.history.filter((h) => h.when).map((h) => ({ day: h.when!.slice(0, 10), n: h.findings })))
  const days = [...new Set(per.flatMap((hs) => hs.map((h) => h.day)))].sort()
  return days.map((day) => ({ date: day, total: per.reduce((a, hs) => a + (hs.filter((h) => h.day <= day).at(-1)?.n ?? 0), 0) }))
}

function useView(findings: Finding[], repos: Repository[], att: Attention | undefined, repo: string) {
  return useMemo(() => {
    const all = repo === 'all'
    const rows = findings.filter((f) => all || f.repo === repo)
    const shownRepos = repos.filter((r) => all || r.repo === repo)
    const fixed = rows.filter(isFixed)
    const open = rows.filter((f) => !isFixed(f))
    const urgent = rows.filter((f) => f.severity === 'critical' || f.severity === 'high')
    return {
      repo,
      rows,
      fixed,
      open,
      urgent,
      confirmed: rows.filter((f) => f.fix_status === 'verified').length,
      topRisks: [...open].sort((a, b) => (b.priority_score ?? 0) - (a.priority_score ?? 0)).slice(0, 10),
      needed: (att?.fixes_needed ?? []).filter((f) => all || f.repo === repo),
      approvals: (att?.approvals ?? []).filter((j) => all || j.repo === repo),
      repos: shownRepos,
      trend: findingsTrend(shownRepos),
    }
  }, [findings, repos, att, repo])
}

type View = ReturnType<typeof useView>

/* ───────────────────────── page ───────────────────────── */

type WorkTab = 'risks' | 'needed' | 'repos'
type Section = 'summary' | WorkTab | 'agents'
const SECTIONS: [Section, string][] = [['summary', 'Summary'], ['risks', 'Top risks'], ['needed', 'Manual remediation'], ['repos', 'Repositories'], ['agents', 'Agents']]
const SECTION_TARGET: Record<Section, string> = { summary: 'top', risks: 'work', needed: 'work', repos: 'work', agents: 'agents' }

function DashboardView({ d, att, findings, repos }: { d: DashboardData; att?: Attention; findings: Finding[]; repos: Repository[] }) {
  const [repo, setRepo] = useState('all')
  const [section, setSection] = useState<Section>('summary')
  const [workTab, setWorkTab] = useState<WorkTab>('risks')
  const v = useView(findings, repos, att, repo)
  const goTo = (t: Section) => {
    setSection(t)
    if (t === 'risks' || t === 'needed' || t === 'repos') setWorkTab(t)
    document.getElementById(SECTION_TARGET[t])?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }
  return (
    <div className="flex flex-col gap-5">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Application security overview</h1>
          <p className="mt-1 text-sm text-ink-3">
            {repo === 'all' ? `All ${repoCount(d.repositories)}` : repo} · vulnerabilities detected, remediated and validated by the four security agents
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {AGENT_IDS.map((id) => <AgentPill key={id} id={id} repo={repo} />)}
          <FiltersButton repos={repos} findings={findings} repo={repo} setRepo={setRepo} />
        </div>
      </div>
      <Tabs<Section> tabs={SECTIONS} value={section} onChange={goTo} />
      {repo !== 'all' && (
        <div className="-mt-2 flex flex-wrap items-center gap-2 text-xs">
          <span className="text-ink-3">Filtered by</span>
          <button onClick={() => setRepo('all')} className="flex items-center gap-1.5 rounded-full btn-blue px-3 py-1 text-white">{repo} <X className="size-3" /></button>
        </div>
      )}
      {v.approvals.length > 0 && <DecisionStrip n={v.approvals.length} />}

      <div className="card-row gap-5 [--card-min:280px]">
        <UrgentCard v={v} />
        <FixedCard v={v} />
        <TrendCard v={v} />
      </div>

      <div id="work" className="grid scroll-mt-32 grid-cols-1 gap-5 xl:grid-cols-3">
        <WorkPanel v={v} tab={workTab} setTab={setWorkTab} />
        <RankingPanel v={v} />
      </div>

      <div id="agents" className="grid scroll-mt-32 grid-cols-1 gap-5 lg:grid-cols-2">
        {AGENT_IDS.map((id) => <AgentOverview key={id} id={id} v={v} />)}
      </div>

      <p className="pb-2 text-center text-xs text-ink-3">
        {plural(d.runs, 'scan')} · {num(d.pull_requests)} pull request{d.pull_requests === 1 ? '' : 's'} opened
      </p>
    </div>
  )
}

/* ───────────────────────── header: agent status pills and the repository filter ───────────────────────── */

const PILL = {
  good: { icon: CheckCircle2, color: statusColor.good },
  warn: { icon: AlertTriangle, color: statusColor.warning },
  bad: { icon: XCircle, color: statusColor.critical },
  info: { icon: Clock, color: 'var(--sky)' },
  idle: { icon: HelpCircle, color: statusColor.serious },
} as const

function AgentPill({ id, repo }: { id: AgentId; repo: string }) {
  const h = useAgentHistory(id)
  const last = (h.data?.runs ?? []).find((r) => repo === 'all' || r.repo === repo)
  const st = last ? AGENT_STATUS[last.status] ?? AGENT_STATUS.pending : { label: 'No scans yet', tone: 'idle' as const }
  const p = PILL[st.tone]
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Link to={`/agents/${id}`} className="flex items-center gap-2 rounded-full border border-hairline bg-panel py-1.5 pl-2.5 pr-3.5 text-xs hover:border-hairline-strong">
          <p.icon className="size-3.5" style={{ color: p.color }} />
          <span className="font-medium">{AGENTS[id].name.replace(' Agent', '')}</span>
          <span className="text-ink-3">{st.label}{last ? ` · ${ago(last.when)}` : ''}</span>
        </Link>
      </TooltipTrigger>
      <TooltipContent className="max-w-64">{AGENTS[id].name}: {AGENTS[id].short.toLowerCase()}.{last ? ` Last scan: ${last.repo}.` : ''}</TooltipContent>
    </Tooltip>
  )
}

function FiltersButton({ repos, findings, repo, setRepo }: { repos: Repository[]; findings: Finding[]; repo: string; setRepo: (r: string) => void }) {
  const count = (r: string) => findings.filter((f) => f.repo === r).length
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <button className="flex items-center gap-2 rounded-full border border-hairline bg-panel px-3.5 py-1.5 text-xs font-medium hover:bg-well">
          <SlidersHorizontal className="size-3.5" /> Filters
          {repo !== 'all' ? <span className="tabular grid size-4 place-items-center rounded-full btn-blue text-[10px] text-white">1</span> : null}
        </button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-72">
        <DropdownMenuLabel>Repository</DropdownMenuLabel>
        <DropdownMenuRadioGroup value={repo} onValueChange={setRepo}>
          <DropdownMenuRadioItem value="all">All repositories</DropdownMenuRadioItem>
          {repos.map((r) => (
            <DropdownMenuRadioItem key={r.repo} value={r.repo}><span className="truncate">{r.repo}</span><span className="ml-auto pl-2 text-xs text-ink-3">{num(count(r.repo))}</span></DropdownMenuRadioItem>
          ))}
        </DropdownMenuRadioGroup>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}

function DecisionStrip({ n }: { n: number }) {
  return (
    <Link to="/approvals" className="group flex flex-wrap items-center gap-3 rounded-[16px] border border-blue/35 bg-[color-mix(in_oklab,var(--blue)_9%,var(--panel))] px-4 py-3 text-sm">
      <span className="tile-signal grid size-8 place-items-center rounded-[9px]"><ShieldCheck className="size-4" /></span>
      <span className="min-w-0 flex-1">
        <b>{plural(n, 'remediation change set')} {n === 1 ? 'is' : 'are'} pending your approval.</b>{' '}
        <span className="text-ink-2">Remediated by the Remediation Agent and verified by the Validation Agent. Approval raises a pull request.</span>
      </span>
      <span className="flex items-center gap-1 font-medium text-sky">Review <ArrowRight className="size-3.5 transition-transform group-hover:translate-x-0.5" /></span>
    </Link>
  )
}

/* ───────────────────────── headline cards ───────────────────────── */

function UrgentCard({ v }: { v: View }) {
  const total = v.rows.length
  const pct = total ? (v.urgent.length / total) * 100 : 0
  const rest = 100 - pct
  return (
    <Link to="/vulnerabilities" className="glass-card card-hero flex flex-col rounded-[20px] p-6">
      <div className="flex items-start justify-between">
        <h3 className="flex items-center gap-1.5 text-sm">Critical and high findings <InfoTip text="The proportion of findings in the latest scan of each repository rated critical or high severity. These are remediated first. The chip shows the count." /></h3>
        <Chip>{num(v.urgent.length)}</Chip>
      </div>
      <div className="mt-2 text-[34px] font-normal leading-none tracking-tight tabular">{pct.toFixed(1)}%</div>
      <div className="mt-auto pt-7">
        <div className="relative">
          <div className="mb-2 text-center text-xs text-ink-3">Medium, low and unrated</div>
          <div className="h-[3px] rounded-full" style={{ background: 'linear-gradient(90deg, rgb(255 255 255 / 0.55), #ffd166 75%, var(--signal))' }} />
          <div className="absolute top-6 h-3 w-px bg-ink" style={{ left: `${rest}%` }} />
          <div className="tabular mt-3 text-right text-xs font-medium" style={{ paddingRight: `${Math.max(0, pct - 6)}%` }}>{rest.toFixed(1)}%</div>
        </div>
      </div>
    </Link>
  )
}

function FixedCard({ v }: { v: View }) {
  const { theme } = useTheme()
  const fixed = v.fixed.length
  const open = v.open.length
  const pct = fixed + open ? Math.round((fixed / (fixed + open)) * 100) : 0
  return (
    <Panel className="flex flex-col p-6">
      <div className="flex items-start justify-between">
        <h3 className="flex items-center gap-1.5 text-sm">Remediated automatically <InfoTip text="Findings remediated by the Remediation Agent on an isolated branch. 'Verified' means the Validation Agent's confirmation scan no longer reports them. Changes reach the codebase once the pull request is approved and merged." /></h3>
        <Chip>{num(open)} open</Chip>
      </div>
      <div className="mt-2 flex flex-1 items-end justify-between gap-4">
        <div className="flex min-w-0 flex-col">
          <div className="text-[34px] leading-none tracking-tight tabular" style={{ color: fixed ? statusColor.good : undefined }}>{num(fixed)}</div>
          <div className="mt-2 text-xs text-ink-3">{fixed ? `${num(v.confirmed)} verified by the Validation Agent` : 'No remediations yet'}</div>
          <ul className="mt-4 flex flex-col gap-1.5 text-xs text-ink-2">
            <li className="flex items-center gap-1.5"><span className="size-1.5 rounded-full" style={{ background: statusColor.good }} />{pct}% of all findings remediated</li>
            <li className="flex items-center gap-1.5"><span className="size-1.5 rounded-full" style={{ background: chartTokens[theme].axis }} />{100 - pct}% outstanding</li>
          </ul>
        </div>
        <div className="size-[92px] shrink-0">
          <Chart
            height={92}
            build={(tk) => ({
              tooltip: { trigger: 'item', formatter: '{b}: {c}' },
              series: [{
                type: 'pie', radius: ['78%', '96%'], padAngle: 3, itemStyle: { borderRadius: 4 }, label: { show: false },
                data: [{ name: 'Remediated automatically', value: fixed, itemStyle: { color: statusColor.good } },
                       { name: 'Open', value: open, itemStyle: { color: tk.axis } }],
              }],
            })}
          />
        </div>
      </div>
    </Panel>
  )
}

function TrendCard({ v }: { v: View }) {
  const last = v.trend.at(-1)?.total ?? 0
  const prev = v.trend.at(-2)?.total ?? last
  const delta = last - prev
  return (
    <Panel className="flex flex-col p-6 md:col-span-2 xl:col-span-1">
      <div className="flex items-start justify-between">
        <h3 className="flex items-center gap-1.5 text-sm">Vulnerabilities identified <InfoTip text="Findings from the latest scan of each repository, aggregated for each day on which a scan ran." /></h3>
        <Chip>{delta >= 0 ? '+' : '−'}{num(Math.abs(delta))} since {v.trend.at(-2) ? shortDate(v.trend.at(-2)!.date) : '–'}</Chip>
      </div>
      <div className="mt-2 text-[34px] leading-none tracking-tight tabular">{num(last)}</div>
      <div className="-mx-2 mt-auto">
        {v.trend.length > 1 ? (
          <>
            <Chart
              height={70}
              build={(tk) => ({
                grid: { left: 6, right: 6, top: 8, bottom: 4 },
                tooltip: { trigger: 'axis', axisPointer: { type: 'line', lineStyle: { color: tk.axis } }, valueFormatter: (x: unknown) => num(Number(x)) },
                xAxis: { type: 'category', show: false, boundaryGap: false, data: v.trend.map((r) => shortDate(r.date)) },
                yAxis: { type: 'value', show: false, min: (m: { min: number }) => m.min * 0.85 },
                series: [{ type: 'line', smooth: 0.5, symbol: 'none', data: v.trend.map((r) => r.total), lineStyle: { width: 2.5, color: tk.series[0] } }],
              })}
            />
            <div className="flex justify-between px-2 text-[11px] text-ink-3">
              <span>{shortDate(v.trend[0].date)}</span>
              <span>{shortDate(v.trend.at(-1)!.date)}</span>
            </div>
          </>
        ) : <p className="px-2 pt-6 text-xs text-ink-3">The trend is shown once scans have run on at least two different days.</p>}
      </div>
    </Panel>
  )
}

/* ───────────────────────── main work panel ───────────────────────── */

function WorkPanel({ v, tab, setTab }: { v: View; tab: WorkTab; setTab: (t: WorkTab) => void }) {
  const [layout, setLayout] = useState<'list' | 'grid'>('list')
  return (
    <Panel className="min-w-0 p-6 xl:col-span-2">
      <div className="flex items-end gap-3">
        <div className="min-w-0 flex-1 overflow-x-auto">
          <Tabs<WorkTab>
            value={tab}
            onChange={setTab}
            tabs={[['risks', `Top risks · ${v.topRisks.length}`], ['needed', `Manual remediation · ${v.needed.length}`], ['repos', `Repositories · ${v.repos.length}`]]}
          />
        </div>
        <div className="mb-2 flex shrink-0 rounded-lg bg-well p-0.5" role="group" aria-label="Layout">
          {([['list', List], ['grid', LayoutGrid]] as const).map(([id, Icon]) => (
            <button
              key={id}
              aria-label={`${id} view`}
              aria-pressed={layout === id}
              onClick={() => setLayout(id)}
              className={cn('grid size-7 place-items-center rounded-md text-ink-3', layout === id && 'bg-blue text-white')}
            >
              <Icon className="size-3.5" />
            </button>
          ))}
        </div>
      </div>
      <div className="mt-4">
        {tab === 'risks' && <RisksView v={v} layout={layout} />}
        {tab === 'needed' && <NeededView v={v} layout={layout} />}
        {tab === 'repos' && <ReposView v={v} layout={layout} />}
      </div>
    </Panel>
  )
}

function RisksView({ v, layout }: { v: View; layout: 'list' | 'grid' }) {
  const { openFinding } = usePanels()
  if (!v.topRisks.length) return <Empty text="No open findings. All findings in this view were remediated automatically." />
  const open = (f: Finding) => f.job_id && openFinding(f.job_id, f.finding_id)
  if (layout === 'grid')
    return (
      <div className="grid gap-3 sm:grid-cols-2">
        {v.topRisks.map((f) => (
          <button key={`${f.job_id}:${f.finding_id}`} onClick={() => open(f)} className="rounded-xl border border-hairline p-4 text-left hover:bg-well/60">
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0">
                <div className="font-medium leading-snug">{f.title}</div>
                <div className="truncate font-mono text-xs text-ink-3">{where(f)}</div>
              </div>
              <RiskScore score={f.priority_score} />
            </div>
            <div className="mt-3 flex items-center justify-between gap-2 text-sm">
              <SevTag sev={f.severity} />
              <span className="truncate text-xs text-ink-3" title={f.repo}>{shortRepo(f.repo)}</span>
            </div>
            <div className="mt-3 border-t border-hairline pt-3"><FixStatusTag s={f.fix_status} /></div>
          </button>
        ))}
      </div>
    )
  return (
    <>
      <DTable head={[['Risk'], ['Severity'], ['Vulnerability'], ['Repository'], ['Agent status']]} minWidth={680}>
        {v.topRisks.map((f) => (
          <tr key={`${f.job_id}:${f.finding_id}`} className="cursor-pointer hover:bg-well/60" onClick={() => open(f)}>
            <td><RiskScore score={f.priority_score} /></td>
            <td><SevTag sev={f.severity} /></td>
            <td className="max-w-[340px]">
              <div className="line-clamp-2 font-medium leading-snug [text-wrap:pretty]" title={f.title}>{f.title}</div>
              <div className="truncate font-mono text-xs text-ink-3" title={where(f)}>{where(f)}</div>
            </td>
            <td className="max-w-[150px] truncate text-xs text-ink-2" title={f.repo}>{shortRepo(f.repo)}</td>
            <td><FixStatusTag s={f.fix_status} /></td>
          </tr>
        ))}
      </DTable>
      <p className="mt-3 text-xs text-ink-3">
        The 10 highest-risk open findings, prioritised by the Analysis Agent on severity, exploitability, execution context and scanner confidence.{' '}
        <Link to="/vulnerabilities" className="text-sky hover:underline">View all {num(v.open.length)}</Link>
      </p>
    </>
  )
}

function NeededView({ v, layout }: { v: View; layout: 'list' | 'grid' }) {
  const { openFinding } = usePanels()
  if (!v.needed.length) return <Empty text="No manual remediation required. All findings in this view were remediated automatically." />
  const rows = [...v.needed].sort((a, b) => (b.score ?? 0) - (a.score ?? 0)).slice(0, 10)
  const open = (f: NeededFix) => openFinding(f.job_id, f.finding_id)
  if (layout === 'grid')
    return (
      <div className="grid gap-3 sm:grid-cols-2">
        {rows.map((f) => (
          <button key={`${f.job_id}:${f.finding_id}`} onClick={() => open(f)} className="rounded-xl border border-hairline p-4 text-left hover:bg-well/60">
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0 font-medium leading-snug">{f.title}</div>
              <SevTag sev={f.severity} />
            </div>
            <div className="mt-1 truncate font-mono text-xs text-ink-3">{f.location}</div>
            <div className="mt-3"><StatusTag tone="warn" label={f.reason} /></div>
            <p className="mt-2 border-t border-hairline pt-3 text-xs text-ink-2">{f.action}</p>
          </button>
        ))}
      </div>
    )
  return (
    <>
      <DTable head={[['Severity'], ['Vulnerability'], ['Root cause'], ['Recommended action']]} minWidth={760}>
        {rows.map((f) => (
          <tr key={`${f.job_id}:${f.finding_id}`} className="cursor-pointer hover:bg-well/60" onClick={() => open(f)}>
            <td><SevTag sev={f.severity} /></td>
            <td className="max-w-[300px]">
              <div className="line-clamp-2 font-medium leading-snug" title={f.title}>{f.title}</div>
              <div className="truncate font-mono text-xs text-ink-3" title={`${f.repo} · ${f.location}`}>{shortRepo(f.repo)} · {f.location}</div>
            </td>
            <td><StatusTag tone="warn" label={f.reason} /></td>
            <td className="max-w-[260px] text-xs text-ink-2">{f.action}</td>
          </tr>
        ))}
      </DTable>
      <p className="mt-3 text-xs text-ink-3">
        {v.needed.length > rows.length ? `The ${rows.length} highest-risk items of ${v.needed.length}. ` : ''}
        Open <Link to="/fixes" className="text-sky hover:underline">Fixes needed</Link> for the complete list, grouped by root cause.
      </p>
    </>
  )
}

function ReposView({ v, layout }: { v: View; layout: 'list' | 'grid' }) {
  if (!v.repos.length) return <Empty text="No repositories have been scanned yet."><LinkBtn to="/scan" kind="primary">Start a scan</LinkBtn></Empty>
  const stats = (r: Repository) => {
    const rows = v.rows.filter((f) => f.repo === r.repo)
    return { total: rows.length, urgent: rows.filter((f) => f.severity === 'critical' || f.severity === 'high').length, fixed: rows.filter(isFixed).length }
  }
  if (layout === 'grid')
    return (
      <div className="grid gap-3 sm:grid-cols-2">
        {v.repos.map((r) => {
          const s = stats(r)
          return (
            <Link key={r.repo} to={`/repositories`} className="rounded-xl border border-hairline p-4 hover:bg-well/60">
              <div className="truncate font-medium">{r.repo}</div>
              <div className="text-xs text-ink-3">last scan {ago(r.latest.finished_at ?? r.latest.created_at)} · {plural(r.runs, 'scan')}</div>
              <div className="mt-3 grid grid-cols-3 text-sm">
                <div><div className="tabular font-medium">{num(s.total)}</div><div className="text-xs text-ink-3">findings</div></div>
                <div><div className="tabular font-medium">{num(s.urgent)}</div><div className="text-xs text-ink-3">critical/high</div></div>
                <div><div className="tabular font-medium" style={{ color: s.fixed ? statusColor.good : undefined }}>{num(s.fixed)}</div><div className="text-xs text-ink-3">remediated</div></div>
              </div>
            </Link>
          )
        })}
      </div>
    )
  return (
    <DTable head={[['Repository'], ['Findings', 'right'], ['Critical / high', 'right'], ['Remediated', 'right'], ['Validation'], ['Last scan']]} minWidth={760}>
      {v.repos.map((r) => {
        const s = stats(r)
        return (
          <tr key={r.repo} className="hover:bg-well/60">
            <td className="font-medium"><Link to={`/runs/${(r.latest_completed ?? r.latest).id}`} className="hover:underline">{r.repo}</Link></td>
            <td className="tabular text-right">{num(s.total)}</td>
            <td className="tabular text-right">{num(s.urgent)}</td>
            <td className="tabular text-right" style={{ color: s.fixed ? statusColor.good : undefined }}>{num(s.fixed)}</td>
            <td><VerdictTag v={(r.latest_completed ?? r.latest).summary?.validation_status} /></td>
            <td className="whitespace-nowrap text-ink-3">{ago(r.latest.finished_at ?? r.latest.created_at)}</td>
          </tr>
        )
      })}
    </DTable>
  )
}

/* ───────────────────────── ranking panel ───────────────────────── */

const RANK_SEVS = ['critical', 'high', 'medium', 'low'] as const

function RankingPanel({ v }: { v: View }) {
  const [tab, setTab] = useState<'kinds' | 'repos'>('kinds')
  const { theme } = useTheme()
  const t = chartTokens[theme]
  const kinds = useMemo(() => {
    const m = new Map<string, { kind: string; n: number; urgent: number }>()
    for (const f of v.rows) {
      const k = kindName(f.category)
      const row = m.get(k) ?? { kind: k, n: 0, urgent: 0 }
      row.n++
      if (f.severity === 'critical' || f.severity === 'high') row.urgent++
      m.set(k, row)
    }
    return [...m.values()].sort((a, b) => b.n - a.n).slice(0, 14)
  }, [v.rows])
  const max = kinds[0]?.n ?? 1
  const repos = v.repos.map((r) => ({ repo: r.repo, rows: v.rows.filter((f) => f.repo === r.repo) })).sort((a, b) => b.rows.length - a.rows.length)
  const repoMax = Math.max(...repos.map((r) => r.rows.length), 1)
  const types = FINDING_TYPES.map(([k, l]) => [l, v.rows.filter((f) => findingType(f) === k).length] as const).filter(([, n]) => n)
  return (
    <Panel className="p-6">
      <Tabs value={tab} onChange={setTab} tabs={[['kinds', 'By category'], ['repos', 'By repository']]} />
      {tab === 'kinds' ? (
        <>
          <h3 className="mt-5 font-semibold">Findings by category</h3>
          <p className="mt-1 text-sm text-ink-3">The most prevalent weakness categories.</p>
          {kinds.length ? (
            <ul className="mt-5 flex flex-col gap-3.5">
              {kinds.map((k, i) => (
                <li key={k.kind} className="grid grid-cols-[136px_1fr] items-center gap-3 text-xs">
                  <span className="truncate text-right text-ink-3" title={k.kind}>{k.kind}</span>
                  <span className="flex items-center gap-2">
                    <span className="rank-bar h-2.5 rounded-full" style={{ width: `${Math.max(3, (k.n / max) * 78)}%`, background: t.series[i % t.series.length], animationDelay: `${i * 40}ms` }} />
                    <span className="tabular font-medium">{num(k.n)}</span>
                    {k.urgent > 0 && <AlertTriangle className="size-3" style={{ color: statusColor.critical }} aria-label={`${k.urgent} critical or high`} />}
                  </span>
                </li>
              ))}
            </ul>
          ) : <div className="mt-5"><Empty text="No findings for the selected filter." /></div>}
          <p className="mt-5 flex items-center gap-1.5 text-xs text-ink-3">
            <AlertTriangle className="size-3" style={{ color: statusColor.critical }} /> Includes critical or high findings
          </p>
          {types.length > 0 && <p className="mt-2 text-xs text-ink-3">{types.map(([l, n]) => `${num(n)} ${l.toLowerCase()}`).join(' · ')}</p>}
        </>
      ) : (
        <>
          <h3 className="mt-5 font-semibold">Findings by repository</h3>
          <p className="mt-1 text-sm text-ink-3">Severity profile of each repository's exposure.</p>
          <ul className="mt-6 flex flex-col gap-6">
            {repos.map((r) => (
              <li key={r.repo}>
                <div className="mb-2 flex items-baseline justify-between gap-3 text-sm">
                  <span className="truncate font-medium" title={r.repo}>{r.repo}</span>
                  <span className="tabular shrink-0 text-ink-3">{num(r.rows.length)} · {num(r.rows.filter(isFixed).length)} fixed</span>
                </div>
                <div className="flex h-2 gap-0.5" style={{ width: `${(r.rows.length / repoMax) * 100}%` }}>
                  {RANK_SEVS.map((sev) => {
                    const c = r.rows.filter((f) => f.severity === sev).length
                    return c ? (
                      <Tooltip key={sev}>
                        <TooltipTrigger asChild>
                          <span className="h-full first:rounded-l-full last:rounded-r-full" style={{ flexGrow: c, background: sevColor(theme, sev) }} />
                        </TooltipTrigger>
                        <TooltipContent>{sevLabel(sev)}: {num(c)}</TooltipContent>
                      </Tooltip>
                    ) : null
                  })}
                </div>
              </li>
            ))}
          </ul>
          <div className="mt-6 flex flex-wrap gap-x-4 gap-y-1.5 text-xs text-ink-3">
            {RANK_SEVS.map((sev) => (
              <span key={sev} className="flex items-center gap-1.5"><span className="size-2 rounded-full" style={{ background: sevColor(theme, sev) }} /> {sevLabel(sev)}</span>
            ))}
          </div>
        </>
      )}
    </Panel>
  )
}

/* ───────────────────────── the four agents ───────────────────────── */

const LEARN = {
  good: { icon: CheckCircle2, color: statusColor.good },
  warn: { icon: AlertTriangle, color: statusColor.warning },
  bad: { icon: XCircle, color: statusColor.critical },
  info: { icon: Info, color: 'var(--sky)' },
} as const

/** What each agent delivers across the findings on this page (the same numbers for every repository filter). */
function agentStats(id: AgentId, v: View): [string, string][] {
  const types = (k: string) => v.rows.filter((f) => findingType(f) === k).length
  if (id === 'analysis') return [[num(v.rows.length), 'vulnerabilities identified'], [num(v.urgent.length), 'critical or high'], [num(types('dependency')), 'in dependencies']]
  if (id === 'remediation') {
    const commits = v.repos.reduce((a, r) => a + (r.latest_completed?.summary?.fixes_applied ?? 0), 0)
    return [[num(v.fixed.length), 'vulnerabilities remediated'], [num(commits), 'remediation commits'], [num(v.needed.length), 'require manual remediation']]
  }
  if (id === 'validation') return [[num(v.confirmed), 'remediations verified'], [num(v.fixed.length - v.confirmed), 'pending verification'], [num(v.approvals.length), 'change sets awaiting approval']]
  const reported = v.repos.filter((r) => r.latest_completed).length
  return [[num(reported), reported === 1 ? 'repository reported' : 'repositories reported'], [num(v.approvals.length), 'awaiting approval'], [num(v.repos.filter((r) => r.latest_completed?.summary?.pull_request_url).length), 'pull requests raised']]
}

const AGENT_OPEN: Record<AgentId, [string, string]> = {
  analysis: ['/vulnerabilities', 'View vulnerabilities'],
  remediation: ['/fixes', 'View manual remediations'],
  validation: ['/approvals', 'View approvals'],
  reporting: ['/reports', 'View reports'],
}

function AgentOverview({ id, v }: { id: AgentId; v: View }) {
  const a = AGENTS[id]
  const h = useAgentHistory(id)
  const last = (h.data?.runs ?? []).find((r) => v.repo === 'all' || r.repo === v.repo)
  const st = last ? AGENT_STATUS[last.status] ?? AGENT_STATUS.pending : null
  const p = st ? PILL[st.tone] : PILL.idle
  const learnings: Learning[] = (last?.learnings ?? []).slice(0, 4)
  const [to, open] = AGENT_OPEN[id]
  return (
    <Panel className="flex flex-col gap-5 p-6">
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-center gap-3">
          <AgentTile id={id} />
          <div>
            <div className="text-xs font-medium text-ink-3">Agent {a.n}</div>
            <h3 className="text-lg font-semibold tracking-tight">{a.name}</h3>
          </div>
        </div>
        <span className="flex items-center gap-1.5 whitespace-nowrap text-xs text-ink-2">
          <p.icon className="size-3.5" style={{ color: p.color }} /> {st?.label ?? 'No scans yet'}{last ? ` · ${ago(last.when)}` : ''}
        </span>
      </div>
      <div className="grid grid-cols-3 gap-4 border-y border-hairline py-4">
        {agentStats(id, v).map(([value, label]) => (
          <div key={label}>
            <div className="tabular text-2xl leading-none tracking-tight">{value}</div>
            <div className="mt-1.5 text-xs text-ink-3">{label}</div>
          </div>
        ))}
      </div>
      <div>
        <h4 className="text-sm font-medium">Key conclusions {last ? <span className="font-normal text-ink-3">· {last.repo}</span> : null}</h4>
        {learnings.length ? (
          <ul className="mt-2 flex flex-col divide-y divide-hairline">
            {learnings.map((l, i) => {
              const L = LEARN[l.tone] ?? LEARN.info
              return (
                <li key={i} className="flex items-start gap-2.5 py-2 text-sm text-ink-2">
                  <L.icon className="mt-0.5 size-3.5 shrink-0" style={{ color: L.color }} />
                  <span className="min-w-0">{l.text}</span>
                </li>
              )
            })}
          </ul>
        ) : <p className="mt-2 text-sm text-ink-3">{a.short}. No results to report yet.</p>}
      </div>
      <div className="mt-auto flex flex-wrap gap-2">
        <Link to={to} className="inline-flex items-center gap-2 rounded-lg btn-blue px-4 py-2 text-sm font-medium text-white">
          {open} <ArrowRight className="size-4" />
        </Link>
        <Link to={`/agents/${id}`} className="inline-flex items-center gap-2 rounded-lg border border-hairline px-4 py-2 text-sm font-medium hover:bg-well">
          {a.name} history
        </Link>
      </div>
    </Panel>
  )
}

function DashboardSkeleton() {
  return (
    <div className="flex flex-col gap-5">
      <Skeleton className="h-12 w-80 rounded-xl" />
      <div className="card-row gap-5 [--card-min:280px]">
        {[0, 1, 2].map((i) => <Skeleton key={i} className="h-40 rounded-2xl" />)}
      </div>
      <div className="grid gap-5 xl:grid-cols-3">
        <Skeleton className="h-96 rounded-2xl xl:col-span-2" />
        <Skeleton className="h-96 rounded-2xl" />
      </div>
    </div>
  )
}
