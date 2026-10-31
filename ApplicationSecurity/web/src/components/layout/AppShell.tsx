import { useEffect, useState, type ComponentType, type CSSProperties, type ReactNode } from 'react'
import { NavLink, Outlet, useLocation } from 'react-router-dom'
import {
  ChevronRight, CircleAlert, CirclePlus, FileText, FolderGit2, Grip, HelpCircle, LayoutGrid, LogOut, Menu, Moon,
  PanelLeftClose, PanelLeftOpen, ScrollText, Settings, ShieldCheck, ShieldAlert, Sun, Workflow, Wrench,
} from 'lucide-react'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { Sheet, SheetContent, SheetTitle } from '@/components/ui/sheet'
import { Wordmark } from '@/components/Brand'
import { AttentionBell } from '@/components/AttentionBell'
import { Assistant } from '@/components/Assistant'
import { FindingDrawer } from '@/components/FindingDrawer'
import { KeysPrompt, useKeysPrompt } from '@/components/KeysPrompt'
import { isLive, useJob, useJobs } from '@/lib/api'
import { goToSharedLogin, useAuth } from '@/lib/auth'
import { AGENTS, AGENT_STATUS, mergedStages } from '@/lib/labels'
import { statusColor, useTheme } from '@/lib/theme'
import type { AgentId } from '@/lib/types'
import { cn } from '@/lib/utils'

type Counts = { agents: Partial<Record<AgentId, string>>; live: boolean }
type Item = { to: string; label: string; icon?: ComponentType<{ className?: string }>; agent?: AgentId }

// The menu follows the work: overview → what needs you → the agents → the results → set-up.
// Each group has its own colour (icons, selected row) so the menu doubles as a map of the site.
const GROUPS: { heading: string; tone: string; on: string; items: Item[] }[] = [
  { heading: 'Overview', tone: 'var(--area-overview)', on: 'var(--area-overview-on)', items: [
    { to: '/', label: 'Dashboard', icon: LayoutGrid },
    { to: '/scan', label: 'New scan', icon: CirclePlus },
  ] },
  { heading: 'Action center', tone: 'var(--area-check)', on: 'var(--area-check-on)', items: [
    { to: '/approvals', label: 'Approvals', icon: ShieldCheck },
    { to: '/fixes', label: 'Fixes needed', icon: Wrench },
    { to: '/errors', label: 'Errors', icon: CircleAlert },
  ] },
  { heading: 'Agents', tone: 'var(--area-trust)', on: 'var(--area-trust-on)', items: (Object.keys(AGENTS) as AgentId[]).map((id) => ({ to: `/agents/${id}`, label: AGENTS[id].name, icon: AGENTS[id].icon, agent: id })) },
  { heading: 'Results', tone: 'var(--area-find)', on: 'var(--area-find-on)', items: [
    { to: '/vulnerabilities', label: 'Vulnerabilities', icon: ShieldAlert },
    { to: '/repositories', label: 'Repositories', icon: FolderGit2 },
    { to: '/runs', label: 'Scan history', icon: Workflow },
    { to: '/activity', label: 'Activity log', icon: ScrollText },
    { to: '/reports', label: 'Reports', icon: FileText },
  ] },
  { heading: 'Configure', tone: 'var(--area-act)', on: 'var(--area-act-on)', items: [
    { to: '/how', label: 'How it works', icon: HelpCircle },
    { to: '/settings', label: 'Settings', icon: Settings },
  ] },
]
const NAV = GROUPS.flatMap((g) => g.items)

// Breadcrumb names for the tabs inside a run
const TAB_NAMES: Record<string, string> = {
  summary: 'Summary', analysis: '① Analysis', remediation: '② Remediation', validation: '③ Validation', reporting: '④ Reporting',
  tests: '⑤ CI tests', findings: 'All findings', logs: 'Activity log',
}

const NAV_KEY = 'appvuln-nav-collapsed'

/** Side menu open (labels) or collapsed (icons only); remembered per browser, Ctrl+B toggles it. */
function useCollapsedNav() {
  const [collapsed, setCollapsed] = useState(() => {
    try {
      return localStorage.getItem(NAV_KEY) === '1'
    } catch {
      return false
    }
  })
  useEffect(() => {
    try {
      localStorage.setItem(NAV_KEY, collapsed ? '1' : '0')
    } catch {
      /* not essential */
    }
  }, [collapsed])
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const typing = (e.target as HTMLElement)?.closest?.('input, textarea, [contenteditable="true"]')
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'b' && !typing) {
        e.preventDefault()
        setCollapsed((c) => !c)
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])
  return [collapsed, setCollapsed] as const
}

/** Live state for the menu: each agent's status in the latest scan, and whether a scan is running. */
function useCounts(): Counts {
  const latest = useJobs({ limit: 1 }, 6_000)
  const latestJob = latest.data?.items[0]
  const job = useJob(latestJob?.id)
  const agents: Counts['agents'] = {}
  if (job.data) for (const s of mergedStages(job.data.stages)) if (s.id in AGENTS) agents[s.id as AgentId] = s.status
  return { agents, live: isLive(latestJob) }
}

export function AppShell() {
  const { pathname } = useLocation()
  const { theme, toggle } = useTheme()
  const { loginUrl } = useAuth()
  const keys = useKeysPrompt()
  const [collapsed, setCollapsed] = useCollapsedNav()
  const counts = useCounts()
  const onHome = pathname === '/'
  // the most specific menu item wins
  const activeItem = NAV.map((i) => i.to)
    .filter((to) => (to === '/' ? pathname === '/' : pathname === to || pathname.startsWith(to + '/')))
    .sort((a, b) => b.length - a.length)[0]

  // A new page always opens at the top.
  useEffect(() => {
    window.scrollTo({ top: 0, left: 0, behavior: 'instant' })
  }, [pathname])

  return (
    <div className="min-h-svh bg-canvas text-ink">
      {/* Top bar */}
      <header className="brand-stripe sticky top-0 z-20 border-b border-hairline bg-canvas">
        <div className="flex h-14 items-center gap-3 px-4 md:px-6">
          <PhoneMenu activeItem={activeItem} counts={counts} />
          <NavLink to="/" className="rounded-lg"><Wordmark compact /></NavLink>
          <div className="flex-1" />
          <NavLink
            to={counts.live ? '/' : '/scan'}
            className="hidden h-9 items-center gap-2 rounded-lg border border-hairline-strong bg-[var(--panel-glass)] px-3 text-sm font-medium text-ink transition-colors hover:bg-well sm:flex"
          >
            {counts.live ? <span className="size-2 animate-pulse rounded-full bg-sky" /> : <CirclePlus className="size-3.5 text-sky" />}
            {counts.live ? 'Scan in progress…' : 'New scan'}
          </NavLink>
          <AttentionBell />
          <Tooltip>
            <TooltipTrigger asChild>
              <button
                onClick={() => { window.location.href = `${loginUrl || 'http://127.0.0.1:8000'}/?switch=1` }}
                className="grid size-9 place-items-center rounded-lg text-ink-2 hover:bg-well hover:text-ink"
                aria-label="Switch workspace"
              >
                <Grip className="size-[18px]" />
              </button>
            </TooltipTrigger>
            <TooltipContent>Switch workspace</TooltipContent>
          </Tooltip>
          <Tooltip>
            <TooltipTrigger asChild>
              <button onClick={toggle} className="grid size-9 place-items-center rounded-lg text-ink-2 hover:bg-well hover:text-ink" aria-label="Switch between light and dark mode">
                {theme === 'dark' ? <Sun className="size-[18px]" /> : <Moon className="size-[18px]" />}
              </button>
            </TooltipTrigger>
            <TooltipContent>{theme === 'dark' ? 'Light mode' : 'Dark mode'}</TooltipContent>
          </Tooltip>
        </div>
      </header>

      <div className="flex">
        <aside
          className={cn(
            'nav-surface sticky ml-3 mt-3 hidden shrink-0 flex-col overflow-hidden rounded-[20px] border border-hairline shadow-[0_1px_2px_rgb(0_0_0/0.04),0_10px_28px_-14px_rgb(0_0_0/0.18)] transition-[width] duration-200 lg:flex',
            collapsed ? 'w-16' : 'w-64',
            'top-[68px] h-[calc(100svh-80px)]',
          )}
        >
          {collapsed ? <CollapsedMenu activeItem={activeItem} counts={counts} onExpand={() => setCollapsed(false)} /> : <>
            <div className="absolute right-3 top-2.5 z-10">
              <Tooltip>
                <TooltipTrigger asChild>
                  <button onClick={() => setCollapsed(true)} className="grid size-9 shrink-0 place-items-center rounded-lg text-ink-2 hover:bg-well hover:text-ink" aria-label="Close the menu" aria-expanded>
                    <PanelLeftClose className="size-[18px]" />
                  </button>
                </TooltipTrigger>
                <TooltipContent side="bottom">Close the menu · Ctrl+B</TooltipContent>
              </Tooltip>
            </div>
            <MenuGroups activeItem={activeItem} counts={counts} />
            <ProfileBox />
          </>}
        </aside>

        <main className="min-w-0 flex-1 px-4 pb-24 pt-6 md:px-6 lg:px-8">
          <div id="top" className="mx-auto max-w-[1680px] scroll-mt-32">
            {!onHome && <Breadcrumb pathname={pathname} activeItem={activeItem} />}
            <Outlet />
          </div>
        </main>
      </div>

      <KeysPrompt prompt={keys} />
      <FindingDrawer />
      <Assistant />
    </div>
  )
}

/* ───────── the menu with labels: side panel on wide screens, slide-in sheet on phones ───────── */

function AgentDot({ status }: { status?: string }) {
  const color = status === 'running' ? 'var(--sky)' : status === 'completed' ? statusColor.good : status === 'warning' ? statusColor.warning
    : status === 'failed' ? statusColor.critical : 'var(--hairline-strong)'
  return <span className={cn('size-2 shrink-0 rounded-full', status === 'running' && 'animate-pulse')} style={{ background: color }} title={AGENT_STATUS[status ?? '']?.label ?? 'Idle'} />
}

function MenuGroups({ activeItem, counts, onPick }: { activeItem?: string; counts: Counts; onPick?: () => void }) {
  return (
    <nav className="nav-scroll flex-1 overflow-y-auto px-3 pb-3 pt-1" aria-label="Main menu">
      {GROUPS.map((g) => (
        <div key={g.heading} className="mt-3 flex flex-col gap-0.5">
          <div className="flex items-center gap-2 px-2 pb-1.5 text-[11px] font-semibold uppercase tracking-[0.12em] text-ink-3 after:h-px after:flex-1 after:bg-hairline after:content-['']">
            <span className="size-1.5 shrink-0 rounded-full" style={{ background: g.tone }} aria-hidden />{g.heading}
          </div>
          {g.items.map((it) => {
            const active = activeItem === it.to
            const Icon = it.icon!
            return (
              <NavLink
                key={it.to}
                to={it.to}
                onClick={onPick}
                aria-current={active ? 'page' : undefined}
                style={{ '--area': g.tone, '--area-on': g.on } as CSSProperties}
                className={cn(
                  'group relative flex h-9 items-center gap-3 rounded-[10px] px-1.5 pr-2.5 text-sm transition-colors',
                  active ? 'nav-on font-semibold text-ink' : 'text-ink-2 hover:bg-well hover:text-ink',
                )}
              >
                <span className="area-tile grid size-7 shrink-0 place-items-center rounded-[8px]">
                  <Icon className="size-4" />
                </span>
                <span className="truncate">{it.label}</span>
                {it.agent && <span className="ml-auto"><AgentDot status={counts.agents[it.agent]} /></span>}
                {it.to === '/' && counts.live && <span className="ml-auto size-2 animate-pulse rounded-full bg-sky" title="A pipeline is running" />}
              </NavLink>
            )
          })}
        </div>
      ))}
    </nav>
  )
}

/** Below 1024px the side menu is hidden; this button opens the same menu as a sheet from the left. */
function PhoneMenu({ activeItem, counts }: { activeItem?: string; counts: Counts }) {
  const [open, setOpen] = useState(false)
  return (
    <>
      <button onClick={() => setOpen(true)} className="-ml-1 grid size-9 place-items-center rounded-lg text-ink-2 hover:bg-well hover:text-ink lg:hidden" aria-label="Open the menu">
        <Menu className="size-5" />
      </button>
      <Sheet open={open} onOpenChange={setOpen}>
        <SheetContent side="left" className="nav-surface gap-0 border-hairline p-0 data-[side=left]:w-[min(300px,85vw)]">
          <SheetTitle className="flex h-14 items-center border-b border-hairline px-4"><Wordmark /></SheetTitle>
          <MenuGroups activeItem={activeItem} counts={counts} onPick={() => setOpen(false)} />
          <ProfileBox />
        </SheetContent>
      </Sheet>
    </>
  )
}

/** Who is signed in, Switch domain (only for people with more than one CyberSuite domain) and Sign out: a box at the
    bottom of the side menu. Collapsed menu: the initials and the buttons. Hidden when there is no shared sign-in. */
function ProfileBox({ compact }: { compact?: boolean }) {
  const { user, loginUrl, signOut } = useAuth()
  const switchTarget = loginUrl || 'http://127.0.0.1:8000'
  const modules = () => { window.location.href = `${switchTarget}/?switch=1` }
  const out = async () => {
    await signOut()
    goToSharedLogin(switchTarget)
  }

  if (!user || user.via === 'off') {
    if (compact) {
      return (
        <div className="flex flex-col items-center gap-1.5 border-t border-hairline py-3">
          <RailButton label="Switch workspace" onClick={modules}><Grip className="size-4" /></RailButton>
        </div>
      )
    }
    return (
      <div className="border-t border-hairline p-3">
        <button
          onClick={modules}
          title="Switch to another CyberSuite workspace"
          className="flex h-9 w-full items-center justify-center gap-2 rounded-lg border border-hairline-strong text-sm font-medium text-ink-2 transition-colors hover:border-blue/60 hover:bg-blue/10 hover:text-ink"
        >
          <Grip className="size-4" /> Switch workspace
        </button>
      </div>
    )
  }

  const initials = (user.name || user.email).split(/[\s@.]+/).filter(Boolean).slice(0, 2).map((w) => w[0]!.toUpperCase()).join('')

  if (compact) {
    return (
      <div className="flex flex-col items-center gap-1.5 border-t border-hairline py-3">
        <Tooltip>
          <TooltipTrigger asChild>
            <span className="grid size-9 place-items-center rounded-full bg-blue text-[12px] font-bold text-white" aria-label={`Signed in as ${user.name}`}>{initials}</span>
          </TooltipTrigger>
          <TooltipContent side="right">{user.name}<span className="text-ink-3"> · {user.email}</span></TooltipContent>
        </Tooltip>
        <RailButton label="Switch workspace" onClick={modules}><Grip className="size-4" /></RailButton>
        <RailButton label="Sign out" onClick={out}><LogOut className="size-4" /></RailButton>
      </div>
    )
  }
  return (
    <div className="border-t border-hairline p-3">
      <div className="rounded-xl border border-hairline bg-panel p-3">
        <div className="flex items-center gap-3">
          <span className="grid size-10 shrink-0 place-items-center rounded-full bg-blue text-[13px] font-bold text-white">{initials}</span>
          <span className="min-w-0 flex-1">
            <span className="block truncate text-sm font-semibold text-ink">{user.name}</span>
            <span className="block truncate text-xs text-ink-3" title={user.email}>{user.email}</span>
          </span>
        </div>
        <div className="mt-3 flex gap-2">
          <button
            onClick={modules}
            title="Switch to another CyberSuite workspace"
            className="flex h-9 flex-1 items-center justify-center gap-2 rounded-lg border border-hairline-strong text-sm font-medium text-ink-2 transition-colors hover:border-blue/60 hover:bg-blue/10 hover:text-ink"
          >
            <Grip className="size-4" /> Switch
          </button>
          <button
            onClick={out}
            className="flex h-9 flex-1 items-center justify-center gap-2 rounded-lg border border-hairline-strong text-sm font-medium text-ink-2 transition-colors hover:border-rose/60 hover:bg-rose/10 hover:text-ink"
          >
            <LogOut className="size-4" /> Sign out
          </button>
        </div>
      </div>
    </div>
  )
}

function RailButton({ label, hint, onClick, children }: { label: string; hint?: string; onClick: () => void; children: ReactNode }) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <button onClick={onClick} aria-label={label} className="grid size-10 place-items-center rounded-xl text-ink-3 hover:bg-well hover:text-ink">
          {children}
        </button>
      </TooltipTrigger>
      <TooltipContent side="right">{label}{hint && <span className="text-ink-3"> · {hint}</span>}</TooltipContent>
    </Tooltip>
  )
}

/* ───────── collapsed menu: the same items as icons; hover shows the name ───────── */

function CollapsedMenu({ activeItem, counts, onExpand }: { activeItem?: string; counts: Counts; onExpand: () => void }) {
  return (
    <>
      <div className="flex flex-col items-center gap-1 pt-3">
        <RailButton label="Open the menu" hint="Ctrl+B" onClick={onExpand}><PanelLeftOpen className="size-[18px]" /></RailButton>
      </div>
      <nav className="nav-scroll flex flex-1 flex-col items-center overflow-y-auto pb-3" aria-label="Main menu">
        {GROUPS.map((g) => (
          <div key={g.heading} className="flex flex-col items-center gap-1">
            <span className="my-2 h-px w-6 bg-hairline" aria-hidden />
            {g.items.map((it) => {
              const active = activeItem === it.to
              const Icon = it.icon!
              return (
                <Tooltip key={it.to}>
                  <TooltipTrigger asChild>
                    <NavLink
                      to={it.to}
                      aria-label={it.label}
                      aria-current={active ? 'page' : undefined}
                      style={{ '--area': g.tone, '--area-on': g.on } as CSSProperties}
                      className={cn('relative grid size-10 place-items-center rounded-[10px] transition-colors', active ? 'area-tile-on' : 'area-tile hover:brightness-125')}
                    >
                      <Icon className="size-[18px]" />
                      {it.agent && <span className="absolute bottom-1 right-1"><AgentDot status={counts.agents[it.agent]} /></span>}
                    </NavLink>
                  </TooltipTrigger>
                  <TooltipContent side="right"><span className="opacity-70">{g.heading} ·</span> {it.label}</TooltipContent>
                </Tooltip>
              )
            })}
          </div>
        ))}
      </nav>
      <ProfileBox compact />
    </>
  )
}

/* ───────── breadcrumb: Page › Run › Tab, the same on every page ───────── */

function Breadcrumb({ pathname, activeItem }: { pathname: string; activeItem?: string }) {
  const item = NAV.find((i) => i.to === activeItem)
  if (!item) return null
  const rest = pathname.slice(item.to.length).split('/').filter(Boolean)
  const parts: string[] = [item.label]
  if (item.to === '/runs' && rest[0]) parts.push(`Run ${rest[0].slice(0, 8)}`, ...(rest[1] ? [TAB_NAMES[rest[1]] ?? rest[1]] : []))
  if (parts.length < 2) return null // the page heading already names the page; a one-step trail would only repeat it
  return (
    <nav aria-label="You are here" className="mb-5 flex items-center gap-1.5 text-xs text-ink-3">
      {parts.map((p, i) => (
        <span key={p} className="flex items-center gap-1.5">
          {i > 0 && <ChevronRight className="size-3" />}
          {i === 0 ? <NavLink to={item.to} className="hover:text-ink">{p}</NavLink>
            : i === 1 && parts.length > 2 ? <NavLink to={`/runs/${rest[0]}`} className="hover:text-ink">{p}</NavLink>
              : <span className={i === parts.length - 1 ? 'font-medium text-ink-2' : ''}>{p}</span>}
        </span>
      ))}
    </nav>
  )
}
