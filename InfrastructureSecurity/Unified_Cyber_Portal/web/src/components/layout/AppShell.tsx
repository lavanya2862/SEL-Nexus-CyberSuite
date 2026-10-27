import { useEffect, useState, type ComponentType, type CSSProperties, type ReactNode } from 'react'
import { NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom'
import {
  Bot, ChevronRight, Crosshair, FileText, Grip, LayoutGrid, Moon, PanelLeftClose, PanelLeftOpen, Play, Radar,
  LogOut, Menu, ScanSearch, Siren, Sun, Wrench,
} from 'lucide-react'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { Sheet, SheetContent, SheetTitle } from '@/components/ui/sheet'
import { Wordmark } from '@/components/Brand'
import { Tour, shouldShowTour } from '@/components/Help'
import { NotificationBell } from '@/components/NotificationBell'
import { HelpBot } from '@/components/HelpBot'
import { goToSharedLogin, useAuth } from '@/lib/auth'
import { useRuns } from '@/lib/runs'
import { useTheme } from '@/lib/theme'
import { cn } from '@/lib/utils'

type Item = { to: string; label: string; icon: ComponentType<{ className?: string }> }

// The menu follows the story: overview (summary, the agents that fetch the data, fixing) -> dashboard -> archives.
// Each group has its own colour (icons, selected row) so the menu doubles as a map of the portal's areas.
const GROUPS: { heading: string; tone: string; on: string; items: Item[] }[] = [
  { heading: 'Overview', tone: 'var(--area-overview)', on: 'var(--area-overview-on)', items: [{ to: '/', label: 'Summary', icon: LayoutGrid }, { to: '/runs', label: 'Agents', icon: Bot }, { to: '/fixes', label: 'Remediation', icon: Wrench }] },
  { heading: 'Dashboard', tone: 'var(--area-find)', on: 'var(--area-find-on)', items: [
    { to: '/uc3', label: 'Vulnerabilities', icon: ScanSearch }, { to: '/uc1', label: 'Threats', icon: Crosshair },
    { to: '/uc1/hunts', label: 'Attack detection', icon: Radar }, { to: '/respond', label: 'Alert triage', icon: Siren }] },
  { heading: 'Archives', tone: 'var(--area-trust)', on: 'var(--area-trust-on)', items: [{ to: '/reports', label: 'Reports', icon: FileText }] },]
const NAV = GROUPS.flatMap((g) => g.items)

// Breadcrumb names for the tabs inside a page (the page itself comes from the menu)
const TAB_NAMES: Record<string, string> = {
  affects: 'Affects us', explorer: 'Explorer', health: 'Health & metrics',
  threat: 'Threat detail', opco: 'By VM', age: 'Age & SLA', trends: 'Trends', devices: 'Devices',
  quality: 'Data quality',
  uc1: 'Threat Intel Agent', uc3: 'Vulnerability Agent', uc4: 'Alert Triage Agent', progress: 'Fix progress',
}

const NAV_KEY = 'portal-nav-collapsed'

/** Side menu open (labels) or collapsed (icons only); remembered per browser, Ctrl+B toggles it. */
function useCollapsedNav() {
  const [collapsed, setCollapsed] = useState(() => {
    const forced = new URLSearchParams(window.location.search).get('menu') // ?menu=icons|full for demos / screenshots
    if (forced === 'icons' || forced === 'full') return forced === 'icons'
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

export function AppShell() {
  const { pathname } = useLocation()
  const { theme, toggle } = useTheme()
  const { openDrawer, runs } = useRuns()
  const [tour, setTour] = useState(false)
  const [collapsed, setCollapsed] = useCollapsedNav()
  const onHome = pathname === '/'
  // the most specific menu item wins (/uc1/hunts is Attack detection, not Threats)
  const activeItem = NAV.map((i) => i.to)
    .filter((to) => (to === '/' ? pathname === '/' : pathname === to || pathname.startsWith(to + '/')))
    .sort((a, b) => b.length - a.length)[0]
  const anyRunning = Object.values(runs ?? {}).some((r) => r?.status === 'running')

  useEffect(() => {
    if (shouldShowTour()) setTour(true)
  }, [])

  // A new page always opens at the top (the browser would otherwise keep the last page's scroll position).
  // Pages that jump to a card themselves (?app= on Fix) still do so after this.
  useEffect(() => {
    window.scrollTo({ top: 0, left: 0, behavior: 'instant' })
  }, [pathname])

  return (
    <div className="min-h-svh bg-canvas text-ink">
      {/* Top bar */}
      <header className="brand-stripe sticky top-0 z-20 border-b border-hairline bg-canvas">
        <div className="flex h-14 items-center gap-3 px-4 md:px-6">
          <PhoneMenu activeItem={activeItem} />
          <NavLink to="/" className="rounded-lg"><Wordmark compact /></NavLink>
          <div className="flex-1" />
          <button
            onClick={() => openDrawer()}
            className="hidden h-9 items-center gap-2 rounded-lg border border-hairline-strong bg-[var(--panel-glass)] px-3 text-sm font-medium text-ink transition-colors hover:bg-well sm:flex"
          >
            {anyRunning ? <span className="size-2 animate-pulse rounded-full bg-sky" /> : <Play className="size-3.5 fill-sky text-sky" />}
            {anyRunning ? 'Agents working…' : 'Run agents'}
          </button>
          <NotificationBell />
          <Tooltip>
            <TooltipTrigger asChild>
              <button onClick={toggle} className="grid size-9 place-items-center rounded-lg text-ink-2 hover:bg-well hover:text-ink" aria-label="Switch light or dark">
                {theme === 'dark' ? <Sun className="size-[18px]" /> : <Moon className="size-[18px]" />}
              </button>
            </TooltipTrigger>
            <TooltipContent>{theme === 'dark' ? 'Light mode' : 'Dark mode'}</TooltipContent>
          </Tooltip>
        </div>

      </header>

      <div className="flex">
        {/* One clear menu */}
        <aside
          className={cn(
            'nav-surface sticky hidden shrink-0 flex-col overflow-hidden border-r border-hairline transition-[width] duration-200 lg:flex',
            collapsed ? 'w-16' : 'w-64',
            'top-14 h-[calc(100svh-56px)]',
          )}
        >
          {collapsed ? <CollapsedMenu
            activeItem={activeItem}
            onExpand={() => setCollapsed(false)}
          /> : <>
          {/* the close button sits in the top-right corner, level with the first heading ("Overview") */}
          <div className="absolute right-3 top-2.5 z-10">
            <Tooltip>
              <TooltipTrigger asChild>
                <button
                  onClick={() => setCollapsed(true)}
                  className="grid size-9 shrink-0 place-items-center rounded-lg text-ink-2 hover:bg-well hover:text-ink"
                  aria-label="Close the menu"
                  aria-expanded
                >
                  <PanelLeftClose className="size-[18px]" />
                </button>
              </TooltipTrigger>
              <TooltipContent side="bottom">Close the menu · Ctrl+B</TooltipContent>
            </Tooltip>
          </div>
          <MenuGroups activeItem={activeItem} />
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

      <Tour open={tour} onOpenChange={setTour} />
      <HelpBot />
    </div>
  )
}

/* ───────── the menu with labels: side panel on wide screens, slide-in sheet on phones ───────── */

function MenuGroups({ activeItem, onPick }: { activeItem?: string; onPick?: () => void }) {
  return (
    <nav className="flex-1 overflow-y-auto px-3 pb-3 pt-1" aria-label="Main menu">
      {GROUPS.map((g) => (
        <div key={g.heading} className="mt-4 flex flex-col gap-0.5">
          <div className="flex items-center gap-2 px-2 pb-1.5 text-[11px] font-semibold uppercase tracking-[0.12em] text-ink-3 after:h-px after:flex-1 after:bg-hairline after:content-['']">
            <span className="size-1.5 shrink-0 rounded-full" style={{ background: g.tone }} aria-hidden />{g.heading}
          </div>
          {g.items.map((it) => {
            const active = activeItem === it.to
            return (
              <NavLink
                key={it.to}
                to={it.to}
                onClick={onPick}
                aria-current={active ? 'page' : undefined}
                style={{ '--area': g.tone, '--area-on': g.on } as CSSProperties}
                className={cn(
                  'group relative flex h-10 items-center gap-3 rounded-[10px] px-1.5 text-sm transition-colors',
                  active ? 'nav-on font-semibold text-ink' : 'text-ink-2 hover:bg-well hover:text-ink',
                )}
              >
                <span className="area-tile grid size-7 shrink-0 place-items-center rounded-[8px]">
                  <it.icon className="size-4" />
                </span>
                <span className="truncate">{it.label}</span>
              </NavLink>
            )
          })}
        </div>
      ))}
    </nav>
  )
}

/** Below 1024px the side menu is hidden; this button opens the same menu as a sheet from the left. */
function PhoneMenu({ activeItem }: { activeItem?: string }) {
  const [open, setOpen] = useState(false)
  return (
    <>
      <button onClick={() => setOpen(true)} className="-ml-1 grid size-9 place-items-center rounded-lg text-ink-2 hover:bg-well hover:text-ink lg:hidden" aria-label="Open the menu">
        <Menu className="size-5" />
      </button>
      <Sheet open={open} onOpenChange={setOpen}>
        <SheetContent side="left" className="nav-surface gap-0 border-hairline p-0 data-[side=left]:w-[min(300px,85vw)]">
          <SheetTitle className="flex h-14 items-center border-b border-hairline px-4"><Wordmark /></SheetTitle>
          <MenuGroups activeItem={activeItem} onPick={() => setOpen(false)} />
          <ProfileBox />
        </SheetContent>
      </Sheet>
    </>
  )
}

/* ───────── collapsed menu: the same items as icons; hover shows the name ───────── */

/** Who is signed in, and Sign out (hidden when sign-in is switched off). */
/** Who is signed in, and Sign out: a box at the bottom of the side menu (hidden when sign-in is switched off).
    Collapsed menu: the initials and a sign-out button. */
function ProfileBox({ compact }: { compact?: boolean }) {
  const { user, config, signOut } = useAuth()
  const navigate = useNavigate()
  if (!user || user.via === 'off') return null
  const initials = (user.name || user.email).split(/[\s@.]+/).filter(Boolean).slice(0, 2).map((w) => w[0]!.toUpperCase()).join('')
  const loginUrl = config?.login_url
  const out = async () => {
    await signOut()
    if (loginUrl) goToSharedLogin(loginUrl)
    else navigate('/login', { replace: true })
  }
  // the shared CyberSuite sign-in page lists the person's domains to switch between
  const modules = loginUrl ? () => { window.location.href = `${loginUrl}/?switch=1` } : null
  if (compact) {
    return (
      <div className="flex flex-col items-center gap-1.5 border-t border-hairline py-3">
        <Tooltip>
          <TooltipTrigger asChild>
            <span className="grid size-9 place-items-center rounded-full bg-blue text-[12px] font-bold text-white" aria-label={`Signed in as ${user.name}`}>{initials}</span>
          </TooltipTrigger>
          <TooltipContent side="right">{user.name}<span className="text-ink-3"> · {user.email}</span></TooltipContent>
        </Tooltip>
        {modules && <RailButton label="Switch domain" onClick={modules}><Grip className="size-4" /></RailButton>}
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
          {modules && (
            <button
              onClick={modules}
              title="Switch to another CyberSuite domain"
              className="flex h-9 flex-1 items-center justify-center gap-2 rounded-lg border border-hairline-strong text-sm font-medium text-ink-2 transition-colors hover:border-blue/60 hover:bg-blue/10 hover:text-ink"
            >
              <Grip className="size-4" /> Switch
            </button>
          )}
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

function CollapsedMenu({ activeItem, onExpand }: { activeItem?: string; onExpand: () => void }) {
  return (
    <>
      <div className="flex flex-col items-center gap-1 pt-3">
        <RailButton label="Open the menu" hint="Ctrl+B" onClick={onExpand}><PanelLeftOpen className="size-[18px]" /></RailButton>
      </div>
      <nav className="flex flex-1 flex-col items-center overflow-y-auto pb-3" aria-label="Main menu">
        {GROUPS.map((g) => (
          <div key={g.heading} className="flex flex-col items-center gap-1">
            <span className="my-2 h-px w-6 bg-hairline" aria-hidden />
            {g.items.map((it) => {
              const active = activeItem === it.to
              return (
                <Tooltip key={it.to}>
                  <TooltipTrigger asChild>
                    <NavLink
                      to={it.to}
                      aria-label={it.label}
                      aria-current={active ? 'page' : undefined}
                      style={{ '--area': g.tone, '--area-on': g.on } as CSSProperties}
                      className={cn('grid size-10 place-items-center rounded-[10px] transition-colors', active ? 'area-tile-on' : 'area-tile hover:brightness-125')}
                    >
                      <it.icon className="size-[18px]" />
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

/* ───────── breadcrumb: Page › Tab, the same on every page ───────── */

function Breadcrumb({ pathname, activeItem }: { pathname: string; activeItem?: string }) {
  const item = NAV.find((i) => i.to === activeItem)
  if (!item) return null
  const rest = pathname.slice(item.to.length).split('/').filter(Boolean)
  const tab = rest[0] ? TAB_NAMES[rest[0]] ?? (item.to === '/respond' ? `Incident #${decodeURIComponent(rest[0])}` : null) : null
  const parts = [item.label, ...(tab ? [tab] : [])]
  if (parts.length < 2) return null // the page heading already names the page; a one-step trail would only repeat it
  return (
    <nav aria-label="You are here" className="mb-5 flex items-center gap-1.5 text-xs text-ink-3">
      {parts.map((p, i) => (
        <span key={p} className="flex items-center gap-1.5">
          {i > 0 && <ChevronRight className="size-3" />}
          {i === 0 && parts.length > 1 ? <NavLink to={item.to} className="hover:text-ink">{p}</NavLink>
            : <span className={i === parts.length - 1 ? 'font-medium text-ink-2' : ''}>{p}</span>}
        </span>
      ))}
    </nav>
  )
}
