import { useEffect, useState } from 'react'
import { NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import {
  Bell, ChevronDown, Crosshair, Database, FileText, Info, LayoutGrid, Link2, PanelLeftClose, PanelLeftOpen, Play,
  Radar, ScanSearch, Search, ShieldCheck, Wrench,
} from 'lucide-react'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { fetchSummary } from '@/lib/api'
import { useFilters, type WorkTab } from '@/lib/filters'
import { useTheme } from '@/lib/theme'
import { cn } from '@/lib/utils'
import './glass.css'

const RAIL = [
  { to: '/glass', label: 'Overview', icon: LayoutGrid, end: true },
  { to: '/glass/uc1', label: 'Threats', icon: Crosshair },
  { to: '/glass/uc3', label: 'Vulnerabilities', icon: ScanSearch },
  { to: '/glass/fixes', label: 'Remediation', icon: Wrench },
  { to: '/glass/reports', label: 'Reports', icon: FileText },
]

const MENU = [
  { to: '/glass', label: 'Summary', icon: LayoutGrid, end: true },
  { to: '/glass/uc1', label: 'Threats', tag: 'Threat Intel Agent', tone: 'var(--g-violet)', icon: Crosshair },
  { to: '/glass/uc1/hunts', label: 'Attack detection', tag: 'Threat Intel Agent', tone: 'var(--g-violet)', icon: Radar },
  { to: '/glass/uc3', label: 'Vulnerabilities', tag: 'Vulnerability Agent', tone: 'var(--g-sky)', icon: ScanSearch },
  { to: '/glass/uc3/quality', label: 'Data quality', tag: 'Vulnerability Agent', tone: 'var(--g-sky)', icon: Database },
  { to: '/glass/fixes', label: 'Remediation', icon: Wrench },
]

const SECTIONS: { id: string; label: string; tab?: WorkTab }[] = [
  { id: 'top', label: 'Overview' },
  { id: 'work', label: 'Top priorities', tab: 'fixes' },
  { id: 'work', label: 'Threats', tab: 'threats' },
  { id: 'work', label: 'Devices', tab: 'devices' },
  { id: 'pipelines', label: 'Pipelines' },
]

export const glassTip = 'border border-[var(--g-line-2)] bg-[#1d140f]/95 text-[var(--g-ink)] backdrop-blur-xl [&_svg]:hidden'

export function GlassShell() {
  const { pathname } = useLocation()
  const navigate = useNavigate()
  const { theme } = useTheme()
  const { opco, setOpco, workTab, setWorkTab } = useFilters()
  const { data } = useQuery({ queryKey: ['summary'], queryFn: fetchSummary, refetchInterval: 30_000 })
  const [panelOpen, setPanelOpen] = useState(true)
  const [panelTab, setPanelTab] = useState<'menu' | 'filters'>('menu')
  const [section, setSection] = useState('Overview')
  const opcos = data?.uc3.opco_totals.map((o) => o.opco) ?? []
  const onHome = pathname === '/glass' || pathname === '/glass/'

  // Glass is a dark world: borrow the dark class while mounted, hand the classic theme back on leave.
  useEffect(() => {
    document.documentElement.classList.add('dark')
    return () => {
      document.documentElement.classList.toggle('dark', theme === 'dark')
    }
  }, [theme])

  const go = (s: (typeof SECTIONS)[number]) => {
    setSection(s.label)
    if (s.tab) setWorkTab(s.tab)
    document.getElementById(s.id)?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }

  return (
    <div className="glass-root min-h-svh">
      <div className="glass-sky" aria-hidden />
      <div className="relative z-10 flex min-h-svh flex-col">
        {/* Top bar */}
        <header className="sticky top-0 z-30 px-3 pt-3 md:px-4">
          <div className="glass-panel flex h-14 items-center gap-3 rounded-2xl px-4">
            <div className="flex items-center gap-2.5">
              <div className="grid size-8 place-items-center rounded-lg glass-ember">
                <ShieldCheck className="size-4 text-[#1b0d06]" />
              </div>
              <span className="text-[14px] font-bold tracking-[0.22em]">SEL NEXUS</span>
              <span className="hidden text-sm text-[var(--g-ink-3)] sm:inline">Infrastructure Security</span>
            </div>
            <button className="ml-2 hidden items-center gap-1 rounded-lg px-2 py-1 text-sm font-medium text-[var(--g-ink-2)] hover:bg-white/5 md:flex">
              Workspace <ChevronDown className="size-4" />
            </button>
            <div className="hidden flex-1 justify-center lg:flex">
              <div className="glass-pill flex w-80 items-center gap-2 px-4 py-2 text-sm text-[var(--g-ink-3)]">
                <Search className="size-4" />
                <span className="flex-1">Search CVE, app or device</span>
                <span className="rounded-md border border-[var(--g-line)] px-1.5 text-[10px]">soon</span>
              </div>
            </div>
            <div className="flex-1 lg:hidden" />
            <Tooltip>
              <TooltipTrigger asChild>
                <span tabIndex={0}>
                  <button disabled className="glass-btn-ember hidden items-center gap-2 rounded-full px-4 py-2 text-sm font-semibold disabled:cursor-not-allowed disabled:opacity-70 sm:flex">
                    <Play className="size-3.5" /> Run pipelines
                  </button>
                </span>
              </TooltipTrigger>
              <TooltipContent className={glassTip}>Preview design: more pages are being added</TooltipContent>
            </Tooltip>
            <Tooltip>
              <TooltipTrigger asChild>
                <button className="grid size-9 place-items-center rounded-full text-[var(--g-ink-2)] hover:bg-white/5" aria-label="About CyberSuite">
                  <Info className="size-[18px]" />
                </button>
              </TooltipTrigger>
              <TooltipContent className={cn(glassTip, 'max-w-64')}>Data: Microsoft Defender and public threat intelligence feeds.</TooltipContent>
            </Tooltip>
            <Tooltip>
              <TooltipTrigger asChild>
                <button className="relative grid size-9 place-items-center rounded-full text-[var(--g-ink-2)] hover:bg-white/5" aria-label="Alerts">
                  <Bell className="size-[18px]" />
                  {data?.uc1.totals.alerts ? (
                    <span className="absolute right-1 top-1 size-2 rounded-full bg-[var(--g-ember-hi)] shadow-[0_0_10px_var(--g-ember-hi)]" />
                  ) : null}
                </button>
              </TooltipTrigger>
              <TooltipContent className={glassTip}>{data?.uc1.totals.alerts ?? 0} alerts raised by the Threat Intel Agent (lab tests included)</TooltipContent>
            </Tooltip>
          </div>

          {/* Section tabs */}
          <div className="mt-3 flex items-center gap-2 overflow-x-auto pb-1">
            <div className="glass-panel flex shrink-0 gap-1 rounded-full p-1">
              {SECTIONS.map((s) => {
                const active = onHome && (s.tab ? section === s.label && workTab === s.tab : section === s.label)
                return (
                  <button
                    key={s.label}
                    disabled={!onHome}
                    data-active={active}
                    onClick={() => go(s)}
                    className={cn('glass-seg rounded-full px-4 py-1.5 text-sm text-[var(--g-ink-3)] hover:text-[var(--g-ink)] disabled:opacity-40')}
                  >
                    {s.label}
                  </button>
                )
              })}
            </div>
            <div className="flex-1" />
            <Tooltip>
              <TooltipTrigger asChild>
                <button
                  className="glass-panel grid size-9 shrink-0 place-items-center rounded-full text-[var(--g-ink-2)]"
                  aria-label="Copy link to this page"
                  onClick={() => navigator.clipboard?.writeText(window.location.href)}
                >
                  <Link2 className="size-4" />
                </button>
              </TooltipTrigger>
              <TooltipContent className={glassTip}>Copy link</TooltipContent>
            </Tooltip>
          </div>
        </header>

        <div className="flex flex-1 gap-3 px-3 pb-4 pt-1 md:px-4">
          {/* Icon rail */}
          <nav className="glass-panel sticky top-[132px] hidden h-[calc(100svh-148px)] w-16 shrink-0 flex-col items-center gap-1.5 rounded-2xl py-4 md:flex">
            {RAIL.map(({ to, label, icon: Icon, end }) => (
              <Tooltip key={to}>
                <TooltipTrigger asChild>
                  <NavLink
                    to={to}
                    end={end}
                    aria-label={label}
                    className={cn(
                      'grid size-10 place-items-center rounded-xl text-[var(--g-ink-3)] transition-colors hover:bg-white/5 hover:text-[var(--g-ink)]',
                      (end ? pathname.replace(/\/$/, '') === to : pathname.startsWith(to)) && 'glass-ember text-[#1b0d06] hover:text-[#1b0d06]',
                    )}
                  >
                    <Icon className="size-[18px]" />
                  </NavLink>
                </TooltipTrigger>
                <TooltipContent side="right" className={glassTip}>{label}</TooltipContent>
              </Tooltip>
            ))}
            <div className="flex-1" />
            <button
              onClick={() => setPanelOpen((v) => !v)}
              className="grid size-10 place-items-center rounded-xl text-[var(--g-ink-3)] hover:bg-white/5"
              aria-label={panelOpen ? 'Hide side panel' : 'Show side panel'}
            >
              {panelOpen ? <PanelLeftClose className="size-[18px]" /> : <PanelLeftOpen className="size-[18px]" />}
            </button>
          </nav>

          {/* Side panel */}
          {panelOpen && (
            <aside className="glass-panel sticky top-[132px] hidden h-[calc(100svh-148px)] w-60 shrink-0 flex-col rounded-2xl lg:flex">
              <div className="px-5 pt-5">
                <h2 className="text-lg font-semibold tracking-tight">Overview</h2>
                <div className="mt-4 flex rounded-full border border-[var(--g-line)] p-1 text-sm">
                  {(['menu', 'filters'] as const).map((t) => (
                    <button
                      key={t}
                      onClick={() => setPanelTab(t)}
                      data-active={panelTab === t}
                      className="glass-seg flex-1 rounded-full py-1.5 capitalize text-[var(--g-ink-3)]"
                    >
                      {t}
                      {t === 'filters' && opco !== 'all' ? <span className="ml-1.5 inline-block size-1.5 rounded-full bg-[var(--g-ember-hi)] align-middle" /> : null}
                    </button>
                  ))}
                </div>
              </div>

              {panelTab === 'menu' ? (
                <div className="flex flex-col gap-0.5 px-3 py-4">
                  {MENU.map(({ to, label, tag, tone, icon: Icon, end }) => (
                    <NavLink
                      key={to}
                      to={to}
                      end={end}
                      className={({ isActive }) =>
                        cn(
                          'flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm text-[var(--g-ink-2)] hover:bg-white/5 hover:text-[var(--g-ink)]',
                          isActive && 'bg-white/[0.07] font-medium text-[var(--g-ink)] shadow-[inset_0_0_0_1px_var(--g-line)]',
                        )
                      }
                    >
                      <Icon className="size-4" />
                      <span className="flex-1">{label}</span>
                      {tag && (
                        <span className="flex items-center gap-1 text-[10px] font-medium text-[var(--g-ink-3)]">
                          <span className="size-1.5 rounded-full" style={{ background: tone, boxShadow: `0 0 8px ${tone}` }} />
                          {tag}
                        </span>
                      )}
                    </NavLink>
                  ))}
                </div>
              ) : (
                <div className="flex flex-col gap-4 px-5 py-5 text-sm">
                  <fieldset>
                    <legend className="mb-2 text-xs font-medium text-[var(--g-ink-3)]">VM</legend>
                    <div className="flex flex-col gap-1">
                      {['all', ...opcos].map((o) => (
                        <label key={o} className="flex cursor-pointer items-center gap-2.5 rounded-lg px-2 py-1.5 hover:bg-white/5">
                          <input type="radio" name="g-opco" className="size-4 accent-[var(--g-ember)]" checked={opco === o} onChange={() => setOpco(o)} />
                          {o === 'all' ? 'All VMs' : o}
                        </label>
                      ))}
                    </div>
                  </fieldset>
                  <p className="text-xs leading-relaxed text-[var(--g-ink-3)]">
                    Filters the vulnerability numbers, charts and tables. Threat-feed numbers  are company-wide.
                  </p>
                </div>
              )}

              <div className="flex-1" />
              <div className="flex items-center gap-5 border-t border-[var(--g-line)] px-5 py-4 text-sm">
                {([['glass', 'Glass'], ['classic', 'Classic']] as const).map(([id, label]) => (
                  <label key={id} className="flex cursor-pointer items-center gap-2">
                    <input
                      type="radio"
                      name="g-design"
                      className="size-4 accent-[var(--g-ember)]"
                      checked={id === 'glass'}
                      onChange={() => id === 'classic' && navigate('/')}
                    />
                    <span className={id === 'glass' ? 'font-medium' : 'text-[var(--g-ink-3)]'}>{label}</span>
                  </label>
                ))}
              </div>
            </aside>
          )}

          <main className="min-w-0 flex-1">
            <div id="top" className="mx-auto max-w-[1400px] scroll-mt-40">
              <Outlet />
            </div>
          </main>
        </div>
      </div>
    </div>
  )
}
