// Help for first-time visitors: a five-step tour of where everything is (shown once), and a glossary of the words
// this site uses, in plain English. Same pattern as the Infrastructure Security portal.
import { useEffect, useState } from 'react'
import { ArrowLeft, ArrowRight, Bot, BookOpen, CirclePlus, Inbox, LayoutGrid, ListChecks } from 'lucide-react'
import { Dialog, DialogContent, DialogDescription, DialogTitle } from '@/components/ui/dialog'
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from '@/components/ui/sheet'
import { cn } from '@/lib/utils'

const TERMS: [string, string][] = [
  ['Vulnerability (finding)', 'A weak spot in our application code, or in a library it uses, that an attacker could abuse. Each one found is a “finding”.'],
  ['Severity', 'How bad a finding is if someone uses it: Critical, High, Medium or Low.'],
  ['Risk score (0–10)', 'Severity adjusted for how likely and how easy the attack is. The highest risk is fixed first.'],
  ['SAST', 'Static application security testing: reading the source code for dangerous patterns, without running it.'],
  ['CodeQL', 'GitHub’s code scanner. Our main tool for finding vulnerabilities in the code itself.'],
  ['Trivy / OSV', 'Scanners for known vulnerabilities in the libraries (dependencies) the code uses, plus leaked secrets and misconfigurations.'],
  ['CVE / GHSA', 'The official ID of one known vulnerability in a library, for example CVE-2024-1234 (GHSA is GitHub’s equivalent).'],
  ['Dependency upgrade', 'Fixing a vulnerable library by moving it to a version where the hole is closed.'],
  ['Code fix', 'A change to our own code that the Remediation Agent writes (using its AI model) for a finding that needs reasoning; the Validation Agent checks it before it is kept.'],
  ['Branch', 'A separate copy of the code where the fixes are made, so the original code is never touched.'],
  ['Validation', 'Proving the fixes work: the code still parses, no security controls were removed, tests still pass, and a fresh scan no longer reports the issue.'],
  ['Needs review', 'One of the validation checks failed. The fixes can still be approved, but the pull request opens as a draft for investigation.'],
  ['Pull request (PR)', 'A request on GitHub to merge the fix branch. A person reviews and merges it.'],
  ['GitHub Actions', 'GitHub’s own machines that run a repository’s tests. Run tests on GitHub pushes the fix branch there; failing tests are fixed by the Remediation Agent and run again, up to 3 times.'],
  ['SARIF', 'A standard file of scan results that GitHub code scanning can import.'],
  ['Patch', 'One file with all the code changes. Apply it yourself with “git apply” if you prefer not to open a pull request.'],
]

export function Glossary({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="w-full overflow-y-auto border-hairline bg-panel sm:max-w-[440px]">
        <SheetHeader>
          <SheetTitle className="flex items-center gap-2 text-lg"><BookOpen className="size-5" /> What does this mean?</SheetTitle>
          <SheetDescription>The words used on this site, in plain English.</SheetDescription>
        </SheetHeader>
        <dl className="flex flex-col gap-4 px-4 pb-6">
          {TERMS.map(([term, text]) => (
            <div key={term} className="rounded-xl border border-hairline p-4">
              <dt className="font-medium">{term}</dt>
              <dd className="mt-1 text-sm leading-relaxed text-ink-2">{text}</dd>
            </div>
          ))}
        </dl>
      </SheetContent>
    </Sheet>
  )
}

const TOUR = [
  { icon: LayoutGrid, title: 'Dashboard: everything at a glance', text: 'How many critical and high findings there are, how many our agents fixed, the top risks still open, and what each of the four agents concluded. Filter it by repository.' },
  { icon: CirclePlus, title: 'New scan: paste a GitHub link', text: 'That is the only input. The four agents then find the vulnerabilities, fix them on a separate branch, prove the fixes work and write the report.' },
  { icon: Inbox, title: 'Action center: what needs you', text: 'Approvals: fix sets waiting for your decision. Fixes needed: issues the agents could not fix, with what to do. Errors: anything that went wrong and how to fix it. The numbers in the menu show how many.' },
  { icon: Bot, title: 'Agents: see each agent work', text: 'One page per agent: what it received, what it produced and what it concluded, for any run, live while it is running.' },
  { icon: ListChecks, title: 'Results and Configure', text: 'Every vulnerability, each repository’s trend, every scan and its downloadable report. Settings connects the AI model and GitHub. The chat button in the corner answers questions about what you are looking at.' },
]

const TOUR_KEY = 'appvuln-tour-done'

export function Tour({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const [i, setI] = useState(0)
  useEffect(() => {
    if (open) setI(0)
  }, [open])
  const close = () => {
    try {
      localStorage.setItem(TOUR_KEY, '1')
    } catch {
      /* not essential */
    }
    onOpenChange(false)
  }
  const step = TOUR[i]
  return (
    <Dialog open={open} onOpenChange={(o) => (o ? onOpenChange(true) : close())}>
      <DialogContent className="max-w-md border-hairline bg-panel p-0">
        <div className="px-7 pb-2 pt-8">
          <div className="tile-signal grid size-11 place-items-center rounded-xl"><step.icon className="size-5" /></div>
          <div className="mt-5 text-[11px] font-semibold uppercase tracking-[0.12em] text-ink-3">Step {i + 1} of {TOUR.length}</div>
          <DialogTitle className="mt-1 text-xl tracking-tight">{step.title}</DialogTitle>
          <DialogDescription className="mt-2 text-sm leading-relaxed text-ink-2">{step.text}</DialogDescription>
        </div>
        <div className="flex items-center justify-between border-t border-hairline px-7 py-4">
          <div className="flex gap-1.5">
            {TOUR.map((_, n) => <span key={n} className={cn('h-1.5 rounded-full transition-all', n === i ? 'w-5 bg-blue' : 'w-1.5 bg-hairline')} />)}
          </div>
          <div className="flex gap-2">
            {i > 0 && (
              <button onClick={() => setI(i - 1)} className="inline-flex items-center gap-1 rounded-lg px-3 py-2 text-sm text-ink-2 hover:bg-well">
                <ArrowLeft className="size-4" /> Back
              </button>
            )}
            <button
              onClick={() => (i < TOUR.length - 1 ? setI(i + 1) : close())}
              className="btn-blue inline-flex items-center gap-1 rounded-lg px-4 py-2 text-sm font-medium text-white"
            >
              {i < TOUR.length - 1 ? <>Next <ArrowRight className="size-4" /></> : 'Start using the site'}
            </button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  )
}

/** True on a first visit (no saved flag, storage readable). `?tour=0` turns it off for screenshots. */
export function shouldShowTour(): boolean {
  if (new URLSearchParams(window.location.search).get('tour') === '0') return false
  try {
    return localStorage.getItem(TOUR_KEY) !== '1'
  } catch {
    return false
  }
}
