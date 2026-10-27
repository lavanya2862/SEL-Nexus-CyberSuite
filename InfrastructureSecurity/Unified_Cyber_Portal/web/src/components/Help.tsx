import { useEffect, useState } from 'react'
import { ArrowLeft, ArrowRight, BookOpen, Database, LayoutGrid, Play, ScanSearch, Wrench } from 'lucide-react'
import { Dialog, DialogContent, DialogDescription, DialogTitle } from '@/components/ui/dialog'
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from '@/components/ui/sheet'
import { cn } from '@/lib/utils'

const TERMS: [string, string][] = [
  ['Vulnerability', 'A known weak spot in a piece of software that an attacker could use. Fixed by updating or removing the app.'],
  ['CVE', 'The official ID of one vulnerability, for example CVE-2025-8088. One old app can have hundreds.'],
  ['Known exploited (KEV)', 'On the US government (CISA) list of vulnerabilities that attackers have really used against organisations. It does not mean they were used against us. Always fix these first.'],
  ['Used by ransomware', 'A vulnerability that criminal gangs use to lock up computers and demand money.'],
  ['Priority 1 (P1)', 'Our most urgent findings: critical severity, or a vulnerability attackers can already use.'],
  ['Severity', 'How bad a vulnerability is if someone uses it: Critical, High, Medium or Low.'],
  ['VM', 'Virtual machine: one of our computers (VM 1, VM 2). Use Filters to look at just one of them.'],
  ['Microsoft Defender', 'The security tool on our computers. It finds the vulnerabilities and records activity we can hunt through.'],
  ['Threat intelligence', 'News about attacks from public security sources (CISA, NVD, NCSC-NL, CERT-EU, abuse.ch). The assistant reads it for us.'],
  ['Attack hunting', 'Searching Defender records for signs that an attacker is already on one of our computers.'],
  ['Agent', 'An automatic helper that does one job end to end. Threat Intel Agent: reads attack news and hunts for attackers. Vulnerability Agent: collects every vulnerability from Defender. Alert Triage Agent: judges Defender’s and Sentinel’s alarms. Run them from Agents in the menu.'],
  ['Data quality check', 'An automatic test that the data is complete and fresh, for example that our row count matches Defender’s.'],
  ['Alert / incident', 'An alarm Microsoft Defender raises when it sees something suspicious. Related alarms are grouped into one incident.'],
  ['Triage', 'Deciding quickly what an alarm is: true positive, false positive, or needs review. The assistant prepares this for you.'],
  ['True / false positive, needs review', 'True positive: a real attack, escalated. False positive: nothing to worry about (the alarm was wrong, or the activity was harmless, like our own antivirus test file EICAR), closed. Needs review: the AI could not decide, so an analyst does.'],
  ['Fix command', 'A ready-made winget line that updates the app. Shown so you can copy it; never run by this portal.'],
]

export function Glossary({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="w-full overflow-y-auto border-hairline bg-panel sm:max-w-[440px]">
        <SheetHeader>
          <SheetTitle className="flex items-center gap-2 text-lg"><BookOpen className="size-5" /> What does this mean?</SheetTitle>
          <SheetDescription>The words used on this portal, in plain English.</SheetDescription>
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
  { icon: LayoutGrid, title: 'Dashboard: everything at a glance', text: 'Three headline numbers, the fixes that matter most, and which apps cause the most risk. Use Filters to look at one VM.' },
  { icon: ScanSearch, title: 'Vulnerabilities, Threats and Attack hunting', text: 'The vulnerabilities Defender found, threat news that affects us, and whether attackers are already inside.' },
  { icon: Wrench, title: 'Fix and Alert triage', text: 'Fix: the apps and Windows updates to install, unsupported software to upgrade and security settings to change, most dangerous first. Press ⚡ Fix it for me and the portal does it for you. Triage: every Defender alarm with the AI’s checked verdict; you agree or disagree.' },
  { icon: Database, title: 'Data quality and Reports', text: 'Vulnerabilities › Data quality checks that every number is complete and fresh. Reports gives Word, PDF and Excel downloads.' },
  { icon: Play, title: 'Agents', text: 'Open Agents in the menu (or press Run agents at the top) to fetch new data, see how fresh each agent’s data is, and watch every step finish, live.' },
]

const TOUR_KEY = 'portal-tour-done'

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
          <div className="grid size-11 place-items-center rounded-xl bg-well"><step.icon className="size-5" /></div>
          <DialogTitle className="mt-5 text-xl tracking-tight">{step.title}</DialogTitle>
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
              className="inline-flex items-center gap-1 rounded-lg btn-blue px-4 py-2 text-sm font-medium text-white"
            >
              {i < TOUR.length - 1 ? <>Next <ArrowRight className="size-4" /></> : 'Start using the portal'}
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
