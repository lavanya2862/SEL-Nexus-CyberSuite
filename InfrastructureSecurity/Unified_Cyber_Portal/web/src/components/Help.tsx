import { useEffect, useState } from 'react'
import { ArrowLeft, ArrowRight, BookOpen, Database, LayoutGrid, Play, ScanSearch, Wrench } from 'lucide-react'
import { Dialog, DialogContent, DialogDescription, DialogTitle } from '@/components/ui/dialog'
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from '@/components/ui/sheet'
import { cn } from '@/lib/utils'

const TERMS: [string, string][] = [
  ['Vulnerability', 'A known security flaw in software that an attacker could exploit. Remediated by updating or removing the application.'],
  ['CVE', 'The official ID of one vulnerability, for example CVE-2025-8088. A single outdated application can have hundreds.'],
  ['Priority 1 (P1)', 'Highest-priority findings: Critical, or High with a known exploit.'],
  ['Severity', 'The impact of a vulnerability if exploited: Critical, High, Medium or Low.'],
  ['VM', 'Virtual machine: a managed device (VM 1, VM 2). Use Filters to view a single VM.'],
  ['Microsoft Defender', 'The endpoint security platform on managed devices. It reports vulnerabilities and records activity used for threat hunting.'],
  ['Threat intelligence', 'Threat reports from public security sources (CISA, NVD, NCSC-NL, CERT-EU, abuse.ch), analysed by the Threat Intel Agent.'],
  ['Attack detection', 'Proactive hunting in Defender records for evidence of an attacker already present on a managed device.'],
  ['Agent', 'An autonomous component that performs one function end to end. Vulnerability Agent: collects every vulnerability from Defender. Threat Intel Agent: analyses threat intelligence and assesses exposure. Attack Detection Agent: hunts for active compromise. Alert Triage Agent: classifies Defender and Sentinel incidents. Run them from Agents in the menu.'],
  ['Data quality check', 'An automatic test that the data is complete and fresh, for example that the ingested record count matches Defender’s.'],
  ['Alert / incident', 'A notification Microsoft Defender raises on suspicious activity. Related alerts are grouped into one incident.'],
  ['Triage', 'Classifying an incident as true positive, false positive or needs review. The Alert Triage Agent prepares this for analysts.'],
  ['True / false positive, needs review', 'True positive: confirmed malicious activity, escalated. False positive: a false detection or authorised activity, closed. Needs review: the agent could not classify it, so an analyst decides.'],
  ['Remediation command', 'A ready-made winget command that updates the application. It can be copied and run manually, or executed by the portal through automated remediation after approval.'],
]

export function Glossary({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="w-full overflow-y-auto border-hairline bg-panel sm:max-w-[440px]">
        <SheetHeader>
          <SheetTitle className="flex items-center gap-2 text-lg"><BookOpen className="size-5" /> Glossary</SheetTitle>
          <SheetDescription>Definitions of terms used in this portal.</SheetDescription>
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
  { icon: LayoutGrid, title: 'Summary: security posture at a glance', text: 'Headline metrics, priority remediations and the applications contributing most risk. Use Filters to view a single VM.' },
  { icon: ScanSearch, title: 'Vulnerabilities, Threats and Attack detection', text: 'Vulnerabilities reported by Defender, applicable threat intelligence, and hunting for active compromise.' },
  { icon: Wrench, title: 'Remediation and Alert triage', text: 'Remediation: application and Windows updates, unsupported software upgrades and security setting changes, highest risk first. Select ⚡ Remediate to queue automated remediation. Triage: every Defender incident with the agent’s validated verdict for analyst review.' },
  { icon: Database, title: 'Data quality and Reports', text: 'Vulnerabilities › Data quality verifies that every figure is complete and current. Reports provides Word, PDF and Excel downloads.' },
  { icon: Play, title: 'Agents', text: 'Open Agents in the menu (or select Run agents at the top) to refresh data, check each agent’s data freshness, and track every stage in real time.' },
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
              {i < TOUR.length - 1 ? <>Next <ArrowRight className="size-4" /></> : 'Get started'}
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
