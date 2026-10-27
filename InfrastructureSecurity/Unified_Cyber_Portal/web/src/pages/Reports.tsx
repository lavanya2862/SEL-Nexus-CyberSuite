import { useQuery } from '@tanstack/react-query'
import { Download, FileSpreadsheet, FileText, FileType } from 'lucide-react'
import { Empty, Panel } from '@/components/kit'
import { ago } from '@/lib/format'

interface ReportFile { name: string; size: number; modified: string | null }

async function fetchReports(): Promise<{ uc1: ReportFile[]; uc3: ReportFile[]; uc4?: ReportFile[] }> {
  const res = await fetch('/api/reports')
  if (!res.ok) throw new Error(`Portal API answered ${res.status}`)
  return res.json()
}

const KIND: Record<string, { icon: typeof FileText; label: string }> = {
  xlsx: { icon: FileSpreadsheet, label: 'Excel' },
  docx: { icon: FileText, label: 'Word' },
  pdf: { icon: FileType, label: 'PDF' },
  md: { icon: FileText, label: 'Text' },
}

const size = (b: number) => (b > 1e6 ? `${(b / 1e6).toFixed(1)} MB` : `${Math.max(1, Math.round(b / 1e3))} KB`)

function describe(name: string) {
  if (name.startsWith('Vulnerability_Report') && name.endsWith('.xlsx')) return 'Every vulnerability with its fix, AI fix plan, charts'
  if (name.startsWith('Vulnerability_Report')) return 'Vulnerability report: summary, charts, what to fix first, AI fix guides'
  if (name.startsWith('UC3_Before_After')) return 'Before / after: time saved by the agent'
  if (name.startsWith('Threat_Intel_Report')) return 'New threats from this run, what affects us, AI fix steps'
  if (name.startsWith('Attack_Detection_Report')) return 'Signs of attack, evidence and AI steps to resolve them'
  if (name.startsWith('Alert_Triage_Report')) return 'Incidents triaged in this run, verdicts, evidence and actions'
  if (name.startsWith('UC1_AI_Spotcheck')) return 'Sheet to check the AI’s answers by hand'
  return 'Report file'
}

export function Reports() {
  const { data, error } = useQuery({ queryKey: ['reports'], queryFn: fetchReports, refetchInterval: 60_000 })
  return (
    <div className="flex flex-col gap-5">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Reports</h1>
        <p className="mt-1 text-sm text-ink-3">Word, PDF and Excel files the agents produce. Newest first.</p>
      </div>
      {error && <Empty text={String((error as Error).message)} />}
      {data && (
        <div className="grid grid-cols-1 gap-5 xl:grid-cols-2">
          <Section uc="uc3" title="Vulnerability Agent" files={data.uc3} />
          <Section uc="uc1" title="Threat Intel Agent" files={data.uc1.filter((f) => !f.name.startsWith('Attack_Detection'))} />
          <Section uc="uc1" title="Attack Detection Agent" files={data.uc1.filter((f) => f.name.startsWith('Attack_Detection'))} />
          <Section uc="uc4" title="Alert Triage Agent" files={data.uc4 ?? []} />
        </div>
      )}
    </div>
  )
}

function Section({ uc, title, files }: { uc: 'uc1' | 'uc3' | 'uc4'; title: string; files: ReportFile[] }) {
  return (
    <Panel className="p-6">
      <div className="flex items-center gap-2 text-xs font-medium text-ink-3">
        <span className={uc === 'uc1' ? 'size-2 rounded-full bg-violet' : uc === 'uc4' ? 'size-2 rounded-full bg-rose' : 'size-2 rounded-full bg-sky'} /> Reports
      </div>
      <h2 className="mt-1 font-semibold tracking-tight">{title}</h2>
      {files.length ? (
        <ul className="mt-4 flex flex-col divide-y divide-hairline">
          {files.map((f) => {
            const ext = f.name.split('.').pop()?.toLowerCase() ?? ''
            const k = KIND[ext] ?? KIND.md
            return (
              <li key={f.name} className="flex items-center gap-3 py-3">
                <span className="grid size-10 shrink-0 place-items-center rounded-xl bg-well"><k.icon className="size-[18px] text-ink-2" /></span>
                <div className="min-w-0 flex-1">
                  <div className="truncate text-sm font-medium" title={f.name}>{f.name}</div>
                  <div className="truncate text-xs text-ink-3">{describe(f.name)} · {k.label} · {size(f.size)} · {ago(f.modified)}</div>
                </div>
                <a href={`/api/files/${uc}/${encodeURIComponent(f.name)}`} className="flex shrink-0 items-center gap-1.5 rounded-lg border border-hairline px-3 py-1.5 text-xs font-medium hover:bg-well">
                  <Download className="size-3.5" /> Download
                </a>
              </li>
            )
          })}
        </ul>
      ) : <div className="mt-4"><Empty text="No files yet." /></div>}
    </Panel>
  )
}
