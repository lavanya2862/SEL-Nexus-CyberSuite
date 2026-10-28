// Talking to the Application Security API (remediation/api.py). One fetch helper, plus a React Query hook per
// endpoint so every page shares the same cache and refresh timing.
import { useQuery } from '@tanstack/react-query'
import type {
  ActivityEntry, AgentHistory, AgentId, AgentView, Attention, Capabilities, Dashboard, Finding, Job, JobStatus, Report,
  Repository, SettingsView, Story,
} from '@/lib/types'

const KEY_STORE = 'appvuln-api-key' // only needed when the server sets API_KEYS

export function getClientKey(): string {
  try {
    return localStorage.getItem(KEY_STORE) ?? ''
  } catch {
    return ''
  }
}

export function setClientKey(key: string) {
  try {
    localStorage.setItem(KEY_STORE, key)
  } catch {
    /* not essential */
  }
}

export class ApiError extends Error {
  status: number
  constructor(message: string, status: number) {
    super(message)
    this.status = status
  }
}

export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json', ...(init.headers as Record<string, string> | undefined) }
  const key = getClientKey()
  if (key) headers['X-API-Key'] = key
  let res: Response
  try {
    res = await fetch(path, { ...init, headers })
  } catch {
    throw new ApiError('Can’t reach the Application Security server. Start it with Start_Application_Security.cmd.', 0)
  }
  if (!res.ok) {
    let detail: unknown = res.statusText
    try {
      detail = (await res.json()).detail
    } catch {
      /* not JSON */
    }
    throw new ApiError(typeof detail === 'string' ? detail : JSON.stringify(detail), res.status)
  }
  const type = res.headers.get('content-type') ?? ''
  return (type.includes('json') ? res.json() : res.text()) as Promise<T>
}

export const post = <T>(path: string, body?: unknown) => api<T>(path, { method: 'POST', body: body === undefined ? undefined : JSON.stringify(body) })
export const put = <T>(path: string, body: unknown) => api<T>(path, { method: 'PUT', body: JSON.stringify(body) })

/** Address of a downloadable file a run produced (report, SARIF, patch). */
export const artifactUrl = (jobId: string, name: string, download = true) =>
  `/api/v1/jobs/${encodeURIComponent(jobId)}/artifacts/${name}${download ? '?download=true' : ''}`

/** What a run hands over to people: PDFs. [file, short name, what it holds] */
export const PDF_FILES: [string, string, string][] = [
  ['report.pdf', 'Report', 'The full report: summary, pipeline, fixes, checks and findings'],
  ['findings.pdf', 'Findings', 'Every finding with its code, description and references'],
  ['fixes.pdf', 'Fixes', 'Every fix with its explanation, checks and code changes'],
]

/** What a run hands over to tools, in the formats those tools read. */
export const TOOL_FILES: [string, string, string][] = [
  ['findings.sarif', 'SARIF', 'For GitHub code scanning'],
  ['fixes.patch', 'Patch', 'All changes; apply with git apply'],
]

export const isLive = (j?: Pick<Job, 'status'> | null) => !!j && (j.status === 'running' || j.status === 'queued')

/** The Test & Fix loop is pushing, waiting for GitHub Actions or asking the Remediation Agent for a fix. */
export const testsActive = (j?: Pick<Job, 'summary'> | null) => ['starting', 'running'].includes(j?.summary?.tests?.status ?? '')

/* ───────── hooks ───────── */

export const useCaps = () =>
  useQuery({ queryKey: ['caps'], queryFn: () => api<Capabilities>('/api/v1/capabilities'), refetchInterval: 30_000 })

export const useAttention = () =>
  useQuery({ queryKey: ['attention'], queryFn: () => api<Attention>('/api/v1/attention'), refetchInterval: 12_000 })

export const useDashboard = () =>
  useQuery({ queryKey: ['dashboard'], queryFn: () => api<Dashboard>('/api/v1/dashboard'), refetchInterval: 15_000 })

export function useJobs(params: { status?: JobStatus | ''; repo?: string; limit?: number } = {}, refetch = 5_000) {
  const q = new URLSearchParams({ limit: String(params.limit ?? 100) })
  if (params.status) q.set('status', params.status)
  if (params.repo) q.set('repo', params.repo)
  return useQuery({
    queryKey: ['jobs', params],
    queryFn: () => api<{ total: number; items: Job[] }>(`/api/v1/jobs?${q}`),
    refetchInterval: refetch,
  })
}

export function useActivity(params: { action?: string; q?: string; limit?: number } = {}) {
  const q = new URLSearchParams({ limit: String(params.limit ?? 200) })
  if (params.action) q.set('action', params.action)
  if (params.q) q.set('q', params.q)
  return useQuery({
    queryKey: ['activity', params],
    queryFn: () => api<{ total: number; items: ActivityEntry[] }>(`/api/v1/activity?${q}`),
    refetchInterval: 10_000,
  })
}

/** One run. Refreshes every 2 s while it is working (or while its PR is being opened), then stops. */
export function useJob(id: string | undefined) {
  return useQuery({
    queryKey: ['job', id],
    queryFn: () => api<Job>(`/api/v1/jobs/${id}`),
    enabled: !!id,
    refetchInterval: (q) => {
      const j = q.state.data
      return isLive(j) || j?.summary?.approval_status === 'publishing' || testsActive(j) ? 2_000 : false
    },
  })
}

export function useJobAgents(id: string | undefined, live: boolean) {
  return useQuery({
    queryKey: ['job', id, 'agents'],
    queryFn: () => api<{ story: Story; agents: Record<AgentId, AgentView> }>(`/api/v1/jobs/${id}/agents`),
    enabled: !!id,
    refetchInterval: live ? 2_500 : false,
  })
}

export function useJobEvents(id: string | undefined, live: boolean) {
  return useQuery({
    queryKey: ['job', id, 'events'],
    queryFn: () => api<{ items: { id: number; ts: string; level: string; message: string }[] }>(`/api/v1/jobs/${id}/events?limit=2000`),
    enabled: !!id,
    refetchInterval: live ? 2_000 : false,
  })
}

/** The report and findings exist only once a run has completed. */
export function useJobResults(id: string | undefined, completed: boolean, prState?: string) {
  const report = useQuery({
    queryKey: ['job', id, 'report', prState],
    queryFn: () => api<Report>(`/api/v1/jobs/${id}/report`),
    enabled: !!id && completed,
  })
  const findings = useQuery({
    queryKey: ['job', id, 'findings'],
    queryFn: async () => (await api<{ items: Finding[] }>(`/api/v1/jobs/${id}/findings`)).items,
    enabled: !!id && completed,
  })
  return { report, findings }
}

export const useVulnerabilities = () =>
  useQuery({ queryKey: ['vulnerabilities'], queryFn: () => api<{ count: number; items: Finding[] }>('/api/v1/vulnerabilities'), refetchInterval: 30_000 })

export const useRepositories = () =>
  useQuery({ queryKey: ['repositories'], queryFn: () => api<{ items: Repository[] }>('/api/v1/repositories'), refetchInterval: 15_000 })

export const useAgentHistory = (id: AgentId) =>
  useQuery({ queryKey: ['agent-history', id], queryFn: () => api<AgentHistory>(`/api/v1/agents/${id}/history?limit=10`), refetchInterval: 20_000 })

export const useSettings = () =>
  useQuery({ queryKey: ['settings'], queryFn: () => api<SettingsView>('/api/v1/settings'), retry: false })
