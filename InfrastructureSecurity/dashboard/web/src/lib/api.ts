// Types for the portal API (/api/summary). Mirrors src/portal/summary.py.

export type HealthStatus = 'ok' | 'stale' | 'error' | 'missing'

export interface Health {
  key: 'threat_intel' | 'vulnerability' | 'alert_triage'
  name: string
  status: HealthStatus
  message: string
  last_run_at: string | null
  data_as_of: string | null
  age_hours: number | null
  quality?: string | null
  coverage?: number | null
  rows?: number | null
  defender_count?: number | null
  vulnerabilities?: number | null

  run_id?: string | null
  model?: string | null
}

export interface Device {
  name: string
  opco: string | null
  findings?: number
  critical?: number
  p1?: number
  last_seen?: string
  threats_exposed?: number
  hunt_hits?: number
  test_hits?: number
}

export interface Fix {
  rank: number
  app: string
  installed_versions: string | null   // null for a security setting
  urgency: string
  urgency_level: number
  fix_by: string | null
  cves: number
  p1: number
  devices: number
  opcos: string
  fix_action: string
  command: string | null
  why_now: string | null
  source: string | null
}

export interface Threat {
  id: string
  title: string
  source: string
  kind: string
  rating: string
  score: number
  why: string
  chips: string[]
  action: string | null
  summary: string | null
  devices: string | null
  url: string | null
  published: string | null
}

export interface Summary {
  generated_at: string
  stale_hours: number
  reports: { threat_intel: number; vulnerability: number }
  health: Health[]
  devices: Device[]
  threat_intel: {
    posture: { rating?: string; urgent?: number; affecting?: number }
    totals: {
      new_threats: number | null
      pct_assessed: number | null
      affecting: number | null
      urgent: number | null
      hunts_per_run: number | null
      hunts_ok: number
      hunts_total: number
      real_hits: number
      test_hits: number
      alerts: number
      median_minutes_to_assess: number | null
      manual_hours_saved: number | null
    }
    funnel: { stage: string; value: number; note: string }[]
    threat_trend: { days: string[]; series: Record<string, number[]> }
    top_threats: Threat[]
    feeds: { ok: number; total: number; failing: string[] }
  }
  vulnerability: {
    totals: {
      total?: number
      p1?: number
      critical?: number
      exploitable?: number
      sla_breaches?: number
      cves?: number
      devices: number
      remediated: number
      fixed_since?: string | null
      changes: Record<string, number>
    }
    trend: { date: string; total: number; p1: number; exploitable: number }[]
    trend_opco: { date: string; opco: string; total: number }[]
    opco_totals: { opco: string; findings: number; p1: number; critical: number; devices: number
                   fixed?: number; fixed_since?: string | null }[]
    apps: { software_name: string; app: string; opco: string; findings: number; p1: number }[]
    quality: { check_name: string; status: string; message: string }[]
    priority: { priority: string; count: number }[]
    opco: { opco: string; severity: string; count: number }[]
    fixes: Fix[]
    ai_fixes: { snapshot?: string; built_at?: string; ai_enabled?: boolean; model?: string } | null
  }
  alert_triage: {
    totals: { incidents: number; escalate: number; closed: number; awaiting_review: number; lab: number; by_verdict: Record<string, number> }
    latest: { incident_id: string; title: string; verdict: string; confidence: string; escalate: boolean; is_lab: boolean; triaged_at: string | null; devices: string[] }[]
  }
}

export async function fetchSummary(): Promise<Summary> {
  const res = await fetch('/api/summary')
  if (!res.ok) throw new Error(`CyberSuite could not complete the request (error ${res.status})`)
  return res.json()
}
