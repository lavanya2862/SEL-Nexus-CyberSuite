// The chat's two ready questions per screen. The answers are filled in from today's data by the portal
// (GET /api/help/ready, src/portal/helpready.py: no AI, instant). These labels show while that loads, so keep them in
// step with helpready.py. Free questions go to /api/help/ask (src/portal/helpbot.py).

export type ScreenKey =
  | 'home' | 'threats' | 'threat' | 'hunts' | 'weak' | 'quality' | 'fixes' | 'progress' | 'respond' | 'case' | 'reports' | 'runs'

export interface Screen {
  name: string
  questions: [string, string]
  placeholder: string
}

/** Which screen an address belongs to (the most specific rule first). */
export function screenFor(pathname: string): ScreenKey {
  if (pathname.startsWith('/attack-detection')) return 'hunts'
  if (pathname.startsWith('/threat-intel/threat/')) return 'threat'
  if (pathname.startsWith('/threat-intel')) return 'threats'
  if (pathname.startsWith('/vulnerabilities/quality')) return 'quality'
  if (pathname.startsWith('/vulnerabilities')) return 'weak'
  if (pathname.startsWith('/fixes/progress')) return 'progress'
  if (pathname.startsWith('/fixes')) return 'fixes'
  if (/^\/respond\/.+/.test(pathname)) return 'case'
  if (pathname.startsWith('/alert-triage')) return 'respond'
  if (pathname.startsWith('/reports')) return 'reports'
  if (pathname.startsWith('/runs')) return 'runs'
  return 'home'
}

export const SCREENS: Record<ScreenKey, Screen> = {
  home: {
    name: 'Summary',
    placeholder: 'For example: which app has the most vulnerabilities?',
    questions: ['How many vulnerabilities do we have right now?', 'Which device is most at risk?'],
  },
  threats: {
    name: 'Threats',
    placeholder: 'For example: are all news sources working?',
    questions: ['How many threats apply to our devices?', 'What is the most serious threat right now?'],
  },
  threat: {
    name: 'Threat detail',
    placeholder: 'For example: what exactly should I do?',
    questions: ['Which of our devices have this?', 'How serious is it?'],
  },
  hunts: {
    name: 'Attack detection',
    placeholder: 'For example: when did we last check?',
    questions: ['Did we find any signs of an attacker?', 'Which device had hunt matches?'],
  },
  weak: {
    name: 'Vulnerabilities',
    placeholder: 'For example: how many were remediated since last time?',
    questions: ['How many vulnerabilities do we have?', 'Which VM has the most?'],
  },
  quality: {
    name: 'Data quality',
    placeholder: 'For example: does our count match Defender’s?',
    questions: ['Can I trust today’s numbers?', 'When was the data last refreshed?'],
  },
  fixes: {
    name: 'Remediation',
    placeholder: 'For example: which remediation is due soonest?',
    questions: ['How many apps need updating?', 'Which app should I update first?'],
  },
  progress: {
    name: 'Remediation progress',
    placeholder: 'For example: which device has the most pending remediations?',
    questions: ['How many remediations are complete?', 'Did any remediation fail?'],
  },
  respond: {
    name: 'Alert triage',
    placeholder: 'For example: how many are waiting for my review?',
    questions: ['How many incidents are there, and where did they come from?', 'How many are real attacks (true positives)?'],
  },
  case: {
    name: 'Incident',
    placeholder: 'For example: how confident is the Alert Triage Agent?',
    questions: ['What happened, in one line?', 'Which device and account were involved?'],
  },
  reports: {
    name: 'Reports',
    placeholder: 'For example: which report should I send my manager?',
    questions: ['What is the newest report?', 'Where is the full vulnerability list?'],
  },
  runs: {
    name: 'Agents',
    placeholder: 'For example: how long does a run take?',
    questions: ['When did each agent last run?', 'Did the last runs work?'],
  },
}
