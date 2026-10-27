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
  if (pathname.startsWith('/uc1/hunts')) return 'hunts'
  if (pathname.startsWith('/uc1/threat/')) return 'threat'
  if (pathname.startsWith('/uc1')) return 'threats'
  if (pathname.startsWith('/uc3/quality')) return 'quality'
  if (pathname.startsWith('/uc3')) return 'weak'
  if (pathname.startsWith('/fixes/progress')) return 'progress'
  if (pathname.startsWith('/fixes')) return 'fixes'
  if (/^\/respond\/.+/.test(pathname)) return 'case'
  if (pathname.startsWith('/respond')) return 'respond'
  if (pathname.startsWith('/reports')) return 'reports'
  if (pathname.startsWith('/runs')) return 'runs'
  return 'home'
}

export const SCREENS: Record<ScreenKey, Screen> = {
  home: {
    name: 'Summary',
    placeholder: 'For example: which computer is most at risk?',
    questions: ['How many vulnerabilities do we have right now?', 'How many vulnerabilities are attackers known to use?'],
  },
  threats: {
    name: 'Threats',
    placeholder: 'For example: are all news sources working?',
    questions: ['How many threats affect us?', 'What is the most dangerous threat right now?'],
  },
  threat: {
    name: 'Threat detail',
    placeholder: 'For example: what exactly should I do?',
    questions: ['Which of our computers have this?', 'Are attackers using it right now?'],
  },
  hunts: {
    name: 'Attack detection',
    placeholder: 'For example: when did we last check?',
    questions: ['Did we find any signs of an attacker?', 'Which computer had signs of attack?'],
  },
  weak: {
    name: 'Vulnerabilities',
    placeholder: 'For example: how many did we fix since last time?',
    questions: ['How many vulnerabilities do we have?', 'Which VM has the most?'],
  },
  quality: {
    name: 'Data quality',
    placeholder: 'For example: does our count match Defender’s?',
    questions: ['Can I trust today’s numbers?', 'When was the data last refreshed?'],
  },
  fixes: {
    name: 'Fix',
    placeholder: 'For example: which fix is due soonest?',
    questions: ['How many apps need updating?', 'Which app should I update first?'],
  },
  progress: {
    name: 'Fix progress',
    placeholder: 'For example: which computer has the most fixes waiting?',
    questions: ['How many fixes are done?', 'Did any fix fail?'],
  },
  respond: {
    name: 'Alert triage',
    placeholder: 'For example: how many are waiting for my review?',
    questions: ['How many incidents are there, and where did they come from?', 'How many are real attacks (true positives)?'],
  },
  case: {
    name: 'Incident',
    placeholder: 'For example: how sure is the assistant?',
    questions: ['What happened, in one line?', 'Which computer and account were involved?'],
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
