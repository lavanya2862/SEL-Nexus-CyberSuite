// First thing after signing in: a person who has not added their own GitHub token or AI model key is asked to, before
// anything else (the welcome tour waits). "Later" hides it until they next open the site.
import { useState } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { Bot, GitPullRequestArrow, KeyRound } from 'lucide-react'
import { Btn } from '@/components/kit'
import { Dialog, DialogContent, DialogDescription, DialogTitle } from '@/components/ui/dialog'
import { useSettings } from '@/lib/api'
import { useAuth } from '@/lib/auth'

const LATER = 'appvuln-keys-later:'

/** show: the popup is open. pending: keys still missing and not put off (the welcome tour waits for this). */
export interface KeysPromptState { show: boolean; pending: boolean; missing: { github: boolean; ai: boolean }; later: () => void }

export function useKeysPrompt(): KeysPromptState {
  const { user } = useAuth()
  const settings = useSettings()
  const { pathname } = useLocation()
  const key = LATER + (user?.email ?? '')
  const [later, setLater] = useState<string | null>(() => {
    try {
      return sessionStorage.getItem(key) === '1' ? key : null
    } catch {
      return null
    }
  })
  const v = settings.data
  const missing = { github: !v?.settings.github_token?.configured, ai: !v?.settings.llm_api_key?.configured }
  // Only with the shared sign-in (everyone has their own keys), and never on the Settings page itself
  const pending = !!v?.per_user && (missing.github || missing.ai) && later !== key
  return {
    show: pending && pathname !== '/settings',
    pending,
    missing,
    later: () => {
      try {
        sessionStorage.setItem(key, '1')
      } catch {
        /* the prompt comes back on the next page load; harmless */
      }
      setLater(key)
    },
  }
}

export function KeysPrompt({ prompt }: { prompt: KeysPromptState }) {
  const navigate = useNavigate()
  const { user } = useAuth()
  const { show, missing, later } = prompt
  const items = [
    missing.github && { icon: GitPullRequestArrow, title: 'Your GitHub personal access token', text: 'Reads your private repositories, pushes the fix branch and opens pull requests in your name.' },
    missing.ai && { icon: Bot, title: 'Your AI model API key', text: 'Lets the Remediation Agent write code fixes and the Security Assistant answer questions.' },
  ].filter(Boolean) as { icon: typeof Bot; title: string; text: string }[]
  return (
    <Dialog open={show} onOpenChange={(o) => { if (!o) later() }}>
      <DialogContent className="max-w-md border-hairline bg-panel p-0">
        <div className="p-6">
          <span className="grid size-10 place-items-center rounded-xl bg-blue/15 text-sky"><KeyRound className="size-5" /></span>
          <DialogTitle className="mt-3 text-xl tracking-tight">First, connect your own keys</DialogTitle>
          <DialogDescription className="mt-2 text-sm leading-relaxed text-ink-2">
            Welcome{user?.name ? `, ${user.name}` : ''}. Scans you start work with your own keys, which only you can use. Add {items.length > 1 ? 'these' : 'this'} in Settings:
          </DialogDescription>
          <ul className="mt-4 flex flex-col gap-2">
            {items.map((i) => (
              <li key={i.title} className="flex items-start gap-3 rounded-xl border border-hairline bg-well/40 p-3">
                <i.icon className="mt-0.5 size-4 shrink-0 text-sky" />
                <div><div className="text-sm font-medium">{i.title}</div><div className="text-xs leading-relaxed text-ink-3">{i.text}</div></div>
              </li>
            ))}
          </ul>
          <p className="mt-3 text-xs text-ink-3">Until then you can still look at every scan and download its reports.</p>
        </div>
        <div className="flex justify-end gap-2 border-t border-hairline px-6 py-4">
          <Btn kind="quiet" onClick={later}>Later</Btn>
          <Btn onClick={() => navigate('/settings')}><KeyRound className="size-4" /> Go to Settings</Btn>
        </div>
      </DialogContent>
    </Dialog>
  )
}
