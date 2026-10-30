import { useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { GitPullRequestArrow, KeyRound, Loader2 } from 'lucide-react'
import { Btn, Card, Field, Loading, Notice, PageHeader, StatusTag, inputCls } from '@/components/kit'
import { ApiError, api, getClientKey, setClientKey, useSettings } from '@/lib/api'
import { statusColor } from '@/lib/theme'
import { useToast } from '@/lib/toast'
import type { SettingEntry, SettingsView } from '@/lib/types'

// The AI model is the organisation's, set on the server (APPSEC_AZURE_FOUNDRY_* in the suite .env), so the only
// personal credential is the GitHub token.

// Changing settings needs this header, which a form on another website cannot send.
const WRITE = { 'X-CyberSuite': 'settings' }

export function SettingsPage() {
  const s = useSettings()
  if (s.isLoading) return <Loading />
  return (
    <div className="flex flex-col gap-5">
      <PageHeader title="Settings" description={s.data?.per_user
        ? <>Connect your GitHub account so the agents can access your repositories, push remediation branches and raise pull requests for the scans you initiate. Your token is personal and used only for your scans{s.data.user && <> (signed in as <span className="font-mono">{s.data.user}</span>)</>}.</>
        : 'Connect GitHub so the agents can access repositories, push remediation branches and raise pull requests. The token is stored on this server only.'} />
      {s.error ? <KeyOnly error={s.error as ApiError} /> : s.data && <Forms view={s.data} />}
    </div>
  )
}

function Source({ e, own }: { e: SettingEntry; own?: boolean }) {
  return e.source === 'ui' ? <StatusTag tone="info" label={own ? 'Personal' : 'Configured here'} />
    : e.source === 'env' ? <StatusTag tone="idle" label={own ? 'Organisation default' : 'From .env'} />
    : e.source === 'default' ? <StatusTag tone="idle" label="Default" /> : <StatusTag tone="warn" label="Not configured" />
}

function useSave() {
  const qc = useQueryClient()
  const toast = useToast()
  return async (payload: Record<string, unknown>, onError?: (m: string) => void) => {
    try {
      await api('/api/v1/settings', { method: 'PUT', body: JSON.stringify(payload), headers: WRITE })
      toast('Settings saved')
      qc.invalidateQueries({ queryKey: ['settings'] })
      qc.invalidateQueries({ queryKey: ['caps'] })
      qc.invalidateQueries({ queryKey: ['attention'] })
      return true
    } catch (e) {
      if (onError) onError((e as Error).message)
      else toast((e as Error).message, true)
      return false
    }
  }
}

function Msg({ m }: { m: { ok: boolean; text: string } | null | 'busy' }) {
  if (m === 'busy') return <span className="flex items-center gap-1.5 text-xs text-ink-3"><Loader2 className="size-3.5 animate-spin" /> Testing…</span>
  if (!m) return null
  return <span className="text-xs" style={{ color: m.ok ? statusColor.good : statusColor.critical }}>{m.text}</span>
}

function Forms({ view }: { view: SettingsView }) {
  const st = view.settings
  const own = view.per_user
  const save = useSave()
  const [gh, setGh] = useState('')
  const [ghMsg, setGhMsg] = useState<{ ok: boolean; text: string } | null | 'busy'>(null)
  const test = async () => {
    setGhMsg('busy')
    try {
      const r = await api<Record<string, string>>('/api/v1/settings/test-github', { method: 'POST', headers: WRITE })
      setGhMsg({ ok: true, text: `✓ Authenticated with GitHub as ${r.login}` })
    } catch (e) {
      setGhMsg({ ok: false, text: (e as Error).message })
    }
  }

  return (
    <div className="grid grid-cols-1 gap-5 xl:grid-cols-2">
      <Card title={<span className="flex items-center gap-2"><GitPullRequestArrow className="size-4 text-sky" /> GitHub</span>}
        description={own ? 'Your personal access token: required for private repositories, and to push remediation branches and raise pull requests under your identity.' : 'Required for private repositories, and to push remediation branches and raise pull requests.'}
        action={st.github_token.configured ? <StatusTag tone="good" label="Token configured" /> : <StatusTag tone="warn" label="No token" />}>
        <div className="flex flex-col gap-4">
          <Notice tone="info" title="Required token permissions">Use a fine-grained personal access token scoped to the repositories you want remediated, with <b>Contents: read &amp; write</b> and <b>Pull requests: read &amp; write</b>. For CI test validation, also grant <b>Workflows: read &amp; write</b> (to add the test workflow) and <b>Actions: read</b> (to monitor test runs). A classic token requires the <span className="font-mono">repo</span> and <span className="font-mono">workflow</span> scopes.</Notice>
          <Field label={<>Personal access token <Source own={own} e={st.github_token} /></>}>
            <input type="password" autoComplete="off" value={gh} onChange={(e) => setGh(e.target.value)} placeholder={st.github_token.configured ? `${st.github_token.value} (leave blank to keep the current token)` : 'github_pat_…'} className={inputCls} />
          </Field>
          <div className="flex flex-wrap items-center gap-2">
            <Btn disabled={!gh.trim()} onClick={async () => { if (await save({ github_token: gh.trim() }, (m) => setGhMsg({ ok: false, text: m }))) setGh('') }}>Save</Btn>
            <Btn kind="quiet" onClick={test}>Test token</Btn>
            {st.github_token.source === 'ui' && <Btn kind="quiet" onClick={() => save({ github_token: null })}>Remove token</Btn>}
            <Msg m={ghMsg} />
          </div>
        </div>
      </Card>

      <Card title={<span className="flex items-center gap-2"><KeyRound className="size-4 text-sky" /> Credential handling</span>}>
        {own ? (
          <p className="text-sm leading-relaxed text-ink-2">Your token is stored against your account, encrypted at rest on this server, and never displayed in full again. It is used only for scans you initiate: to read your repositories, push remediation branches, raise pull requests and run CI test validation on GitHub. Other users cannot view or use your token, and scanners never receive it.</p>
        ) : (
          <>
            <p className="text-sm leading-relaxed text-ink-2">The token entered here is stored on this server in <span className="font-mono">DATA_DIR/runtime_settings.json</span>, is never displayed in full again, and is removed from the environment of every scanner. Settings can be changed only from this machine unless the server sets <span className="font-mono">API_KEYS</span>.</p>
            <ClientKey />
          </>
        )}
      </Card>
    </div>
  )
}

/** Only needed when the server sets API_KEYS: the key this browser sends with every request. */
function ClientKey({ onSaved }: { onSaved?: () => void }) {
  const [k, setK] = useState(getClientKey)
  const toast = useToast()
  return (
    <div className="mt-4 flex flex-col gap-2">
      <Field label="Client API key (required only when the server sets API_KEYS)"><input type="password" value={k} onChange={(e) => setK(e.target.value)} placeholder="X-API-Key" className={inputCls} /></Field>
      <div><Btn kind="quiet" onClick={() => { setClientKey(k.trim()); toast('Client key saved'); onSaved?.() }}>Save client key</Btn></div>
    </div>
  )
}

function KeyOnly({ error }: { error: ApiError }) {
  const qc = useQueryClient()
  return (
    <Card title="API access">
      <Notice tone="warn" title={error.status === 401 ? 'This server requires an API key' : 'Settings are unavailable'}>{error.message}</Notice>
      <ClientKey onSaved={() => qc.invalidateQueries()} />
    </Card>
  )
}
