import { useCallback, useEffect, useState, type ReactNode } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { Bot, GitPullRequestArrow, KeyRound, Loader2, RefreshCw, SlidersHorizontal } from 'lucide-react'
import { Btn, Card, Choice, Field, Loading, Notice, PageHeader, StatusTag, inputCls } from '@/components/kit'
import { ApiError, api, getClientKey, setClientKey, useSettings } from '@/lib/api'
import { statusColor } from '@/lib/theme'
import { useToast } from '@/lib/toast'
import type { SettingEntry, SettingsView } from '@/lib/types'

// Pick a provider, paste its key, choose a model from the list the provider gives for that key. The address is known
// for each provider; only "Other" (Azure OpenAI, a company gateway, vLLM, LiteLLM, Ollama...) needs one.
type Kind = 'gemini' | 'openai' | 'anthropic' | 'other' | 'none'
const link = (href: string, text: string) => <a className="text-sky underline" href={href} target="_blank" rel="noopener noreferrer">{text}</a>
const PROVIDERS: Record<Kind, { label: string; hint: ReactNode }> = {
  gemini: { label: 'Google Gemini', hint: <>Generate an API key at {link('https://aistudio.google.com/apikey', 'aistudio.google.com/apikey')}.</> },
  openai: { label: 'OpenAI', hint: <>Generate an API key at {link('https://platform.openai.com/api-keys', 'platform.openai.com/api-keys')}.</> },
  anthropic: { label: 'Anthropic (Claude)', hint: <>Generate an API key at {link('https://console.anthropic.com/settings/keys', 'console.anthropic.com')}.</> },
  other: { label: 'Other (OpenAI-compatible endpoint)', hint: <>Azure OpenAI, an enterprise AI gateway, vLLM, LiteLLM or Ollama (<span className="font-mono">http://localhost:11434/v1</span>). Enter the endpoint below.</> },
  none: { label: 'Disabled', hint: 'AI-assisted remediation and the Security Assistant are disabled.' },
}
const KNOWN_URLS = ['https://api.openai.com/v1', 'https://generativelanguage.googleapis.com/v1beta/openai', 'https://api.anthropic.com/v1']

/** Which choice the saved settings amount to ("auto" and a default address are shown as the provider they reach). */
function savedKind(view: SettingsView): Kind {
  const saved = String(view.settings.llm_provider.value || 'auto')
  const base = String(view.settings.llm_base_url.value ?? '').replace(/\/$/, '')
  const custom = !!base && !KNOWN_URLS.includes(base)
  if (saved === 'none' || saved === 'gemini' || saved === 'anthropic') return saved
  if (saved === 'openai') return custom ? 'other' : 'openai'
  const reached = view.llm_provider
  if (reached === 'gemini' || reached === 'anthropic') return reached
  if (reached === 'openai') return custom ? 'other' : 'openai'
  return 'gemini'
}

// Changing settings needs this header, which a form on another website cannot send.
const WRITE = { 'X-CyberSuite': 'settings' }

export function SettingsPage() {
  const s = useSettings()
  if (s.isLoading) return <Loading />
  return (
    <div className="flex flex-col gap-5">
      <PageHeader title="Settings" description={s.data?.per_user
        ? <>Connect your AI model provider and GitHub account to enable AI-assisted remediation and pull requests for the scans you initiate. These credentials are personal and used only for your scans{s.data.user && <> (signed in as <span className="font-mono">{s.data.user}</span>)</>}.</>
        : 'Connect an AI model provider and GitHub to enable AI-assisted remediation and pull requests. Credentials are stored on this server only.'} />
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
  const [kind, setKind] = useState<Kind>(() => savedKind(view))
  const [model, setModel] = useState(String(st.llm_model.value ?? ''))
  const [base, setBase] = useState(() => (savedKind(view) === 'other' ? String(st.llm_base_url.value ?? '') : ''))
  const [key, setKey] = useState('')
  const [models, setModels] = useState<string[] | null>(null)
  const [modelsMsg, setModelsMsg] = useState<{ ok: boolean; text: string } | null | 'busy'>(null)
  const [gh, setGh] = useState('')
  const [max, setMax] = useState(String(st.max_findings_per_run.value ?? ''))
  const [attempts, setAttempts] = useState(String(st.llm_fix_attempts.value ?? ''))
  const [llmMsg, setLlmMsg] = useState<{ ok: boolean; text: string } | null | 'busy'>(null)
  const [ghMsg, setGhMsg] = useState<{ ok: boolean; text: string } | null | 'busy'>(null)
  const keyKnown = !!key.trim() || st.llm_api_key.configured

  // The provider's own list of models this key can use, so nobody has to type (or mistype) a model name
  const loadModels = useCallback(async (k: Kind, typedKey: string, address: string) => {
    if (k === 'none' || (k === 'other' && !address.trim())) return
    setModelsMsg('busy')
    try {
      const r = await api<{ models: string[] }>('/api/v1/settings/models', { method: 'POST', headers: WRITE, body: JSON.stringify({
        llm_provider: k === 'other' ? 'openai' : k, llm_api_key: typedKey.trim() || undefined, llm_base_url: k === 'other' ? address.trim() : undefined }) })
      setModels(r.models)
      setModel((m) => (r.models.includes(m) ? m : r.models[0] ?? m))
      setModelsMsg(r.models.length ? null : { ok: false, text: 'No chat models are available for this API key at this provider.' })
    } catch (e) {
      setModels(null)
      setModelsMsg({ ok: false, text: (e as Error).message })
    }
  }, [])
  useEffect(() => {
    if (st.llm_api_key.configured) void loadModels(savedKind(view), '', String(st.llm_base_url.value ?? ''))
  }, [loadModels, st.llm_api_key.configured, st.llm_base_url.value, view])

  const pickKind = (k: Kind) => {
    setKind(k)
    setModels(null)
    setModelsMsg(null)
    setLlmMsg(null)
    if (k !== 'other' && keyKnown) void loadModels(k, key, '')
  }
  const pickModel = (m: string) => {
    setModel(m)
    setLlmMsg(null)
  }
  const saveAi = async () => {
    const body: Record<string, unknown> = kind === 'none' ? { llm_provider: 'none' }
      : { llm_provider: kind === 'other' ? 'openai' : kind, llm_model: model.trim(), llm_base_url: kind === 'other' ? base.trim() : null }
    if (key.trim()) body.llm_api_key = key.trim()
    if (await save(body, (m) => setLlmMsg({ ok: false, text: m }))) setKey('')
  }
  const test = async (path: string, set: typeof setLlmMsg, ok: (r: Record<string, string>) => string, body?: Record<string, unknown>) => {
    set('busy')
    try {
      set({ ok: true, text: ok(await api<Record<string, string>>(path, { method: 'POST', headers: WRITE, body: body ? JSON.stringify(body) : undefined })) })
    } catch (e) {
      set({ ok: false, text: (e as Error).message })
    }
  }
  // Tests exactly what is on screen (provider, model, a key typed but not saved yet), not only what was saved
  const testAi = () => test('/api/v1/settings/test-llm', setLlmMsg, (r) => r.answered_by && r.answered_by !== r.model
    ? `✓ Connected to ${PROVIDERS[kind].label}. You selected ${r.model}; the provider answered as ${r.answered_by}.`
    : `✓ Connected to ${PROVIDERS[kind].label}. ${r.model} responded successfully.`,
  { llm_provider: kind === 'other' ? 'openai' : kind, llm_model: model.trim(), llm_api_key: key.trim() || undefined, llm_base_url: kind === 'other' ? base.trim() : undefined })

  const modelOptions = models ? [...(model && !models.includes(model) ? [{ value: model, label: `${model} (not available for this key)` }] : []), ...models.map((m) => ({ value: m, label: m }))] : []

  return (
    <div className="grid grid-cols-1 gap-5 xl:grid-cols-2">
      <Card title={<span className="flex items-center gap-2"><Bot className="size-4 text-sky" /> AI model</span>}
        description="Powers AI-assisted remediation by the Remediation Agent and the Security Assistant."
        action={view.llm_enabled ? <StatusTag tone="good" label="Connected" /> : <StatusTag tone="warn" label="Not connected" />}>
        <div className="flex flex-col gap-4">
          <Field label={<>Provider <Source own={own} e={st.llm_provider} /></>} hint={PROVIDERS[kind].hint}>
            <Choice field label="Provider" value={kind} onChange={(v) => pickKind(v as Kind)}
              options={(Object.keys(PROVIDERS) as Kind[]).map((k) => ({ value: k, label: PROVIDERS[k].label }))} />
          </Field>
          {kind === 'other' && (
            <Field label={<>Endpoint (base URL) <Source own={own} e={st.llm_base_url} /></>} hint="The OpenAI-compatible endpoint of your gateway or model server, ending in /v1.">
              <input type="url" value={base} onChange={(e) => setBase(e.target.value)} onBlur={() => keyKnown && void loadModels(kind, key, base)} placeholder="https://your-gateway.example.com/v1" className={inputCls} />
            </Field>
          )}
          {kind !== 'none' && (
            <>
              <Field label={<>API key <Source own={own} e={st.llm_api_key} /></>}>
                <input type="password" autoComplete="off" value={key} onChange={(e) => { setKey(e.target.value); setLlmMsg(null) }} onBlur={() => key.trim() && void loadModels(kind, key, base)}
                  placeholder={st.llm_api_key.configured ? `${st.llm_api_key.value} (leave blank to keep the current key)` : 'Paste your API key'} className={inputCls} />
              </Field>
              <Field label={<span className="flex items-center gap-2">Model <Source own={own} e={st.llm_model} />
                {keyKnown && <button type="button" onClick={() => void loadModels(kind, key, base)} className="ml-auto inline-flex items-center gap-1 text-xs font-normal text-sky hover:underline"><RefreshCw className="size-3" /> Refresh list</button>}</span>}
                hint={modelsMsg === 'busy' ? <span className="flex items-center gap-1.5"><Loader2 className="size-3 animate-spin" /> Retrieving the models available to your key from {PROVIDERS[kind].label}…</span>
                  : modelsMsg ? <span style={{ color: statusColor.critical }}>{modelsMsg.text}</span>
                  : models ? `${models.length} models available for your key.` : keyKnown ? undefined : 'Enter your API key to list the models available to it.'}>
                {models && models.length ? (
                  <Choice field label="Model" value={model} onChange={pickModel} options={modelOptions} />
                ) : (
                  <input value={model} onChange={(e) => pickModel(e.target.value)} placeholder={keyKnown ? 'Or enter a model name' : 'Available once your API key is entered'} className={inputCls} />
                )}
              </Field>
            </>
          )}
          <div className="flex flex-wrap items-center gap-2">
            <Btn onClick={saveAi} disabled={kind !== 'none' && (!model.trim() || (kind === 'other' && !base.trim()))}>Save</Btn>
            {kind !== 'none' && <Btn kind="quiet" disabled={!model.trim() || !keyKnown} onClick={testAi}>Test connection</Btn>}
            {st.llm_api_key.source === 'ui' && <Btn kind="quiet" onClick={() => save({ llm_api_key: null })}>Remove key</Btn>}
            <Msg m={llmMsg} />
          </div>
        </div>
      </Card>

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
            <Btn kind="quiet" onClick={() => test('/api/v1/settings/test-github', setGhMsg, (r) => `✓ Authenticated with GitHub as ${r.login}`)}>Test token</Btn>
            {st.github_token.source === 'ui' && <Btn kind="quiet" onClick={() => save({ github_token: null })}>Remove token</Btn>}
            <Msg m={ghMsg} />
          </div>
        </div>
      </Card>

      <Card title={<span className="flex items-center gap-2"><SlidersHorizontal className="size-4 text-sky" /> Remediation limits</span>} description="Controls how much the Remediation Agent may change in a single scan.">
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <Field label={<>Maximum remediations per scan <Source own={own} e={st.max_findings_per_run} /></>}><input type="number" min={1} max={500} value={max} onChange={(e) => setMax(e.target.value)} className={inputCls} /></Field>
          <Field label={<>Attempts per finding <Source own={own} e={st.llm_fix_attempts} /></>}><input type="number" min={1} max={5} value={attempts} onChange={(e) => setAttempts(e.target.value)} className={inputCls} /></Field>
        </div>
        <div className="mt-4"><Btn onClick={() => save({ max_findings_per_run: Number(max), llm_fix_attempts: Number(attempts) })}>Save</Btn></div>
      </Card>

      <Card title={<span className="flex items-center gap-2"><KeyRound className="size-4 text-sky" /> Credential handling</span>}>
        {own ? (
          <p className="text-sm leading-relaxed text-ink-2">Your credentials are stored against your account, encrypted at rest on this server, and never displayed in full again. They are used only for scans you initiate: to read your repositories, push remediation branches, raise pull requests and run CI test validation on GitHub. Other users cannot view or use your credentials, and scanners never receive them.</p>
        ) : (
          <>
            <p className="text-sm leading-relaxed text-ink-2">Credentials entered here are stored on this server in <span className="font-mono">DATA_DIR/runtime_settings.json</span>, are never displayed in full again, and are removed from the environment of every scanner. Settings can be changed only from this machine unless the server sets <span className="font-mono">API_KEYS</span>.</p>
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
