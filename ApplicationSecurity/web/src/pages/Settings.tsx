import { useCallback, useEffect, useState, type ReactNode } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { Bot, GitPullRequestArrow, KeyRound, Loader2, RefreshCw, SlidersHorizontal } from 'lucide-react'
import { Btn, Card, Field, Loading, Notice, PageHeader, StatusTag, inputCls } from '@/components/kit'
import { ApiError, api, getClientKey, setClientKey, useSettings } from '@/lib/api'
import { statusColor } from '@/lib/theme'
import { useToast } from '@/lib/toast'
import type { SettingEntry, SettingsView } from '@/lib/types'

// Pick a provider, paste its key, choose a model from the list the provider gives for that key. The address is known
// for each provider; only "Other" (Azure OpenAI, a company gateway, vLLM, LiteLLM, Ollama...) needs one.
type Kind = 'gemini' | 'openai' | 'anthropic' | 'other' | 'none'
const link = (href: string, text: string) => <a className="text-sky underline" href={href} target="_blank" rel="noopener noreferrer">{text}</a>
const PROVIDERS: Record<Kind, { label: string; hint: ReactNode }> = {
  gemini: { label: 'Google Gemini', hint: <>Get a key at {link('https://aistudio.google.com/apikey', 'aistudio.google.com/apikey')}.</> },
  openai: { label: 'OpenAI', hint: <>Get a key at {link('https://platform.openai.com/api-keys', 'platform.openai.com/api-keys')}.</> },
  anthropic: { label: 'Anthropic (Claude)', hint: <>Get a key at {link('https://console.anthropic.com/settings/keys', 'console.anthropic.com')}.</> },
  other: { label: 'Other (OpenAI-compatible address)', hint: <>Azure OpenAI, a company gateway, vLLM, LiteLLM or Ollama (<span className="font-mono">http://localhost:11434/v1</span>): enter its address below.</> },
  none: { label: 'Switched off', hint: 'The Remediation Agent\u2019s code fixes and the Security Assistant are switched off.' },
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
        ? <>Connect your own AI model and GitHub account so the agents can write code fixes and open pull requests for the scans you start. Only you can use these keys{s.data.user && <> (signed in as <span className="font-mono">{s.data.user}</span>)</>}.</>
        : 'Connect an AI model and GitHub so the agents can write code fixes and open pull requests. Keys are kept on this server only.'} />
      {s.error ? <KeyOnly error={s.error as ApiError} /> : s.data && <Forms view={s.data} />}
    </div>
  )
}

function Source({ e, own }: { e: SettingEntry; own?: boolean }) {
  return e.source === 'ui' ? <StatusTag tone="info" label={own ? 'yours' : 'set here'} />
    : e.source === 'env' ? <StatusTag tone="idle" label={own ? 'server default' : 'from .env'} />
    : e.source === 'default' ? <StatusTag tone="idle" label="default" /> : <StatusTag tone="warn" label="not set" />
}

function useSave() {
  const qc = useQueryClient()
  const toast = useToast()
  return async (payload: Record<string, unknown>, onError?: (m: string) => void) => {
    try {
      await api('/api/v1/settings', { method: 'PUT', body: JSON.stringify(payload), headers: WRITE })
      toast('Saved')
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
  if (m === 'busy') return <span className="flex items-center gap-1.5 text-xs text-ink-3"><Loader2 className="size-3.5 animate-spin" /> testing…</span>
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
      setModelsMsg(r.models.length ? null : { ok: false, text: 'This key has no chat models at this provider.' })
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
    if (k !== 'other' && keyKnown) void loadModels(k, key, '')
  }
  const saveAi = async () => {
    const body: Record<string, unknown> = kind === 'none' ? { llm_provider: 'none' }
      : { llm_provider: kind === 'other' ? 'openai' : kind, llm_model: model.trim(), llm_base_url: kind === 'other' ? base.trim() : null }
    if (key.trim()) body.llm_api_key = key.trim()
    if (await save(body, (m) => setLlmMsg({ ok: false, text: m }))) setKey('')
  }
  const test = async (path: string, set: typeof setLlmMsg, ok: (r: Record<string, string>) => string) => {
    set('busy')
    try {
      set({ ok: true, text: ok(await api<Record<string, string>>(path, { method: 'POST', headers: WRITE })) })
    } catch (e) {
      set({ ok: false, text: (e as Error).message })
    }
  }

  return (
    <div className="grid grid-cols-1 gap-5 xl:grid-cols-2">
      <Card title={<span className="flex items-center gap-2"><Bot className="size-4 text-sky" /> AI model</span>}
        description="Used by the Remediation Agent to write code fixes, and by the Security Assistant."
        action={view.llm_enabled ? <StatusTag tone="good" label="Connected" /> : <StatusTag tone="warn" label="Not connected" />}>
        <div className="flex flex-col gap-4">
          <Field label={<>Provider <Source own={own} e={st.llm_provider} /></>} hint={PROVIDERS[kind].hint}>
            <select value={kind} onChange={(e) => pickKind(e.target.value as Kind)} className={inputCls}>
              {(Object.keys(PROVIDERS) as Kind[]).map((k) => <option key={k} value={k}>{PROVIDERS[k].label}</option>)}
            </select>
          </Field>
          {kind === 'other' && (
            <Field label={<>Address (base URL) <Source own={own} e={st.llm_base_url} /></>} hint="The OpenAI-compatible address of your gateway or server, ending in /v1.">
              <input type="url" value={base} onChange={(e) => setBase(e.target.value)} onBlur={() => keyKnown && void loadModels(kind, key, base)} placeholder="https://your-gateway.example.com/v1" className={inputCls} />
            </Field>
          )}
          {kind !== 'none' && (
            <>
              <Field label={<>API key <Source own={own} e={st.llm_api_key} /></>}>
                <input type="password" autoComplete="off" value={key} onChange={(e) => setKey(e.target.value)} onBlur={() => key.trim() && void loadModels(kind, key, base)}
                  placeholder={st.llm_api_key.configured ? `${st.llm_api_key.value} (leave empty to keep)` : 'paste your API key'} className={inputCls} />
              </Field>
              <Field label={<span className="flex items-center gap-2">Model <Source own={own} e={st.llm_model} />
                {keyKnown && <button type="button" onClick={() => void loadModels(kind, key, base)} className="ml-auto inline-flex items-center gap-1 text-xs font-normal text-sky hover:underline"><RefreshCw className="size-3" /> refresh list</button>}</span>}
                hint={modelsMsg === 'busy' ? <span className="flex items-center gap-1.5"><Loader2 className="size-3 animate-spin" /> Asking {PROVIDERS[kind].label} which models your key can use\u2026</span>
                  : modelsMsg ? <span style={{ color: statusColor.critical }}>{modelsMsg.text}</span>
                  : models ? `${models.length} models available for your key.` : keyKnown ? undefined : 'Paste your API key: the models it can use are listed here.'}>
                {models && models.length ? (
                  <select value={model} onChange={(e) => setModel(e.target.value)} className={inputCls}>
                    {model && !models.includes(model) && <option value={model}>{model} (not available for this key)</option>}
                    {models.map((m) => <option key={m} value={m}>{m}</option>)}
                  </select>
                ) : (
                  <input value={model} onChange={(e) => setModel(e.target.value)} placeholder={keyKnown ? 'or type a model name' : 'appears once your key is in'} className={inputCls} />
                )}
              </Field>
            </>
          )}
          <div className="flex flex-wrap items-center gap-2">
            <Btn onClick={saveAi} disabled={kind !== 'none' && (!model.trim() || (kind === 'other' && !base.trim()))}>Save</Btn>
            <Btn kind="quiet" onClick={() => test('/api/v1/settings/test-llm', setLlmMsg, (r) => `✓ ${r.provider} · ${r.model} replied “${r.reply}”`)}>Test connection</Btn>
            {st.llm_api_key.source === 'ui' && <Btn kind="quiet" onClick={() => save({ llm_api_key: null })}>Remove key</Btn>}
            <Msg m={llmMsg} />
          </div>
        </div>
      </Card>

      <Card title={<span className="flex items-center gap-2"><GitPullRequestArrow className="size-4 text-sky" /> GitHub</span>}
        description={own ? 'Your own token: needed for private repositories, and to push the fix branch and open pull requests in your name.' : 'Needed for private repositories, and to push the fix branch and open pull requests.'}
        action={st.github_token.configured ? <StatusTag tone="good" label="Token set" /> : <StatusTag tone="warn" label="No token" />}>
        <div className="flex flex-col gap-4">
          <Notice tone="info" title="Which token?">A fine-grained personal access token on the repositories you want fixed, with <b>Contents: read &amp; write</b> and <b>Pull requests: read &amp; write</b>. For <b>Run tests on GitHub</b> also <b>Workflows: read &amp; write</b> (it adds the test workflow) and <b>Actions: read</b> (it follows the test runs). A classic token needs the <span className="font-mono">repo</span> and <span className="font-mono">workflow</span> scopes.</Notice>
          <Field label={<>Personal access token <Source own={own} e={st.github_token} /></>}>
            <input type="password" autoComplete="off" value={gh} onChange={(e) => setGh(e.target.value)} placeholder={st.github_token.configured ? `${st.github_token.value} (leave empty to keep)` : 'github_pat_…'} className={inputCls} />
          </Field>
          <div className="flex flex-wrap items-center gap-2">
            <Btn disabled={!gh.trim()} onClick={async () => { if (await save({ github_token: gh.trim() }, (m) => setGhMsg({ ok: false, text: m }))) setGh('') }}>Save</Btn>
            <Btn kind="quiet" onClick={() => test('/api/v1/settings/test-github', setGhMsg, (r) => `✓ signed in to GitHub as ${r.login}`)}>Test token</Btn>
            {st.github_token.source === 'ui' && <Btn kind="quiet" onClick={() => save({ github_token: null })}>Remove token</Btn>}
            <Msg m={ghMsg} />
          </div>
        </div>
      </Card>

      <Card title={<span className="flex items-center gap-2"><SlidersHorizontal className="size-4 text-sky" /> Limits</span>} description="How much the Remediation Agent may do in one scan.">
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <Field label={<>Max code fixes per scan <Source own={own} e={st.max_findings_per_run} /></>}><input type="number" min={1} max={500} value={max} onChange={(e) => setMax(e.target.value)} className={inputCls} /></Field>
          <Field label={<>Attempts per finding <Source own={own} e={st.llm_fix_attempts} /></>}><input type="number" min={1} max={5} value={attempts} onChange={(e) => setAttempts(e.target.value)} className={inputCls} /></Field>
        </div>
        <div className="mt-4"><Btn onClick={() => save({ max_findings_per_run: Number(max), llm_fix_attempts: Number(attempts) })}>Save</Btn></div>
      </Card>

      <Card title={<span className="flex items-center gap-2"><KeyRound className="size-4 text-sky" /> How keys are kept</span>}>
        {own ? (
          <p className="text-sm leading-relaxed text-ink-2">Your keys are saved under your sign-in, encrypted on this server, and never shown in full again, not even to you. Only the scans you start use them: to read your repositories, push fix branches, open pull requests and run your tests on GitHub. Other people cannot see your keys or your scans, and you cannot see theirs. Scanners never receive your keys.</p>
        ) : (
          <>
            <p className="text-sm leading-relaxed text-ink-2">Keys entered here are saved on this server in <span className="font-mono">DATA_DIR/runtime_settings.json</span>, are never shown in full again, and are removed from the environment of every scanner. Settings can only be changed from this computer unless the server sets <span className="font-mono">API_KEYS</span>.</p>
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
      <Field label="Client API key (only if the server sets API_KEYS)"><input type="password" value={k} onChange={(e) => setK(e.target.value)} placeholder="X-API-Key" className={inputCls} /></Field>
      <div><Btn kind="quiet" onClick={() => { setClientKey(k.trim()); toast('Client key saved'); onSaved?.() }}>Save client key</Btn></div>
    </div>
  )
}

function KeyOnly({ error }: { error: ApiError }) {
  const qc = useQueryClient()
  return (
    <Card title="API access">
      <Notice tone="warn" title={error.status === 401 ? 'This server needs an API key' : 'Settings are not available'}>{error.message}</Notice>
      <ClientKey onSaved={() => qc.invalidateQueries()} />
    </Card>
  )
}
