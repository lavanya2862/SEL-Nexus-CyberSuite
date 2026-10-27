import { useState, type ReactNode } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { Bot, GitPullRequestArrow, KeyRound, Loader2, SlidersHorizontal } from 'lucide-react'
import { Btn, Card, Field, Loading, Notice, PageHeader, StatusTag, inputCls } from '@/components/kit'
import { ApiError, getClientKey, post, put, setClientKey, useSettings } from '@/lib/api'
import { statusColor } from '@/lib/theme'
import { useToast } from '@/lib/toast'
import type { SettingEntry, SettingsView } from '@/lib/types'

// Picking a provider fills in its address (unless a custom one was typed) and an example model.
const PRESETS: Record<string, { url: string; model: string; hint: ReactNode }> = {
  gemini: { url: 'https://generativelanguage.googleapis.com/v1beta/openai', model: 'e.g. gemini-2.5-flash or gemini-2.5-pro',
    hint: <>A Google AI Studio key (<a className="text-sky underline" href="https://aistudio.google.com/apikey" target="_blank" rel="noopener noreferrer">aistudio.google.com/apikey</a>). Uses Gemini’s OpenAI-compatible address.</> },
  openai: { url: 'https://api.openai.com/v1', model: 'e.g. gpt-4o', hint: <>OpenAI, Azure / OpenAI-compatible gateways, vLLM, LiteLLM or Ollama (<span className="font-mono">http://localhost:11434/v1</span>).</> },
  anthropic: { url: 'https://api.anthropic.com/v1', model: 'e.g. a claude-sonnet model', hint: 'Anthropic Messages API.' },
  auto: { url: '', model: 'e.g. gemini-2.5-flash, gpt-4o or claude-…', hint: 'Detected from the model name or address (gemini-* → Gemini, claude-* → Anthropic, otherwise OpenAI-compatible).' },
  none: { url: '', model: '', hint: 'The Remediation Agent’s code fixes and the assistant are switched off.' },
}
const PRESET_URLS = Object.values(PRESETS).map((p) => p.url).filter(Boolean)

export function SettingsPage() {
  const s = useSettings()
  if (s.isLoading) return <Loading />
  return (
    <div className="flex flex-col gap-5">
      <PageHeader title="Settings" description="Connect an AI model and GitHub so the agents can write code fixes and open pull requests. Keys are kept on this server only." />
      {s.error ? <KeyOnly error={s.error as ApiError} /> : s.data && <Forms view={s.data} />}
    </div>
  )
}

function Source({ e }: { e: SettingEntry }) {
  return e.source === 'ui' ? <StatusTag tone="info" label="set here" /> : e.source === 'env' ? <StatusTag tone="idle" label="from .env" />
    : e.source === 'default' ? <StatusTag tone="idle" label="default" /> : <StatusTag tone="warn" label="not set" />
}

function useSave() {
  const qc = useQueryClient()
  const toast = useToast()
  return async (payload: Record<string, unknown>, onError?: (m: string) => void) => {
    try {
      await put('/api/v1/settings', payload)
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
  const save = useSave()
  const [provider, setProvider] = useState(String(st.llm_provider.value || 'auto'))
  const [model, setModel] = useState(String(st.llm_model.value ?? ''))
  const [base, setBase] = useState(String(st.llm_base_url.value ?? ''))
  const [key, setKey] = useState('')
  const [gh, setGh] = useState('')
  const [max, setMax] = useState(String(st.max_findings_per_run.value ?? ''))
  const [attempts, setAttempts] = useState(String(st.llm_fix_attempts.value ?? ''))
  const [llmMsg, setLlmMsg] = useState<{ ok: boolean; text: string } | null | 'busy'>(null)
  const [ghMsg, setGhMsg] = useState<{ ok: boolean; text: string } | null | 'busy'>(null)
  const p = PRESETS[provider] ?? PRESETS.auto

  const pickProvider = (v: string) => {
    setProvider(v)
    const url = PRESETS[v]?.url
    if (url && (!base.trim() || PRESET_URLS.includes(base.trim().replace(/\/$/, '')))) setBase(url)
  }
  const test = async (path: string, set: typeof setLlmMsg, ok: (r: Record<string, string>) => string) => {
    set('busy')
    try {
      set({ ok: true, text: ok(await post<Record<string, string>>(path)) })
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
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <Field label={<>Provider <Source e={st.llm_provider} /></>}>
              <select value={provider} onChange={(e) => pickProvider(e.target.value)} className={inputCls}>
                <option value="auto">Detect automatically</option><option value="gemini">Google Gemini</option>
                <option value="openai">OpenAI / OpenAI-compatible</option><option value="anthropic">Anthropic (Claude)</option><option value="none">Switched off</option>
              </select>
            </Field>
            <Field label={<>Model <Source e={st.llm_model} /></>}><input value={model} onChange={(e) => setModel(e.target.value)} placeholder={p.model} className={inputCls} /></Field>
          </div>
          <Field label={<>Address (base URL) <Source e={st.llm_base_url} /></>} hint={<>{p.hint}{view.llm_endpoint && <> Requests now go to <span className="font-mono">{view.llm_endpoint}</span>.</>}</>}>
            <input type="url" value={base} onChange={(e) => setBase(e.target.value)} placeholder="https://api.openai.com/v1" className={inputCls} />
          </Field>
          <Field label={<>API key <Source e={st.llm_api_key} /></>}>
            <input type="password" autoComplete="off" value={key} onChange={(e) => setKey(e.target.value)} placeholder={st.llm_api_key.configured ? `${st.llm_api_key.value} (leave empty to keep)` : 'paste your API key'} className={inputCls} />
          </Field>
          <div className="flex flex-wrap items-center gap-2">
            <Btn onClick={async () => { const body: Record<string, unknown> = { llm_provider: provider, llm_model: model.trim(), llm_base_url: base.trim() }; if (key.trim()) body.llm_api_key = key.trim(); if (await save(body, (m) => setLlmMsg({ ok: false, text: m }))) setKey('') }}>Save</Btn>
            <Btn kind="quiet" onClick={() => test('/api/v1/settings/test-llm', setLlmMsg, (r) => `✓ ${r.provider} · ${r.model} replied “${r.reply}”`)}>Test connection</Btn>
            {st.llm_api_key.source === 'ui' && <Btn kind="quiet" onClick={() => save({ llm_api_key: null })}>Remove key</Btn>}
            <Msg m={llmMsg} />
          </div>
        </div>
      </Card>

      <Card title={<span className="flex items-center gap-2"><GitPullRequestArrow className="size-4 text-sky" /> GitHub</span>}
        description="Needed for private repositories, and to push the fix branch and open pull requests."
        action={st.github_token.configured ? <StatusTag tone="good" label="Token set" /> : <StatusTag tone="warn" label="No token" />}>
        <div className="flex flex-col gap-4">
          <Notice tone="info" title="Which token?">A fine-grained personal access token on the repositories you want fixed, with <b>Contents: read &amp; write</b> and <b>Pull requests: read &amp; write</b>. For <b>Run tests on GitHub</b> also <b>Workflows: read &amp; write</b> (it adds the test workflow) and <b>Actions: read</b> (it follows the test runs). A classic token needs the <span className="font-mono">repo</span> and <span className="font-mono">workflow</span> scopes.</Notice>
          <Field label={<>Personal access token <Source e={st.github_token} /></>}>
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
          <Field label={<>Max code fixes per scan <Source e={st.max_findings_per_run} /></>}><input type="number" min={1} max={500} value={max} onChange={(e) => setMax(e.target.value)} className={inputCls} /></Field>
          <Field label={<>Attempts per finding <Source e={st.llm_fix_attempts} /></>}><input type="number" min={1} max={5} value={attempts} onChange={(e) => setAttempts(e.target.value)} className={inputCls} /></Field>
        </div>
        <div className="mt-4"><Btn onClick={() => save({ max_findings_per_run: Number(max), llm_fix_attempts: Number(attempts) })}>Save</Btn></div>
      </Card>

      <Card title={<span className="flex items-center gap-2"><KeyRound className="size-4 text-sky" /> How keys are kept</span>}>
        <p className="text-sm leading-relaxed text-ink-2">Keys entered here are saved on this server in <span className="font-mono">DATA_DIR/runtime_settings.json</span>, are never shown in full again, and are removed from the environment of every scanner. Settings can only be changed from this computer unless the server sets <span className="font-mono">API_KEYS</span>.</p>
        <ClientKey />
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
