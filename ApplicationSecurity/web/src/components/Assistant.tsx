// The Security Assistant: the chat button in the bottom-right corner of every screen (same look as the Defender &
// Infrastructure portal's chat). It knows what you are looking at: a whole run, one finding, or nothing in particular,
// and answers from that run's findings, fixes and validation results (POST /api/v1/assistant/chat).
import { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { ArrowRight, Bot, Loader2, SendHorizonal, Sparkles, X } from 'lucide-react'
import { Markdown } from '@/components/Code'
import { post, useCaps } from '@/lib/api'
import { chatKey, usePanels, type ChatContext } from '@/lib/panels'
import { statusColor } from '@/lib/theme'
import { cn } from '@/lib/utils'

type Msg = { role: 'user' | 'assistant'; content: string; error?: boolean }

const SUGGEST: Record<ChatContext['type'], string[]> = {
  general: ['How does the pipeline validate fixes?', 'What is CodeQL vs Trivy?', 'How do I fix SQL injection in Python?'],
  run: ['Summarise the most critical risks', 'Why was validation flagged?', 'Which findings still need manual work?', 'What should I review before merging?'],
  finding: ['Explain this vulnerability simply', 'How do I fix it safely?', 'Is this exploitable here?', 'Review the applied fix'],
}

const INTRO: Record<ChatContext['type'], string> = {
  general: 'Hi! I can explain how the pipeline works, help you read a security finding, or suggest a secure fix. Open a scan to ask about its results.',
  run: 'I have this scan’s findings, fixes and validation results. What would you like to know?',
  finding: 'I have this finding’s details, its source code and any fix that was applied. Ask away.',
}

export function Assistant() {
  const { chat, openChat, closeChat, setChatContext } = usePanels()
  const caps = useCaps()
  const llm = caps.data?.llm
  const [histories, setHistories] = useState<Record<string, Msg[]>>({})
  const [busy, setBusy] = useState(false)
  const [text, setText] = useState('')
  const listRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLTextAreaElement>(null)
  const ctx = chat.ctx
  const key = chatKey(ctx)
  const msgs = histories[key] ?? []

  useEffect(() => {
    listRef.current?.scrollTo({ top: listRef.current.scrollHeight, behavior: 'smooth' })
  }, [msgs.length, busy])

  useEffect(() => {
    if (!chat.open) return
    inputRef.current?.focus()
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && closeChat()
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [chat.open, closeChat])

  const send = async (q: string) => {
    q = q.trim()
    if (!q || busy) return
    const hist = [...msgs, { role: 'user' as const, content: q }]
    setHistories((h) => ({ ...h, [key]: hist }))
    setText('')
    setBusy(true)
    try {
      const r = await post<{ reply: string }>('/api/v1/assistant/chat', {
        messages: hist.filter((m) => !m.error).slice(-12).map(({ role, content }) => ({ role, content })),
        job_id: 'jobId' in ctx ? ctx.jobId : null,
        finding_id: ctx.type === 'finding' ? ctx.findingId : null,
      })
      setHistories((h) => ({ ...h, [key]: [...hist, { role: 'assistant', content: r.reply || '(empty reply)' }] }))
    } catch (e) {
      setHistories((h) => ({ ...h, [key]: [...hist, { role: 'assistant', content: (e as Error).message, error: true }] }))
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <button
        onClick={() => (chat.open ? closeChat() : openChat())}
        aria-label={chat.open ? 'Close the Security Assistant' : 'Open the Security Assistant'}
        title={chat.open ? 'Close chat' : 'Ask the Security Assistant'}
        aria-expanded={chat.open}
        className={cn(
          'fixed bottom-4 right-4 z-40 grid size-12 place-items-center rounded-[14px] border border-white/15 bg-blue text-white shadow-float transition-[transform,background-color] duration-200 hover:-translate-y-0.5 hover:bg-blue-hi active:translate-y-0',
          chat.open && 'max-sm:hidden',
        )}
      >
        {chat.open ? <X className="size-5" strokeWidth={2.2} /> : <Bot className="size-6" strokeWidth={2.2} />}
      </button>

      {chat.open && (
        <section
          role="dialog"
          aria-label="Security Assistant"
          className="fixed inset-x-0 bottom-0 top-14 z-40 flex flex-col overflow-hidden border border-hairline bg-panel shadow-float animate-in fade-in slide-in-from-bottom-3 duration-200 sm:inset-x-auto sm:bottom-20 sm:right-5 sm:top-auto sm:h-[min(620px,calc(100svh-8rem))] sm:w-[400px] sm:rounded-2xl"
        >
          <header className="flex items-center gap-3 border-b border-hairline px-4 py-3">
            <span className="tile-signal grid size-9 place-items-center rounded-[9px]"><Bot className="size-5" /></span>
            <div className="min-w-0 flex-1">
              <div className="text-sm font-semibold">Security Assistant</div>
              <div className="truncate text-xs text-ink-3">{llm?.enabled ? `${llm.provider} · ${llm.model}` : 'No AI model connected yet'}</div>
            </div>
            <button onClick={closeChat} aria-label="Close chat" className="grid size-8 place-items-center rounded-lg text-ink-3 hover:bg-well hover:text-ink">
              <X className="size-4" />
            </button>
          </header>

          <div className="flex flex-wrap items-center gap-1.5 border-b border-hairline px-4 py-2 text-xs">
            <span className="text-ink-3">Talking about:</span>
            <span className="max-w-[220px] truncate rounded-full border border-hairline bg-well px-2 py-0.5 font-medium text-ink-2" title={'label' in ctx ? ctx.label : undefined}>
              {ctx.type === 'general' ? 'General questions' : `${ctx.type === 'finding' ? 'Finding' : 'Scan'}: ${ctx.label}`}
            </span>
            {ctx.type === 'finding' && (
              <button onClick={() => setChatContext({ type: 'run', jobId: ctx.jobId, label: 'this scan' })} className="rounded-full px-2 py-0.5 text-sky hover:bg-well">whole scan</button>
            )}
            {ctx.type !== 'general' && <button onClick={() => setChatContext({ type: 'general' })} className="ml-auto rounded-full px-2 py-0.5 text-ink-3 hover:bg-well hover:text-ink">general</button>}
          </div>

          <div ref={listRef} className="flex flex-1 flex-col gap-3 overflow-y-auto px-4 py-4">
            {llm && !llm.enabled ? (
              <div className="rounded-xl bg-well px-3.5 py-3 text-sm text-ink-2">
                <b className="text-ink">Connect an AI model to chat.</b> The assistant uses the same model as the Remediation Agent.{' '}
                <Link to="/settings" onClick={closeChat} className="inline-flex items-center gap-1 font-medium text-sky">Open Settings <ArrowRight className="size-3" /></Link>
              </div>
            ) : (
              <Bubble from="bot">{INTRO[ctx.type]}</Bubble>
            )}
            {msgs.map((m, i) => (
              <Bubble key={i} from={m.role === 'user' ? 'you' : 'bot'} error={m.error}>
                {m.role === 'assistant' && !m.error ? <Markdown text={m.content} className="text-[13px] [&_p]:my-1.5" /> : m.content}
                {m.role === 'assistant' && !m.error && <p className="mt-1.5 flex items-center gap-1 text-[10px] text-ink-3"><Sparkles className="size-3" /> Security Assistant answer · check important details in the scan</p>}
              </Bubble>
            ))}
            {busy && <Bubble from="bot"><span className="flex items-center gap-2 text-ink-3"><Loader2 className="size-3.5 animate-spin" /> Thinking…</span></Bubble>}
          </div>

          <div className="border-t border-hairline px-4 pb-4 pt-3">
            {!msgs.length && llm?.enabled && (
              <div className="mb-2.5 flex flex-col gap-1.5">
                {SUGGEST[ctx.type].map((q) => (
                  <button key={q} onClick={() => send(q)} disabled={busy}
                    className="flex items-center justify-between gap-2 rounded-xl border border-hairline px-3 py-2 text-left text-xs font-medium text-ink-2 transition-colors hover:border-blue/45 hover:bg-blue/8 hover:text-ink disabled:opacity-60">
                    {q} <ArrowRight className="size-3.5 shrink-0 text-ink-3" />
                  </button>
                ))}
              </div>
            )}
            <div className="flex items-end gap-2 rounded-xl border border-hairline bg-field px-3 py-2 transition-[border-color,box-shadow] focus-within:border-blue/60 focus-within:ring-3 focus-within:ring-blue/15">
              <textarea
                ref={inputRef}
                value={text}
                disabled={!llm?.enabled}
                onChange={(e) => setText(e.target.value.slice(0, 4000))}
                onKeyDown={(e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(text) } }}
                rows={1}
                aria-label="Your question"
                style={{ outline: 'none' }}
                placeholder="Ask about findings, fixes, validation…"
                className="max-h-28 min-h-6 flex-1 resize-none bg-transparent text-sm outline-none placeholder:text-ink-3 disabled:opacity-50 [field-sizing:content]"
              />
              <button onClick={() => send(text)} disabled={!text.trim() || busy || !llm?.enabled} aria-label="Send" className="btn-blue grid size-8 shrink-0 place-items-center rounded-lg disabled:opacity-30">
                <SendHorizonal className="size-4" />
              </button>
            </div>
          </div>
        </section>
      )}
    </>
  )
}

function Bubble({ from, error, children }: { from: 'you' | 'bot'; error?: boolean; children: React.ReactNode }) {
  return (
    <div
      className={cn(
        'max-w-[88%] rounded-2xl px-3.5 py-2.5 text-sm leading-relaxed',
        from === 'you' ? 'self-end rounded-br-md bg-blue text-white' : 'self-start rounded-bl-md border border-hairline bg-well text-ink-2',
      )}
      style={error ? { color: statusColor.critical } : undefined}
    >
      {children}
    </div>
  )
}
