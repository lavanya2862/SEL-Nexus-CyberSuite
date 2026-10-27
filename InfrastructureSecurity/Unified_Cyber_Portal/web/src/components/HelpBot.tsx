import { useEffect, useRef, useState } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ArrowRight, Bot, Loader2, SendHorizonal, Sparkles, X } from 'lucide-react'
import { SCREENS, screenFor, type ScreenKey } from '@/lib/helpFaq'
import { statusColor } from '@/lib/theme'
import { cn } from '@/lib/utils'

/* The Chat button in the bottom-right corner of every screen. Two ready questions per screen are answered from
   today's data by the portal (GET /api/help/ready, no AI); anything else is answered by the AI from the portal's own
   data (POST /api/help/ask). */

type Msg =
  | { id: number; from: 'you'; text: string }
  | { id: number; from: 'bot'; text: string; kind: 'ready' | 'ai' | 'error' | 'screen'; links?: { label: string; to: string }[] }

type NewMsg = Msg extends infer M ? (M extends Msg ? Omit<M, 'id'> : never) : never

interface Saved { answer: string; links: { label: string; to: string }[] }
interface Ready extends Saved { question: string }

let nextId = 1

export function HelpBot() {
  const { pathname } = useLocation()
  const navigate = useNavigate()
  const screen = screenFor(pathname)
  const info = SCREENS[screen]
  const [open, setOpen] = useState(() => new URLSearchParams(window.location.search).get('help') === 'open')
  const [msgs, setMsgs] = useState<Msg[]>([])
  const [text, setText] = useState('')
  const lastScreen = useRef<ScreenKey | null>(null)
  const listRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLTextAreaElement>(null)
  const qc = useQueryClient()
  const [readyBusy, setReadyBusy] = useState(false)

  const status = useQuery({
    queryKey: ['help', 'status'],
    queryFn: async () => (await fetch('/api/help/status')).json() as Promise<{ ai_ready: boolean; asked_today: number; cap: number }>,
    enabled: open,
    staleTime: 60_000,
  })

  const ask = useMutation({
    mutationFn: async (question: string) => {
      const history = pairs(msgs).slice(-4)
      const res = await fetch('/api/help/ask', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Portal': 'help' },
        body: JSON.stringify({ question, screen, path: pathname, history }),
      })
      const out = await res.json().catch(() => ({}))
      if (!res.ok) throw new Error(out.error ?? `the portal answered ${res.status}`)
      return out.saved as Saved
    },
    onSuccess: (s) => add({ from: 'bot', kind: 'ai', text: s.answer, links: s.links }),
    onError: (e) => add({ from: 'bot', kind: 'error', text: (e as Error).message }),
  })

  const add = (m: NewMsg) => setMsgs((list) => [...list, { ...m, id: nextId++ } as Msg])

  // When the user moves to another screen with a conversation going, note it so answers read in context.
  useEffect(() => {
    if (lastScreen.current && lastScreen.current !== screen && msgs.length) add({ from: 'bot', kind: 'screen', text: `You’re now on ${info.name}.` })
    lastScreen.current = screen
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [screen])

  useEffect(() => {
    listRef.current?.scrollTo({ top: listRef.current.scrollHeight, behavior: 'smooth' })
  }, [msgs, ask.isPending, readyBusy])

  useEffect(() => {
    if (!open) return
    inputRef.current?.focus()
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && setOpen(false)
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [open])

  // A ready question: fetch today's answer fresh on every click, so it always matches the page.
  const ready = async (i: number) => {
    if (readyBusy) return
    add({ from: 'you', text: info.questions[i] })
    setReadyBusy(true)
    try {
      const items = await qc.fetchQuery({
        queryKey: ['help', 'ready', screen, pathname],
        staleTime: 0,
        queryFn: async () => {
          const res = await fetch(`/api/help/ready?screen=${screen}&path=${encodeURIComponent(pathname)}`)
          const out = await res.json().catch(() => ({}))
          if (!res.ok) throw new Error(out.error ?? `the portal answered ${res.status}`)
          return out.items as Ready[]
        },
      })
      const it = items[i]
      add({ from: 'bot', kind: 'ready', text: it?.answer ?? 'I couldn’t find that answer right now.', links: it?.links })
    } catch (e) {
      add({ from: 'bot', kind: 'error', text: `I couldn’t look that up: ${(e as Error).message}` })
    } finally {
      setReadyBusy(false)
    }
  }
  const send = () => {
    const q = text.trim()
    if (!q || ask.isPending) return
    add({ from: 'you', text: q })
    setText('')
    ask.mutate(q)
  }
  const aiOff = status.data && !status.data.ai_ready
  const used = status.data && status.data.asked_today >= status.data.cap

  return (
    <>
      {/* the bubble: raised on Fix so it never covers the basket's Run fixes button */}
      <button
        onClick={() => setOpen((o) => !o)}
        aria-label={open ? 'Close chat' : 'Open chat'}
        title={open ? 'Close chat' : 'Ask about this screen'}
        aria-expanded={open}
        className={cn(
          'fixed right-4 z-40 grid size-12 place-items-center rounded-[14px] border border-white/15 bg-blue text-white shadow-float transition-[bottom,transform,background-color] duration-200 hover:-translate-y-0.5 hover:bg-blue-hi active:translate-y-0',
          screen === 'fixes' ? 'bottom-24' : 'bottom-4',
          open && 'max-sm:hidden',
        )}
      >
        {open ? <X className="size-5" strokeWidth={2.2} /> : <Bot className="size-6" strokeWidth={2.2} />}
      </button>

      {open && (
        <section
          role="dialog"
          aria-label={`Chat about ${info.name}`}
          className={cn(
            'fixed z-40 flex flex-col overflow-hidden border border-hairline bg-panel shadow-float animate-in fade-in slide-in-from-bottom-3 duration-200',
            'inset-x-0 bottom-0 top-14 sm:inset-x-auto sm:top-auto sm:right-5 sm:w-[390px] sm:rounded-2xl',
            screen === 'fixes' ? 'sm:bottom-40 sm:h-[min(560px,calc(100svh-13rem))]' : 'sm:bottom-20 sm:h-[min(600px,calc(100svh-8rem))]',
          )}
        >
          <header className="flex items-center gap-3 border-b border-hairline px-4 py-3">
            <span className="tile-signal grid size-9 place-items-center rounded-[9px]"><Bot className="size-5" /></span>
            <div className="min-w-0 flex-1">
              <div className="text-sm font-semibold">Chat</div>
              <div className="truncate text-xs text-ink-3">You’re on <span className="text-ink-2">{info.name}</span></div>
            </div>
            <button onClick={() => setOpen(false)} aria-label="Close chat" className="grid size-8 place-items-center rounded-lg text-ink-3 hover:bg-well hover:text-ink">
              <X className="size-4" />
            </button>
          </header>

          <div ref={listRef} className="flex flex-1 flex-col gap-3 overflow-y-auto px-4 py-4">
            <Bubble from="bot">
              Hi! I’m here to help. Ask me anything about this screen.
            </Bubble>
            {msgs.map((m) =>
              m.from === 'you' ? (
                <Bubble key={m.id} from="you">{m.text}</Bubble>
              ) : m.kind === 'screen' ? (
                <div key={m.id} className="flex items-center gap-2 text-[11px] text-ink-3"><span className="h-px flex-1 bg-hairline" />{m.text}<span className="h-px flex-1 bg-hairline" /></div>
              ) : (
                <Bubble key={m.id} from="bot" error={m.kind === 'error'}>
                  <p className="whitespace-pre-line">{m.text}</p>
                  {m.links && m.links.length > 0 && (
                    <div className="mt-2 flex flex-wrap gap-1.5">
                      {m.links.map((l) => (
                        <button key={l.to} onClick={() => navigate(l.to)} className="inline-flex items-center gap-1 rounded-full border border-hairline bg-panel px-2.5 py-1 text-xs font-medium hover:bg-well">
                          Open {l.label} <ArrowRight className="size-3" />
                        </button>
                      ))}
                    </div>
                  )}
                  {m.kind === 'ready' && <p className="mt-1.5 text-[10px] text-ink-3">From today’s data</p>}
                  {m.kind === 'ai' && <p className="mt-1.5 flex items-center gap-1 text-[10px] text-ink-3"><Sparkles className="size-3" /> AI answer from the portal’s data · check important numbers on the page</p>}
                </Bubble>
              ),
            )}
            {(ask.isPending || readyBusy) && (
              <Bubble from="bot"><span className="flex items-center gap-2 text-ink-3"><Loader2 className="size-3.5 animate-spin" /> Looking at the portal’s data…</span></Bubble>
            )}
          </div>

          <div className="border-t border-hairline px-4 pb-4 pt-3">
            <div className="mb-2.5 flex flex-col gap-1.5">
              {info.questions.map((q, i) => (
                <button
                  key={q}
                  onClick={() => ready(i)}
                  disabled={readyBusy}
                  className="flex items-center justify-between gap-2 rounded-xl border border-hairline px-3 py-2 text-left text-xs font-medium text-ink-2 transition-colors hover:border-blue/45 hover:bg-blue/8 hover:text-ink disabled:opacity-60"
                >
                  {q} <ArrowRight className="size-3.5 shrink-0 text-ink-3" />
                </button>
              ))}
            </div>
            {aiOff || used ? (
              <p className="rounded-xl bg-well px-3 py-2 text-xs text-ink-2">
                {aiOff ? 'Free questions need the AI, which isn’t set up for the portal yet. The two questions above still work.' : `Today’s ${status.data?.cap} free questions are used up. The two questions above still work.`}
              </p>
            ) : (
              <div className="flex items-end gap-2 rounded-xl border border-hairline bg-field px-3 py-2 transition-[border-color,box-shadow] focus-within:border-blue/60 focus-within:ring-3 focus-within:ring-blue/15">
                <textarea
                  ref={inputRef}
                  value={text}
                  onChange={(e) => setText(e.target.value.slice(0, 500))}
                  onKeyDown={(e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send() } }}
                  rows={1}
                  aria-label="Your question"
                  style={{ outline: 'none' }} /* the wrapper's border shows focus; the global :focus-visible ring would double it */
                  placeholder={info.placeholder}
                  className="max-h-28 min-h-6 flex-1 resize-none bg-transparent text-sm outline-none placeholder:text-ink-3 [field-sizing:content]"
                />
                <button onClick={send} disabled={!text.trim() || ask.isPending} aria-label="Send" className="btn-blue grid size-8 shrink-0 place-items-center rounded-lg disabled:opacity-30">
                  <SendHorizonal className="size-4" />
                </button>
              </div>
            )}
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

/** Question/answer pairs so far, sent along so follow-up questions ("and the critical ones?") make sense. */
function pairs(msgs: Msg[]) {
  const out: { question: string; answer: string }[] = []
  msgs.forEach((m, i) => {
    const next = msgs[i + 1]
    if (m.from === 'you' && next?.from === 'bot' && next.kind !== 'error' && next.kind !== 'screen') out.push({ question: m.text, answer: next.text })
  })
  return out
}
