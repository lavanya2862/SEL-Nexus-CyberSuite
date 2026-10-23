// Showing code: a fix's diff, the vulnerable lines with the finding highlighted, and Markdown text.
import { md } from '@/lib/md'
import { cn } from '@/lib/utils'

export function Diff({ diff }: { diff: string }) {
  if (!diff?.trim()) return <p className="text-sm text-ink-3">No changes.</p>
  return (
    <pre className="codebox">
      {diff.split('\n').map((l, i) => {
        const c = /^(\+\+\+|---|diff |index )/.test(l) ? 'f' : l.startsWith('+') ? 'a' : l.startsWith('-') ? 'd' : l.startsWith('@@') ? 'h' : ''
        return <span key={i} className={c}>{l || ' '}</span>
      })}
    </pre>
  )
}

export function CodeView({ code, start, from, to }: { code: string; start: number; from: number; to: number }) {
  return (
    <pre className="codebox">
      {code.split('\n').map((l, i) => {
        const n = start + i
        return <span key={i} className={cn(n >= from && n <= to && 'hl')}><span className="ln">{n}</span>{l || ' '}</span>
      })}
    </pre>
  )
}

/** Markdown from reports and the assistant. md() escapes its input first, so this HTML is safe to show. */
export function Markdown({ text, className }: { text: string; className?: string }) {
  return <div className={cn('md', className)} dangerouslySetInnerHTML={{ __html: md(text) }} />
}
