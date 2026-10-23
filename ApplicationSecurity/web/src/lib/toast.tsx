// Small confirmations in the bottom-left corner ("Approved: opening the pull request…"). Errors stay a little longer.
import { createContext, useCallback, useContext, useState, type ReactNode } from 'react'
import { CheckCircle2, XCircle } from 'lucide-react'
import { statusColor } from '@/lib/theme'

interface Toast { id: number; text: string; error: boolean }
const ToastContext = createContext<(text: string, error?: boolean) => void>(() => {})
let nextId = 1

export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<Toast[]>([])
  const show = useCallback((text: string, error = false) => {
    const id = nextId++
    setItems((list) => [...list, { id, text, error }])
    setTimeout(() => setItems((list) => list.filter((t) => t.id !== id)), error ? 7000 : 3500)
  }, [])
  return (
    <ToastContext.Provider value={show}>
      {children}
      <div className="pointer-events-none fixed bottom-4 left-4 z-50 flex max-w-[min(420px,calc(100vw-6rem))] flex-col gap-2" aria-live="polite">
        {items.map((t) => (
          <div key={t.id} className="flex items-start gap-2.5 rounded-xl border border-hairline bg-raised px-4 py-3 text-sm text-ink shadow-float animate-in fade-in slide-in-from-bottom-2">
            {t.error ? <XCircle className="mt-0.5 size-4 shrink-0" style={{ color: statusColor.critical }} /> : <CheckCircle2 className="mt-0.5 size-4 shrink-0" style={{ color: statusColor.good }} />}
            <span>{t.text}</span>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  )
}

export const useToast = () => useContext(ToastContext)
