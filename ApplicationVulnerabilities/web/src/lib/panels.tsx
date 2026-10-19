// Two things any page can open: the details of one finding (a drawer from the right) and the Security Assistant
// (the chat in the bottom-right corner, told what you are looking at).
import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { post } from '@/lib/api'
import { useToast } from '@/lib/toast'

export type ChatContext =
  | { type: 'general' }
  | { type: 'run'; jobId: string; label: string }
  | { type: 'finding'; jobId: string; findingId: string; label: string }

interface Panels {
  finding: { jobId: string; findingId: string } | null
  openFinding: (jobId: string, findingId: string) => void
  closeFinding: () => void
  chat: { open: boolean; ctx: ChatContext }
  openChat: (ctx?: ChatContext) => void
  setChatContext: (ctx: ChatContext) => void
  closeChat: () => void
}

const PanelsContext = createContext<Panels | null>(null)

export function PanelsProvider({ children }: { children: ReactNode }) {
  const [finding, setFinding] = useState<Panels['finding']>(null)
  const [chat, setChat] = useState<Panels['chat']>({ open: false, ctx: { type: 'general' } })
  const openFinding = useCallback((jobId: string, findingId: string) => setFinding({ jobId, findingId }), [])
  const closeFinding = useCallback(() => setFinding(null), [])
  const openChat = useCallback((ctx?: ChatContext) => setChat((c) => ({ open: true, ctx: ctx ?? c.ctx })), [])
  const setChatContext = useCallback((ctx: ChatContext) => setChat((c) => (sameCtx(c.ctx, ctx) ? c : { ...c, ctx })), [])
  const closeChat = useCallback(() => setChat((c) => ({ ...c, open: false })), [])
  const value = useMemo(() => ({ finding, openFinding, closeFinding, chat, openChat, setChatContext, closeChat }),
    [finding, openFinding, closeFinding, chat, openChat, setChatContext, closeChat])
  return <PanelsContext.Provider value={value}>{children}</PanelsContext.Provider>
}

export const chatKey = (c: ChatContext) => (c.type === 'finding' ? `f:${c.jobId}:${c.findingId}` : c.type === 'run' ? `r:${c.jobId}` : 'general')
const sameCtx = (a: ChatContext, b: ChatContext) => chatKey(a) === chatKey(b) && ('label' in a ? a.label : '') === ('label' in b ? b.label : '')

export function usePanels(): Panels {
  const ctx = useContext(PanelsContext)
  if (!ctx) throw new Error('usePanels needs <PanelsProvider>')
  return ctx
}

/** Human approval: push the fix branch and open the pull request (draft when validation flagged it). */
export function useApprove() {
  const qc = useQueryClient()
  const toast = useToast()
  return useMutation({
    mutationFn: (jobId: string) => post<{ status: string; pull_request_url?: string }>(`/api/v1/jobs/${jobId}/publish`),
    onSuccess: (r) => {
      toast(r.status === 'exists' ? 'A pull request already exists.' : 'Approved: pushing the branch and opening the pull request…')
      qc.invalidateQueries()
    },
    onError: (e) => toast((e as Error).message, true),
  })
}
