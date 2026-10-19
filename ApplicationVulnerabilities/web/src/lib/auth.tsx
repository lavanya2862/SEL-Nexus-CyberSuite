// Who is signed in. People sign in once on the shared SEL Nexus CyberSuite sign-in page (login/, port 8000); this
// site only reads the result through GET /api/v1/auth/me (remediation/suite_auth.py checks the shared cookie).
// Without SUITE_LOGIN_URL on the server (local use) everyone is "Local user" and there is nothing to sign in to.
import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'
import { useQueryClient } from '@tanstack/react-query'

export interface User { email: string; name: string; via: string; expires: number | null }

interface AuthState {
  user: User | null
  loginUrl: string | null
  ready: boolean
  signOut: () => Promise<void>
}

const AuthContext = createContext<AuthState | null>(null)
const SIGNED_OUT = 'appvuln:signed-out'

// Any /api/* answer of 401 (sign-in expired, signed out in another module) sends the person back to the sign-in page.
let watching = false
function watchForSignOut() {
  if (watching) return
  watching = true
  const original = window.fetch.bind(window)
  window.fetch = async (input, init) => {
    const res = await original(input, init)
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
    if (res.status === 401 && url.includes('/api/') && !url.includes('/api/v1/auth/') && res.headers.get('content-type')?.includes('json')) {
      const body = await res.clone().json().catch(() => ({}))
      if (String(body.detail ?? '').includes('sign-in page')) window.dispatchEvent(new Event(SIGNED_OUT))
    }
    return res
  }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient()
  const [user, setUser] = useState<User | null>(null)
  const [loginUrl, setLoginUrl] = useState<string | null>(null)
  const [ready, setReady] = useState(false)

  useEffect(() => {
    watchForSignOut()
    const onSignedOut = () => {
      setUser(null)
      queryClient.clear()
    }
    window.addEventListener(SIGNED_OUT, onSignedOut)
    fetch('/api/v1/auth/me')
      .then((r) => r.json())
      .then((me: { user: User | null; login_url: string | null }) => {
        setLoginUrl(me.login_url)
        setUser(me.user)
      })
      .catch(() => setUser({ email: 'local', name: 'Local user', via: 'off', expires: null }))
      .finally(() => setReady(true))
    return () => window.removeEventListener(SIGNED_OUT, onSignedOut)
  }, [queryClient])

  const signOut = useCallback(async () => {
    await fetch('/api/v1/auth/logout', { method: 'POST', headers: { 'X-CyberSuite': 'auth' } }).catch(() => undefined)
    queryClient.clear()
    setUser(null)
  }, [queryClient])

  const value = useMemo(() => ({ user, loginUrl, ready, signOut }), [user, loginUrl, ready, signOut])
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth needs <AuthProvider>')
  return ctx
}

/** Leaves this site for the shared sign-in page, which sends the person back to `next` afterwards. */
export function goToSharedLogin(loginUrl: string, next?: string) {
  window.location.replace(next ? `${loginUrl}/?next=${encodeURIComponent(next)}` : `${loginUrl}/`)
}

/** Pages need a signed-in person; everyone else goes to the shared sign-in page and comes back afterwards. */
export function RequireAuth({ children }: { children: ReactNode }) {
  const { user, loginUrl, ready } = useAuth()
  useEffect(() => {
    if (ready && !user && loginUrl) goToSharedLogin(loginUrl, window.location.href)
  }, [ready, user, loginUrl])
  if (!ready || (!user && loginUrl)) return <div className="min-h-svh bg-canvas" aria-busy="true" />
  return <>{children}</>
}
