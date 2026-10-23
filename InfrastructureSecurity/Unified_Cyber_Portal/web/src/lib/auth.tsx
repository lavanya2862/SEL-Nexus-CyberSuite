// Who is signed in. The portal API decides (src/portal/auth.py): local accounts today, Amazon Cognito later
// (PORTAL_AUTH=cognito, no rebuild needed: the pool ids come from /api/auth/config). Either way the browser ends up
// with the portal's own HttpOnly session cookie, so the rest of the app just calls /api/* as before.
// In the SEL Nexus CyberSuite layout (PORTAL_LOGIN_URL set) the shared sign-in page sets that cookie instead, and
// signed-out visitors are sent there.
import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'
import { Navigate, useLocation, useSearchParams } from 'react-router-dom'
import { useQueryClient } from '@tanstack/react-query'
import { cognitoConfirm, cognitoResendCode, cognitoSignIn, cognitoSignUp, type CognitoConfig } from '@/lib/cognito'

export interface User {
  email: string
  name: string
  via: 'local' | 'cognito' | 'off'
  expires: number | null
}

export interface AuthConfig {
  mode: 'local' | 'cognito' | 'off'
  signup_open: boolean
  password_rule: string
  allowed_email_domains: string[]
  cognito: CognitoConfig | null
  /** the shared SEL Nexus CyberSuite sign-in page; when set, people sign in and out there, not on this portal */
  login_url?: string | null
}

export type SignUpResult = 'signed_in' | 'confirm_email'

interface AuthState {
  user: User | null
  config: AuthConfig | null
  ready: boolean
  signIn: (email: string, password: string) => Promise<void>
  signUp: (name: string, email: string, password: string) => Promise<SignUpResult>
  confirm: (email: string, code: string, password: string) => Promise<void>
  resendCode: (email: string) => Promise<void>
  signOut: () => Promise<void>
}

const AuthContext = createContext<AuthState | null>(null)
const SIGNED_OUT = 'portal:signed-out'

// Any /api/* answer of 401 (session expired, key changed) sends the person back to the sign-in page.
let watching = false
function watchForSignOut() {
  if (watching) return
  watching = true
  const original = window.fetch.bind(window)
  window.fetch = async (input, init) => {
    const res = await original(input, init)
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
    if (res.status === 401 && url.includes('/api/') && !url.includes('/api/auth/')) window.dispatchEvent(new Event(SIGNED_OUT))
    return res
  }
}

async function post(path: string, body: object = {}): Promise<{ user: User | null }> {
  const res = await fetch(`/api/auth/${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Portal': 'auth' },
    body: JSON.stringify(body),
  })
  const data = await res.json().catch(() => ({}))
  if (!res.ok) throw new Error(data.error || `The portal answered ${res.status}`)
  return data
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient()
  const [user, setUser] = useState<User | null>(null)
  const [config, setConfig] = useState<AuthConfig | null>(null)
  const [ready, setReady] = useState(false)

  useEffect(() => {
    watchForSignOut()
    const onSignedOut = () => {
      setUser(null)
      queryClient.clear()
    }
    window.addEventListener(SIGNED_OUT, onSignedOut)
    Promise.all([fetch('/api/auth/config'), fetch('/api/auth/me')])
      .then(async ([cfg, me]) => {
        if (cfg.status === 404) {
          // a portal API from before sign-in existed: it has no accounts, so nothing to sign in to
          setConfig({ mode: 'off', signup_open: false, password_rule: '', allowed_email_domains: [], cognito: null })
          setUser({ email: 'local', name: 'Local user', via: 'off', expires: null })
          return
        }
        if (!cfg.ok) throw new Error(`Portal API answered ${cfg.status}`)
        setConfig(await cfg.json())
        setUser((await me.json()).user ?? null)
      })
      .catch(() => setConfig(null))
      .finally(() => setReady(true))
    return () => window.removeEventListener(SIGNED_OUT, onSignedOut)
  }, [queryClient])

  const cognito = useCallback(() => {
    if (!config?.cognito) throw new Error('Amazon Cognito is not set up on this portal.')
    return config.cognito
  }, [config])

  const signIn = useCallback(async (email: string, password: string) => {
    const out = config?.mode === 'cognito'
      ? await post('cognito', { id_token: await cognitoSignIn(cognito(), email, password) })
      : await post('login', { email, password })
    queryClient.clear()
    setUser(out.user)
  }, [config, cognito, queryClient])

  const signUp = useCallback(async (name: string, email: string, password: string): Promise<SignUpResult> => {
    if (config?.mode === 'cognito') {
      const { confirmed } = await cognitoSignUp(cognito(), name, email, password)
      if (!confirmed) return 'confirm_email'
      await signIn(email, password)
      return 'signed_in'
    }
    const out = await post('signup', { name, email, password })
    queryClient.clear()
    setUser(out.user)
    return 'signed_in'
  }, [config, cognito, signIn, queryClient])

  const confirm = useCallback(async (email: string, code: string, password: string) => {
    await cognitoConfirm(cognito(), email, code)
    await signIn(email, password)
  }, [cognito, signIn])

  const resendCode = useCallback((email: string) => cognitoResendCode(cognito(), email), [cognito])

  const signOut = useCallback(async () => {
    await post('logout').catch(() => undefined)
    queryClient.clear()
    setUser(null)
  }, [queryClient])

  const value = useMemo(() => ({ user, config, ready, signIn, signUp, confirm, resendCode, signOut }),
    [user, config, ready, signIn, signUp, confirm, resendCode, signOut])
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth needs <AuthProvider>')
  return ctx
}

/** Leaves this portal for the shared CyberSuite sign-in page, which sends the person back to `next` afterwards. */
export function goToSharedLogin(loginUrl: string, next?: string) {
  window.location.replace(next ? `${loginUrl}/?next=${encodeURIComponent(next)}` : `${loginUrl}/`)
}

function SharedLoginRedirect({ loginUrl, next }: { loginUrl: string; next?: string }) {
  useEffect(() => goToSharedLogin(loginUrl, next), [loginUrl, next])
  return <div className="min-h-svh bg-canvas" aria-busy="true" />
}

/** This portal's own /login and /signup pages, unless the shared CyberSuite sign-in page is in use. */
export function LocalSignIn({ children }: { children: ReactNode }) {
  const { config, ready } = useAuth()
  const [params] = useSearchParams()
  if (!ready) return <div className="min-h-svh bg-canvas" aria-busy="true" />
  if (config?.login_url) return <SharedLoginRedirect loginUrl={config.login_url} next={window.location.origin + safeNext(params.get('next'))} />
  return <>{children}</>
}

/** Pages inside need a signed-in person; everyone else goes to /login and comes back afterwards. */
export function RequireAuth({ children }: { children: ReactNode }) {
  const { user, config, ready } = useAuth()
  const location = useLocation()
  if (!ready) return <div className="min-h-svh bg-canvas" aria-busy="true" />
  if (!user && config?.login_url) return <SharedLoginRedirect loginUrl={config.login_url} next={window.location.href} />
  if (!user) {
    const next = location.pathname + location.search
    return <Navigate to={next && next !== '/' ? `/login?next=${encodeURIComponent(next)}` : '/login'} replace />
  }
  return <>{children}</>
}

/** Only allow a same-site path after sign-in (never another website). */
export function safeNext(next: string | null): string {
  return next && next.startsWith('/') && !next.startsWith('//') && !next.startsWith('/\\') && !next.startsWith('/login') && !next.startsWith('/signup') ? next : '/'
}
