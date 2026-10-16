import { useState, type FormEvent } from 'react'
import { Link, Navigate, useLocation, useNavigate, useSearchParams } from 'react-router-dom'
import { CognitoError } from '@/lib/cognito'
import { safeNext, useAuth } from '@/lib/auth'
import { AuthHeading, AuthLayout, Field, FormError, Submit } from './AuthLayout'

export function Login() {
  const { user, config, ready, signIn } = useAuth()
  const [params] = useSearchParams()
  const navigate = useNavigate()
  const location = useLocation()
  const next = safeNext(params.get('next'))
  const [email, setEmail] = useState<string>((location.state as { email?: string } | null)?.email ?? '')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  if (ready && (user || config?.mode === 'off')) return <Navigate to={next} replace />

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setError(null)
    setBusy(true)
    try {
      await signIn(email.trim(), password)
      navigate(next, { replace: true })
    } catch (err) {
      if (err instanceof CognitoError && err.code === 'UserNotConfirmedException') {
        navigate('/signup', { state: { confirm: email.trim() } })
        return
      }
      setError(err instanceof Error ? err.message : 'Sign-in failed.')
      setPassword('')
    } finally {
      setBusy(false)
    }
  }

  return (
    <AuthLayout>
      <AuthHeading title="Sign in">Use your work email to open Defender &amp; Infrastructure.</AuthHeading>
      {ready && !config && <FormError message="The portal is not answering. Check that it is running, then reload this page." />}
      <form onSubmit={submit} className="space-y-5" noValidate>
        <Field label="Work email" type="email" autoComplete="username" inputMode="email" required autoFocus
          value={email} onChange={(e) => setEmail(e.target.value)} disabled={busy} invalid={!!error} />
        <Field label="Password" type="password" autoComplete="current-password" required
          value={password} onChange={(e) => setPassword(e.target.value)} disabled={busy} invalid={!!error} />
        <FormError message={error} />
        <Submit busy={busy} busyText="Signing in…">Sign in</Submit>
      </form>
      <p className="mt-6 text-center text-sm text-ink-3">
        {config?.signup_open === false ? (
          'Need access? Ask the portal owner to add you.'
        ) : (
          <>
            New here?{' '}
            <Link to={`/signup${params.get('next') ? `?next=${encodeURIComponent(next)}` : ''}`} className="font-medium text-sky underline-offset-4 hover:underline">
              Create an account
            </Link>
          </>
        )}
      </p>
    </AuthLayout>
  )
}
