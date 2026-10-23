import { useState, type FormEvent } from 'react'
import { Link, Navigate, useLocation, useNavigate, useSearchParams } from 'react-router-dom'
import { Check, MailCheck } from 'lucide-react'
import { safeNext, useAuth } from '@/lib/auth'
import { cn } from '@/lib/utils'
import { AuthHeading, AuthLayout, Field, FormError, Submit } from './AuthLayout'

// Same rule as the portal API and Amazon Cognito's default password policy
const RULES: [string, (p: string) => boolean][] = [
  ['8 or more characters', (p) => p.length >= 8],
  ['Upper- and lower-case letters', (p) => /[a-z]/.test(p) && /[A-Z]/.test(p)],
  ['A number', (p) => /\d/.test(p)],
  ['A symbol, like ! ? # -', (p) => /[^A-Za-z0-9]/.test(p)],
]

export function Signup() {
  const { user, config, ready, signUp } = useAuth()
  const [params] = useSearchParams()
  const navigate = useNavigate()
  const location = useLocation()
  const next = safeNext(params.get('next'))
  const [name, setName] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [confirmFor, setConfirmFor] = useState<string | null>((location.state as { confirm?: string } | null)?.confirm ?? null)

  if (ready && (user || config?.mode === 'off')) return <Navigate to={next} replace />
  if (confirmFor) return <ConfirmEmail email={confirmFor} password={password} next={next} />

  const domains = config?.allowed_email_domains ?? []
  const passwordOk = RULES.every(([, test]) => test(password))

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setError(null)
    if (!name.trim()) return setError('Enter your name.')
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email.trim())) return setError('Enter a valid email address.')
    if (!passwordOk) return setError('Choose a password that meets every rule below the password box.')
    setBusy(true)
    try {
      const result = await signUp(name.trim(), email.trim(), password)
      if (result === 'confirm_email') setConfirmFor(email.trim())
      else navigate(next, { replace: true })
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not create the account.')
    } finally {
      setBusy(false)
    }
  }

  if (ready && config?.signup_open === false) {
    return (
      <AuthLayout>
        <AuthHeading title="New accounts are closed">Ask the portal owner to add you, then sign in with the email they used.</AuthHeading>
        <Link to="/login" className="flex h-14 w-full items-center justify-center rounded-[10px] border border-hairline-strong bg-field text-[15px] font-medium hover:bg-well">
          Back to sign in
        </Link>
      </AuthLayout>
    )
  }

  return (
    <AuthLayout>
      <AuthHeading title="Create your account">
        {domains.length ? `Use your ${domains.map((d) => '@' + d).join(' or ')} email address.` : 'Use your work email address.'}
      </AuthHeading>
      <form onSubmit={submit} className="space-y-5" noValidate>
        <Field label="Full name" autoComplete="name" required autoFocus maxLength={80}
          value={name} onChange={(e) => setName(e.target.value)} disabled={busy} />
        <Field label="Work email" type="email" autoComplete="email" inputMode="email" required
          value={email} onChange={(e) => setEmail(e.target.value)} disabled={busy} />
        <Field
          label="Password" type="password" autoComplete="new-password" required
          value={password} onChange={(e) => setPassword(e.target.value)} disabled={busy}
          hint={
            <ul className="mt-1 grid grid-cols-1 gap-x-4 gap-y-1 sm:grid-cols-2" aria-label="Password rules">
              {RULES.map(([label, test]) => {
                const ok = test(password)
                return (
                  <li key={label} className={cn('flex items-center gap-1.5 transition-colors', ok && 'text-teal')}>
                    <span className={cn('grid size-3.5 place-items-center rounded-full border', ok ? 'border-teal bg-teal text-white' : 'border-hairline')}>
                      {ok && <Check className="size-2.5" strokeWidth={3} aria-hidden />}
                    </span>
                    {label}
                    <span className="sr-only">{ok ? ' (done)' : ' (not yet)'}</span>
                  </li>
                )
              })}
            </ul>
          }
        />
        <FormError message={error} />
        <Submit busy={busy} busyText="Creating account…">Create account</Submit>
      </form>
      <p className="mt-6 text-center text-sm text-ink-3">
        Already have an account?{' '}
        <Link to="/login" className="font-medium text-sky underline-offset-4 hover:underline">Sign in</Link>
      </p>
    </AuthLayout>
  )
}

/** Amazon Cognito only: the 6-digit code Cognito emails after sign-up. */
function ConfirmEmail({ email, password, next }: { email: string; password: string; next: string }) {
  const { confirm, resendCode } = useAuth()
  const navigate = useNavigate()
  const [code, setCode] = useState('')
  const [pw, setPw] = useState(password)
  const [error, setError] = useState<string | null>(null)
  const [note, setNote] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setError(null)
    setBusy(true)
    try {
      await confirm(email, code.trim(), pw)
      navigate(next, { replace: true })
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not confirm the code.')
    } finally {
      setBusy(false)
    }
  }

  const resend = async () => {
    setError(null)
    try {
      await resendCode(email)
      setNote('A new code is on its way.')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not send a new code.')
    }
  }

  return (
    <AuthLayout>
      <div className="tile-signal mb-6 grid size-11 place-items-center rounded-[11px]">
        <MailCheck className="size-5 text-sky" aria-hidden />
      </div>
      <AuthHeading title="Check your email">
        We sent a 6-digit code to <span className="font-medium text-ink">{email}</span>. Enter it to finish your account.
      </AuthHeading>
      <form onSubmit={submit} className="space-y-5" noValidate>
        <Field label="Code" autoComplete="one-time-code" inputMode="numeric" required autoFocus maxLength={8}
          className="[&_input]:tabular [&_input]:tracking-[0.3em]"
          value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))} disabled={busy} />
        {!password && (
          <Field label="Password" type="password" autoComplete="current-password" required
            hint="The password you chose when you signed up." value={pw} onChange={(e) => setPw(e.target.value)} disabled={busy} />
        )}
        <FormError message={error} />
        {note && !error && <p className="text-sm text-ink-2" aria-live="polite">{note}</p>}
        <Submit busy={busy} busyText="Confirming…">Confirm and sign in</Submit>
      </form>
      <p className="mt-6 text-center text-sm text-ink-3">
        No email?{' '}
        <button type="button" onClick={resend} className="font-medium text-sky underline-offset-4 hover:underline">Send a new code</button>
        {' · '}
        <Link to="/login" state={{ email }} className="font-medium text-sky underline-offset-4 hover:underline">Sign in</Link>
      </p>
    </AuthLayout>
  )
}
