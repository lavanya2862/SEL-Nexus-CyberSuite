// Shared frame and form parts for the sign-in and sign-up pages: headline on the dot field, form in a bordered card.
import { useId, useState, type InputHTMLAttributes, type ReactNode } from 'react'
import { AlertCircle, Eye, EyeOff, Loader2, Radar, ScanSearch, Siren, Wrench } from 'lucide-react'
import { Wordmark } from '@/components/Brand'
import { useAuth } from '@/lib/auth'
import { cn } from '@/lib/utils'

const AREAS = [
  { icon: Radar, label: 'Threat news & hunting', hint: 'New threats checked against our devices' },
  { icon: ScanSearch, label: 'Vulnerability management', hint: 'Software flaws, weak settings and unsupported software across every OpCo' },
  { icon: Wrench, label: 'Fix & protect', hint: 'What to patch, upgrade or lock down first, and progress' },
  { icon: Siren, label: 'Alert response', hint: 'Defender alerts triaged by the agent' },
]

export function AuthLayout({ children }: { children: ReactNode }) {
  const { config } = useAuth()
  const via = config?.mode === 'cognito' ? 'Amazon Cognito' : 'this portal'
  return (
    <div className="relative flex min-h-svh flex-col text-ink">
      <header className="relative z-10 px-5 pt-6 sm:px-10 lg:px-16 lg:pt-10">
        <Wordmark />
      </header>

      <div className="relative z-10 mx-auto grid w-full max-w-[1340px] flex-1 items-center gap-12 px-4 py-10 sm:px-10 lg:grid-cols-[minmax(0,1fr)_minmax(0,580px)] lg:gap-12 lg:px-16 xl:gap-16">
        <section className="hidden lg:block">
          <h2 className="text-[44px] font-bold leading-[1.08] tracking-[-0.03em] [text-wrap:balance] xl:text-[54px]">
            Enterprise&#8209;Wide Security.
            <span className="block text-sky">One Unified Platform.</span>
          </h2>
          <p className="mt-6 max-w-[34rem] text-lg leading-relaxed text-ink-2">
            Threat intelligence, vulnerabilities, fixes and alert triage from Microsoft Defender, side by side.
          </p>
          <ul className="mt-12 grid max-w-[38rem] grid-cols-2 gap-x-6 gap-y-7">
            {AREAS.map(({ icon: Icon, label, hint }) => (
              <li key={label} className="flex items-start gap-3.5">
                <span className="tile-signal grid size-10 shrink-0 place-items-center rounded-[10px]">
                  <Icon className="size-[18px]" aria-hidden />
                </span>
                <span className="pt-0.5">
                  <span className="block whitespace-nowrap text-[15px] font-semibold">{label}</span>
                  <span className="mt-0.5 block text-sm leading-snug text-ink-3">{hint}</span>
                </span>
              </li>
            ))}
          </ul>
        </section>

        <main className="portal-rise glass-card mx-auto w-full max-w-[580px] overflow-hidden rounded-[24px] shadow-float">
          <div className="px-6 pb-8 pt-9 sm:px-14 sm:pb-11 sm:pt-12">{children}</div>
        </main>
      </div>

      <p className="relative z-10 px-4 pb-6 text-center text-xs text-ink-3">Sign-in handled by {via}</p>
    </div>
  )
}

export function AuthHeading({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <header className="mb-8">
      <h1 className="text-[28px] font-bold leading-tight tracking-[-0.02em] sm:text-[30px]">{title}</h1>
      {children && <p className="mt-2.5 text-[15px] leading-relaxed text-ink-3">{children}</p>}
    </header>
  )
}

const inputClass =
  'h-14 w-full rounded-[10px] border border-hairline-strong bg-field px-4 text-[15px] text-ink outline-none transition-[border-color,box-shadow] placeholder:text-ink-3 ' +
  'hover:border-[color-mix(in_oklab,var(--hairline-strong),var(--ink-3)_35%)] focus:border-blue focus:ring-4 focus:ring-blue/15 aria-invalid:border-rose aria-invalid:ring-rose/15 disabled:opacity-60'

interface FieldProps extends InputHTMLAttributes<HTMLInputElement> {
  label: string
  hint?: ReactNode
  invalid?: boolean
}

export function Field({ label, hint, invalid, className, type, ...props }: FieldProps) {
  const id = useId()
  const [shown, setShown] = useState(false)
  const isPassword = type === 'password'
  return (
    <div className={cn('space-y-2', className)}>
      <label htmlFor={id} className="block text-sm font-medium text-ink">{label}</label>
      <div className="relative">
        <input
          id={id}
          type={isPassword && shown ? 'text' : type}
          aria-invalid={invalid || undefined}
          aria-describedby={hint ? `${id}-hint` : undefined}
          style={{ outline: 'none' }}
          className={cn(inputClass, isPassword && 'pr-14')}
          {...props}
        />
        {isPassword && (
          <button
            type="button"
            onClick={() => setShown((s) => !s)}
            className="absolute inset-y-0 right-0 grid w-14 place-items-center rounded-r-[10px] text-ink-3 transition-colors hover:text-ink"
            aria-label={shown ? 'Hide password' : 'Show password'}
            aria-pressed={shown}
          >
            {shown ? <EyeOff className="size-[18px]" /> : <Eye className="size-[18px]" />}
          </button>
        )}
      </div>
      {hint && <div id={`${id}-hint`} className="text-[13px] text-ink-3">{hint}</div>}
    </div>
  )
}

export function FormError({ message }: { message: string | null }) {
  return (
    <div aria-live="assertive">
      {message && (
        <p role="alert" className="flex items-start gap-2 rounded-xl border border-rose/35 bg-rose/10 px-3.5 py-3 text-sm text-ink">
          <AlertCircle className="mt-0.5 size-4 shrink-0 text-rose" aria-hidden />
          {message}
        </p>
      )}
    </div>
  )
}

export function Submit({ busy, children, busyText }: { busy: boolean; children: ReactNode; busyText: string }) {
  return (
    <button
      type="submit"
      disabled={busy}
      className="btn-blue flex h-14 w-full items-center justify-center gap-2 rounded-[10px] text-[15px] font-semibold disabled:opacity-70"
    >
      {busy && <Loader2 className="size-4 animate-spin" aria-hidden />}
      {busy ? busyText : children}
    </button>
  )
}
