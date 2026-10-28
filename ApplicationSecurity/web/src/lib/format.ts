const nf = new Intl.NumberFormat('en-GB')

export const num = (v: number | null | undefined) => (v == null ? '–' : nf.format(v))

export function ago(iso: string | null | undefined): string {
  if (!iso) return 'never'
  const mins = Math.round((Date.now() - new Date(iso).getTime()) / 60000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins} min ago`
  const hours = Math.round(mins / 60)
  if (hours < 48) return `${hours} h ago`
  return `${Math.round(hours / 24)} days ago`
}

export function dateTime(iso: string | null | undefined): string {
  if (!iso) return '–'
  return new Date(iso).toLocaleString('en-GB', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' })
}

/** Full date and time for the activity log, e.g. "28 Oct 2026, 14:05:09". */
export function stamp(iso: string | null | undefined): string {
  if (!iso) return '–'
  return new Date(iso).toLocaleString('en-GB', { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

/** "Ana (ana@example.com)", or whichever of the two is known. */
export function personLabel(p: { name: string | null; email: string | null }): string {
  if (p.name && p.email && p.name !== p.email) return `${p.name} (${p.email})`
  return p.name || p.email || 'someone'
}

export const shortDate = (d: string) => new Date(d).toLocaleDateString('en-GB', { day: 'numeric', month: 'short' })
