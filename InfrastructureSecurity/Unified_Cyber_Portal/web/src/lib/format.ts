const nf = new Intl.NumberFormat('en-GB')

export const num = (v: number | null | undefined) => (v == null ? '–' : nf.format(v))

/** A data-quality status in words (the pipelines store PASS / WARN / FAIL / INFO) */
export const qualityWord = (s: string | null | undefined) =>
  s ? ({ PASS: 'Passed', WARN: 'Warning', FAIL: 'Failed', INFO: 'Info', ERROR: 'Failed' } as Record<string, string>)[s.toUpperCase()] ?? s : '–'

export function ago(iso: string | null | undefined): string {
  if (!iso) return 'never'
  const mins = Math.round((Date.now() - new Date(iso).getTime()) / 60000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins} min ago`
  const hours = Math.round(mins / 60)
  if (hours < 48) return `${hours} h ago`
  return `${Math.round(hours / 24)} days ago`
}

/** A timestamp written in UTC without a zone (UC1's fix state) as ISO the browser reads as UTC, not local time */
export const utc = (s: string | null | undefined) => (s ? s.replace(' ', 'T') + (s.endsWith('Z') || s.includes('+') ? '' : 'Z') : null)

export function dateTime(iso: string | null | undefined): string {
  if (!iso) return '–'
  return new Date(iso).toLocaleString('en-GB', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' })
}

export const shortDate = (d: string) => new Date(d).toLocaleDateString('en-GB', { day: 'numeric', month: 'short' })
