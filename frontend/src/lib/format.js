// Formats a timestamp for display.
// Times that include a timezone (e.g. "2026-10-03T02:01:58Z") are shown in UTC,
// so they match the timestamps inside the log lines, whatever the viewer's timezone.
// ISO times without a timezone (e.g. syslog, which has none) are shown as-is, just
// tidied ("2025-12-10 07:13:43"), because guessing their timezone could show the wrong time.
// Anything else is shown exactly as the backend sent it.
const ISO_WITH_ZONE = /^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:?\d{2})$/i
const ISO_NO_ZONE = /^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?$/

export function formatTime(value) {
  if (!value) return '—'
  const text = String(value).trim()
  if (ISO_NO_ZONE.test(text)) return text.replace('T', ' ')
  if (!ISO_WITH_ZONE.test(text)) return text
  const d = new Date(text.replace(' ', 'T'))
  if (Number.isNaN(d.getTime())) return text
  return `${d.toISOString().slice(0, 19).replace('T', ' ')} UTC`
}

// Time range for an alert. Shows a single time when start and end are the same.
export function formatRange(first, last) {
  const a = formatTime(first)
  const b = formatTime(last)
  return a === b || !last ? a : `${a} → ${b}`
}
