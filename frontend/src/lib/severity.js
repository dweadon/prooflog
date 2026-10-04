// Colors, sort order and plain-English labels for each alert severity.
// `hint` explains the level to someone who isn't a security expert.
export const SEVERITY = {
  critical: { rank: 4, label: 'Urgent', hint: 'Someone may have got in. Act now.', badge: 'bg-red-500/15 text-red-300 ring-red-500/40', bar: 'bg-red-500' },
  high: { rank: 3, label: 'Serious', hint: 'A clear attack attempt.', badge: 'bg-orange-500/15 text-orange-300 ring-orange-500/40', bar: 'bg-orange-500' },
  medium: { rank: 2, label: 'Suspicious', hint: 'Repeated failed attempts worth knowing about.', badge: 'bg-amber-400/15 text-amber-200 ring-amber-400/40', bar: 'bg-amber-400' },
  low: { rank: 1, label: 'Unusual', hint: 'Odd, but possibly harmless.', badge: 'bg-sky-500/15 text-sky-300 ring-sky-500/40', bar: 'bg-sky-500' },
}

// Unknown severities still render (grey) instead of crashing.
export function severityStyle(severity) {
  return SEVERITY[severity] ?? { rank: 0, label: severity || 'Unknown', hint: '', badge: 'bg-slate-500/15 text-slate-300 ring-slate-500/40', bar: 'bg-slate-500' }
}

// Most severe first.
export function sortBySeverity(alerts) {
  return [...alerts].sort((a, b) => severityStyle(b.severity).rank - severityStyle(a.severity).rank)
}
