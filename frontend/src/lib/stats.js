import { parseLog } from './scan.js'
import { severityStyle } from './severity.js'

// Numbers for the Summary, Attackers and Scores tabs, all computed from the
// report itself. The log lines are re-read with the same parser as the backend
// (scan.js), so every figure can be traced back to lines in the log.

const IPV4 = /\b\d{1,3}(?:\.\d{1,3}){3}\b/g
const pct = (part, whole) => (whole ? Math.round((part / whole) * 1000) / 10 : 0) // one decimal
export const fmtTime = (ms) => (ms == null ? '—' : new Date(ms).toISOString().slice(0, 19).replace('T', ' '))

export function computeStats(report) {
  const parsed = parseLog(report.log_lines.map((l) => l.text).join('\n'))
  parsed.forEach((p, i) => (p.line = report.log_lines[i]?.line ?? p.line)) // keep the report's numbering
  const byLine = new Map(parsed.map((p) => [p.line, p]))

  // Lines each finding cites (through its statements), and every cited line.
  const linesByAlert = new Map()
  for (const c of report.claims) {
    if (!linesByAlert.has(c.alert_id)) linesByAlert.set(c.alert_id, new Set())
    c.evidence_lines.forEach((n) => linesByAlert.get(c.alert_id).add(n))
  }
  const citedLines = new Set([...linesByAlert.values()].flatMap((s) => [...s]))

  // Which addresses each finding is about: IPs named in its summary, plus IPs on its cited lines.
  const ipsByAlert = new Map()
  for (const a of report.alerts) {
    const ips = new Set(a.summary.match(IPV4) ?? [])
    for (const n of linesByAlert.get(a.id) ?? []) if (byLine.get(n)?.ip) ips.add(byLine.get(n).ip)
    ipsByAlert.set(a.id, ips)
  }
  const flagged = new Set([...ipsByAlert.values()].flatMap((s) => [...s]))

  // Per-address activity.
  const ips = new Map()
  const totals = { failed: 0, invalid: 0, accepted: 0, disconnect: 0, other: 0 }
  let first = null
  let last = null
  for (const p of parsed) {
    if (p.ms !== null) {
      first = first === null ? p.ms : Math.min(first, p.ms)
      last = last === null ? p.ms : Math.max(last, p.ms)
    }
    const kind = { failed_password: 'failed', invalid_user: 'invalid', accepted_login: 'accepted', disconnect: 'disconnect' }[p.type] ?? 'other'
    totals[kind] += kind === 'failed' ? p.repeat : 1
    if (!p.ip || kind === 'other' || kind === 'disconnect') continue
    if (!ips.has(p.ip)) ips.set(p.ip, { ip: p.ip, failed: 0, invalid: 0, accepted: 0, users: new Set(), first: p.ms, last: p.ms })
    const s = ips.get(p.ip)
    s[kind] += kind === 'failed' ? p.repeat : 1
    if (p.user !== null) s.users.add(p.user)
    if (p.ms !== null) {
      s.first = s.first === null ? p.ms : Math.min(s.first, p.ms)
      s.last = s.last === null ? p.ms : Math.max(s.last, p.ms)
    }
  }

  const attackers = [...ips.values()]
    .filter((s) => flagged.has(s.ip))
    .map((s) => ({
      ...s,
      users: [...s.users].sort(),
      alerts: report.alerts.filter((a) => ipsByAlert.get(a.id).has(s.ip)),
    }))
    .sort((a, b) => b.failed - a.failed || a.ip.localeCompare(b.ip))

  // "Login attempts" = failed passwords + successful logins.
  const attempts = totals.failed + totals.accepted
  const attackAttempts = attackers.reduce((n, a) => n + a.failed + a.accepted, 0)
  const attackerLogins = attackers.filter((a) => a.accepted > 0)
  const accountsTargeted = new Set(attackers.flatMap((a) => a.users))

  const bySeverity = {}
  for (const a of report.alerts) bySeverity[a.severity] = (bySeverity[a.severity] ?? 0) + 1
  const worst = [...report.alerts].sort((a, b) => severityStyle(b.severity).rank - severityStyle(a.severity).rank)[0]
  const proven = report.claims.filter((c) => c.verified).length

  return {
    lines: report.log_lines.length,
    first, last, totals, attempts, attackers, attackerLogins, accountsTargeted,
    citedLines, ipsByAlert, bySeverity, worst,
    percent: {
      attackShare: pct(attackAttempts, attempts),
      failureRate: pct(totals.failed, attempts),
      proven: pct(proven, report.claims.length),
      coverage: pct(citedLines.size, report.log_lines.length),
    },
    proven,
  }
}

// One-line verdict for the result header, from the most serious finding.
export function verdictFor(stats) {
  if (!stats.worst) return { text: 'No threats found', tone: 'clean' }
  if (stats.attackerLogins.length) return { text: 'An attacker may have got in', tone: 'critical' }
  return {
    critical: { text: 'An attacker may have got in', tone: 'critical' },
    high: { text: 'Your server is under attack', tone: 'high' },
    medium: { text: 'Repeated break-in attempts', tone: 'medium' },
    low: { text: 'Some unusual activity', tone: 'low' },
  }[stats.worst.severity] ?? { text: 'Suspicious activity', tone: 'medium' }
}
