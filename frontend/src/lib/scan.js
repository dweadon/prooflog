// Instant in-browser scan: the same parser and detection rules as the Python
// backend (engine/parser.py and engine/detect.py), ported to JavaScript so a
// dropped log file can be scanned on the website without any server.
// The file never leaves the browser. There's no AI here: every finding is a
// fact computed directly from the log lines it cites.

// ---- Thresholds (same as engine/detect.py) -----------------------------------------
const BRUTE_FORCE_MIN_FAILURES = 5
const BRUTE_FORCE_WINDOW_SECONDS = 600
const SPRAY_MIN_USERNAMES = 4
const SPRAY_WINDOW_SECONDS = 1800
const SPRAY_MAX_TOP_USERNAME_SHARE = 0.6
const SUCCESS_MIN_PRIOR_FAILURES = 5
const SUCCESS_LOOKBACK_SECONDS = 3600
const ODD_HOUR_START = 0
const ODD_HOUR_END = 6
const MAX_FILE_BYTES = 20 * 1024 * 1024

// ---- Parsing (same patterns as engine/parser.py) -------------------------------------
const HEADER = /^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^\s[:]+)(?:\[\d+\])?:\s?(.*)$/
const IP = '(?<ip>\\d{1,3}(?:\\.\\d{1,3}){3}|[0-9A-Fa-f]*:[0-9A-Fa-f:.]*)'
const PORT = '(?: port \\d+)?'
// Usernames match greedily, so the LAST "from <ip>" wins and a username can't fake the IP.
const EVENT_PATTERNS = [
  ['failed_password', new RegExp(`^Failed \\S+ for (?:invalid user )?(?<user>.*) from ${IP} port \\d+`)],
  ['accepted_login', new RegExp(`^Accepted \\S+ for (?<user>.*) from ${IP} port \\d+`)],
  ['invalid_user', new RegExp(`^Invalid user (?<user>.*) from ${IP}${PORT}\\s*$`)],
  ['disconnect', new RegExp(`^(?:error: )?Received disconnect from ${IP}${PORT}:`)],
  ['disconnect', new RegExp(
    `^(?:Disconnected from|Connection closed by|Connection reset by) (?:(?:invalid |authenticating )?user (?<user>.*) )?${IP}${PORT}(?: \\[preauth\\])?\\s*$`)],
]
const USERNAME_ONLY_PATTERNS = [
  /^input_userauth_request: invalid user (?<user>.*) \[preauth\]\s*$/,
  /^Disconnecting: Too many authentication failures for (?:invalid user )?(?<user>.*) \[preauth\]\s*$/,
  /^pam_unix\(sshd:\w+\): session (?:opened|closed) for user (?<user>\S+)/,
  /\buser=(?<user>\S+)\s*$/,
]
const REPEATED = /^message repeated (\d+) times: \[\s?(.*?)\s?\]\s*$/
const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']

// Returns the IP if it's a real IPv4/IPv6 address, otherwise null.
function validIp(value) {
  if (!value) return null
  if (value.includes(':')) {
    try {
      new URL(`http://[${value}]/`)
      return value
    } catch {
      return null
    }
  }
  return value.split('.').every((p) => Number(p) <= 255 && String(Number(p)) === p) ? value : null
}

// Reads an sshd message: [eventType, username, ip, repeatCount].
function classifyMessage(msg) {
  let repeat = 1
  const rep = msg.match(REPEATED)
  if (rep) {
    repeat = Number(rep[1])
    msg = rep[2]
  }
  for (const [type, pattern] of EVENT_PATTERNS) {
    const m = msg.match(pattern)
    if (m) return [type, m.groups.user ?? null, validIp(m.groups.ip), repeat]
  }
  for (const pattern of USERNAME_ONLY_PATTERNS) {
    const m = msg.match(pattern)
    if (m) return ['other', m.groups.user, null, 1]
  }
  return ['other', null, null, 1]
}

// "Dec 10 06:55:46" + year -> milliseconds (UTC, so the viewer's timezone never shifts it), or null.
function parseTimestamp(ts, year) {
  const [mon, day, time] = ts.split(/\s+/)
  const month = MONTHS.indexOf(mon)
  const [h, mi, s] = time.split(':').map(Number)
  const d = Number(day)
  if (month < 0 || d < 1 || d > 31 || h > 23 || mi > 59 || s > 59) return null
  const ms = Date.UTC(year, month, d, h, mi, s)
  return new Date(ms).getUTCDate() === d ? ms : null // rejects e.g. Feb 31
}

// ms -> "2025-12-10T06:55:46" (no timezone, like the backend).
const isoTime = (ms) => new Date(ms).toISOString().slice(0, 19)

// Parses the whole text into numbered lines. Syslog has no year: use the most
// recent year that doesn't put the log in the future, rolling over at Dec -> Jan.
function parseWithYear(lines, startYear) {
  let year = startYear
  let prevMonth = null
  return lines.map((text, i) => {
    const out = { line: i + 1, text, ms: null, ip: null, user: null, type: 'other', repeat: 1 }
    const h = text.match(HEADER)
    if (!h) return out
    let ms = parseTimestamp(h[1], year)
    if (ms !== null) {
      const month = new Date(ms).getUTCMonth()
      if (prevMonth !== null && month < prevMonth) {
        year += 1
        ms = parseTimestamp(h[1], year)
      }
      prevMonth = new Date(ms).getUTCMonth()
      out.ms = ms
    }
    if (h[3].startsWith('sshd')) [out.type, out.user, out.ip, out.repeat] = classifyMessage(h[4])
    return out
  })
}

export function parseLog(text) {
  const lines = text.split(/\r\n|\n|\r/)
  if (lines.length && lines[lines.length - 1] === '') lines.pop()
  const now = Date.now()
  let parsed = parseWithYear(lines, new Date(now).getUTCFullYear())
  const first = parsed.find((l) => l.ms !== null)
  if (first && first.ms > now + 86400000) parsed = parseWithYear(lines, new Date(now).getUTCFullYear() - 1)
  return parsed
}

// ---- Detection (same rules as engine/detect.py) --------------------------------------
function linesByIp(lines, types) {
  const groups = new Map()
  for (const l of lines) {
    if (types.has(l.type) && l.ip && l.ms !== null) {
      if (!groups.has(l.ip)) groups.set(l.ip, [])
      groups.get(l.ip).push(l)
    }
  }
  for (const events of groups.values()) events.sort((a, b) => a.ms - b.ms || a.line - b.line)
  return groups
}

const countFailures = (events) => events.reduce((n, l) => n + (l.type === 'failed_password' ? l.repeat : 0), 0)
const distinctUsers = (events) => [...new Set(events.filter((l) => l.user !== null).map((l) => l.user))].sort()

function topUsernameShare(events) {
  const counts = new Map()
  for (const l of events) if (l.user !== null) counts.set(l.user, (counts.get(l.user) ?? 0) + l.repeat)
  const values = [...counts.values()]
  return values.length ? Math.max(...values) / values.reduce((a, b) => a + b, 0) : 0
}

// Sliding time window over one IP's events; joins qualifying windows into bursts.
function findBursts(events, windowSeconds, qualifies) {
  const span = windowSeconds * 1000
  const marked = new Array(events.length).fill(false)
  let left = 0
  for (let right = 0; right < events.length; right++) {
    while (events[right].ms - events[left].ms > span) left++
    if (qualifies(events.slice(left, right + 1))) for (let i = left; i <= right; i++) marked[i] = true
  }
  const bursts = []
  let prev = null
  events.forEach((e, i) => {
    if (!marked[i]) {
      prev = null
      return
    }
    if (prev === null || e.ms - prev.ms > span) bursts.push([])
    bursts[bursts.length - 1].push(e)
    prev = e
  })
  return bursts
}

function makeAlert(rule, severity, title, summary, ip, evidence, facts) {
  const times = evidence.map((l) => l.ms).sort((a, b) => a - b)
  return {
    rule, severity, title, summary, ip, facts,
    first_seen: isoTime(times[0]),
    last_seen: isoTime(times[times.length - 1]),
    evidence: [...new Set(evidence.map((l) => l.line))].sort((a, b) => a - b),
  }
}

function detect(lines) {
  const alerts = []
  const nice = (ms) => isoTime(ms).replace('T', ' ') // "2025-12-10 08:24:32" reads better in summaries
  const range = (b) => `between ${nice(b[0].ms)} and ${nice(b[b.length - 1].ms)}`

  const spraying = []
  for (const [ip, events] of linesByIp(lines, new Set(['failed_password', 'invalid_user']))) {
    for (const burst of findBursts(events, SPRAY_WINDOW_SECONDS, (w) => distinctUsers(w).length >= SPRAY_MIN_USERNAMES)) {
      if (topUsernameShare(burst) > SPRAY_MAX_TOP_USERNAME_SHARE) continue
      const users = distinctUsers(burst)
      spraying.push(makeAlert('password_spraying', 'high', 'Password spraying across many usernames',
        `${ip} tried ${users.length} different usernames ${range(burst)}.`, ip, burst,
        { users: users.length, failures: countFailures(burst) }))
    }
  }
  const sprayed = new Set(spraying.flatMap((a) => a.evidence.map((n) => `${a.ip}|${n}`)))

  for (const [ip, events] of linesByIp(lines, new Set(['failed_password']))) {
    for (const burst of findBursts(events, BRUTE_FORCE_WINDOW_SECONDS, (w) => countFailures(w) >= BRUTE_FORCE_MIN_FAILURES)) {
      const n = countFailures(burst)
      const a = makeAlert('brute_force', 'medium', 'Brute-force login attempts',
        `${n} failed SSH logins from ${ip} ${range(burst)}.`, ip, burst, { failures: n, users: distinctUsers(burst) })
      if (!a.evidence.every((line) => sprayed.has(`${ip}|${line}`))) alerts.push(a)
    }
  }
  alerts.push(...spraying)

  const failuresByIp = linesByIp(lines, new Set(['failed_password']))
  for (const ok of lines) {
    if (ok.type !== 'accepted_login' || !ok.ip || ok.ms === null) continue
    const prior = (failuresByIp.get(ok.ip) ?? []).filter((f) => ok.ms - SUCCESS_LOOKBACK_SECONDS * 1000 <= f.ms && f.ms <= ok.ms)
    const n = countFailures(prior)
    if (n >= SUCCESS_MIN_PRIOR_FAILURES) {
      alerts.push(makeAlert('success_after_failures', 'critical', 'Successful login after repeated failures',
        `${ok.ip} logged in successfully at ${nice(ok.ms)} after ${n} failed logins in the previous hour.`,
        ok.ip, [...prior, ok], { failures: n, okLine: ok.line }))
    }
  }

  for (const l of lines) {
    if (l.type !== 'accepted_login' || l.ms === null) continue
    const hour = new Date(l.ms).getUTCHours()
    if (hour >= ODD_HOUR_START && hour < ODD_HOUR_END) {
      alerts.push(makeAlert('odd_hour_login', 'low', 'Login at an unusual hour',
        `Successful SSH login from ${l.ip} at ${nice(l.ms)}, outside normal hours (00:00-05:59).`,
        l.ip, [l], { hour }))
    }
  }

  alerts.sort((a, b) => a.evidence[0] - b.evidence[0] || a.rule.localeCompare(b.rule))
  alerts.forEach((a, i) => (a.id = i + 1))
  return alerts
}

// One or two plain facts per finding, each citing the lines it was computed from.
// They're true by construction (computed by code from exactly those lines).
function factsFor(alert) {
  const time = (iso) => iso.slice(11)
  const when = alert.first_seen === alert.last_seen
    ? `at ${time(alert.first_seen)}`
    : `between ${time(alert.first_seen)} and ${time(alert.last_seen)}`
  switch (alert.rule) {
    case 'brute_force':
      return [`${alert.facts.failures} failed login attempts came from ${alert.ip} ${when}.`]
    case 'password_spraying':
      return [`${alert.ip} tried ${alert.facts.users} different usernames ${when}.`]
    case 'success_after_failures':
      return [`${alert.ip} logged in successfully after ${alert.facts.failures} failed attempts in the hour before.`]
    case 'odd_hour_login':
      return [`A successful login from ${alert.ip} happened ${when}, between midnight and 6 AM.`]
    default:
      return []
  }
}

// Scans a dropped File and returns a report in the same shape as the backend's
// report.json, plus `instant: true` so the dashboard can say "no AI used".
// Throws a friendly Error for files it can't use.
export async function scanFile(file) {
  if (file.size > MAX_FILE_BYTES) throw new Error('That file is larger than 20 MB. Try a smaller log.')
  const buffer = await file.arrayBuffer()
  if (new Uint8Array(buffer.slice(0, 8192)).includes(0)) {
    throw new Error(`"${file.name}" looks like a binary file, not a text log.`)
  }
  const text = new TextDecoder('utf-8').decode(buffer)
  const lines = parseLog(text)
  if (!lines.some((l) => l.type !== 'other')) {
    throw new Error(`No SSH login events found in "${file.name}". ProofLog reads SSH login logs, such as /var/log/auth.log on Linux.`)
  }
  const alerts = detect(lines)
  const claims = []
  for (const a of alerts) {
    for (const text of factsFor(a)) {
      claims.push({
        id: claims.length + 1, alert_id: a.id, text, evidence_lines: a.evidence, verified: true,
        verifier_note: 'Computed directly from these log lines by ProofLog’s rules (no AI involved).',
      })
    }
  }
  return {
    instant: true,
    meta: { source_name: file.name, source_type: 'own app', generated_at: new Date().toISOString().slice(0, 19) + 'Z' },
    trust_score: { verified: claims.length, total: claims.length },
    alerts: alerts.map(({ id, severity, title, first_seen, last_seen, summary }) => ({ id, severity, title, first_seen, last_seen, summary })),
    claims,
    log_lines: lines.map((l) => ({ line: l.line, text: l.text, untrusted_fields: l.user !== null ? ['username'] : [] })),
  }
}
