// Finds where untrusted fields (like username or user_agent) sit inside a raw
// log line, so the log viewer can mark exactly that text as attacker-controlled.
//
// The data contract only tells us WHICH fields are untrusted, not WHERE they are,
// so we recognise common log formats. Each pattern only runs on lines that look
// like its format, to avoid underlining the wrong text. Anything we can't locate
// is returned in `unlocated`, and the viewer tags the whole line instead.

const escapeKeys = (keys) => keys.map((k) => k.replace(/[^\w-]/g, '')).join('|')

// key=value, value quoted or bare. Groups 1/2/3 = "double", 'single', bare.
const keyValue = (keys) =>
  new RegExp(`(?:^|[\\s,;{])(?:${keys})=(?:"((?:[^"\\\\]|\\\\.)*)"|'([^']*)'|([^\\s,;}]+))`, 'di')

// JSON logs: "key": "value"
const jsonValue = (keys) => new RegExp(`"(?:${keys})"\\s*:\\s*"((?:[^"\\\\]|\\\\.)*)"`, 'di')

const SSHD_LINE = /sshd|Failed password|Accepted (?:password|publickey)|Invalid user/i
const ACCESS_LOG_LINE = /"[A-Z]+ \S+ HTTP\/[\d.]+"/ // Apache/nginx: "GET /path HTTP/1.1"

const PATTERNS = {
  username: [
    { re: jsonValue('username|user|user_name|login|account') },
    { re: keyValue('user|username|user_name|login|account') },
    // sshd: "Failed password for root from ...", "Invalid user admin from ..."
    { re: /\b(?:invalid user|for)\s+(\S+)\s+from\b/di, when: SSHD_LINE },
    // sshd: "input_userauth_request: invalid user admin [preauth]"
    { re: /\binvalid user\s+(\S+)/di, when: SSHD_LINE },
    // sshd/pam: "session opened for user bob by ...", "Too many authentication failures for root"
    { re: /\b(?:for user|authentication failures for)\s+(\S+)/di, when: SSHD_LINE },
  ],
  user_agent: [
    { re: jsonValue('user_agent|userAgent|http_user_agent|ua') },
    { re: keyValue('ua|user_agent|user-agent|useragent|http_user_agent') },
    { re: /"((?:[^"\\]|\\.)*)"\s*$/d, when: ACCESS_LOG_LINE }, // combined format: UA is the last quoted string
  ],
}

function patternsFor(field) {
  if (PATTERNS[field]) return PATTERNS[field]
  const key = escapeKeys([field])
  return key ? [{ re: jsonValue(key) }, { re: keyValue(key) }] : []
}

function locate(text, field) {
  for (const { re, when } of patternsFor(field)) {
    if (when && !when.test(text)) continue
    const m = re.exec(text)
    if (!m) continue
    const group = [1, 2, 3].find((g) => m[g] !== undefined)
    if (group && m.indices[group][1] > m.indices[group][0]) {
      const [start, end] = m.indices[group]
      return { start, end, field }
    }
  }
  return null
}

// Returns { segments: [{ text, field|null }], unlocated: [field] }.
export function splitUntrusted(text, fields = []) {
  const found = []
  const unlocated = []
  for (const field of fields) {
    const r = locate(text, field)
    // Skip ranges that overlap one already found.
    if (r && !found.some((f) => r.start < f.end && f.start < r.end)) found.push(r)
    else if (!r) unlocated.push(field)
  }
  found.sort((a, b) => a.start - b.start)

  const segments = []
  let pos = 0
  for (const r of found) {
    if (r.start > pos) segments.push({ text: text.slice(pos, r.start), field: null })
    segments.push({ text: text.slice(r.start, r.end), field: r.field })
    pos = r.end
  }
  if (pos < text.length) segments.push({ text: text.slice(pos), field: null })
  return { segments, unlocated }
}
