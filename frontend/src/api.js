import { API_BASE_URL, UPLOAD_FIELD_NAME } from './config.js'

// How long to wait for the AI analysis before giving up.
// A 2,000-line log took about 3 minutes on the real backend, so leave plenty of room.
const ANALYZE_TIMEOUT_MS = 10 * 60 * 1000

// Checks that a report has the shape the dashboard needs, and fills in
// harmless defaults (e.g. a missing evidence list becomes []) so one bad
// field can't crash the whole UI. Throws a readable error if it's unusable.
function checkReport(report) {
  if (!report || typeof report !== 'object') throw new Error('The report is empty or not a JSON object.')
  const required = ['meta', 'trust_score', 'alerts', 'claims', 'log_lines']
  const missing = required.filter((key) => report[key] == null)
  if (missing.length) throw new Error(`The report is missing: ${missing.join(', ')}`)
  for (const key of ['alerts', 'claims', 'log_lines']) {
    if (!Array.isArray(report[key])) throw new Error(`In the report, "${key}" should be a list.`)
  }
  const numbers = (list) => (Array.isArray(list) ? list.map(Number).filter(Number.isFinite) : [])
  return {
    ...report,
    claims: report.claims.map((c) => ({ ...c, evidence_lines: numbers(c.evidence_lines) })),
    log_lines: report.log_lines.map((l) => ({
      ...l,
      line: Number(l.line),
      text: String(l.text ?? ''),
      untrusted_fields: Array.isArray(l.untrusted_fields) ? l.untrusted_fields : [],
    })),
  }
}

// Pulls a short error message out of a failed response, if the backend sent one
// (FastAPI uses {"detail": ...}; others use "error" or "message").
async function errorDetail(res) {
  try {
    const body = await res.json()
    const detail = body?.detail ?? body?.error ?? body?.message
    return typeof detail === 'string' ? detail.slice(0, 200) : ''
  } catch {
    return ''
  }
}

// Calls the backend and turns every kind of failure into a short message
// a person can act on: backend down, timeout, HTTP error, or bad JSON.
async function request(path, { messages = {}, timeoutMs, ...options } = {}) {
  let res
  try {
    res = await fetch(`${API_BASE_URL}${path}`, {
      ...options,
      signal: timeoutMs ? AbortSignal.timeout(timeoutMs) : undefined,
    })
  } catch (e) {
    if (e.name === 'TimeoutError') {
      throw new Error(`The backend took longer than ${Math.round(timeoutMs / 60000)} minutes and was stopped. Try a smaller log.`)
    }
    // The browser reports "backend down" and "blocked by CORS" the same way, so mention both.
    throw new Error(
      `Can't reach the backend at ${API_BASE_URL || window.location.origin}. Check that it's running and that it allows requests from this page (CORS).`,
    )
  }

  if (!res.ok) {
    const detail = await errorDetail(res)
    if (messages[res.status]) throw new Error(`${messages[res.status]}${detail ? ` Backend said: ${detail}` : ''}`)
    throw new Error(`The backend returned an error (${res.status})${detail ? `: ${detail}` : '.'}`)
  }

  let data
  try {
    data = await res.json()
  } catch {
    throw new Error('The backend did not return valid JSON.')
  }
  return checkReport(data)
}

// GET /report: the most recent report the backend produced.
export function fetchLatestReport() {
  return request('/report', {
    messages: { 404: 'The backend has no report yet. Upload a log to create one.' },
  })
}

// POST /analyze: sends a log file (multipart form field "file") and gets back a report.
export function analyzeLog(file) {
  const form = new FormData()
  form.append(UPLOAD_FIELD_NAME, file)
  const wrongFormat =
    `The backend rejected the upload. It may expect a different format: the dashboard sends the log as ` +
    `multipart form field "${UPLOAD_FIELD_NAME}" (change UPLOAD_FIELD_NAME in src/config.js to match the backend).`
  return request('/analyze', {
    method: 'POST',
    body: form,
    timeoutMs: ANALYZE_TIMEOUT_MS,
    messages: {
      404: 'The backend has no /analyze endpoint yet (404).',
      409: 'An analysis is already running. Wait for it to finish, then try again.',
      405: 'The backend does not accept POST on /analyze (405).',
      413: 'That log file is too large for the backend.',
      415: wrongFormat,
      422: wrongFormat,
    },
  })
}

// GET /status: the backend's progress while it analyzes, e.g.
// { stage: "verifying", done: 4, total: 12, elapsed_seconds: 51 }.
// Optional extra: returns null on any problem, so a backend without it still works.
export async function fetchStatus() {
  try {
    const res = await fetch(`${API_BASE_URL}/status`, { signal: AbortSignal.timeout(3000) })
    return res.ok ? await res.json() : null
  } catch {
    return null
  }
}

// Reads a report.json the user picked from disk (no backend needed).
export async function readReportFile(file) {
  let data
  try {
    data = JSON.parse(await file.text())
  } catch {
    throw new Error(`"${file.name}" is not valid JSON.`)
  }
  return checkReport(data)
}
