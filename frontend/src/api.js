import { AI_AVAILABLE, API_BASE_URL, DEMO_MODE, UPLOAD_FIELD_NAME } from './config.js'

// How long to wait for the AI analysis before giving up.
// A 2,000-line log takes about 1 minute on the live backend; a sleeping free host adds
// about a minute more, so leave plenty of room.
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
// `parse` turns the JSON into what the caller needs (a checked report by default).
async function request(path, { messages = {}, timeoutMs, parse = checkReport, ...options } = {}) {
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
  return parse(data)
}

// GET /report: the most recent report the backend produced.
// In the online demo there's no backend, so it loads the bundled real report instead.
export function fetchLatestReport() {
  if (DEMO_MODE) return request(`${import.meta.env.BASE_URL}demo-report.json`)
  return request('/report', {
    messages: { 404: 'The backend has no report yet. Upload a log to create one.' },
  })
}

// POST /analyze: sends a log file (multipart form field "file") and gets back a report.
export function analyzeLog(file) {
  if (!AI_AVAILABLE) {
    return Promise.reject(new Error(
      'This online demo only shows a saved report. To check your own log file, run ProofLog on your computer (see the GitHub page).'))
  }
  const form = new FormData()
  form.append(UPLOAD_FIELD_NAME, file)
  const wrongFormat =
    `The backend rejected the upload. It may expect a different format: the dashboard sends the log as ` +
    `multipart form field "${UPLOAD_FIELD_NAME}" (change UPLOAD_FIELD_NAME in src/config.js to match the backend).`
  return request('/analyze', {
    method: 'POST',
    body: form,
    timeoutMs: ANALYZE_TIMEOUT_MS,
    // A free hosted backend may be asleep: the first request can take a minute to wake it.
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

// A live job from the backend: the report so far, plus which statements are still being checked.
function checkJob(body) {
  if (!body || typeof body !== 'object' || !body.report) throw new Error('The backend sent an unexpected answer.')
  return {
    job: body.job ?? null,
    state: body.state ?? 'done',
    report: { ...checkReport(body.report), live: true },
    pending: new Set(Array.isArray(body.pending_claims) ? body.pending_claims : []),
    progress: body.progress ?? {},
  }
}

// POST /analyze/start: uploads a log and gets the rule-based findings back at once.
// The AI statements and verdicts then fill in: poll pollAnalysis(job).
export function startAnalysis(file) {
  if (!AI_AVAILABLE) {
    return Promise.reject(new Error(
      'This online demo only shows a saved report. To check your own log file, run ProofLog on your computer (see the GitHub page).'))
  }
  const form = new FormData()
  form.append(UPLOAD_FIELD_NAME, file)
  return request('/analyze/start', {
    method: 'POST',
    body: form,
    timeoutMs: 3 * 60 * 1000, // only the upload and the rules; a sleeping free host may need a minute to wake
    parse: checkJob,
    messages: {
      409: 'An analysis is already running. Wait a minute, then try again.',
      413: 'That log file is too large for the backend.',
    },
  })
}

// GET /analyze/{job}: the live job so far.
export function pollAnalysis(jobId) {
  return request(`/analyze/${encodeURIComponent(jobId)}`, { timeoutMs: 20000, parse: checkJob })
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
  return parse(data)
}
