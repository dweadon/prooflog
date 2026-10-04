import { fmtTime, verdictFor } from '../../lib/stats.js'
import { plural } from '../../lib/plain.js'
import { formatTime } from '../../lib/format.js'
import TrustBadge from '../TrustBadge.jsx'

// Colors per verdict tone (ring, text, card border).
const TONE = {
  clean: { ring: '#10b981', text: 'text-emerald-300', border: 'border-emerald-500/40' },
  low: { ring: '#0ea5e9', text: 'text-sky-300', border: 'border-sky-500/40' },
  medium: { ring: '#f59e0b', text: 'text-amber-300', border: 'border-amber-400/40' },
  high: { ring: '#f97316', text: 'text-orange-300', border: 'border-orange-500/40' },
  critical: { ring: '#ef4444', text: 'text-red-300', border: 'border-red-500/40' },
}

// ResultHeader: the VirusTotal-style result card at the top. A ring with the
// number of threats, a one-line verdict, and the file's key facts.
export default function ResultHeader({ report, stats, trust, live }) {
  const verdict = verdictFor(stats)
  const tone = TONE[verdict.tone]
  const n = report.alerts.length
  const fraction = Math.min(1, n / 10) // ring fills up to 10 findings
  return (
    <section className={`mx-4 mt-4 flex flex-col gap-5 rounded-xl border bg-slate-900 p-5 sm:mx-5 sm:flex-row sm:items-center ${tone.border}`}>
      <div className="relative h-28 w-28 shrink-0 self-center" title={`${n} suspicious activities found`}>
        <svg viewBox="0 0 36 36" className="h-28 w-28 -rotate-90" aria-hidden="true">
          <circle cx="18" cy="18" r="15.9" fill="none" stroke="#1e293b" strokeWidth="3" />
          <circle cx="18" cy="18" r="15.9" fill="none" stroke={tone.ring} strokeWidth="3" strokeLinecap="round"
            strokeDasharray={`${n ? Math.max(4, fraction * 100) : 100} 100`} />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className={`text-3xl font-bold ${tone.text}`}>{n}</span>
          <span className="text-[11px] text-slate-400">{n === 1 ? 'threat' : 'threats'}</span>
        </div>
      </div>

      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
          <p className={`text-2xl font-bold ${tone.text}`}>{verdict.text}</p>
          {live?.state === 'running' ? (
            <span className="inline-flex items-center gap-2 rounded-full bg-emerald-500/15 px-3 py-1 text-sm font-medium text-emerald-200 ring-1 ring-emerald-500/40">
              <span className="h-3 w-3 animate-spin rounded-full border-2 border-emerald-700 border-t-emerald-300" aria-hidden="true" />
              AI is writing and checking statements…
            </span>
          ) : report.instant ? (
            <span className="inline-flex items-center rounded-full bg-sky-500/15 px-3 py-1 text-sm font-medium text-sky-200 ring-1 ring-sky-500/40">
              Instant scan · no AI · nothing uploaded
            </span>
          ) : (
            <TrustBadge verified={trust.verified} total={trust.total} />
          )}
        </div>
        <p className="mt-1 text-slate-300">
          {n === 0
            ? 'ProofLog found no suspicious login activity in this log.'
            : `${plural(n, 'suspicious activity', 'suspicious activities')} from ${plural(stats.attackers.length, 'address', 'addresses')}, targeting ${plural(stats.accountsTargeted.size, 'account', 'accounts')}.`}
        </p>
        <dl className="mt-3 grid grid-cols-2 gap-x-6 gap-y-1 text-sm sm:grid-cols-5">
          <Fact label="File" value={report.meta.source_name} />
          <Fact label="Lines" value={stats.lines.toLocaleString()} />
          <Fact label="Log covers" value={span(stats.first, stats.last)} />
          <Fact label="Scan type" value={report.instant ? 'Instant (rules only)' : 'AI + verified'} />
          <Fact label="Checked on" value={formatTime(report.meta.generated_at)} />
        </dl>
        {live?.job && <LiveProgress live={live} claims={report.claims.length} />}
      </div>
    </section>
  )
}

// Progress of a live AI analysis: findings written, statements still being checked, time so far.
function LiveProgress({ live, claims }) {
  const p = live.progress ?? {}
  const steps = (p.alerts_total ?? 0) + claims
  const done = (p.alerts_done ?? 0) + (claims - (p.claims_pending ?? 0))
  const percent = live.state === 'running' ? (steps ? Math.round((done / steps) * 100) : 5) : 100
  return (
    <div className="mt-3" aria-live="polite">
      <div className="h-1.5 overflow-hidden rounded-full bg-slate-800">
        <div className="h-full rounded-full bg-emerald-500 transition-all duration-500" style={{ width: `${percent}%` }} />
      </div>
      <p className="mt-1.5 text-xs text-slate-400">
        {live.state === 'running'
          ? `AI statements written for ${p.alerts_done ?? 0} of ${p.alerts_total ?? 0} findings · ${p.claims_pending ?? 0} being checked against the log · ${p.elapsed_seconds ?? 0}s`
          : live.state === 'error'
            ? 'The AI analysis stopped early; what was finished is shown.'
            : `AI analysis finished in ${p.elapsed_seconds ?? 0}s. The findings above were shown instantly; the AI statements filled in as they were checked.`}
      </p>
    </div>
  )
}

// "2025-12-10 06:55 → 11:04" on one day, full dates otherwise.
function span(first, last) {
  const a = fmtTime(first).slice(0, 16)
  const b = fmtTime(last).slice(0, 16)
  return a.slice(0, 10) === b.slice(0, 10) ? `${a} → ${b.slice(11)}` : `${a} → ${b}`
}

function Fact({ label, value }) {
  return (
    <div className="min-w-0">
      <dt className="text-xs text-slate-500 uppercase">{label}</dt>
      <dd className="truncate text-slate-200" title={value}>{value}</dd>
    </div>
  )
}
