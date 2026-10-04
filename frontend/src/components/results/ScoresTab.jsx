import { SEVERITY } from '../../lib/severity.js'
import { Card, H } from './SummaryTab.jsx'

// ScoresTab: the percentages, each with a plain "how we calculated this".
// Every number is a direct count from the log, never a made-up risk score.
export default function ScoresTab({ report, stats }) {
  const p = stats.percent
  const scores = [
    {
      value: p.attackShare, color: '#f97316', title: 'Login attempts from attackers',
      how: `${stats.attackers.reduce((n, a) => n + a.failed + a.accepted, 0).toLocaleString()} of ${stats.attempts.toLocaleString()} login attempts came from addresses ProofLog flagged.`,
    },
    {
      value: p.failureRate, color: '#f59e0b', title: 'Failed login attempts',
      how: `${stats.totals.failed.toLocaleString()} of ${stats.attempts.toLocaleString()} login attempts used a wrong password. On a healthy server this is usually low.`,
    },
    report.instant
      ? {
          value: 100, color: '#10b981', title: 'Facts computed from the log',
          how: 'This instant scan used no AI: every fact was computed directly from the lines it cites.',
        }
      : {
          value: p.proven, color: '#10b981', title: 'AI statements proven',
          how: `${stats.proven} of ${report.claims.length} AI statements passed every check against their cited lines. The rest are marked “not proven”.`,
        },
    {
      value: p.coverage, color: '#0ea5e9', title: 'Log lines used as proof',
      how: `${stats.citedLines.size.toLocaleString()} of ${stats.lines.toLocaleString()} log lines are cited as evidence for a finding.`,
    },
  ]

  const total = report.alerts.length
  return (
    <div className="flex flex-col gap-4">
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {scores.map((s) => (
          <Card key={s.title} className="flex flex-col items-center text-center">
            <Ring value={s.value} color={s.color} />
            <p className="mt-3 font-semibold text-white">{s.title}</p>
            <p className="mt-2 text-sm leading-relaxed text-slate-400">{s.how}</p>
          </Card>
        ))}
      </div>

      <Card>
        <H>Findings by severity</H>
        {total === 0 ? (
          <p className="text-slate-300">No findings.</p>
        ) : (
          <>
            <div className="flex h-4 overflow-hidden rounded-full bg-slate-800" role="img"
              aria-label={Object.entries(SEVERITY).map(([k, s]) => `${stats.bySeverity[k] ?? 0} ${s.label}`).join(', ')}>
              {Object.entries(SEVERITY).sort((a, b) => b[1].rank - a[1].rank).map(([key, s]) =>
                stats.bySeverity[key] ? <div key={key} className={s.bar} style={{ width: `${(stats.bySeverity[key] / total) * 100}%` }} /> : null)}
            </div>
            <ul className="mt-4 grid gap-2 sm:grid-cols-4">
              {Object.entries(SEVERITY).sort((a, b) => b[1].rank - a[1].rank).map(([key, s]) => (
                <li key={key} className="flex items-center gap-2 text-sm">
                  <span className={`h-3 w-3 rounded-sm ${s.bar}`} aria-hidden="true" />
                  <span className="text-slate-200">{s.label}</span>
                  <span className="text-slate-400">{stats.bySeverity[key] ?? 0}</span>
                  <span className="text-xs text-slate-500">· {s.hint}</span>
                </li>
              ))}
            </ul>
          </>
        )}
      </Card>

      <Card>
        <H>What happened in the log</H>
        <dl className="grid grid-cols-2 gap-4 sm:grid-cols-5">
          {[
            ['Failed passwords', stats.totals.failed],
            ['Unknown usernames tried', stats.totals.invalid],
            ['Successful logins', stats.totals.accepted],
            ['Disconnects', stats.totals.disconnect],
            ['Other lines', stats.totals.other],
          ].map(([label, n]) => (
            <div key={label}>
              <dd className="text-2xl font-bold text-white">{n.toLocaleString()}</dd>
              <dt className="text-sm text-slate-400">{label}</dt>
            </div>
          ))}
        </dl>
      </Card>
    </div>
  )
}

// A percentage ring.
function Ring({ value, color }) {
  return (
    <div className="relative h-24 w-24">
      <svg viewBox="0 0 36 36" className="h-24 w-24 -rotate-90" aria-hidden="true">
        <circle cx="18" cy="18" r="15.9" fill="none" stroke="#1e293b" strokeWidth="3" />
        <circle cx="18" cy="18" r="15.9" fill="none" stroke={color} strokeWidth="3" strokeLinecap="round"
          strokeDasharray={`${Math.max(value, 0.5)} 100`} />
      </svg>
      <span className="absolute inset-0 flex items-center justify-center text-xl font-bold text-white">{value}%</span>
    </div>
  )
}
