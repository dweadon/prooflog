import { ALERT_EXPLAINERS, plural } from '../../lib/plain.js'
import { severityStyle, sortBySeverity } from '../../lib/severity.js'
import { fmtTime } from '../../lib/stats.js'

// SummaryTab: the plain-English overview. What happened, whether anyone got
// in, the main attackers, and what to do, without any log lines.
export default function SummaryTab({ report, stats, onGoTo }) {
  const alerts = sortBySeverity(report.alerts)
  if (!alerts.length) {
    return (
      <Card>
        <p className="text-xl font-semibold text-emerald-300">Good news: nothing suspicious found.</p>
        <p className="mt-2 text-slate-300">
          ProofLog read all {stats.lines.toLocaleString()} lines and found no brute-force, password-spraying or other
          suspicious login activity.
        </p>
      </Card>
    )
  }

  // Count findings by type, e.g. "4 × Password spraying".
  const byType = new Map()
  for (const a of alerts) byType.set(a.title, [...(byType.get(a.title) ?? []), a])
  const todos = [...byType.keys()].map((t) => [t, ALERT_EXPLAINERS[t]?.todo]).filter(([, todo]) => todo)
  const loggedIn = stats.attackerLogins

  return (
    <div className="grid gap-4 lg:grid-cols-3">
      <Card className="lg:col-span-2">
        <H>What happened</H>
        <p className="leading-relaxed text-slate-200">
          Between <b>{fmtTime(stats.first)}</b> and <b>{fmtTime(stats.last)}</b>,{' '}
          {plural(stats.attackers.length, 'internet address', 'internet addresses')} made{' '}
          <b>{stats.attackers.reduce((n, a) => n + a.failed, 0).toLocaleString()} failed login attempts</b> against{' '}
          {plural(stats.accountsTargeted.size, 'account', 'accounts')}. ProofLog grouped this into{' '}
          {plural(alerts.length, 'suspicious activity', 'suspicious activities')}.
        </p>
        <div className={`mt-4 rounded-lg border p-3 ${loggedIn.length ? 'border-red-500/50 bg-red-500/10' : 'border-emerald-500/40 bg-emerald-500/5'}`}>
          {loggedIn.length ? (
            <p className="text-red-200">
              <b>⚠ Did anyone get in? Possibly.</b> {plural(loggedIn.length, 'flagged address', 'flagged addresses')}{' '}
              ({loggedIn.map((a) => a.ip).join(', ')}) also logged in successfully. Check those accounts first.
            </p>
          ) : (
            <p className="text-emerald-200">
              <b>✓ Did anyone get in? No sign of it.</b> None of the flagged addresses ever logged in successfully.
            </p>
          )}
        </div>

        <H className="mt-6">Findings by type</H>
        <ul className="divide-y divide-slate-800">
          {[...byType.entries()].map(([title, list]) => (
            <li key={title} className="flex items-center justify-between gap-3 py-2">
              <span className="flex items-center gap-2">
                <span className={`rounded px-1.5 py-0.5 text-[11px] font-semibold uppercase ring-1 ${severityStyle(list[0].severity).badge}`}>
                  {severityStyle(list[0].severity).label}
                </span>
                <span className="text-slate-100">{title}</span>
              </span>
              <span className="text-slate-400">× {list.length}</span>
            </li>
          ))}
        </ul>
        <button type="button" onClick={() => onGoTo('findings')} className="mt-3 text-sm font-medium text-emerald-300 hover:underline">
          Open the findings and their proof →
        </button>
      </Card>

      <Card>
        <H>What you could do</H>
        <ol className="list-decimal space-y-2 pl-5 text-slate-200">
          {loggedIn.length > 0 && <li>Check the accounts that were logged into from flagged addresses, and change their passwords.</li>}
          {todos.map(([title, todo]) => (
            <li key={title}>{todo}</li>
          ))}
          <li>Block the flagged addresses in your firewall (they’re listed under Attackers).</li>
        </ol>
      </Card>

      <Card className="lg:col-span-3">
        <div className="flex items-center justify-between">
          <H>Top attackers</H>
          <button type="button" onClick={() => onGoTo('attackers')} className="text-sm font-medium text-emerald-300 hover:underline">
            See all {stats.attackers.length} →
          </button>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="text-xs text-slate-400 uppercase">
              <tr><th className="py-2 pr-4">Address</th><th className="pr-4">Failed attempts</th><th className="pr-4">Accounts tried</th><th>Logged in?</th></tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {stats.attackers.slice(0, 5).map((a) => (
                <tr key={a.ip}>
                  <td className="py-2 pr-4 font-mono text-slate-100">{a.ip}</td>
                  <td className="pr-4 text-slate-200">{a.failed.toLocaleString()}</td>
                  <td className="pr-4 text-slate-200">{a.users.length}</td>
                  <td className={a.accepted ? 'font-semibold text-red-300' : 'text-slate-400'}>{a.accepted ? 'Yes' : 'No'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  )
}

export function Card({ children, className = '' }) {
  return <div className={`rounded-xl border border-slate-800 bg-slate-900 p-5 ${className}`}>{children}</div>
}

export function H({ children, className = '' }) {
  return <h3 className={`mb-3 text-sm font-semibold tracking-wider text-slate-400 uppercase ${className}`}>{children}</h3>
}
