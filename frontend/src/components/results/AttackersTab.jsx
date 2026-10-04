import { severityStyle } from '../../lib/severity.js'
import { fmtTime } from '../../lib/stats.js'
import { Card } from './SummaryTab.jsx'

// AttackersTab: one row per flagged internet address, like VirusTotal's
// "relations". Usernames are attacker-typed text, shown as plain text only.
export default function AttackersTab({ stats, onOpenFinding }) {
  if (!stats.attackers.length) {
    return <Card><p className="text-slate-300">No attacking addresses were flagged in this log.</p></Card>
  }
  return (
    <Card className="overflow-x-auto p-0">
      <p className="border-b border-slate-800 px-5 py-3 text-sm text-slate-400">
        {stats.attackers.length} addresses were involved in suspicious activity. Usernames they tried are shown as
        plain text; they were typed by the attacker.
      </p>
      <table className="w-full min-w-[760px] text-left text-sm">
        <thead className="text-xs text-slate-400 uppercase">
          <tr>
            <th className="px-5 py-3">Address</th>
            <th className="py-3 pr-4">Failed</th>
            <th className="py-3 pr-4">Logged in?</th>
            <th className="py-3 pr-4">Accounts tried</th>
            <th className="py-3 pr-4">Active</th>
            <th className="py-3 pr-5">Findings</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-800">
          {stats.attackers.map((a) => (
            <tr key={a.ip} className="align-top">
              <td className="px-5 py-3 font-mono text-slate-100">{a.ip}</td>
              <td className="py-3 pr-4 text-slate-200">{a.failed.toLocaleString()}</td>
              <td className={`py-3 pr-4 ${a.accepted ? 'font-semibold text-red-300' : 'text-slate-400'}`}>
                {a.accepted ? `Yes (${a.accepted})` : 'No'}
              </td>
              <td className="max-w-xs py-3 pr-4 text-slate-300">
                <span className="text-slate-200">{a.users.length}</span>
                {a.users.length > 0 && (
                  <span className="block truncate text-xs text-amber-100/80" title={a.users.join(', ')}>
                    {a.users.slice(0, 6).join(', ')}{a.users.length > 6 ? ', …' : ''}
                  </span>
                )}
              </td>
              <td className="py-3 pr-4 whitespace-nowrap text-slate-400">
                {fmtTime(a.first).slice(11, 16)}–{fmtTime(a.last).slice(11, 16)}
                <span className="block text-xs">{fmtTime(a.first).slice(0, 10)}</span>
              </td>
              <td className="py-3 pr-5">
                <div className="flex flex-wrap gap-1">
                  {a.alerts.map((al) => (
                    <button key={al.id} type="button" onClick={() => onOpenFinding(al.id)}
                      title={`Open: ${al.title}`}
                      className={`rounded px-1.5 py-0.5 text-[11px] font-semibold uppercase ring-1 hover:brightness-125 ${severityStyle(al.severity).badge}`}>
                      {severityStyle(al.severity).label}
                    </button>
                  ))}
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </Card>
  )
}
