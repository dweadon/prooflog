import { useState } from 'react'
import { Card } from './SummaryTab.jsx'

// ChecksTab: every statement in one list with its verdict, filterable.
// "Show proof" opens the finding with that statement selected.
export default function ChecksTab({ report, onOpenFinding }) {
  const [filter, setFilter] = useState('all')
  const titleOf = new Map(report.alerts.map((a) => [a.id, a.title]))
  const shown = report.claims.filter((c) => filter === 'all' || (filter === 'proven') === c.verified)
  const proven = report.claims.filter((c) => c.verified).length
  const options = [
    ['all', `All (${report.claims.length})`],
    ['proven', `Proven (${proven})`],
    ['unproven', `Not proven (${report.claims.length - proven})`],
  ]

  return (
    <div className="flex flex-col gap-4">
      <Card>
        <p className="text-slate-200">
          {report.instant
            ? 'This instant scan used no AI. Each fact below was computed directly from the log lines it cites.'
            : 'Each AI statement was checked against only the log lines it cites: do the lines exist, do the numbers, addresses and times match, and does a second AI agree? Anything that fails is marked not proven, with the reason.'}
        </p>
        <div className="mt-4 flex flex-wrap gap-2" role="group" aria-label="Filter statements">
          {options.map(([key, label]) => (
            <button key={key} type="button" onClick={() => setFilter(key)} aria-pressed={filter === key}
              className={`rounded-full px-3 py-1 text-sm ring-1 ${filter === key ? 'bg-slate-200 text-slate-900 ring-slate-200' : 'text-slate-300 ring-slate-600 hover:bg-slate-800'}`}>
              {label}
            </button>
          ))}
        </div>
      </Card>

      <ul className="flex flex-col gap-2">
        {shown.map((c) => (
          <li key={c.id} className={`rounded-xl border bg-slate-900 p-4 ${c.verified ? 'border-slate-800' : 'border-red-500/50'}`}>
            <div className="flex gap-3">
              <span aria-label={c.verified ? 'Proven' : 'Not proven'}
                className={`mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-full text-sm font-bold ${c.verified ? 'bg-emerald-500/20 text-emerald-300' : 'bg-red-500/20 text-red-300'}`}>
                {c.verified ? '✓' : '!'}
              </span>
              <div className="min-w-0 flex-1">
                <p className="text-xs text-slate-500">{titleOf.get(c.alert_id)}</p>
                <p className="mt-0.5 text-slate-100">{c.text}</p>
                <p className={`mt-1 text-sm ${c.verified ? 'text-emerald-300/90' : 'text-red-300'}`}>
                  {c.verified ? '✓ Proven by the log' : `Not proven: ${c.verifier_note || 'no reason given.'}`}
                </p>
              </div>
              <button type="button" onClick={() => onOpenFinding(c.alert_id, c.id)}
                className="shrink-0 self-start rounded-md px-2 py-1 text-sm text-emerald-300 hover:bg-slate-800">
                Show proof →
              </button>
            </div>
          </li>
        ))}
        {shown.length === 0 && <li className="px-1 text-slate-400">Nothing here.</li>}
      </ul>
    </div>
  )
}
