import { severityStyle, sortBySeverity } from '../lib/severity.js'
import { moveFocusWithArrows } from '../lib/keyboard.js'
import { formatTime } from '../lib/format.js'

// AlertList: left panel. One card per alert, most severe first.
// The colored bar and badge show severity; the selected alert is highlighted.
// Keyboard: Tab into the list, ↑ / ↓ to move, Enter to open.
export default function AlertList({ alerts, selectedId, onSelect }) {
  return (
    <nav aria-label="Alerts" className="flex flex-col gap-2 p-3">
      <h2 className="px-1 text-xs font-semibold tracking-wider text-slate-400 uppercase">
        What we found ({alerts.length})
      </h2>
      {alerts.length === 0 ? (
        <p className="px-1 text-sm text-slate-300">Nothing suspicious in this log.</p>
      ) : (
        <ul className="flex flex-col gap-2" onKeyDown={(e) => moveFocusWithArrows(e, 'button')}>
          {sortBySeverity(alerts).map((alert, i) => {
            const sev = severityStyle(alert.severity)
            const selected = alert.id === selectedId
            return (
              <li key={`${alert.id}-${i}`}>
                <button
                  type="button"
                  onClick={() => onSelect(alert.id)}
                  aria-current={selected ? 'true' : undefined}
                  className={`relative w-full overflow-hidden rounded-lg border py-2.5 pr-3 pl-4 text-left transition-colors ${
                    selected
                      ? 'border-slate-500 bg-slate-800'
                      : 'border-slate-800 bg-slate-900 hover:border-slate-700 hover:bg-slate-800/60'
                  }`}
                >
                  <span className={`absolute inset-y-0 left-0 w-1 ${sev.bar}`} aria-hidden="true" />
                  <span className={`inline-block rounded px-1.5 py-0.5 text-[11px] font-semibold uppercase ring-1 ${sev.badge}`}>
                    {sev.label}
                  </span>
                  <span className="mt-1 block text-sm font-medium text-slate-100">{alert.title}</span>
                  <span className="mt-0.5 block text-xs text-slate-400">{formatTime(alert.first_seen)}</span>
                </button>
              </li>
            )
          })}
        </ul>
      )}
    </nav>
  )
}
