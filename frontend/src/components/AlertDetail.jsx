import ClaimItem from './ClaimItem.jsx'
import { severityStyle } from '../lib/severity.js'
import { formatRange } from '../lib/format.js'
import { moveFocusWithArrows } from '../lib/keyboard.js'
import { ALERT_EXPLAINERS } from '../lib/plain.js'

// AlertDetail: center panel. The selected alert's title, time range,
// summary, and the AI's claims about it. Click a claim to see its proof.
// Keyboard: ↑ / ↓ move between claims, Enter selects, Esc clears the selection.
export default function AlertDetail({ alert, claims, selectedClaimId, onSelectClaim, onJumpToLine, jumpLine, existingLines, instant, pending, aiRunning }) {
  if (!alert) {
    return <p className="p-6 text-slate-400">Pick a finding on the left to see what happened.</p>
  }
  const sev = severityStyle(alert.severity)
  const explainer = ALERT_EXPLAINERS[alert.title]
  return (
    <article className="flex flex-col gap-5 p-6">
      <div>
        <span className={`inline-block rounded px-2 py-0.5 text-xs font-semibold uppercase ring-1 ${sev.badge}`}>
          {sev.label}
        </span>
        {sev.hint && <span className="ml-2 text-sm text-slate-400">{sev.hint}</span>}
        <h2 className="mt-2 text-xl font-semibold text-white">{alert.title}</h2>
        <p className="mt-1 text-sm text-slate-400">
          When: {formatRange(alert.first_seen, alert.last_seen)}
        </p>
      </div>

      {explainer && (
        <div className="grid gap-3 rounded-lg border border-slate-700 bg-slate-800/40 p-4 text-sm sm:grid-cols-2">
          <div>
            <p className="font-semibold text-slate-100">What this means</p>
            <p className="mt-1 text-slate-300">{explainer.what}</p>
          </div>
          <div>
            <p className="font-semibold text-slate-100">What you could do</p>
            <p className="mt-1 text-slate-300">{explainer.todo}</p>
          </div>
        </div>
      )}

      <div>
        <h3 className="mb-1 text-xs font-semibold tracking-wider text-slate-400 uppercase">In this log</h3>
        <p className="leading-relaxed text-slate-200">{alert.summary}</p>
      </div>

      <section>
        <h3 className="mb-1 text-xs font-semibold tracking-wider text-slate-400 uppercase">
          {instant ? 'Facts from your log' : 'What the AI says'} ({claims.length})
        </h3>
        <p className="mb-2 text-sm text-slate-400">
          {instant
            ? 'Computed directly from the log by ProofLog’s rules. Click one to see its lines highlighted.'
            : 'Each statement was checked against the log. Click one to see its proof highlighted on the right.'}
        </p>
        {claims.length ? (
          <ul
            className="flex flex-col gap-2"
            onKeyDown={(e) => {
              if (e.key === 'Escape') onSelectClaim(null)
              else moveFocusWithArrows(e, '[data-claim]')
            }}
          >
            {claims.map((claim, i) => (
              <ClaimItem
                key={`${claim.id}-${i}`}
                claim={claim}
                selected={claim.id === selectedClaimId}
                onSelect={onSelectClaim}
                onJumpToLine={onJumpToLine}
                jumpLine={jumpLine}
                existingLines={existingLines}
                pending={pending?.has(claim.id)}
              />
            ))}
          </ul>
        ) : (
          aiRunning && !alert.summary.includes('AI analysis unavailable') && !alert.summary.includes('Not sent to AI') ? (
            <p className="flex items-center gap-2 text-sm text-slate-400">
              <span className="h-3 w-3 animate-spin rounded-full border-2 border-slate-600 border-t-emerald-400" aria-hidden="true" />
              The AI is writing statements about this finding…
            </p>
          ) : <p className="text-sm text-slate-400">The AI didn’t write about this one (it may have been skipped to save time). The summary above comes straight from the detection rules.</p>
        )}
      </section>
    </article>
  )
}
