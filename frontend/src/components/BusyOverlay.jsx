import { STAGE_TEXT } from '../lib/plain.js'

// BusyOverlay: covers the screen while the backend works (analysis can take
// minutes), so nobody clicks things mid-request. While a log is being checked,
// `progress` (from GET /status) shows which step it's on, with a progress bar.
export default function BusyOverlay({ message, progress }) {
  const step = progress && STAGE_TEXT[progress.stage]
  const percent = progress?.total ? Math.round((progress.done / progress.total) * 100) : null
  return (
    <div
      role="status"
      aria-live="polite"
      className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/75 p-4 backdrop-blur-sm"
    >
      <div className="w-full max-w-md rounded-lg border border-slate-700 bg-slate-900 px-5 py-4 shadow-xl">
        <div className="flex items-center gap-3">
          <span className="h-5 w-5 shrink-0 animate-spin rounded-full border-2 border-slate-600 border-t-emerald-400" aria-hidden="true" />
          <span className="text-slate-100">{message}</span>
        </div>
        {step && (
          <div className="mt-3">
            <p className="text-sm text-slate-300">
              {step}
              {progress.total ? ` (${progress.done} of ${progress.total})` : ''}…
            </p>
            {percent !== null && (
              <div className="mt-2 h-2 overflow-hidden rounded-full bg-slate-800">
                <div className="h-full rounded-full bg-emerald-500 transition-all" style={{ width: `${percent}%` }} />
              </div>
            )}
          </div>
        )}
        {progress && (
          <p className="mt-3 text-xs text-slate-400">
            {progress.seconds}s so far. This usually takes about a minute (a little longer if the server was asleep).
          </p>
        )}
      </div>
    </div>
  )
}
