import TrustBadge from './TrustBadge.jsx'
import { formatTime } from '../lib/format.js'

// Header: product name and action buttons on top; below that (once a report is
// loaded) where the log came from, when the report was made, and the trust score.
// `trust` is recounted from the claims by the dashboard, not copied from the backend.
export default function Header({ report, trust, actions, onShowHelp, onHome }) {
  const meta = report?.meta
  return (
    <header className="border-b border-slate-800 bg-slate-900/80 px-4 py-3 sm:px-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-baseline gap-3">
          <h1 className="text-lg font-semibold tracking-tight text-white">
            <button type="button" onClick={onHome} title="Back to the start page" className="rounded hover:opacity-80">
              Proof<span className="text-emerald-400">Log</span>
            </button>
          </h1>
          <span className="hidden text-xs text-slate-400 sm:inline">AI security checks you can verify</span>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {actions}
          <button type="button" onClick={onShowHelp} className="rounded-md px-3 py-1.5 text-sm text-slate-300 hover:bg-slate-800">
            ? How it works
          </button>
        </div>
      </div>

      {report && (
        <div className="mt-2.5 flex flex-wrap items-center gap-x-6 gap-y-2 text-sm">
          <div className="min-w-0">
            <span className="text-slate-400">Log file: </span>
            <span className="break-words text-slate-100">{meta.source_name}</span>
          </div>
          <div>
            <span className="text-slate-400">Checked on: </span>
            <time dateTime={meta.generated_at} className="text-slate-100">
              {formatTime(meta.generated_at)}
            </time>
          </div>
          <TrustBadge verified={trust.verified} total={trust.total} />
        </div>
      )}
    </header>
  )
}
