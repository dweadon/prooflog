import { DEMO_MODE } from '../config.js'

// DropOverlay: shown while a file is dragged over the page. Dropping it
// anywhere starts a scan (instantly in the browser online, full AI analysis
// when the backend is running).
export default function DropOverlay() {
  return (
    <div className="pointer-events-none fixed inset-0 z-50 flex items-center justify-center bg-slate-950/85 p-6 backdrop-blur-sm">
      <div className="w-full max-w-xl rounded-2xl border-2 border-dashed border-emerald-400 bg-emerald-500/10 px-8 py-14 text-center">
        <p className="text-3xl font-bold text-white">Drop your log file to scan it</p>
        <p className="mt-3 text-slate-300">
          {DEMO_MODE
            ? 'Scanned instantly in your browser. Your file never leaves your computer.'
            : 'ProofLog will analyse it and check every finding against the log.'}
        </p>
      </div>
    </div>
  )
}
