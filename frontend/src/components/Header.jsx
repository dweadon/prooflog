
// Header: product name (click to go back to the start page) and the action buttons.
// Details about the current report live in the result card below it.
export default function Header({ actions, onShowHelp, onHome }) {
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

    </header>
  )
}
