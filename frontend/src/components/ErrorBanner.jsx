// ErrorBanner: a friendly error shown above the dashboard when something fails
// while a report is already on screen (the old report stays visible).
export default function ErrorBanner({ message, onDismiss }) {
  return (
    <div role="alert" className="flex items-start justify-between gap-3 border-b border-red-500/40 bg-red-500/10 px-5 py-2.5 text-sm text-red-200">
      <p>
        <span className="font-semibold">Something went wrong: </span>
        {message}
      </p>
      <button type="button" onClick={onDismiss} className="shrink-0 rounded px-2 text-red-200 hover:bg-red-500/20" aria-label="Dismiss error">
        ✕
      </button>
    </div>
  )
}
