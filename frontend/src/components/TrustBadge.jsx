// TrustBadge: "X of Y claims verified".
// Green = every AI claim was checked against the log and holds up.
// Amber = a few claims failed checking. Red = many failed (under 80%).
export default function TrustBadge({ verified, total }) {
  if (!total) {
    return (
      <div className="inline-flex items-center rounded-full bg-slate-700/40 px-3 py-1 text-sm text-slate-300 ring-1 ring-slate-600">
        No AI statements to check
      </div>
    )
  }
  const allGood = verified === total
  const color = allGood
    ? 'bg-emerald-500/15 text-emerald-300 ring-emerald-500/40'
    : verified / total >= 0.8
      ? 'bg-amber-400/15 text-amber-200 ring-amber-400/40'
      : 'bg-red-500/15 text-red-300 ring-red-500/40'

  return (
    <div
      title="How many of the AI's statements a separate checker confirmed against the log"
      className={`inline-flex items-center gap-2 rounded-full px-3 py-1 text-sm font-medium ring-1 ${color}`}
    >
      <span aria-hidden="true">{allGood ? '✓' : '⚠'}</span>
      <span>
        {verified} of {total} AI statements proven
      </span>
    </div>
  )
}
