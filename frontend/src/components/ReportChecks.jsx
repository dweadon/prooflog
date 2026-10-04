// ReportChecks: an amber bar listing problems the dashboard found in the
// backend's report (wrong trust score, evidence pointing at missing lines,
// duplicate ids...). Hidden when the report is consistent.
export default function ReportChecks({ warnings }) {
  if (!warnings.length) return null
  return (
    <details className="border-b border-amber-400/40 bg-amber-400/10 px-5 py-2 text-sm text-amber-100">
      <summary className="cursor-pointer font-medium">
        ⚠ Heads-up: {warnings.length} thing{warnings.length === 1 ? '' : 's'} in this report look{warnings.length === 1 ? 's' : ''} inconsistent (click for details)
      </summary>
      <ul className="mt-2 list-disc space-y-1 pl-5">
        {warnings.map((w, i) => (
          <li key={i}>{w}</li>
        ))}
      </ul>
    </details>
  )
}
