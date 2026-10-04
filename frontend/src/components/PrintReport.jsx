import { sortBySeverity, severityStyle } from '../lib/severity.js'
import { formatRange, formatTime } from '../lib/format.js'
import { BUTTON, PRIMARY_BUTTON } from '../lib/ui.js'

// How many cited log lines to quote under each claim in the PDF.
const MAX_QUOTED_LINES = 4

// PrintReport: a clean, light, print-friendly version of the report for
// "Print → Save as PDF". Every claim keeps its line references and quotes the
// first few cited log lines, so the PDF is auditable on its own.
// The toolbar at the top is hidden when printing.
export default function PrintReport({ report, trust, warnings, onClose }) {
  const { meta } = report
  const lineText = new Map(report.log_lines.map((l) => [l.line, l.text]))

  return (
    <div className="min-h-screen bg-white text-slate-900">
      <div className="sticky top-0 flex justify-center gap-2 border-b border-slate-200 bg-slate-100 px-4 py-3 print:hidden">
        <button type="button" onClick={() => window.print()} className={PRIMARY_BUTTON}>
          Print / Save as PDF
        </button>
        <button type="button" onClick={onClose} className={`${BUTTON} border-slate-400 text-slate-800 hover:bg-slate-200`}>
          Back to dashboard
        </button>
      </div>

      <article className="mx-auto max-w-3xl px-6 py-8 print:max-w-none print:p-0">
        <header className="border-b-2 border-slate-900 pb-4">
          <p className="text-sm font-semibold tracking-wide text-emerald-700 uppercase">ProofLog · AI you can audit</p>
          <h1 className="mt-1 text-2xl font-bold">Security Incident Report</h1>
          <dl className="mt-3 grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
            <dt className="font-semibold">Generated</dt>
            <dd>{formatTime(meta.generated_at)}</dd>
            <dt className="font-semibold">Data source</dt>
            <dd>
              {meta.source_name} ({meta.source_type})
            </dd>
            <dt className="font-semibold">Trust score</dt>
            <dd>
              {trust.verified} of {trust.total} claims verified against the log
              {trust.verified < trust.total && ' — unverified claims are marked below'}
            </dd>
            <dt className="font-semibold">Alerts</dt>
            <dd>{report.alerts.length}</dd>
          </dl>
        </header>

        {warnings.length > 0 && (
          <section className="mt-6 break-inside-avoid rounded border border-amber-500 bg-amber-50 px-4 py-3 text-sm">
            <h2 className="font-bold">Report consistency checks</h2>
            <ul className="mt-1 list-disc pl-5">
              {warnings.map((w, i) => (
                <li key={i}>{w}</li>
              ))}
            </ul>
          </section>
        )}

        {report.alerts.length === 0 && <p className="mt-6">No alerts were found in this log.</p>}

        {sortBySeverity(report.alerts).map((alert) => {
          const claims = report.claims.filter((c) => c.alert_id === alert.id)
          return (
            <section key={alert.id} className="mt-8">
              <h2 className="text-lg font-bold break-after-avoid">
                <span className="mr-2 rounded border border-slate-900 px-1.5 py-0.5 text-xs font-bold uppercase">
                  {severityStyle(alert.severity).label}
                </span>
                {alert.title}
              </h2>
              <p className="mt-1 text-sm text-slate-600">
                {formatRange(alert.first_seen, alert.last_seen)}
              </p>
              <p className="mt-2">{alert.summary}</p>

              <ol className="mt-3 space-y-3">
                {claims.map((claim) => (
                  <li
                    key={claim.id}
                    className={`break-inside-avoid border-l-4 pl-3 ${claim.verified ? 'border-emerald-600' : 'border-red-600'}`}
                  >
                    <p>
                      <span className={`font-semibold ${claim.verified ? 'text-emerald-700' : 'text-red-700'}`}>
                        {claim.verified ? '✓ Verified' : '✗ NOT VERIFIED'}
                      </span>{' '}
                      — {claim.text}
                    </p>
                    {(!claim.verified || claim.verifier_note) && (
                      <p className="mt-0.5 text-sm text-slate-700">
                        <span className="font-semibold">Verifier note:</span> {claim.verifier_note || 'No reason given.'}
                      </p>
                    )}
                    <p className="mt-0.5 text-sm text-slate-700">
                      <span className="font-semibold">Evidence:</span>{' '}
                      {claim.evidence_lines.length ? `log lines ${claim.evidence_lines.join(', ')}` : 'none cited'}
                    </p>
                    {claim.evidence_lines.length > 0 && (
                      <pre className="mt-1 overflow-hidden rounded bg-slate-100 px-2 py-1 font-mono text-[11px] leading-4 break-all whitespace-pre-wrap text-slate-800">
                        {claim.evidence_lines
                          .slice(0, MAX_QUOTED_LINES)
                          .map((n) => `${n}: ${lineText.get(n) ?? '(line not found in log)'}`)
                          .join('\n')}
                        {claim.evidence_lines.length > MAX_QUOTED_LINES &&
                          `\n… and ${claim.evidence_lines.length - MAX_QUOTED_LINES} more lines`}
                      </pre>
                    )}
                  </li>
                ))}
                {claims.length === 0 && <li className="text-sm text-slate-600">No claims for this alert.</li>}
              </ol>
            </section>
          )
        })}

        <footer className="mt-10 border-t border-slate-300 pt-3 text-xs text-slate-600">
          Quoted log text may contain attacker-controlled content (usernames, user agents). It is shown as data only
          and was never treated as instructions. Times with a timezone are shown in UTC.
        </footer>
      </article>
    </div>
  )
}
