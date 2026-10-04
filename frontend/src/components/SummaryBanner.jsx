import { useState } from 'react'
import { severityStyle, sortBySeverity } from '../lib/severity.js'
import { plural } from '../lib/plain.js'

const GUIDE_KEY = 'prooflog.guideDismissed'

// Reads/writes the "guide dismissed" flag. Storage can be blocked (private
// windows), so failures just mean the guide shows again next time.
function guideDismissed() {
  try {
    return localStorage.getItem(GUIDE_KEY) === '1'
  } catch {
    return false
  }
}
function rememberDismissed() {
  try {
    localStorage.setItem(GUIDE_KEY, '1')
  } catch {
    /* not important */
  }
}

// SummaryBanner: the first thing you see. Says in one or two plain sentences
// what was found and how much of the AI's write-up is proven, then (until
// dismissed) a 3-step guide to reading the rest of the screen.
export default function SummaryBanner({ report, trust, onShowHelp }) {
  const [showGuide, setShowGuide] = useState(() => !guideDismissed())
  const alerts = report.alerts
  const worst = sortBySeverity(alerts)[0]
  const unproven = trust.total - trust.verified

  return (
    <section aria-label="Summary" className="border-b border-slate-800 bg-slate-900/60 px-4 py-4 sm:px-5">
      {alerts.length === 0 ? (
        <p className="text-lg font-semibold text-emerald-300">
          Good news: nothing suspicious was found in {report.meta.source_name}.
        </p>
      ) : (
        <>
          <p className="text-lg font-semibold text-white">
            We found {plural(alerts.length, 'suspicious activity', 'suspicious activities')} in this log.
          </p>
          <p className="mt-1 text-slate-300">
            Most serious:{' '}
            <span className={`rounded px-1.5 py-0.5 text-sm font-semibold ring-1 ${severityStyle(worst.severity).badge}`}>
              {severityStyle(worst.severity).label}
            </span>{' '}
            {worst.title}.
          </p>
          {report.instant && (
            <p className="mt-1 text-slate-300">
              Every finding below was computed directly from your log, and each one links to the exact lines behind it.
            </p>
          )}
          {!report.instant && trust.total > 0 && (
            <p className="mt-1 text-slate-300">
              The AI made {plural(trust.total, 'statement', 'statements')} about them.{' '}
              <span className="font-medium text-emerald-300">{trust.verified} proven by the log ✓</span>
              {unproven > 0 && (
                <>
                  {', '}
                  <span className="font-medium text-red-300">
                    {unproven} could not be proven
                  </span>{' '}
                  (marked in red, don’t rely on {unproven === 1 ? 'it' : 'those'})
                </>
              )}
              .
            </p>
          )}
        </>
      )}

      {showGuide && alerts.length > 0 && (
        <div className="mt-3 flex flex-col gap-3 rounded-lg border border-emerald-500/30 bg-emerald-500/5 p-3 lg:flex-row lg:items-center">
          <ol className="grid flex-1 gap-2 text-sm text-slate-200 sm:grid-cols-3">
            <li><Step n="1" />Pick a finding from the list<Where> on the <strong>left</strong></Where>.</li>
            <li><Step n="2" />Read what happened in plain English<Where>, in the <strong>middle</strong></Where>.</li>
            <li><Step n="3" />Click any {report.instant ? 'fact' : 'AI statement'} to see the exact log lines that prove it<Where>, on the <strong>right</strong></Where>.</li>
          </ol>
          <div className="flex shrink-0 gap-2">
            <button type="button" onClick={onShowHelp} className="rounded-md px-3 py-1.5 text-sm text-emerald-300 hover:bg-emerald-500/10">
              How it works
            </button>
            <button
              type="button"
              onClick={() => {
                rememberDismissed()
                setShowGuide(false)
              }}
              className="rounded-md bg-emerald-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-emerald-500"
            >
              Got it
            </button>
          </div>
        </div>
      )}
    </section>
  )
}

// A small numbered circle for the guide steps.
function Step({ n }) {
  return (
    <span className="mr-2 inline-flex h-5 w-5 items-center justify-center rounded-full bg-emerald-600 text-xs font-bold text-white">
      {n}
    </span>
  )
}

// Position words ("on the left") only make sense in the wide 3-column layout;
// on narrow screens the panels stack, so they're hidden there.
function Where({ children }) {
  return <span className="hidden lg:inline">{children}</span>
}
