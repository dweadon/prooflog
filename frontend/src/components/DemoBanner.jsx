import { REPO_URL } from '../config.js'

// DemoBanner: shown only on the online demo. It explains what's on screen:
// the bundled example report, an instant in-browser scan of the visitor's own
// file (with an "Analyse with AI" button when a hosted backend is configured),
// or a full AI analysis that came back from that backend.
export default function DemoBanner({ report, onAnalyseWithAI }) {
  const link = (
    <a href={REPO_URL} target="_blank" rel="noreferrer" className="font-medium text-sky-300 underline">
      run ProofLog yourself
    </a>
  )
  return (
    <div className="flex flex-wrap items-center gap-x-4 gap-y-2 border-b border-sky-500/30 bg-sky-500/10 px-4 py-2 text-sm text-sky-100 sm:px-5">
      <p className="min-w-0 flex-1">
        {report?.live && report.claims.length > 0 ? (
          <>
            <strong>Full AI analysis</strong> from the live ProofLog server: every AI statement was checked against your
            log, line by line.
          </>
        ) : report?.live ? (
          <>
            <strong>The ProofLog server answered, but its AI wasn’t available</strong> (busy or not configured), so only
            the rule-based findings are shown. Try again in a minute.
          </>
        ) : report?.instant ? (
          <>
            <strong>Instant scan, done in your browser:</strong> your file never left your computer. Findings come from
            ProofLog’s detection rules.{' '}
            {onAnalyseWithAI
              ? 'For plain-English AI explanations, each checked against your log, send it to the ProofLog server.'
              : <>For plain-English AI explanations, {link}.</>}
          </>
        ) : (
          <>
            <strong>Live demo:</strong> a real report ProofLog produced from a public log of a server under attack
            (Loghub OpenSSH dataset). <strong>Drag your own log file onto this page</strong> to scan it.
          </>
        )}
      </p>
      {onAnalyseWithAI && (
        <button
          type="button"
          onClick={onAnalyseWithAI}
          title="Uploads this file to the ProofLog server for AI analysis. Takes about a minute."
          className="shrink-0 rounded-md bg-emerald-600 px-3 py-1.5 font-medium text-white hover:bg-emerald-500"
        >
          Analyse with AI →
        </button>
      )}
    </div>
  )
}
