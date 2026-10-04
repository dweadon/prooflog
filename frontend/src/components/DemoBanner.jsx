import { REPO_URL } from '../config.js'

// DemoBanner: shown only on the online demo. For the bundled example it says
// it's a real saved report; for a file the visitor dropped in, it explains the
// instant in-browser scan (rules only, file never uploaded).
export default function DemoBanner({ report }) {
  const link = (
    <a href={REPO_URL} target="_blank" rel="noreferrer" className="font-medium text-sky-300 underline">
      run ProofLog yourself
    </a>
  )
  return (
    <div className="border-b border-sky-500/30 bg-sky-500/10 px-4 py-2 text-sm text-sky-100 sm:px-5">
      {report?.instant ? (
        <>
          <strong>Instant scan, done in your browser:</strong> your file never left your computer. Findings come from
          ProofLog’s detection rules. For plain-English AI explanations, {link}.
        </>
      ) : (
        <>
          <strong>Live demo:</strong> a real report ProofLog produced from a public log of a server under attack
          (Loghub OpenSSH dataset). <strong>Drag your own log file onto this page</strong> to scan it instantly, or{' '}
          {link}.
        </>
      )}
    </div>
  )
}
