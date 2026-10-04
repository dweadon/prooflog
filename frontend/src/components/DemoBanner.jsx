import { REPO_URL } from '../config.js'

// DemoBanner: shown only on the online demo. Explains that this is a real
// report ProofLog produced earlier, and where to get the full app.
export default function DemoBanner() {
  return (
    <div className="border-b border-sky-500/30 bg-sky-500/10 px-4 py-2 text-sm text-sky-100 sm:px-5">
      <strong>Live demo:</strong> a real report ProofLog produced from a public log of a server under attack
      (Loghub OpenSSH dataset). Click around freely. To check your own logs,{' '}
      <a href={REPO_URL} target="_blank" rel="noreferrer" className="font-medium text-sky-300 underline">
        run ProofLog yourself
      </a>
      .
    </div>
  )
}
