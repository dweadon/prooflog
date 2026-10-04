import { useState } from 'react'

const LINES_SHOWN = 8 // longer evidence lists are folded behind "show all"

// ClaimItem: one AI claim, written as a plain sentence. Clicking it shows the
// proof in the log viewer. A green check means the claim was verified against
// the log; a red warning means it wasn't, with the verifier's reason shown.
// Each cited line number ("L27") is its own button that jumps to that exact line.
// Cited line numbers that don't exist in the log are flagged in red.
// The claim and the line numbers are real <button>s, so Tab / Enter / Space work.
export default function ClaimItem({ claim, selected, onSelect, onJumpToLine, jumpLine, existingLines, pending }) {
  const ok = claim.verified
  const [showAll, setShowAll] = useState(false)
  const lines = showAll ? claim.evidence_lines : claim.evidence_lines.slice(0, LINES_SHOWN)
  const hidden = claim.evidence_lines.length - lines.length
  return (
    <li
      className={`rounded-lg border transition-colors ${
        pending
          ? 'border-slate-700 bg-slate-900'
          : selected
          ? ok
            ? 'border-emerald-500/70 bg-emerald-500/10'
            : 'border-red-500/70 bg-red-500/10'
          : ok
            ? 'border-slate-800 bg-slate-900 hover:border-slate-600'
            : 'border-red-500/40 bg-slate-900 hover:border-red-500/70'
      }`}
    >
      <button
        type="button"
        data-claim
        onClick={() => onSelect(selected ? null : claim.id)}
        aria-pressed={selected}
        className="flex w-full gap-3 rounded-lg px-4 pt-3 pb-1.5 text-left"
      >
        <span
          aria-label={pending ? 'Being checked' : ok ? 'Proven by the log' : 'Not proven'}
          title={pending ? 'Being checked against the log' : ok ? 'Proven by the log' : 'Not proven'}
          className={`mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full text-xs font-bold ${
            pending ? 'animate-pulse bg-slate-700 text-slate-300' : ok ? 'bg-emerald-500/20 text-emerald-300' : 'bg-red-500/20 text-red-300'
          }`}
        >
          {pending ? '…' : ok ? '✓' : '!'}
        </span>
        <span className="min-w-0">
          <span className="block text-slate-100">{claim.text}</span>

          {pending && <span className="mt-1 block text-xs text-slate-400">Checking against the log…</span>}

          {!ok && !pending && (
            <span className="mt-2 block rounded border border-red-500/30 bg-red-500/10 px-2 py-1.5 text-sm text-red-200">
              <span className="font-semibold">Not proven, don’t rely on this. </span>
              {claim.verifier_note || 'No reason given.'}
            </span>
          )}

          {ok && <span className="mt-1 block text-xs font-medium text-emerald-300">✓ Proven by the log</span>}
          {ok && claim.verifier_note && selected && (
            <span className="mt-1 block text-xs text-slate-400">Checker: {claim.verifier_note}</span>
          )}
        </span>
      </button>

      <div className="flex flex-wrap items-center gap-1 px-4 pb-3 pl-12 text-xs text-slate-400">
        <span className="mr-0.5">Proof in log lines:</span>
        {claim.evidence_lines.length === 0 && <span>none given</span>}
        {lines.map((n, i) =>
          existingLines.has(n) ? (
            <button
              key={`${n}-${i}`}
              type="button"
              onClick={() => onJumpToLine(claim.id, n)}
              title={`Jump to log line ${n}`}
              aria-label={`Jump to log line ${n}`}
              className={`rounded px-1 py-0.5 ring-1 transition-colors ${
                selected && jumpLine === n
                  ? 'bg-slate-200 text-slate-900 ring-slate-200'
                  : 'text-slate-300 ring-slate-600 hover:bg-slate-700 hover:text-white'
              }`}
            >
              {n}
            </button>
          ) : (
            <span
              key={`${n}-${i}`}
              className="px-1 text-red-400 line-through"
              title="This line is not in the log"
            >
              {n}
            </span>
          ),
        )}
        {hidden > 0 && (
          <button type="button" onClick={() => setShowAll(true)} className="rounded px-1 py-0.5 text-emerald-300 hover:bg-slate-800">
            +{hidden} more
          </button>
        )}
      </div>
    </li>
  )
}
