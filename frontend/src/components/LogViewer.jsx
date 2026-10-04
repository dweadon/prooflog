import { useEffect, useMemo, useRef } from 'react'
import LogChunk from './LogChunk.jsx'

const CHUNK_SIZE = 500

// LogViewer: right panel. The raw log with line numbers.
// When a claim is selected, its evidence lines light up and the viewer
// smoothly scrolls to the first one. The toggle hides every other line.
// Text is rendered as plain text (React escapes it), so nothing in a log
// line can ever run as code or be treated as an instruction.
// If a specific line number was clicked (jumpTarget), it scrolls to that line instead
// and outlines it.
export default function LogViewer({ lines, claim, jumpTarget, onlyEvidence, onToggleOnlyEvidence }) {
  const listRef = useRef(null)

  const evidence = useMemo(() => new Set(claim?.evidence_lines ?? []), [claim])
  const highlight = claim ? (claim.verified ? 'verified' : 'unverified') : null
  const shown = useMemo(
    () => (claim && onlyEvidence ? lines.filter((l) => evidence.has(l.line)) : lines),
    [lines, claim, onlyEvidence, evidence],
  )

  // Split the visible lines into blocks. Index in the key keeps React happy
  // even if the backend sends duplicate line numbers.
  const chunks = useMemo(() => {
    const out = []
    for (let i = 0; i < shown.length; i += CHUNK_SIZE) {
      out.push(shown.slice(i, i + CHUNK_SIZE).map((l, j) => ({ ...l, key: `${l.line}-${i + j}` })))
    }
    return out
  }, [shown])

  // Scroll to the first evidence line whenever the selected claim (or the toggle) changes.
  // Short distances scroll smoothly; long jumps are instant (smooth-scrolling past
  // thousands of lines is slow). scrollIntoView also brings the log panel on screen
  // on phones, where it sits below the claims.
  useEffect(() => {
    const list = listRef.current
    if (!claim || !list) return
    const candidates = jumpTarget ? [jumpTarget.line] : [...claim.evidence_lines].sort((a, b) => a - b)
    const first = candidates.map((n) => list.querySelector(`[data-line="${n}"]`)).find(Boolean)
    if (!first) return
    const distance = Math.abs(first.getBoundingClientRect().top - list.getBoundingClientRect().top)
    first.scrollIntoView({ behavior: distance > list.clientHeight * 3 ? 'auto' : 'smooth', block: 'center' })
  }, [claim, onlyEvidence, jumpTarget])

  return (
    <section aria-label="Log viewer" className="flex h-full min-h-0 flex-col">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 px-4 py-2">
        <h2 className="text-xs font-semibold tracking-wider text-slate-400 uppercase">
          Original log ({lines.length.toLocaleString()} lines)
          <span aria-live="polite" className="ml-2 font-normal tracking-normal text-slate-300 normal-case">
            {claim
              ? `· ${evidence.size} line${evidence.size === 1 ? '' : 's'} of proof highlighted`
              : '· click an AI statement to highlight its proof here'}
          </span>
        </h2>
        <label className={`flex items-center gap-2 text-xs ${claim ? 'text-slate-300' : 'text-slate-400 opacity-60'}`}>
          <input
            type="checkbox"
            checked={onlyEvidence}
            disabled={!claim}
            onChange={(e) => onToggleOnlyEvidence(e.target.checked)}
            className="accent-emerald-500"
          />
          Show only the proof
        </label>
      </div>

      <ol ref={listRef} className="min-h-0 flex-1 overflow-auto py-1 font-mono text-xs leading-5">
        {chunks.map((chunk) => {
          const marked = chunk.filter((l) => evidence.has(l.line)).map((l) => l.line)
          const focusedHere = jumpTarget && chunk.some((l) => l.line === jumpTarget.line)
          return (
            <LogChunk
              key={chunk[0].key}
              lines={chunk}
              evidence={evidence}
              highlight={highlight}
              focusedLine={focusedHere ? jumpTarget.line : null}
              markedKey={`${marked.length ? `${highlight}:${marked.join(',')}` : ''}|${focusedHere ? jumpTarget.line : ''}`}
            />
          )
        })}
        {lines.length === 0 && (
          <li className="px-4 py-3 font-sans text-slate-400">This report contains no log lines.</li>
        )}
        {claim && lines.length > 0 && shown.length === 0 && (
          <li className="px-4 py-3 font-sans text-slate-400">This statement points to no lines that exist in the log.</li>
        )}
      </ol>
    </section>
  )
}
