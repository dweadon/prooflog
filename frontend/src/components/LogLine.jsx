import { memo, useMemo } from 'react'
import { splitUntrusted } from '../lib/untrusted.js'
import UntrustedText, { UntrustedTag } from './UntrustedText.jsx'

// Lets the browser skip drawing rows that are off screen (big speed-up for long logs).
const OFFSCREEN_SKIP = { contentVisibility: 'auto', containIntrinsicSize: 'auto 20px' }

// LogLine: one row of the log. Shows the line number, the text with untrusted
// fields marked, and a highlight when the line is evidence for the selected claim
// (green for a verified claim, red for a claim that failed verification).
// `focused` outlines the one line whose number was clicked under a claim.
// memo = a row only re-draws when its own highlight changes, not on every click.
const LogLine = memo(function LogLine({ line, highlight, focused }) {
  const { segments, unlocated } = useMemo(
    () => splitUntrusted(line.text, line.untrusted_fields),
    [line.text, line.untrusted_fields],
  )
  const style =
    highlight === 'verified'
      ? 'border-emerald-400 bg-emerald-500/15'
      : highlight === 'unverified'
        ? 'border-red-400 bg-red-500/15'
        : highlight === 'flagged' // evidence for some finding (Log file tab)
          ? 'border-amber-400/70 bg-amber-400/10'
          : 'border-transparent hover:bg-slate-800/40'

  return (
    <li
      data-line={line.line}
      aria-current={focused ? 'true' : undefined}
      style={OFFSCREEN_SKIP}
      className={`flex border-l-2 ${style} ${focused ? 'outline-2 -outline-offset-2 outline-slate-200' : ''}`}
    >
      <span className={`w-14 shrink-0 pr-3 text-right select-none ${highlight ? 'text-slate-200' : 'text-slate-400'}`}>
        {line.line}
      </span>
      <span className="min-w-0 pr-4 break-all whitespace-pre-wrap text-slate-300">
        {segments.map((s, i) =>
          s.field ? (
            <UntrustedText key={i} field={s.field}>{s.text}</UntrustedText>
          ) : (
            <span key={i}>{s.text}</span>
          ),
        )}
        {unlocated.length > 0 && <UntrustedTag fields={unlocated} />}
      </span>
    </li>
  )
})

export default LogLine
