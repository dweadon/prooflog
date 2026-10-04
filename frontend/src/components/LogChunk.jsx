import { memo } from 'react'
import LogLine from './LogLine.jsx'

// LogChunk: a block of ~500 log lines. Big logs are split into blocks so that
// selecting a claim only re-draws the blocks whose highlighted lines changed,
// which keeps clicks instant even on logs with tens of thousands of lines.
// `markedKey` is a short text summary of what's highlighted in this block;
// if it hasn't changed, React skips the whole block.
const LogChunk = memo(function LogChunk({ lines, evidence, highlight, focusedLine, markedKey }) {
  void markedKey // only used to decide whether to re-draw
  return lines.map((l) => (
    <LogLine
      key={l.key}
      line={l}
      highlight={evidence.has(l.line) ? highlight : null}
      focused={l.line === focusedLine}
    />
  ))
}, (prev, next) => prev.lines === next.lines && prev.markedKey === next.markedKey)

export default LogChunk
