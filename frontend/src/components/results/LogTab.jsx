import { useMemo, useState } from 'react'
import LogLine from '../LogLine.jsx'

const MAX_SHOWN = 3000 // rows drawn at once; a search narrows it down

// LogTab: the whole original log on its own page. Lines used as proof for
// any finding are marked; you can show only those, or search the text.
export default function LogTab({ report, stats }) {
  const [onlySuspicious, setOnlySuspicious] = useState(false)
  const [query, setQuery] = useState('')

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase()
    return report.log_lines.filter(
      (l) => (!onlySuspicious || stats.citedLines.has(l.line)) && (!q || l.text.toLowerCase().includes(q)),
    )
  }, [report, stats, onlySuspicious, query])

  return (
    <div className="flex h-full min-h-[70vh] flex-col rounded-xl border border-slate-800 bg-slate-900">
      <div className="flex flex-wrap items-center gap-3 border-b border-slate-800 px-4 py-3">
        <input type="search" value={query} onChange={(e) => setQuery(e.target.value)}
          placeholder="Search the log, e.g. an IP address or username"
          className="min-w-0 flex-1 rounded-md border border-slate-700 bg-slate-950 px-3 py-1.5 text-sm text-slate-100 placeholder:text-slate-500" />
        <label className="flex items-center gap-2 text-sm text-slate-300">
          <input type="checkbox" checked={onlySuspicious} onChange={(e) => setOnlySuspicious(e.target.checked)} className="accent-emerald-500" />
          Only lines used as proof
        </label>
        <span className="text-sm text-slate-400">
          {rows.length.toLocaleString()} of {report.log_lines.length.toLocaleString()} lines
        </span>
      </div>
      <p className="border-b border-slate-800 px-4 py-2 text-xs text-slate-400">
        <span className="mr-1 inline-block h-2.5 w-2.5 rounded-sm bg-amber-400/70 align-middle" /> marked lines are evidence for a finding ·
        <span className="ml-1 rounded-sm bg-amber-400/10 text-amber-100 underline decoration-amber-400 decoration-dashed">underlined text</span> was typed by an outsider
      </p>
      <ol className="min-h-0 flex-1 overflow-auto py-1 font-mono text-xs leading-5">
        {rows.slice(0, MAX_SHOWN).map((l, i) => (
          <LogLine key={`${l.line}-${i}`} line={l} highlight={stats.citedLines.has(l.line) ? 'flagged' : null} />
        ))}
        {rows.length > MAX_SHOWN && (
          <li className="px-4 py-3 font-sans text-slate-400">Showing the first {MAX_SHOWN.toLocaleString()} lines. Search to narrow it down.</li>
        )}
        {rows.length === 0 && <li className="px-4 py-3 font-sans text-slate-400">No lines match.</li>}
      </ol>
    </div>
  )
}
