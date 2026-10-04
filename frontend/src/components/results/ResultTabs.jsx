// ResultTabs: the tab bar under the result card, like VirusTotal's
// Detection / Details / Relations tabs. Each kind of information has its own page.
export default function ResultTabs({ tab, onChange, counts, instant }) {
  const tabs = [
    ['summary', 'Summary'],
    ['findings', `Findings (${counts.findings})`],
    ['attackers', `Attackers (${counts.attackers})`],
    ['scores', 'Scores'],
    ['checks', `${instant ? 'Facts' : 'Proof checks'} (${counts.checks})`],
    ['log', 'Log file'],
  ]
  return (
    <nav aria-label="Result sections" className="mx-4 mt-4 mb-3 overflow-x-auto sm:mx-5">
      <div role="tablist" className="flex min-w-max gap-1 border-b border-slate-800">
        {tabs.map(([key, label]) => (
          <button
            key={key}
            type="button"
            role="tab"
            aria-selected={tab === key}
            onClick={() => onChange(key)}
            className={`-mb-px border-b-2 px-4 py-2 text-sm font-medium transition-colors ${
              tab === key ? 'border-emerald-400 text-white' : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            {label}
          </button>
        ))}
      </div>
    </nav>
  )
}
