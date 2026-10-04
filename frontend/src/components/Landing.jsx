import FilePickerButton from './FilePickerButton.jsx'
import { DEMO_MODE, EXAMPLE_LOG_URL, REPO_URL } from '../config.js'

const BIG_PRIMARY =
  'inline-flex items-center justify-center rounded-lg bg-emerald-600 px-6 py-3 text-base font-semibold text-white shadow-lg shadow-emerald-900/40 hover:bg-emerald-500'
const BIG_SECONDARY =
  'inline-flex items-center justify-center rounded-lg border border-slate-600 px-6 py-3 text-base font-medium text-slate-100 hover:bg-slate-800'

const STEPS = [
  {
    title: 'You give it a log',
    text: 'Every time someone tries to log in to your server, a line is written to its log. ProofLog numbers every single line.',
  },
  {
    title: 'Simple rules spot attacks',
    text: 'Predictable rules flag things like hundreds of wrong passwords in a minute. No AI guessing at this step.',
  },
  {
    title: 'AI explains it in plain English',
    text: 'For each finding, the AI writes short statements, and each one must point to the log lines it is based on.',
  },
  {
    title: 'A checker tests every statement',
    text: 'Code and a second AI check each statement against its lines. Anything that doesn’t add up is marked “not proven”.',
  },
]

// Landing: the first screen. Explains what ProofLog is and how it works, in
// plain words, before showing any analysis. A big drop zone takes a log file
// (scanned in the browser online, or analysed by the backend locally); the
// main button opens the real example report (online) or the last result (locally).
export default function Landing({ onOpenReport, onUpload, onShowHelp }) {
  return (
    <div className="min-h-screen bg-slate-950 text-slate-200">
      <header className="flex items-center justify-between px-5 py-4 sm:px-8">
        <span className="text-xl font-semibold tracking-tight text-white">
          Proof<span className="text-emerald-400">Log</span>
        </span>
        <nav className="flex items-center gap-1 text-sm">
          <a href="#how" className="rounded-md px-3 py-1.5 text-slate-300 hover:bg-slate-800">How it works</a>
          <a href={REPO_URL} target="_blank" rel="noreferrer" className="rounded-md px-3 py-1.5 text-slate-300 hover:bg-slate-800">
            GitHub
          </a>
        </nav>
      </header>

      {/* Hero */}
      <section className="mx-auto max-w-4xl px-5 pt-12 pb-16 text-center sm:px-8 sm:pt-20">
        <p className="text-sm font-semibold tracking-widest text-emerald-400 uppercase">AI security checks you can verify</p>
        <h1 className="mt-4 text-4xl leading-tight font-bold text-white sm:text-6xl">
          Is someone trying to break into your server?
        </h1>
        <p className="mx-auto mt-6 max-w-2xl text-lg leading-relaxed text-slate-300">
          ProofLog reads your server’s login log, spots attacks and explains them in plain English. And it never asks
          you to take its word for it: <strong className="text-white">every statement points to the exact log lines
          that prove it</strong>, and a separate checker tests each one.
        </p>
        <FilePickerButton
          onFile={onUpload}
          className="mx-auto mt-10 block w-full max-w-2xl rounded-2xl border-2 border-dashed border-slate-600 bg-slate-900/60 px-6 py-10 text-center transition-colors hover:border-emerald-400 hover:bg-emerald-500/5"
        >
          <span className="block text-xl font-semibold text-white">Drag a log file here, or click to choose one</span>
          <span className="mt-2 block text-sm text-slate-400">
            {DEMO_MODE
              ? 'Scanned instantly in your browser. Your file never leaves your computer.'
              : 'ProofLog analyses it with AI and checks every statement against the log.'}
          </span>
          <span className="mt-1 block text-xs text-slate-500">SSH login logs, such as /var/log/auth.log on Linux</span>
        </FilePickerButton>
        <div className="mt-6 flex flex-wrap justify-center gap-3">
          <button type="button" onClick={onOpenReport} className={BIG_PRIMARY}>
            {DEMO_MODE ? 'See a real example report →' : 'See the last result →'}
          </button>
          <a href={EXAMPLE_LOG_URL} download="OpenSSH_2k.log" className={BIG_SECONDARY}>
            Download the example log
          </a>
        </div>
        {DEMO_MODE && (
          <p className="mt-4 text-sm text-slate-400">
            No log handy? The example report was made from a real log of a server under attack. No sign-up needed.
          </p>
        )}
      </section>

      {/* How it works */}
      <section id="how" className="border-t border-slate-800 bg-slate-900/40 px-5 py-16 sm:px-8">
        <div className="mx-auto max-w-6xl">
          <h2 className="text-center text-3xl font-bold text-white">How it works</h2>
          <p className="mx-auto mt-3 max-w-2xl text-center text-slate-400">Four steps, from a raw log file to a report you can check yourself.</p>
          <ol className="mt-10 grid gap-5 sm:grid-cols-2 lg:grid-cols-4">
            {STEPS.map((step, i) => (
              <li key={step.title} className="rounded-xl border border-slate-800 bg-slate-900 p-6">
                <span className="flex h-9 w-9 items-center justify-center rounded-full bg-emerald-600 font-bold text-white">{i + 1}</span>
                <h3 className="mt-4 text-lg font-semibold text-white">{step.title}</h3>
                <p className="mt-2 leading-relaxed text-slate-300">{step.text}</p>
              </li>
            ))}
          </ol>
        </div>
      </section>

      {/* What you'll see */}
      <section className="px-5 py-16 sm:px-8">
        <div className="mx-auto grid max-w-6xl items-center gap-10 lg:grid-cols-2">
          <div>
            <h2 className="text-3xl font-bold text-white">Proven, or clearly marked</h2>
            <p className="mt-4 leading-relaxed text-slate-300">
              Every AI statement gets a verdict. Green means the checker confirmed it against the log, so you can rely
              on it. Red means it didn’t add up, and you see exactly why. Click any statement in the report and its
              proof lights up in the original log.
            </p>
            <p className="mt-4 leading-relaxed text-slate-300">
              Logs can also contain text written by attackers, such as a username like “IGNORE PREVIOUS
              INSTRUCTIONS”. ProofLog treats all log text as data to report, never as instructions to follow.
            </p>
          </div>
          <div className="flex flex-col gap-3">
            <ExampleStatement
              ok
              text="There were 29 failed authentication events logged between 08:24:32 and 08:26:24 on Dec 10, all originating from IP 5.188.10.180."
              note="Proven by the log ✓"
            />
            <ExampleStatement
              text="The attacker at 5.36.59.76 failed to log in 46 times."
              note="Not proven: the number 46 doesn’t match any count in the cited lines."
            />
            <p className="text-xs text-slate-500">
              Real examples from the demo. The red one was planted on purpose to show the checker catching it (the
              real count is 6).
            </p>
          </div>
        </div>
      </section>

      {/* Call to action */}
      <section className="border-t border-slate-800 bg-slate-900/40 px-5 py-14 text-center sm:px-8">
        <h2 className="text-2xl font-bold text-white">See it on a real attack</h2>
        <p className="mx-auto mt-3 max-w-2xl text-slate-300">
          The example is 2,000 lines from a real server under attack, from the public Loghub dataset. Download it to
          check any line the report cites.
        </p>
        <div className="mt-6 flex flex-wrap justify-center gap-3">
          <button type="button" onClick={onOpenReport} className={BIG_PRIMARY}>
            {DEMO_MODE ? 'Open the example report →' : 'See the last result →'}
          </button>
          <button type="button" onClick={onShowHelp} className={BIG_SECONDARY}>
            What do the labels mean?
          </button>
        </div>
      </section>

      <footer className="px-5 py-8 text-center text-sm text-slate-500 sm:px-8">
        Example log from{' '}
        <a href="https://github.com/logpai/loghub" target="_blank" rel="noreferrer" className="underline hover:text-slate-300">
          Loghub
        </a>{' '}
        (LogPAI). Source code on{' '}
        <a href={REPO_URL} target="_blank" rel="noreferrer" className="underline hover:text-slate-300">
          GitHub
        </a>
        .
      </footer>
    </div>
  )
}

// A sample AI statement styled like the real report: green if proven, red if not.
function ExampleStatement({ ok, text, note }) {
  return (
    <div className={`rounded-lg border p-4 ${ok ? 'border-emerald-500/50 bg-emerald-500/5' : 'border-red-500/50 bg-red-500/5'}`}>
      <div className="flex gap-3">
        <span
          aria-hidden="true"
          className={`mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full text-xs font-bold ${
            ok ? 'bg-emerald-500/20 text-emerald-300' : 'bg-red-500/20 text-red-300'
          }`}
        >
          {ok ? '✓' : '!'}
        </span>
        <div>
          <p className="text-slate-100">{text}</p>
          <p className={`mt-1 text-sm ${ok ? 'text-emerald-300' : 'text-red-300'}`}>{note}</p>
        </div>
      </div>
    </div>
  )
}
