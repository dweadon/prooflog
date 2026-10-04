import { useEffect, useRef } from 'react'

// HelpDialog: "How it works" — explains ProofLog and every term on screen in
// plain English. Closes with the button, Esc, or a click outside the box.
export default function HelpDialog({ onClose }) {
  const closeRef = useRef(null)
  useEffect(() => {
    closeRef.current?.focus()
    const onKey = (e) => e.key === 'Escape' && onClose()
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="help-title"
      onClick={(e) => e.target === e.currentTarget && onClose()}
      className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 p-4 backdrop-blur-sm"
    >
      <div className="max-h-[90vh] w-full max-w-2xl overflow-y-auto rounded-xl border border-slate-700 bg-slate-900 p-6 shadow-2xl">
        <div className="flex items-start justify-between gap-4">
          <h2 id="help-title" className="text-xl font-semibold text-white">How ProofLog works</h2>
          <button ref={closeRef} type="button" onClick={onClose} className="rounded-md px-2 py-1 text-slate-300 hover:bg-slate-800" aria-label="Close">
            ✕
          </button>
        </div>

        <ol className="mt-4 space-y-3 text-slate-200">
          <li><strong className="text-white">1. You give it a server log.</strong> A log is the diary a server keeps: every login attempt, one per line.</li>
          <li><strong className="text-white">2. Simple rules spot suspicious activity</strong>, like hundreds of wrong passwords in a minute. No AI is involved in this step.</li>
          <li><strong className="text-white">3. An AI explains each finding in plain English.</strong> Every statement it makes must point to the exact log lines that prove it.</li>
          <li><strong className="text-white">4. A separate checker tests every statement</strong> against those lines. If the numbers, addresses or times don’t match, the statement is marked <span className="text-red-300">not proven</span>.</li>
        </ol>

        <h3 className="mt-6 text-sm font-semibold tracking-wider text-slate-400 uppercase">What the labels mean</h3>
        <dl className="mt-2 grid gap-x-4 gap-y-2 text-sm sm:grid-cols-[auto_1fr]">
          <Term name={<span className="text-emerald-300">✓ Proven by the log</span>}>The checker confirmed this statement against the cited lines. You can rely on it.</Term>
          <Term name={<span className="text-red-300">! Not proven</span>}>The checker couldn’t confirm it. The reason is shown underneath. Don’t rely on it.</Term>
          <Term name={<span className="rounded-sm bg-amber-400/10 text-amber-100 underline decoration-amber-400 decoration-dashed">dashed underline</span>}>Text typed by an outsider, such as a username an attacker tried. It is only ever displayed, never trusted or obeyed.</Term>
          <Term name="Urgent / Serious / Suspicious / Unusual">How worried to be, from most to least.</Term>
          <Term name="IP address">The internet address of the computer that tried to log in, e.g. 183.62.140.253.</Term>
          <Term name="Brute force">Guessing one account’s password over and over.</Term>
          <Term name="Password spraying">Trying many different accounts, hoping one has a weak password.</Term>
          <Term name="Line 185">A line number in the original log file, so anyone can check the proof themselves.</Term>
        </dl>

        <button type="button" onClick={onClose} className="mt-6 rounded-md bg-emerald-600 px-4 py-2 text-sm font-medium text-white hover:bg-emerald-500">
          Got it
        </button>
      </div>
    </div>
  )
}

// One label + explanation row in the glossary.
function Term({ name, children }) {
  return (
    <>
      <dt className="font-medium text-slate-100">{name}</dt>
      <dd className="text-slate-300">{children}</dd>
    </>
  )
}
