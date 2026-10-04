import FilePickerButton from './FilePickerButton.jsx'
import { PRIMARY_BUTTON } from '../lib/ui.js'

// EmptyState: the welcome screen when there's no report yet. Explains in
// three plain steps what ProofLog does, with one big button to start.
// Any error from the last attempt is shown here too.
export default function EmptyState({ error, onUpload, onShowHelp }) {
  return (
    <div className="flex flex-1 items-center justify-center p-8">
      <div className="max-w-xl text-center">
        <h2 className="text-2xl font-semibold text-white">Is someone trying to break into your server?</h2>
        <p className="mt-3 text-slate-300">
          Give ProofLog your server’s login log. It finds suspicious activity, explains it in plain English, and{' '}
          <strong className="text-white">proves every statement</strong> with the exact lines from your log.
        </p>

        {error && !/no report yet/i.test(error) && (
          <p role="alert" className="mt-4 rounded-md border border-amber-400/40 bg-amber-400/10 px-3 py-2 text-sm text-amber-200">
            {error}
          </p>
        )}

        <div className="mt-6 flex flex-wrap justify-center gap-3">
          <FilePickerButton onFile={onUpload} className={`${PRIMARY_BUTTON} px-5 py-2.5 text-base`}>
            Check a log file
          </FilePickerButton>
          <button type="button" onClick={onShowHelp} className="rounded-md px-4 py-2.5 text-slate-300 hover:bg-slate-800">
            How it works
          </button>
        </div>
        <p className="mt-4 text-sm text-slate-400">
          On Linux the file is usually <code className="text-slate-300">/var/log/auth.log</code>. Checking takes a few minutes.
        </p>
      </div>
    </div>
  )
}
