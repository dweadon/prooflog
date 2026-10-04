import FilePickerButton from './FilePickerButton.jsx'
import { BUTTON, PRIMARY_BUTTON } from '../lib/ui.js'

// Toolbar: the four things you can do.
// Upload log  -> backend analyzes a new log (POST /analyze)
// Load latest -> fetch the backend's most recent report (GET /report)
// Open file   -> open a saved report.json, no backend needed
// Export      -> print-friendly report for "Save as PDF"
export default function Toolbar({ busy, hasReport, onUpload, onLoadLatest, onOpenFile, onExport }) {
  return (
    <>
      <FilePickerButton onFile={onUpload} className={PRIMARY_BUTTON} disabled={busy}>
        Check a log file
      </FilePickerButton>
      <button type="button" onClick={onLoadLatest} className={BUTTON} disabled={busy} title="Show the most recent result again">
        Last result
      </button>
      <FilePickerButton onFile={onOpenFile} accept=".json,application/json" className={BUTTON} disabled={busy}>
        Open saved report
      </FilePickerButton>
      <button type="button" onClick={onExport} className={BUTTON} disabled={busy || !hasReport}>
        Save as PDF
      </button>
    </>
  )
}
