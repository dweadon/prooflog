import { useCallback, useEffect, useMemo, useState } from 'react'
import { analyzeLog, fetchLatestReport, fetchStatus, readReportFile } from './api.js'
import { sortBySeverity } from './lib/severity.js'
import { checkReportIntegrity } from './lib/reportChecks.js'
import Header from './components/Header.jsx'
import Toolbar from './components/Toolbar.jsx'
import AlertList from './components/AlertList.jsx'
import AlertDetail from './components/AlertDetail.jsx'
import LogViewer from './components/LogViewer.jsx'
import EmptyState from './components/EmptyState.jsx'
import ErrorBanner from './components/ErrorBanner.jsx'
import ReportChecks from './components/ReportChecks.jsx'
import BusyOverlay from './components/BusyOverlay.jsx'
import PrintReport from './components/PrintReport.jsx'
import SummaryBanner from './components/SummaryBanner.jsx'
import HelpDialog from './components/HelpDialog.jsx'
import DemoBanner from './components/DemoBanner.jsx'
import { DEMO_MODE } from './config.js'

// App: holds the current report and what's selected, and lays out the
// dashboard: alerts (left), alert details + claims (center), log (right).
// On small screens the three panels stack vertically.
export default function App() {
  const [report, setReport] = useState(null)
  const [busyMessage, setBusyMessage] = useState(null) // non-null while waiting on the backend
  const [error, setError] = useState(null)
  const [selectedAlertId, setSelectedAlertId] = useState(null)
  const [selectedClaimId, setSelectedClaimId] = useState(null)
  const [onlyEvidence, setOnlyEvidence] = useState(false)
  // Set when a line number under a claim is clicked: { line, nonce }. nonce lets the same line be re-jumped to.
  const [jumpTarget, setJumpTarget] = useState(null)
  const [showPrint, setShowPrint] = useState(false)
  const [showHelp, setShowHelp] = useState(false)
  const [progress, setProgress] = useState(null) // backend progress while a log is being checked

  // Shared by every way of getting a report: show a busy message,
  // then either show the new report or a friendly error (keeping the old report).
  const loadWith = useCallback(async (message, getReport) => {
    setBusyMessage(message)
    setError(null)
    try {
      const data = await getReport()
      setReport(data)
      setSelectedAlertId(sortBySeverity(data.alerts)[0]?.id ?? null) // start on the most severe alert
      setSelectedClaimId(null)
      setJumpTarget(null)
    } catch (e) {
      setError(e.message)
    } finally {
      setBusyMessage(null)
    }
  }, [])

  const loadLatest = useCallback(() => loadWith('Loading the last result…', fetchLatestReport), [loadWith])
  // Upload: while the backend works (can take minutes), poll GET /status every 2 seconds
  // and show its progress in the spinner, so the demo never looks frozen.
  const uploadLog = (file) => {
    const started = Date.now()
    setProgress({ stage: 'parsing', done: 0, total: 0, seconds: 0 })
    const timer = setInterval(async () => {
      const s = await fetchStatus()
      const seconds = Math.round((Date.now() - started) / 1000)
      setProgress((current) => (current ? { ...current, ...(s?.stage && s.stage !== 'idle' ? s : {}), seconds } : current))
    }, 2000)
    return loadWith(`Checking ${file.name}`, () => analyzeLog(file)).finally(() => {
      clearInterval(timer)
      setProgress(null)
    })
  }
  const openFile = (file) => loadWith(`Opening ${file.name}…`, () => readReportFile(file))

  // Try to show the backend's latest report on startup.
  // A "no report yet" error here is normal, so it's shown quietly in the empty state.
  useEffect(() => {
    loadLatest()
  }, [loadLatest])

  const selectAlert = (id) => {
    setSelectedAlertId(id)
    setSelectedClaimId(null)
    setJumpTarget(null)
  }

  // Clicking a claim: show its evidence and scroll to the first line.
  const selectClaim = (id) => {
    setSelectedClaimId(id)
    setJumpTarget(null)
  }

  // Clicking "L27" under a claim: select that claim and scroll to line 27 exactly.
  const jumpToLine = (claimId, line) => {
    setSelectedClaimId(claimId)
    setJumpTarget({ line, nonce: Date.now() })
  }

  // Double-check the backend's report (trust score recount, broken evidence links, duplicate ids).
  const checks = useMemo(() => (report ? checkReportIntegrity(report) : null), [report])
  const existingLines = useMemo(() => new Set(report?.log_lines.map((l) => l.line)), [report])
  const selectedAlert = report?.alerts.find((a) => a.id === selectedAlertId)
  const alertClaims = report?.claims.filter((c) => c.alert_id === selectedAlertId) ?? []
  const selectedClaim = alertClaims.find((c) => c.id === selectedClaimId) ?? null

  if (showPrint && report) {
    return <PrintReport report={report} trust={checks.trust} warnings={checks.warnings} onClose={() => setShowPrint(false)} />
  }

  return (
    <div className="flex min-h-screen flex-col bg-slate-950 text-slate-200 lg:h-screen">
      <Header
        report={report}
        trust={checks?.trust}
        onShowHelp={() => setShowHelp(true)}
        actions={
          <Toolbar
            busy={Boolean(busyMessage)}
            hasReport={Boolean(report)}
            onUpload={uploadLog}
            onLoadLatest={loadLatest}
            onOpenFile={openFile}
            onExport={() => setShowPrint(true)}
          />
        }
      />

      {DEMO_MODE && <DemoBanner />}
      {report && error && <ErrorBanner message={error} onDismiss={() => setError(null)} />}
      {checks && <ReportChecks warnings={checks.warnings} />}
      {report && <SummaryBanner report={report} trust={checks.trust} onShowHelp={() => setShowHelp(true)} />}

      {!report ? (
        busyMessage ? null : <EmptyState error={error} onUpload={uploadLog} onShowHelp={() => setShowHelp(true)} />
      ) : (
        <main className="flex flex-col lg:grid lg:min-h-0 lg:flex-1 lg:grid-cols-[260px_minmax(0,1fr)_minmax(0,1.15fr)]">
          <div className="border-b border-slate-800 lg:min-h-0 lg:overflow-y-auto lg:border-r lg:border-b-0">
            <AlertList alerts={report.alerts} selectedId={selectedAlertId} onSelect={selectAlert} />
          </div>
          {/* key = alert id, so switching alerts starts this panel scrolled to the top */}
          <div
            key={selectedAlertId}
            className="border-b border-slate-800 lg:min-h-0 lg:overflow-y-auto lg:border-r lg:border-b-0"
          >
            <AlertDetail
              alert={selectedAlert}
              claims={alertClaims}
              selectedClaimId={selectedClaimId}
              onSelectClaim={selectClaim}
              onJumpToLine={jumpToLine}
              jumpLine={jumpTarget?.line}
              existingLines={existingLines}
            />
          </div>
          <div className="h-[75vh] bg-slate-900/40 lg:h-auto lg:min-h-0">
            <LogViewer
              lines={report.log_lines}
              claim={selectedClaim}
              jumpTarget={selectedClaim ? jumpTarget : null}
              onlyEvidence={onlyEvidence}
              onToggleOnlyEvidence={setOnlyEvidence}
            />
          </div>
        </main>
      )}

      {busyMessage && <BusyOverlay message={busyMessage} progress={progress} />}
      {showHelp && <HelpDialog onClose={() => setShowHelp(false)} />}
    </div>
  )
}
