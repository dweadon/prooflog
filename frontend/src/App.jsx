import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { fetchLatestReport, pollAnalysis, readReportFile, startAnalysis } from './api.js'
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
import HelpDialog from './components/HelpDialog.jsx'
import DemoBanner from './components/DemoBanner.jsx'
import Landing from './components/Landing.jsx'
import DropOverlay from './components/DropOverlay.jsx'
import { scanFile } from './lib/scan.js'
import { computeStats } from './lib/stats.js'
import ResultHeader from './components/results/ResultHeader.jsx'
import ResultTabs from './components/results/ResultTabs.jsx'
import SummaryTab from './components/results/SummaryTab.jsx'
import ScoresTab from './components/results/ScoresTab.jsx'
import AttackersTab from './components/results/AttackersTab.jsx'
import ChecksTab from './components/results/ChecksTab.jsx'
import LogTab from './components/results/LogTab.jsx'
import { AI_AVAILABLE, DEMO_MODE } from './config.js'

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
  const [view, setView] = useState('landing') // 'landing' first, then 'dashboard'
  const [dragging, setDragging] = useState(false) // a file is being dragged over the page
  const [tab, setTab] = useState('summary') // which results tab is open
  const [lastFile, setLastFile] = useState(null) // the file behind an instant scan, for 'Analyse with AI'
  // A live AI analysis filling in: { job, state, pending: Set of claim ids, progress }. null otherwise.
  const [live, setLive] = useState(null)
  const liveJob = useRef(null) // id of the job being polled; anything else stops polling

  // Shared by every way of getting a report: show a busy message,
  // then either show the new report or a friendly error (keeping the old report).
  // Shows a new report from the start: most severe finding selected, Summary tab open.
  const showNewReport = useCallback((data) => {
    setReport(data)
    setSelectedAlertId(sortBySeverity(data.alerts)[0]?.id ?? null)
    setTab('summary')
    setSelectedClaimId(null)
    setJumpTarget(null)
  }, [])

  const loadWith = useCallback(async (message, getReport) => {
    setBusyMessage(message)
    setError(null)
    liveJob.current = null // a new report stops any live analysis updates
    setLive(null)
    try {
      showNewReport(await getReport())
    } catch (e) {
      setError(e.message)
    } finally {
      setBusyMessage(null)
    }
  }, [showNewReport])

  const loadLatest = useCallback(() => loadWith('Loading the last result…', fetchLatestReport), [loadWith])
  // Upload for the full AI analysis. The backend answers at once with the rule-based
  // findings, which are shown straight away; then we poll every 1.5 s and the AI
  // statements and their verdicts fill in on screen as they're written and checked.
  const uploadLog = async (file) => {
    setError(null)
    setBusyMessage(`Uploading ${file.name}…`)
    liveJob.current = null
    let first
    try {
      first = await startAnalysis(file)
    } catch (e) {
      setError(e.message)
      return
    } finally {
      setBusyMessage(null)
    }
    showNewReport(first.report)
    setLive(first)
    if (first.state !== 'running' || !first.job) return
    liveJob.current = first.job
    let failures = 0
    while (liveJob.current === first.job) {
      await new Promise((r) => setTimeout(r, 1500))
      if (liveJob.current !== first.job) return
      try {
        const next = await pollAnalysis(first.job, first.report.log_lines)
        if (liveJob.current !== first.job) return
        failures = 0
        setReport(next.report) // keeps the selected finding, statement and tab
        setLive(next)
        if (next.state !== 'running') liveJob.current = null
      } catch (e) {
        if (++failures >= 5) {
          setError(`Lost contact with the backend while the AI was working: ${e.message}`)
          liveJob.current = null
        }
      }
    }
  }
  const openFile = (file) => loadWith(`Opening ${file.name}…`, () => readReportFile(file))

  // From the landing page: open the report (the example online, the last result locally),
  // or check a new log file. Either way we switch to the dashboard.
  const openReportFromLanding = () => {
    setView('dashboard')
    if (!report) loadLatest()
  }
  // Every way of giving ProofLog a log file (buttons, drag-and-drop) ends here.
  // Online (no backend) the file is scanned instantly in the browser and never
  // uploaded; with the backend running it gets the full AI analysis.
  const handleLogFile = (file) => {
    setView('dashboard')
    if (DEMO_MODE) {
      setLastFile(file)
      return loadWith(`Scanning ${file.name}…`, () => scanFile(file))
    }
    return uploadLog(file)
  }

  // Drag-and-drop anywhere on the page, like VirusTotal: drop a log, get results.
  // The listeners are re-added on every render, so they always see the current state.
  const busy = Boolean(busyMessage)
  useEffect(() => {
    const hasFile = (e) => [...(e.dataTransfer?.types ?? [])].includes('Files')
    const onOver = (e) => {
      if (!hasFile(e)) return
      e.preventDefault()
      if (!busy) setDragging(true)
    }
    const onLeave = (e) => {
      if (!e.relatedTarget) setDragging(false) // left the browser window
    }
    const onDrop = (e) => {
      if (!hasFile(e)) return
      e.preventDefault()
      setDragging(false)
      const file = e.dataTransfer.files[0]
      if (file && !busy) handleLogFile(file)
    }
    window.addEventListener('dragover', onOver)
    window.addEventListener('dragleave', onLeave)
    window.addEventListener('drop', onDrop)
    return () => {
      window.removeEventListener('dragover', onOver)
      window.removeEventListener('dragleave', onLeave)
      window.removeEventListener('drop', onDrop)
    }
  })

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

  // From the other tabs: open a finding (and optionally one of its statements) in the Findings tab.
  const openFinding = (alertId, claimId = null) => {
    setTab('findings')
    selectAlert(alertId)
    if (claimId) setSelectedClaimId(claimId)
  }

  // Double-check the backend's report (trust score recount, broken evidence links, duplicate ids).
  const checks = useMemo(() => (report ? checkReportIntegrity(report) : null), [report])
  const existingLines = useMemo(() => new Set(report?.log_lines.map((l) => l.line)), [report])
  const stats = useMemo(() => (report ? computeStats(report) : null), [report])
  const selectedAlert = report?.alerts.find((a) => a.id === selectedAlertId)
  const alertClaims = report?.claims.filter((c) => c.alert_id === selectedAlertId) ?? []
  const selectedClaim = alertClaims.find((c) => c.id === selectedClaimId) ?? null

  if (view === 'landing') {
    return (
      <>
        <Landing onOpenReport={openReportFromLanding} onUpload={handleLogFile} onShowHelp={() => setShowHelp(true)} />
        {showHelp && <HelpDialog onClose={() => setShowHelp(false)} />}
        {dragging && <DropOverlay />}
      </>
    )
  }

  if (showPrint && report) {
    return <PrintReport report={report} trust={checks.trust} warnings={checks.warnings} onClose={() => setShowPrint(false)} />
  }

  return (
    <div className="flex min-h-screen flex-col bg-slate-950 text-slate-200 lg:h-screen">
      <Header
        onShowHelp={() => setShowHelp(true)}
        onHome={() => setView('landing')}
        actions={
          <Toolbar
            busy={Boolean(busyMessage)}
            hasReport={Boolean(report)}
            onUpload={handleLogFile}
            onLoadLatest={loadLatest}
            onOpenFile={openFile}
            onExport={() => setShowPrint(true)}
          />
        }
      />

      {DEMO_MODE && (
        <DemoBanner
          report={report}
          onAnalyseWithAI={AI_AVAILABLE && lastFile && report?.instant ? () => uploadLog(lastFile) : null}
          aiRunning={live?.state === 'running'}
        />
      )}
      {report && error && <ErrorBanner message={error} onDismiss={() => setError(null)} />}
      {checks && <ReportChecks warnings={checks.warnings} />}
      {!report ? (
        busyMessage ? null : <EmptyState error={error} onUpload={handleLogFile} onShowHelp={() => setShowHelp(true)} />
      ) : (
        <div className="flex flex-col lg:min-h-0 lg:flex-1">
          <ResultHeader report={report} stats={stats} trust={checks.trust} live={live} />
          <ResultTabs
            tab={tab}
            onChange={setTab}
            counts={{ findings: report.alerts.length, attackers: stats.attackers.length, checks: report.claims.length }}
            instant={Boolean(report.instant)}
          />
          {tab === 'findings' ? (
        <main className="mx-4 mb-4 flex flex-col overflow-hidden rounded-xl border border-slate-800 sm:mx-5 lg:grid lg:min-h-0 lg:flex-1 lg:grid-cols-[260px_minmax(0,1fr)_minmax(0,1.15fr)]">
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
              instant={Boolean(report.instant)}
              pending={live?.pending}
              aiRunning={live?.state === 'running'}
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
          ) : (
            <main className="mx-4 mb-4 sm:mx-5 lg:min-h-0 lg:flex-1 lg:overflow-y-auto">
              {tab === 'summary' && <SummaryTab report={report} stats={stats} onGoTo={setTab} />}
              {tab === 'scores' && <ScoresTab report={report} stats={stats} />}
              {tab === 'attackers' && <AttackersTab stats={stats} onOpenFinding={openFinding} />}
              {tab === 'checks' && <ChecksTab report={report} onOpenFinding={openFinding} pending={live?.pending} />}
              {tab === 'log' && <LogTab report={report} stats={stats} />}
            </main>
          )}
        </div>
      )}

      {busyMessage && <BusyOverlay message={busyMessage} />}
      {showHelp && <HelpDialog onClose={() => setShowHelp(false)} />}
      {dragging && <DropOverlay />}
    </div>
  )
}
