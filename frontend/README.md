# ProofLog — Dashboard

**AI you can audit.** ProofLog reads a real server log and writes an incident report.
Every AI claim links to the exact log lines that prove it, and this dashboard makes
that proof visible: click a claim, and its evidence lights up in the log.

This repo is the **frontend only** (React + Vite + Tailwind). The backend is a separate
project; the two talk only through `report.json` (format below).

## Install and run

Requires Node.js 18+.

```bash
npm install
npm run dev
```

Open http://localhost:5173.

Build for production: `npm run build` (output in `dist/`), preview it with `npm run preview`.

## Run as one app (backend serves the dashboard)

This folder lives inside the backend project (`prooflog/frontend`). The backend
serves the built dashboard at its root, so one server runs everything:

```bash
cd frontend && npm install && npm run build   # once, and after every frontend change
cd .. && .venv/bin/uvicorn engine.api:app --port 8000
```

Open http://localhost:8000/ — dashboard and API on the same address, no CORS needed.
(The backend's health check is at `/health`.)

For frontend development with live reload, use `npm run dev` instead (http://localhost:5173,
talks to the backend on port 8000).

## Point it at the backend

The backend address lives in `src/config.js` (dev: `http://localhost:8000`; built app: same address as the page).
You can also override it without editing code:

```bash
VITE_API_BASE_URL=http://localhost:9000 npm run dev
```

If the backend expects the uploaded log under a different form field name than `file`,
change `UPLOAD_FIELD_NAME` in `src/config.js` (or set `VITE_UPLOAD_FIELD_NAME`).

No backend? Use **Open report file** to load a saved `report.json` from disk.
`demo-backup/OpenSSH_2k_report.json` is a real report from the backend (public OpenSSH dataset), kept as a demo fallback.

## What the backend must provide

| Endpoint | What it does |
|---|---|
| `GET /report` | Returns the latest `report.json`. Return 404 if there is none yet. |
| `POST /analyze` | Accepts a log file as **multipart/form-data, field name `file`** (configurable), returns `report.json`. |

- Must send CORS headers allowing `http://localhost:5173` (or `*`), or the browser blocks the request.
- On errors, a JSON body like `{"detail": "reason"}` is shown to the user.
- `/analyze` is given up after 10 minutes (change `ANALYZE_TIMEOUT_MS` in `src/api.js`).
- Number log lines from **1**, and make `evidence_lines` use those same numbers.
- Send times as ISO with a timezone (e.g. `2026-10-03T02:01:58Z`); they are shown in UTC to match the log.

### The dashboard double-checks every report

It does not blindly trust the backend. On load it:
- **recounts the trust score** from the claims' own `verified` flags (and says so if the backend's number differs);
- flags evidence pointing at **lines that don't exist**, claims with **no evidence**, logs numbered from **0**,
  duplicate line numbers / alert ids / claim ids, and claims linked to a missing alert.

Problems appear in an amber bar under the header and in the exported PDF.

### report.json

```json
{
  "meta": { "source_name": "string", "source_type": "public dataset | honeypot | own app", "generated_at": "ISO time" },
  "trust_score": { "verified": 0, "total": 0 },
  "alerts": [{ "id": 1, "severity": "low | medium | high | critical", "title": "", "first_seen": "", "last_seen": "", "summary": "" }],
  "claims": [{ "id": 1, "alert_id": 1, "text": "", "evidence_lines": [1, 2], "verified": true, "verifier_note": "" }],
  "log_lines": [{ "line": 1, "text": "", "untrusted_fields": ["username", "user_agent"] }]
}
```

## Using the dashboard

- **Upload log**: sends a log to the backend for analysis.
- **Load latest report**: fetches the backend's most recent report.
- **Open report file**: loads a saved `report.json` (works offline, good demo backup).
- **Export report**: print-friendly view, then **Print / Save as PDF**.
- Click an **alert** (left), then a **claim** (center): its evidence lines highlight in the log (right)
  and the log scrolls to them. Tick **Show only evidence lines** to hide everything else.
- Click a line number under a claim (e.g. **L27**) to jump straight to that line; it gets outlined.
- ✓ green = claim verified against the log. **!** red = not verified, with the verifier's reason.
- Dashed amber underline = **untrusted** text (attacker-controlled, e.g. username, user agent).
  It is displayed as plain text and never treated as instructions. Recognised formats: `key=value`,
  JSON logs, sshd auth logs, Apache/nginx access logs. In other formats the whole line gets an
  **UNTRUSTED** tag instead.
- Keyboard: Tab into a list, ↑ ↓ to move, Enter to select, Esc to clear the selected claim.

## Code map

```
src/
  config.js                 backend address
  api.js                    all backend calls + friendly error messages
  App.jsx                   state (report, selected alert/claim) + layout
  lib/
    untrusted.js            finds username / user agent inside a raw log line
    reportChecks.js         double-checks the report (trust recount, broken evidence links)
    severity.js             severity colors and sort order
    format.js               date formatting
    keyboard.js             arrow-key navigation for lists
    ui.js                   shared button styles
  components/
    Header.jsx              name, data source, time, trust badge
    TrustBadge.jsx          "X of Y claims verified" (green / amber / red)
    Toolbar.jsx             Upload / Load latest / Open file / Export
    FilePickerButton.jsx    button that opens a file chooser
    AlertList.jsx           left panel
    AlertDetail.jsx         center panel
    ClaimItem.jsx           one claim with verified / not verified state
    LogViewer.jsx           right panel, highlight + scroll to evidence
    LogChunk.jsx            block of 500 rows (keeps big logs fast)
    LogLine.jsx             one log row with untrusted fields marked
    ReportChecks.jsx        amber bar listing problems found in the report
    UntrustedText.jsx       the "untrusted" underline / tag + tooltip
    PrintReport.jsx         print / PDF view
    EmptyState.jsx          "No report yet"
    ErrorBanner.jsx         error shown above an existing report
    BusyOverlay.jsx         spinner while the backend works
```
