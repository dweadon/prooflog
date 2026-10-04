// App settings.

// Online demo build (GitHub Pages): built with VITE_DEMO=1. The bundled example
// report is shown, and dropped files are scanned instantly in the browser.
export const DEMO_MODE = import.meta.env.VITE_DEMO === '1'

// Optional: the address of a hosted ProofLog backend (e.g. on Render) that the
// online demo can send a file to for the full AI analysis. Set at build time with
// VITE_LIVE_API_URL; empty = the demo has no AI backend.
export const LIVE_API_URL = (import.meta.env.VITE_LIVE_API_URL || '').replace(/\/+$/, '')

// Where the ProofLog backend runs (no trailing slash).
// - While developing (`npm run dev`), the backend is a separate server on port 8000.
// - In the built app, the backend itself serves the dashboard, so calls go to the
//   same address the page came from ('' = same origin, no CORS needed).
// - In the online demo, it's the hosted backend above (if any).
// Override with VITE_API_BASE_URL=http://localhost:9000 npm run dev
export const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL ??
  (DEMO_MODE ? LIVE_API_URL : import.meta.env.DEV ? 'http://localhost:8000' : '')

// True when this page can ask a backend for the full AI analysis.
export const AI_AVAILABLE = !DEMO_MODE || Boolean(LIVE_API_URL)

// Name of the multipart form field the log file is sent in (POST /analyze).
// Must match the backend, e.g. FastAPI `file: UploadFile` -> 'file'.
export const UPLOAD_FIELD_NAME = import.meta.env.VITE_UPLOAD_FIELD_NAME || 'file'

export const REPO_URL = 'https://github.com/dweadon/prooflog'

// The real example log the demo report was made from. The online demo serves
// its own copy (so "download" works); locally it comes from the GitHub repo.
export const EXAMPLE_LOG_URL = DEMO_MODE
  ? `${import.meta.env.BASE_URL}OpenSSH_2k.log`
  : `${REPO_URL}/raw/main/examples/OpenSSH_2k.log`
