// App settings.

// Where the ProofLog backend runs (no trailing slash).
// - While developing (`npm run dev`), the backend is a separate server on port 8000.
// - In the built app, the backend itself serves the dashboard, so calls go to the
//   same address the page came from ('' = same origin, no CORS needed).
// Override either way without editing code:
//   VITE_API_BASE_URL=http://localhost:9000 npm run dev
export const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL ?? (import.meta.env.DEV ? 'http://localhost:8000' : '')

// Name of the multipart form field the log file is sent in (POST /analyze).
// Must match the backend, e.g. FastAPI `file: UploadFile` -> 'file'.
export const UPLOAD_FIELD_NAME = import.meta.env.VITE_UPLOAD_FIELD_NAME || 'file'

// Online demo build (GitHub Pages): there's no backend, so the dashboard shows a
// real report bundled with the site instead. Build with VITE_DEMO=1.
export const DEMO_MODE = import.meta.env.VITE_DEMO === '1'
export const REPO_URL = 'https://github.com/dweadon/prooflog'

// The real example log the demo report was made from. The online demo serves
// its own copy (so "download" works); locally it comes from the GitHub repo.
export const EXAMPLE_LOG_URL = DEMO_MODE
  ? `${import.meta.env.BASE_URL}OpenSSH_2k.log`
  : `${REPO_URL}/raw/main/examples/OpenSSH_2k.log`
