"""Stage 5: HTTP API for the dashboard.

POST /analyze  upload a log file -> returns report.json (and saves it)
GET  /report   returns the latest saved report
GET  /         health check

Run:  uvicorn engine.api:app --port 8000
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
from pathlib import Path

from fastapi import FastAPI, File, Form, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from . import progress
from .claims import MODEL, PROVIDER, VERIFY_MODEL
from . import jobs
from .report import BadLogError, build_report

MAX_UPLOAD_BYTES = 10 * 1024 * 1024  # 10 MB
PROJECT_DIR = Path(__file__).resolve().parent.parent  # paths below work no matter where the server is started
REPORT_PATH = Path(os.environ.get("PROOFLOG_REPORT_PATH", PROJECT_DIR / "reports" / "latest.json"))

# Only one analysis at a time: a second upload while one is running gets a
# clear 409 instead of doubling the AI cost and mixing up /status.
_analysis_lock = threading.Lock()

app = FastAPI(title="ProofLog Engine")

# Let the dashboard call us from any origin (hackathon setup).
# The AI-errors header is exposed so the browser can read it.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-ProofLog-AI-Errors", "X-ProofLog-Cache"],
)


# Builds a JSON error response: {"error": "..."} with the given HTTP status.
def error(status: int, message: str) -> JSONResponse:
    return JSONResponse(status_code=status, content={"error": message})


# Saves the report to disk atomically: write a temp file, then rename it over
# the old one, so a crash mid-write never leaves a half-written report.
def save_report(report: dict) -> None:
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = REPORT_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(report), encoding="utf-8")
    os.replace(tmp, REPORT_PATH)


# Where a fully successful report for exactly this input is cached. The key
# covers the file bytes, its name and every option that changes the result.
def cache_path(data: bytes, filename: str, source_type: str, year, inject: bool) -> Path:
    h = hashlib.sha256(f"{MODEL}|{filename}|{source_type}|{year}|{inject}|".encode() + data).hexdigest()
    return REPORT_PATH.parent / "cache" / f"{h[:32]}.json"


# Pre-loads the cache with saved, fully verified reports for the bundled example
# logs (examples/<name>.log + examples/<name>.report.json), so analysing the
# example is instant even on hosts that wipe their disk when they sleep.
def seed_example_cache() -> None:
    for log in sorted((PROJECT_DIR / "examples").glob("*.log")):
        saved = log.with_suffix(".report.json")
        if not saved.exists():
            continue
        target = cache_path(log.read_bytes(), log.name, "public dataset", None, False)
        if target.exists():
            continue
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(saved.read_text(encoding="utf-8"), encoding="utf-8")
        except OSError:
            pass  # not critical: the example just gets analysed the slow way


seed_example_cache()


# Health check, so the dashboard (or you) can see the server is up.
@app.get("/health")
def health():
    key = "GROQ_API_KEY" if PROVIDER == "groq" else "ANTHROPIC_API_KEY"
    return {"status": "ok", "provider": PROVIDER, "model": MODEL, "verify_model": VERIFY_MODEL,
            "ai_key_set": bool(os.environ.get(key)),
            "version": os.environ.get("RENDER_GIT_COMMIT", "local")[:7]}  # Render sets the deployed commit


# Accepts an uploaded log file, runs the whole pipeline, saves and returns report.json.
# If the AI failed for some alerts, the report is still returned, and the
# X-ProofLog-AI-Errors header says why (the contract has no field for errors).
@app.post("/analyze")
def analyze(
    file: UploadFile = File(...),
    source_type: str = Form("public dataset"),
    year: int | None = Form(None),
    debug_inject_false_claim: bool = Form(False),
    use_cache: bool = Form(True),
):
    data = file.file.read(MAX_UPLOAD_BYTES + 1)
    if len(data) > MAX_UPLOAD_BYTES:
        return error(413, f"File too large (max {MAX_UPLOAD_BYTES // (1024 * 1024)} MB).")
    filename = file.filename or "upload.log"
    inject = debug_inject_false_claim or os.environ.get("PROOFLOG_DEBUG_INJECT") == "1"

    # Same file and options as a previous fully successful run: answer instantly.
    cached = cache_path(data, filename, source_type, year, inject)
    if use_cache and cached.exists():
        try:
            report = json.loads(cached.read_text(encoding="utf-8"))
            save_report(report)
            return JSONResponse(content=report, headers={"X-ProofLog-Cache": "hit"})
        except (OSError, json.JSONDecodeError):
            pass  # unreadable cache entry: just analyse again

    if not _analysis_lock.acquire(blocking=False):
        return error(409, "An analysis is already running. Watch GET /status and try again when it's done.")
    try:
        report, ai_errors = build_report(data, filename, source_type, year=year, inject_false=inject)
    except BadLogError as e:
        progress.start_stage("error")
        return error(400, str(e))
    except Exception as e:  # last-resort guard: never crash the server
        progress.start_stage("error")
        return error(500, f"Analysis failed unexpectedly: {type(e).__name__}")
    finally:
        _analysis_lock.release()

    try:
        save_report(report)
        if not ai_errors and report["claims"]:  # cache only complete, AI-backed reports
            cached.parent.mkdir(parents=True, exist_ok=True)
            cached.write_text(json.dumps(report), encoding="utf-8")
    except OSError as e:
        return error(500, f"Report built but could not be saved: {e.strerror}")

    headers = {"X-ProofLog-Cache": "miss"}
    if ai_errors:
        unique = sorted(set(ai_errors.values()))
        headers["X-ProofLog-AI-Errors"] = f"{len(ai_errors)} issue(s): " + " | ".join(unique)
    return JSONResponse(content=report, headers=headers)


# Live jobs by id (only the most recent few are kept).
JOBS: dict[str, jobs.Job] = {}
MAX_JOBS = 5


# Called when a live job ends: saves the report as the latest, caches it if
# complete, and frees the one-analysis-at-a-time lock.
def finish_job(job, report: dict, ai_errors: dict, cached: Path) -> None:
    try:
        save_report(report)
        if job.state == "done" and not ai_errors and report["claims"]:
            cached.parent.mkdir(parents=True, exist_ok=True)
            cached.write_text(json.dumps(report), encoding="utf-8")
    except OSError:
        pass
    finally:
        _analysis_lock.release()


# Starts a live analysis and answers at once with the rule-based findings.
# The AI statements and their verdicts then fill in: poll GET /analyze/{job}.
# A file analysed before is answered from the cache, already complete.
@app.post("/analyze/start")
def analyze_start(
    file: UploadFile = File(...),
    source_type: str = Form("public dataset"),
    year: int | None = Form(None),
    debug_inject_false_claim: bool = Form(False),
    use_cache: bool = Form(True),
):
    data = file.file.read(MAX_UPLOAD_BYTES + 1)
    if len(data) > MAX_UPLOAD_BYTES:
        return error(413, f"File too large (max {MAX_UPLOAD_BYTES // (1024 * 1024)} MB).")
    filename = file.filename or "upload.log"
    inject = debug_inject_false_claim or os.environ.get("PROOFLOG_DEBUG_INJECT") == "1"

    cached = cache_path(data, filename, source_type, year, inject)
    if use_cache and cached.exists():
        try:
            report = json.loads(cached.read_text(encoding="utf-8"))
            save_report(report)
            done = {"alerts_done": 0, "alerts_total": 0, "claims_pending": 0, "elapsed_seconds": 0}
            return JSONResponse(content={"job": None, "state": "done", "report": report, "pending_claims": [],
                                         "progress": done}, headers={"X-ProofLog-Cache": "hit"})
        except (OSError, json.JSONDecodeError):
            pass

    if not _analysis_lock.acquire(blocking=False):
        return error(409, "An analysis is already running. Try again in a minute.")
    try:
        job = jobs.start_job(data, filename, source_type, year, inject,
                             on_done=lambda j, report, errs: finish_job(j, report, errs, cached))
    except BadLogError as e:
        _analysis_lock.release()
        return error(400, str(e))
    except Exception as e:  # last-resort guard: never crash the server
        _analysis_lock.release()
        return error(500, f"Analysis failed unexpectedly: {type(e).__name__}")

    JOBS[job.id] = job
    for old_id in list(JOBS)[:-MAX_JOBS]:
        JOBS.pop(old_id, None)
    return JSONResponse(status_code=202, content=job.snapshot(), headers={"X-ProofLog-Cache": "miss"})


# The live job so far: the report (AI statements fill in as they're written and
# checked), which statements are still being checked, and progress counts.
# `lines=0` leaves out the log lines, which the dashboard already has.
@app.get("/analyze/{job_id}")
def analyze_status(job_id: str, lines: int = 1):
    job = JOBS.get(job_id)
    if job is None:
        return error(404, "No such analysis (it may have finished long ago). Start a new one.")
    return job.snapshot(include_lines=bool(lines))


# Progress of the current analysis, for the dashboard's loading screen:
# {"stage": "idle|parsing|writing_claims|verifying|done|error", "done": 3, "total": 12, "elapsed_seconds": 41}
@app.get("/status")
def status():
    return progress.snapshot()


# Returns the latest saved report, or 404 if nothing has been analysed yet.
@app.get("/report")
def latest_report():
    if not REPORT_PATH.exists():
        return error(404, "No report yet. POST a log file to /analyze first.")
    try:
        return JSONResponse(content=json.loads(REPORT_PATH.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError):
        return error(500, "Saved report is unreadable. Run /analyze again.")


# Finds the dashboard's files so this one server can also serve the frontend.
# Looks for a built app first (frontend/dist from Vite, frontend/build from
# Create React App), then plain HTML in frontend/. PROOFLOG_FRONTEND_DIR overrides it.
def find_frontend() -> Path | None:
    candidates = [os.environ.get("PROOFLOG_FRONTEND_DIR", "")] + [
        str(PROJECT_DIR / "frontend" / sub) for sub in ("dist", "build", "")]
    for folder in candidates:
        if folder and (Path(folder) / "index.html").is_file():
            return Path(folder)
    return None


# Serves the dashboard at "/" if it's there; otherwise "/" is the health check.
# This comes last, so /analyze, /report, /status and /health keep working.
FRONTEND_DIR = find_frontend()
if FRONTEND_DIR:
    app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")
else:
    app.add_api_route("/", health, methods=["GET"])
