"""Live analysis jobs: results appear while the AI is still working.

Starting a job returns at once with the rule-based findings (no AI needed).
Then, in the background, each finding's AI statements are written and each
statement is checked as soon as it exists, while other findings are still
being written. The dashboard polls the job and shows statements and verdicts
as they arrive. The finished report is the same report.json as /analyze.
"""
from __future__ import annotations

import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, wait
from dataclasses import replace

from .claims import PARALLEL_CALLS, AIError, analyze_alert, choose_alerts_for_ai, make_client
from .detect import run_detections
from .report import TIME_BUDGET_SECONDS, assemble_report, prepare_lines
from .schema import Claim
from .verify import inject_false_claim, verify_claim

CHECKING_NOTE = "Checking against the log…"


class Job:
    """One analysis in progress. All shared state is read and written under `lock`."""

    def __init__(self, source_name, source_type, lines, alerts, inject_false):
        self.id = uuid.uuid4().hex[:12]
        self.lock = threading.Lock()
        self.state = "running"          # running | done | error
        self.started = time.monotonic()
        self.seconds = None             # total time once finished
        self.source_name, self.source_type = source_name, source_type
        self.lines, self.alerts = lines, alerts
        self.inject_false = inject_false
        self.claims: list[Claim] = []
        self.pending: set[int] = set()  # claim ids still being checked
        self.errors: dict[int, str] = {}
        self.alerts_total = 0
        self.alerts_done = 0

    # A copy of the job right now: the report so far (contract format) plus progress.
    # `include_lines=False` leaves out log_lines (they never change during a job),
    # so the dashboard's frequent updates stay small.
    def snapshot(self, include_lines: bool = True) -> dict:
        with self.lock:
            report = assemble_report(self.source_name, self.source_type, self.alerts, self.claims,
                                     self.lines if include_lines else [])
            if not include_lines:
                del report["log_lines"]
            return {
                "job": self.id,
                "state": self.state,
                "report": report,
                "pending_claims": sorted(self.pending),
                "progress": {
                    "alerts_done": self.alerts_done,
                    "alerts_total": self.alerts_total,
                    "claims_pending": len(self.pending),
                    "elapsed_seconds": round(self.seconds if self.seconds is not None
                                             else time.monotonic() - self.started),
                },
            }

    # Adds new statements (shown as "checking" until verified). Returns them.
    def add_claims(self, alert_id: int, items: list[dict]) -> list[Claim]:
        with self.lock:
            new = []
            for item in items:
                claim = Claim(id=len(self.claims) + 1, alert_id=alert_id, text=item["text"],
                              evidence_lines=item["evidence_lines"], verifier_note=CHECKING_NOTE)
                self.claims.append(claim)
                self.pending.add(claim.id)
                new.append(claim)
            return new


# Checks the upload, runs the rules, and starts the AI work in the background.
# Returns the job immediately. Raises BadLogError for unusable files.
# `on_done(job, report, ai_errors)` is called once when the job ends, success or not.
def start_job(data: bytes, source_name: str, source_type: str, year=None, inject_false=False,
              client=None, on_done=None) -> Job:
    lines = prepare_lines(data, source_type, year)
    alerts = run_detections(lines)
    job = Job(source_name, source_type, lines, alerts, inject_false)
    threading.Thread(target=_run, args=(job, client, on_done), daemon=True).start()
    return job


# The background work: write statements per finding, and check each one as soon as it exists.
def _run(job: Job, client, on_done) -> None:
    deadline = job.started + TIME_BUDGET_SECONDS
    lines_by_number = {l.line: l for l in job.lines}
    all_usernames = {l.username for l in job.lines if l.username}
    chosen = choose_alerts_for_ai(job.alerts)
    client_error = None
    try:
        try:
            client = client or make_client()
        except AIError as e:
            client_error = str(e)

        chosen_ids = {a.id for a in chosen}
        with job.lock:
            job.alerts_total = len(chosen)
            for alert in job.alerts:
                if alert.id not in chosen_ids:
                    alert.summary += " (Not sent to AI: over the per-report alert limit.)"

        # Checks one statement on a copy, then saves the verdict (so readers never see half an update).
        def check(claim: Claim) -> None:
            result = replace(claim)
            verify_claim(result, lines_by_number, all_usernames, client, client_error, deadline)
            with job.lock:
                claim.verified, claim.verifier_note, claim.checked = result.verified, result.verifier_note, result.checked
                job.pending.discard(claim.id)

        with ThreadPoolExecutor(max_workers=PARALLEL_CALLS) as writers, \
             ThreadPoolExecutor(max_workers=PARALLEL_CALLS) as checkers:
            checks = []

            # Debug: plant the false claim first; plain code catches it at once, no AI needed.
            if job.inject_false and job.alerts:
                planted: list[Claim] = []
                inject_false_claim(planted, job.alerts)
                for claim in job.add_claims(planted[0].alert_id, [
                        {"text": planted[0].text, "evidence_lines": planted[0].evidence_lines}]):
                    checks.append(checkers.submit(check, claim))

            # Writes one finding's statements, then hands each one to the checkers.
            def write(alert) -> None:
                if client_error:
                    result_error, result = client_error, None
                else:
                    result = analyze_alert(client, alert, lines_by_number, deadline)
                    result_error = result.error
                with job.lock:
                    job.alerts_done += 1
                    if result_error:
                        job.errors[alert.id] = result_error
                        alert.summary += " (AI analysis unavailable for this alert.)"
                        return
                    alert.summary = result.summary
                for claim in job.add_claims(alert.id, result.claims):
                    checks.append(checkers.submit(check, claim))

            # All writers finish first, so by then every check has been submitted.
            wait([writers.submit(write, a) for a in chosen])
            wait(checks)

        with job.lock:
            job.state = "done"
            job.seconds = time.monotonic() - job.started
    except Exception:  # never leave a job hanging
        with job.lock:
            job.state = "error"
            job.seconds = time.monotonic() - job.started
            for claim in job.claims:
                if not claim.checked:
                    claim.verifier_note = "Not checked: the analysis stopped unexpectedly."
            job.pending.clear()
    finally:
        snap = job.snapshot()
        unchecked = [c for c in job.claims if not c.checked]
        errors = dict(job.errors)
        if unchecked:
            errors[0] = f"{len(unchecked)} claim(s) could not be fully verified."
        if on_done:
            on_done(job, snap["report"], errors)
