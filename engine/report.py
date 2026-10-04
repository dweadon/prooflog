"""Builds the full report.json (contract format) by running every stage in order."""
from __future__ import annotations

import os
import time
from datetime import datetime, timezone

from . import progress
from .claims import PROVIDER, write_claims
from .detect import run_detections
from .parser import decode_log_bytes, parse_text
from .schema import OTHER
from .verify import inject_false_claim, verify_claims

SOURCE_TYPES = ("public dataset", "honeypot", "own app")

# The whole analysis must finish within this many seconds, so /analyze always
# answers. AI work still pending when time runs out is skipped and explained.
# Groq's free tier is rate-limited, so it gets longer by default.
TIME_BUDGET_SECONDS = int(os.environ.get("PROOFLOG_TIME_BUDGET", 420 if PROVIDER == "groq" else 240))


class BadLogError(ValueError):
    """The uploaded file can't be analysed (empty, not text, or not an SSH auth log)."""


# Counts verified claims for the trust score: {"verified": X, "total": Y}.
def trust_score(claims) -> dict:
    return {"verified": sum(1 for c in claims if c.verified), "total": len(claims)}


# Runs parse -> detect -> AI claims -> verify and returns (report_dict, ai_errors).
# If any claim couldn't be fully checked (no key, AI error, time budget), that
# counts as an AI error too, so the API won't cache an incomplete report.
# `inject_false` (debug) adds one deliberately false claim before
# verification, to demo the verifier catching it.
# Raises BadLogError for files we can't analyse.
def build_report(data: bytes, source_name: str, source_type: str, year: int | None = None,
                 client=None, inject_false: bool = False) -> tuple[dict, dict[int, str]]:
    if source_type not in SOURCE_TYPES:
        raise BadLogError(f"source_type must be one of: {', '.join(SOURCE_TYPES)}")
    if not data.strip():
        raise BadLogError("The file is empty.")
    if b"\x00" in data[:8192]:
        raise BadLogError("This looks like a binary file, not a text log.")

    progress.start_stage("parsing")
    lines = parse_text(decode_log_bytes(data), year=year)
    if not any(l.event_type != OTHER for l in lines):
        raise BadLogError("No SSH login events found. Expected an SSH auth.log (Loghub SSH format).")

    start = time.monotonic()
    alerts = run_detections(lines)
    # Claim writing gets the first 60% of the time budget, and verification the rest.
    claims, ai_errors = write_claims(alerts, lines, client=client,
                                     deadline=start + TIME_BUDGET_SECONDS * 0.6)
    if inject_false:
        inject_false_claim(claims, alerts)
    verify_claims(claims, lines, client=client, deadline=start + TIME_BUDGET_SECONDS)

    report = {
        "meta": {
            "source_name": source_name,
            "source_type": source_type,
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        },
        "trust_score": trust_score(claims),
        "alerts": [a.to_contract() for a in alerts],
        "claims": [c.to_contract() for c in claims],
        "log_lines": [l.to_contract() for l in lines],
    }
    unchecked = [c for c in claims if not c.checked]
    if unchecked:
        ai_errors = {**ai_errors, 0: f"{len(unchecked)} claim(s) could not be fully verified."}
    progress.start_stage("done")
    return report, ai_errors
