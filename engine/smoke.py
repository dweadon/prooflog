"""Pre-demo check: runs the REAL AI on the smallest alert only (a few cents,
about a minute) to prove the API accepts our requests before the full run.

Run:  python -m engine.smoke [examples/OpenSSH_2k.log]     (needs ANTHROPIC_API_KEY or GROQ_API_KEY)
Prints PASS or FAIL, and estimates how long a full analysis will take.
"""
from __future__ import annotations

import math
import sys
import time

from .claims import MAX_AI_ALERTS, MODEL, PARALLEL_CALLS, PROVIDER, AIError, make_client, write_claims
from .detect import format_ranges, run_detections
from .parser import parse_file
from .report import TIME_BUDGET_SECONDS
from .verify import inject_false_claim, verify_claims


# Prints a step result and returns whether it passed.
def report_step(ok: bool, message: str) -> bool:
    print(f"  {'OK  ' if ok else 'FAIL'} {message}")
    return ok


# Runs the check and returns the exit code: 0 = ready for the demo, 1 = something's wrong.
def main() -> int:
    path = sys.argv[1] if len(sys.argv) > 1 else "examples/OpenSSH_2k.log"
    print(f"ProofLog smoke test: {path}, provider {PROVIDER}, model {MODEL}\n")

    try:
        client = make_client()
        lines = parse_file(path)
    except (AIError, OSError) as e:
        print(f"FAIL: {e}")
        return 1

    alerts = run_detections(lines)
    if not alerts:
        print("FAIL: no alerts detected in this file, nothing to test.")
        return 1
    alert = min(alerts, key=lambda a: len(a.evidence_lines))
    print(f"Testing alert {alert.id} ({alert.title}, lines {format_ranges(alert.evidence_lines)})")

    t0 = time.monotonic()
    claims, errors = write_claims([alert], lines, client=client)
    claim_seconds = time.monotonic() - t0
    if not report_step(not errors and bool(claims),
                       f"claim writer: {len(claims)} claims in {claim_seconds:.0f}s"
                       + (f" - {errors[alert.id]}" if errors else "")):
        return 1
    print(f"       summary: {alert.summary}")

    inject_false_claim(claims, [alert])
    t0 = time.monotonic()
    verify_claims(claims, lines, client=client)
    verify_seconds = (time.monotonic() - t0) / max(1, math.ceil(len(claims) / PARALLEL_CALLS))
    real, fake = claims[:-1], claims[-1]
    for c in real:
        print(f"       {'VERIFIED  ' if c.verified else 'UNVERIFIED'} {c.text}\n                  {c.verifier_note}")
    ok = report_step(all(c.checked for c in real), "verifier: every real claim got a final verdict")
    ok &= report_step(not fake.verified, f"verifier caught the injected false claim ({fake.verifier_note})")
    if not any(c.verified for c in real):
        print("  WARN no real claim was verified: read the notes above, the prompt or checks may be too strict.")

    rounds = lambda n: math.ceil(n / PARALLEL_CALLS)
    estimate = rounds(min(len(alerts), MAX_AI_ALERTS)) * claim_seconds \
        + rounds(min(len(alerts), MAX_AI_ALERTS) * 3) * verify_seconds
    print(f"\nFull run estimate for {len(alerts)} alerts: about {estimate / 60:.1f} minutes "
          f"(time budget {TIME_BUDGET_SECONDS}s).")
    print("PASS: ready for the demo." if ok else "FAIL: see above.")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
