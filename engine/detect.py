"""Stage 2: rule-based detection (no AI).

Each rule is plain, deterministic code over the parsed lines. Every alert
remembers the exact line numbers that triggered it (internally). Stage 3
sends only those lines to the AI.

Run:  python -m engine.detect data/OpenSSH_2k.log          (table)
      python -m engine.detect data/OpenSSH_2k.log --json   (alerts in contract format)
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from datetime import datetime, timedelta

from .parser import parse_file
from .schema import (
    ACCEPTED_LOGIN, BRUTE_FORCE, FAILED_PASSWORD, INVALID_USER, ODD_HOUR_LOGIN,
    PASSWORD_SPRAYING, SUCCESS_AFTER_FAILURES, Alert, ParsedLine,
)

# ---- Thresholds: change these to tune detection --------------------------------
BRUTE_FORCE_MIN_FAILURES = 5        # at least this many failed passwords...
BRUTE_FORCE_WINDOW_SECONDS = 600    # ...from one IP within 10 minutes

SPRAY_MIN_USERNAMES = 4             # at least this many different usernames...
SPRAY_WINDOW_SECONDS = 1800         # ...tried by one IP within 30 minutes
SPRAY_MAX_TOP_USERNAME_SHARE = 0.6  # if one username gets more than 60% of the attempts,
                                    # it's brute force on that account, not spraying

SUCCESS_MIN_PRIOR_FAILURES = 5      # an accepted login after this many failures...
SUCCESS_LOOKBACK_SECONDS = 3600     # ...from the same IP in the hour before

ODD_HOUR_START = 0                  # accepted logins from 00:00...
ODD_HOUR_END = 6                    # ...up to 05:59 (the log's own clock) are "odd"
# --------------------------------------------------------------------------------


# Converts a line's ISO timestamp into a datetime we can compare and subtract.
def when(line: ParsedLine) -> datetime:
    return datetime.fromisoformat(line.timestamp)


# Groups lines of the given event types by source IP, sorted by time.
# Lines without a timestamp or IP are skipped, because time rules can't use them.
def lines_by_ip(lines: list[ParsedLine], event_types: set[str]) -> dict[str, list[ParsedLine]]:
    groups = defaultdict(list)
    for l in lines:
        if l.event_type in event_types and l.source_ip and l.timestamp:
            groups[l.source_ip].append(l)
    for events in groups.values():
        events.sort(key=lambda l: (when(l), l.line))
    return groups


# Counts failed passwords. A "message repeated N times" line counts as N.
def count_failures(events: list[ParsedLine]) -> int:
    return sum(l.repeat_count for l in events if l.event_type == FAILED_PASSWORD)


# The different usernames in these events, sorted. These values are UNTRUSTED.
def distinct_usernames(events: list[ParsedLine]) -> list[str]:
    return sorted({l.username for l in events if l.username is not None})


# Finds "bursts" in one IP's time-ordered events.
# A sliding time window moves along the events, and every event inside a
# window that passes `qualifies` gets marked. Marked events close together
# in time are then joined into one burst, so one attack gives one alert.
def find_bursts(events: list[ParsedLine], window_seconds: int, qualifies) -> list[list[ParsedLine]]:
    window = timedelta(seconds=window_seconds)
    marked = [False] * len(events)
    left = 0
    for right in range(len(events)):
        while when(events[right]) - when(events[left]) > window:
            left += 1
        if qualifies(events[left:right + 1]):
            for i in range(left, right + 1):
                marked[i] = True

    bursts, previous = [], None
    for event, is_marked in zip(events, marked):
        if not is_marked:
            previous = None
            continue
        if previous is None or when(event) - when(previous) > window:
            bursts.append([])
        bursts[-1].append(event)
        previous = event
    return bursts


# Builds an Alert. first_seen/last_seen and the sorted line list all come from the evidence lines.
def make_alert(rule, severity, title, summary, ip, evidence, facts) -> Alert:
    times = sorted(l.timestamp for l in evidence)
    return Alert(
        id=0, rule=rule, severity=severity, title=title,
        first_seen=times[0], last_seen=times[-1], summary=summary, source_ip=ip,
        evidence_lines=sorted({l.line for l in evidence}), facts=facts,
    )


# Rule 1 - Brute force: many failed passwords from one IP in a short window.
def detect_brute_force(lines: list[ParsedLine]) -> list[Alert]:
    alerts = []
    for ip, events in lines_by_ip(lines, {FAILED_PASSWORD}).items():
        for burst in find_bursts(events, BRUTE_FORCE_WINDOW_SECONDS,
                                 lambda w: count_failures(w) >= BRUTE_FORCE_MIN_FAILURES):
            n = count_failures(burst)
            alerts.append(make_alert(
                BRUTE_FORCE, "medium", "Brute-force login attempts",
                f"{n} failed SSH logins from {ip} between {burst[0].timestamp} and {burst[-1].timestamp}.",
                ip, burst, {"failure_count": n, "usernames": distinct_usernames(burst)},
            ))
    return alerts


# The share of attempts that went to the single most-targeted username (0.0-1.0).
def top_username_share(events: list[ParsedLine]) -> float:
    counts = defaultdict(int)
    for l in events:
        if l.username is not None:
            counts[l.username] += l.repeat_count
    return max(counts.values()) / sum(counts.values()) if counts else 0.0


# Rule 2 - Password spraying: one IP trying many different usernames, without
# focusing on one of them (that would be brute force on that account instead).
def detect_password_spraying(lines: list[ParsedLine]) -> list[Alert]:
    alerts = []
    for ip, events in lines_by_ip(lines, {FAILED_PASSWORD, INVALID_USER}).items():
        for burst in find_bursts(events, SPRAY_WINDOW_SECONDS,
                                 lambda w: len(distinct_usernames(w)) >= SPRAY_MIN_USERNAMES):
            if top_username_share(burst) > SPRAY_MAX_TOP_USERNAME_SHARE:
                continue
            users = distinct_usernames(burst)
            alerts.append(make_alert(
                PASSWORD_SPRAYING, "high", "Password spraying across many usernames",
                f"{ip} tried {len(users)} different usernames between {burst[0].timestamp} and {burst[-1].timestamp}.",
                ip, burst, {"distinct_usernames": len(users), "usernames": users,
                            "failure_count": count_failures(burst)},
            ))
    return alerts


# Rule 3 - Success after failures: an accepted login from an IP that just failed
# many times, which suggests the attack may have worked.
def detect_success_after_failures(lines: list[ParsedLine]) -> list[Alert]:
    failures_by_ip = lines_by_ip(lines, {FAILED_PASSWORD})
    lookback = timedelta(seconds=SUCCESS_LOOKBACK_SECONDS)
    alerts = []
    for ok in lines:
        if ok.event_type != ACCEPTED_LOGIN or not ok.source_ip or not ok.timestamp:
            continue
        prior = [f for f in failures_by_ip.get(ok.source_ip, [])
                 if when(ok) - lookback <= when(f) <= when(ok)]
        n = count_failures(prior)
        if n >= SUCCESS_MIN_PRIOR_FAILURES:
            alerts.append(make_alert(
                SUCCESS_AFTER_FAILURES, "critical", "Successful login after repeated failures",
                f"{ok.source_ip} logged in successfully at {ok.timestamp} after {n} failed logins in the previous hour.",
                ok.source_ip, prior + [ok],
                {"failure_count": n, "success_line": ok.line, "success_username": ok.username},
            ))
    return alerts


# Rule 4 - Odd-hour logins: successful logins in the middle of the night (by the log's own clock).
def detect_odd_hour_logins(lines: list[ParsedLine]) -> list[Alert]:
    alerts = []
    for l in lines:
        if l.event_type == ACCEPTED_LOGIN and l.timestamp and ODD_HOUR_START <= when(l).hour < ODD_HOUR_END:
            alerts.append(make_alert(
                ODD_HOUR_LOGIN, "low", "Login at an unusual hour",
                f"Successful SSH login from {l.source_ip} at {l.timestamp}, "
                f"outside normal hours ({ODD_HOUR_START:02d}:00-{ODD_HOUR_END - 1:02d}:59).",
                l.source_ip, [l], {"hour": when(l).hour, "username": l.username},
            ))
    return alerts


# Runs all four rules, removes duplicates, and numbers the alerts 1, 2, 3...
# If every line of a brute-force alert is also in a spraying alert from the
# same IP, it's the same attack, so we keep only the spraying alert.
def run_detections(lines: list[ParsedLine]) -> list[Alert]:
    spraying = detect_password_spraying(lines)
    sprayed = {(a.source_ip, n) for a in spraying for n in a.evidence_lines}
    brute = [a for a in detect_brute_force(lines)
             if not all((a.source_ip, n) in sprayed for n in a.evidence_lines)]

    alerts = brute + spraying + detect_success_after_failures(lines) + detect_odd_hour_logins(lines)
    alerts.sort(key=lambda a: (a.evidence_lines[0], a.rule))
    for number, alert in enumerate(alerts, start=1):
        alert.id = number
    return alerts


# Formats [2,3,4,5,9] as "2-5,9" for readable output.
def format_ranges(numbers: list[int]) -> str:
    parts, start = [], None
    for i, n in enumerate(numbers):
        if start is None:
            start = n
        if i == len(numbers) - 1 or numbers[i + 1] != n + 1:
            parts.append(str(start) if start == n else f"{start}-{n}")
            start = None
    return ",".join(parts)


# CLI: parses a log, runs the rules, and prints a table (or contract JSON with --json).
def main() -> int:
    ap = argparse.ArgumentParser(description="Run rule-based detections on an SSH auth.log.")
    ap.add_argument("logfile")
    ap.add_argument("--year", type=int, help="year for timestamps (default: this year)")
    ap.add_argument("--json", action="store_true", help="print alerts in contract format")
    args = ap.parse_args()

    try:
        lines = parse_file(args.logfile, year=args.year)
    except OSError as e:
        print(f"error: cannot read {args.logfile}: {e}", file=sys.stderr)
        return 1

    alerts = run_detections(lines)
    if args.json:
        json.dump({"alerts": [a.to_contract() for a in alerts]}, sys.stdout, indent=2)
        print()
        return 0

    for a in alerts:
        print(f"[{a.id}] {a.severity.upper():8} {a.title}  (lines {format_ranges(a.evidence_lines)})")
        print(f"     {a.summary}")
    print(f"{len(alerts)} alerts from {len(lines)} lines")
    return 0


if __name__ == "__main__":
    sys.exit(main())
