"""Stage 1: SSH auth.log parser (Loghub SSH format).

Turns a raw log file into numbered, structured lines. Every input line is
kept and numbered, including lines we can't parse, so line N in our output
is always line N of the file. That's what lets later stages cite evidence
anyone can check.

Run:  python -m engine.parser data/OpenSSH_2k.log          (first 10 lines, as a table)
      python -m engine.parser data/OpenSSH_2k.log --json   (all log_lines, contract JSON)
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from datetime import datetime, timedelta
from pathlib import Path

from .schema import ACCEPTED_LOGIN, DISCONNECT, FAILED_PASSWORD, INVALID_USER, OTHER, ParsedLine

# Line header: "Dec 10 06:55:46 LabSZ sshd[24200]: <message>"
HEADER = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>[^\s\[:]+)(?:\[\d+\])?:\s?(?P<msg>.*)$"
)

# An IPv4 or IPv6 address. It's strict on purpose, so the word "[preauth]" or
# a stray number can never be taken as an IP.
IP = r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f]*:[0-9A-Fa-f:.]*)"
PORT = r"(?: port \d+)?"

# sshd messages that are real events. Usernames are matched greedily (.*), so
# the LAST "from <ip>" on the line wins. That way a malicious username like
# "x from 9.9.9.9" can't fake the source IP.
EVENT_PATTERNS: list[tuple[str, re.Pattern]] = [
    (FAILED_PASSWORD, re.compile(r"^Failed \S+ for (?:invalid user )?(?P<user>.*) from " + IP + r" port \d+")),
    (ACCEPTED_LOGIN, re.compile(r"^Accepted \S+ for (?P<user>.*) from " + IP + r" port \d+")),
    (INVALID_USER, re.compile(r"^Invalid user (?P<user>.*) from " + IP + PORT + r"\s*$")),
    (DISCONNECT, re.compile(r"^(?:error: )?Received disconnect from " + IP + PORT + r":")),
    (DISCONNECT, re.compile(
        r"^(?:Disconnected from|Connection closed by|Connection reset by) "
        r"(?:(?:invalid |authenticating )?user (?P<user>.*) )?" + IP + PORT + r"(?: \[preauth\])?\s*$")),
]

# sshd messages that aren't counted as events but still contain a username.
# We extract it only so the line is correctly marked untrusted.
USERNAME_ONLY_PATTERNS = [
    re.compile(r"^input_userauth_request: invalid user (?P<user>.*) \[preauth\]\s*$"),
    re.compile(r"^Disconnecting: Too many authentication failures for (?:invalid user )?(?P<user>.*) \[preauth\]\s*$"),
    re.compile(r"^pam_unix\(sshd:\w+\): session (?:opened|closed) for user (?P<user>\S+)"),
    re.compile(r"\buser=(?P<user>\S+)\s*$"),  # pam "authentication failure; ... user=root"
]

# rsyslog collapses duplicates: "message repeated 3 times: [ Failed password ... ]"
REPEATED = re.compile(r"^message repeated (?P<n>\d+) times: \[\s?(?P<inner>.*?)\s?\]\s*$")


# Returns the IP if it's a real IPv4/IPv6 address, otherwise None.
def valid_ip(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


# Reads an sshd message and returns (event_type, username, ip, repeat_count).
def classify_message(msg: str) -> tuple[str, str | None, str | None, int]:
    repeat = 1
    m = REPEATED.match(msg)
    if m:
        repeat, msg = int(m["n"]), m["inner"]

    for event_type, pattern in EVENT_PATTERNS:
        m = pattern.match(msg)
        if m:
            return event_type, m.groupdict().get("user"), valid_ip(m["ip"]), repeat

    for pattern in USERNAME_ONLY_PATTERNS:
        m = pattern.search(msg)
        if m:
            return OTHER, m["user"], None, 1
    return OTHER, None, None, 1


# Turns "Dec 10 06:55:46" into a datetime. Syslog leaves out the year, so the caller supplies it.
def parse_timestamp(ts: str, year: int) -> datetime | None:
    try:
        return datetime.strptime(f"{year} {' '.join(ts.split())}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None


# Parses the whole log text into numbered lines.
# `year` fills in the missing syslog year. If it isn't given, we use the most
# recent year that doesn't put the log in the future (a "Dec 10" log read in
# October must be from last December). If the month goes backwards
# (Dec -> Jan) partway through, we assume the year rolled over.
def parse_text(text: str, year: int | None = None) -> list[ParsedLine]:
    if year is None:
        now = datetime.now()
        lines = _parse_with_year(text, now.year)
        first = next((l.timestamp for l in lines if l.timestamp), None)
        if first and datetime.fromisoformat(first) > now + timedelta(days=1):
            lines = _parse_with_year(text, now.year - 1)
        return lines
    return _parse_with_year(text, year)


# Does the actual parsing, with a fixed starting year.
def _parse_with_year(text: str, year: int) -> list[ParsedLine]:
    prev_month = None
    results = []

    for number, text_line in enumerate(text.splitlines(), start=1):
        timestamp = ip = user = None
        event_type, repeat = OTHER, 1

        header = HEADER.match(text_line)
        if header:
            dt = parse_timestamp(header["ts"], year)
            if dt and prev_month and dt.month < prev_month:
                year += 1
                dt = dt.replace(year=year)
            if dt:
                prev_month = dt.month
                timestamp = dt.isoformat()
            # Only sshd lines are SSH login events ("sshd-session" on newer OpenSSH).
            if header["proc"].startswith("sshd"):
                event_type, user, ip, repeat = classify_message(header["msg"])

        results.append(ParsedLine(
            line=number, text=text_line, timestamp=timestamp, source_ip=ip,
            username=user, user_agent=None, event_type=event_type, repeat_count=repeat,
        ))
    return results


# Decodes uploaded bytes safely: invalid bytes become "�" instead of crashing.
def decode_log_bytes(data: bytes) -> str:
    return data.decode("utf-8", errors="replace").replace("\x00", "�")


# Reads a log file from disk and parses it.
def parse_file(path: str | Path, year: int | None = None) -> list[ParsedLine]:
    return parse_text(decode_log_bytes(Path(path).read_bytes()), year=year)


# Shortens a value for terminal display. repr() shows control characters as
# escapes, so a malicious username can't mess up the terminal.
def _show(value, width: int) -> str:
    if value is None:
        return "-"
    s = repr(value)[1:-1] if isinstance(value, str) else str(value)
    return s if len(s) <= width else s[: width - 1] + "…"


# CLI: prints the first N parsed lines as a table, or all log_lines as contract JSON with --json.
def main() -> int:
    ap = argparse.ArgumentParser(description="Parse an SSH auth.log into numbered lines.")
    ap.add_argument("logfile")
    ap.add_argument("--year", type=int, help="year for timestamps (syslog has none; default: latest year not in the future)")
    ap.add_argument("--limit", type=int, default=10, help="lines to show in table mode (default 10)")
    ap.add_argument("--json", action="store_true", help="print all log_lines in contract format")
    args = ap.parse_args()

    try:
        lines = parse_file(args.logfile, year=args.year)
    except OSError as e:
        print(f"error: cannot read {args.logfile}: {e}", file=sys.stderr)
        return 1

    if args.json:
        json.dump({"log_lines": [l.to_contract() for l in lines]}, sys.stdout, indent=2)
        print()
        return 0

    print(f"{'LINE':>4}  {'TIMESTAMP':19}  {'EVENT':15}  {'SOURCE IP':15}  {'USERNAME':20}  UNTRUSTED")
    for l in lines[: args.limit]:
        print(f"{l.line:>4}  {_show(l.timestamp, 19):19}  {l.event_type:15}  "
              f"{_show(l.source_ip, 15):15}  {_show(l.username, 20):20}  {l.untrusted_fields()}")
    print(f"... {len(lines)} lines total")
    return 0


if __name__ == "__main__":
    sys.exit(main())
