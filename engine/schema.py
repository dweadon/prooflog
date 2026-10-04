"""Data shapes for ProofLog.

Two kinds of objects live here:
- INTERNAL records (ParsedLine, Alert) carry extra fields the engine needs,
  such as event types, IPs and evidence line numbers.
- Their `to_contract()` methods output ONLY the fields in the shared
  report.json contract. The frontend depends on that shape, so never rename
  or add fields there.
"""
from __future__ import annotations

from dataclasses import dataclass, field

# Event types the parser can assign to a line (internal only).
FAILED_PASSWORD = "failed_password"
INVALID_USER = "invalid_user"
ACCEPTED_LOGIN = "accepted_login"
DISCONNECT = "disconnect"
OTHER = "other"  # line is kept and numbered, but isn't one of the events above

# Fields an attacker can control. The username is whatever the attacker typed
# at the login prompt, so it must be treated as data, never as instructions.
UNTRUSTED_FIELD_NAMES = ("username", "user_agent")

# Allowed severities (contract).
SEVERITIES = ("low", "medium", "high", "critical")

# Detection rule names (internal only).
BRUTE_FORCE = "brute_force"
PASSWORD_SPRAYING = "password_spraying"
SUCCESS_AFTER_FAILURES = "success_after_failures"
ODD_HOUR_LOGIN = "odd_hour_login"


@dataclass
class ParsedLine:
    """One numbered line from the log file, plus what the parser extracted from it."""

    line: int                      # 1-based line number in the original file
    text: str                      # exact original text, never rewritten
    timestamp: str | None          # ISO 8601, or None if it couldn't be read
    source_ip: str | None          # a validated IPv4/IPv6 address, or None
    username: str | None           # UNTRUSTED: chosen by whoever tried to log in
    user_agent: str | None         # UNTRUSTED: SSH logs never have one, so always None here
    event_type: str
    repeat_count: int = 1          # "message repeated N times" counts as N events

    def untrusted_fields(self) -> list[str]:
        """Names of the attacker-controlled fields present on this line."""
        return [f for f in UNTRUSTED_FIELD_NAMES if getattr(self, f) is not None]

    def to_contract(self) -> dict:
        """The log_lines entry exactly as the contract defines it."""
        return {"line": self.line, "text": self.text, "untrusted_fields": self.untrusted_fields()}


@dataclass
class Alert:
    """One rule-based detection.

    `evidence_lines` and `facts` stay internal. Stage 3 sends only those lines
    to the AI, and Stage 4 uses `facts` to check the AI's claims.
    """

    id: int
    rule: str
    severity: str
    title: str                     # fixed text from code; never includes untrusted values
    first_seen: str
    last_seen: str
    summary: str                   # code-written fallback; Stage 3 replaces it with the AI summary
    source_ip: str | None
    evidence_lines: list[int]
    facts: dict = field(default_factory=dict)

    def to_contract(self) -> dict:
        """The alerts entry exactly as the contract defines it."""
        return {
            "id": self.id, "severity": self.severity, "title": self.title,
            "first_seen": self.first_seen, "last_seen": self.last_seen, "summary": self.summary,
        }


@dataclass
class Claim:
    """One plain-English statement the AI made about an alert, with the lines it cites as proof.

    It starts unverified. Stage 4 sets `verified` and `verifier_note`.
    """

    id: int
    alert_id: int
    text: str
    evidence_lines: list[int]
    verified: bool = False
    verifier_note: str = "Not verified yet."
    checked: bool = False  # internal: True once every check actually ran (not in the contract)

    def to_contract(self) -> dict:
        """The claims entry exactly as the contract defines it."""
        return {
            "id": self.id, "alert_id": self.alert_id, "text": self.text,
            "evidence_lines": self.evidence_lines, "verified": self.verified,
            "verifier_note": self.verifier_note,
        }
