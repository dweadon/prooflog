"""Stage 1 tests for the SSH parser. Run: python -m unittest -v"""
import unittest
from pathlib import Path

from engine.parser import decode_log_bytes, parse_file, parse_text

SAMPLE = Path(__file__).resolve().parent / "fixtures" / "auth_test.log"


class ParserTests(unittest.TestCase):
    def setUp(self):
        self.lines = parse_file(SAMPLE, year=2026)
        self.by_no = {l.line: l for l in self.lines}

    def test_every_line_numbered_from_one_and_text_unchanged(self):
        original = SAMPLE.read_text().splitlines()
        self.assertEqual([l.line for l in self.lines], list(range(1, len(original) + 1)))
        self.assertEqual([l.text for l in self.lines], original)

    def test_contract_shape(self):
        self.assertEqual(self.by_no[3].to_contract(), {
            "line": 3,
            "text": "Oct  3 02:14:07 LabSZ sshd[3101]: Failed password for root from 203.0.113.45 port 52211 ssh2",
            "untrusted_fields": ["username"],
        })
        self.assertEqual(self.by_no[1].to_contract()["untrusted_fields"], [])

    def test_failed_password(self):
        l = self.by_no[3]
        self.assertEqual((l.event_type, l.username, l.source_ip), ("failed_password", "root", "203.0.113.45"))
        self.assertEqual(l.timestamp, "2026-10-03T02:14:07")

    def test_repeated_message_counts(self):
        self.assertEqual((self.by_no[7].event_type, self.by_no[7].repeat_count), ("failed_password", 3))

    def test_loghub_formats(self):
        self.assertEqual((self.by_no[14].event_type, self.by_no[14].source_ip), ("invalid_user", "198.51.100.23"))  # no port
        self.assertEqual(self.by_no[16].username, "admin")                       # "for invalid user admin"
        self.assertEqual(self.by_no[11].event_type, "accepted_login")
        self.assertEqual((self.by_no[13].event_type, self.by_no[13].source_ip), ("disconnect", "203.0.113.45"))  # "from IP: 11:"
        self.assertEqual((self.by_no[28].event_type, self.by_no[28].source_ip), ("disconnect", "198.51.100.23"))  # "[preauth]"

    def test_username_only_lines_marked_untrusted_but_not_events(self):
        for n in (2, 10, 15, 32):  # pam user=, PAM N more, input_userauth_request
            self.assertEqual(self.by_no[n].event_type, "other")
            self.assertEqual(self.by_no[n].untrusted_fields(), ["username"])

    def test_injection_username_kept_as_data(self):
        l = self.by_no[31]
        self.assertEqual(l.event_type, "invalid_user")
        self.assertTrue(l.username.startswith("IGNORE PREVIOUS INSTRUCTIONS"))
        self.assertEqual(l.source_ip, "198.51.100.99")

    def test_username_cannot_spoof_ip(self):
        [l] = parse_text("Oct  3 02:00:00 h sshd[1]: Invalid user x from 9.9.9.9 port 1 from 1.2.3.4 port 22")
        self.assertEqual(l.source_ip, "1.2.3.4")
        [l] = parse_text("Oct  3 02:00:00 h sshd[1]: Connection closed by invalid user x 1.2.3.4 port 1 [preauth]")
        self.assertEqual((l.username, l.source_ip), ("x", "1.2.3.4"))

    def test_unparsed_lines_kept(self):
        self.assertEqual(self.by_no[36].event_type, "other")  # kernel
        self.assertEqual(self.by_no[37].event_type, "other")  # garbage
        self.assertIsNone(self.by_no[37].timestamp)

    def test_default_year_never_in_the_future(self):
        from datetime import datetime
        [l] = parse_text("Dec 31 23:59:59 h sshd[1]: x")
        self.assertLessEqual(datetime.fromisoformat(l.timestamp), datetime.now())

    def test_windows_line_endings(self):
        lines = parse_text("Oct  3 02:00:00 h sshd[1]: Invalid user bob from 1.2.3.4\r\nOct  3 02:00:01 h sshd[1]: x\r\n")
        self.assertEqual((len(lines), lines[0].username, lines[0].source_ip), (2, "bob", "1.2.3.4"))
        self.assertNotIn("\r", lines[0].text)

    def test_year_rollover(self):
        lines = parse_text("Dec 31 23:59:59 h sshd[1]: x\nJan  1 00:00:01 h sshd[1]: y", year=2025)
        self.assertEqual([l.timestamp[:4] for l in lines], ["2025", "2026"])

    def test_bad_input_does_not_crash(self):
        self.assertEqual(parse_text(""), [])
        lines = parse_text(decode_log_bytes(
            b"\xff\xfe\x00garbage\nOct 99 99:99:99 h sshd[1]: Failed password for a from 1.1.1.1 port 1 ssh2"))
        self.assertEqual(len(lines), 2)
        self.assertIsNone(lines[1].timestamp)  # impossible date -> None, not a crash
        [l] = parse_text("Oct  3 02:00:00 h sshd[1]: Failed password for a from 999.1.1.1 port 1 ssh2")
        self.assertIsNone(l.source_ip)          # not a real IP


if __name__ == "__main__":
    unittest.main()
