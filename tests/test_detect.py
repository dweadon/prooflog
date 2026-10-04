"""Stage 2 tests for rule-based detection. Run: python -m unittest -v"""
import unittest
from pathlib import Path

from engine.detect import format_ranges, run_detections
from engine.parser import parse_file, parse_text

SAMPLE = Path(__file__).resolve().parent / "fixtures" / "auth_test.log"


# Builds one "Failed password" syslog line for quick test logs.
def fail(ts, ip="1.2.3.4", user="root"):
    return f"Oct  3 {ts} h sshd[1]: Failed password for {user} from {ip} port 2 ssh2"


class SampleDetectionTests(unittest.TestCase):
    def setUp(self):
        self.alerts = run_detections(parse_file(SAMPLE, year=2026))
        self.by_rule = {}
        for a in self.alerts:
            self.by_rule.setdefault(a.rule, []).append(a)

    def test_brute_force(self):
        [a] = self.by_rule["brute_force"]
        self.assertEqual((a.source_ip, a.evidence_lines), ("203.0.113.45", [3, 4, 5, 6, 7, 8, 9]))
        self.assertEqual(a.facts["failure_count"], 9)  # line 7 = "repeated 3 times"
        self.assertEqual((a.first_seen, a.last_seen), ("2026-10-03T02:14:07", "2026-10-03T02:14:33"))

    def test_password_spraying(self):
        [a] = self.by_rule["password_spraying"]
        self.assertEqual(a.source_ip, "198.51.100.23")
        self.assertEqual(a.facts["distinct_usernames"], 7)
        self.assertEqual(a.evidence_lines, [14] + list(range(16, 28)))

    def test_spraying_ip_not_double_reported_as_brute_force(self):
        self.assertNotIn("198.51.100.23", [a.source_ip for a in self.by_rule["brute_force"]])

    def test_success_after_failures(self):
        [a] = self.by_rule["success_after_failures"]
        self.assertEqual((a.severity, a.facts["success_line"]), ("critical", 11))
        self.assertEqual(a.evidence_lines, [3, 4, 5, 6, 7, 8, 9, 11])

    def test_odd_hour_logins(self):
        self.assertEqual(sorted(a.evidence_lines[0] for a in self.by_rule["odd_hour_login"]), [11, 29])

    def test_normal_activity_not_flagged(self):
        flagged = {n for a in self.alerts for n in a.evidence_lines}
        self.assertFalse(flagged & {31, 34, 38, 39})  # injection attempt (1 try), alice 09:12, carol

    def test_contract_shape(self):
        for a in self.alerts:
            c = a.to_contract()
            self.assertEqual(list(c), ["id", "severity", "title", "first_seen", "last_seen", "summary"])
            self.assertIsInstance(c["id"], int)
            self.assertIn(c["severity"], ("low", "medium", "high", "critical"))
        self.assertEqual([a.id for a in self.alerts], list(range(1, len(self.alerts) + 1)))

    def test_titles_and_summaries_never_contain_untrusted_text(self):
        for a in self.alerts:
            self.assertNotIn("IGNORE", a.title + a.summary)
            self.assertNotIn("root", a.title + a.summary)


class EdgeCaseTests(unittest.TestCase):
    def test_slow_failures_outside_window_not_brute_force(self):
        text = "\n".join(fail(f"{h:02d}:00:00") for h in range(10, 16))  # 6 failures, 1 per hour
        self.assertEqual(run_detections(parse_text(text)), [])

    def test_two_separate_bursts_give_two_alerts(self):
        text = "\n".join([fail(f"10:00:0{i}") for i in range(5)] + [fail(f"14:00:0{i}") for i in range(5)])
        self.assertEqual([a.evidence_lines for a in run_detections(parse_text(text))],
                         [[1, 2, 3, 4, 5], [6, 7, 8, 9, 10]])

    def test_lines_without_timestamps_are_ignored(self):
        text = "\n".join(["Failed password for root from 1.2.3.4 port 2 ssh2"] * 10)
        self.assertEqual(run_detections(parse_text(text)), [])

    def test_many_usernames_but_one_dominant_is_brute_force_not_spraying(self):
        users = ["root"] * 12 + ["a1", "b2", "c3", "d4"]  # 75% of attempts on root
        text = "\n".join(fail(f"10:00:{i:02d}", user=u) for i, u in enumerate(users))
        self.assertEqual([a.rule for a in run_detections(parse_text(text))], ["brute_force"])

    def test_empty_input(self):
        self.assertEqual(run_detections([]), [])

    def test_format_ranges(self):
        self.assertEqual(format_ranges([2, 3, 4, 5, 9, 11, 12]), "2-5,9,11-12")


if __name__ == "__main__":
    unittest.main()
