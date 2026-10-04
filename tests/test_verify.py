"""Stage 4 tests for the verifier, using a fake AI client. Run: python -m unittest -v"""
import os
import unittest
from pathlib import Path
from unittest import mock

from engine.claims import AIError
from engine.detect import run_detections
from engine.parser import parse_file
from engine.schema import Claim
from engine.verify import inject_false_claim, verify_claims
from tests.test_claims import FakeClient

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "auth_test.log"
BRUTE = list(range(3, 10))     # 203.0.113.45 -> root, 02:14:07-02:14:33, 9 failures (line 7 = x3)
SPRAY = [14] + list(range(16, 28))  # 198.51.100.23, 7 usernames, 03:02:10-03:02:36


class VerifierTests(unittest.TestCase):
    def setUp(self):
        self.lines = parse_file(FIXTURE, year=2026)

    # Verifies one claim with a fake AI that answers `verdict`; returns the claim.
    def check(self, text, lines, verdict=None, client=None):
        claim = Claim(id=1, alert_id=1, text=text, evidence_lines=lines)
        verify_claims([claim], self.lines, client=client or FakeClient([{}], verdict=verdict))
        return claim

    def test_true_claim_is_verified(self):
        c = self.check("203.0.113.45 failed to log in as root 9 times between 02:14:07 and 02:14:33.", BRUTE)
        self.assertTrue(c.verified, c.verifier_note)
        self.assertTrue(c.verifier_note.startswith("Verified"))

    def test_check1_missing_line(self):
        c = self.check("203.0.113.45 failed to log in.", [3, 999])
        self.assertFalse(c.verified)
        self.assertIn("999 do not exist", c.verifier_note)

    def test_check1_no_lines(self):
        self.assertFalse(self.check("Something happened.", []).verified)

    def test_check2_wrong_ip(self):
        c = self.check("10.9.9.9 failed to log in as root.", BRUTE)
        self.assertFalse(c.verified)
        self.assertIn("IP 10.9.9.9", c.verifier_note)

    def test_check2_wrong_count(self):
        c = self.check("203.0.113.45 failed to log in 49 times.", BRUTE)
        self.assertFalse(c.verified)
        self.assertIn("number 49", c.verifier_note)

    def test_check2_wrong_time(self):
        c = self.check("The failures started at 02:20.", BRUTE)
        self.assertFalse(c.verified)
        self.assertIn("Time 02:20", c.verifier_note)

    def test_wrong_full_time_reported_as_time_not_ip(self):
        c = self.check("The first failure was at 02:20:00.", BRUTE)
        self.assertEqual(c.verifier_note, "Time 02:20:00 is not in the cited lines.")
        self.assertTrue(self.check("A login came from 2001:db8::1.", [3], client=FakeClient([{}])).verifier_note
                        .startswith("IP 2001:db8::1"))

    def test_check2_username_not_in_cited_lines(self):
        c = self.check("The attacker also tried alice.", BRUTE)  # alice is in the log, not in these lines
        self.assertFalse(c.verified)
        self.assertIn("'alice'", c.verifier_note)

    def test_check2_number_words_and_durations(self):
        self.assertTrue(self.check("There were nine failed logins.", BRUTE).verified)
        self.assertFalse(self.check("There were fifteen failed logins.", BRUTE).verified)
        c = self.check("198.51.100.23 tried 7 different usernames within 26 seconds.", SPRAY)
        self.assertTrue(c.verified, c.verifier_note)

    def test_line_references_are_not_counts(self):
        c = self.check("Lines 3-9 show 9 failed logins from 203.0.113.45.", BRUTE)
        self.assertTrue(c.verified, c.verifier_note)

    def test_port_or_pid_digits_do_not_count_as_proof(self):
        c = self.check("203.0.113.45 failed to log in 52211 times.", BRUTE)  # 52211 is a port on line 3
        self.assertIn("number 52211", c.verifier_note)

    def test_ports_and_pids_are_checked(self):
        self.assertTrue(self.check("The first attempt came from port 52211.", BRUTE).verified)
        self.assertIn("Port 4444", self.check("The first attempt came from port 4444.", BRUTE).verifier_note)
        self.assertIn("Process ID 999", self.check("It was handled by sshd[999].", BRUTE).verifier_note)

    def test_dates_are_checked(self):
        self.assertTrue(self.check("On October 3rd, 203.0.113.45 failed 9 times.", BRUTE).verified)
        self.assertIn("Date Oct 5", self.check("On Oct 5, 203.0.113.45 failed 9 times.", BRUTE).verifier_note)
        self.assertIn("Date 2026-10-05", self.check("On 2026-10-05 there were 9 failures.", BRUTE).verifier_note)
        self.assertTrue(self.check("There were 9 separate failures.", BRUTE).verified)  # "sep" is not a month here

    def test_commas_and_percentages(self):
        self.assertIn("number 1234", self.check("There were 1,234 failures.", BRUTE).verifier_note)
        self.assertTrue(self.check("100% of the 9 failures targeted root.", BRUTE).verified)

    def test_common_word_usernames_checked_only_as_usernames(self):
        self.assertIn("'test'", self.check("The attacker tried the username test.", BRUTE).verifier_note)
        self.assertTrue(self.check("This looks like a test of 9 passwords.", BRUTE).verified)

    def test_quoted_text_must_be_in_lines(self):
        self.assertTrue(self.check('Each line says "Failed password for root".', BRUTE).verified)
        self.assertIn("Quoted text", self.check('A line says "Accepted password".', BRUTE).verifier_note)

    def test_failures_per_username_count(self):
        self.assertTrue(self.check("The username root was tried 9 times.", BRUTE).verified)

    def test_check3_ai_says_not_supported(self):
        c = self.check("203.0.113.45 is a known botnet.", BRUTE,
                       verdict={"verdict": "not supported", "reason": "Nothing shows a botnet."})
        self.assertFalse(c.verified)
        self.assertEqual(c.verifier_note, "AI check: not supported. Nothing shows a botnet.")

    def test_ai_check_sees_only_claim_and_cited_lines(self):
        client = FakeClient([{}])
        self.check("203.0.113.45 failed to log in.", [3, 4], client=client)
        [prompt] = client.verify_prompts
        self.assertIn("<claim>", prompt)
        self.assertIn("[3] ", prompt)
        self.assertNotIn("[5] ", prompt)

    def test_ai_failure_means_unverified(self):
        c = self.check("203.0.113.45 failed to log in.", BRUTE, client=FakeClient([AIError("network down")],
                                                                                  verdict=AIError("network down")))
        self.assertFalse(c.verified)
        self.assertIn("AI check failed", c.verifier_note)

    def test_missing_key_means_unverified(self):
        claim = Claim(id=1, alert_id=1, text="203.0.113.45 failed to log in.", evidence_lines=BRUTE)
        with mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": ""}):
            verify_claims([claim], self.lines)
        self.assertFalse(claim.verified)
        self.assertIn("could not run", claim.verifier_note)

    def test_injected_false_claim_is_caught(self):
        alerts = run_detections(self.lines)
        claims = []
        inject_false_claim(claims, alerts)
        client = FakeClient([{}])
        verify_claims(claims, self.lines, client=client)
        self.assertFalse(claims[0].verified)
        self.assertIn("number 49", claims[0].verifier_note)  # 9 real failures + 40
        self.assertEqual(client.verify_prompts, [])         # caught by code, no AI call needed


if __name__ == "__main__":
    unittest.main()
