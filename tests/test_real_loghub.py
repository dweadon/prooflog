"""Checks against the real Loghub OpenSSH_2k.log (skipped if it isn't downloaded).
Download: see README "Get a real log". Run: python -m unittest -v"""
import unittest
from collections import Counter
from pathlib import Path

from engine.detect import run_detections
from engine.parser import HEADER, parse_file

REAL = Path(__file__).resolve().parent.parent / "data" / "OpenSSH_2k.log"


@unittest.skipUnless(REAL.exists(), "data/OpenSSH_2k.log not downloaded")
class RealLoghubTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lines = parse_file(REAL)

    def test_all_2000_lines_numbered_with_timestamps(self):
        self.assertEqual(len(self.lines), 2000)
        self.assertTrue(all(l.timestamp for l in self.lines))
        self.assertFalse(any("\r" in l.text for l in self.lines))

    def test_every_login_event_is_classified_with_an_ip(self):
        for l in self.lines:
            msg = HEADER.match(l.text)["msg"]
            if msg.startswith(("Failed password", "Accepted ", "Invalid user ", "Connection closed by",
                               "Received disconnect")):
                self.assertNotEqual(l.event_type, "other", l.text)
                self.assertIsNotNone(l.source_ip, l.text)

    def test_detections(self):
        alerts = run_detections(self.lines)
        rules = Counter(a.rule for a in alerts)
        self.assertGreater(rules["brute_force"], 0)
        self.assertGreater(rules["password_spraying"], 0)
        # 183.62.140.253 aims ~94% of attempts at root: brute force, not spraying.
        self.assertEqual({a.rule for a in alerts if a.source_ip == "183.62.140.253"}, {"brute_force"})
