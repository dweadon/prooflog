"""Tests for live analysis jobs (results fill in while the AI works). Fake AI, no key.
Run: python -m unittest -v"""
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from engine import api, jobs
from tests.test_claims import GOOD, FakeClient

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "auth_test.log"


class JobTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        patches = [mock.patch.object(api, "REPORT_PATH", Path(self.tmp.name) / "latest.json"),
                   mock.patch.object(jobs, "make_client", lambda: FakeClient([GOOD]))]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.addCleanup(self.tmp.cleanup)
        self.client = TestClient(api.app)

    def start(self, **form):
        return self.client.post("/analyze/start", files={"file": ("auth.log", FIXTURE.read_bytes())},
                                data={"year": "2026", **form})

    def wait_done(self, job_id):
        for _ in range(200):
            body = self.client.get(f"/analyze/{job_id}").json()
            if body["state"] != "running":
                return body
            time.sleep(0.02)
        self.fail("job did not finish")

    def test_rule_findings_come_back_immediately(self):
        r = self.start()
        self.assertEqual(r.status_code, 202)
        body = r.json()
        self.assertEqual(len(body["report"]["alerts"]), 5)       # rules ran before answering
        self.assertEqual(len(body["report"]["log_lines"]), 39)
        self.assertEqual(list(body["report"]), ["meta", "trust_score", "alerts", "claims", "log_lines"])
        self.wait_done(body["job"])

    def test_claims_fill_in_and_get_verdicts(self):
        body = self.wait_done(self.start().json()["job"])
        report = body["report"]
        self.assertEqual(body["state"], "done")
        self.assertEqual(body["pending_claims"], [])
        self.assertEqual(len(report["claims"]), 10)                 # 2 per alert from the fake AI
        self.assertTrue(all(c["verifier_note"] != jobs.CHECKING_NOTE for c in report["claims"]))
        self.assertEqual(report["trust_score"]["total"], 10)
        self.assertEqual(self.client.get("/report").json()["claims"], report["claims"])  # saved as latest

    def test_finished_job_is_cached(self):
        self.wait_done(self.start().json()["job"])
        again = self.start()
        self.assertEqual((again.status_code, again.headers["X-ProofLog-Cache"], again.json()["state"]), (200, "hit", "done"))

    def test_planted_false_claim_is_caught(self):
        report = self.wait_done(self.start(debug_inject_false_claim="true").json()["job"])["report"]
        planted = [c for c in report["claims"] if "failed to log in 49 times" in c["text"]]
        self.assertEqual(len(planted), 1)
        self.assertFalse(planted[0]["verified"])
        self.assertIn("number 49", planted[0]["verifier_note"])

    def test_bad_file_and_unknown_job(self):
        r = self.client.post("/analyze/start", files={"file": ("x.txt", b"not a log\n")})
        self.assertEqual(r.status_code, 400)
        self.assertEqual(self.client.get("/analyze/nope").status_code, 404)

    def test_only_one_job_at_a_time(self):
        api._analysis_lock.acquire()
        try:
            self.assertEqual(self.start(use_cache="false").status_code, 409)
        finally:
            api._analysis_lock.release()

    def test_missing_key_finishes_without_hanging(self):
        with mock.patch.object(jobs, "make_client", side_effect=jobs.AIError("GROQ_API_KEY is not set.")):
            body = self.wait_done(self.start(use_cache="false").json()["job"])
        self.assertEqual(body["state"], "done")
        self.assertEqual(body["report"]["claims"], [])
        self.assertTrue(all("AI analysis unavailable" in a["summary"] for a in body["report"]["alerts"]))


if __name__ == "__main__":
    unittest.main()
