"""Stage 5 tests for the HTTP API (fake AI client, temp report file). Run: python -m unittest -v"""
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from engine import api, report
from tests.test_claims import GOOD, FakeClient

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "auth_test.log"


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.patch_path = mock.patch.object(api, "REPORT_PATH", Path(self.tmp.name) / "latest.json")
        self.patch_path.start()
        self.client = TestClient(api.app)

    def tearDown(self):
        self.patch_path.stop()
        self.tmp.cleanup()

    # Uploads the test log with the fake AI wired into both claim writing and verification.
    def upload(self, **form):
        write, verify = report.write_claims, report.verify_claims
        with mock.patch.object(report, "write_claims",
                               lambda a, l, client=None, **kw: write(a, l, client=FakeClient([GOOD]), **kw)), \
             mock.patch.object(report, "verify_claims",
                               lambda c, l, client=None, **kw: verify(c, l, client=FakeClient([GOOD]), **kw)):
            return self.client.post("/analyze", files={"file": ("auth.log", FIXTURE.read_bytes())},
                                    data={"year": "2026", **form})

    def test_analyze_returns_contract_and_saves(self):
        r = self.upload()
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(list(body), ["meta", "trust_score", "alerts", "claims", "log_lines"])
        self.assertEqual(list(body["meta"]), ["source_name", "source_type", "generated_at"])
        self.assertEqual(body["trust_score"]["total"], len(body["claims"]))
        self.assertEqual(self.client.get("/report").json(), body)  # saved and served back

    def test_debug_flag_injects_one_false_claim_that_fails(self):
        normal = self.upload().json()
        debug = self.upload(debug_inject_false_claim="true").json()
        self.assertEqual(len(debug["claims"]), len(normal["claims"]) + 1)
        injected = debug["claims"][-1]
        self.assertFalse(injected["verified"])
        self.assertIn("doesn't match", injected["verifier_note"])
        self.assertEqual(debug["trust_score"]["total"], len(debug["claims"]))
        self.assertEqual(debug["trust_score"]["verified"], sum(c["verified"] for c in debug["claims"]))

    def test_second_identical_upload_is_served_from_cache(self):
        first = self.upload()
        second = self.upload()
        self.assertEqual((first.headers["X-ProofLog-Cache"], second.headers["X-ProofLog-Cache"]), ("miss", "hit"))
        self.assertEqual(first.json(), second.json())
        self.assertEqual(self.upload(use_cache="false").headers["X-ProofLog-Cache"], "miss")
        self.assertEqual(self.upload(debug_inject_false_claim="true").headers["X-ProofLog-Cache"], "miss")

    def test_incomplete_reports_are_not_cached(self):
        with mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": ""}):
            for _ in range(2):
                r = self.client.post("/analyze", files={"file": ("auth.log", FIXTURE.read_bytes())})
                self.assertEqual(r.headers["X-ProofLog-Cache"], "miss")

    def test_status_reports_progress(self):
        self.upload()
        s = self.client.get("/status").json()
        self.assertEqual(s["stage"], "done")
        self.assertEqual(set(s), {"stage", "done", "total", "elapsed_seconds"})

    def test_second_analysis_while_running_gets_409(self):
        api._analysis_lock.acquire()
        try:
            r = self.client.post("/analyze", files={"file": ("auth.log", FIXTURE.read_bytes())},
                                 data={"use_cache": "false"})
        finally:
            api._analysis_lock.release()
        self.assertEqual(r.status_code, 409)

    def test_report_404_before_any_analysis(self):
        self.assertEqual(self.client.get("/report").status_code, 404)

    def test_bad_inputs_give_400(self):
        for content in (b"", b"\x00\x01binary", b"hello world\nnot a log\n"):
            r = self.client.post("/analyze", files={"file": ("x.log", content)})
            self.assertEqual(r.status_code, 400, content)
            self.assertIn("error", r.json())

    def test_bad_source_type(self):
        self.assertEqual(self.upload(source_type="nope").status_code, 400)

    def test_missing_key_still_returns_report_with_header(self):
        with mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": ""}):
            r = self.client.post("/analyze", files={"file": ("auth.log", FIXTURE.read_bytes())})
        self.assertEqual(r.status_code, 200)
        self.assertIn("ANTHROPIC_API_KEY", r.headers["X-ProofLog-AI-Errors"])
        self.assertEqual(r.json()["claims"], [])


if __name__ == "__main__":
    unittest.main()
