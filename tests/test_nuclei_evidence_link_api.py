"""Runtime contract for opt-in, aggregate-only Nuclei evidence links."""

import hashlib
import json
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import server
from scanner import normalize_target
from storage import Store


PRIVATE_MARKER = "PRIVATE_NUCLEI_MATCHED_AT_20261011"
REPORT = [
    {
        "template-id": "http-missing-slash",
        "type": "http",
        "info": {
            "name": "Missing Slash",
            "severity": "info"
        },
        "matched-at": "https://example.invalid/"
    },
    {
        "template-id": "http-default-credentials",
        "type": "http",
        "info": {
            "name": "Default Credentials",
            "severity": "high"
        },
        "matched-at": f"https://example.invalid/admin?{PRIVATE_MARKER}"
    }
]


class NucleiEvidenceLinkApiTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.previous_store = server.STORE
        self.store = Store(Path(self.temporary.name) / "sniper.db")
        server.STORE = self.store
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.SniperHandler)
        self.httpd.daemon_threads = True
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        target = self.store.create_target(normalize_target("https://example.invalid"))
        self.engagement = self.store.create_engagement(
            target_id=target["id"], name="synthetic authorized review", authorization_ref="FIXTURE-AUTH",
            scope_notes="synthetic", out_of_scope="", test_window="",
            special_approvals={"redacted_data_proof": True},
        )
        self.control_id = self.engagement["tests"][0]["control_id"]
        self.path = f'/api/engagements/{self.engagement["id"]}/tool-evidence/nuclei-jsonl'

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=3)
        server.STORE = self.previous_store
        self.temporary.cleanup()

    def request(self, path, payload=None):
        body = None if payload is None else json.dumps(payload).encode()
        request = Request(
            self.base + path, data=body, method="POST" if body is not None else "GET",
            headers={"Content-Type": "application/json"} if body is not None else {},
        )
        try:
            with urlopen(request, timeout=5) as response:
                return response.status, json.loads(response.read())
        except HTTPError as error:
            try:
                return error.code, json.loads(error.read())
            finally:
                error.close()

    def test_link_is_opt_in_aggregate_only_idempotent_and_needs_review(self):
        payload = {"control_id": self.control_id, "report": REPORT, "confirm_link": True}
        code, linked = self.request(self.path, payload)
        self.assertEqual(code, 201)
        expected_digest = hashlib.sha256(
            json.dumps(REPORT, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        self.assertEqual(linked["tool_identity"], "nuclei-jsonl")
        self.assertEqual(linked["report_sha256"], expected_digest)
        self.assertEqual(linked["record_count"], 2)
        self.assertEqual(linked["unique_template_count"], 2)
        self.assertEqual(linked["severity_counts"], {"info": 1, "low": 0, "medium": 0, "high": 1, "critical": 0, "unknown": 0})

        duplicate_code, duplicate = self.request(self.path, payload)
        self.assertEqual(duplicate_code, 200)
        self.assertEqual(duplicate["id"], linked["id"])

        engagement_code, engagement = self.request(f'/api/engagements/{self.engagement["id"]}')
        self.assertEqual(engagement_code, 200)
        self.assertEqual(len(engagement["tool_evidence"]), 1)
        self.assertEqual(engagement["tool_evidence"][0]["id"], linked["id"])
        controls = {test["control_id"]: test for test in engagement["tests"]}
        self.assertEqual(controls[self.control_id]["status"], "needs_review")
        self.assertNotEqual(controls[self.control_id]["status"], "passed")

        with self.store._connect() as db:
            rows = [dict(row) for row in db.execute("SELECT * FROM nuclei_tool_evidence_links")]
        self.assertEqual(len(rows), 1)
        self.assertNotIn(PRIVATE_MARKER, json.dumps({"linked": linked, "engagement": engagement["tool_evidence"], "db": rows}))

    def test_requires_explicit_consent_authorization_and_valid_report(self):
        payload = {"control_id": self.control_id, "report": REPORT, "confirm_link": True}
        self.assertEqual(self.request(self.path, {**payload, "confirm_link": False})[0], 400)
        self.assertEqual(self.request(self.path, {**payload, "raw_report": PRIVATE_MARKER})[0], 400)
        self.assertEqual(self.request(self.path, {**payload, "report": [{"template-id": "x"}]})[0], 400)
        self.assertEqual(self.request(self.path, {**payload, "control_id": "MISSING-CONTROL"})[0], 400)

    def test_missing_engagement_returns_404(self):
        payload = {"control_id": self.control_id, "report": REPORT, "confirm_link": True}
        path = f'/api/engagements/nonexistent-id/tool-evidence/nuclei-jsonl'
        code, _ = self.request(path, payload)
        self.assertEqual(code, 404)

    def test_paused_engagement_returns_403(self):
        # Pause the engagement
        with self.store._connect() as db:
            db.execute("UPDATE engagements SET status = ? WHERE id = ?", ("paused", self.engagement["id"]))
        payload = {"control_id": self.control_id, "report": REPORT, "confirm_link": True}
        code, _ = self.request(self.path, payload)
        self.assertEqual(code, 403)
