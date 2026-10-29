import atexit
import hashlib
import json
import os
import shutil
import sys
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

_BOOT_DATA_DIR = tempfile.mkdtemp(prefix="sniper_ssllabs_evidence_boot_")
atexit.register(shutil.rmtree, _BOOT_DATA_DIR, True)
os.environ["SNIPER_DATA_DIR"] = _BOOT_DATA_DIR
APP_ROOT = Path(os.environ.get("SNIPER_APP_ROOT", Path(__file__).resolve().parents[1])).resolve()
sys.path.insert(0, str(APP_ROOT))

import server  # noqa: E402
from scanner import normalize_target  # noqa: E402
from storage import Store  # noqa: E402


REPORT = {
    "status": "READY",
    "host": "private-host.ssl.invalid",
    "statusMessage": "private operator note",
    "endpoints": [
        {"grade": "A+", "ipAddress": "198.51.100.71", "details": {"cert": {"subject": "private-cert-subject"}}},
        {"grade": "F", "ipAddress": "198.51.100.72"},
    ],
}


class SsllabsEvidenceLinkApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.previous_store = server.STORE
        self.previous_limiter = server.LIMITER
        server.LIMITER = server.RateLimiter()
        self.store = Store(Path(self.temp.name) / "sniper.db")
        server.STORE = self.store
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.SniperHandler)
        self.httpd.daemon_threads = True
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        target = self.store.create_target(normalize_target("https://example.com"))
        self.engagement = self.store.create_engagement(
            target_id=target["id"], name="local fixture", authorization_ref="LOCAL-TEST",
            scope_notes="", out_of_scope="", test_window="",
            special_approvals={"redacted_data_proof": True},
        )
        self.control = self.engagement["tests"][0]["control_id"]
        self.path = f'/api/engagements/{self.engagement["id"]}/tool-evidence/ssllabs-host'

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)
        server.STORE = self.previous_store
        server.LIMITER = self.previous_limiter
        self.temp.cleanup()

    def request(self, path, payload=None):
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        req = Request(
            self.base + path, data=body, method="POST" if body is not None else "GET",
            headers={"Content-Type": "application/json"} if body is not None else {},
        )
        try:
            with urlopen(req, timeout=5) as response:
                return response.status, json.loads(response.read())
        except HTTPError as error:
            try:
                return error.code, json.loads(error.read())
            finally:
                error.close()

    def test_explicit_link_is_idempotent_private_and_needs_review(self):
        payload = {"control_id": self.control, "report": REPORT, "confirm_link": True}
        expected_digest = hashlib.sha256(
            json.dumps(REPORT, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        status, linked = self.request(self.path, payload)
        self.assertEqual(status, 201)
        self.assertEqual(linked["tool_identity"], "ssllabs-v4-host")
        self.assertEqual(linked["report_sha256"], expected_digest)
        self.assertEqual(linked["assessment_status"], "READY")
        self.assertEqual(linked["endpoint_count"], 2)
        self.assertEqual((linked["grade_counts"]["A+"], linked["grade_counts"]["F"]), (1, 1))

        duplicate_status, duplicate = self.request(self.path, payload)
        self.assertEqual(duplicate_status, 200)
        self.assertEqual(duplicate["id"], linked["id"])
        detail_status, detail = self.request(f'/api/engagements/{self.engagement["id"]}')
        self.assertEqual(detail_status, 200)
        self.assertEqual(len(detail["tool_evidence"]), 1)
        self.assertEqual(detail["tests"][0]["status"], "needs_review")
        with self.store._connect() as db:
            rows = [dict(row) for row in db.execute("SELECT * FROM ssllabs_tool_evidence_links")]
        self.assertEqual(len(rows), 1)
        surfaces = json.dumps([linked, detail["tool_evidence"], rows])
        for private in ("private-host.ssl.invalid", "198.51.100.71", "private-cert-subject", "private operator note"):
            self.assertNotIn(private, surfaces)

    def test_missing_consent_invalid_report_and_paused_engagement_rejected(self):
        payload = {"control_id": self.control, "report": REPORT, "confirm_link": True}
        self.assertEqual(self.request(self.path, {**payload, "confirm_link": False})[0], 400)
        self.assertEqual(self.request(self.path, {**payload, "raw_host": "secret"})[0], 400)
        self.assertEqual(self.request(self.path, {**payload, "report": {"status": "READY", "endpoints": [{"grade": "G"}]}})[0], 400)
        self.assertEqual(self.request(self.path, {**payload, "control_id": "nonexistent"})[0], 400)
        self.store.update_engagement(self.engagement["id"], {"status": "paused"})
        self.assertEqual(self.request(self.path, payload)[0], 403)
        with self.store._connect() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM ssllabs_tool_evidence_links").fetchone()[0], 0)


if __name__ == "__main__":
    unittest.main()
