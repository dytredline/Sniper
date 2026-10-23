"""Live HTTP contract for opt-in, aggregate-only Semgrep evidence."""

import json
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import server
from scanner import normalize_target
from storage import Store
from tool_report_semgrep import SEVERITY_VALUES


PRIVATE = "PRIVATE_LOCAL_PROJECT_PATH_AND_SOURCE"
SUMMARY = {
    "format": "semgrep-native-json",
    "profile": "local-trusted-rules-v1",
    "result_count": 1,
    "severity_counts": {key: int(key == "ERROR") for key in SEVERITY_VALUES},
    "report_sha256": "a" * 64,
}


class SemgrepEvidenceLinkApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.old_store = server.STORE
        self.store = Store(Path(self.temp.name) / "sniper.db")
        server.STORE = self.store
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.SniperHandler)
        self.httpd.daemon_threads = True
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        target = self.store.create_target(normalize_target("https://example.invalid"))
        self.engagement = self.store.create_engagement(
            target_id=target["id"], name="synthetic", authorization_ref="FIXTURE-AUTH",
            scope_notes="synthetic", out_of_scope="", test_window="",
            special_approvals={"redacted_data_proof": True},
        )
        self.control_id = self.engagement["tests"][0]["control_id"]
        self.path = f'/api/engagements/{self.engagement["id"]}/tool-runs/semgrep-local'
        self.payload = {
            "control_id": self.control_id, "project_path": f"/home/community-user/{PRIVATE}",
            "confirm_local": True, "confirm_link": True,
        }

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=3)
        server.STORE = self.old_store
        self.temp.cleanup()

    def request(self, path, payload=None):
        data = None if payload is None else json.dumps(payload).encode()
        req = Request(self.base + path, data=data,
                      method="POST" if data is not None else "GET",
                      headers={"Content-Type": "application/json"} if data else {})
        try:
            with urlopen(req, timeout=5) as response:
                return response.status, json.loads(response.read())
        except HTTPError as error:
            return error.code, json.loads(error.read())

    def test_fresh_scan_link_is_aggregate_only_idempotent_and_needs_review(self):
        with patch.object(server, "run_local_semgrep", return_value=SUMMARY) as scan:
            code, link = self.request(self.path, self.payload)
            self.assertEqual(code, 201)
            scan.assert_called_once_with(self.payload["project_path"])
            self.assertEqual(link["tool_identity"], "semgrep-local")
            self.assertEqual(link["result_count"], 1)
            self.assertEqual(link["severity_counts"]["ERROR"], 1)
            self.assertNotIn("severity_counts_json", link)
            self.assertEqual(self.request(self.path, self.payload)[0], 200)
        _, engagement = self.request(f'/api/engagements/{self.engagement["id"]}')
        self.assertEqual(len(engagement["tool_evidence"]), 1)
        self.assertEqual(engagement["tool_evidence"][0]["id"], link["id"])
        self.assertEqual(next(t for t in engagement["tests"] if t["control_id"] == self.control_id)["status"], "needs_review")
        with self.store._connect() as db:
            rows = [dict(r) for r in db.execute("SELECT * FROM semgrep_tool_evidence_links")]
        self.assertEqual(len(rows), 1)
        self.assertNotIn(PRIVATE, json.dumps({"link": link, "engagement": engagement["tool_evidence"], "db": rows}))

    def test_invalid_consent_scope_control_and_payload_never_scan(self):
        with patch.object(server, "run_local_semgrep", return_value=SUMMARY) as scan:
            for change in (
                {"confirm_local": False}, {"confirm_link": False},
                {"control_id": "MISSING"}, {"summary": SUMMARY},
            ):
                self.assertEqual(self.request(self.path, {**self.payload, **change})[0], 400)
            self.store.update_engagement(self.engagement["id"], {"status": "paused"})
            self.assertEqual(self.request(self.path, self.payload)[0], 403)
            scan.assert_not_called()

    def test_storage_rejects_nonaggregate_or_inconsistent_results(self):
        for altered in (
            {**SUMMARY, "path": PRIVATE},
            {**SUMMARY, "result_count": 2},
            {**SUMMARY, "report_sha256": "not-a-digest"},
            {**SUMMARY, "severity_counts": {**SUMMARY["severity_counts"], "ERROR": True}},
        ):
            with self.assertRaises(ValueError):
                self.store.add_semgrep_tool_evidence(self.engagement["id"], self.control_id, altered)
        with self.store._connect() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM semgrep_tool_evidence_links").fetchone()[0], 0)


if __name__ == "__main__":
    unittest.main()
