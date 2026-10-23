"""Runtime contract for explicit, aggregate-only TestSSL evidence links."""
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
from tool_report_testssl import parse_testssl_json_summary

PRIVATE_MARKERS = (
    "PRIVATE_TESTSSL_ID_20261012",
    "PRIVATE_TESTSSL_IP_20261012",
    "PRIVATE_TESTSSL_FINDING_20261012",
)
REPORT = [{
    "id": PRIVATE_MARKERS[0],
    "ip": PRIVATE_MARKERS[1],
    "port": "443",
    "severity": "HIGH",
    "finding": PRIVATE_MARKERS[2],
}]


class TestsslEvidenceLinkApiTests(unittest.TestCase):
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
        target = self.store.create_target(normalize_target("https://fixture.invalid"))
        self.engagement = self.store.create_engagement(
            target_id=target["id"], name="synthetic authorized TLS review",
            authorization_ref="FIXTURE-AUTH", scope_notes="synthetic fixture",
            out_of_scope="", test_window="",
            special_approvals={"redacted_data_proof": True},
        )
        self.engagement_id = self.engagement["id"]
        self.control_id = self.engagement["tests"][0]["control_id"]
        self.path = f"/api/engagements/{self.engagement_id}/tool-evidence/testssl-flat-json"

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=3)
        server.STORE = self.previous_store
        self.temporary.cleanup()

    def request(self, path, payload=None):
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        request = Request(
            self.base + path,
            data=body,
            method="POST" if body is not None else "GET",
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

    def payload(self, **updates):
        result = {"control_id": self.control_id, "report": REPORT, "confirm_link": True}
        result.update(updates)
        return result

    def test_link_is_explicit_aggregate_only_idempotent_and_readable(self):
        code, linked = self.request(self.path, self.payload())
        self.assertEqual(code, 201)
        expected = parse_testssl_json_summary(REPORT)
        self.assertEqual(linked["tool_identity"], "testssl-flat-json")
        self.assertEqual(linked["report_sha256"], expected["report_sha256"])
        self.assertEqual(linked["record_count"], 1)
        self.assertEqual(linked["severity_counts"], expected["severity_counts"])
        self.assertTrue(all(marker not in json.dumps(linked) for marker in PRIVATE_MARKERS))

        duplicate_code, duplicate = self.request(self.path, self.payload())
        self.assertEqual(duplicate_code, 200)
        self.assertEqual(duplicate["id"], linked["id"])

        read_code, engagement = self.request(f"/api/engagements/{self.engagement_id}")
        self.assertEqual(read_code, 200)
        self.assertEqual([item["id"] for item in engagement["tool_evidence"]], [linked["id"]])
        controls = {item["control_id"]: item for item in engagement["tests"]}
        self.assertEqual(controls[self.control_id]["status"], "needs_review")
        serialized = json.dumps(engagement, ensure_ascii=False)
        self.assertTrue(all(marker not in serialized for marker in PRIVATE_MARKERS))

        with self.store._connect() as db:
            evidence = [dict(row) for row in db.execute("SELECT * FROM testssl_tool_evidence_links")]
            tests = [dict(row) for row in db.execute(
                "SELECT * FROM manual_tests WHERE engagement_id = ?", (self.engagement_id,)
            )]
            audit = [dict(row) for row in db.execute(
                "SELECT * FROM audit_log WHERE entity_id = ?", (self.engagement_id,)
            )]
        stored = json.dumps({"evidence": evidence, "tests": tests, "audit": audit}, ensure_ascii=False)
        self.assertTrue(all(marker not in stored for marker in PRIVATE_MARKERS))
        self.assertEqual(len(evidence), 1)
        self.assertNotIn("report", evidence[0])
        self.assertNotIn("finding", evidence[0])
        self.assertNotIn("ip", evidence[0])

    def test_no_consent_malformed_input_and_unknown_fields_are_rejected(self):
        self.assertEqual(self.request(self.path, self.payload(confirm_link=False))[0], 400)
        self.assertEqual(self.request(self.path, self.payload(extra="unexpected"))[0], 400)
        self.assertEqual(self.request(self.path, self.payload(raw_report=REPORT))[0], 400)
        self.assertEqual(self.request(self.path, self.payload(control_id="MISSING-CONTROL"))[0], 400)
        self.assertEqual(self.request(self.path, self.payload(report=123))[0], 400)
        self.assertEqual(self.request(self.path, self.payload(report=[{"id": "x"}]))[0], 400)
        self.assertEqual(self.request(self.path, self.payload(report=[{
            "id": "x", "ip": "127.0.0.1", "port": "443",
            "severity": "HIGH", "finding": "x" * 60_001,
        }]))[0], 400)

    def test_authorized_active_engagement_and_special_approval_are_required(self):
        self.assertEqual(self.request(
            "/api/engagements/missing-fixture/tool-evidence/testssl-flat-json", self.payload()
        )[0], 404)
        with self.store._connect() as db:
            db.execute("UPDATE engagements SET status = 'paused' WHERE id = ?", (self.engagement_id,))
        self.assertEqual(self.request(self.path, self.payload())[0], 403)
        with self.store._connect() as db:
            db.execute(
                "UPDATE engagements SET status = 'active', special_approvals_json = ? WHERE id = ?",
                (json.dumps({"redacted_data_proof": False}), self.engagement_id),
            )
        self.assertEqual(self.request(self.path, self.payload())[0], 403)
        with self.store._connect() as db:
            db.execute(
                "UPDATE engagements SET authorization_ref = ' ' , special_approvals_json = ? WHERE id = ?",
                (json.dumps({"redacted_data_proof": True}), self.engagement_id),
            )
        self.assertEqual(self.request(self.path, self.payload())[0], 403)

    def test_link_never_downgrades_passed_control(self):
        with self.store._connect() as db:
            db.execute(
                "UPDATE manual_tests SET status = 'passed' WHERE engagement_id = ? AND control_id = ?",
                (self.engagement_id, self.control_id),
            )
        self.assertEqual(self.request(self.path, self.payload())[0], 201)
        with self.store._connect() as db:
            status = db.execute(
                "SELECT status FROM manual_tests WHERE engagement_id = ? AND control_id = ?",
                (self.engagement_id, self.control_id),
            ).fetchone()[0]
        self.assertEqual(status, "passed")

    def test_testssl_links_count_toward_shared_100_record_cap(self):
        summary = parse_testssl_json_summary(REPORT)
        _, created = self.store.add_testssl_tool_evidence(self.engagement_id, self.control_id, summary)
        self.assertTrue(created)
        with self.store._connect() as db:
            for index in range(99):
                digest = f"{index:064x}"
                db.execute(
                    """INSERT INTO burp_sitemap_tool_evidence_links(
                        id, engagement_id, control_id, tool_identity, report_sha256, item_count,
                        status_counts_json, mimetype_counts_json, created_at
                    ) VALUES (?, ?, ?, 'burp-sitemap-xml', ?, 0, '{}', '{}', '2026-10-12T00:00:00Z')""",
                    (f"seed-{index}", self.engagement_id, self.control_id, digest),
                )
        report_two = [{
            "id": "second", "ip": "127.0.0.1", "port": "8443",
            "severity": "INFO", "finding": "second report",
        }]
        self.assertEqual(self.request(self.path, self.payload(report=report_two))[0], 400)


if __name__ == "__main__":
    unittest.main()
