"""Runtime contract for explicit, aggregate-only ZAP traditional JSON links."""
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
from tool_report_zap import parse_zap_traditional_json_summary


PRIVATE = "PRIVATE_ZAP_ALERT_BODY_20261013"
REPORT = {"site": [{"@name": "https://private.invalid/secret", "alerts": [
    {"riskcode": "3", "count": "2", "name": PRIVATE, "instances": [{"evidence": PRIVATE}]},
]}]}


class ZapEvidenceLinkApiTests(unittest.TestCase):
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
        engagement = self.store.create_engagement(
            target_id=target["id"], name="synthetic ZAP review",
            authorization_ref="FIXTURE-AUTH", scope_notes="synthetic fixture",
            out_of_scope="", test_window="",
            special_approvals={"redacted_data_proof": True},
        )
        self.engagement_id = engagement["id"]
        self.control_id = engagement["tests"][0]["control_id"]
        self.path = f"/api/engagements/{self.engagement_id}/tool-evidence/zap-traditional-json"

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=3)
        server.STORE = self.previous_store
        self.temporary.cleanup()

    def request(self, path, payload=None):
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        request = Request(
            self.base + path, data=body,
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

    def payload(self, **changes):
        value = {"control_id": self.control_id, "report": REPORT, "confirm_link": True}
        value.update(changes)
        return value

    def test_explicit_link_persists_only_aggregate_and_is_idempotent(self):
        status, link = self.request(self.path, self.payload())
        self.assertEqual(status, 201)
        expected = parse_zap_traditional_json_summary(REPORT)
        for key in ("report_sha256", "site_count", "alert_type_count", "instance_count", "risk_counts"):
            self.assertEqual(link[key], expected[key])
        self.assertEqual(link["tool_identity"], "zap-traditional-json")
        self.assertEqual(self.request(self.path, self.payload())[0], 200)
        status, engagement = self.request(f"/api/engagements/{self.engagement_id}")
        self.assertEqual(status, 200)
        self.assertEqual([item["id"] for item in engagement["tool_evidence"]], [link["id"]])
        self.assertEqual(next(item for item in engagement["tests"] if item["control_id"] == self.control_id)["status"], "needs_review")
        with self.store._connect() as db:
            rows = [dict(row) for row in db.execute("SELECT * FROM zap_tool_evidence_links")]
            audit = [dict(row) for row in db.execute("SELECT * FROM audit_log WHERE entity_id = ?", (self.engagement_id,))]
        self.assertEqual(len(rows), 1)
        self.assertNotIn(PRIVATE, json.dumps({"link": link, "engagement": engagement, "rows": rows, "audit": audit}))
        self.assertNotIn("private.invalid", json.dumps({"link": link, "engagement": engagement, "rows": rows, "audit": audit}))

    def test_missing_consent_invalid_report_and_unknown_fields_are_rejected(self):
        bad = [
            self.payload(confirm_link=False), self.payload(extra="unexpected"),
            self.payload(control_id="missing"), self.payload(report=[]),
            self.payload(report={"site": [{"alerts": [{"riskcode": "4", "count": "1"}]}]}),
            self.payload(report={"site": [{"alerts": [{"riskcode": "3", "count": "0"}]}]}),
            self.payload(report={"site": [{"alerts": [{"riskcode": "3", "count": "1", "text": "x" * 60_001}]}]}),
        ]
        for payload in bad:
            with self.subTest(payload=payload.keys()):
                self.assertEqual(self.request(self.path, payload)[0], 400)
        with self.store._connect() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM zap_tool_evidence_links").fetchone()[0], 0)

    def test_only_active_authorized_redacted_engagement_can_link(self):
        self.assertEqual(self.request("/api/engagements/missing/tool-evidence/zap-traditional-json", self.payload())[0], 404)
        with self.store._connect() as db:
            db.execute("UPDATE engagements SET status = 'paused' WHERE id = ?", (self.engagement_id,))
        self.assertEqual(self.request(self.path, self.payload())[0], 403)
        with self.store._connect() as db:
            db.execute("UPDATE engagements SET status = 'active', special_approvals_json = '{}' WHERE id = ?", (self.engagement_id,))
        self.assertEqual(self.request(self.path, self.payload())[0], 403)
        with self.store._connect() as db:
            db.execute("UPDATE engagements SET authorization_ref = ' ', special_approvals_json = ? WHERE id = ?", (json.dumps({"redacted_data_proof": True}), self.engagement_id))
        self.assertEqual(self.request(self.path, self.payload())[0], 403)

    def test_existing_decision_is_not_downgraded(self):
        with self.store._connect() as db:
            db.execute("UPDATE manual_tests SET status = 'passed' WHERE engagement_id = ? AND control_id = ?", (self.engagement_id, self.control_id))
        self.assertEqual(self.request(self.path, self.payload())[0], 201)
        with self.store._connect() as db:
            value = db.execute("SELECT status FROM manual_tests WHERE engagement_id = ? AND control_id = ?", (self.engagement_id, self.control_id)).fetchone()[0]
        self.assertEqual(value, "passed")

    def test_shared_link_cap_counts_zap_both_directions(self):
        self.assertEqual(self.request(self.path, self.payload())[0], 201)
        with self.store._connect() as db:
            for index in range(99):
                db.execute(
                    """INSERT INTO burp_sitemap_tool_evidence_links(
                       id, engagement_id, control_id, tool_identity, report_sha256, item_count,
                       status_counts_json, mimetype_counts_json, created_at
                    ) VALUES (?, ?, ?, 'burp-sitemap-xml', ?, 0, '{}', '{}', '2026-10-13T00:00:00Z')""",
                    (f"seed-{index}", self.engagement_id, self.control_id, f"{index:064x}"),
                )
        second = {"site": [{"alerts": [{"riskcode": "1", "count": "1"}]}]}
        self.assertEqual(self.request(self.path, self.payload(report=second))[0], 400)
        testssl = [{"id": "one", "ip": "127.0.0.1", "port": "443", "severity": "INFO", "finding": "fixture"}]
        self.assertEqual(self.request(
            f"/api/engagements/{self.engagement_id}/tool-evidence/testssl-flat-json",
            {"control_id": self.control_id, "report": testssl, "confirm_link": True},
        )[0], 400)

    def test_schema_is_added_to_existing_synthetic_database(self):
        with self.store._connect() as db:
            db.execute("DROP TABLE zap_tool_evidence_links")
        replacement = Store(self.store.path)
        with replacement._connect() as db:
            self.assertEqual(db.execute("PRAGMA integrity_check").fetchone()[0], "ok")
            self.assertEqual(db.execute("SELECT COUNT(*) FROM zap_tool_evidence_links").fetchone()[0], 0)


if __name__ == "__main__":
    unittest.main()
