"""Runtime contract for opt-in, aggregate-only Burp Site-map evidence links."""
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
from tool_report_burp_sitemap import parse_burp_sitemap_summary

PRIVATE_MARKERS = ("private.invalid", "PRIVATE_BURP_REQUEST_20261012", "PRIVATE_BURP_RESPONSE_20261012")
REPORT = (
    "<items>"
    "<item><url>https://private.invalid/a</url><host>private.invalid</host>"
    "<request>PRIVATE_BURP_REQUEST_20261012</request>"
    "<response>PRIVATE_BURP_RESPONSE_20261012</response>"
    "<status>200</status><mimetype>HTML</mimetype></item>"
    "<item><url>https://private.invalid/b</url><status>404</status><mimetype>JSON</mimetype></item>"
    "</items>"
)

class BurpSitemapEvidenceLinkApiTests(unittest.TestCase):
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
            target_id=target["id"], name="synthetic authorized Burp review",
            authorization_ref="FIXTURE-AUTH", scope_notes="synthetic", out_of_scope="", test_window="",
            special_approvals={"redacted_data_proof": True},
        )
        self.control_id = self.engagement["tests"][0]["control_id"]
        self.engagement_id = self.engagement["id"]
        self.path = f"/api/engagements/{self.engagement_id}/tool-evidence/burp-sitemap-xml"

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=3)
        server.STORE = self.previous_store
        self.temporary.cleanup()

    def request(self, path, payload=None):
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        request = Request(self.base + path, data=body, method="POST" if body is not None else "GET", headers={"Content-Type": "application/json"} if body is not None else {})
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
        summary = parse_burp_sitemap_summary(REPORT)
        self.assertEqual(linked["tool_identity"], "burp-sitemap-xml")
        self.assertEqual(linked["report_sha256"], summary["report_sha256"])
        self.assertEqual(linked["item_count"], 2)
        self.assertEqual(linked["status_counts"], {"200": 1, "404": 1})
        self.assertEqual(linked["mimetype_counts"], {"HTML": 1, "JSON": 1, "XML": 0, "OTHER": 0, "UNKNOWN": 0})
        duplicate_code, duplicate = self.request(self.path, self.payload())
        self.assertEqual(duplicate_code, 200)
        self.assertEqual(duplicate["id"], linked["id"])
        read_code, engagement = self.request(f"/api/engagements/{self.engagement_id}")
        self.assertEqual(read_code, 200)
        self.assertEqual([x["id"] for x in engagement["tool_evidence"]], [linked["id"]])
        controls = {x["control_id"]: x for x in engagement["tests"]}
        self.assertEqual(controls[self.control_id]["status"], "needs_review")
        with self.store._connect() as db:
            evidence_rows = [dict(x) for x in db.execute("SELECT * FROM burp_sitemap_tool_evidence_links")]
            test_rows = [dict(x) for x in db.execute("SELECT * FROM manual_tests WHERE engagement_id = ?", (self.engagement_id,))]
            audit_rows = [dict(x) for x in db.execute("SELECT * FROM audit_log WHERE entity_id = ?", (self.engagement_id,))]
        serialized = json.dumps({"response": linked, "evidence": evidence_rows, "tests": test_rows, "audit": audit_rows})
        self.assertTrue(all(marker not in serialized for marker in PRIVATE_MARKERS))

    def test_no_consent_malformed_report_and_unknown_fields_are_rejected(self):
        self.assertEqual(self.request(self.path, self.payload(confirm_link=False))[0], 400)
        self.assertEqual(self.request(self.path, self.payload(extra="unexpected"))[0], 400)
        self.assertEqual(self.request(self.path, self.payload(report="<items><item><status>99</status></item></items>"))[0], 400)
        self.assertEqual(self.request(self.path, self.payload(report=123))[0], 400)
        self.assertEqual(self.request(self.path, self.payload(control_id="MISSING-CONTROL"))[0], 400)
        self.assertEqual(self.request(self.path, self.payload(raw_xml="PRIVATE_BURP_REQUEST_20261012"))[0], 400)

    def test_engagement_and_special_approval_are_required(self):
        missing = self.request("/api/engagements/missing-fixture/tool-evidence/burp-sitemap-xml", self.payload())
        self.assertEqual(missing[0], 404)
        with self.store._connect() as db:
            db.execute("UPDATE engagements SET status = 'paused' WHERE id = ?", (self.engagement_id,))
        self.assertEqual(self.request(self.path, self.payload())[0], 403)
        with self.store._connect() as db:
            db.execute("UPDATE engagements SET status = 'active', special_approvals_json = ? WHERE id = ?", (json.dumps({"redacted_data_proof": False}), self.engagement_id))
        self.assertEqual(self.request(self.path, self.payload())[0], 403)

    def test_link_never_downgrades_a_passed_control(self):
        with self.store._connect() as db:
            db.execute("UPDATE manual_tests SET status = 'passed' WHERE engagement_id = ? AND control_id = ?", (self.engagement_id, self.control_id))
        self.assertEqual(self.request(self.path, self.payload())[0], 201)
        with self.store._connect() as db:
            status = db.execute("SELECT status FROM manual_tests WHERE engagement_id = ? AND control_id = ?", (self.engagement_id, self.control_id)).fetchone()[0]
        self.assertEqual(status, "passed")

    def test_all_tool_evidence_writers_share_the_100_link_cap(self):
        with self.store._connect() as db:
            for index in range(100):
                digest = f"{index:064x}"
                db.execute("INSERT INTO burp_sitemap_tool_evidence_links(id, engagement_id, control_id, tool_identity, report_sha256, item_count, status_counts_json, mimetype_counts_json, created_at) VALUES (?, ?, ?, 'burp-sitemap-xml', ?, 0, '{}', '{}', '2026-10-12T00:00:00Z')", (f"seed-{index}", self.engagement_id, self.control_id, digest))
        summary = parse_burp_sitemap_summary(REPORT)
        attempts = (
            lambda: self.store.add_burp_sitemap_tool_evidence(self.engagement_id, self.control_id, summary),
            lambda: self.store.add_nmap_tool_evidence(self.engagement_id, self.control_id, {"report_sha256": "a" * 64, "host_count": 0, "up_host_count": 0, "open_port_count": 0, "open_protocol_counts": {"tcp": 0, "udp": 0}, "open_port_bands": {"well_known": 0, "registered": 0, "dynamic": 0}}),
            lambda: self.store.add_nuclei_tool_evidence(self.engagement_id, self.control_id, {"report_sha256": "b" * 64, "record_count": 0, "unique_template_count": 0, "severity_counts": {}}),
            lambda: self.store.add_gitleaks_tool_evidence(self.engagement_id, self.control_id, {"report_sha256": "c" * 64, "total_findings": 0, "rules_triggered": 0, "files_affected": 0}),
            lambda: self.store.add_trivy_tool_evidence(self.engagement_id, self.control_id, {"report_sha256": "d" * 64, "result_count": 0, "class_counts": {}, "vuln_counts": {}, "finding_counts": {}}),
        )
        for attempt in attempts:
            with self.assertRaises(ValueError):
                attempt()
