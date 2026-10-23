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


class BurpRootChildrenRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=Path.cwd())
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
            target_id=target["id"], name="synthetic authorized Burp review",
            authorization_ref="FIXTURE-AUTH", scope_notes="synthetic", out_of_scope="", test_window="",
            special_approvals={"redacted_data_proof": True},
        )
        self.engagement_id = engagement["id"]
        self.control_id = engagement["tests"][0]["control_id"]
        self.link_path = f"/api/engagements/{self.engagement_id}/tool-evidence/burp-sitemap-xml"

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=3)
        server.STORE = self.previous_store
        self.temporary.cleanup()

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

    def summary(self, report):
        return self.request("/api/tool-reports/burp-sitemap/summary", {"report": report})

    def test_valid_empty_item_and_arbitrary_item_fields_preserve_aggregate(self):
        empty = "<?xml version=\"1.0\"?><!DOCTYPE items [<!ELEMENT items (item*)>]><items/>"
        empty_code, empty_result = self.summary(empty)
        self.assertEqual(empty_code, 200)
        self.assertEqual(empty_result["item_count"], 0)

        plain = "<items><item><status>200</status><mimetype>HTML</mimetype></item></items>"
        plain_code, plain_result = self.summary(plain)
        self.assertEqual(plain_code, 200)
        self.assertEqual(plain_result["item_count"], 1)
        self.assertEqual(plain_result["status_counts"], {"200": 1})

        with_fields = (
            "<?xml version=\"1.0\"?><!DOCTYPE items [<!ELEMENT items (item*)>]>"
            "<items>  <!-- accepted comment -->\n"
            "<item><url>https://private.invalid/a</url><host>private.invalid</host>"
            "<status>200</status><request>PRIVATE_REQUEST</request>"
            "<mimetype>HTML</mimetype><custom><nested>ignored</nested></custom></item>\n </items>"
        )
        fields_code, fields_result = self.summary(with_fields)
        self.assertEqual(fields_code, 200)
        self.assertEqual(fields_result, plain_result)
        self.assertNotIn("private.invalid", json.dumps(fields_result))
        self.assertNotIn("PRIVATE_REQUEST", json.dumps(fields_result))

    def test_direct_unexpected_root_children_are_http_400_without_aggregate(self):
        malformed = (
            "<items><metadata/></items>",
            "<items><item><status>200</status></item><metadata/></items>",
            "<items><wrapper><item><status>200</status></item></wrapper></items>",
        )
        for xml in malformed:
            with self.subTest(xml=xml):
                code, result = self.summary(xml)
                self.assertEqual(code, 400)
                self.assertNotIn("item_count", result)
                self.assertNotIn("report_sha256", result)

    def test_authorized_link_rejects_unexpected_child_without_new_record(self):
        malformed = (
            "<items><metadata/></items>",
            "<items><item><status>200</status></item><metadata/></items>",
            "<items><wrapper><item><status>200</status></item></wrapper></items>",
        )
        for xml in malformed:
            with self.subTest(xml=xml):
                code, _ = self.request(self.link_path, {
                    "control_id": self.control_id, "report": xml, "confirm_link": True,
                })
                self.assertEqual(code, 400)
                with self.store._connect() as db:
                    count = db.execute(
                        "SELECT COUNT(*) FROM burp_sitemap_tool_evidence_links WHERE engagement_id = ?",
                        (self.engagement_id,),
                    ).fetchone()[0]
                    control_status = db.execute(
                        "SELECT status FROM manual_tests WHERE engagement_id = ? AND control_id = ?",
                        (self.engagement_id, self.control_id),
                    ).fetchone()[0]
                self.assertEqual(count, 0)
                self.assertEqual(control_status, "not_tested")


if __name__ == "__main__":
    unittest.main()
