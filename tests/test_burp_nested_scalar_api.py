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


class BurpNestedScalarApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path.home())
        self.previous_store = server.STORE
        self.store = Store(Path(self.temp.name) / "data" / "sniper.db")
        server.STORE = self.store
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.SniperHandler)
        self.httpd.daemon_threads = True
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        self.url = self.base_url + "/api/tool-reports/burp-sitemap/summary"

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)
        server.STORE = self.previous_store
        self.temp.cleanup()

    def post(self, xml):
        request = Request(
            self.url,
            data=json.dumps({"report": xml}).encode("utf-8"),
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with urlopen(request, timeout=5) as response:
            return response.status, json.loads(response.read())

    def assert_bad_xml(self, xml):
        with self.assertRaises(HTTPError) as context:
            self.post(xml)
        self.assertEqual(context.exception.code, 400)
        self.assertNotIn("404", context.exception.read().decode("utf-8"))

    def test_valid_scalar_and_duplicate_items_control(self):
        xml = "<items><item><status>200</status><mimetype>HTML</mimetype></item><item><status>200</status><mimetype>JSON</mimetype></item></items>"
        status, payload = self.post(xml)
        self.assertEqual(status, 200)
        self.assertEqual(payload["item_count"], 2)
        self.assertEqual(payload["status_counts"], {"200": 2})
        self.assertEqual(payload["mimetype_counts"]["HTML"], 1)
        self.assertEqual(payload["mimetype_counts"]["JSON"], 1)

    def test_valid_unrelated_nested_item_data_control(self):
        xml = "<items><item><status>200</status><mimetype>HTML</mimetype><response><body>ok</body></response></item></items>"
        status, payload = self.post(xml)
        self.assertEqual(status, 200)
        self.assertEqual(payload["item_count"], 1)

    def test_nested_status_rejected(self):
        for xml in (
            "<items><item><status>200<status>404</status></status><mimetype>HTML</mimetype></item></items>",
            "<items><item><status>200<code>404</code></status></item></items>",
        ):
            with self.subTest(xml=xml):
                self.assert_bad_xml(xml)

    def test_nested_mimetype_rejected(self):
        for xml in (
            "<items><item><status>200</status><mimetype>HTML<mimetype>JSON</mimetype></mimetype></item></items>",
            "<items><item><status>200</status><mimetype>image/png<other>secret</other></mimetype></item></items>",
        ):
            with self.subTest(xml=xml):
                self.assert_bad_xml(xml)

    def test_non_item_root_child_rejected_task24_regression(self):
        self.assert_bad_xml("<items><item><status>200</status></item><wrapper><item><status>404</status></item></wrapper></items>")

    def test_nested_scalar_evidence_link_rejected_without_record(self):
        target = self.store.create_target(normalize_target("https://fixture.invalid"))
        engagement = self.store.create_engagement(
            target_id=target["id"], name="synthetic authorized Burp review",
            authorization_ref="FIXTURE-AUTH", scope_notes="synthetic",
            out_of_scope="", test_window="",
            special_approvals={"redacted_data_proof": True},
        )
        control_id = engagement["tests"][0]["control_id"]
        xml = "<items><item><status>200<status>404</status></status><mimetype>HTML</mimetype></item></items>"
        body = json.dumps({
            "control_id": control_id, "report": xml, "confirm_link": True,
        }).encode("utf-8")
        request = Request(
            self.base_url + f"/api/engagements/{engagement['id']}/tool-evidence/burp-sitemap-xml",
            data=body, method="POST", headers={"Content-Type": "application/json"},
        )
        with self.assertRaises(HTTPError) as context:
            urlopen(request, timeout=5)
        self.assertEqual(context.exception.code, 400)
        with self.store._connect() as db:
            records = db.execute(
                "SELECT COUNT(*) FROM burp_sitemap_tool_evidence_links WHERE engagement_id = ?",
                (engagement["id"],),
            ).fetchone()[0]
            status = db.execute(
                "SELECT status FROM manual_tests WHERE engagement_id = ? AND control_id = ?",
                (engagement["id"], control_id),
            ).fetchone()[0]
        self.assertEqual(records, 0)
        self.assertEqual(status, "not_tested")


if __name__ == "__main__":
    unittest.main()
