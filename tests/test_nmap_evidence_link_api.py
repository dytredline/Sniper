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


XML = '<nmaprun><host><status state="up"/><ports><port protocol="tcp" portid="443"><state state="open"/></port></ports></host></nmaprun>'


class NmapEvidenceLinkApiTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=Path.home())
        self.original_store = server.STORE
        self.store = Store(Path(self.temporary.name) / "sniper.db")
        server.STORE = self.store
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.SniperHandler)
        self.httpd.daemon_threads = True
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        target = self.store.create_target(normalize_target("https://example.com"))
        self.engagement = self.store.create_engagement(
            target_id=target["id"], name="fixture", authorization_ref="AUTH-1",
            scope_notes="", out_of_scope="", test_window="",
            special_approvals={"redacted_data_proof": True},
        )
        self.control = self.engagement["tests"][0]["control_id"]
        self.path = f'/api/engagements/{self.engagement["id"]}/tool-evidence/nmap'

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)
        server.STORE = self.original_store
        self.temporary.cleanup()

    def request(self, path, payload=None):
        body = None if payload is None else json.dumps(payload).encode()
        request = Request(
            self.base + path, data=body, method="POST" if body else "GET",
            headers={"Content-Type": "application/json"} if body else {},
        )
        try:
            with urlopen(request, timeout=5) as response:
                return response.status, json.loads(response.read())
        except HTTPError as error:
            try:
                return error.code, json.loads(error.read())
            finally:
                error.close()

    def test_link_is_opt_in_idempotent_and_does_not_mark_control_passed(self):
        payload = {"control_id": self.control, "report": XML, "confirm_link": True}
        status, linked = self.request(self.path, payload)
        self.assertEqual(status, 201)
        self.assertEqual(linked["report_sha256"], hashlib.sha256(XML.encode()).hexdigest())
        self.assertEqual(linked["open_port_count"], 1)
        status, duplicate = self.request(self.path, payload)
        self.assertEqual(status, 200)
        self.assertEqual(duplicate["id"], linked["id"])
        status, engagement = self.request(f'/api/engagements/{self.engagement["id"]}')
        self.assertEqual(status, 200)
        self.assertEqual(len(engagement["tool_evidence"]), 1)
        self.assertEqual(engagement["tests"][0]["status"], "needs_review")
        with self.store._connect() as db:
            row = dict(db.execute("SELECT * FROM tool_evidence_links").fetchone())
        self.assertNotIn(XML, json.dumps(row))
        self.assertNotIn("example.com", json.dumps(row))

    def test_rejects_missing_confirmation_invalid_report_and_inactive_engagement(self):
        base = {"control_id": self.control, "report": XML}
        self.assertEqual(self.request(self.path, {**base, "confirm_link": False})[0], 400)
        self.assertEqual(self.request(self.path, {**base, "confirm_link": True, "raw_log": "secret"})[0], 400)
        self.assertEqual(self.request(self.path, {**base, "report": "<bad/>", "confirm_link": True})[0], 400)
        self.store.update_engagement(self.engagement["id"], {"status": "paused"})
        self.assertEqual(self.request(self.path, {**base, "confirm_link": True})[0], 403)


if __name__ == "__main__":
    unittest.main()
