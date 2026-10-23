import hashlib
import json
import os
import sqlite3
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


def fixture_report(host):
    return {"status": "READY", "host": host, "statusMessage": "PRIVATE_FIXTURE_NOTE",
            "endpoints": [{"grade": "A", "ipAddress": "198.51.100.77"}]}


def logical_db_hash(path):
    with sqlite3.connect(path) as db:
        return hashlib.sha256("\n".join(db.iterdump()).encode()).hexdigest()


class SsllabsTargetPreviewOnlyApiTests(unittest.TestCase):
    def setUp(self):
        expected = os.getenv("EXPECTED_SERVER_PATH")
        if expected:
            self.assertEqual(Path(server.__file__).resolve(), Path(expected).resolve())
        self.temp = tempfile.TemporaryDirectory()
        self.dbpath = Path(self.temp.name) / "fixture.db"
        self.old_store, self.old_limiter = server.STORE, server.LIMITER
        server.STORE = Store(self.dbpath)
        server.LIMITER = server.RateLimiter()
        self.store = server.STORE
        self.create_engagement("https://example.com")
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.SniperHandler)
        self.httpd.daemon_threads = True
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=3)
        server.STORE, server.LIMITER = self.old_store, self.old_limiter
        self.temp.cleanup()

    def create_engagement(self, target):
        target_row = self.store.create_target(normalize_target(target))
        self.engagement = self.store.create_engagement(
            target_id=target_row["id"], name="fixture", authorization_ref="LOCAL-TEST",
            scope_notes="", out_of_scope="", test_window="",
            special_approvals={"redacted_data_proof": True},
        )
        self.path = f'/api/engagements/{self.engagement["id"]}/tool-reports/ssllabs-host/target-preview'

    def post(self, payload):
        req = Request(self.base + self.path, data=json.dumps(payload).encode(), method="POST",
                      headers={"Content-Type": "application/json"})
        try:
            with urlopen(req, timeout=5) as response:
                return response.status, json.loads(response.read())
        except HTTPError as error:
            try:
                return error.code, json.loads(error.read())
            finally:
                error.close()

    def preview(self, host):
        return self.post({"report": fixture_report(host), "confirm_host_preview": True})

    def test_equal_is_private_and_does_not_change_logical_db(self):
        before = logical_db_hash(self.dbpath)
        status, body = self.preview("EXAMPLE.COM.")
        after = logical_db_hash(self.dbpath)
        self.assertEqual(status, 200)
        self.assertEqual(before, after)
        self.assertEqual(body["hostname_consistency"], "normalized_hostname_equal")
        self.assertIs(body["normalized_hostname_equal"], True)
        self.assertIs(body["scope_verified"], False)
        self.assertIs(body["original_hostname_identity_verified"], False)
        self.assertIs(body["evidence_link_created"], False)
        self.assertEqual(body["endpoint_count"], 1)
        self.assertEqual(body["report_sha256"], hashlib.sha256(
            json.dumps(fixture_report("EXAMPLE.COM."), sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest())
        for secret in ("EXAMPLE.COM", "198.51.100.77", "PRIVATE_FIXTURE_NOTE"):
            self.assertNotIn(secret, json.dumps(body))

    def test_suffix_mismatch_is_not_equal(self):
        status, body = self.preview("example.com.evil.invalid")
        self.assertEqual(status, 200)
        self.assertEqual(body["hostname_consistency"], "normalized_hostname_different")
        self.assertIs(body["normalized_hostname_equal"], False)

    def test_invalid_host_and_missing_consent_rejected(self):
        for host in ("127.1", "0177.0.0.1", "faß.de", "xn--a.example", "example.com:443"):
            with self.subTest(host=host):
                self.assertEqual(self.preview(host)[0], 400)
        self.assertEqual(self.post({"report": fixture_report("example.com"), "confirm_host_preview": False})[0], 400)

    def test_unsupported_target_and_idn_identity_are_explicit(self):
        self.create_engagement("http://example.com")
        status, body = self.preview("example.com")
        self.assertEqual(status, 200)
        self.assertEqual(body["hostname_consistency"], "unsupported_target_profile")
        self.create_engagement("https://faß.de")
        status, body = self.preview("fass.de")
        self.assertEqual(status, 200)
        self.assertIs(body["normalized_hostname_equal"], True)
        self.assertIs(body["original_hostname_identity_verified"], False)
        self.assertIs(body["scope_verified"], False)

    def test_paused_engagement_forbidden(self):
        self.store.update_engagement(self.engagement["id"], {"status": "paused"})
        self.assertEqual(self.preview("example.com")[0], 403)


if __name__ == "__main__":
    unittest.main()
