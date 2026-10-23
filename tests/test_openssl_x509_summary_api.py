import json
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import server
from storage import Store
from tool_report_openssl_x509 import parse_openssl_x509_summary


def openssl_date(value):
    return f"{value.strftime('%b')} {value.day:2d} {value:%H:%M:%S %Y} GMT"


def report(before, after):
    fingerprint = ":".join(["AB"] * 32)
    return f"notBefore={openssl_date(before)}\nnotAfter={openssl_date(after)}\nsha256 Fingerprint={fingerprint}\n"


class OpenSslX509SummaryApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path.home())
        self.previous_store = server.STORE
        server.STORE = Store(Path(self.temp.name) / "sniper.db")
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.SniperHandler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}/api/tool-reports/openssl-x509/summary"

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)
        server.STORE = self.previous_store
        self.temp.cleanup()

    def request(self, value):
        body = json.dumps({"report": value}).encode()
        req = Request(self.url, data=body, headers={"Content-Type": "application/json"})
        try:
            with urlopen(req, timeout=5) as response:
                return response.status, json.loads(response.read())
        except HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def test_expiring_certificate_summary_without_input_echo(self):
        now = datetime.now(timezone.utc)
        value = report(now - timedelta(days=1), now + timedelta(days=10))
        status, body = self.request(value)
        self.assertEqual(status, 200)
        self.assertEqual(body["format"], "openssl-x509-dates-fingerprint-v1")
        self.assertEqual(body["validity"], "expiring_soon")
        self.assertGreaterEqual(body["days_until_expiry"], 9)
        self.assertLessEqual(body["days_until_expiry"], 11)
        self.assertEqual(len(body["report_sha256"]), 64)
        self.assertNotIn("AB:AB", json.dumps(body))
        self.assertNotIn("notBefore", json.dumps(body))

    def test_expired_and_not_yet_valid(self):
        now = datetime.now(timezone.utc)
        body = parse_openssl_x509_summary(report(now - timedelta(days=10), now - timedelta(days=1)), now=now)
        self.assertEqual((body["validity"], body["days_until_expiry"]), ("expired", 0))
        body = parse_openssl_x509_summary(report(now + timedelta(days=1), now + timedelta(days=20)), now=now)
        self.assertEqual(body["validity"], "not_yet_valid")

    def test_rejects_duplicate_missing_extra_and_reversed_dates(self):
        now = datetime.now(timezone.utc)
        value = report(now - timedelta(days=1), now + timedelta(days=40))
        first = value.splitlines()[0]
        for bad in (value + first + "\n", value.replace("notAfter", "notAft", 1),
                    value + "subject=private.example\n", report(now + timedelta(days=2), now)):
            with self.subTest(bad=bad[:30]):
                with self.assertRaises(ValueError) as raised:
                    parse_openssl_x509_summary(bad, now=now)
                self.assertNotIn("private.example", str(raised.exception))

    def test_rejects_bad_fingerprint_date_and_oversize(self):
        now = datetime.now(timezone.utc)
        value = report(now - timedelta(days=1), now + timedelta(days=40))
        for bad in (value.replace("AB:AB", "ZZ:AB", 1), value.replace(" GMT", " PST", 1),
                    value + "X" * 3000):
            with self.subTest(bad=bad[:30]):
                with self.assertRaises(ValueError):
                    parse_openssl_x509_summary(bad, now=now)

    def test_rejects_non_string_report(self):
        status, _ = self.request({"notBefore": "today"})
        self.assertEqual(status, 400)
