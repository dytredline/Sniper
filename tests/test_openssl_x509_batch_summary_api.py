import hashlib
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


def openssl_date(value):
    return f"{value.strftime('%b')} {value.day:2d} {value:%H:%M:%S %Y} GMT"


def report(before, after):
    fingerprint = ":".join(["AB"] * 32)
    return f"notBefore={openssl_date(before)}\nnotAfter={openssl_date(after)}\nsha256 Fingerprint={fingerprint}\n"


class OpenSslX509BatchSummaryApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path.home())
        self.previous_store = server.STORE
        server.STORE = Store(Path(self.temp.name) / "sniper.db")
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.SniperHandler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.batch_url = f"http://127.0.0.1:{self.httpd.server_address[1]}/api/tool-reports/openssl-x509/batch-summary"
        self.single_url = f"http://127.0.0.1:{self.httpd.server_address[1]}/api/tool-reports/openssl-x509/summary"

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)
        server.STORE = self.previous_store
        self.temp.cleanup()

    def request_batch(self, value):
        body = json.dumps(value).encode()
        req = Request(self.batch_url, data=body, headers={"Content-Type": "application/json"})
        try:
            with urlopen(req, timeout=5) as response:
                return response.status, json.loads(response.read())
        except HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def request_single(self, value):
        body = json.dumps(value).encode()
        req = Request(self.single_url, data=body, headers={"Content-Type": "application/json"})
        try:
            with urlopen(req, timeout=5) as response:
                return response.status, json.loads(response.read())
        except HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def test_batch_summary_positive_mixed_validity(self):
        now = datetime.now(timezone.utc)
        valid_report = report(now - timedelta(days=30), now + timedelta(days=60))
        expiring_report = report(now - timedelta(days=1), now + timedelta(days=10))
        expired_report = report(now - timedelta(days=10), now - timedelta(days=1))
        not_yet_valid_report = report(now + timedelta(days=1), now + timedelta(days=20))

        reports = [valid_report, expiring_report, expired_report, not_yet_valid_report]
        status, body = self.request_batch({"reports": reports})
        self.assertEqual(status, 200)
        self.assertEqual(body["format"], "openssl-x509-batch-summary-v1")
        self.assertEqual(body["report_count"], 4)
        self.assertEqual(body["validity_counts"], {
            "valid": 1,
            "expiring_soon": 1,
            "expired": 1,
            "not_yet_valid": 1
        })
        self.assertEqual(len(body["batch_sha256"]), 64)
        # Verify SHA256 matches canonical JSON
        canonical = json.dumps(reports, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        expected_sha256 = hashlib.sha256(canonical).hexdigest()
        self.assertEqual(body["batch_sha256"], expected_sha256)
        # No raw data exposed
        self.assertNotIn("AB:AB", json.dumps(body))
        self.assertNotIn("notBefore", json.dumps(body))
        self.assertNotIn("notAfter", json.dumps(body))

    def test_batch_summary_single_report_control(self):
        # Use a date far from 30-day boundary: 45 days validity ensures 'valid'
        now = datetime.now(timezone.utc)
        single_report = report(now - timedelta(days=1), now + timedelta(days=45))
        # Call the *single-report* URL as control (not batch)
        status, body = self.request_single({"report": single_report})
        self.assertEqual(status, 200)
        self.assertEqual(body["format"], "openssl-x509-dates-fingerprint-v1")
        self.assertEqual(body["validity"], "valid")
        self.assertEqual(len(body["report_sha256"]), 64)

    def test_batch_summary_empty_reports_400(self):
        status, body = self.request_batch({"reports": []})
        self.assertEqual(status, 400)
        self.assertIn("Geçersiz OpenSSL x509 rapor grubu.", body.get("error", ""))

    def test_batch_summary_too_many_reports_400(self):
        now = datetime.now(timezone.utc)
        reports = [report(now - timedelta(days=1), now + timedelta(days=45)) for _ in range(9)]
        status, body = self.request_batch({"reports": reports})
        self.assertEqual(status, 400)
        self.assertIn("Geçersiz OpenSSL x509 rapor grubu.", body.get("error", ""))

    def test_batch_summary_wrong_type_reports_400(self):
        status, body = self.request_batch({"reports": ["valid", 123]})
        self.assertEqual(status, 400)
        self.assertIn("Geçersiz OpenSSL x509 rapor grubu.", body.get("error", ""))

    def test_batch_summary_extra_key_400(self):
        now = datetime.now(timezone.utc)
        reports = [report(now - timedelta(days=1), now + timedelta(days=45))]
        status, body = self.request_batch({"reports": reports, "extra": "value"})
        self.assertEqual(status, 400)
        self.assertIn("Geçersiz OpenSSL x509 rapor grubu.", body.get("error", ""))

    def test_batch_summary_non_list_reports_400(self):
        status, body = self.request_batch({"reports": "not-a-list"})
        self.assertEqual(status, 400)
        self.assertIn("Geçersiz OpenSSL x509 rapor grubu.", body.get("error", ""))

    def test_batch_summary_invalid_report_400(self):
        now = datetime.now(timezone.utc)
        invalid_report = "not a valid 3-line report"
        status, body = self.request_batch({"reports": [invalid_report]})
        self.assertEqual(status, 400)
        self.assertIn("Geçersiz OpenSSL x509 rapor grubu.", body.get("error", ""))

    def test_batch_summary_oversized_report_400(self):
        now = datetime.now(timezone.utc)
        oversized_report = report(now - timedelta(days=1), now + timedelta(days=45)) + "X" * 4000
        status, body = self.request_batch({"reports": [oversized_report]})
        self.assertEqual(status, 400)
        self.assertIn("Geçersiz OpenSSL x509 rapor grubu.", body.get("error", ""))

    def test_batch_summary_missing_reports_key_400(self):
        status, body = self.request_batch({"other": "value"})
        self.assertEqual(status, 400)
        self.assertIn("Geçersiz OpenSSL x509 rapor grubu.", body.get("error", ""))

    def test_batch_summary_empty_string_report_400(self):
        status, body = self.request_batch({"reports": [""]})
        self.assertEqual(status, 400)
        self.assertIn("Geçersiz OpenSSL x509 rapor grubu.", body.get("error", ""))

    def test_batch_summary_null_report_400(self):
        status, body = self.request_batch({"reports": [None]})
        self.assertEqual(status, 400)
        self.assertIn("Geçersiz OpenSSL x509 rapor grubu.", body.get("error", ""))

    def test_batch_summary_duplicate_reports_counted_separately(self):
        now = datetime.now(timezone.utc)
        report_text = report(now - timedelta(days=1), now + timedelta(days=45))
        status, body = self.request_batch({"reports": [report_text, report_text]})
        self.assertEqual(status, 200)
        self.assertEqual(body["report_count"], 2)
        self.assertEqual(body["validity_counts"]["valid"], 2)
        self.assertEqual(body["validity_counts"]["expiring_soon"], 0)
