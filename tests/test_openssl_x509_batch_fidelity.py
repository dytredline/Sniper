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
from tool_report_openssl_x509 import (
    count_byte_identical_duplicate_reports,
    parse_openssl_x509_batch_fidelity_summary,
    parse_openssl_x509_batch_summary,
    parse_openssl_x509_summary,
    split_openssl_x509_batch_reports,
)


def openssl_date(value: datetime) -> str:
    return f"{value.strftime('%b')} {value.day:2d} {value:%H:%M:%S %Y} GMT"


def make_report(before: datetime, after: datetime, hex_byte: str = "AA", trailing_lf: bool = True) -> str:
    fingerprint = ":".join([hex_byte] * 32)
    lines = (
        f"notBefore={openssl_date(before)}\n"
        f"notAfter={openssl_date(after)}\n"
        f"sha256 Fingerprint={fingerprint}"
    )
    return lines + ("\n" if trailing_lf else "")


class OpenSslX509BatchFidelityTests(unittest.TestCase):
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

    def request_batch(self, payload: dict):
        body = json.dumps(payload).encode("utf-8")
        req = Request(self.batch_url, data=body, headers={"Content-Type": "application/json"})
        try:
            with urlopen(req, timeout=5) as response:
                return response.status, json.loads(response.read())
        except HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def test_task13_task64_canonical_sha256_vectors_and_exact_byte_fidelity(self):
        now = datetime(2027, 1, 1, tzinfo=timezone.utc)
        report_no_lf = (
            "notBefore=Jan  1 00:00:00 2025 GMT\n"
            "notAfter=Jan  1 00:00:00 2030 GMT\n"
            "sha256 Fingerprint=" + ":".join(["AA"] * 32)
        )
        report_with_lf = report_no_lf + "\n"
        report_crlf_no_lf = report_no_lf.replace("\n", "\r\n")

        # Exact-byte splitter preserves absence/presence of terminal LF and CRLF
        self.assertEqual(split_openssl_x509_batch_reports(report_no_lf), [report_no_lf])
        self.assertEqual(split_openssl_x509_batch_reports(report_with_lf), [report_with_lf])
        self.assertEqual(split_openssl_x509_batch_reports(report_crlf_no_lf), [report_crlf_no_lf])
        self.assertEqual(
            split_openssl_x509_batch_reports(json.dumps([report_no_lf])),
            [report_no_lf],
        )
        self.assertEqual(
            split_openssl_x509_batch_reports(json.dumps({"reports": [report_crlf_no_lf]})),
            [report_crlf_no_lf],
        )

        # Normalized mode appends terminal LF and normalizes CRLF -> LF
        self.assertEqual(
            split_openssl_x509_batch_reports(report_no_lf, preserve_exact_bytes=False),
            [report_with_lf],
        )
        self.assertEqual(
            split_openssl_x509_batch_reports(report_crlf_no_lf, preserve_exact_bytes=False),
            [report_with_lf],
        )

        # Verify exact Task42/Task64 SHA-256 digests
        summary_no_lf = parse_openssl_x509_batch_summary([report_no_lf], now=now)
        summary_with_lf = parse_openssl_x509_batch_summary([report_with_lf], now=now)
        summary_crlf = parse_openssl_x509_batch_summary([report_crlf_no_lf], now=now)

        self.assertEqual(
            summary_no_lf["batch_sha256"],
            "65b46e7c03c87e496d2f1ddb0779292247e5aaa146fe288866c381c3afa91284",
        )
        self.assertEqual(
            summary_with_lf["batch_sha256"],
            "2088e6cc6ba5dc667b69e6a93ff2110be3d6f7c9fcd5e7c7a7b61f2bd2082565",
        )
        self.assertEqual(
            summary_crlf["batch_sha256"],
            "076c93ade21cceee2d475ca4a5b64d47307bb19f61067e60a28e2511f995af3c",
        )

    def test_blank_line_multi_report_byte_preservation_without_synthetic_lf(self):
        now = datetime.now(timezone.utc)
        rep_a = make_report(now - timedelta(days=2), now + timedelta(days=60), "AA", trailing_lf=False)
        rep_b = make_report(now - timedelta(days=5), now + timedelta(days=15), "BB", trailing_lf=False)
        pasted = f"{rep_a}\n\n{rep_b}"

        parsed = split_openssl_x509_batch_reports(pasted, preserve_exact_bytes=True)
        self.assertEqual(parsed, [rep_a, rep_b])

        status, body = self.request_batch({"reports": parsed})
        self.assertEqual(status, 200)
        self.assertEqual(set(body.keys()), {"format", "report_count", "validity_counts", "batch_sha256"})
        expected_sha = hashlib.sha256(
            json.dumps([rep_a, rep_b], ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        self.assertEqual(body["batch_sha256"], expected_sha)
        self.assertEqual(body["validity_counts"], {"valid": 1, "expiring_soon": 1, "expired": 0, "not_yet_valid": 0})

    def test_duplicate_report_count_is_byte_exact(self):
        now = datetime.now(timezone.utc)
        first = make_report(now - timedelta(days=1), now + timedelta(days=45), "AB", trailing_lf=True)
        second = make_report(now - timedelta(days=2), now + timedelta(days=46), "CD", trailing_lf=True)
        first_lowercase = first.replace(":".join(["AB"] * 32), ":".join(["ab"] * 32))
        first_no_lf = first.rstrip("\n")

        batch_with_dups = [first, second, first, first]
        self.assertEqual(count_byte_identical_duplicate_reports(batch_with_dups), 2)
        summary = parse_openssl_x509_batch_summary(batch_with_dups, now=now, include_duplicate_count=True)
        self.assertEqual(summary["duplicate_report_count"], 2)
        self.assertEqual(summary["report_count"], 4)

        # Distinct byte representations of the same certificate are not counted as byte-duplicates
        distinct_bytes_batch = [first, first_lowercase, first_no_lf]
        self.assertEqual(count_byte_identical_duplicate_reports(distinct_bytes_batch), 0)
        fidelity = parse_openssl_x509_batch_fidelity_summary(distinct_bytes_batch, now=now)
        self.assertEqual(fidelity["duplicate_report_count"], 0)
        self.assertEqual(len(set(fidelity["report_sha256_list"])), 3)
        self.assertNotIn("AB:AB", json.dumps(fidelity))
        self.assertNotIn("notBefore", json.dumps(fidelity))

    def test_rejects_exotic_line_separators_nul_and_double_trailing_newlines(self):
        now = datetime.now(timezone.utc)
        valid_no_lf = make_report(now - timedelta(days=1), now + timedelta(days=45), "AA", trailing_lf=False)
        lines = valid_no_lf.split("\n")

        invalid_variants = [
            f"{lines[0]}\v{lines[1]}\n{lines[2]}",
            f"{lines[0]}\f{lines[1]}\n{lines[2]}",
            f"{lines[0]}\u2028{lines[1]}\n{lines[2]}",
            f"{lines[0]}\r{lines[1]}\n{lines[2]}",
            valid_no_lf + "\x00",
            valid_no_lf + "\n\n",
            valid_no_lf.replace("\n", "\r\n") + "\r\n\r\n",
        ]
        for bad in invalid_variants:
            with self.subTest(bad=repr(bad[:40])):
                with self.assertRaises(ValueError):
                    parse_openssl_x509_summary(bad, now=now)
                with self.assertRaises(ValueError):
                    parse_openssl_x509_batch_summary([bad], now=now)
                with self.assertRaises(ValueError):
                    split_openssl_x509_batch_reports(bad)


if __name__ == "__main__":
    unittest.main()
