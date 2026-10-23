from __future__ import annotations

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
from storage import Store


ROUTE = "/api/tool-reports/schemathesis-junit/summary"


class SchemathesisJunitSummaryApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path.home())
        self.previous_store = server.STORE
        server.STORE = Store(Path(self.temp.name) / "data" / "sniper.db")
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.SniperHandler)
        self.httpd.daemon_threads = True
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)
        server.STORE = self.previous_store
        self.temp.cleanup()

    def request(self, payload):
        body = json.dumps(payload).encode("utf-8")
        request = Request(self.base_url + ROUTE, data=body, method="POST",
                          headers={"Content-Type": "application/json"})
        with urlopen(request, timeout=5) as response:
            return json.loads(response.read())

    def assert_rejected(self, report):
        with self.assertRaises(HTTPError) as ctx:
            self.request({"report": report})
        self.assertEqual(ctx.exception.code, 400)
        return ctx.exception.read().decode("utf-8")

    def test_saved_junit_counts_cases_and_redacts_sensitive_details(self):
        report = '''<?xml version="1.0"?>
<testsuites tests="999" failures="999">
  <testsuite name="secret-suite" tests="999">
    <testcase name="GET /private/path?token=SECRET">
      <failure message="curl -H Authorization:secret">private response body</failure>
      <system-out>bearer SECRET</system-out>
    </testcase>
    <testcase name="stateful"><skipped message="private reason"/></testcase>
    <testcase name="POST /things"/>
  </testsuite>
  <testsuite name="second"><testcase name="bad"><error>stack secret</error></testcase></testsuite>
</testsuites>'''
        result = self.request({"report": report})
        self.assertEqual(result, {
            "format": "schemathesis-junit-xml",
            "suite_count": 2,
            "testcase_count": 4,
            "outcome_counts": {"passed": 1, "failed": 1, "errors": 1, "skipped": 1},
            "report_sha256": hashlib.sha256(report.encode("utf-8")).hexdigest(),
        })
        encoded = json.dumps(result)
        for secret in ("SECRET", "curl", "private", "stateful", "stack"):
            self.assertNotIn(secret, encoded)

    def test_single_suite_and_empty_suite(self):
        result = self.request({"report": '<testsuite name="schemathesis"><testcase name="GET /"/></testsuite>'})
        self.assertEqual(result["suite_count"], 1)
        self.assertEqual(result["testcase_count"], 1)
        self.assertEqual(result["outcome_counts"]["passed"], 1)
        empty = self.request({"report": '<testsuites><testsuite name="empty"/></testsuites>'})
        self.assertEqual(empty["testcase_count"], 0)

    def test_rejects_declarations_and_does_not_echo_payload(self):
        for report in (
            '<!DOCTYPE testsuite [<!ENTITY secret "SENSITIVE">]><testsuite><testcase name="&secret;"/></testsuite>',
            '<!DOCTYPE testsuite SYSTEM "file:///etc/passwd"><testsuite/>',
            '<testsuite><testcase name="SENSITIVE"></testsuite>',
            '<?xml-stylesheet href="https://example.invalid/evil"?><testsuite/>',
        ):
            self.assertNotIn("SENSITIVE", self.assert_rejected(report))
            self.assertNotIn("file:///", self.assert_rejected(report))

    def test_rejects_wrong_structure_and_ambiguous_outcome(self):
        for report in (
            '<root><testsuite/></root>',
            '<testsuites><testcase/></testsuites>',
            '<testsuite><testcase><failure/><error/></testcase></testsuite>',
            '<testsuite><testcase><failure/><failure/></testcase></testsuite>',
        ):
            self.assert_rejected(report)

    def test_enforces_report_suite_and_case_limits(self):
        self.assert_rejected("<testsuite>" + "x" * 60_000 + "</testsuite>")
        self.assert_rejected("<testsuites>" + "<testsuite/>" * 21 + "</testsuites>")
        self.assert_rejected("<testsuite>" + "<testcase/>" * 501 + "</testsuite>")

    def test_payload_shape_is_exact_and_type_checked(self):
        for payload in ({}, {"report": []}, {"report": "<testsuite/>", "target": "example.com"}):
            with self.assertRaises(HTTPError) as ctx:
                self.request(payload)
            self.assertEqual(ctx.exception.code, 400)


if __name__ == "__main__":
    unittest.main()
