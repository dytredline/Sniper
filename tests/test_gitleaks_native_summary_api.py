import json
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
import tempfile
import threading
from urllib.request import Request, urlopen
from urllib.error import HTTPError

import server
from storage import Store


class GitleaksNativeSummaryApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path.home())
        self.base = Path(self.temp.name)
        self.previous_store = server.STORE
        server.STORE = Store(self.base / "data" / "sniper.db")
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

    def request_json(self, path, payload=None):
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        request = Request(
            self.base_url + path,
            data=body,
            method="GET" if payload is None else "POST",
            headers={"Content-Type": "application/json"} if body else {},
        )
        try:
            with urlopen(request, timeout=5) as response:
                return json.loads(response.read())
        except HTTPError as e:
            raise e

    def test_gitleaks_summary_two_findings(self):
        report = [
            {"RuleID": "test-rule-1", "File": "auth.py", "Match": "password = 'secret'", "Secret": "secret"},
            {"RuleID": "test-rule-2", "File": "config.yaml", "Match": "api_key: abc123", "Secret": "abc123"}
        ]
        result = self.request_json("/api/tool-reports/gitleaks/summary", {"report": report})
        self.assertEqual(result["format"], "gitleaks-native-json")
        self.assertEqual(result["total_findings"], 2)
        self.assertEqual(result["rules_triggered"], 2)
        self.assertEqual(result["files_affected"], 2)
        self.assertEqual(set(result.keys()), {"format", "total_findings", "rules_triggered", "files_affected"})

    def test_gitleaks_summary_empty_array(self):
        report = []
        result = self.request_json("/api/tool-reports/gitleaks/summary", {"report": report})
        self.assertEqual(result["format"], "gitleaks-native-json")
        self.assertEqual(result["total_findings"], 0)
        self.assertEqual(result["rules_triggered"], 0)
        self.assertEqual(result["files_affected"], 0)
        self.assertEqual(set(result.keys()), {"format", "total_findings", "rules_triggered", "files_affected"})

    def test_gitleaks_summary_duplicate_rule_and_file(self):
        report = [
            {"RuleID": "same-rule", "File": "same-file.py", "Match": "match1", "Secret": "secret1"},
            {"RuleID": "same-rule", "File": "same-file.py", "Match": "match2", "Secret": "secret2"}
        ]
        result = self.request_json("/api/tool-reports/gitleaks/summary", {"report": report})
        self.assertEqual(result["total_findings"], 2)
        self.assertEqual(result["rules_triggered"], 1)
        self.assertEqual(result["files_affected"], 1)
        self.assertEqual(set(result.keys()), {"format", "total_findings", "rules_triggered", "files_affected"})

    def test_gitleaks_summary_blank_ruleid_and_file_excluded(self):
        report = [
            {"RuleID": "", "File": "", "Match": "match1", "Secret": "secret1"},
            {"RuleID": "valid-rule", "File": "valid-file.py", "Match": "match2", "Secret": "secret2"}
        ]
        result = self.request_json("/api/tool-reports/gitleaks/summary", {"report": report})
        self.assertEqual(result["total_findings"], 2)
        self.assertEqual(result["rules_triggered"], 1)
        self.assertEqual(result["files_affected"], 1)
        self.assertEqual(set(result.keys()), {"format", "total_findings", "rules_triggered", "files_affected"})

    def test_gitleaks_summary_wrong_type_top_level(self):
        report = {"not": "array"}
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/gitleaks/summary", {"report": report})
        self.assertEqual(cm.exception.code, 400)

    def test_gitleaks_summary_missing_required_field(self):
        report = [{"RuleID": "test", "File": "test.py", "Match": "match"}]  # missing "Secret"
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/gitleaks/summary", {"report": report})
        self.assertEqual(cm.exception.code, 400)

    def test_gitleaks_summary_wrong_type_required_field(self):
        report = [{"RuleID": "test", "File": "test.py", "Match": "match", "Secret": 123}]  # Secret not string
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/gitleaks/summary", {"report": report})
        self.assertEqual(cm.exception.code, 400)

    def test_gitleaks_summary_exceeds_max_findings(self):
        report = [{"RuleID": "r", "File": "f", "Match": "m", "Secret": "s"} for _ in range(501)]
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/gitleaks/summary", {"report": report})
        self.assertEqual(cm.exception.code, 400)

    def test_gitleaks_summary_secret_marker_absent(self):
        secret_marker = "SECRET_MARKER_2026-10-09"
        report = [{"RuleID": secret_marker, "File": secret_marker, "Match": secret_marker, "Secret": secret_marker}]
        result = self.request_json("/api/tool-reports/gitleaks/summary", {"report": report})
        result_json_str = json.dumps(result)
        self.assertNotIn(secret_marker, result_json_str)
        self.assertEqual(result["total_findings"], 1)
        self.assertEqual(result["rules_triggered"], 1)
        self.assertEqual(result["files_affected"], 1)
        self.assertEqual(set(result.keys()), {"format", "total_findings", "rules_triggered", "files_affected"})

    def test_gitleaks_summary_health_200(self):
        result = self.request_json("/api/health", None)
        self.assertEqual(result["status"], "ok")
