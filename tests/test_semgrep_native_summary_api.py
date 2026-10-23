import hashlib
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


class SemgrepNativeJsonSummaryApiTests(unittest.TestCase):
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

    def test_semgrep_summary_mixed_severity(self):
        report = {
            "results": [
                {
                    "check_id": "rule-1",
                    "path": "app.py",
                    "start": {"line": 1, "col": 1, "offset": 0},
                    "end": {"line": 1, "col": 10, "offset": 9},
                    "extra": {
                        "message": "Found secret",
                        "metadata": {"cwe": "CWE-798"},
                        "fingerprint": "abc123",
                        "lines": "secret = 'xxx'",
                        "severity": "HIGH"
                    }
                },
                {
                    "check_id": "rule-2",
                    "path": "config.yaml",
                    "start": {"line": 5, "col": 3, "offset": 42},
                    "end": {"line": 5, "col": 15, "offset": 54},
                    "extra": {
                        "message": "Debug mode enabled",
                        "metadata": {"owasp": "A6"},
                        "fingerprint": "def456",
                        "lines": "DEBUG = True",
                        "severity": "MEDIUM"
                    }
                },
                {
                    "check_id": "rule-3",
                    "path": "main.go",
                    "start": {"line": 10, "col": 2, "offset": 98},
                    "end": {"line": 10, "col": 8, "offset": 104},
                    "extra": {
                        "message": "Unused variable",
                        "metadata": {"severity": "low"},
                        "fingerprint": "ghi789",
                        "lines": "x := 0",
                        "severity": "LOW"
                    }
                }
            ],
            "errors": [],
            "paths": {
                "scanned": ["app.py", "config.yaml", "main.go"]
            }
        }
        result = self.request_json("/api/tool-reports/semgrep-native-json/summary", {"report": report})
        self.assertEqual(result["format"], "semgrep-native-json")
        self.assertEqual(result["result_count"], 3)
        self.assertEqual(result["severity_counts"], {
            "ERROR": 0, "WARNING": 0, "EXPERIMENT": 0, "INVENTORY": 0,
            "CRITICAL": 0, "HIGH": 1, "MEDIUM": 1, "LOW": 1, "INFO": 0
        })
        self.assertIn("report_sha256", result)
        self.assertEqual(set(result.keys()), {"format", "result_count", "severity_counts", "report_sha256"})
        # Validate SHA-256 format
        sha = result["report_sha256"]
        self.assertEqual(len(sha), 64)
        self.assertTrue(all(c in '0123456789abcdef' for c in sha))
        # Validate exact SHA-256 equals raw report digest
        expected_sha = hashlib.sha256(json.dumps(report, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        self.assertEqual(sha, expected_sha)

    def test_semgrep_summary_empty_results(self):
        report = {
            "results": [],
            "errors": [],
            "paths": {
                "scanned": []
            }
        }
        result = self.request_json("/api/tool-reports/semgrep-native-json/summary", {"report": report})
        self.assertEqual(result["format"], "semgrep-native-json")
        self.assertEqual(result["result_count"], 0)
        self.assertEqual(result["severity_counts"], {
            "ERROR": 0, "WARNING": 0, "EXPERIMENT": 0, "INVENTORY": 0,
            "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0
        })
        self.assertIn("report_sha256", result)
        self.assertEqual(set(result.keys()), {"format", "result_count", "severity_counts", "report_sha256"})
        expected_sha = hashlib.sha256(json.dumps(report, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        self.assertEqual(result["report_sha256"], expected_sha)

    def test_semgrep_summary_empty_check_id_http_200(self):
        report = {
            "results": [
                {
                    "check_id": "",
                    "path": "app.py",
                    "start": {"line": 1, "col": 1, "offset": 0},
                    "end": {"line": 1, "col": 10, "offset": 9},
                    "extra": {
                        "message": "Found secret",
                        "metadata": {},
                        "fingerprint": "abc123",
                        "lines": "secret = 'xxx'",
                        "severity": "HIGH"
                    }
                }
            ],
            "errors": [],
            "paths": {"scanned": ["app.py"]}
        }
        result = self.request_json("/api/tool-reports/semgrep-native-json/summary", {"report": report})
        self.assertEqual(result["format"], "semgrep-native-json")
        self.assertEqual(result["result_count"], 1)

    def test_semgrep_summary_empty_path_http_200(self):
        report = {
            "results": [
                {
                    "check_id": "rule-1",
                    "path": "",
                    "start": {"line": 1, "col": 1, "offset": 0},
                    "end": {"line": 1, "col": 10, "offset": 9},
                    "extra": {
                        "message": "Found secret",
                        "metadata": {},
                        "fingerprint": "abc123",
                        "lines": "secret = 'xxx'",
                        "severity": "HIGH"
                    }
                }
            ],
            "errors": [],
            "paths": {"scanned": [""]}
        }
        result = self.request_json("/api/tool-reports/semgrep-native-json/summary", {"report": report})
        self.assertEqual(result["format"], "semgrep-native-json")
        self.assertEqual(result["result_count"], 1)

    def test_semgrep_summary_empty_fingerprint_http_200(self):
        report = {
            "results": [
                {
                    "check_id": "rule-1",
                    "path": "app.py",
                    "start": {"line": 1, "col": 1, "offset": 0},
                    "end": {"line": 1, "col": 10, "offset": 9},
                    "extra": {
                        "message": "Found secret",
                        "metadata": {},
                        "fingerprint": "",
                        "lines": "secret = 'xxx'",
                        "severity": "HIGH"
                    }
                }
            ],
            "errors": [],
            "paths": {"scanned": ["app.py"]}
        }
        result = self.request_json("/api/tool-reports/semgrep-native-json/summary", {"report": report})
        self.assertEqual(result["format"], "semgrep-native-json")
        self.assertEqual(result["result_count"], 1)

    def test_semgrep_summary_missing_check_id_http_400(self):
        report = {
            "results": [
                {
                    "path": "app.py",
                    "start": {"line": 1, "col": 1, "offset": 0},
                    "end": {"line": 1, "col": 10, "offset": 9},
                    "extra": {
                        "message": "Found secret",
                        "metadata": {},
                        "fingerprint": "abc123",
                        "lines": "secret = 'xxx'",
                        "severity": "HIGH"
                    }
                }
            ],
            "errors": [],
            "paths": {"scanned": ["app.py"]}
        }
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/semgrep-native-json/summary", {"report": report})
        self.assertEqual(cm.exception.code, 400)

    def test_semgrep_summary_missing_path_http_400(self):
        report = {
            "results": [
                {
                    "check_id": "rule-1",
                    "start": {"line": 1, "col": 1, "offset": 0},
                    "end": {"line": 1, "col": 10, "offset": 9},
                    "extra": {
                        "message": "Found secret",
                        "metadata": {},
                        "fingerprint": "abc123",
                        "lines": "secret = 'xxx'",
                        "severity": "HIGH"
                    }
                }
            ],
            "errors": [],
            "paths": {"scanned": ["app.py"]}
        }
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/semgrep-native-json/summary", {"report": report})
        self.assertEqual(cm.exception.code, 400)

    def test_semgrep_summary_missing_fingerprint_http_400(self):
        report = {
            "results": [
                {
                    "check_id": "rule-1",
                    "path": "app.py",
                    "start": {"line": 1, "col": 1, "offset": 0},
                    "end": {"line": 1, "col": 10, "offset": 9},
                    "extra": {
                        "message": "Found secret",
                        "metadata": {},
                        "lines": "secret = 'xxx'",
                        "severity": "HIGH"
                    }
                }
            ],
            "errors": [],
            "paths": {"scanned": ["app.py"]}
        }
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/semgrep-native-json/summary", {"report": report})
        self.assertEqual(cm.exception.code, 400)

    def test_semgrep_summary_non_string_check_id_http_400(self):
        report = {
            "results": [
                {
                    "check_id": 123,
                    "path": "app.py",
                    "start": {"line": 1, "col": 1, "offset": 0},
                    "end": {"line": 1, "col": 10, "offset": 9},
                    "extra": {
                        "message": "Found secret",
                        "metadata": {},
                        "fingerprint": "abc123",
                        "lines": "secret = 'xxx'",
                        "severity": "HIGH"
                    }
                }
            ],
            "errors": [],
            "paths": {"scanned": ["app.py"]}
        }
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/semgrep-native-json/summary", {"report": report})
        self.assertEqual(cm.exception.code, 400)

    def test_semgrep_summary_non_string_path_http_400(self):
        report = {
            "results": [
                {
                    "check_id": "rule-1",
                    "path": 123,
                    "start": {"line": 1, "col": 1, "offset": 0},
                    "end": {"line": 1, "col": 10, "offset": 9},
                    "extra": {
                        "message": "Found secret",
                        "metadata": {},
                        "fingerprint": "abc123",
                        "lines": "secret = 'xxx'",
                        "severity": "HIGH"
                    }
                }
            ],
            "errors": [],
            "paths": {"scanned": ["app.py"]}
        }
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/semgrep-native-json/summary", {"report": report})
        self.assertEqual(cm.exception.code, 400)

    def test_semgrep_summary_non_string_fingerprint_http_400(self):
        report = {
            "results": [
                {
                    "check_id": "rule-1",
                    "path": "app.py",
                    "start": {"line": 1, "col": 1, "offset": 0},
                    "end": {"line": 1, "col": 10, "offset": 9},
                    "extra": {
                        "message": "Found secret",
                        "metadata": {},
                        "fingerprint": 123,
                        "lines": "secret = 'xxx'",
                        "severity": "HIGH"
                    }
                }
            ],
            "errors": [],
            "paths": {"scanned": ["app.py"]}
        }
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/semgrep-native-json/summary", {"report": report})
        self.assertEqual(cm.exception.code, 400)

    def test_semgrep_summary_missing_results(self):
        report = {
            "errors": [],
            "paths": {"scanned": []}
        }
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/semgrep-native-json/summary", {"report": report})
        self.assertEqual(cm.exception.code, 400)

    def test_semgrep_summary_missing_errors(self):
        report = {
            "results": [],
            "paths": {"scanned": []}
        }
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/semgrep-native-json/summary", {"report": report})
        self.assertEqual(cm.exception.code, 400)

    def test_semgrep_summary_missing_paths(self):
        report = {
            "results": [],
            "errors": []
        }
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/semgrep-native-json/summary", {"report": report})
        self.assertEqual(cm.exception.code, 400)

    def test_semgrep_summary_non_object_report(self):
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/semgrep-native-json/summary", {"report": [1, 2, 3]})
        self.assertEqual(cm.exception.code, 400)

    def test_semgrep_summary_exceeds_limit(self):
        results = [{
            "check_id": f"rule-{i}",
            "path": f"file{i}.py",
            "start": {"line": 1, "col": 1, "offset": 0},
            "end": {"line": 1, "col": 10, "offset": 9},
            "extra": {
                "message": "Test",
                "metadata": {},
                "fingerprint": f"fp{i}",
                "lines": "x",
                "severity": "LOW"
            }
        } for i in range(501)]
        report = {
            "results": results,
            "errors": [],
            "paths": {"scanned": [f"file{i}.py" for i in range(501)]}
        }
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/semgrep-native-json/summary", {"report": report})
        self.assertEqual(cm.exception.code, 400)

    def test_semgrep_summary_invalid_severity(self):
        report = {
            "results": [
                {
                    "check_id": "rule-1",
                    "path": "app.py",
                    "start": {"line": 1, "col": 1, "offset": 0},
                    "end": {"line": 1, "col": 10, "offset": 9},
                    "extra": {
                        "message": "Test",
                        "metadata": {},
                        "fingerprint": "abc123",
                        "lines": "x",
                        "severity": "INVALID"
                    }
                }
            ],
            "errors": [],
            "paths": {"scanned": ["app.py"]}
        }
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/semgrep-native-json/summary", {"report": report})
        self.assertEqual(cm.exception.code, 400)

    def test_semgrep_summary_privacy_no_echo(self):
        secret_marker = "SECRET_MARKER_2026-10-09"
        report = {
            "results": [
                {
                    "check_id": secret_marker,
                    "path": "app.py",
                    "start": {"line": 1, "col": 1, "offset": 0},
                    "end": {"line": 1, "col": 10, "offset": 9},
                    "extra": {
                        "message": "Test",
                        "metadata": {},
                        "fingerprint": "abc123",
                        "lines": "x",
                        "severity": "LOW"
                    }
                }
            ],
            "errors": [],
            "paths": {"scanned": ["app.py"]}
        }
        result = self.request_json("/api/tool-reports/semgrep-native-json/summary", {"report": report})
        result_json_str = json.dumps(result)
        self.assertNotIn(secret_marker, result_json_str)
        self.assertEqual(result["result_count"], 1)

    def test_semgrep_summary_health_200(self):
        result = self.request_json("/api/health", None)
        self.assertEqual(result["status"], "ok")

    def test_semgrep_summary_paths_scanned_must_be_array_of_strings(self):
        report = {
            "results": [],
            "errors": [],
            "paths": {"scanned": ["app.py", 123]}
        }
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/semgrep-native-json/summary", {"report": report})
        self.assertEqual(cm.exception.code, 400)

    def test_semgrep_summary_paths_scanned_missing(self):
        report = {
            "results": [],
            "errors": [],
            "paths": {}
        }
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/semgrep-native-json/summary", {"report": report})
        self.assertEqual(cm.exception.code, 400)

    def test_semgrep_summary_start_line_not_integer(self):
        report = {
            "results": [
                {
                    "check_id": "rule-1",
                    "path": "app.py",
                    "start": {"line": "1", "col": 1, "offset": 0},
                    "end": {"line": 1, "col": 10, "offset": 9},
                    "extra": {
                        "message": "Test",
                        "metadata": {},
                        "fingerprint": "abc123",
                        "lines": "x",
                        "severity": "LOW"
                    }
                }
            ],
            "errors": [],
            "paths": {"scanned": ["app.py"]}
        }
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/semgrep-native-json/summary", {"report": report})
        self.assertEqual(cm.exception.code, 400)

    def test_semgrep_summary_start_col_boolean_rejected(self):
        report = {
            "results": [
                {
                    "check_id": "rule-1",
                    "path": "app.py",
                    "start": {"line": 1, "col": True, "offset": 0},
                    "end": {"line": 1, "col": 10, "offset": 9},
                    "extra": {
                        "message": "Test",
                        "metadata": {},
                        "fingerprint": "abc123",
                        "lines": "x",
                        "severity": "LOW"
                    }
                }
            ],
            "errors": [],
            "paths": {"scanned": ["app.py"]}
        }
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/semgrep-native-json/summary", {"report": report})
        self.assertEqual(cm.exception.code, 400)

    def test_semgrep_summary_metadata_accepts_any_json_value(self):
        report = {
            "results": [
                {
                    "check_id": "rule-1",
                    "path": "app.py",
                    "start": {"line": 1, "col": 1, "offset": 0},
                    "end": {"line": 1, "col": 10, "offset": 9},
                    "extra": {
                        "message": "Test",
                        "metadata": [1, 2, 3],
                        "fingerprint": "abc123",
                        "lines": "x",
                        "severity": "LOW"
                    }
                }
            ],
            "errors": [],
            "paths": {"scanned": ["app.py"]}
        }
        result = self.request_json("/api/tool-reports/semgrep-native-json/summary", {"report": report})
        self.assertEqual(result["result_count"], 1)

    def test_semgrep_summary_metadata_null_accepted(self):
        report = {
            "results": [
                {
                    "check_id": "rule-1",
                    "path": "app.py",
                    "start": {"line": 1, "col": 1, "offset": 0},
                    "end": {"line": 1, "col": 10, "offset": 9},
                    "extra": {
                        "message": "Test",
                        "metadata": None,
                        "fingerprint": "abc123",
                        "lines": "x",
                        "severity": "LOW"
                    }
                }
            ],
            "errors": [],
            "paths": {"scanned": ["app.py"]}
        }
        result = self.request_json("/api/tool-reports/semgrep-native-json/summary", {"report": report})
        self.assertEqual(result["result_count"], 1)

    def test_semgrep_summary_metadata_missing_http_400(self):
        report = {
            "results": [
                {
                    "check_id": "rule-1",
                    "path": "app.py",
                    "start": {"line": 1, "col": 1, "offset": 0},
                    "end": {"line": 1, "col": 10, "offset": 9},
                    "extra": {
                        "message": "Test",
                        "fingerprint": "abc123",
                        "lines": "x",
                        "severity": "LOW"
                    }
                }
            ],
            "errors": [],
            "paths": {"scanned": ["app.py"]}
        }
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/semgrep-native-json/summary", {"report": report})
        self.assertEqual(cm.exception.code, 400)
