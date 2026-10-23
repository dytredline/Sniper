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


class SarifSummaryApiTests(unittest.TestCase):
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

    def test_sarif_summary_accepts_valid_multitool_sarif(self):
        sarif = {
            "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "Semgrep"}},
                    "results": [
                        {"level": "error", "message": {"text": "secret marker must not appear"}},
                        {"level": "warning"},
                    ],
                },
                {
                    "tool": {"driver": {"name": "Gitleaks"}},
                    "results": [
                        {"level": "note"},
                        {"level": "none"},
                    ],
                },
            ],
        }
        result = self.request_json("/api/tool-reports/sarif/summary", {"sarif": sarif})
        self.assertEqual(result["format"], "sarif")
        self.assertEqual(result["run_count"], 2)
        self.assertEqual(result["result_count"], 4)
        self.assertIn("report_sha256", result)
        tools = {t["name"]: t for t in result["tools"]}
        self.assertIn("Semgrep", tools)
        self.assertIn("Gitleaks", tools)
        self.assertEqual(tools["Semgrep"]["result_count"], 2)
        self.assertEqual(tools["Semgrep"]["levels"], {"error": 1, "warning": 1, "note": 0, "none": 0})
        self.assertEqual(tools["Gitleaks"]["result_count"], 2)
        self.assertEqual(tools["Gitleaks"]["levels"], {"error": 0, "warning": 0, "note": 1, "none": 1})
        self.assertNotIn("message", result)
        self.assertNotIn("snippet", result)

    def test_codeql_sarif_preview_counts_results_without_exposing_content(self):
        sarif = {
            "version": "2.1.0",
            "runs": [
                {"tool": {"driver": {"name": "CodeQL command-line toolchain"}},
                 "results": [
                     {"level": "error", "message": {"text": "private CodeQL finding"},
                      "locations": [{"physicalLocation": {"artifactLocation": {"uri": "private/path.py"}}}]},
                     {"level": "warning"},
                 ]},
                {"tool": {"driver": {"name": "Semgrep"}},
                 "results": [{"level": "note"}]},
            ],
        }
        result = self.request_json("/api/tool-reports/sarif/summary", {"sarif": sarif})
        self.assertEqual(result["run_count"], 2)
        self.assertEqual(result["result_count"], 3)
        tools = {entry["name"]: entry for entry in result["tools"]}
        self.assertEqual(tools["CodeQL command-line toolchain"]["levels"],
                         {"error": 1, "warning": 1, "note": 0, "none": 0})
        self.assertEqual(tools["Semgrep"]["result_count"], 1)
        encoded = json.dumps(result)
        self.assertNotIn("private CodeQL finding", encoded)
        self.assertNotIn("private/path.py", encoded)

    def test_codeql_alias_is_not_accepted_as_a_driver(self):
        sarif = {"version": "2.1.0", "runs": [
            {"tool": {"driver": {"name": "CodeQL"}}, "results": []},
        ]}
        with self.assertRaises(HTTPError) as ctx:
            self.request_json("/api/tool-reports/sarif/summary", {"sarif": sarif})
        self.assertEqual(ctx.exception.code, 400)

    def test_osv_scanner_sarif_preview_counts_results_without_source_paths(self):
        sarif = {"version": "2.1.0", "runs": [
            {"tool": {"driver": {"name": "osv-scanner"}}, "results": [
                {"level": "warning", "message": {"text": "private advisory detail"},
                 "locations": [{"physicalLocation": {"artifactLocation": {"uri": "private/lockfile"}}}]},
                {"level": "error"},
            ]},
        ]}
        result = self.request_json("/api/tool-reports/sarif/summary", {"sarif": sarif})
        self.assertEqual(result["run_count"], 1)
        self.assertEqual(result["result_count"], 2)
        self.assertEqual(result["tools"][0]["name"], "osv-scanner")
        self.assertEqual(result["tools"][0]["levels"],
                         {"error": 1, "warning": 1, "note": 0, "none": 0})
        encoded = json.dumps(result)
        self.assertNotIn("private advisory detail", encoded)
        self.assertNotIn("private/lockfile", encoded)

    def test_osv_scanner_alias_is_not_accepted_as_a_driver(self):
        sarif = {"version": "2.1.0", "runs": [
            {"tool": {"driver": {"name": "OSV-Scanner"}}, "results": []},
        ]}
        with self.assertRaises(HTTPError) as ctx:
            self.request_json("/api/tool-reports/sarif/summary", {"sarif": sarif})
        self.assertEqual(ctx.exception.code, 400)

    def test_sarif_summary_rejects_missing_sarif(self):
        with self.assertRaises(HTTPError) as ctx:
            self.request_json("/api/tool-reports/sarif/summary", {})
        self.assertEqual(ctx.exception.code, 400)

    def test_sarif_summary_rejects_wrong_version(self):
        sarif = {
            "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
            "version": "2.0.0",
            "runs": [{"tool": {"driver": {"name": "Semgrep"}}, "results": []}],
        }
        with self.assertRaises(HTTPError) as ctx:
            self.request_json("/api/tool-reports/sarif/summary", {"sarif": sarif})
        self.assertEqual(ctx.exception.code, 400)

    def test_sarif_summary_rejects_unknown_tool(self):
        sarif = {
            "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "UnknownTool"}}, "results": []}],
        }
        with self.assertRaises(HTTPError) as ctx:
            self.request_json("/api/tool-reports/sarif/summary", {"sarif": sarif})
        self.assertEqual(ctx.exception.code, 400)

    def test_sarif_summary_rejects_malformed_run(self):
        sarif = {
            "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{"tool": "not-a-dict", "results": []}],
        }
        with self.assertRaises(HTTPError) as ctx:
            self.request_json("/api/tool-reports/sarif/summary", {"sarif": sarif})
        self.assertEqual(ctx.exception.code, 400)

    def test_sarif_summary_rejects_malformed_result(self):
        sarif = {
            "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "Semgrep"}}, "results": ["not-a-dict"]}],
        }
        with self.assertRaises(HTTPError) as ctx:
            self.request_json("/api/tool-reports/sarif/summary", {"sarif": sarif})
        self.assertEqual(ctx.exception.code, 400)

    def test_sarif_summary_rejects_invalid_level(self):
        sarif = {
            "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "Semgrep"}}, "results": [{"level": "invalid"}]}],
        }
        with self.assertRaises(HTTPError) as ctx:
            self.request_json("/api/tool-reports/sarif/summary", {"sarif": sarif})
        self.assertEqual(ctx.exception.code, 400)

    def test_health_route_returns_ok(self):
        result = self.request_json("/api/health")
        self.assertEqual(result["status"], "ok")

    def test_report_hash_changes_with_secret_message(self):
        sarif1 = {
            "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "Semgrep"}},
                    "results": [
                        {"level": "error", "message": {"text": "secret123"}},
                    ],
                },
            ],
        }
        sarif2 = {
            "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "Semgrep"}},
                    "results": [
                        {"level": "error", "message": {"text": "secret456"}},
                    ],
                },
            ],
        }
        result1 = self.request_json("/api/tool-reports/sarif/summary", {"sarif": sarif1})
        result2 = self.request_json("/api/tool-reports/sarif/summary", {"sarif": sarif2})
        self.assertNotEqual(result1["report_sha256"], result2["report_sha256"])
        self.assertNotIn("secret", result1)
        self.assertNotIn("secret", result2)
