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


class TrivyNativeSummaryApiTests(unittest.TestCase):
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

    def test_trivy_summary_mixed_classes_and_findings(self):
        report = {
            "SchemaVersion": 2,
            "Results": [
                {
                    "Target": "alpine:latest",
                    "Class": "os-pkgs",
                    "Vulnerabilities": [
                        {"Severity": "HIGH"},
                        {"Severity": "MEDIUM"}
                    ],
                    "Misconfigurations": [
                        {"Severity": "HIGH"},
                        {"Severity": "MEDIUM"}
                    ],
                    "Secrets": [
                        {}
                    ],
                    "Licenses": [
                        {}
                    ]
                },
                {
                    "Target": "node_modules",
                    "Class": "lang-pkgs",
                    "Vulnerabilities": [
                        {"Severity": "CRITICAL"},
                        {"Severity": "UNKNOWN"}
                    ],
                    "Misconfigurations": [
                        {"Severity": "critical"}
                    ]
                },
                {
                    "Target": "config.yaml",
                    "Class": "config",
                    "Misconfigurations": [
                        {"Severity": "low"}
                    ]
                },
                {
                    "Target": "secrets.txt",
                    "Class": "secret",
                    "Secrets": [
                        {}
                    ]
                },
                {
                    "Target": "package.json",
                    "Class": "license",
                    "Licenses": [
                        {}
                    ]
                },
                {
                    "Target": "unknown",
                    "Class": "future-class",
                    "Vulnerabilities": [
                        {"Severity": "low"}
                    ]
                }
            ]
        }
        result = self.request_json("/api/tool-reports/trivy-native-json/summary", {"report": report})
        self.assertEqual(result["format"], "trivy-native-json")
        self.assertEqual(result["schema_version"], 2)
        self.assertEqual(result["result_count"], 6)
        self.assertEqual(result["class_counts"], {
            "os-pkgs": 1,
            "lang-pkgs": 1,
            "config": 1,
            "secret": 1,
            "license": 1,
            "license-file": 0,
            "crypto": 0,
            "custom": 0,
            "unknown": 1
        })
        self.assertEqual(result["vuln_counts"], {
            "critical": 1,
            "high": 1,
            "medium": 1,
            "low": 1,
            "unknown": 1
        })
        self.assertEqual(result["misconfig_sev_counts"], {
            "critical": 1,
            "high": 1,
            "medium": 1,
            "low": 1,
            "unknown": 0
        })
        self.assertEqual(result["finding_counts"], {
            "vulnerabilities": 5,
            "misconfigurations": 4,
            "secrets": 2,
            "licenses": 2
        })
        self.assertEqual(set(result.keys()), {
            "format", "schema_version", "result_count",
            "class_counts", "vuln_counts", "misconfig_sev_counts",
            "finding_counts", "report_sha256"
        })

    def test_trivy_summary_clean_report_no_results(self):
        report = {
            "SchemaVersion": 2
        }
        result = self.request_json("/api/tool-reports/trivy-native-json/summary", {"report": report})
        self.assertEqual(result["format"], "trivy-native-json")
        self.assertEqual(result["schema_version"], 2)
        self.assertEqual(result["result_count"], 0)
        self.assertEqual(result["class_counts"], {
            "os-pkgs": 0,
            "lang-pkgs": 0,
            "config": 0,
            "secret": 0,
            "license": 0,
            "license-file": 0,
            "crypto": 0,
            "custom": 0,
            "unknown": 0
        })
        self.assertEqual(result["vuln_counts"], {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "unknown": 0
        })
        self.assertEqual(result["misconfig_sev_counts"], {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "unknown": 0
        })
        self.assertEqual(result["finding_counts"], {
            "vulnerabilities": 0,
            "misconfigurations": 0,
            "secrets": 0,
            "licenses": 0
        })
        self.assertEqual(set(result.keys()), {
            "format", "schema_version", "result_count",
            "class_counts", "vuln_counts", "misconfig_sev_counts",
            "finding_counts", "report_sha256"
        })

    def test_trivy_summary_privacy_no_echo(self):
        secret_marker = "SECRET_MARKER_2026-10-09"
        report = {
            "SchemaVersion": 2,
            "Results": [
                {
                    "Target": secret_marker,
                    "Class": "secret",
                    "Secrets": [
                        {"Data": secret_marker}
                    ],
                    "Misconfigurations": [
                        {"Severity": "critical"}
                    ]
                }
            ]
        }
        result = self.request_json("/api/tool-reports/trivy-native-json/summary", {"report": report})
        result_json_str = json.dumps(result)
        self.assertNotIn(secret_marker, result_json_str)
        self.assertEqual(result["result_count"], 1)
        self.assertEqual(result["class_counts"]["secret"], 1)
        self.assertEqual(result["finding_counts"]["secrets"], 1)
        self.assertEqual(result["misconfig_sev_counts"]["critical"], 1)

    def test_trivy_summary_malformed_missing_report(self):
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/trivy-native-json/summary", {"notreport": {}})
        self.assertEqual(cm.exception.code, 400)

    def test_trivy_summary_malformed_report_not_object(self):
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/trivy-native-json/summary", {"report": []})
        self.assertEqual(cm.exception.code, 400)

    def test_trivy_summary_malformed_schema_version_not_int(self):
        report = {"SchemaVersion": "2"}
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/trivy-native-json/summary", {"report": report})
        self.assertEqual(cm.exception.code, 400)

    def test_trivy_summary_malformed_schema_version_wrong_int(self):
        report = {"SchemaVersion": 1}
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/trivy-native-json/summary", {"report": report})
        self.assertEqual(cm.exception.code, 400)

    def test_trivy_summary_malformed_results_not_array(self):
        report = {"SchemaVersion": 2, "Results": {}}
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/trivy-native-json/summary", {"report": report})
        self.assertEqual(cm.exception.code, 400)

    def test_trivy_summary_malformed_results_too_many(self):
        report = {
            "SchemaVersion": 2,
            "Results": [{} for _ in range(501)]
        }
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/trivy-native-json/summary", {"report": report})
        self.assertEqual(cm.exception.code, 400)

    def test_trivy_summary_malformed_result_not_object(self):
        report = {
            "SchemaVersion": 2,
            "Results": ["not object"]
        }
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/trivy-native-json/summary", {"report": report})
        self.assertEqual(cm.exception.code, 400)

    def test_trivy_summary_malformed_class_not_string(self):
        report = {
            "SchemaVersion": 2,
            "Results": [{"Class": 123}]
        }
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/trivy-native-json/summary", {"report": report})
        self.assertEqual(cm.exception.code, 400)

    def test_trivy_summary_malformed_vulnerabilities_not_array(self):
        report = {
            "SchemaVersion": 2,
            "Results": [{"Vulnerabilities": "not array"}]
        }
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/trivy-native-json/summary", {"report": report})
        self.assertEqual(cm.exception.code, 400)

    def test_trivy_summary_malformed_vulnerability_not_object(self):
        report = {
            "SchemaVersion": 2,
            "Results": [{"Vulnerabilities": ["not object"]}]
        }
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/trivy-native-json/summary", {"report": report})
        self.assertEqual(cm.exception.code, 400)

    def test_trivy_summary_malformed_severity_not_string(self):
        report = {
            "SchemaVersion": 2,
            "Results": [{"Vulnerabilities": [{"Severity": 123}]}]
        }
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/trivy-native-json/summary", {"report": report})
        self.assertEqual(cm.exception.code, 400)

    def test_trivy_summary_malformed_vulnerabilities_too_many(self):
        report = {
            "SchemaVersion": 2,
            "Results": [{"Vulnerabilities": [{} for _ in range(501)]}]
        }
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/trivy-native-json/summary", {"report": report})
        self.assertEqual(cm.exception.code, 400)

    def test_trivy_summary_malformed_misconfigurations_not_array(self):
        report = {
            "SchemaVersion": 2,
            "Results": [{"Misconfigurations": "not array"}]
        }
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/trivy-native-json/summary", {"report": report})
        self.assertEqual(cm.exception.code, 400)

    def test_trivy_summary_malformed_misconfig_entry_not_object(self):
        report = {
            "SchemaVersion": 2,
            "Results": [{"Misconfigurations": ["not object"]}]
        }
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/trivy-native-json/summary", {"report": report})
        self.assertEqual(cm.exception.code, 400)

    def test_trivy_summary_malformed_misconfig_severity_not_string(self):
        report = {
            "SchemaVersion": 2,
            "Results": [{"Misconfigurations": [{"Severity": 123}]}]
        }
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/trivy-native-json/summary", {"report": report})
        self.assertEqual(cm.exception.code, 400)

    def test_trivy_summary_misconfig_severity_missing_counts_unknown(self):
        report = {
            "SchemaVersion": 2,
            "Results": [
                {
                    "Class": "config",
                    "Misconfigurations": [
                        {},
                        {"Severity": "medium"},
                        {"Severity": "HIGH"},
                        {"Severity": "unknown"},
                        {"Severity": "UNKNOWN"},
                        {"Severity": "CRITICAL"},
                        {"Severity": "low"}
                    ]
                }
            ]
        }
        result = self.request_json("/api/tool-reports/trivy-native-json/summary", {"report": report})
        self.assertEqual(result["misconfig_sev_counts"], {
            "critical": 1,
            "high": 1,
            "medium": 1,
            "low": 1,
            "unknown": 3  # missing + "unknown" string
        })

    def test_trivy_summary_misconfig_severity_unrecognized_counts_unknown(self):
        report = {
            "SchemaVersion": 2,
            "Results": [
                {
                    "Class": "config",
                    "Misconfigurations": [
                        {"Severity": "Critical"},
                        {"Severity": "HIGHEST"},
                        {"Severity": "INFO"},
                        {"Severity": ""}
                    ]
                }
            ]
        }
        result = self.request_json("/api/tool-reports/trivy-native-json/summary", {"report": report})
        self.assertEqual(result["misconfig_sev_counts"], {
            "critical": 1,
            "high": 0,
            "medium": 0,
            "low": 0,
            "unknown": 3
        })

    def test_trivy_summary_secrets_not_array(self):
        report = {
            "SchemaVersion": 2,
            "Results": [{"Secrets": "not array"}]
        }
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/trivy-native-json/summary", {"report": report})
        self.assertEqual(cm.exception.code, 400)

    def test_trivy_summary_licenses_not_array(self):
        report = {
            "SchemaVersion": 2,
            "Results": [{"Licenses": "not array"}]
        }
        with self.assertRaises(HTTPError) as cm:
            self.request_json("/api/tool-reports/trivy-native-json/summary", {"report": report})
        self.assertEqual(cm.exception.code, 400)

    def test_trivy_summary_health_200(self):
        result = self.request_json("/api/health", None)
        self.assertEqual(result["status"], "ok")
