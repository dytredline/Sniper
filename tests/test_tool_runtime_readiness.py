from __future__ import annotations

import hashlib
import json
import os
import socket
import tempfile
import threading
import unittest
from tests.pin_helpers import pin_env
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock
from urllib.request import urlopen

import server
from storage import Store
from tool_runtime_readiness import runtime_readiness_payload


def profile(payload, tool_id, route=None):
    tool = next(tool for tool in payload["tools"] if tool["id"] == tool_id)
    return next(item for item in tool["profiles"] if item["route"] == route)


class RuntimeReadinessTests(unittest.TestCase):
    def test_readiness_is_read_only_and_distinguishes_workflow_modes(self):
        with mock.patch.dict(os.environ, {"SNIPER_SEMGREP_BINARY": "", "SNIPER_SEMGREP_RULES": "",
                                          "SNIPER_OPENGREP_BINARY": "/nonexistent/opengrep"}), \
             mock.patch("subprocess.Popen", side_effect=AssertionError("scanner started")):
            payload = runtime_readiness_payload()
        self.assertEqual(len(payload["tools"]), 24)
        self.assertEqual(profile(payload, "semgrep", "/api/tool-runs/semgrep")["runtime"], "unavailable")
        self.assertEqual(profile(payload, "burp-suite", "/api/tool-reports/burp-sitemap/summary")["action"], "report_only")
        self.assertEqual(profile(payload, "codeql")["action"], "external_only")
        self.assertEqual(profile(payload, "codeql", "/api/tool-reports/sarif/summary")["action"], "report_only")
        self.assertEqual(profile(payload, "osv-scanner")["action"], "external_only")
        self.assertEqual(profile(payload, "osv-scanner", "/api/tool-reports/sarif/summary")["action"], "report_only")
        self.assertEqual(profile(payload, "schemathesis", "/api/tool-reports/schemathesis-junit/summary")["action"], "report_only")
        self.assertEqual(profile(payload, "expert-review")["action"], "manual")
        self.assertEqual(profile(payload, "sniper-baseline", "/api/scans")["action"], "native")
        self.assertEqual(profile(payload, "sniper-baseline", "/api/scans")["execution_service"], "sniper_serving")
        self.assertNotIn("/home/", json.dumps(payload))

    def test_schemathesis_general_loopback_configuration_is_distinct_from_fixture(self):
        route = "/api/tool-runs/schemathesis-loopback"
        with mock.patch.dict(os.environ, {"SNIPER_SCHEMATHESIS_ALLOWED_PORTS": ""}):
            unavailable = profile(runtime_readiness_payload(), "schemathesis", route)
        self.assertEqual(unavailable["runtime"], "unavailable")
        self.assertEqual(unavailable["reason_code"], "approved_ports_unconfigured")
        self.assertEqual(unavailable["action"], "local_input_required")
        with mock.patch.dict(os.environ, {"SNIPER_SCHEMATHESIS_ALLOWED_PORTS": "49123"}), \
             mock.patch("schemathesis_loopback_active._docker_ready"):
            ready = profile(runtime_readiness_payload(), "schemathesis", route)
        self.assertEqual(ready["runtime"], "precheck_passed")
        with mock.patch.dict(os.environ, {"SNIPER_SCHEMATHESIS_ALLOWED_PORTS": "49123,49123"}), \
             mock.patch("schemathesis_loopback_active._docker_ready"):
            malformed = profile(runtime_readiness_payload(), "schemathesis", route)
        self.assertEqual(malformed["runtime"], "unavailable")
        self.assertNotEqual(route, profile(runtime_readiness_payload(), "schemathesis", "/api/tool-runs/schemathesis-local")["route"])

    def test_semgrep_rules_and_binary_both_required_and_symlinks_rejected(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as temp:
            root = Path(temp)
            binary = root / "semgrep"
            binary.write_text("#!/bin/sh\nexit 0\n")
            binary.chmod(0o755)
            rules = root / "rules.yml"
            rules.write_text("rules: []\n")
            env = {"SNIPER_SEMGREP_BINARY": str(binary), "SNIPER_SEMGREP_RULES": str(rules), **pin_env("semgrep", binary)}
            with mock.patch.dict(os.environ, env):
                self.assertEqual(profile(runtime_readiness_payload(), "semgrep", "/api/tool-runs/semgrep")["runtime"], "precheck_passed")
                rules.unlink()
                rules.symlink_to(binary)
                self.assertEqual(profile(runtime_readiness_payload(), "semgrep", "/api/tool-runs/semgrep")["runtime"], "unavailable")

    def test_requested_tool_workflows_keep_scan_and_report_actions_distinct(self):
        with mock.patch("subprocess.Popen", side_effect=AssertionError("scanner started")):
            payload = runtime_readiness_payload()
        self.assertEqual(profile(payload, "nuclei", "/api/nuclei/http-scans")["action"], "authorization_required")
        self.assertEqual(profile(payload, "nuclei", "/api/tool-runs/nuclei-loopback")["action"], "local_input_required")
        self.assertEqual(profile(payload, "gitleaks", "/api/tool-runs/gitleaks")["action"], "local_input_required")
        self.assertEqual(profile(payload, "trufflehog", "/api/tool-runs/trufflehog-git-history")["action"], "local_input_required")
        self.assertEqual(profile(payload, "npm-audit", "/api/tool-runs/npm-audit-local")["action"], "local_input_required")
        for tool_id, route in (
            ("dependabot", "/api/tool-reports/dependabot/summary"),
            ("ssllabs", "/api/tool-reports/ssllabs-host/summary"),
            ("openssl", "/api/tool-reports/openssl-x509/summary"),
        ):
            item = profile(payload, tool_id, route)
            self.assertEqual(item["action"], "report_only")
            self.assertEqual(item["runtime"], "not_applicable")
        self.assertNotIn("/home/", json.dumps(payload))

    def test_local_secret_tools_and_npm_require_real_configured_runtime(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as temp:
            root = Path(temp)
            binary = root / "tool"
            binary.write_text("#!/bin/sh\nexit 0\n")
            binary.chmod(0o755)
            npm_cli = root / "npm-cli.js"
            npm_cli.write_text("module.exports = {}\n")
            env = {
                "SNIPER_GITLEAKS_BINARY": str(binary),
                "SNIPER_TRUFFLEHOG_BINARY": str(binary),
                **pin_env("gitleaks", binary), **pin_env("trufflehog", binary),
                "SNIPER_NODE_BINARY": str(binary),
                "SNIPER_NODE_SHA256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                "SNIPER_NPM_CLI": str(npm_cli),
                "SNIPER_NPM_CLI_SHA256": hashlib.sha256(npm_cli.read_bytes()).hexdigest(),
            }
            with mock.patch.dict(os.environ, env):
                payload = runtime_readiness_payload()
                for tool_id, route in (
                    ("gitleaks", "/api/tool-runs/gitleaks"),
                    ("trufflehog", "/api/tool-runs/trufflehog-filesystem"),
                    ("npm-audit", "/api/tool-runs/npm-audit-local"),
                ):
                    self.assertEqual(profile(payload, tool_id, route)["runtime"], "precheck_passed")
                npm_cli.write_text("tampered\n")
                self.assertEqual(profile(runtime_readiness_payload(), "npm-audit", "/api/tool-runs/npm-audit-local")["runtime"], "unavailable")
                binary.unlink()
                binary.symlink_to(npm_cli)
                self.assertEqual(profile(runtime_readiness_payload(), "gitleaks", "/api/tool-runs/gitleaks")["runtime"], "unavailable")

    def test_trivy_vulnerability_database_is_checked_per_route(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as temp:
            root = Path(temp)
            binary = root / "trivy"
            binary.write_text("#!/bin/sh\nexit 0\n")
            binary.chmod(0o755)
            db_dir = root / "cache" / "db"
            db_dir.mkdir(parents=True)
            (db_dir / "metadata.json").write_text("{}")
            db = db_dir / "trivy.db"
            db.write_bytes(b"pinned fixture")
            env = {"SNIPER_TRIVY_BINARY": str(binary),
                   "SNIPER_TRIVY_BINARY_SHA256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                   "SNIPER_TRIVY_VULN_CACHE_DIR": str(root / "cache"),
                   "SNIPER_TRIVY_VULN_DB_SHA256": hashlib.sha256(db.read_bytes()).hexdigest()}
            with mock.patch.dict(os.environ, env):
                ready = runtime_readiness_payload()
                self.assertEqual(profile(ready, "trivy", "/api/tool-runs/trivy-vulnerability")["runtime"], "precheck_passed")
                self.assertEqual(profile(ready, "trivy", "/api/tool-runs/trivy-secret")["runtime"], "precheck_passed")
                self.assertEqual(profile(ready, "trivy", "/api/tool-runs/trivy-dockerfile-config")["runtime"], "precheck_passed")
                db.write_bytes(b"tampered")
                changed = runtime_readiness_payload()
                self.assertEqual(profile(changed, "trivy", "/api/tool-runs/trivy-vulnerability")["reason_code"], "pinned_database_unavailable")
                self.assertEqual(profile(changed, "trivy", "/api/tool-runs/trivy-secret")["runtime"], "precheck_passed")

    def test_all_active_trivy_routes_reject_a_binary_digest_mismatch(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as temp:
            root = Path(temp)
            binary = root / "trivy"
            binary.write_text("#!/bin/sh\nexit 0\n")
            binary.chmod(0o755)
            db_dir = root / "cache" / "db"
            db_dir.mkdir(parents=True)
            (db_dir / "metadata.json").write_text("{}")
            db = db_dir / "trivy.db"
            db.write_bytes(b"pinned fixture")
            env = {
                "SNIPER_TRIVY_BINARY": str(binary),
                "SNIPER_TRIVY_BINARY_SHA256": "0" * 64,
                "SNIPER_TRIVY_VULN_CACHE_DIR": str(root / "cache"),
                "SNIPER_TRIVY_VULN_DB_SHA256": hashlib.sha256(db.read_bytes()).hexdigest(),
            }
            routes = (
                "/api/tool-runs/trivy-secret",
                "/api/tool-runs/trivy-vulnerability",
                "/api/tool-runs/trivy-npm-vulnerability",
                "/api/tool-runs/trivy-go-mod-vulnerability",
                "/api/tool-runs/trivy-image-archive-vulnerability",
            )
            with mock.patch.dict(os.environ, env):
                payload = runtime_readiness_payload()
            for route in routes:
                item = profile(payload, "trivy", route)
                self.assertEqual(item["runtime"], "unavailable", route)
                self.assertEqual(item["reason_code"], "binary_digest_mismatch", route)

    def test_zap_requires_user_bus_for_on_demand_service(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as temp:
            root = Path(temp)
            with mock.patch.dict(os.environ, {"SNIPER_DATA_DIR": str(root), "XDG_RUNTIME_DIR": str(root)}), \
                 mock.patch("zap_passive_active._trusted_runtime", return_value=("/usr/bin/systemd-run", root)):
                missing = profile(runtime_readiness_payload(), "owasp-zap", "/api/tool-runs/zap-self-passive")
                self.assertEqual(missing["runtime"], "unavailable")
                with socket.socket(socket.AF_UNIX) as bus:
                    bus.bind(str(root / "bus"))
                    present = profile(runtime_readiness_payload(), "owasp-zap", "/api/tool-runs/zap-self-passive")
                    self.assertEqual(present["runtime"], "precheck_passed")
                    self.assertEqual(present["execution_service"], "on_demand")

    def test_http_endpoint_is_read_only_and_returns_non_sensitive_states(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as temp:
            previous_store = server.STORE
            server.STORE = Store(Path(temp) / "sniper.db")
            httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.SniperHandler)
            httpd.daemon_threads = True
            thread = threading.Thread(target=httpd.serve_forever, daemon=True)
            thread.start()
            try:
                url = f"http://127.0.0.1:{httpd.server_address[1]}/api/tooling/readiness"
                with mock.patch("subprocess.Popen", side_effect=AssertionError("scanner started")):
                    with urlopen(url, timeout=10) as response:
                        self.assertEqual(response.status, 200)
                        payload = json.load(response)
                self.assertEqual(len(payload["tools"]), 24)
                self.assertNotIn("SNIPER_TRIVY_BINARY", json.dumps(payload))
            finally:
                httpd.shutdown()
                httpd.server_close()
                thread.join(timeout=2)
                server.STORE = previous_store

    def test_trivy_vulnerability_db_metadata_freshness_is_reported_safely(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as temp:
            root = Path(temp)
            binary = root / "trivy"
            binary.write_text("#!/bin/sh\nexit 0\n")
            binary.chmod(0o755)
            db_dir = root / "cache" / "db"
            db_dir.mkdir(parents=True)
            (db_dir / "metadata.json").write_text(json.dumps({
                "Version": 2,
                "UpdatedAt": "2026-10-12T09:47:21.509023105Z",
                "NextUpdate": "2026-10-13T09:47:21.509022788Z",
                "DownloadedAt": "2026-10-12T12:20:41.534413767Z",
            }))
            db = db_dir / "trivy.db"
            db.write_bytes(b"pinned fixture")
            env = {
                "SNIPER_TRIVY_BINARY": str(binary),
                "SNIPER_TRIVY_BINARY_SHA256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                "SNIPER_TRIVY_VULN_CACHE_DIR": str(root / "cache"),
                "SNIPER_TRIVY_VULN_DB_SHA256": hashlib.sha256(db.read_bytes()).hexdigest(),
            }
            with mock.patch.dict(os.environ, env):
                ready = runtime_readiness_payload()
                vuln_prof = profile(ready, "trivy", "/api/tool-runs/trivy-vulnerability")
                self.assertEqual(vuln_prof["runtime"], "precheck_passed")
                self.assertEqual(vuln_prof["db_metadata"], {
                    "schema_version": 2,
                    "updated_at": "2026-10-12T09:47:21.509023105Z",
                    "next_update": "2026-10-13T09:47:21.509022788Z",
                    "downloaded_at": "2026-10-12T12:20:41.534413767Z",
                })
                (db_dir / "metadata.json").write_text(json.dumps({
                    "Version": 2,
                    "UpdatedAt": "/home/community-user/path",
                    "NextUpdate": "2026-10-13T09:47:21Z",
                }))
                sanitized = runtime_readiness_payload()
                self.assertNotIn("db_metadata", profile(sanitized, "trivy", "/api/tool-runs/trivy-vulnerability"))
                self.assertNotIn("/home/", json.dumps(sanitized))


if __name__ == "__main__":
    unittest.main()
