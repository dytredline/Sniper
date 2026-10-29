import os
import sys
import tempfile
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from methodology import CATEGORIES, TEST_CATALOG  # noqa: E402
from tool_catalog import CATEGORY_TOOLING, TOOLS, tooling_payload  # noqa: E402


class ToolCatalogTests(unittest.TestCase):
    def test_every_category_and_control_has_tool_recommendations(self):
        category_slugs = {slug for slug, _title, _reference in CATEGORIES}
        self.assertEqual(set(CATEGORY_TOOLING), category_slugs)
        tool_ids = {tool["id"] for tool in TOOLS}
        payload = tooling_payload()
        self.assertEqual(payload["summary"]["control_count"], len(TEST_CATALOG))
        self.assertEqual(len(payload["controls"]), len(TEST_CATALOG))
        for control in payload["controls"]:
            self.assertTrue(control["tool_ids"])
            self.assertTrue(set(control["tool_ids"]).issubset(tool_ids))

    def test_tool_workflows_match_source_routes_and_do_not_overstate_execution(self):
        payload = tooling_payload()
        self.assertEqual(payload["summary"]["native_execution_count"], 3)
        self.assertEqual(payload["summary"]["integrated_workflow_tool_count"], 24)
        self.assertIn("düşük etkili", payload["policy"]["native"])
        self.assertIn("ikili", payload["policy"]["external"])
        routes_source = (Path(__file__).resolve().parents[1] / "server.py").read_text()
        for tool in payload["tools"]:
            self.assertTrue(tool["workflows"], tool["id"])
            self.assertEqual(tool["execution"], " · ".join(item["label"] for item in tool["workflows"]))
            for workflow in tool["workflows"]:
                self.assertIn(workflow["mode"], {"built_in", "local", "authorized", "report_import", "external", "manual"})
                for route in workflow["routes"]:
                    self.assertIn(f'"{route}"', routes_source, (tool["id"], route))
                if workflow["mode"] in {"external", "manual"}:
                    self.assertFalse(workflow["routes"], tool["id"])
                else:
                    self.assertTrue(workflow["routes"], tool["id"])
        by_id = {tool["id"]: tool for tool in payload["tools"]}
        self.assertEqual({workflow["mode"] for workflow in by_id["burp-suite"]["workflows"]}, {"report_import"})
        self.assertEqual({workflow["mode"] for workflow in by_id["codeql"]["workflows"]}, {"report_import", "external"})
        self.assertEqual({workflow["mode"] for workflow in by_id["osv-scanner"]["workflows"]}, {"report_import", "external", "local"})
        self.assertEqual({workflow["mode"] for workflow in by_id["schemathesis"]["workflows"]}, {"report_import", "external", "local"})
        schemathesis_routes = [route for workflow in by_id["schemathesis"]["workflows"]
                              for route in workflow["routes"]]
        self.assertIn("/api/tool-runs/schemathesis-loopback", schemathesis_routes)
        self.assertIn("/api/tool-runs/schemathesis-local", schemathesis_routes)
        self.assertEqual({workflow["mode"] for workflow in by_id["browser-tests"]["workflows"]}, {"report_import", "external"})
        self.assertEqual({workflow["mode"] for workflow in by_id["k6"]["workflows"]}, {"report_import", "external"})
        self.assertEqual({workflow["mode"] for workflow in by_id["siem-review"]["workflows"]}, {"report_import", "external"})
        self.assertEqual({workflow["mode"] for workflow in by_id["trivy"]["workflows"]}, {"local", "report_import"})
        self.assertEqual({workflow["mode"] for workflow in by_id["syft-grype"]["workflows"]}, {"local"})
        self.assertEqual({workflow["mode"] for workflow in by_id["nmap"]["workflows"]}, {"authorized", "report_import"})
        self.assertEqual({workflow["mode"] for workflow in by_id["nuclei"]["workflows"]}, {"local", "authorized", "report_import"})
        self.assertEqual({workflow["mode"] for workflow in by_id["gitleaks"]["workflows"]}, {"local", "report_import"})
        self.assertEqual({workflow["mode"] for workflow in by_id["trufflehog"]["workflows"]}, {"local", "report_import"})
        self.assertEqual({workflow["mode"] for workflow in by_id["npm-audit"]["workflows"]}, {"local", "report_import"})
        for report_only in ("dependabot", "ssllabs"):
            self.assertEqual({workflow["mode"] for workflow in by_id[report_only]["workflows"]}, {"report_import"})
        self.assertEqual({workflow["mode"] for workflow in by_id["openssl"]["workflows"]}, {"local", "report_import"})

    def test_binary_presence_statuses(self):
        # Build an isolated PATH with only a temporary directory
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            original_path = os.environ.get("PATH", "")
            os.environ["PATH"] = str(tmp_path)
            try:
                # Create fake executables for nmap and trivy
                nmap_bin = tmp_path / "nmap"
                trivy_bin = tmp_path / "trivy"
                for p in (nmap_bin, trivy_bin):
                    p.write_text("#!/bin/sh\nexit 0\n")
                    p.chmod(0o755)
                # semgrep is intentionally missing
                payload = tooling_payload()
                tool_map = {t["id"]: t for t in payload["tools"]}
                self.assertEqual(tool_map["nmap"]["binary_presence"], "detected")
                self.assertEqual(tool_map["semgrep"]["binary_presence"], "not_found")
                self.assertEqual(tool_map["trivy"]["binary_presence"], "detected")
                # Non-CLI tools must be not_applicable
                self.assertEqual(tool_map["owasp-zap"]["binary_presence"], "not_applicable")
                self.assertEqual(tool_map["codeql"]["binary_presence"], "not_applicable")
            finally:
                # Restore original PATH
                if original_path:
                    os.environ["PATH"] = original_path
                elif "PATH" in os.environ:
                    del os.environ["PATH"]

    def test_non_executable_cli_binaries_report_not_found(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            original_path = os.environ.get("PATH", "")
            os.environ["PATH"] = str(tmp_path)
            try:
                # Create non-executable nmap
                nmap_bin = tmp_path / "nmap"
                nmap_bin.write_text("#!/bin/sh\nexit 0\n")
                # semgrep and trivy are missing
                payload = tooling_payload()
                tool_map = {t["id"]: t for t in payload["tools"]}
                self.assertEqual(tool_map["nmap"]["binary_presence"], "not_found")
                self.assertEqual(tool_map["semgrep"]["binary_presence"], "not_found")
                self.assertEqual(tool_map["trivy"]["binary_presence"], "not_found")
            finally:
                if original_path:
                    os.environ["PATH"] = original_path
                elif "PATH" in os.environ:
                    del os.environ["PATH"]


if __name__ == "__main__":
    unittest.main()
