import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

import cli_reports
from cli_reports import build_parser, run_cvss_ssvc_cli, run_zero_trust_mesh_cli


PERMISSIVE_YAML = (
    "apiVersion: security.istio.io/v1beta1\n"
    "kind: PeerAuthentication\n"
    "metadata:\n"
    "  name: default\n"
    "  namespace: shop\n"
    "spec:\n"
    "  mtls:\n"
    "    mode: PERMISSIVE\n"
)


class AdvancedSuiteV3CliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def _read_json(self, path: Path) -> dict:
        return json.loads(path.read_text(encoding="utf-8"))

    def test_parser_registers_new_subcommands(self):
        parser = build_parser()
        for command in (
            "secret-intel",
            "privacy-dataflow",
            "host-cis",
            "dos-resilience",
            "audit-logging",
            "extension-pwa",
            "zero-trust-mesh",
        ):
            with self.subTest(command=command):
                args = parser.parse_args([command, "--input", "x.txt", "--filename", "y.txt"])
                self.assertEqual(args.command, command)
                self.assertEqual(args.input_path, "x.txt")
                self.assertEqual(args.filename, "y.txt")
                self.assertIsNone(args.project_path)
                self.assertEqual(args.output_format, "json")
        args = parser.parse_args(["host-cis", "--project", "/tmp/p", "--config-type", "sshd"])
        self.assertEqual(args.config_type, "sshd")
        self.assertEqual(args.project_path, "/tmp/p")
        args = parser.parse_args(["audit-logging", "--verify-chain", "chain.json"])
        self.assertEqual(args.verify_chain, "chain.json")
        args = parser.parse_args(["cvss-ssvc", "--vector", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "--mission", "essential"])
        self.assertEqual(args.mission_prevalence, "essential")
        self.assertEqual(args.exposure, "internet")
        self.assertEqual(args.exploitation, "none")

    def test_cvss_vector_run_writes_json(self):
        out = self.base / "cvss.json"
        result = run_cvss_ssvc_cli(vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", output=out)
        self.assertEqual(result["base_score"], 9.8)
        saved = self._read_json(out)
        self.assertEqual(saved["base_score"], 9.8)
        self.assertEqual(saved["severity"], "Critical")
        self.assertEqual(saved["cvss40_score"], 9.3)
        self.assertEqual(saved["cvss40_severity"], "Critical")
        self.assertTrue(saved["cvss40_vector"].startswith("CVSS:4.0/"))

    def test_cvss40_vector_scored_directly(self):
        out = self.base / "cvss40.json"
        result = run_cvss_ssvc_cli(vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:P", output=out)
        self.assertEqual(result["format"], "sniper-cvss40-score-v1")
        self.assertEqual(self._read_json(out)["score"], 8.9)
        self.assertEqual(result["severity"], "High")

    def test_cvss_vector_via_main(self):
        out = self.base / "main-cvss.json"
        argv = [
            "sniper-report",
            "cvss-ssvc",
            "--vector",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            "--output",
            str(out),
        ]
        with mock.patch.object(sys, "argv", argv):
            cli_reports.main()
        self.assertEqual(self._read_json(out)["base_score"], 6.1)

    def test_cvss_findings_input(self):
        findings_file = self.base / "findings.json"
        findings_file.write_text(
            json.dumps({"findings": [{"title": "SQLi", "cwe": "CWE-89", "severity": "critical"}]}),
            encoding="utf-8",
        )
        out = self.base / "prioritized.json"
        run_cvss_ssvc_cli(
            input_path=str(findings_file),
            now="2026-10-18",
            discovered_at="2026-10-01",
            output=out,
        )
        saved = self._read_json(out)
        self.assertEqual(saved["format"], "sniper-cvss-ssvc-prioritization-v1")
        self.assertEqual(saved["prioritized_findings"][0]["cvss31_score"], 9.8)
        self.assertEqual(saved["prioritized_findings"][0]["sla_status"], "overdue")

    def test_cvss_requires_exactly_one_source(self):
        with self.assertRaises(ValueError):
            run_cvss_ssvc_cli()
        with self.assertRaises(ValueError):
            run_cvss_ssvc_cli(input_path="a.json", vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

    def test_zero_trust_input_run(self):
        manifest = self.base / "peer.yaml"
        manifest.write_text(PERMISSIVE_YAML, encoding="utf-8")
        out = self.base / "zt.json"
        run_zero_trust_mesh_cli(input_path=str(manifest), output=out)
        saved = self._read_json(out)
        self.assertEqual(saved["format"], "sniper-zero-trust-mesh-inline-v1")
        self.assertEqual(saved["filename"], "peer.yaml")
        self.assertIn("SNIPER-ZT-03", [f["control_id"] for f in saved["findings"]])

    def test_zero_trust_via_main_with_filename_override(self):
        manifest = self.base / "input.txt"
        manifest.write_text(PERMISSIVE_YAML, encoding="utf-8")
        out = self.base / "zt-main.json"
        argv = [
            "sniper-report",
            "zero-trust-mesh",
            "--input",
            str(manifest),
            "--filename",
            "mesh/peer.yaml",
            "--output",
            str(out),
        ]
        with mock.patch.object(sys, "argv", argv):
            cli_reports.main()
        saved = self._read_json(out)
        self.assertEqual(saved["filename"], "mesh/peer.yaml")
        self.assertGreaterEqual(saved["finding_count"], 1)

    def test_main_rejects_both_project_and_input(self):
        argv = ["sniper-report", "zero-trust-mesh", "--project", str(self.base), "--input", "x.yaml"]
        with mock.patch.object(sys, "argv", argv), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as ctx:
                cli_reports.main()
        self.assertEqual(ctx.exception.code, 2)

    def test_main_rejects_missing_source(self):
        argv = ["sniper-report", "cvss-ssvc"]
        with mock.patch.object(sys, "argv", argv), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as ctx:
                cli_reports.main()
        self.assertEqual(ctx.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
