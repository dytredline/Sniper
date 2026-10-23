from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest import mock

import burp_handoff_profile
import changed_scan
import cli_reports
import nuclei_active
import qa_broker_client
import server
import tool_report_burp_sitemap
import tool_report_nmap
import tool_report_schemathesis_junit
import trivy_image_archive_active


class CodeQLNonPathProductGuardTests(unittest.TestCase):
    @staticmethod
    def _handler() -> server.SniperHandler:
        handler = server.SniperHandler.__new__(server.SniperHandler)
        handler.command = "GET"
        handler.request_version = "HTTP/1.1"
        handler.requestline = "GET /codeql-product-guard HTTP/1.1"
        handler.wfile = io.BytesIO()
        handler.log_request = lambda *_args: None
        return handler

    def test_changed_scan_project_path_is_process_cwd_not_argv(self) -> None:
        hostile_root = Path("/tmp/repo;touch${IFS}CODEQL_SENTINEL\n--upload-pack=evil")
        completed = subprocess.CompletedProcess([], 0, stdout=b"/tmp/repo\n", stderr=b"")

        with mock.patch.object(changed_scan, "_git_binary", return_value="/usr/bin/git"), \
                mock.patch.object(changed_scan.subprocess, "run", return_value=completed) as runner:
            changed_scan._git(hostile_root, "rev-parse", "--show-toplevel")

        command = runner.call_args.args[0]
        kwargs = runner.call_args.kwargs
        self.assertNotIn("-C", command)
        self.assertNotIn(str(hostile_root), command)
        self.assertEqual(command[-2:], ["rev-parse", "--show-toplevel"])
        self.assertEqual(kwargs["cwd"], str(hostile_root))
        self.assertIs(kwargs.get("shell", False), False)
        self.assertEqual(kwargs["env"]["GIT_CONFIG_GLOBAL"], "/dev/null")
        self.assertEqual(kwargs["env"]["GIT_CONFIG_NOSYSTEM"], "1")

    def test_nuclei_and_qa_reject_shell_tokens_before_process_launch(self) -> None:
        hostile_values = (
            "127.0.0.1:80;touch${IFS}owned",
            "127.0.0.1:80\n--target evil",
            "$(touch owned)",
            "--help",
        )
        with mock.patch.object(nuclei_active.subprocess, "Popen") as popen:
            for value in hostile_values:
                with self.subTest(engine="nuclei", value=value), self.assertRaises(ValueError):
                    nuclei_active.run_nuclei_loopback(value)
            popen.assert_not_called()

        with mock.patch.object(qa_broker_client, "_exchange_via_unit") as via_unit, \
                mock.patch.object(qa_broker_client, "_exchange") as direct:
            for value in ("k6;id", "$(id)", "schemathesis\n--property=evil", ["k6"]):
                with self.subTest(engine="qa-broker", value=value), self.assertRaises(ValueError):
                    qa_broker_client.run_qa_broker_probe(value)
            via_unit.assert_not_called()
            direct.assert_not_called()

    def test_trivy_archive_metacharacters_are_not_propagated_to_argv(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.home()) as temp:
            root = Path(temp)
            project = root / "project"
            project.mkdir()
            archive_name = "image;touch${IFS}${SNIPER_SENTINEL}.tar"
            (project / archive_name).write_bytes(b"synthetic archive")

            data_dir = root / "data"
            data_dir.mkdir()
            cache = root / "cache"
            database = cache / "db"
            database.mkdir(parents=True)
            (database / "metadata.json").write_text("{}", encoding="utf-8")
            database_bytes = b"synthetic trivy db"
            (database / "trivy.db").write_bytes(database_bytes)

            fake_trivy = root / "fake-trivy"
            fake_trivy.write_text(
                "#!/usr/bin/python3\n"
                "import json, os, pathlib, sys\n"
                "pathlib.Path(os.environ['SNIPER_ARGV_CAPTURE']).write_text(json.dumps(sys.argv[1:]))\n"
                "out = sys.argv[sys.argv.index('--output') + 1]\n"
                "pathlib.Path(out).write_text(json.dumps({'SchemaVersion': 2, 'Results': []}))\n",
                encoding="utf-8",
            )
            fake_trivy.chmod(fake_trivy.stat().st_mode | stat.S_IXUSR)
            sentinel = root / "command-injection-sentinel.tar"
            argv_capture = root / "trivy-argv.json"

            environment = {
                "SNIPER_DATA_DIR": str(data_dir),
                "SNIPER_TRIVY_BINARY": str(fake_trivy),
                "SNIPER_TRIVY_VULN_CACHE_DIR": str(cache),
                "SNIPER_TRIVY_VULN_DB_SHA256": hashlib.sha256(database_bytes).hexdigest(),
                "SNIPER_SENTINEL": str(sentinel.with_suffix("")),
                "SNIPER_ARGV_CAPTURE": str(argv_capture),
            }
            with mock.patch.dict(os.environ, environment, clear=False):
                result = trivy_image_archive_active.run_local_trivy_image_archive_vulnerability(
                    str(project), archive_name
                )

            self.assertEqual(result["profile"], "local-image-archive-offline-v1")
            self.assertFalse(sentinel.exists())
            argv = json.loads(argv_capture.read_text(encoding="utf-8"))
            input_value = argv[argv.index("--input") + 1]
            self.assertEqual(Path(input_value).name, "image.tar")
            self.assertNotIn(archive_name, input_value)
            self.assertEqual(argv.count(input_value), 1)

    def test_nested_entity_bombs_are_rejected_by_every_xml_entry_path(self) -> None:
        declarations = (
            '<!ENTITY a "1234567890">'
            '<!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">'
            '<!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">'
            '<!ENTITY d "&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;">'
        )
        cases = (
            (
                "schemathesis-junit",
                tool_report_schemathesis_junit.parse_schemathesis_junit_summary,
                f'<!DOCTYPE testsuite [{declarations}]><testsuite><testcase name="&d;"/></testsuite>',
            ),
            (
                "nmap",
                tool_report_nmap.parse_nmap_inline_summary,
                f'<!DOCTYPE nmaprun [{declarations}]><nmaprun scanner="&d;"/>',
            ),
            (
                "burp-summary",
                tool_report_burp_sitemap.parse_burp_sitemap_summary,
                f'<!DOCTYPE items [{declarations}]><items><item><status>200</status><mimetype>&d;</mimetype></item></items>',
            ),
            (
                "burp-handoff-present-status",
                burp_handoff_profile.parse_burp_sitemap_xml_summary,
                f'<!DOCTYPE items [{declarations}]><items><item><url>https://app.example.test/&d;</url><status>200</status></item></items>',
            ),
            (
                "burp-handoff-default-status-branch",
                burp_handoff_profile.parse_burp_sitemap_xml_summary,
                f'<!DOCTYPE items [{declarations}]><items><item><url>https://app.example.test/&d;</url></item></items>',
            ),
        )
        for name, parser, payload in cases:
            self.assertLess(len(payload.encode("utf-8")), 60_000)
            with self.subTest(parser=name), self.assertRaises(ValueError):
                parser(payload)

    def test_secret_cli_never_emits_or_stores_the_raw_secret(self) -> None:
        # Generate a deterministic credential-shaped fixture at runtime instead
        # of retaining a plaintext token-shaped value in the source tree.
        synthetic_value = "sk-proj-" + hashlib.sha256(b"sniper-secret-cli-fixture").hexdigest()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "application.env"
            descriptor = os.open(source, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as source_file:
                source_file.write(f"FIXTURE={synthetic_value}\n")
            report = root / "secret-report.md"
            stdout = io.StringIO()

            with contextlib.redirect_stdout(stdout):
                result = cli_reports.run_secret_intel_cli(input_path=source)
            cli_reports.run_secret_intel_cli(
                input_path=source,
                output_format="markdown",
                output=report,
            )

            self.assertEqual(result["finding_count"], 1)
            self.assertNotIn(synthetic_value, json.dumps(result, ensure_ascii=False))
            self.assertNotIn(synthetic_value, stdout.getvalue())
            self.assertNotIn(synthetic_value, report.read_text(encoding="utf-8"))
            self.assertEqual(
                result["findings"][0]["masked_preview"],
                synthetic_value[:4] + "…" + synthetic_value[-2:],
            )
            self.assertEqual(
                result["findings"][0]["fingerprint_sha256"],
                hashlib.sha256(synthetic_value.encode()).hexdigest(),
            )

    def test_common_response_header_gate_rejects_multiline_variants_for_alerted_sinks(self) -> None:
        # #484: the portfolio format allowlist rejects the tainted filename source
        # before constructing Content-Disposition.
        portfolio_handler = self._handler()
        portfolio_handler._portfolio_get(
            "/api/portfolio/export",
            {"format": ['csv\r\n X-Injected: yes']},
        )
        self.assertNotIn(b"X-Injected", portfolio_handler.wfile.getvalue())

        # #485: JSON downloads use the common gate even for obsolete line folding.
        json_handler = self._handler()
        with self.assertRaises(ValueError):
            json_handler._json(
                {"ok": True},
                disposition='attachment; filename="x.json"\r\n\tX-Injected: yes',
            )

        # #486: even an unexpectedly tainted platform MIME mapping cannot cross
        # the common header boundary.
        with tempfile.TemporaryDirectory() as temp:
            static_root = Path(temp)
            (static_root / "proof.weird").write_bytes(b"proof")
            static_handler = self._handler()
            with mock.patch.object(server, "STATIC_DIR", static_root), \
                    mock.patch.object(server.ui_assets, "bundle_asset", return_value=None), \
                    mock.patch.object(
                        server.mimetypes,
                        "guess_type",
                        return_value=("text/plain\rContent-Length: 0\r\nX-Injected: yes", None),
                    ), self.assertRaises(ValueError):
                static_handler._static("/proof.weird")

        # #487: a multiline scan identifier reaches the CSV filename formatter,
        # but is rejected before the response is flushed.
        diff_handler = self._handler()
        with self.assertRaises(ValueError):
            diff_handler._diff_csv_report(
                {},
                "scn_0123456789ab",
                "scn_fedcba987654\n\nX-Injected: yes",
            )

        for handler in (json_handler, static_handler, diff_handler):
            buffered = b"".join(getattr(handler, "_headers_buffer", ()))
            self.assertNotIn(b"X-Injected", buffered)
            self.assertNotIn(b"X-Injected", handler.wfile.getvalue())


if __name__ == "__main__":
    unittest.main()
