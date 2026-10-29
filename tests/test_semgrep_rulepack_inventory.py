from __future__ import annotations

import hashlib
import json
import os
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import server
from semgrep_rulepack_inventory import (
    MAX_RULEPACK_BYTES,
    summarize_trusted_semgrep_rulepack,
)


REAL_RULEPACK_CANDIDATES = (
    Path("/home/community-user/.local/state/sniper-tool-runtimes/semgrep-1.93.0/sniper-local-rules.yml"),
    Path("/home/community-user/.local/state/sniper-tool-runtimes/semgrep-1.180.0-smoke/rules/no-eval.yaml"),
)


class SemgrepRulepackInventoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory(prefix="sniper_rulepack_inv_")
        self.base = Path(self._tmpdir.name).resolve()

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_real_or_fixture_rulepack_summary_and_extension_coverage(self) -> None:
        rulepack_path = next((p for p in REAL_RULEPACK_CANDIDATES if p.is_file() and not p.is_symlink()), None)
        if rulepack_path is None:
            rulepack_path = self.base / "sniper-local-rules.yml"
            rulepack_path.write_text(
                "rules:\n"
                "  - id: sniper.python.eval-call\n"
                "    languages: [python]\n"
                "    severity: ERROR\n"
                "    message: Dynamic evaluation can execute untrusted code.\n"
                "    pattern: eval(...)\n",
                encoding="utf-8",
            )

        expected_sha = hashlib.sha256(rulepack_path.read_bytes()).hexdigest()
        summary = summarize_trusted_semgrep_rulepack(
            rulepack_path,
            target_extensions=[".py", ".rs", ".go"],
        )

        self.assertEqual(summary["format"], "semgrep-rulepack-inventory-v1")
        self.assertIsInstance(summary["rule_count"], int)
        self.assertGreaterEqual(summary["rule_count"], 1)
        self.assertIn("python", summary["languages"])
        self.assertEqual(summary["languages"], sorted(summary["languages"]))
        self.assertEqual(summary["rulepack_sha256"], expected_sha)
        self.assertEqual(len(summary["rulepack_sha256"]), 64)
        self.assertEqual(summary["scope_notice"], "bounded_trusted_rulepack_only")
        self.assertEqual(summary["covered_extensions"], [".py"])
        self.assertEqual(summary["uncovered_extensions"], [".go", ".rs"])

        serialized = json.dumps(summary, sort_keys=True)
        self.assertNotIn("/home/", serialized)
        self.assertNotIn(str(rulepack_path), serialized)

    def test_multilang_yaml_rulepack_uncovered_extension_detection(self) -> None:
        rules_file = self.base / "multilang-rules.yaml"
        content = (
            "---\n"
            "# Trusted local Semgrep rulepack\n"
            "rules:\n"
            "  - id: sniper.python.exec\n"
            "    languages: [python]\n"
            "    severity: ERROR\n"
            "    message: Avoid dynamic exec\n"
            "    pattern: exec(...)\n"
            "  - id: sniper.web.dom-xss\n"
            "    severity: WARNING\n"
            "    languages:\n"
            "      - javascript\n"
            "      - typescript\n"
            "    message: Check innerHTML assignment\n"
            "    pattern: $EL.innerHTML = $VAL\n"
        )
        rules_file.write_text(content, encoding="utf-8")

        summary = summarize_trusted_semgrep_rulepack(
            str(rules_file),
            target_extensions=[".py", "js", ".ts", ".tsx", ".rs", ".go"],
        )

        self.assertEqual(summary["format"], "semgrep-rulepack-inventory-v1")
        self.assertEqual(summary["rule_count"], 2)
        self.assertEqual(summary["languages"], ["javascript", "python", "typescript"])
        self.assertEqual(
            summary["rulepack_sha256"],
            hashlib.sha256(content.encode("utf-8")).hexdigest(),
        )
        self.assertEqual(summary["scope_notice"], "bounded_trusted_rulepack_only")
        self.assertEqual(summary["covered_extensions"], [".js", ".py", ".ts", ".tsx"])
        self.assertEqual(summary["uncovered_extensions"], [".go", ".rs"])

    def test_json_rulepack_and_omitted_target_extensions(self) -> None:
        rules_file = self.base / "rules.json"
        payload = {
            "rules": [
                {
                    "id": "sniper.py.pickle",
                    "languages": ["python"],
                    "severity": "ERROR",
                    "message": "Avoid pickle",
                    "pattern": "pickle.loads(...)",
                },
                {
                    "id": "sniper.js.eval",
                    "languages": ["javascript"],
                    "severity": "WARNING",
                    "message": "Avoid eval",
                    "pattern": "eval(...)",
                },
            ]
        }
        raw = json.dumps(payload, indent=2)
        rules_file.write_text(raw, encoding="utf-8")

        summary = summarize_trusted_semgrep_rulepack(rules_file)
        self.assertEqual(
            set(summary.keys()),
            {"format", "rule_count", "languages", "rulepack_sha256", "scope_notice"},
        )
        self.assertEqual(summary["rule_count"], 2)
        self.assertEqual(summary["languages"], ["javascript", "python"])
        self.assertEqual(
            summary["rulepack_sha256"],
            hashlib.sha256(raw.encode("utf-8")).hexdigest(),
        )

    def test_symlink_relative_and_directory_paths_fail_closed(self) -> None:
        valid_file = self.base / "valid.yaml"
        valid_file.write_text(
            "rules:\n"
            "  - id: r1\n"
            "    languages: [python]\n"
            "    severity: ERROR\n",
            encoding="utf-8",
        )

        # Relative path fails closed
        with self.assertRaises(ValueError):
            summarize_trusted_semgrep_rulepack("relative/rules.yaml")

        with self.assertRaises(ValueError):
            summarize_trusted_semgrep_rulepack(Path("rules.yaml"))

        # Empty string fails closed
        with self.assertRaises(ValueError):
            summarize_trusted_semgrep_rulepack("   ")

        # Symlink file fails closed
        symlink_file = self.base / "symlink-rules.yaml"
        symlink_file.symlink_to(valid_file)
        with self.assertRaises(ValueError):
            summarize_trusted_semgrep_rulepack(symlink_file)

        # Symlink parent directory fails closed
        real_dir = self.base / "real_dir"
        real_dir.mkdir()
        nested_rule = real_dir / "rules.yaml"
        nested_rule.write_text(valid_file.read_text(encoding="utf-8"), encoding="utf-8")
        symlink_dir = self.base / "sym_dir"
        symlink_dir.symlink_to(real_dir)
        with self.assertRaises(ValueError):
            summarize_trusted_semgrep_rulepack(symlink_dir / "rules.yaml")

        # Directory path fails closed
        with self.assertRaises(ValueError):
            summarize_trusted_semgrep_rulepack(real_dir)

        # Non-existent file fails closed
        with self.assertRaises(ValueError):
            summarize_trusted_semgrep_rulepack(self.base / "missing.yaml")

    def test_empty_and_oversized_rulepacks_fail_closed(self) -> None:
        empty_file = self.base / "empty.yaml"
        empty_file.write_text("", encoding="utf-8")
        with self.assertRaises(ValueError):
            summarize_trusted_semgrep_rulepack(empty_file)

        whitespace_file = self.base / "whitespace.yaml"
        whitespace_file.write_text("   \n  # comment only\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            summarize_trusted_semgrep_rulepack(whitespace_file)

        empty_rules_yaml = self.base / "empty_rules.yaml"
        empty_rules_yaml.write_text("rules: []\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            summarize_trusted_semgrep_rulepack(empty_rules_yaml)

        empty_rules_json = self.base / "empty_rules.json"
        empty_rules_json.write_text('{"rules": []}', encoding="utf-8")
        with self.assertRaises(ValueError):
            summarize_trusted_semgrep_rulepack(empty_rules_json)

        oversized_file = self.base / "oversized.yaml"
        oversized_file.write_bytes(b"a" * (MAX_RULEPACK_BYTES + 1))
        with self.assertRaises(ValueError):
            summarize_trusted_semgrep_rulepack(oversized_file)

    def test_unsafe_yaml_tags_and_invalid_fields_fail_closed(self) -> None:
        unsafe_tag_file = self.base / "unsafe_tag.yaml"
        unsafe_tag_file.write_text(
            "rules:\n"
            "  - id: !!python/object/apply:os.system ['echo unsafe']\n"
            "    languages: [python]\n"
            "    severity: ERROR\n",
            encoding="utf-8",
        )
        with self.assertRaises(ValueError):
            summarize_trusted_semgrep_rulepack(unsafe_tag_file)

        custom_tag_file = self.base / "custom_tag.yaml"
        custom_tag_file.write_text(
            "rules:\n"
            "  - id: r1\n"
            "    languages: [!include other.yaml]\n"
            "    severity: ERROR\n",
            encoding="utf-8",
        )
        with self.assertRaises(ValueError):
            summarize_trusted_semgrep_rulepack(custom_tag_file)

        invalid_severity_file = self.base / "bad_severity.yaml"
        invalid_severity_file.write_text(
            "rules:\n"
            "  - id: r1\n"
            "    languages: [python]\n"
            "    severity: UNKNOWN_SEV\n",
            encoding="utf-8",
        )
        with self.assertRaises(ValueError):
            summarize_trusted_semgrep_rulepack(invalid_severity_file)

        missing_lang_file = self.base / "missing_lang.yaml"
        missing_lang_file.write_text(
            "rules:\n"
            "  - id: r1\n"
            "    severity: ERROR\n",
            encoding="utf-8",
        )
        with self.assertRaises(ValueError):
            summarize_trusted_semgrep_rulepack(missing_lang_file)

        valid_file = self.base / "valid_ext_test.yaml"
        valid_file.write_text(
            "rules:\n"
            "  - id: r1\n"
            "    languages: [python]\n"
            "    severity: ERROR\n",
            encoding="utf-8",
        )
        with self.assertRaises(ValueError):
            summarize_trusted_semgrep_rulepack(valid_file, target_extensions=".py")  # type: ignore[arg-type]

        with self.assertRaises(ValueError):
            summarize_trusted_semgrep_rulepack(valid_file, target_extensions=["../py"])

    def test_http_rulepack_inventory_endpoint(self) -> None:
        rules_file = self.base / "http-rules.yaml"
        rules_content = (
            "rules:\n"
            "  - id: sniper.python.eval-call\n"
            "    languages: [python]\n"
            "    severity: ERROR\n"
            "    message: Dynamic evaluation can execute untrusted code.\n"
            "    pattern: eval(...)\n"
        )
        rules_file.write_text(rules_content, encoding="utf-8")

        httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.SniperHandler)
        httpd.daemon_threads = True
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        url = f"http://127.0.0.1:{httpd.server_address[1]}/api/tool-reports/semgrep/rulepack-inventory"

        def post_json(payload: object) -> tuple[int, dict[str, object]]:
            raw = json.dumps(payload).encode("utf-8")
            req = Request(url, data=raw, method="POST", headers={"Content-Type": "application/json"})
            try:
                with urlopen(req, timeout=5) as resp:
                    return resp.status, json.loads(resp.read().decode("utf-8"))
            except HTTPError as err:
                return err.code, json.loads(err.read().decode("utf-8"))

        try:
            with patch.dict(os.environ, {"SNIPER_SEMGREP_RULES": str(rules_file)}, clear=False):
                status, body = post_json({"target_extensions": [".py", ".rs"]})
                self.assertEqual(status, 200)
                self.assertEqual(body.get("format"), "semgrep-rulepack-inventory-v1")
                self.assertEqual(body.get("rule_count"), 1)
                self.assertEqual(body.get("languages"), ["python"])
                self.assertEqual(body.get("covered_extensions"), [".py"])
                self.assertEqual(body.get("uncovered_extensions"), [".rs"])
                self.assertEqual(body.get("scope_notice"), "bounded_trusted_rulepack_only")
                self.assertNotIn("/home/", json.dumps(body))

                status_bad, _ = post_json({"target_extensions": ["../py"]})
                self.assertEqual(status_bad, 400)

            with patch.dict(os.environ, {"SNIPER_SEMGREP_RULES": ""}, clear=False):
                status_unavail, body_unavail = post_json({"target_extensions": [".py", ".rs"]})
                self.assertEqual(status_unavail, 503)
                self.assertIn("yapılandırılmamış", str(body_unavail.get("error", "")))
        finally:
            httpd.shutdown()
            httpd.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
