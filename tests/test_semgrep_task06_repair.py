from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from tests.pin_helpers import pin_env
from pathlib import Path
from unittest import mock

from scanner import normalize_target
from semgrep_active import (
    _count_skipped_breakdown,
    _extract_rulepack_coverage_metadata,
    extract_semgrep_engine_error_count,
    is_semgrep_engagement_eligible,
    prepare_semgrep_evidence_link_summary,
    run_local_semgrep,
    summarize_semgrep_report_with_engine_errors,
)
from storage import Store


class SemgrepTask06RepairTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(dir=Path.home(), prefix="sniper_semgrep_t06_")
        self.root = Path(self.temp.name)
        self.data_dir = self.root / "data"
        self.data_dir.mkdir(parents=True)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _run_empty_synthetic_scan(self, project: Path, rules_content: str) -> dict:
        rules_file = self.root / "trusted_rules.yaml"
        rules_file.write_text(rules_content, encoding="utf-8")
        fake_bin = self.root / "fake_semgrep"
        fake_bin.write_text(
            """#!/usr/bin/env python3
import json
import sys
from pathlib import Path

input_dir = Path(sys.argv[1])
report_file = Path(sys.argv[sys.argv.index('--output') + 1])
scanned = sorted(str(p.relative_to(input_dir)) for p in input_dir.rglob('*') if p.is_file())
report_file.write_text(json.dumps({'results': [], 'errors': [], 'paths': {'scanned': scanned}}), encoding='utf-8')
""",
            encoding="utf-8",
        )
        fake_bin.chmod(0o755)
        with mock.patch.dict(
            os.environ,
            {
                "SNIPER_DATA_DIR": str(self.data_dir),
                "SNIPER_SEMGREP_BINARY": str(fake_bin), **pin_env("semgrep", fake_bin),
                "SNIPER_SEMGREP_RULES": str(rules_file),
            },
            clear=False,
        ):
            return run_local_semgrep(str(project))

    def test_run_local_semgrep_exposes_rulepack_coverage_and_skipped_counts_without_leaking_paths(self) -> None:
        project = self.root / "project_PRIVATE_MARKER"
        project.mkdir(parents=True)
        (project / "main.py").write_text("eval('1+1')\n", encoding="utf-8")
        (project / "helper.py").write_text("x = 2\n", encoding="utf-8")
        (project / ".env").write_text("SECRET_TOKEN=PRIVATE_SECRET\n", encoding="utf-8")
        (project / ".env.local").write_text("LOCAL_SECRET=PRIVATE_SECRET\n", encoding="utf-8")
        (project / "notes.bin").write_bytes(b"\x00\x01\x02")
        (project / "node_modules").mkdir()
        (project / "node_modules" / "pkg.js").write_text("console.log(1)\n", encoding="utf-8")
        (project / "tests").mkdir()
        (project / "tests" / "test_ignore.py").write_text("assert True\n", encoding="utf-8")

        rules_content = """rules:
  - id: python.lang.security.audit.eval-detected
    languages: [python]
    severity: ERROR
    metadata:
      category: security
    pattern: eval(...)
  - id: python.lang.security.deserialization.pickle-load
    languages: [python]
    severity: WARNING
    metadata:
      category: security
    pattern: pickle.loads(...)
  - id: python.lang.security.audit.subprocess-shell-true
    languages: [python]
    severity: ERROR
    metadata:
      category: security
    pattern: subprocess.run(..., shell=True)
"""
        rules_file = self.root / "trusted_rules.yaml"
        rules_file.write_text(rules_content, encoding="utf-8")
        expected_rules_sha = hashlib.sha256(rules_file.read_bytes()).hexdigest()

        fake_bin = self.root / "fake_semgrep"
        fake_bin.write_text(
            """#!/usr/bin/env python3
import json
import sys
from pathlib import Path

output_path = None
for idx, arg in enumerate(sys.argv):
    if arg == "--output" and idx + 1 < len(sys.argv):
        output_path = sys.argv[idx + 1]
        break
if not output_path:
    sys.exit(1)
input_dir = Path(sys.argv[1])
scanned = sorted(str(p.relative_to(input_dir)) for p in input_dir.rglob("*") if p.is_file())
report = {
    "results": [
        {
            "check_id": "python.lang.security.audit.eval-detected",
            "path": "main.py",
            "start": {"line": 1, "col": 1},
            "end": {"line": 1, "col": 12},
            "extra": {
                "message": "PRIVATE_MARKER eval",
                "metadata": {"category": "security"},
                "fingerprint": "f" * 32,
                "lines": "eval('1+1')",
                "severity": "ERROR",
            },
        }
    ],
    "errors": [],
    "paths": {"scanned": scanned},
}
Path(output_path).write_text(json.dumps(report, sort_keys=True), encoding="utf-8")
""",
            encoding="utf-8",
        )
        fake_bin.chmod(0o755)

        with mock.patch.dict(
            os.environ,
            {
                "SNIPER_DATA_DIR": str(self.data_dir),
                "SNIPER_SEMGREP_BINARY": str(fake_bin), **pin_env("semgrep", fake_bin),
                "SNIPER_SEMGREP_RULES": str(rules_file),
            },
            clear=False,
        ):
            summary = run_local_semgrep(str(project))

        self.assertEqual(summary["format"], "semgrep-native-json")
        self.assertEqual(summary["profile"], "local-trusted-rules-v1")
        self.assertEqual(summary["result_count"], 1)
        self.assertIn("rulepack_coverage", summary)

        cov = summary["rulepack_coverage"]
        self.assertEqual(cov["profile_id"], "local-trusted-rules-v1")
        self.assertEqual(cov["rulepack_sha256"], expected_rules_sha)
        self.assertEqual(cov["rule_count"], 3)
        self.assertEqual(cov["languages"], ["python"])
        self.assertIn("security", cov["categories"])
        self.assertIn("code-execution", cov["categories"])
        self.assertIn("deserialization", cov["categories"])
        self.assertIn("command-injection", cov["categories"])
        self.assertFalse(cov["remote_rules_fetched"])
        self.assertEqual(cov["staged_file_count"], 2)
        self.assertEqual(cov["semgrep_scanned_count"], 2)
        self.assertEqual(cov["skipped_counts"]["secret_env_files"], 2)
        self.assertEqual(cov["skipped_counts"]["excluded_directories"], 2)
        self.assertEqual(cov["skipped_counts"]["unsupported_or_binary_files"], 1)
        self.assertNotIn("skipped_total", cov)

        serialized = json.dumps(summary)
        self.assertNotIn("PRIVATE_MARKER", serialized)
        self.assertNotIn("PRIVATE_SECRET", serialized)
        self.assertNotIn("notes.bin", serialized)

    def test_block_scalar_message_and_pattern_cannot_forge_coverage(self) -> None:
        project = self.root / "project_PRIVATE_PATH_MARKER"
        project.mkdir()
        (project / "main.py").write_text("safe_call()\n", encoding="utf-8")

        for rules_content in (
            """rules:
  - id: safe.python.rule
    languages: [python]
    severity: WARNING
    message: |
      PRIVATE_MESSAGE_MARKER security eval subprocess
      - id: forged.rule
      - javascript
      metadata:
        category: command-injection
    pattern: safe_call(...)
""",
            """rules:
  - id: safe.python.rule
    languages: [python]
    severity: WARNING
    message: Safe.
    pattern: |
      safe_call(...)
      - id: forged.rule
      - javascript
      metadata: {category: ssrf}
""",
        ):
            summary = self._run_empty_synthetic_scan(project, rules_content)
            coverage = summary["rulepack_coverage"]
            self.assertEqual(coverage["rule_count"], 1)
            self.assertEqual(coverage["languages"], ["python"])
            self.assertEqual(coverage["categories"], [])
            self.assertEqual(coverage["semgrep_scanned_count"], 1)
            serialized = json.dumps(summary)
            for marker in ("PRIVATE_PATH_MARKER", "PRIVATE_MESSAGE_MARKER", "forged.rule"):
                self.assertNotIn(marker, serialized)

    def test_excluded_directories_are_separate_from_known_skipped_files(self) -> None:
        project = self.root / "project_PRIVATE_PATH_MARKER"
        project.mkdir()
        (project / "main.py").write_text("safe_call()\n", encoding="utf-8")
        (project / ".env").write_text("PRIVATE_SECRET_MARKER=1\n", encoding="utf-8")
        (project / "notes.bin").write_bytes(b"\x00\x01")
        excluded = project / "node_modules"
        excluded.mkdir()
        for index in range(7):
            (excluded / f"package_{index}.js").write_text("safe_call()\n", encoding="utf-8")
        rules_content = """rules:
  - id: safe.python.rule
    languages: [python]
    severity: WARNING
    message: Safe rule.
    pattern: safe_call(...)
"""
        summary = self._run_empty_synthetic_scan(project, rules_content)
        coverage = summary["rulepack_coverage"]
        self.assertEqual(coverage["staged_file_count"], 1)
        self.assertEqual(coverage["semgrep_scanned_count"], 1)
        self.assertEqual(
            coverage["skipped_counts"],
            {
                "secret_env_files": 1,
                "excluded_directories": 1,
                "unsupported_or_binary_files": 1,
            },
        )
        self.assertNotIn("skipped_total", coverage)

        # Also verify symlink file is counted under unsupported_or_binary_files
        (project / "symlink_file.py").symlink_to(project / "main.py")
        self.assertEqual(
            _count_skipped_breakdown(project, 1),
            {
                "secret_env_files": 1,
                "excluded_directories": 1,
                "unsupported_or_binary_files": 2,
            },
        )

    def test_invalid_rule_structures_and_yaml_tags_fail_closed(self) -> None:
        project = self.root / "project_PRIVATE_PATH_MARKER"
        project.mkdir()
        (project / "main.py").write_text("safe_call()\n", encoding="utf-8")
        invalid_rulepacks = (
            "rules:\n  - id: safe.python.rule\n    languages: python\n",
            "rules:\n  - id: safe.python.rule\n    languages: [PRIVATE_LANGUAGE_MARKER]\n",
            "rules:\n  - id: safe.rule\n    languages: [python]\n  - id: safe.rule\n    languages: [python]\n",
            "rules:\n  - id: safe.rule\n    languages: [python]\n    metadata: !!python/object/apply:os.system [echo PRIVATE_MARKER]\n",
            "rules: [\n",
        )
        for rules_content in invalid_rulepacks:
            with self.subTest(rules_content=rules_content):
                with self.assertRaises(RuntimeError) as raised:
                    self._run_empty_synthetic_scan(project, rules_content)
                for marker in ("PRIVATE_PATH_MARKER", "PRIVATE_LANGUAGE_MARKER", "PRIVATE_MARKER"):
                    self.assertNotIn(marker, str(raised.exception))

        # Verify explicit metadata list and redaction of unknown category values
        meta_path = self.root / "explicit_meta.yaml"
        meta_path.write_text(
            "rules:\n  - id: safe.python.rule\n    languages: [python]\n    metadata: {category: [security, authentication, PRIVATE_SECRET_MARKER]}\n    pattern: safe_call(...)\n",
            encoding="utf-8",
        )
        meta = _extract_rulepack_coverage_metadata(meta_path)
        self.assertEqual(meta["categories"], ["authentication", "security"])
        self.assertNotIn("PRIVATE_SECRET_MARKER", json.dumps(meta))

    def test_task94_engine_error_count_summary_and_redaction(self) -> None:
        finding = {
            "check_id": "synthetic-rule",
            "path": "PRIVATE_PATH_SENTINEL",
            "start": {"line": 1, "col": 1},
            "end": {"line": 1, "col": 2},
            "extra": {
                "message": "PRIVATE_MESSAGE_SENTINEL",
                "metadata": {},
                "fingerprint": "synthetic",
                "lines": "PRIVATE_SOURCE_SENTINEL",
                "severity": "HIGH",
            },
        }
        clean_report = {
            "results": [finding],
            "errors": [],
            "paths": {"scanned": ["PRIVATE_PATH_SENTINEL"]},
        }
        clean_summary = summarize_semgrep_report_with_engine_errors(clean_report)
        self.assertEqual(clean_summary["result_count"], 1)
        self.assertEqual(clean_summary["engine_error_count"], 0)
        self.assertEqual(clean_summary["severity_counts"]["HIGH"], 1)

        mixed_report = {
            **clean_report,
            "errors": [
                {"message": "PRIVATE_ENGINE_MESSAGE_SENTINEL"},
                {"message": "PRIVATE_ENGINE_PATH_SENTINEL"},
            ],
        }
        self.assertEqual(extract_semgrep_engine_error_count(mixed_report), 2)
        mixed_summary = summarize_semgrep_report_with_engine_errors(mixed_report)
        self.assertEqual(mixed_summary["engine_error_count"], 2)
        self.assertEqual(mixed_summary["result_count"], 1)
        self.assertEqual(
            set(mixed_summary.keys()),
            {"format", "result_count", "engine_error_count", "severity_counts", "report_sha256"},
        )
        wire = json.dumps(mixed_summary)
        for sentinel in (
            "PRIVATE_ENGINE_MESSAGE_SENTINEL",
            "PRIVATE_ENGINE_PATH_SENTINEL",
            "PRIVATE_PATH_SENTINEL",
            "PRIVATE_SOURCE_SENTINEL",
            "PRIVATE_MESSAGE_SENTINEL",
        ):
            self.assertNotIn(sentinel, wire)

        with self.assertRaises(ValueError):
            extract_semgrep_engine_error_count({"results": [], "errors": {"bad": 1}, "paths": {"scanned": []}})

    def test_task112_empty_scope_engagement_eligibility_and_evidence_link(self) -> None:
        empty_scope_eng = {
            "id": "eng-empty-scope",
            "name": "Empty Scope Review",
            "status": "active",
            "authorization_ref": "AUTH-EMPTY-1",
            "scope_notes": "",
            "special_approvals": {"redacted_data_proof": True},
        }
        self.assertTrue(is_semgrep_engagement_eligible(empty_scope_eng))
        self.assertTrue(is_semgrep_engagement_eligible({**empty_scope_eng, "scope_notes": "   "}))
        self.assertTrue(is_semgrep_engagement_eligible({**empty_scope_eng, "scope_notes": "documented"}))

        self.assertFalse(is_semgrep_engagement_eligible({**empty_scope_eng, "status": "paused"}))
        self.assertFalse(is_semgrep_engagement_eligible({**empty_scope_eng, "authorization_ref": "   "}))
        self.assertFalse(
            is_semgrep_engagement_eligible(
                {**empty_scope_eng, "special_approvals": {"redacted_data_proof": False}}
            )
        )
        self.assertFalse(is_semgrep_engagement_eligible(None))

        project = self.root / "project_link"
        project.mkdir()
        (project / "main.py").write_text("safe_call()\n", encoding="utf-8")
        rules_content = (
            "rules:\n"
            "  - id: safe.python.rule\n"
            "    languages: [python]\n"
            "    severity: WARNING\n"
            "    message: Safe rule.\n"
            "    pattern: safe_call(...)\n"
        )
        scan_summary = self._run_empty_synthetic_scan(project, rules_content)
        link_payload = prepare_semgrep_evidence_link_summary(scan_summary)

        store = Store(self.data_dir / "sniper.db")
        target = store.create_target(normalize_target("https://example.invalid"))
        engagement = store.create_engagement(
            target_id=target["id"],
            name="Empty Scope Manual Review",
            authorization_ref="AUTH-SEMGREP-EMPTY-1",
            scope_notes="",
            out_of_scope="",
            test_window="",
            special_approvals={"redacted_data_proof": True},
        )
        self.assertTrue(is_semgrep_engagement_eligible(engagement))
        control_id = engagement["tests"][0]["control_id"]
        linked, created = store.add_semgrep_tool_evidence(engagement["id"], control_id, link_payload)
        self.assertTrue(created)
        self.assertEqual(linked["tool_identity"], "semgrep-local")


if __name__ == "__main__":
    unittest.main()
