from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import project_analyzer
import semgrep_active
from tests.pin_helpers import pin_env


SAFE_RULES = """rules:
  - id: safe.python.rule
    languages: [python]
    severity: WARNING
    message: safe
    pattern: safe_call(...)
"""


class SemgrepProjectTreeHardeningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(dir=Path.home(), prefix="sniper_semgrep_tree_")
        self.root = Path(self.temp.name)
        self.data = self.root / "data"
        self.data.mkdir()
        self.trace = self.root / "trace.json"
        self.rules = self.root / "rules.yaml"
        self.rules.write_text(SAFE_RULES, encoding="utf-8")
        self.binary = self.root / "fake-semgrep"
        self.binary.write_text(
            """#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path

source = Path(sys.argv[1])
config = Path(sys.argv[sys.argv.index('--config') + 1])
candidate = source / 'main.py'
if not candidate.exists():
    candidate = source / 'src' / 'main.py'
trace = {
    'source': candidate.read_text(encoding='utf-8') if candidate.is_file() else '<missing>',
    'rules': config.read_text(encoding='utf-8'),
}
Path(os.environ['SNIPER_TEST_TRACE']).write_text(json.dumps(trace), encoding='utf-8')
report = {'results': [], 'errors': [], 'paths': {'scanned': [] if trace['source'] == '<missing>' else ['main.py']}}
Path(sys.argv[sys.argv.index('--output') + 1]).write_text(json.dumps(report), encoding='utf-8')
""",
            encoding="utf-8",
        )
        self.binary.chmod(0o755)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _run(self, project: Path) -> dict:
        env = {
            "SNIPER_DATA_DIR": str(self.data),
            "SNIPER_SEMGREP_BINARY": str(self.binary),
            "SNIPER_SEMGREP_RULES": str(self.rules),
            "SNIPER_TEST_TRACE": str(self.trace),
            **pin_env("semgrep", self.binary),
        }
        with mock.patch.dict(os.environ, env, clear=False):
            return semgrep_active.run_local_semgrep(str(project))

    def test_parent_path_swap_stages_bytes_from_pinned_project(self) -> None:
        project = self.root / "project"
        displaced = self.root / "project-original"
        outside = self.root / "outside"
        project.mkdir()
        outside.mkdir()
        (project / "main.py").write_text("SAFE_PROJECT_SENTINEL\n", encoding="utf-8")
        (outside / "main.py").write_text("OUTSIDE_PROJECT_SENTINEL\n", encoding="utf-8")

        real_read = project_analyzer.ProjectTree.read_bytes
        swapped = False

        def racing_read(tree, project_file, *args, **kwargs):
            nonlocal swapped
            if not swapped and project_file.path.as_posix() == "main.py":
                swapped = True
                project.rename(displaced)
                project.symlink_to(outside, target_is_directory=True)
            return real_read(tree, project_file, *args, **kwargs)

        try:
            with mock.patch.object(project_analyzer.ProjectTree, "read_bytes", new=racing_read):
                summary = self._run(project)
        finally:
            if project.is_symlink():
                project.unlink()
            if displaced.exists():
                displaced.rename(project)

        trace = json.loads(self.trace.read_text(encoding="utf-8"))
        self.assertTrue(swapped)
        self.assertEqual(trace["source"], "SAFE_PROJECT_SENTINEL\n")
        self.assertNotIn("OUTSIDE_PROJECT_SENTINEL", json.dumps(trace))
        self.assertEqual(summary["rulepack_coverage"]["staged_file_count"], 1)

    def test_intermediate_directory_swap_fails_closed(self) -> None:
        project = self.root / "project"
        source = project / "src"
        displaced = project / "src-original"
        outside = self.root / "outside-src"
        source.mkdir(parents=True)
        outside.mkdir()
        (source / "main.py").write_text("SAFE_PROJECT_SENTINEL\n", encoding="utf-8")
        (outside / "main.py").write_text("OUTSIDE_PROJECT_SENTINEL\n", encoding="utf-8")

        real_read = project_analyzer.ProjectTree.read_bytes
        swapped = False

        def racing_read(tree, project_file, *args, **kwargs):
            nonlocal swapped
            if not swapped and project_file.path.as_posix() == "src/main.py":
                swapped = True
                source.rename(displaced)
                source.symlink_to(outside, target_is_directory=True)
            return real_read(tree, project_file, *args, **kwargs)

        try:
            with mock.patch.object(project_analyzer.ProjectTree, "read_bytes", new=racing_read):
                summary = self._run(project)
        finally:
            if source.is_symlink():
                source.unlink()
            if displaced.exists():
                displaced.rename(source)

        trace = json.loads(self.trace.read_text(encoding="utf-8"))
        self.assertTrue(swapped)
        self.assertEqual(trace["source"], "<missing>")
        self.assertNotIn("OUTSIDE_PROJECT_SENTINEL", json.dumps(trace))
        self.assertEqual(summary["rulepack_coverage"]["staged_file_count"], 0)

    def test_rulepack_is_snapshotted_once_before_engine_launch(self) -> None:
        project = self.root / "project"
        project.mkdir()
        (project / "main.py").write_text("safe_call()\n", encoding="utf-8")
        displaced = self.root / "rules-original.yaml"
        outside = self.root / "outside-rules.yaml"
        outside.write_text(SAFE_RULES.replace("safe.python.rule", "outside.python.rule"), encoding="utf-8")

        real_read = semgrep_active._read_rulepack_bytes

        def racing_rule_read(path: Path) -> bytes:
            payload = real_read(path)
            self.rules.rename(displaced)
            self.rules.symlink_to(outside)
            return payload

        try:
            with mock.patch.object(semgrep_active, "_read_rulepack_bytes", side_effect=racing_rule_read):
                summary = self._run(project)
        finally:
            if self.rules.is_symlink():
                self.rules.unlink()
            if displaced.exists():
                displaced.rename(self.rules)

        trace = json.loads(self.trace.read_text(encoding="utf-8"))
        self.assertEqual(trace["rules"], SAFE_RULES)
        self.assertNotIn("outside.python.rule", trace["rules"])
        self.assertEqual(summary["rulepack_coverage"]["rule_count"], 1)


if __name__ == "__main__":
    unittest.main()
