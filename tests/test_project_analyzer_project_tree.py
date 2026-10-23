from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

import project_analyzer


class ProjectAnalyzerPinnedTreeTests(unittest.TestCase):
    def test_parent_swap_after_validation_is_rejected_before_external_source_is_scanned(self) -> None:
        with tempfile.TemporaryDirectory(prefix="sniper-project-analyzer-tree-") as temp:
            base = Path(temp)
            parent = base / "selected"
            project = parent / "project"
            project.mkdir(parents=True)
            (project / "app.py").write_text("SAFE = True\n", encoding="utf-8")

            outside_parent = base / "outside"
            outside_project = outside_parent / "project"
            outside_project.mkdir(parents=True)
            (outside_project / "app.py").write_text(
                "import os\nos.system(input())\n",
                encoding="utf-8",
            )
            moved_parent = base / "selected-original"
            original_validate = project_analyzer.validate_project_path
            swapped = False

            def validate_then_swap(value: str, allowed_roots=None):
                nonlocal swapped
                validated = original_validate(value, allowed_roots)
                parent.rename(moved_parent)
                parent.symlink_to(outside_parent, target_is_directory=True)
                swapped = True
                return validated

            with mock.patch.object(project_analyzer, "validate_project_path", side_effect=validate_then_swap):
                with self.assertRaises(project_analyzer.ProjectRejected) as captured:
                    project_analyzer.analyze_project(str(project), allowed_roots=(base,))

            self.assertTrue(swapped, "test must replace the validated project parent")
            self.assertIn("Proje ağacı güvenli biçimde", str(captured.exception))


if __name__ == "__main__":
    unittest.main()
