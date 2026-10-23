from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

import ai_triage
from attack_path_correlator import _enclosing_names, correlate_attack_paths
from project_analyzer import validate_project_path


class AttackPathInlineBoundaryTests(unittest.TestCase):
    def test_project_reader_rejects_symlink_project_root(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.home()) as temp:
            base = Path(temp)
            real_project = base / "real-project"
            real_project.mkdir()
            (real_project / "chosen.py").write_text("VALUE = 1\n", encoding="utf-8")
            linked_project = base / "linked-project"
            linked_project.symlink_to(real_project, target_is_directory=True)

            with self.assertRaises(ai_triage.TriageError):
                ai_triage.project_file_lines(str(linked_project), "chosen.py")

    def test_stored_audit_lookup_rejects_project_parent_symlink_replacement(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.home()) as temp:
            base = Path(temp)
            work = base / "work"
            project = work / "project"
            project.mkdir(parents=True)
            (project / "chosen.py").write_text("VALUE = 1\n", encoding="utf-8")
            outside = base / "outside"
            outside_project = outside / "project"
            outside_project.mkdir(parents=True)
            (outside_project / "chosen.py").write_text(
                "def payload_selected_handler():\n    return 'outside'\n",
                encoding="utf-8",
            )
            validated = validate_project_path(str(project), allowed_roots=(base,))
            original_lstat = ai_triage.os.lstat
            original_open = ai_triage.os.open
            swapped = False

            def replace_parent() -> None:
                nonlocal swapped
                if not swapped:
                    swapped = True
                    work.rename(base / "work-safe")
                    work.symlink_to(outside, target_is_directory=True)

            def replace_parent_before_root_lstat(path: object) -> object:
                if Path(path) == validated:
                    replace_parent()
                return original_lstat(path)

            def replace_parent_before_component_open(path: object, *args: object, **kwargs: object) -> int:
                if path == "work":
                    replace_parent()
                return original_open(path, *args, **kwargs)

            # The root was policy-validated, but its writable parent changes
            # before project_file_lines establishes its descriptor.
            with mock.patch.object(ai_triage.os, "lstat", side_effect=replace_parent_before_root_lstat), \
                    mock.patch.object(ai_triage.os, "open", side_effect=replace_parent_before_component_open):
                names = _enclosing_names(validated, "chosen.py", 2)

        self.assertEqual(names, set())

    def test_stored_audit_lookup_rejects_intermediate_symlink_replacement(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.home()) as temp:
            base = Path(temp)
            project = base / "project"
            safe_dir = project / "pkg"
            outside = base / "outside"
            safe_dir.mkdir(parents=True)
            outside.mkdir()
            source = safe_dir / "chosen.py"
            source.write_text("VALUE = 1\n", encoding="utf-8")
            (outside / "chosen.py").write_text(
                "def payload_selected_handler():\n    return 'outside'\n",
                encoding="utf-8",
            )
            resolved_source = source.resolve(strict=True)
            original_relative_to = Path.relative_to
            swapped = False

            def replace_after_containment(path: Path, *other: object) -> Path:
                nonlocal swapped
                result = original_relative_to(path, *other)
                if path == resolved_source and not swapped:
                    swapped = True
                    safe_dir.rename(project / "pkg-safe")
                    safe_dir.symlink_to(outside, target_is_directory=True)
                return result

            # The old flow resolved + checked containment and then reopened the
            # path by name.  Swap an intermediate component at that exact gap.
            with mock.patch.object(Path, "relative_to", replace_after_containment):
                names = _enclosing_names(project, "pkg/chosen.py", 2)

        self.assertEqual(names, set())

    def test_inline_project_audit_cannot_use_payload_paths_for_source_lookup(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.home()) as temp:
            project = Path(temp)
            source = project / "chosen.py"
            source.write_text(
                "def payload_selected_handler():\n"
                "    user_value = request.args.get('value')\n"
                "    return db.execute('SELECT ' + user_value)\n",
                encoding="utf-8",
            )
            inline_audit = {
                "project_path": str(project),
                "route_inventory": {
                    "routes": [{
                        "file": "router.py",
                        "line": 1,
                        "path": "/selected",
                        "methods": ["GET"],
                        "handler": "payload_selected_handler",
                        "public": True,
                    }]
                },
                "findings": [{
                    "file": "chosen.py",
                    "line": 3,
                    "category": "data_query",
                    "severity": "critical",
                    "title": "inline payload must not authorize a file read",
                    "taint_flow": {
                        "source_label": "request",
                        "source_file": "chosen.py",
                        "source_line": 2,
                        "source": "request.args",
                        "sink": "db.execute",
                        "sink_kind": "sql",
                    },
                }],
            }

            result = correlate_attack_paths(project_audit=inline_audit)

        self.assertEqual(result["route_chain_count"], 0)
        self.assertEqual(result["route_chains"], [])


if __name__ == "__main__":
    unittest.main()
