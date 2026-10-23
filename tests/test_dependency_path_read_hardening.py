from __future__ import annotations

import ast
import inspect
import json
import os
from pathlib import Path
import tempfile
import textwrap
import unittest
from unittest import mock

import dependency_reachability as dr
from dependency_security import analyze_vulnerability_reachability
from project_tree import ProjectTreeError


def _path_read_text_calls(function: object) -> list[int]:
    """Return direct ``Path.read_text``-style calls in a function and its closures."""
    source = textwrap.dedent(inspect.getsource(function))
    tree = ast.parse(source)
    return [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "read_text"
        and not (
            isinstance(node.func.value, ast.Name)
            and node.func.value.id in {"tree", "project_tree", "_project_tree"}
        )
    ]


class DependencyPathReadHardeningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.project = self.base / "project"
        self.project.mkdir()

    @staticmethod
    def _replace_on_first_stat(source: Path, replacement: Path):
        """Build a Path.stat hook that performs a real regular-file-to-symlink swap."""
        original_stat = Path.stat
        replaced = False

        def replacing_stat(path: Path, *args: object, **kwargs: object):
            nonlocal replaced
            result = original_stat(path, *args, **kwargs)
            if not replaced and os.fspath(path) == os.fspath(source):
                source.unlink()
                source.symlink_to(replacement)
                replaced = True
            return result

        return replacing_stat

    @staticmethod
    def _walk_after_parent_replacement(root: Path, parent: Path, replacement: Path):
        """Replay a completed walk, swapping one enumerated parent before use."""
        entries = list(os.walk(root, followlinks=False))
        replaced = False

        def racing_walk(_root: Path, *, followlinks: bool = False):
            nonlocal replaced
            for current, directories, files in entries:
                if not replaced and Path(current) == parent:
                    parent.rename(parent.with_name(parent.name + "-validated"))
                    parent.symlink_to(replacement, target_is_directory=True)
                    replaced = True
                yield current, list(directories), list(files)

        return racing_walk

    def test_npm_alias_reader_does_not_follow_file_replaced_after_metadata_check(self) -> None:
        manifest = self.project / "package.json"
        manifest.write_text(json.dumps({"dependencies": {"left-pad": "1.0.0"}}), encoding="utf-8")
        outside = self.base / "outside-package.json"
        outside.write_text(
            json.dumps({"dependencies": {"safealias": "npm:evil-package@1.0.0"}}),
            encoding="utf-8",
        )
        real_open = os.open
        replaced = False

        def replacing_open(path: object, flags: int, *args: object, **kwargs: object):
            nonlocal replaced
            if not replaced and Path(path).name == manifest.name:
                manifest.unlink()
                manifest.symlink_to(outside)
                replaced = True
            return real_open(path, flags, *args, **kwargs)

        with mock.patch.object(dr.os, "open", side_effect=replacing_open):
            with self.assertRaises(ProjectTreeError):
                dr.npm_dependency_aliases(self.project, ())

        self.assertTrue(replaced)

    def test_manifest_readers_reject_parent_directory_symlink_replacement(self) -> None:
        cases = (
            (
                "Cargo.toml",
                '[dependencies]\nsafe_alias = { package = "safe-package", version = "1" }\n',
                '[dependencies]\nevil_alias = { package = "evil-package", version = "1" }\n',
                lambda root: dr.cargo_dependency_aliases(root, ()),
                "evil-package",
            ),
            (
                "package.json",
                json.dumps({"dependencies": {"safe": "npm:safe-package@1"}}),
                json.dumps({"dependencies": {"evil": "npm:evil-package@1"}}),
                lambda root: dr.npm_dependency_aliases(root, ()),
                "evil-package",
            ),
            (
                "package.json",
                json.dumps({"dependencies": {"safe-package": "1"}}),
                json.dumps({"dependencies": {"evil-package": "1"}}),
                lambda root: dr.direct_dependencies(root, ()),
                "evil-package",
            ),
        )
        for index, (leaf, safe_text, outside_text, reader, forbidden) in enumerate(cases):
            with self.subTest(leaf=leaf, reader=reader):
                project = self.base / f"project-{index}"
                manifest_dir = project / "manifest"
                outside = self.base / (project.name + "-outside")
                manifest_dir.mkdir(parents=True)
                outside.mkdir()
                (manifest_dir / leaf).write_text(safe_text, encoding="utf-8")
                (outside / leaf).write_text(outside_text, encoding="utf-8")
                hook = self._walk_after_parent_replacement(project, manifest_dir, outside)

                with mock.patch.object(dr.os, "walk", hook):
                    result = reader(project)

                self.assertNotIn(forbidden, result)

    def test_reachability_reader_does_not_follow_source_replaced_after_metadata_check(self) -> None:
        source = self.project / "app.py"
        source.write_text("print('safe')\n", encoding="utf-8")
        outside = self.base / "outside.py"
        outside.write_text("import urllib3\n", encoding="utf-8")

        with mock.patch.object(Path, "stat", self._replace_on_first_stat(source, outside)):
            report = analyze_vulnerability_reachability(
                str(self.project),
                findings=[
                    {
                        "package_name": "urllib3",
                        "vulnerability_id": "CVE-2099-0001",
                        "severity": "high",
                    }
                ],
                allowed_roots=(self.base,),
            )

        item = report["items"][0]
        self.assertFalse(item["reachable"])
        self.assertEqual(item["reachability_status"], "not_imported_in_source")

    def test_dependency_reachability_contains_no_unbounded_path_text_reads(self) -> None:
        functions = (
            dr.cargo_dependency_aliases,
            dr.npm_dependency_aliases,
            dr.bundler_autorequired,
            dr.composer_namespaces,
            dr.direct_dependencies,
            dr.build_usage_index,
            dr.jvm_config_mentions,
            dr.npm_tool_mentions,
            dr.cli_tool_mentions,
        )
        unsafe = {
            function.__name__: _path_read_text_calls(function)
            for function in functions
            if _path_read_text_calls(function)
        }
        self.assertEqual(unsafe, {})

    def test_package_reachability_contains_no_unbounded_path_text_reads(self) -> None:
        self.assertEqual(_path_read_text_calls(analyze_vulnerability_reachability), [])


if __name__ == "__main__":
    unittest.main()
