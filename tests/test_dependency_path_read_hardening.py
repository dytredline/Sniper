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

    def test_npm_alias_reader_does_not_follow_file_replaced_after_metadata_check(self) -> None:
        manifest = self.project / "package.json"
        manifest.write_text(json.dumps({"dependencies": {"left-pad": "1.0.0"}}), encoding="utf-8")
        outside = self.base / "outside-package.json"
        outside.write_text(
            json.dumps({"dependencies": {"safealias": "npm:evil-package@1.0.0"}}),
            encoding="utf-8",
        )

        with mock.patch.object(Path, "stat", self._replace_on_first_stat(manifest, outside)):
            aliases = dr.npm_dependency_aliases(self.project, ())

        self.assertNotIn("evil-package", aliases)

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
