from __future__ import annotations

import os
import shutil
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock

import iac_engine
import memsafety_c
import supply_chain


class CodeQL510To513Tests(unittest.TestCase):
    def test_helm_values_root_parent_swap_cannot_escape_project(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            parent = base / "project-parent"
            root = parent / "project"
            chart = root / "charts" / "demo"
            outside_parent = base / "outside"
            outside_chart = outside_parent / "project" / "charts" / "demo"
            chart.mkdir(parents=True)
            outside_chart.mkdir(parents=True)
            (chart / "Chart.yaml").write_text("apiVersion: v2\nname: demo\nversion: 1\n", encoding="utf-8")
            (chart / "values.yaml").write_text("source: safe\n", encoding="utf-8")
            (outside_chart / "Chart.yaml").write_text(
                "apiVersion: v2\nname: outside\nversion: 1\n", encoding="utf-8"
            )
            (outside_chart / "values.yaml").write_text("source: outside\n", encoding="utf-8")

            original_open = os.open
            swapped_parent = base / "project-parent-safe"
            swapped = False

            def swap_root_parent() -> None:
                nonlocal swapped
                if not swapped:
                    swapped = True
                    parent.rename(swapped_parent)
                    parent.symlink_to(outside_parent, target_is_directory=True)

            def swap_before_root_component_open(path, flags, *args, **kwargs):
                path_text = os.fspath(path)
                if not swapped and (path_text == os.fspath(root) or path_text == parent.name):
                    swap_root_parent()
                return original_open(path, flags, *args, **kwargs)

            with mock.patch.object(iac_engine.os, "open", side_effect=swap_before_root_component_open):
                result = iac_engine.helm_values_for(root, "charts/demo/templates/deploy.yaml")

            self.assertTrue(swapped, "test must replace an intermediate component of the absolute root")
            self.assertNotEqual(result, {"source": "outside"})

    def test_helm_values_parent_directory_swap_cannot_escape_project(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            root = base / "project"
            chart = root / "charts" / "demo"
            outside = base / "outside"
            chart.mkdir(parents=True)
            outside.mkdir()
            (chart / "Chart.yaml").write_text("apiVersion: v2\nname: demo\nversion: 1\n", encoding="utf-8")
            (chart / "values.yaml").write_text("source: safe\n", encoding="utf-8")
            (outside / "Chart.yaml").write_text("apiVersion: v2\nname: outside\nversion: 1\n", encoding="utf-8")
            (outside / "values.yaml").write_text("source: outside\n", encoding="utf-8")

            values_path = chart / "values.yaml"
            original_resolve = Path.resolve
            original_open = os.open
            swapped = False

            def perform_swap() -> None:
                nonlocal swapped
                if not swapped:
                    swapped = True
                    shutil.rmtree(chart)
                    chart.symlink_to(outside, target_is_directory=True)

            def swap_after_resolve(path: Path, *args: object, **kwargs: object):
                result = original_resolve(path, *args, **kwargs)
                if path == values_path and not swapped:
                    perform_swap()
                return result

            def swap_before_child_open(path, flags, *args, **kwargs):
                if os.fspath(path) == "demo" and not swapped:
                    perform_swap()
                return original_open(path, flags, *args, **kwargs)

            with mock.patch.object(Path, "resolve", swap_after_resolve), \
                    mock.patch.object(iac_engine.os, "open", side_effect=swap_before_child_open):
                result = iac_engine.helm_values_for(root, "charts/demo/templates/deploy.yaml")

            self.assertTrue(swapped, "test must perform the real parent-directory replacement")
            self.assertNotEqual(result, {"source": "outside"})

    def test_helm_values_normal_chart_and_traversal_edge(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            root = base / "project"
            chart = root / "charts" / "demo"
            chart.mkdir(parents=True)
            (chart / "Chart.yaml").write_text("apiVersion: v2\nname: demo\nversion: 1\n", encoding="utf-8")
            (chart / "values.yaml").write_text("enabled: true\n", encoding="utf-8")
            self.assertEqual(
                iac_engine.helm_values_for(root, "charts/demo/templates/deploy.yaml"),
                {"enabled": True},
            )
            self.assertIsNone(iac_engine.helm_values_for(root, "../outside/templates/deploy.yaml"))

    def test_requirements_glob_rejects_symlink_and_reads_regular_control(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            root = base / "project"
            root.mkdir()
            outside = base / "outside.txt"
            outside.write_text("internal-secret==1\n", encoding="utf-8")
            (root / "requirements-linked.txt").symlink_to(outside)
            self.assertEqual(supply_chain.dependency_confusion_findings(root), [])

            (root / "requirements-linked.txt").unlink()
            (root / "requirements-prod.txt").write_text("internal-utils==1\n", encoding="utf-8")
            findings = supply_chain.dependency_confusion_findings(root)
            self.assertTrue(any("internal-utils" in finding["evidence"] for finding in findings))

    def test_define_comment_stripping_is_linear_and_preserves_semantics(self) -> None:
        adversarial = "#define SIZE /*" + "a/*" * 8_000 + "\n"
        started = time.perf_counter()
        self.assertEqual(memsafety_c._collect_defines(adversarial), {})
        elapsed = time.perf_counter() - started
        self.assertLess(elapsed, 0.10, f"define comment stripping took {elapsed:.3f}s")

        defines = memsafety_c._collect_defines(
            "#define SIZE (8 /* units */ + 2) // trailing comment\n"
            "#define OTHER SIZE + 1\n"
            "#define BROKEN /* unterminated // trailing comment\n"
        )
        self.assertEqual(set(defines), {"SIZE", "OTHER"})

    def test_repeated_closed_define_comments_are_linear(self) -> None:
        repetitions = 16_000
        adversarial = "/*a*/x" * repetitions
        started = time.perf_counter()
        self.assertEqual(memsafety_c._strip_define_comments(adversarial), "x" * repetitions)
        elapsed = time.perf_counter() - started
        self.assertLess(elapsed, 0.10, f"closed define comments took {elapsed:.3f}s")


if __name__ == "__main__":
    unittest.main()
