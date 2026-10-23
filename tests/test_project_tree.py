from __future__ import annotations

import os
from pathlib import Path, PurePosixPath
import tempfile
import unittest
from unittest import mock

import engine_identity
import project_tree
from project_tree import ProjectTree, ProjectTreeError


class ProjectTreeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="sniper-project-tree-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.project = self.base / "parent" / "project"
        self.project.mkdir(parents=True)

    def test_project_tree_participates_in_engine_identity(self) -> None:
        self.assertIn("project_tree.py", engine_identity.ENGINE_FILES)

    def test_validation_then_project_parent_symlink_swap_is_rejected(self) -> None:
        outside_parent = self.base / "outside"
        outside_project = outside_parent / "project"
        outside_project.mkdir(parents=True)
        (outside_project / "source.txt").write_text("outside", encoding="utf-8")
        validated = self.project.resolve(strict=True)

        parent = self.project.parent
        parent.rename(self.base / "validated-parent")
        parent.symlink_to(outside_parent, target_is_directory=True)

        with self.assertRaises(ProjectTreeError):
            with ProjectTree(validated):
                self.fail("a symlinked absolute component must never become the project root")

    def test_open_root_descriptor_survives_parent_name_replacement(self) -> None:
        (self.project / "source.txt").write_text("verified", encoding="utf-8")
        outside_parent = self.base / "outside"
        outside_project = outside_parent / "project"
        outside_project.mkdir(parents=True)
        (outside_project / "source.txt").write_text("outside", encoding="utf-8")

        with ProjectTree(self.project) as tree:
            parent = self.project.parent
            parent.rename(self.base / "opened-parent")
            parent.symlink_to(outside_parent, target_is_directory=True)
            self.assertEqual(tree.read_text("source.txt", 100), "verified")

    def test_duplicate_owns_an_independent_descriptor_for_the_same_root(self) -> None:
        (self.project / "source.txt").write_text("verified", encoding="utf-8")
        with ProjectTree(self.project) as tree:
            duplicate = tree.duplicate()
        try:
            self.assertEqual(duplicate.read_text("source.txt", 100), "verified")
        finally:
            duplicate.close()
        self.assertTrue(duplicate.closed)

    def test_walk_rejects_intermediate_directory_replaced_after_yield(self) -> None:
        package = self.project / "package"
        package.mkdir()
        (package / "source.py").write_text("SAFE = True\n", encoding="utf-8")
        outside = self.base / "outside-package"
        outside.mkdir()
        (outside / "source.py").write_text("OUTSIDE = True\n", encoding="utf-8")

        with ProjectTree(self.project) as tree:
            walker = tree.walk()
            root_entry = next(walker)
            self.assertEqual(root_entry.directory, PurePosixPath("."))
            self.assertEqual(root_entry.directories, (PurePosixPath("package"),))

            package.rename(self.project / "package-verified")
            package.symlink_to(outside, target_is_directory=True)
            with self.assertRaises(ProjectTreeError):
                next(walker)
            walker.close()

    def test_leaf_symlink_is_rejected_by_read_and_walk(self) -> None:
        outside = self.base / "outside.txt"
        outside.write_text("outside", encoding="utf-8")
        (self.project / "linked.txt").symlink_to(outside)

        with ProjectTree(self.project) as tree:
            with self.assertRaises(ProjectTreeError):
                tree.read_bytes("linked.txt", 100)
            with self.assertRaises(ProjectTreeError):
                list(tree.iter_files())

    def test_non_regular_leaf_is_rejected_without_blocking(self) -> None:
        fifo = self.project / "pipe"
        os.mkfifo(fifo)

        with ProjectTree(self.project) as tree:
            with self.assertRaises(ProjectTreeError):
                tree.read_bytes("pipe", 100)
            with self.assertRaises(ProjectTreeError):
                list(tree.iter_files())

    def test_scanner_mode_omits_unsafe_entries_and_reports_skipped_directories(self) -> None:
        outside = self.base / "outside.txt"
        outside.write_text("outside", encoding="utf-8")
        (self.project / "linked.txt").symlink_to(outside)
        os.mkfifo(self.project / "pipe")
        skipped = self.project / "VeNdOr"
        skipped.mkdir()
        (skipped / "ignored.py").write_text("IGNORED = True\n", encoding="utf-8")
        (self.project / "source.py").write_text("SAFE = True\n", encoding="utf-8")

        with ProjectTree(self.project) as tree:
            entries = list(tree.walk(skip_dirs={"vendor"}, reject_unsafe=False))

        self.assertEqual([item.path.as_posix() for item in entries[0].files], ["source.py"])
        self.assertEqual(
            [item.as_posix() for item in entries[0].skipped_directories],
            ["VeNdOr"],
        )

    def test_regular_walk_and_bounded_reads(self) -> None:
        nested = self.project / "pkg" / "nested"
        nested.mkdir(parents=True)
        (self.project / "root.txt").write_text("root", encoding="utf-8")
        (nested / "source.txt").write_text("merhaba", encoding="utf-8")

        with ProjectTree(self.project) as tree:
            files = list(tree.iter_files())
            self.assertEqual(
                [entry.path for entry in files],
                [PurePosixPath("root.txt"), PurePosixPath("pkg/nested/source.txt")],
            )
            self.assertEqual(tree.read_bytes(files[1], 7), b"merhaba")
            self.assertEqual(tree.read_text(PurePosixPath("root.txt"), 4), "root")

    def test_iterated_regular_file_replacement_is_rejected_by_identity(self) -> None:
        target = self.project / "source.txt"
        target.write_text("first", encoding="utf-8")

        with ProjectTree(self.project) as tree:
            entry = next(tree.iter_files())
            target.rename(self.project / "source-original.txt")
            target.write_text("second", encoding="utf-8")
            with self.assertRaises(ProjectTreeError):
                tree.read_text(entry, 100)

    def test_static_limit_and_growth_after_fstat_are_rejected(self) -> None:
        oversized = self.project / "oversized.bin"
        oversized.write_bytes(b"12345")
        growing = self.project / "growing.bin"
        growing.write_bytes(b"abc")

        with ProjectTree(self.project) as tree:
            with self.assertRaises(ProjectTreeError):
                tree.read_bytes("oversized.bin", 4)

            real_read = project_tree.os.read
            grew = False

            def grow_before_read(fd: int, count: int) -> bytes:
                nonlocal grew
                if not grew:
                    with growing.open("ab") as stream:
                        stream.write(b"def")
                    grew = True
                return real_read(fd, count)

            with mock.patch.object(project_tree.os, "read", side_effect=grow_before_read):
                with self.assertRaises(ProjectTreeError):
                    tree.read_bytes("growing.bin", 3)
            self.assertTrue(grew, "test must grow the already-open file after fstat")

    def test_truncated_read_returns_only_the_stable_prefix(self) -> None:
        (self.project / "large.txt").write_text("abcdef", encoding="utf-8")
        with ProjectTree(self.project) as tree:
            self.assertEqual(tree.read_bytes("large.txt", 3, truncate=True), b"abc")
            self.assertEqual(tree.read_text("large.txt", 4, truncate=True), "abcd")

    def test_relative_paths_are_strictly_validated(self) -> None:
        (self.project / "file.txt").write_text("ok", encoding="utf-8")
        invalid = ("", ".", "../file.txt", "a/../file.txt", "a//file.txt", "/file.txt", "a\\file.txt")

        with ProjectTree(self.project) as tree:
            for value in invalid:
                with self.subTest(value=value), self.assertRaises(ProjectTreeError):
                    tree.read_bytes(value, 100)


if __name__ == "__main__":
    unittest.main()
