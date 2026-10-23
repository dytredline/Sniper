from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import c_build
import joern_active
import memsafety_clang
from project_tree import ProjectTree, ProjectTreeError


class CompilerProjectTreeTests(unittest.TestCase):
    def test_c_build_keeps_pinned_parent_after_path_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "project"
            root.mkdir()
            (root / "a.c").write_text("int safe;\n", encoding="utf-8")
            (root / "Makefile").write_text("CFLAGS=-DSAFE\n", encoding="utf-8")
            with ProjectTree(str(root)) as tree:
                parked = base / "original"
                root.rename(parked)
                root.mkdir()
                (root / "a.c").write_text("int attacker;\n", encoding="utf-8")
                (root / "Makefile").write_text("CFLAGS=-DEVIL\n", encoding="utf-8")
                info = c_build.load(root, project_tree=tree)
            self.assertEqual(info.flags_for(root / "a.c").args, ["-DSAFE"])

    def test_c_build_rejects_config_replaced_after_walk(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a.c").write_text("int safe;\n", encoding="utf-8")
            makefile = root / "Makefile"
            makefile.write_text("CFLAGS=-DSAFE\n", encoding="utf-8")
            original = ProjectTree.read_text
            replaced = False

            def swap(tree, relative, *args, **kwargs):
                nonlocal replaced
                if not replaced and getattr(relative, "name", "") == "Makefile":
                    replacement = root / "replacement"
                    replacement.write_text("CFLAGS=-DEVIL\n", encoding="utf-8")
                    os.replace(replacement, makefile)
                    replaced = True
                return original(tree, relative, *args, **kwargs)

            with mock.patch.object(ProjectTree, "read_text", new=swap):
                with self.assertRaises(ProjectTreeError):
                    c_build.load(root)

    def test_clang_receives_only_verified_private_stage(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "project"
            root.mkdir()
            source = root / "a.c"
            source.write_text("/* SAFE */ int x;\n", encoding="utf-8")
            seen: list[tuple[str, str]] = []

            def replace_parent(*_args, **_kwargs):
                parked = base / "original"
                root.rename(parked)
                root.mkdir()
                (root / "a.c").write_text("/* EVIL */ int x;\n", encoding="utf-8")
                return None

            def run(_clang, path, *_args, **_kwargs):
                seen.append((str(path), path.read_text(encoding="utf-8")))
                return [], "yok", "plain"

            with mock.patch.object(memsafety_clang, "binary", return_value="/usr/bin/clang"), \
                    mock.patch.object(c_build, "load", side_effect=replace_parent), \
                    mock.patch.object(memsafety_clang, "_run_with_build", side_effect=run):
                result = memsafety_clang.analyze_files(root, [source], workers=1)
            self.assertEqual(result["status"], "ok")
            self.assertEqual([text for _path, text in seen], ["/* SAFE */ int x;\n"])
            self.assertNotIn(str(root), seen[0][0])
            self.assertIn("sniper-clang-stage-", seen[0][0])

    def test_joern_copy_uses_record_from_pinned_parent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "project"
            root.mkdir()
            source = root / "src" / "a.c"
            source.parent.mkdir()
            source.write_text("/* SAFE */\n", encoding="utf-8")
            destination = base / "stage"
            destination.mkdir()
            records = {}
            with ProjectTree(str(root)) as tree:
                sources = joern_active.collect_sources(root, project_tree=tree, records_out=records)
                parked = base / "original"
                root.rename(parked)
                (root / "src").mkdir(parents=True)
                (root / "src" / "a.c").write_text("/* EVIL */\n", encoding="utf-8")
                copied = joern_active._copy_sources(
                    root,
                    sources["c"],
                    destination,
                    "c",
                    project_tree=tree,
                    records=records,
                )
            self.assertEqual(copied, 1)
            self.assertEqual((destination / "src" / "a.c").read_text(encoding="utf-8"), "/* SAFE */\n")

    def test_joern_rejects_source_replaced_after_collection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "project"
            root.mkdir()
            source = root / "a.c"
            source.write_text("/* SAFE */\n", encoding="utf-8")
            destination = Path(tmp) / "stage"
            destination.mkdir()
            records = {}
            with ProjectTree(str(root)) as tree:
                sources = joern_active.collect_sources(root, project_tree=tree, records_out=records)
                replacement = root / "replacement.c"
                replacement.write_text("/* EVIL */\n", encoding="utf-8")
                os.replace(replacement, source)
                with self.assertRaises(ProjectTreeError):
                    joern_active._copy_sources(
                        root,
                        sources["c"],
                        destination,
                        "c",
                        project_tree=tree,
                        records=records,
                    )


if __name__ == "__main__":
    unittest.main()
