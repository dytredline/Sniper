from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import license_compliance
import monorepo
import supply_chain


class ProjectTreeManifestConsumerTests(unittest.TestCase):
    @staticmethod
    def _restore(project: Path, displaced: Path) -> None:
        if project.is_symlink():
            project.unlink()
        if displaced.exists():
            displaced.rename(project)

    def test_license_reader_keeps_original_root_after_parent_swap(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            project = base / "project"
            displaced = base / "project-original"
            outside = base / "outside"
            project.mkdir()
            outside.mkdir()
            (project / "LICENSE").write_text("SAFE_LICENSE_SENTINEL", encoding="utf-8")
            (outside / "LICENSE").write_text("OUTSIDE_LICENSE_SENTINEL", encoding="utf-8")

            reader = license_compliance._Reader(project)
            try:
                project.rename(displaced)
                project.symlink_to(outside, target_is_directory=True)
                text = reader.read(project / "LICENSE")
            finally:
                reader.close()
                self._restore(project, displaced)

            self.assertEqual(text, "SAFE_LICENSE_SENTINEL")

    def test_monorepo_detection_uses_one_pinned_tree(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            project = base / "project"
            displaced = base / "project-original"
            outside = base / "outside"
            (project / "packages" / "safe").mkdir(parents=True)
            (outside / "packages" / "outside").mkdir(parents=True)
            (project / "package.json").write_text(
                json.dumps({"workspaces": ["packages/*"]}), encoding="utf-8",
            )
            (project / "packages" / "safe" / "package.json").write_text("{}", encoding="utf-8")
            (outside / "package.json").write_text(
                json.dumps({"workspaces": ["packages/*"]}), encoding="utf-8",
            )
            (outside / "packages" / "outside" / "package.json").write_text("{}", encoding="utf-8")

            real_read = monorepo.ProjectTree.read_text
            swapped = False

            def racing_read(tree, target, *args, **kwargs):
                nonlocal swapped
                if not swapped:
                    swapped = True
                    project.rename(displaced)
                    project.symlink_to(outside, target_is_directory=True)
                return real_read(tree, target, *args, **kwargs)

            try:
                with mock.patch.object(monorepo.ProjectTree, "read_text", new=racing_read):
                    result = monorepo.detect(project)
            finally:
                self._restore(project, displaced)

            self.assertTrue(swapped)
            self.assertEqual([item["path"] for item in result["subprojects"]], ["packages/safe"])

    def test_supply_chain_manifest_read_stays_on_pinned_root(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            project = base / "project"
            displaced = base / "project-original"
            outside = base / "outside"
            project.mkdir()
            outside.mkdir()
            (project / "package.json").write_text(
                json.dumps({"name": "acmecorp-app", "dependencies": {"internal-safe": "1"}}),
                encoding="utf-8",
            )
            (outside / "package.json").write_text(
                json.dumps({"name": "acmecorp-app", "dependencies": {"internal-outside": "1"}}),
                encoding="utf-8",
            )

            real_read = supply_chain.ProjectTree.read_text
            swapped = False

            def racing_read(tree, target, *args, **kwargs):
                nonlocal swapped
                if not swapped:
                    swapped = True
                    project.rename(displaced)
                    project.symlink_to(outside, target_is_directory=True)
                return real_read(tree, target, *args, **kwargs)

            try:
                with mock.patch.object(supply_chain.ProjectTree, "read_text", new=racing_read):
                    findings = supply_chain.dependency_confusion_findings(project)
            finally:
                self._restore(project, displaced)

            evidence = " ".join(item["evidence"] for item in findings)
            self.assertTrue(swapped)
            self.assertIn("internal-safe", evidence)
            self.assertNotIn("internal-outside", evidence)


if __name__ == "__main__":
    unittest.main()
