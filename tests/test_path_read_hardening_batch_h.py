"""Batch-H: changed/container path reads stay on the verified local inode."""

from __future__ import annotations

import io
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock

import changed_scan
import container_scan
import scan_scope


def _rootfs_tar(path: Path, os_id: str) -> None:
    payload = f"ID={os_id}\nVERSION_ID=1\n".encode()
    with tarfile.open(path, "w") as archive:
        info = tarfile.TarInfo("etc/os-release")
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))


class ChangedScanPathReadTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.root = self.base / "repo"
        self.root.mkdir()

    def test_compute_changes_rejects_leaf_replaced_by_symlink_after_walk(self) -> None:
        outside = self.base / "outside.py"
        outside.write_text("outside = True\n", encoding="utf-8")
        target = self.root / "victim.py"
        target.symlink_to(outside)
        base = changed_scan.BaseTree(self.root, "", "0" * 40, "sha1", {})

        # The injected relative name models a regular entry already yielded by the
        # walker and replaced before the consumer opens it.
        with mock.patch.object(changed_scan, "_walk_worktree", return_value=iter(["victim.py"])), \
                mock.patch.object(changed_scan, "_ignored_paths", return_value=(set(), ())):
            changes = changed_scan.compute_changes(self.root, base, scan_scope.DEFAULT_SCOPE)

        self.assertEqual(changes.added, set())
        self.assertEqual(changes.current_blobs, {})

    def test_import_context_does_not_parse_replaced_symlink(self) -> None:
        outside = self.base / "outside.py"
        outside.write_text("import victim\n", encoding="utf-8")
        (self.root / "a.py").symlink_to(outside)
        (self.root / "victim.py").write_text("VALUE = 1\n", encoding="utf-8")

        with mock.patch.object(changed_scan, "_walk_worktree", return_value=iter(["a.py", "victim.py"])):
            context = changed_scan.import_context(self.root, {"a.py"}, scan_scope.DEFAULT_SCOPE)

        self.assertEqual(context, frozenset({"a.py"}))

    def test_fingerprint_does_not_use_replaced_symlink_contents(self) -> None:
        outside = self.base / "outside.py"
        outside.write_text("SECRET_DEPENDENT_LINE\n", encoding="utf-8")
        (self.root / "a.py").symlink_to(outside)
        clean_root = self.base / "clean"
        clean_root.mkdir()
        (clean_root / "a.py").write_text("", encoding="utf-8")
        finding = {"file": "a.py", "line": 1, "reference": "CWE-X", "category": "x", "title": "t"}

        replaced = changed_scan.context_fingerprints([dict(finding)], self.root)
        unreadable = changed_scan.context_fingerprints([dict(finding)], clean_root)

        self.assertEqual(replaced, unreadable)


class ContainerPathReadTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)

    def test_archive_source_rejects_leaf_symlink(self) -> None:
        outside = self.base / "outside.tar"
        _rootfs_tar(outside, "outside")
        replaced = self.base / "image.tar"
        replaced.symlink_to(outside)

        with self.assertRaises(container_scan.ContainerScanError):
            source = container_scan._Source(replaced)
            source.close()

    def test_rootfs_fallback_reuses_verified_descriptor_after_replacement(self) -> None:
        image = self.base / "image.tar"
        outside = self.base / "outside.tar"
        _rootfs_tar(image, "verified")
        _rootfs_tar(outside, "replaced")
        original_close = container_scan._Source.close
        swapped = False

        def close_and_replace(source: container_scan._Source) -> None:
            nonlocal swapped
            original_close(source)
            if not swapped:
                swapped = True
                image.unlink()
                image.symlink_to(outside)

        with mock.patch.object(container_scan._Source, "close", close_and_replace):
            vfs, meta = container_scan.load_image(image)

        self.assertEqual(meta["format"], "rootfs-tar")
        self.assertEqual(container_scan.parse_os_release(vfs.read("etc/os-release"))["ID"], "verified")

    def test_dockerfile_replacement_is_not_followed(self) -> None:
        dockerfile = self.base / "Dockerfile"
        outside = self.base / "outside.Dockerfile"
        dockerfile.write_text("FROM scratch\n", encoding="utf-8")
        outside.write_text("FROM attacker/image\n", encoding="utf-8")

        def replace_after_initial_check(_value: str, _roots: tuple[Path, ...] | None) -> Path:
            dockerfile.unlink()
            dockerfile.symlink_to(outside)
            return dockerfile

        with mock.patch.object(container_scan, "validate_image_path", side_effect=replace_after_initial_check), \
                self.assertRaises(container_scan.ContainerScanError):
            container_scan._read_dockerfile(str(dockerfile), (self.base,))


if __name__ == "__main__":
    unittest.main()
