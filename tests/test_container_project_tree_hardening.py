from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import container_scan
from project_tree import ProjectTree


class ContainerPinnedPathTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)

    @staticmethod
    def _rootfs(root: Path, os_id: str) -> None:
        (root / "etc").mkdir(parents=True)
        (root / "etc" / "os-release").write_text(
            f"ID={os_id}\nVERSION_ID=1\n", encoding="utf-8",
        )

    @staticmethod
    def _oci_layout(root: Path, index: str = '{"safe": true}') -> None:
        root.mkdir(parents=True)
        (root / "oci-layout").write_text('{"imageLayoutVersion":"1.0.0"}', encoding="utf-8")
        (root / "index.json").write_text(index, encoding="utf-8")

    def test_rootfs_parent_replacement_keeps_original_directory_descriptor(self) -> None:
        root = self.base / "rootfs"
        root.mkdir()
        self._rootfs(root, "verified")
        source = container_scan._Source(root)
        parked = self.base / "original-rootfs"
        root.rename(parked)
        root.mkdir()
        self._rootfs(root, "attacker")

        vfs, meta = container_scan.load_image(source)

        self.assertEqual(meta["format"], "rootfs-dir")
        self.assertEqual(container_scan.parse_os_release(vfs.read("etc/os-release"))["ID"], "verified")

    def test_oci_parent_replacement_keeps_original_records(self) -> None:
        root = self.base / "oci"
        self._oci_layout(root)
        source = container_scan._Source(root)
        parked = self.base / "original-oci"
        root.rename(parked)
        self._oci_layout(root, '{"safe": false}')
        try:
            self.assertEqual(source.read_json("index.json"), {"safe": True})
        finally:
            source.close()

    def test_oci_intermediate_directory_replacement_is_rejected(self) -> None:
        root = self.base / "oci"
        self._oci_layout(root)
        digest = "a" * 64
        blob = root / "blobs" / "sha256" / digest
        blob.parent.mkdir(parents=True)
        blob.write_bytes(b"verified")
        source = container_scan._Source(root)
        old = root / "old-blobs"
        (root / "blobs").rename(old)
        replacement = root / "blobs" / "sha256" / digest
        replacement.parent.mkdir(parents=True)
        replacement.write_bytes(b"attacker")
        try:
            with self.assertRaises(container_scan.ContainerScanError):
                with source.open(f"blobs/sha256/{digest}") as handle:
                    handle.read()
        finally:
            source.close()

    def test_rootfs_file_replaced_after_walk_fails_closed(self) -> None:
        root = self.base / "rootfs"
        root.mkdir()
        self._rootfs(root, "verified")
        original = ProjectTree.read_bytes
        swapped = False

        def replace_before_read(tree, relative, *args, **kwargs):
            nonlocal swapped
            if not swapped and getattr(relative, "name", "") == "os-release":
                replacement = root / "replacement"
                replacement.write_text("ID=attacker\nVERSION_ID=1\n", encoding="utf-8")
                os.replace(replacement, root / "etc" / "os-release")
                swapped = True
            return original(tree, relative, *args, **kwargs)

        with mock.patch.object(ProjectTree, "read_bytes", new=replace_before_read):
            with self.assertRaises(container_scan.ContainerScanError):
                container_scan.load_image(root)

    def test_dockerfile_intermediate_symlink_swap_is_rejected(self) -> None:
        project = self.base / "project"
        docker_dir = project / "docker"
        docker_dir.mkdir(parents=True)
        dockerfile = docker_dir / "Dockerfile"
        dockerfile.write_text("FROM scratch\n", encoding="utf-8")
        outside = self.base / "outside"
        outside.mkdir()
        (outside / "Dockerfile").write_text("FROM attacker/image\n", encoding="utf-8")
        original_allowed = container_scan._allowed_input_path

        def swap_parent(value: str, roots: tuple[Path, ...] | None) -> Path:
            path = original_allowed(value, roots)
            docker_dir.rename(project / "original-docker")
            docker_dir.symlink_to(outside, target_is_directory=True)
            return path

        with mock.patch.object(container_scan, "_allowed_input_path", side_effect=swap_parent), \
                self.assertRaises(container_scan.ContainerScanError):
            container_scan._read_dockerfile(str(dockerfile), (self.base,))


if __name__ == "__main__":
    unittest.main()
