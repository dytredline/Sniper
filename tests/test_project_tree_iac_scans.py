from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

import iac_k8s_project
import iac_tf_project


class ProjectTreeIacScanTests(unittest.TestCase):
    def _assert_parent_swap_reads_pinned_tree(self, module, filename: str, safe: bytes, outside: bytes) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            project = base / "project"
            displaced = base / "project-original"
            external = base / "external"
            project.mkdir()
            external.mkdir()
            (project / filename).write_bytes(safe)
            (external / filename).write_bytes(outside)

            real_read = module.ProjectTree.read_bytes
            observed_payloads: list[bytes] = []
            swapped = False

            def racing_read(tree, project_file, *args, **kwargs):
                nonlocal swapped
                if not swapped:
                    swapped = True
                    project.rename(displaced)
                    project.symlink_to(external, target_is_directory=True)
                payload = real_read(tree, project_file, *args, **kwargs)
                observed_payloads.append(payload)
                return payload

            try:
                with mock.patch.object(module.ProjectTree, "read_bytes", new=racing_read):
                    result = module.scan_tree(project, set())
            finally:
                if project.is_symlink():
                    project.unlink()
                if displaced.exists():
                    displaced.rename(project)

            self.assertTrue(swapped, "test must replace the project pathname after the descriptor is pinned")
            self.assertEqual(observed_payloads, [safe])
            self.assertTrue(result.analysis_complete)

    def test_kubernetes_scan_keeps_parent_descriptor_after_path_swap(self) -> None:
        self._assert_parent_swap_reads_pinned_tree(
            iac_k8s_project,
            "pod.yaml",
            b"apiVersion: v1\nkind: Pod\nmetadata: {name: safe}\nspec: {}\n",
            b"apiVersion: v1\nkind: Pod\nmetadata: {name: outside}\nspec: {}\n",
        )

    def test_terraform_scan_keeps_parent_descriptor_after_path_swap(self) -> None:
        self._assert_parent_swap_reads_pinned_tree(
            iac_tf_project,
            "main.tf",
            b'resource "aws_kms_key" "safe" { enable_key_rotation = true }\n',
            b'resource "aws_db_instance" "outside" { publicly_accessible = true }\n',
        )


if __name__ == "__main__":
    unittest.main()
