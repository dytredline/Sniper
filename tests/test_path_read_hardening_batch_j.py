from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

import monorepo
import openapi_contract_auditor
import safe_file_read
import sbom_formats
import supply_chain
import iac_k8s_project
import iac_tf_project


class PathReadHardeningBatchJTests(unittest.TestCase):
    @staticmethod
    def _swap_when_checked(victim: Path, replacement: Path):
        original = Path.is_file
        swapped = False

        def racing_is_file(path: Path) -> bool:
            nonlocal swapped
            if path == victim and not swapped:
                swapped = True
                victim.unlink()
                victim.symlink_to(replacement)
            return original(path)

        return racing_is_file

    def test_manifest_helpers_do_not_follow_replacement_at_open(self) -> None:
        readers = (
            lambda path: monorepo._read(path),
            lambda path: sbom_formats._read(path),
            lambda path: supply_chain._read_json(path, 4096),
        )
        real_open = safe_file_read.os.open
        for reader in readers:
            with self.subTest(reader=reader):
                with tempfile.TemporaryDirectory() as temp:
                    root = Path(temp)
                    victim = root / "manifest.json"
                    secret = root / "secret.json"
                    victim.write_text('{"scope":"public"}', encoding="utf-8")
                    secret.write_text('{"scope":"private"}', encoding="utf-8")
                    swapped = False

                    def racing_open(path, flags, *args, **kwargs):
                        nonlocal swapped
                        if not swapped and (Path(path) == victim or path == "manifest.json"):
                            swapped = True
                            victim.unlink()
                            victim.symlink_to(secret)
                        return real_open(path, flags, *args, **kwargs)

                    with mock.patch.object(safe_file_read.os, "open", side_effect=racing_open):
                        result = reader(victim)
                    self.assertTrue(swapped, "test must exercise the open-time replacement")
                    self.assertIsNone(result)

    def test_project_contract_reader_rejects_file_replaced_by_symlink_after_check(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            project = base / "project"
            project.mkdir()
            victim = project / "openapi.yaml"
            victim.write_text("openapi: 3.0.0\ninfo: {title: local, version: '1'}\npaths: {}\n", encoding="utf-8")
            external = base / "external.yaml"
            external.write_text("openapi: 3.0.0\ninfo: {title: external, version: '1'}\npaths: {}\n", encoding="utf-8")
            real_read = openapi_contract_auditor.ProjectTree.read_text
            swapped = False

            def racing_read(tree, project_file, *args, **kwargs):
                nonlocal swapped
                if project_file.path.as_posix() == "openapi.yaml" and not swapped:
                    swapped = True
                    victim.unlink()
                    victim.symlink_to(external)
                return real_read(tree, project_file, *args, **kwargs)

            with mock.patch.object(openapi_contract_auditor.ProjectTree, "read_text", new=racing_read):
                with self.assertRaises(openapi_contract_auditor.ProjectRejected):
                    openapi_contract_auditor.audit_project_api_contracts(
                        str(project), allowed_roots=(base,)
                    )

        self.assertTrue(swapped, "test must replace the selected contract before descriptor-relative open")

    def test_k8s_total_budget_uses_bytes_actually_read_after_growth(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "manifest.yaml").write_text("x", encoding="utf-8")
            grown = "apiVersion: v1\nkind: Pod\n"
            with mock.patch.object(iac_k8s_project, "MAX_TOTAL_BYTES", 5), \
                    mock.patch.object(iac_k8s_project.ProjectTree, "read_bytes", return_value=grown.encode()):
                result = iac_k8s_project.scan_tree(root, set())

        self.assertFalse(result.analysis_complete)
        self.assertIn("total-bytes", result.limitations)

    def test_terraform_total_budget_uses_bytes_actually_read_after_growth(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "main.tf").write_text("x", encoding="utf-8")
            grown = 'resource "x" "y" {}\n'
            with mock.patch.object(iac_tf_project, "MAX_TF_TOTAL_BYTES", 5), \
                    mock.patch.object(iac_tf_project.ProjectTree, "read_bytes", return_value=grown.encode()):
                result = iac_tf_project.scan_tree(root, set())

        self.assertFalse(result.analysis_complete)
        self.assertIn("total-bytes", result.limitations)

    def test_terraform_invalid_utf8_still_consumes_candidate_budget(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "a.tf").write_bytes(b"x")
            (root / "b.tf").write_bytes(b"x")
            with mock.patch.object(iac_tf_project, "MAX_TF_FILES", 1), \
                    mock.patch.object(iac_tf_project.ProjectTree, "read_bytes", return_value=b"\xff"):
                result = iac_tf_project.scan_tree(root, set())

        self.assertFalse(result.analysis_complete)
        self.assertIn("file", result.limitations)


if __name__ == "__main__":
    unittest.main()
