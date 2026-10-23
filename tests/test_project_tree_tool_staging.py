from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import npm_audit_active
import sbom_scan
import semgrep_tls_verify_filter
import trivy_config_active
import trivy_kubernetes_active
import trivy_vuln_active


class ProjectTreeToolStagingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="sniper-project-tree-staging-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()

    def test_parent_swap_never_stages_outside_terraform_content(self) -> None:
        project = self.base / "parent" / "project"
        project.mkdir(parents=True)
        (project / "main.tf").write_text("# INSIDE_CONTENT\n", encoding="utf-8")
        validated = project.resolve(strict=True)

        outside_parent = self.base / "outside-parent"
        outside_project = outside_parent / "project"
        outside_project.mkdir(parents=True)
        (outside_project / "main.tf").write_text("# OUTSIDE_STAGING_SENTINEL\n", encoding="utf-8")

        def validate_then_swap(_value: str, *, allowed_roots=None) -> Path:
            project.parent.rename(self.base / "validated-parent")
            project.parent.symlink_to(outside_parent, target_is_directory=True)
            return validated

        lock_fd = os.open("/dev/null", os.O_RDONLY)

        class MustNotRun:
            def __init__(self, command, **_kwargs) -> None:
                staged = Path(command[-1]) / "main.tf"
                content = staged.read_text(encoding="utf-8")
                raise AssertionError(f"dış içerik staging alanına taşındı: {content!r}")

        with mock.patch.object(
            trivy_config_active,
            "validate_project_path",
            side_effect=validate_then_swap,
        ), mock.patch.object(
            trivy_config_active,
            "_trusted_binary",
            return_value=Path("/bin/true"),
        ), mock.patch.object(
            trivy_config_active,
            "_scan_lock",
            return_value=lock_fd,
        ), mock.patch.object(
            trivy_config_active.subprocess,
            "Popen",
            MustNotRun,
        ):
            with self.assertRaises(ValueError):
                trivy_config_active.run_local_trivy_terraform(str(project), "main.tf")

    def test_root_level_tool_inputs_keep_bytes_and_validation_contracts(self) -> None:
        project = self.base / "normal" / "project"
        project.mkdir(parents=True)
        lock = {
            "name": "demo",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies": {"left-pad": "1.3.0"}},
                "node_modules/left-pad": {
                    "version": "1.3.0",
                    "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
                },
            },
        }
        (project / "package-lock.json").write_text(json.dumps(lock), encoding="utf-8")
        (project / "Dockerfile").write_bytes(b"FROM scratch\n")
        (project / "main.tf").write_bytes(b'resource "null_resource" "demo" {}\n')
        (project / "pod.yaml").write_bytes(b"apiVersion: v1\nkind: Pod\n")
        (project / "requirements.txt").write_bytes(b"requests==2.31.0\n")

        parsed_lock, manifest = npm_audit_active._read_lockfile(project)
        self.assertEqual(parsed_lock["lockfileVersion"], 3)
        self.assertEqual(manifest["dependencies"], {"left-pad": "1.3.0"})
        self.assertEqual(trivy_config_active._read_dockerfile(project), b"FROM scratch\n")
        self.assertEqual(
            trivy_config_active._read_terraform_file(project, "main.tf"),
            b'resource "null_resource" "demo" {}\n',
        )
        self.assertEqual(
            trivy_kubernetes_active._read_manifest(project, "pod.yaml"),
            b"apiVersion: v1\nkind: Pod\n",
        )
        self.assertEqual(
            trivy_vuln_active._read_root_project_file(
                project,
                "requirements.txt",
                1_000_000,
                allow_empty=True,
            ),
            b"requests==2.31.0\n",
        )

    def test_sbom_reader_rejects_leaf_symlink_and_keeps_normal_bytes(self) -> None:
        directory = self.base / "sbom"
        directory.mkdir()
        document = b'{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}'
        bom = directory / "bom.json"
        bom.write_bytes(document)
        self.assertEqual(sbom_scan._read_sbom_file(bom), document)
        bom.rename(directory / "real.json")
        bom.symlink_to(directory / "real.json")
        with self.assertRaises(sbom_scan.SbomScanError):
            sbom_scan._read_sbom_file(bom)

    def test_semgrep_filter_reads_identity_bound_relative_python_source(self) -> None:
        source_root = self.base / "semgrep"
        source_root.mkdir()
        source = source_root / "client.py"
        source.write_text(
            "import requests\nrequests.get('https://example.invalid', verify=False)\n",
            encoding="utf-8",
        )
        candidate = {
            "check_id": "sniper.python.requests-get-verify-false",
            "path": "client.py",
            "start": {"line": 2, "col": 1},
        }

        self.assertEqual(
            semgrep_tls_verify_filter.filter_direct_requests_tls_findings([candidate], source_root),
            [candidate],
        )

        outside = self.base / "outside.py"
        outside.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
        source.unlink()
        source.symlink_to(outside)
        with self.assertRaises(ValueError):
            semgrep_tls_verify_filter.filter_direct_requests_tls_findings([candidate], source_root)


if __name__ == "__main__":
    unittest.main()
