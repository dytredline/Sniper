from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import dos_resilience_redos_auditor
import host_cis_hardening_auditor
import privacy_dataflow_auditor
import project_tree
from project_tree import ProjectTreeError
import secret_intelligence_auditor
import supply_chain_slsa_auditor
import zero_trust_mesh_auditor


_AUDITORS = (
    (dos_resilience_redos_auditor, "audit_dos_resilience_project"),
    (host_cis_hardening_auditor, "audit_host_config_project"),
    (privacy_dataflow_auditor, "audit_privacy_project"),
    (secret_intelligence_auditor, "audit_secrets_project"),
    (zero_trust_mesh_auditor, "audit_zero_trust_project"),
    (supply_chain_slsa_auditor, "audit_supply_chain_slsa"),
)


class ProjectTreeAuditorsBatchBTests(unittest.TestCase):
    def _write_minimal_project(self, root: Path) -> None:
        (root / "sshd_config").write_text("PermitRootLogin no\n", encoding="utf-8")
        (root / "app.py").write_text("print('safe')\n", encoding="utf-8")
        (root / "service.yaml").write_text(
            "apiVersion: v1\nkind: Service\nmetadata:\n  name: demo\n",
            encoding="utf-8",
        )
        (root / "package.json").write_text(
            '{"name":"demo","version":"1.0.0","dependencies":{}}',
            encoding="utf-8",
        )

    def test_parent_swap_after_validation_is_rejected_by_every_auditor(self) -> None:
        for module, function_name in _AUDITORS:
            with self.subTest(auditor=function_name), tempfile.TemporaryDirectory() as tmp:
                base = Path(tmp).resolve()
                original_parent = base / "checked"
                project = original_parent / "project"
                attacker_parent = base / "attacker"
                attacker_project = attacker_parent / "project"
                project.mkdir(parents=True)
                attacker_project.mkdir(parents=True)
                self._write_minimal_project(project)
                self._write_minimal_project(attacker_project)
                real_validate = module.validate_project_path
                swapped = False

                def validate_then_swap(*args, **kwargs):
                    nonlocal swapped
                    validated = real_validate(*args, **kwargs)
                    preserved = base / "checked-preserved"
                    original_parent.rename(preserved)
                    original_parent.symlink_to(attacker_parent, target_is_directory=True)
                    swapped = True
                    return validated

                patches = [
                    mock.patch.object(module, "validate_project_path", side_effect=validate_then_swap),
                    mock.patch("taint_flow.activate_project", return_value=None),
                    mock.patch("taint_flow.activate_project_js_handlers", return_value=None),
                    mock.patch.object(
                        supply_chain_slsa_auditor,
                        "discover_components",
                        return_value=(project, []),
                    ),
                ]
                with patches[0], patches[1], patches[2], patches[3]:
                    with self.assertRaises(ProjectTreeError):
                        getattr(module, function_name)(str(project), allowed_roots=(base,))
                self.assertTrue(swapped)

    def test_intermediate_directory_swap_during_walk_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            project = base / "project"
            original = project / "configs"
            attacker = base / "attacker" / "configs"
            original.mkdir(parents=True)
            attacker.mkdir(parents=True)
            (original / "app.env").write_text("API_KEY=safe-placeholder\n", encoding="utf-8")
            (attacker / "app.env").write_text("API_KEY=attacker-controlled\n", encoding="utf-8")
            real_open = os.open
            swapped = False

            def swap_then_open(path, flags, *args, **kwargs):
                nonlocal swapped
                if not swapped and path == "configs" and kwargs.get("dir_fd") is not None:
                    original.rename(project / "configs-preserved")
                    original.symlink_to(attacker, target_is_directory=True)
                    swapped = True
                return real_open(path, flags, *args, **kwargs)

            with mock.patch.object(project_tree.os, "open", side_effect=swap_then_open):
                with self.assertRaises(ProjectTreeError):
                    secret_intelligence_auditor.audit_secrets_project(
                        str(project), allowed_roots=(base,)
                    )
            self.assertTrue(swapped)

    def test_normal_reports_keep_logical_paths_and_module_contracts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            project = base / "project"
            (project / "src").mkdir(parents=True)
            (project / "etc" / "ssh").mkdir(parents=True)
            (project / ".github" / "workflows").mkdir(parents=True)
            (project / "dist").mkdir(parents=True)
            (project / "src" / "client.py").write_text(
                "import requests\nrequests.get(url)\nemail = user.email\n",
                encoding="utf-8",
            )
            (project / "etc" / "ssh" / "sshd_config").write_text(
                "PermitRootLogin yes\n",
                encoding="utf-8",
            )
            (project / "mesh.yaml").write_text(
                "apiVersion: v1\nkind: Service\nmetadata:\n  name: demo\n",
                encoding="utf-8",
            )
            (project / ".env").write_text(
                "API_KEY=" + "sk" + "_live_1234567890abcdefghijklmnop\n",
                encoding="utf-8",
            )
            (project / "package.json").write_text(
                '{"name":"demo","version":"1.0.0","license":"GPL-3.0","dependencies":{}}',
                encoding="utf-8",
            )
            (project / ".github" / "workflows" / "ci.yml").write_text(
                "steps:\n  - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567\n",
                encoding="utf-8",
            )
            (project / "bom.cdx.json").write_text("{}", encoding="utf-8")
            (project / "dist" / "MANIFEST.json").write_text(
                '{"format":"sniper-release/1","version":"1.2.3","files":[]}',
                encoding="utf-8",
            )
            (project / "dist" / "MANIFEST.json.sig").write_text("signature", encoding="utf-8")

            reports = (
                dos_resilience_redos_auditor.audit_dos_resilience_project(
                    str(project), allowed_roots=(base,)
                ),
                host_cis_hardening_auditor.audit_host_config_project(
                    str(project), allowed_roots=(base,)
                ),
                privacy_dataflow_auditor.audit_privacy_project(
                    str(project), allowed_roots=(base,)
                ),
                secret_intelligence_auditor.audit_secrets_project(
                    str(project), allowed_roots=(base,)
                ),
                zero_trust_mesh_auditor.audit_zero_trust_project(
                    str(project), allowed_roots=(base,)
                ),
            )
            expected_formats = (
                "sniper-dos-resilience-audit-v1",
                "sniper-host-cis-hardening-audit-v1",
                "sniper-privacy-dataflow-audit-v1",
                "sniper-secret-intelligence-audit-v1",
                "sniper-zero-trust-mesh-audit-v1",
            )
            for report, expected_format in zip(reports, expected_formats):
                with self.subTest(format=expected_format):
                    self.assertEqual(report["format"], expected_format)
                    self.assertEqual(report["project_path"], str(project))
                    self.assertGreaterEqual(report["scanned_files"], 1)
                    for finding in report["findings"]:
                        if "file" in finding:
                            self.assertFalse(str(finding["file"]).startswith("/"))

            slsa = supply_chain_slsa_auditor.audit_supply_chain_slsa(
                str(project), allowed_roots=(base,)
            )
            self.assertEqual(slsa["format"], "sniper-supply-chain-slsa-audit-v1")
            self.assertEqual(slsa["provenance_files"]["sbom"], ["bom.cdx.json"])
            self.assertEqual(slsa["release_manifest"]["path"], "dist/MANIFEST.json")
            self.assertTrue(slsa["release_manifest"]["signed"])
            self.assertEqual(slsa["unpinned_actions"], [])
            self.assertTrue(any(item["license"] == "GPL-3.0" for item in slsa["license_risks"]))


if __name__ == "__main__":
    unittest.main()
