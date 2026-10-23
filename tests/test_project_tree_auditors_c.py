from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import crypto_cbom_pqc_auditor
import desktop_protocol_security_auditor
import mobile_security_auditor
import openapi_contract_auditor
import project_tree
import web3_iot_firmware_auditor
from project_analyzer import ProjectRejected


class ProjectTreeAuditorsBatchCTests(unittest.TestCase):
    def test_all_project_auditors_keep_normal_results_and_logical_paths(self) -> None:
        with tempfile.TemporaryDirectory(prefix="sniper_tree_c_crypto_") as temp:
            base = Path(temp).resolve()
            project = base / "project"
            (project / "src").mkdir(parents=True)
            (project / "src" / "crypto.py").write_text(
                "import hashlib\ndigest = hashlib.md5(b'legacy').hexdigest()\n",
                encoding="utf-8",
            )
            report = crypto_cbom_pqc_auditor.audit_crypto_pqc_project(
                str(project), allowed_roots=(base,)
            )
            self.assertEqual(report["format"], "sniper-crypto-cbom-pqc-audit-v1")
            self.assertEqual(report["scanned_files"], 1)
            self.assertIn("src/crypto.py", {item.get("file") for item in report["findings"]})

        with tempfile.TemporaryDirectory(prefix="sniper_tree_c_desktop_") as temp:
            base = Path(temp).resolve()
            project = base / "project"
            (project / "src").mkdir(parents=True)
            (project / "src" / "main.js").write_text(
                "const {BrowserWindow} = require('electron');\n"
                "new BrowserWindow({webPreferences: {nodeIntegration: true}});\n",
                encoding="utf-8",
            )
            report = desktop_protocol_security_auditor.audit_desktop_app_project(
                str(project), allowed_roots=(base,)
            )
            self.assertEqual(report["format"], "sniper-desktop-security-audit-v1")
            self.assertEqual(report["scanned_files"], 1)
            self.assertIn("src/main.js", {item.get("file") for item in report["findings"]})

        with tempfile.TemporaryDirectory(prefix="sniper_tree_c_mobile_") as temp:
            base = Path(temp).resolve()
            project = base / "project"
            (project / "lib").mkdir(parents=True)
            (project / "lib" / "main.dart").write_text("void main() {}\n", encoding="utf-8")
            report = mobile_security_auditor.audit_mobile_project(
                str(project), allowed_roots=(base,)
            )
            self.assertEqual(report["format"], "sniper-mobile-security-audit-v1")
            self.assertEqual(report["scanned_files"], 1)
            self.assertIn("flutter", report["detected_platforms"])

        with tempfile.TemporaryDirectory(prefix="sniper_tree_c_openapi_") as temp:
            base = Path(temp).resolve()
            project = base / "project"
            (project / "spec").mkdir(parents=True)
            (project / "spec" / "openapi.json").write_text(
                json.dumps({
                    "openapi": "3.0.3",
                    "info": {"title": "Local", "version": "1"},
                    "paths": {},
                }),
                encoding="utf-8",
            )
            report = openapi_contract_auditor.audit_project_api_contracts(
                str(project), allowed_roots=(base,)
            )
            self.assertEqual(report["format"], "sniper-project-api-contract-audit-v1")
            self.assertEqual(report["contracts_audited"], 1)
            self.assertEqual(report["contracts"][0]["source_name"], "spec/openapi.json")

        with tempfile.TemporaryDirectory(prefix="sniper_tree_c_web3_") as temp:
            base = Path(temp).resolve()
            project = base / "project"
            (project / "contracts").mkdir(parents=True)
            (project / "contracts" / "Vault.sol").write_text(
                "contract Vault { function auth() public { require(tx.origin == owner); } }\n",
                encoding="utf-8",
            )
            report = web3_iot_firmware_auditor.audit_web3_and_iot_project(
                str(project), allowed_roots=(base,)
            )
            self.assertEqual(report["format"], "sniper-web3-iot-project-audit-v1")
            self.assertEqual(report["scanned_files"], 1)
            self.assertEqual(report["smart_contract_files"], 1)
            self.assertIn("contracts/Vault.sol", {item.get("file") for item in report["findings"]})

    def test_parent_swap_after_validation_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="sniper_tree_c_parent_") as temp:
            base = Path(temp).resolve()
            parent = base / "owner"
            project = parent / "project"
            project.mkdir(parents=True)
            (project / "crypto.py").write_text("safe = True\n", encoding="utf-8")

            attacker_parent = base / "attacker"
            attacker_project = attacker_parent / "project"
            attacker_project.mkdir(parents=True)
            (attacker_project / "crypto.py").write_text(
                "import hashlib\nhashlib.md5(b'attacker')\n", encoding="utf-8"
            )
            held_parent = base / "owner-held"
            original_validate = crypto_cbom_pqc_auditor.validate_project_path
            swapped = False

            def validate_then_swap(value, allowed_roots=None):
                nonlocal swapped
                resolved = original_validate(value, allowed_roots)
                parent.rename(held_parent)
                parent.symlink_to(attacker_parent, target_is_directory=True)
                swapped = True
                return resolved

            with mock.patch.object(
                crypto_cbom_pqc_auditor,
                "validate_project_path",
                side_effect=validate_then_swap,
            ):
                with self.assertRaises(ProjectRejected):
                    crypto_cbom_pqc_auditor.audit_crypto_pqc_project(
                        str(project), allowed_roots=(base,)
                    )
            self.assertTrue(swapped, "test must replace the validated parent")

    def test_intermediate_swap_before_open_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="sniper_tree_c_intermediate_") as temp:
            base = Path(temp).resolve()
            project = base / "project"
            source = project / "src"
            source.mkdir(parents=True)
            victim = source / "openapi.json"
            victim.write_text(
                json.dumps({"openapi": "3.0.3", "info": {"title": "Local", "version": "1"}, "paths": {}}),
                encoding="utf-8",
            )

            attacker_source = base / "attacker-src"
            attacker_source.mkdir()
            (attacker_source / "openapi.json").write_text(
                json.dumps({"openapi": "3.0.3", "info": {"title": "Attacker", "version": "1"}, "paths": {}}),
                encoding="utf-8",
            )
            held_source = project / "src-held"
            real_open = project_tree.os.open
            swapped = False

            def racing_open(path, flags, *args, **kwargs):
                nonlocal swapped
                if not swapped and (os.fspath(path) == "src" or Path(path) == victim):
                    source.rename(held_source)
                    source.symlink_to(attacker_source, target_is_directory=True)
                    swapped = True
                return real_open(path, flags, *args, **kwargs)

            with mock.patch.object(project_tree.os, "open", side_effect=racing_open):
                with self.assertRaises(ProjectRejected):
                    openapi_contract_auditor.audit_project_api_contracts(
                        str(project), allowed_roots=(base,)
                    )
            self.assertTrue(swapped, "test must replace the intermediate directory")

    def test_skip_limits_and_encoding_semantics_are_preserved(self) -> None:
        with tempfile.TemporaryDirectory(prefix="sniper_tree_c_semantics_") as temp:
            base = Path(temp).resolve()
            project = base / "project"
            (project / "node_modules").mkdir(parents=True)
            (project / "node_modules" / "ignored.sol").write_text(
                "contract Bad { function auth() public { require(tx.origin == owner); } }\n",
                encoding="utf-8",
            )
            (project / "empty.dart").write_bytes(b"")
            (project / "openapi.json").write_bytes(b"\xff")
            (project / "oversized.sol").write_bytes(b"x" * 9)
            os.mkfifo(project / "ignored-pipe.sol")

            mobile = mobile_security_auditor.audit_mobile_project(str(project), allowed_roots=(base,))
            contracts = openapi_contract_auditor.audit_project_api_contracts(str(project), allowed_roots=(base,))
            with mock.patch.object(web3_iot_firmware_auditor, "MAX_FILE_BYTES", 8):
                web3 = web3_iot_firmware_auditor.audit_web3_and_iot_project(
                    str(project), allowed_roots=(base,)
                )

            self.assertEqual(mobile["scanned_files"], 1, "empty mobile source remains a scanned file")
            self.assertEqual(contracts["contracts_audited"], 0, "strict UTF-8 contract remains skipped")
            self.assertEqual(
                web3["scanned_files"],
                0,
                "configured dependency directory, oversized source and FIFO remain skipped",
            )


if __name__ == "__main__":
    unittest.main()
