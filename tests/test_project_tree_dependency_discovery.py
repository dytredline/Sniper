from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import dependency_reachability as dr
import dependency_security as ds
import project_tree
from project_tree import ProjectTree, ProjectTreeError
import supply_chain_slsa_auditor


class ProjectTreeDependencyDiscoveryTests(unittest.TestCase):
    def test_component_discovery_rejects_parent_swap_after_validation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            checked_parent = base / "checked"
            project = checked_parent / "project"
            attacker_parent = base / "attacker"
            attacker = attacker_parent / "project"
            project.mkdir(parents=True)
            attacker.mkdir(parents=True)
            (project / "requirements.txt").write_text("safe-package==1.0\n", encoding="utf-8")
            (attacker / "requirements.txt").write_text("outside-package==9.9\n", encoding="utf-8")
            real_validate = ds.validate_project_path
            swapped = False

            def validate_then_swap(*args, **kwargs):
                nonlocal swapped
                validated = real_validate(*args, **kwargs)
                checked_parent.rename(base / "checked-preserved")
                checked_parent.symlink_to(attacker_parent, target_is_directory=True)
                swapped = True
                return validated

            with mock.patch.object(ds, "validate_project_path", side_effect=validate_then_swap):
                with self.assertRaises((ds.DependencySecurityError, ProjectTreeError)):
                    ds.discover_components(str(project), allowed_roots=(base,))
            self.assertTrue(swapped)

    def test_usage_index_rejects_intermediate_swap_instead_of_reading_outside_import(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            project = base / "project"
            source_dir = project / "src"
            attacker_dir = base / "attacker" / "src"
            source_dir.mkdir(parents=True)
            attacker_dir.mkdir(parents=True)
            (source_dir / "app.py").write_text("print('safe')\n", encoding="utf-8")
            (attacker_dir / "app.py").write_text("import urllib3\nurllib3.request('GET', url)\n", encoding="utf-8")
            real_open = os.open
            swapped = False

            def swap_then_open(path, flags, *args, **kwargs):
                nonlocal swapped
                relative_open = path == "src" and kwargs.get("dir_fd") is not None
                legacy_leaf_open = os.fspath(path) == os.fspath(source_dir / "app.py")
                if not swapped and (relative_open or legacy_leaf_open):
                    source_dir.rename(project / "src-preserved")
                    source_dir.symlink_to(attacker_dir, target_is_directory=True)
                    swapped = True
                return real_open(path, flags, *args, **kwargs)

            with mock.patch.object(project_tree.os, "open", side_effect=swap_then_open):
                with self.assertRaises(ProjectTreeError):
                    dr.build_usage_index(
                        project,
                        (),
                        packages_hint={"urllib3"},
                        packages={"urllib3"},
                    )
            self.assertTrue(swapped)

    def test_shared_tree_keeps_component_usage_jvm_and_cli_contracts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            project = base / "project"
            (project / "src").mkdir(parents=True)
            (project / "config").mkdir()
            (project / "requirements.txt").write_text("urllib3==2.2.3\n", encoding="utf-8")
            (project / "src" / "app.py").write_text(
                "import urllib3\nurllib3.request('GET', url)\n",
                encoding="utf-8",
            )
            (project / "config" / "application.properties").write_text(
                "spring.datasource.url=jdbc:mysql://localhost/demo\n",
                encoding="utf-8",
            )
            (project / "Dockerfile").write_text("CMD [\"gunicorn\", \"app:app\"]\n", encoding="utf-8")

            with ProjectTree(project) as tree:
                root, components = ds.discover_components(
                    str(project), allowed_roots=(base,), project_tree=tree
                )
                usage = dr.build_usage_index(
                    root,
                    (),
                    packages_hint={"urllib3"},
                    packages={"urllib3"},
                    project_tree=tree,
                )
                jvm = dr.jvm_config_mentions(
                    root,
                    {"mysql:mysql-connector-java": {"jdbc:mysql:"}},
                    (),
                    project_tree=tree,
                )
                cli = dr.cli_tool_mentions(root, {"gunicorn"}, (), project_tree=tree)

            slsa = supply_chain_slsa_auditor.audit_supply_chain_slsa(
                str(project), allowed_roots=(base,)
            )
            reachability = ds.analyze_vulnerability_reachability(
                str(project),
                allowed_roots=(base,),
                findings=[{
                    "package_name": "urllib3",
                    "vulnerability_id": "CVE-2099-0001",
                    "severity": "high",
                }],
            )

            self.assertEqual(
                [(item["name"], item["version"], item["manifest"]) for item in components],
                [("urllib3", "2.2.3", "requirements.txt")],
            )
            uses = usage.for_package({"urllib3"})
            self.assertTrue(
                any(item["file"] == "src/app.py" for sites in uses.values() for item in sites)
            )
            self.assertEqual(jvm["mysql:mysql-connector-java"]["file"], "config/application.properties")
            self.assertEqual(cli["gunicorn"], {"file": "Dockerfile", "line": 1, "via": "script"})
            self.assertEqual(slsa["format"], "sniper-supply-chain-slsa-audit-v1")
            self.assertEqual(slsa["component_count"], 1)
            self.assertEqual(reachability["format"], "sniper-vulnerability-reachability-v1")
            self.assertTrue(reachability["items"][0]["reachable"])
            self.assertEqual(reachability["items"][0]["call_sites"][0]["file"], "src/app.py")


if __name__ == "__main__":
    unittest.main()
