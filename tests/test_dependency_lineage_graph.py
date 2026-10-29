"""Depolar arası exact-pinned Python dependency lineage sözleşmeleri."""
from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import bulk_scan
import dependency_lineage_graph


def _write(root: Path, relative: str, text: str) -> None:
    target = root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")


class DependencyLineageGraphTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.api = self.root / "api"
        self.worker = self.root / "worker"
        self.api.mkdir()
        self.worker.mkdir()

    def test_same_normalized_package_with_different_exact_versions_creates_drift_edge(self) -> None:
        _write(self.api, "requirements.txt", (
            "--index-url https://user:do-not-return@packages.internal/simple\n"
            "Django==5.1.4\n"
        ))
        _write(self.worker, "requirements-prod.txt", "django==4.2.17\n")

        graph = dependency_lineage_graph.build([("api", self.api), ("worker", self.worker)])

        self.assertEqual(graph["format"], "sniper-dependency-lineage-graph-v1")
        self.assertEqual(graph["summary"], {
            "repositories": 2, "nodes": 2, "edges": 1, "packages_with_drift": 1, "truncated": False,
        })
        self.assertEqual(graph["nodes"], [
            {"id": "repo:api", "repository": "api"},
            {"id": "repo:worker", "repository": "worker"},
        ])
        self.assertEqual(graph["edges"], [{
            "left": "repo:api",
            "right": "repo:worker",
            "ecosystem": "pypi",
            "package": "django",
            "relation": "version-drift",
            "versions": {"left": "5.1.4", "right": "4.2.17"},
            "evidence": {
                "left": {"file": "requirements.txt", "line": 2},
                "right": {"file": "requirements-prod.txt", "line": 1},
            },
        }])
        rendered = json.dumps(graph, sort_keys=True)
        self.assertNotIn("packages.internal", rendered)
        self.assertNotIn("do-not-return", rendered)
        self.assertNotIn("index-url", rendered)

    def test_pep503_name_normalization_extras_and_hashes_still_link_exact_pins(self) -> None:
        _write(self.api, "requirements/base.in", "Requests_Socks[socks]==2.31.0 --hash=sha256:" + "a" * 64 + "\n")
        _write(self.worker, "requirements.lock.txt", "requests-socks==2.32.0\n")

        graph = dependency_lineage_graph.build([("api", self.api), ("worker", self.worker)])

        self.assertEqual(graph["summary"]["edges"], 1)
        self.assertEqual(graph["edges"][0]["package"], "requests-socks")
        self.assertEqual(graph["edges"][0]["versions"], {"left": "2.31.0", "right": "2.32.0"})

    def test_self_same_version_unpinned_url_and_conditional_requirements_fail_closed(self) -> None:
        _write(self.api, "requirements.txt", (
            "Flask==3.1.0\n"
            "requests>=2.31\n"
            "private-lib @ https://user:secret@packages.internal/private.whl\n"
            "conditional==1.0 ; python_version < '3.12'\n"
        ))
        _write(self.api, "requirements-dev.txt", "flask==2.3.0\n")
        _write(self.worker, "requirements.txt", (
            "flask==3.1.0\n"
            "requests==2.32.0\n"
            "different==1.0\n"
        ))

        graph = dependency_lineage_graph.build([("api", self.api), ("worker", self.worker)])

        self.assertEqual(graph["edges"], [])
        self.assertEqual(graph["nodes"], [])

    def test_malformed_and_oversized_requirement_files_are_ignored(self) -> None:
        _write(self.api, "requirements.txt", "not a requirement == ???\n")
        _write(self.api, "requirements-huge.txt", " " * (dependency_lineage_graph.MAX_REQUIREMENTS_BYTES + 1))
        _write(self.worker, "requirements.txt", "django==4.2.17\n")

        graph = dependency_lineage_graph.build([("api", self.api), ("worker", self.worker)])

        self.assertEqual(graph["summary"], {
            "repositories": 2, "nodes": 0, "edges": 0, "packages_with_drift": 0, "truncated": False,
        })


class BulkDependencyLineageIntegrationTests(unittest.TestCase):
    def test_bulk_run_persists_dependency_lineage_and_lists_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = root / "data"
            data.mkdir()
            api = root / "api"
            worker = root / "worker"
            api.mkdir()
            worker.mkdir()
            _write(api, "requirements.txt", "django==5.1.4\n")
            _write(worker, "requirements.txt", "django==4.2.17\n")

            def run_route(route, payload):
                self.assertEqual(route, "/api/project-audits")
                name = Path(payload["project_path"]).name
                return 201, {"id": f"prj_{name}", "project_name": name, "findings": []}

            with mock.patch.dict(os.environ, {"SNIPER_DATA_DIR": str(data)}):
                created = bulk_scan.create_run(
                    root,
                    [api, worker],
                    group="local-dependencies",
                    options=bulk_scan.BulkOptions(sca=False),
                )
                result = bulk_scan.execute(created["id"], run_route)
                stored = bulk_scan.public_run(bulk_scan.get_run(created["id"]), "succeeded")
                listed = bulk_scan.list_runs()[0]

        self.assertEqual(result["dependency_lineage"]["summary"]["edges"], 1)
        self.assertEqual(stored["dependency_lineage"], result["dependency_lineage"])
        self.assertEqual(listed["dependency_lineage"]["edges"], 1)


if __name__ == "__main__":
    unittest.main()
