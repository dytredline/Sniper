"""Cross-file GitHub Actions artifact trust graph contracts."""
from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

import supply_chain_slsa_auditor


UPLOAD_SHA = "a" * 40
DOWNLOAD_SHA = "b" * 40


def _write(root: Path, name: str, content: str) -> None:
    target = root / ".github" / "workflows" / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")


def _producer(*, artifact: str = "pr-dist", trigger: str = "pull_request") -> str:
    return (
        "name: PR Build\n"
        "on:\n"
        f"  {trigger}:\n"
        "permissions:\n"
        "  contents: read\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        f"      - uses: actions/upload-artifact@{UPLOAD_SHA}\n"
        "        with:\n"
        f"          name: {artifact}\n"
        "          path: dist\n"
    )


def _consumer(*, artifact: str = "pr-dist", permissions: str = "  contents: write\n  actions: read\n",
              verification: str = "", execute: str = "bash artifact/build.sh") -> str:
    verify_step = f"      - run: {verification}\n" if verification else ""
    return (
        "name: Publish\n"
        "on:\n"
        "  workflow_run:\n"
        "    workflows: [\"PR Build\"]\n"
        "    types: [completed]\n"
        "permissions:\n"
        f"{permissions}"
        "jobs:\n"
        "  publish:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        f"      - uses: actions/download-artifact@{DOWNLOAD_SHA}\n"
        "        with:\n"
        f"          name: {artifact}\n"
        "          path: artifact\n"
        "          run-id: ${{ github.event.workflow_run.id }}\n"
        "          github-token: ${{ github.token }}\n"
        f"{verify_step}"
        f"      - run: {execute}\n"
    )


class CiArtifactTrustGraphTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "project"
        self.root.mkdir()

    def audit(self) -> dict:
        return supply_chain_slsa_auditor.audit_supply_chain_slsa(
            str(self.root), allowed_roots=(self.root.parent,)
        )

    def test_untrusted_pr_artifact_to_privileged_workflow_execution_is_linked(self) -> None:
        _write(self.root, "pr-build.yml", _producer())
        _write(self.root, "publish.yml", _consumer())

        report = self.audit()
        graph = report["artifact_trust_graph"]

        self.assertEqual(graph["format"], "sniper-github-artifact-trust-graph-v1")
        self.assertEqual(graph["summary"], {
            "workflows": 2,
            "producers": 1,
            "consumers": 1,
            "edges": 1,
            "review_edges": 1,
            "unresolved_downloads": 0,
            "parse_errors": 0,
            "truncated": False,
        })
        self.assertEqual(graph["nodes"], [
            {
                "id": "workflow:.github/workflows/pr-build.yml",
                "workflow": "PR Build",
                "file": ".github/workflows/pr-build.yml",
                "role": "producer",
                "trigger": "pull_request",
            },
            {
                "id": "workflow:.github/workflows/publish.yml",
                "workflow": "Publish",
                "file": ".github/workflows/publish.yml",
                "role": "consumer",
                "trigger": "workflow_run",
            },
        ])
        edge = graph["edges"][0]
        self.assertEqual(edge["producer"], "workflow:.github/workflows/pr-build.yml")
        self.assertEqual(edge["consumer"], "workflow:.github/workflows/publish.yml")
        self.assertEqual(edge["artifact"], "pr-dist")
        self.assertEqual(edge["consumer_trigger"], "workflow_run")
        self.assertEqual(edge["permissions"], "write-capable")
        self.assertEqual(edge["secrets"], "not-seen")
        self.assertEqual(edge["verification"], "missing")
        self.assertEqual(edge["status"], "review")
        self.assertGreater(edge["evidence"]["upload_line"], 0)
        self.assertGreater(edge["evidence"]["download_line"], 0)
        self.assertGreater(edge["evidence"]["execution_line"], edge["evidence"]["download_line"])
        graph_findings = [f for f in report["findings"] if f.get("control_id") == "SNIPER-SLSA-ARTIFACT-GRAPH-04"]
        self.assertEqual(len(graph_findings), 1)
        self.assertIn("pr-build.yml", graph_findings[0]["evidence"])
        self.assertIn("publish.yml", graph_findings[0]["evidence"])

    def test_command_declarations_do_not_mitigate_but_explicit_read_only_permissions_do(self) -> None:
        cases = (
            ("attested", "  contents: write\n  actions: read\n", "gh attestation verify artifact --repo example/repo",
             "write-capable", "declared_unverified", "review"),
            ("checksum", "  contents: write\n  actions: read\n", "sha256sum -c artifact/SHA256SUMS",
             "write-capable", "declared_unverified", "review"),
            ("read-only", "  contents: read\n  actions: read\n", "", "read-only", "missing", "mitigated"),
        )
        for name, permissions, verification, permission_state, verification_state, status in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "project"
                root.mkdir()
                _write(root, "pr-build.yml", _producer())
                _write(root, "publish.yml", _consumer(permissions=permissions, verification=verification))

                report = supply_chain_slsa_auditor.audit_supply_chain_slsa(
                    str(root), allowed_roots=(root.parent,)
                )
                edge = report["artifact_trust_graph"]["edges"][0]

                self.assertEqual(edge["permissions"], permission_state)
                self.assertEqual(edge["secrets"], "not-seen")
                self.assertEqual(edge["verification"], verification_state)
                self.assertEqual(edge["status"], status)
                self.assertEqual(report["artifact_trust_graph"]["summary"]["review_edges"], status == "review")
                self.assertEqual(any(
                    f.get("control_id") in {"SNIPER-SLSA-ARTIFACT-GRAPH-04", "SNIPER-SLSA-ARTIFACT-03"}
                    for f in report["findings"]
                ), status == "review")

    def test_verification_after_execution_does_not_mitigate(self) -> None:
        _write(self.root, "pr-build.yml", _producer())
        consumer = _consumer().replace(
            "      - run: bash artifact/build.sh\n",
            "      - run: |\n          bash artifact/build.sh\n          sha256sum -c artifact/SHA256SUMS\n",
        )
        _write(self.root, "publish.yml", consumer)

        edge = self.audit()["artifact_trust_graph"]["edges"][0]

        self.assertEqual(edge["verification"], "missing")
        self.assertEqual(edge["status"], "review")

    def test_read_only_token_does_not_mitigate_explicit_secret_use(self) -> None:
        _write(self.root, "pr-build.yml", _producer())
        consumer = _consumer(
            permissions="  contents: read\n  actions: read\n",
            execute='echo "${{ secrets.DEPLOY_KEY }}" > artifact/key && bash artifact/build.sh',
        )
        _write(self.root, "publish.yml", consumer)

        edge = self.audit()["artifact_trust_graph"]["edges"][0]

        self.assertEqual(edge["permissions"], "read-only")
        self.assertEqual(edge["secrets"], "referenced")
        self.assertEqual(edge["status"], "review")

    def test_unresolved_or_non_pr_artifacts_do_not_create_edges(self) -> None:
        cases = (
            ("dynamic", _producer(artifact="${{ github.sha }}"), _consumer()),
            ("mismatch", _producer(artifact="pr-dist"), _consumer(artifact="other-dist")),
            ("trusted-trigger", _producer(trigger="push"), _consumer()),
            ("unrelated-execution", _producer(), _consumer(execute="npm test")),
        )
        for name, producer, consumer in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "project"
                root.mkdir()
                _write(root, "pr-build.yml", producer)
                _write(root, "publish.yml", consumer)

                graph = supply_chain_slsa_auditor.audit_supply_chain_slsa(
                    str(root), allowed_roots=(root.parent,)
                )["artifact_trust_graph"]

                self.assertEqual(graph["edges"], [])
                self.assertEqual(graph["nodes"], [])
                self.assertEqual(graph["summary"]["review_edges"], 0)
                self.assertEqual(graph["summary"]["unresolved_downloads"], 1)

    def test_ambiguous_duplicate_producers_fail_closed(self) -> None:
        _write(self.root, "pr-build-a.yml", _producer())
        _write(self.root, "pr-build-b.yml", _producer())
        _write(self.root, "publish.yml", _consumer())

        graph = self.audit()["artifact_trust_graph"]

        self.assertEqual(graph["summary"]["producers"], 2)
        self.assertEqual(graph["summary"]["unresolved_downloads"], 1)
        self.assertEqual(graph["edges"], [])

    def test_malformed_workflow_fails_closed(self) -> None:
        _write(self.root, "broken.yml", "name: [broken\non:\n  pull_request:\n")
        _write(self.root, "publish.yml", _consumer())

        graph = self.audit()["artifact_trust_graph"]

        self.assertEqual(graph["edges"], [])
        self.assertEqual(graph["nodes"], [])
        self.assertEqual(graph["summary"]["parse_errors"], 1)
        self.assertEqual(graph["summary"]["unresolved_downloads"], 1)


if __name__ == "__main__":
    unittest.main()

