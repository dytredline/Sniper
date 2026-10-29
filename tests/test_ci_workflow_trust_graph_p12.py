"""Cross-file GitHub Actions reusable-workflow trust graph (P1.2)."""

from __future__ import annotations

from pathlib import Path
import tempfile

import supply_chain_slsa_auditor


CALLEE = """
name: Release
on:
  workflow_call:
permissions:
  contents: write
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - run: ./scripts/publish.sh
"""


def _audit(caller: str, callee: str = CALLEE) -> dict:
    with tempfile.TemporaryDirectory() as raw_base:
        base = Path(raw_base)
        project = base / "project"
        workflows = project / ".github/workflows"
        workflows.mkdir(parents=True)
        (workflows / "caller.yml").write_text(caller, encoding="utf-8")
        (workflows / "release.yml").write_text(callee, encoding="utf-8")
        return supply_chain_slsa_auditor.audit_supply_chain_slsa(
            str(project), allowed_roots=(base,)
        )


def _trust_findings(report: dict) -> list[dict]:
    return [
        finding
        for finding in report["findings"]
        if finding.get("control_id") == "SNIPER-SLSA-WORKFLOW-CALL-04"
    ]


def test_untrusted_caller_inheriting_secrets_into_write_callee_is_correlated() -> None:
    report = _audit(
        """
name: Pull request release
on:
  pull_request:
permissions:
  contents: write
jobs:
  deploy:
    uses: ./.github/workflows/release.yml
    secrets: inherit
"""
    )

    findings = _trust_findings(report)
    assert len(findings) == 1
    assert findings[0]["caller"] == ".github/workflows/caller.yml"
    assert findings[0]["callee"] == ".github/workflows/release.yml"
    assert findings[0]["effective_write_permissions"] == ["contents"]
    assert findings[0]["secrets_mode"] == "inherit"
    assert findings[0]["severity"] == "critical"

    assert report["workflow_call_graph"] == [
        {
            "caller": ".github/workflows/caller.yml",
            "caller_job": "deploy",
            "callee": ".github/workflows/release.yml",
            "resolved": True,
            "ref_trust": "same_commit_local",
            "untrusted_trigger": True,
            "secrets_mode": "inherit",
            "caller_write_permissions": ["contents"],
            "callee_write_permissions": ["contents"],
            "effective_write_permissions": ["contents"],
        }
    ]


def test_read_only_caller_cannot_be_elevated_by_write_request_in_callee() -> None:
    report = _audit(
        """
name: Pull request checks
on:
  pull_request:
permissions:
  contents: read
jobs:
  verify:
    uses: ./.github/workflows/release.yml
    secrets: inherit
"""
    )

    assert _trust_findings(report) == []
    assert report["workflow_call_graph"][0]["caller_write_permissions"] == []
    assert report["workflow_call_graph"][0]["callee_write_permissions"] == ["contents"]
    assert report["workflow_call_graph"][0]["effective_write_permissions"] == []

    callee_override = _audit(
        """
name: Pull request checks
on:
  pull_request:
permissions:
  contents: write
jobs:
  verify:
    uses: ./.github/workflows/release.yml
    secrets: inherit
""",
        callee="""
name: Release
on:
  workflow_call:
permissions:
  contents: write
jobs:
  publish:
    permissions:
      contents: read
    runs-on: ubuntu-latest
    steps:
      - run: ./scripts/publish.sh
""",
    )
    assert _trust_findings(callee_override) == []
    assert callee_override["workflow_call_graph"][0]["callee_write_permissions"] == []


def test_missing_local_callee_and_mapped_secret_are_not_claimed_as_proven_chain() -> None:
    report = _audit(
        """
name: Pull request checks
on: [pull_request]
permissions: write-all
jobs:
  missing:
    uses: ./.github/workflows/not-present.yml
    secrets:
      release_token: ${{ secrets.RELEASE_TOKEN }}
"""
    )

    assert _trust_findings(report) == []
    assert report["workflow_call_graph"] == [
        {
            "caller": ".github/workflows/caller.yml",
            "caller_job": "missing",
            "callee": ".github/workflows/not-present.yml",
            "resolved": False,
            "ref_trust": "same_commit_local",
            "untrusted_trigger": True,
            "secrets_mode": "mapped",
            "caller_write_permissions": ["*"],
            "callee_write_permissions": [],
            "effective_write_permissions": [],
        }
    ]

