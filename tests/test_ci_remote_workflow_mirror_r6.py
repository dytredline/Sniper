"""Offline remote reusable-workflow mirror/lock contracts (R6)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile

import supply_chain_slsa_auditor


COMMIT = "a" * 40
REPOSITORY = "acme/release"
WORKFLOW = ".github/workflows/release.yml"
REMOTE = f"{REPOSITORY}/{WORKFLOW}@{COMMIT}"
MIRROR_PATH = f".sniper-workflow-mirror/acme__release/{COMMIT}.yml"
CALLEE = """name: Release
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


def _caller(uses: str = REMOTE) -> str:
    return f"""name: Pull request release
on:
  pull_request:
permissions:
  contents: write
jobs:
  deploy:
    uses: {uses}
    secrets: inherit
"""


def _entry(*, repository: str = REPOSITORY, commit: str = COMMIT,
           workflow: str = WORKFLOW, mirror_path: str = MIRROR_PATH,
           digest: str | None = None) -> dict[str, str]:
    return {
        "repository": repository,
        "commit": commit,
        "workflow": workflow,
        "mirror_path": mirror_path,
        "sha256": digest or hashlib.sha256(CALLEE.encode()).hexdigest(),
    }


def _audit(*, uses: str = REMOTE, entries: list[dict[str, str]] | None = None,
           mirror: bytes | None = CALLEE.encode(), symlink: bool = False) -> dict:
    with tempfile.TemporaryDirectory() as raw:
        base = Path(raw)
        root = base / "project"
        workflow_root = root / ".github/workflows"
        workflow_root.mkdir(parents=True)
        (workflow_root / "caller.yml").write_text(_caller(uses), encoding="utf-8")
        if entries is not None:
            (root / ".sniper-workflow-mirror.lock.json").write_text(json.dumps({
                "schema": "sniper-workflow-mirror-lock-v1",
                "workflows": entries,
            }), encoding="utf-8")
        if mirror is not None:
            target = root / MIRROR_PATH
            target.parent.mkdir(parents=True, exist_ok=True)
            if symlink:
                backing = root / "backing.yml"
                backing.write_bytes(mirror)
                target.symlink_to(backing)
            else:
                target.write_bytes(mirror)
        return supply_chain_slsa_auditor.audit_supply_chain_slsa(
            str(root), allowed_roots=(base,)
        )


def _workflow_findings(report: dict) -> list[dict]:
    return [
        item for item in report["findings"]
        if item.get("control_id") == "SNIPER-SLSA-WORKFLOW-CALL-04"
    ]


def test_commit_pinned_remote_workflow_resolves_only_through_verified_offline_lock() -> None:
    report = _audit(entries=[_entry()])

    assert report["workflow_mirror"] == {
        "format": "sniper-workflow-mirror-resolution-v1",
        "status": "valid",
        "lock_present": True,
        "entry_count": 1,
        "verified_entries": 1,
        "errors": [],
    }
    edge = report["workflow_call_graph"][0]
    assert edge["callee"] == REMOTE
    assert edge["repository"] == REPOSITORY
    assert edge["commit"] == COMMIT
    assert edge["workflow"] == WORKFLOW
    assert edge["resolved"] is True
    assert edge["resolution"] == "verified_lock"
    assert edge["ref_trust"] == "offline_mirror_locked"
    assert edge["mirror_content_sha256_verified"] is True
    assert edge["effective_write_permissions"] == ["contents"]
    assert len(_workflow_findings(report)) == 1


def test_mutable_dynamic_missing_and_wrong_repository_refs_fail_closed() -> None:
    cases = (
        ("tag", f"{REPOSITORY}/{WORKFLOW}@v1", None, "mutable_ref"),
        ("dynamic", f"{REPOSITORY}/{WORKFLOW}@${{{{ github.sha }}}}", None, "dynamic_ref"),
        ("missing-lock", REMOTE, None, "mirror_lock_absent"),
        ("wrong-repository", REMOTE, [_entry(repository="other/release")], "mirror_entry_missing"),
    )
    for _name, uses, entries, reason in cases:
        report = _audit(uses=uses, entries=entries)
        edge = report["workflow_call_graph"][0]
        assert edge["resolved"] is False
        assert edge["resolution"] == reason
        assert edge["effective_write_permissions"] == []
        assert _workflow_findings(report) == []


def test_wrong_digest_duplicate_identity_and_extra_schema_key_invalidate_whole_lock() -> None:
    cases = (
        [_entry(digest="0" * 64)],
        [_entry(), _entry(mirror_path=f".sniper-workflow-mirror/acme__release/{COMMIT}-2.yml")],
        [{**_entry(), "url": "https://should-not-be-accepted.example"}],
    )
    for entries in cases:
        report = _audit(entries=entries)
        assert report["workflow_mirror"]["status"] == "invalid"
        assert report["workflow_mirror"]["errors"]
        edge = report["workflow_call_graph"][0]
        assert edge["resolved"] is False
        assert edge["resolution"] == "mirror_lock_invalid"
        assert _workflow_findings(report) == []


def test_mirror_symlink_and_oversized_workflow_are_never_followed_or_resolved() -> None:
    symlinked = _audit(entries=[_entry()], symlink=True)
    assert symlinked["workflow_mirror"]["status"] == "invalid"
    assert symlinked["workflow_call_graph"][0]["resolved"] is False

    oversized = b"#" + b"x" * (1_000_000 + 1)
    report = _audit(entries=[_entry(digest=hashlib.sha256(oversized).hexdigest())], mirror=oversized)
    assert report["workflow_mirror"]["status"] == "invalid"
    assert "mirror_file_oversize" in report["workflow_mirror"]["errors"]
    assert report["workflow_call_graph"][0]["resolved"] is False


def test_command_name_alone_never_marks_cross_run_artifact_verified() -> None:
    producer = """name: PR Build
on: [pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/upload-artifact@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
        with:
          name: pr-dist
          path: dist
"""
    consumer = """name: Publish
on:
  workflow_run:
    workflows: [\"PR Build\"]
permissions: write-all
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
        with:
          name: pr-dist
          path: artifact
          run-id: ${{ github.event.workflow_run.id }}
          github-token: ${{ github.token }}
      - run: cosign verify-attestation artifact && bash artifact/build.sh
"""
    with tempfile.TemporaryDirectory() as raw:
        base = Path(raw)
        root = base / "project/.github/workflows"
        root.mkdir(parents=True)
        (root / "producer.yml").write_text(producer, encoding="utf-8")
        (root / "consumer.yml").write_text(consumer, encoding="utf-8")
        report = supply_chain_slsa_auditor.audit_supply_chain_slsa(
            str(base / "project"), allowed_roots=(base,)
        )

    edge = report["artifact_trust_graph"]["edges"][0]
    assert edge["verification"] == "declared_unverified"
    assert edge["status"] == "review"
    assert report["has_provenance"] is False
    assert report["declared_provenance_tools"] == ["cosign"]
    assert any(
        item.get("control_id") == "SNIPER-SLSA-ARTIFACT-GRAPH-04"
        for item in report["findings"]
    )

