"""Cross-repository auth contract graph for bulk analysis (P2.1d)."""

from __future__ import annotations

import json
from pathlib import Path

import bulk_scan


ISSUER = "https://identity.example.test/"
AUDIENCE = "orders-api"


def _manifest(*contracts: dict) -> str:
    return json.dumps({"format": "sniper-auth-contracts/1", "contracts": list(contracts)})


def _contract(role: str, *, scopes: list[str], tenant: str, issuer: str = ISSUER) -> dict:
    return {
        "role": role,
        "issuer": issuer,
        "audience": AUDIENCE,
        "scopes": scopes,
        "tenant": tenant,
    }


def _repo(root: Path, name: str, manifest: str) -> Path:
    repo = root / name
    repo.mkdir(parents=True)
    (repo / "sniper-auth-contracts.json").write_text(manifest, encoding="utf-8")
    return repo


def _execute(root: Path, repos: list[Path], monkeypatch) -> tuple[dict, dict]:
    data = root.parent / "data"
    data.mkdir()
    monkeypatch.setenv("SNIPER_DATA_DIR", str(data))
    run = bulk_scan.create_run(
        root,
        repos,
        group="auth-contracts",
        options=bulk_scan.BulkOptions(sca=False, skip_unchanged=False),
    )

    def route(_path: str, payload: dict) -> tuple[int, dict]:
        name = Path(payload["project_path"]).name
        return 201, {
            "id": f"prj_{name}",
            "project_name": name,
            "score": 100,
            "grade": "A",
            "findings": [],
        }

    result = bulk_scan.execute(run["id"], route)
    stored = bulk_scan.public_run(bulk_scan.get_run(run["id"]) or {})
    return result, stored


def test_bulk_execute_reports_cross_repo_scope_and_tenant_mismatch_without_secrets(tmp_path, monkeypatch) -> None:
    root = tmp_path / "portfolio"
    producer = _repo(
        root,
        "identity",
        _manifest(_contract("producer", scopes=["orders.read"], tenant="tenant-a")),
    )
    consumer = _repo(
        root,
        "orders",
        _manifest(_contract("consumer", scopes=["orders.read", "orders.write"], tenant="tenant-b")),
    )
    secret = "eyJhbGciOiJIUzI1NiJ9.secret.signature"
    (consumer / "local-token.txt").write_text(secret, encoding="utf-8")

    result, stored = _execute(root, [producer, consumer], monkeypatch)
    graph = result["auth_contract_graph"]

    assert graph["format"] == "sniper-bulk-auth-contract-graph/1"
    assert graph["contract_count"] == 2
    assert graph["link_count"] == 1
    assert graph["finding_count"] == 1
    assert graph["findings"] == [{
        "rule_id": "SNIPER-BULK-AUTH-01",
        "severity": "high",
        "category": "authorization",
        "title": "Depolar arası kimlik doğrulama sözleşmesi uyumsuz",
        "producer_repo": "identity",
        "consumer_repo": "orders",
        "issuer": ISSUER,
        "audience": AUDIENCE,
        "missing_scopes": ["orders.write"],
        "producer_tenant": "tenant-a",
        "consumer_tenant": "tenant-b",
    }]
    assert stored["auth_contract_graph"] == graph
    assert secret not in json.dumps(result)
    assert "local-token.txt" not in json.dumps(result)


def test_matching_cross_repo_contract_is_a_passing_control(tmp_path, monkeypatch) -> None:
    root = tmp_path / "portfolio"
    producer = _repo(
        root,
        "identity",
        _manifest(_contract("producer", scopes=["orders.read", "orders.write"], tenant="tenant-a")),
    )
    consumer = _repo(
        root,
        "orders",
        _manifest(_contract("consumer", scopes=["orders.read"], tenant="tenant-a")),
    )

    result, _stored = _execute(root, [producer, consumer], monkeypatch)
    graph = result["auth_contract_graph"]
    assert (graph["link_count"], graph["finding_count"], graph["findings"]) == (1, 0, [])
    discovered = bulk_scan.discover(str(root), allowed_roots=(tmp_path,))
    assert {item["name"] for item in discovered["candidates"]} == {"identity", "orders"}


def test_dynamic_partial_self_and_ambiguous_contracts_fail_closed(tmp_path, monkeypatch) -> None:
    root = tmp_path / "portfolio"
    self_repo = _repo(
        root,
        "self-service",
        _manifest(
            _contract("producer", scopes=["orders.read"], tenant="tenant-a"),
            _contract("consumer", scopes=["orders.admin"], tenant="tenant-b"),
        ),
    )
    dynamic = _repo(
        root,
        "dynamic-consumer",
        _manifest(_contract("consumer", scopes=["orders.admin"], tenant="tenant-a", issuer="${OIDC_ISSUER}")),
    )
    partial_contract = _contract("consumer", scopes=["orders.admin"], tenant="tenant-a")
    partial_contract.pop("tenant")
    partial = _repo(root, "partial-consumer", _manifest(partial_contract))
    secret_contract = _contract("consumer", scopes=["orders.admin"], tenant="tenant-a")
    secret_contract["audience"] = "eyJhbGciOiJIUzI1NiJ9.secretpart.signaturepart"
    secret = _repo(root, "secret-shaped-consumer", _manifest(secret_contract))
    producer_a = _repo(
        root,
        "identity-a",
        _manifest(_contract("producer", scopes=["orders.read"], tenant="tenant-a")),
    )
    producer_b = _repo(
        root,
        "identity-b",
        _manifest(_contract("producer", scopes=["orders.read"], tenant="tenant-a")),
    )
    consumer = _repo(
        root,
        "orders",
        _manifest(_contract("consumer", scopes=["orders.admin"], tenant="tenant-b")),
    )

    result, _stored = _execute(
        root,
        [self_repo, dynamic, partial, secret, producer_a, producer_b, consumer],
        monkeypatch,
    )
    graph = result["auth_contract_graph"]
    assert graph["skipped_manifest_count"] == 3
    assert graph["ambiguous_pair_count"] == 1
    assert graph["link_count"] == 0
    assert graph["finding_count"] == 0
    assert graph["findings"] == []
    assert "secretpart" not in json.dumps(result)
