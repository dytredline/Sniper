"""Bounded observed-runtime correlation for static cross-repository graphs (Wave 2 / R4)."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import bulk_scan


TRACE_NAME = "sniper-runtime-service-trace.json"
TRACE_FORMAT = "sniper-runtime-service-trace/1"


def _write(root: Path, relative: str, content: str) -> None:
    target = root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")


def _repo(root: Path, name: str, files: dict[str, str]) -> Path:
    repo = root / name
    repo.mkdir(parents=True)
    for relative, content in files.items():
        _write(repo, relative, content)
    return repo


def _manifest(repository: str, observations: list[dict], *, nonce: str) -> str:
    payload = {
        "format": TRACE_FORMAT,
        "repository": repository,
        "generated_at": "2026-10-27T12:34:56Z",
        "nonce": nonce,
        "observations": observations,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    payload["integrity_sha256"] = hashlib.sha256(canonical).hexdigest()
    return json.dumps(payload, sort_keys=True)


def _observation(source: str, target: str, protocol: str, operation: str, count: int = 1) -> dict:
    return {
        "source_repository": source,
        "target_repository": target,
        "protocol": protocol,
        "operation": operation,
        "event_count": count,
    }


def _execute(root: Path, repos: list[Path], monkeypatch) -> tuple[dict, dict, dict]:
    data = root.parent / "data"
    data.mkdir(exist_ok=True)
    monkeypatch.setenv("SNIPER_DATA_DIR", str(data))
    run = bulk_scan.create_run(
        root,
        repos,
        group="observed-runtime",
        options=bulk_scan.BulkOptions(sca=False, skip_unchanged=False),
    )

    def route(_path: str, payload: dict) -> tuple[int, dict]:
        name = Path(payload["project_path"]).name
        return 201, {"id": f"prj_{name}", "project_name": name, "findings": []}

    result = bulk_scan.execute(run["id"], route)
    stored = bulk_scan.public_run(bulk_scan.get_run(run["id"]) or {})
    listed = bulk_scan.list_runs()[0]
    return result, stored, listed


def _portfolio(root: Path) -> list[Path]:
    orders = _repo(
        root,
        "orders",
        {
            "publish.py": (
                "from kafka import KafkaProducer\n"
                "producer = KafkaProducer()\n"
                "producer.send('orders.created', value=payload)\n"
                "requests.post('https://events.internal/webhooks/orders/e-7', json=payload)\n"
            ),
            TRACE_NAME: _manifest(
                "orders",
                [
                    _observation("orders", "events", "webhook-http", "POST /webhooks/orders/{event_id}", 2),
                    _observation("orders", "billing", "kafka", "orders.created", 3),
                ],
                nonce="1" * 32,
            ),
        },
    )
    orders_api = _repo(
        root,
        "orders-api",
        {
            "openapi.json": json.dumps({
                "openapi": "3.0.3",
                "info": {"title": "Orders", "version": "1"},
                "servers": [{"url": "https://orders.internal"}],
                "paths": {"/v1/orders/{order_id}": {"get": {"responses": {"200": {"description": "ok"}}}}},
            }),
        },
    )
    checkout = _repo(
        root,
        "checkout",
        {
            "client.py": "requests.get('https://orders.internal/v1/orders/42', headers={'Authorization': token})\n",
            TRACE_NAME: _manifest(
                "checkout",
                [_observation("checkout", "orders-api", "http", "GET /v1/orders/{order_id}", 5)],
                nonce="2" * 32,
            ),
        },
    )
    events = _repo(
        root,
        "events",
        {
            "openapi.json": json.dumps({
                "openapi": "3.0.3",
                "info": {"title": "Events", "version": "1"},
                "servers": [{"url": "https://events.internal"}],
                "paths": {
                    "/webhooks/orders/{event_id}": {
                        "post": {"security": [{"signature": []}], "responses": {"204": {"description": "ok"}}},
                    },
                },
            }),
        },
    )
    billing = _repo(
        root,
        "billing",
        {"consume.py": "from kafka import KafkaConsumer\nconsumer = KafkaConsumer('orders.created')\n"},
    )
    catalog = _repo(root, "catalog", {"schema.graphql": "type Query { product: String }\n"})
    storefront = _repo(
        root,
        "storefront",
        {
            "product.graphql": "query Product { product }\n",
            TRACE_NAME: _manifest(
                "storefront",
                [_observation("storefront", "catalog", "graphql", "query product", 7)],
                nonce="3" * 32,
            ),
        },
    )
    return [orders, orders_api, checkout, events, billing, catalog, storefront]


def test_exact_local_integrity_verified_traces_annotate_all_four_static_graphs(tmp_path, monkeypatch) -> None:
    root = tmp_path / "portfolio"
    result, stored, listed = _execute(root, _portfolio(root), monkeypatch)

    assert result["service_graph"]["edges"][0]["observed"] is True
    assert result["service_graph"]["edges"][0]["runtime_evidence_count"] == 1
    assert result["service_graph"]["edges"][0]["runtime_event_count"] == 5
    assert result["webhook_graph"]["edges"][0]["observed"] is True
    assert result["webhook_graph"]["edges"][0]["runtime_event_count"] == 2
    assert result["message_graph"]["edges"][0]["observed"] is True
    assert result["message_graph"]["edges"][0]["runtime_event_count"] == 3
    assert result["graphql_service_graph"]["edges"][0]["observed"] is True
    assert result["graphql_service_graph"]["edges"][0]["runtime_event_count"] == 7
    assert result["runtime_service_trace"] == {
        "format": TRACE_FORMAT,
        "status": "evaluated",
        "accepted_manifest_count": 3,
        "rejected_manifest_count": 0,
        "observation_count": 4,
        "matched_edge_count": 4,
        "unmatched_observation_count": 0,
        "truncated": False,
    }
    assert stored["runtime_service_trace"] == result["runtime_service_trace"]
    assert listed["runtime_service_trace"] == result["runtime_service_trace"]
    serialized = json.dumps(result, sort_keys=True)
    assert "orders.internal" not in serialized
    assert "events.internal" not in serialized
    assert "Authorization" not in serialized
    assert "token" not in serialized
    assert "2026-10-27T12:34:56Z" not in serialized
    assert "1" * 32 not in serialized


def test_absent_trace_keeps_static_edge_without_observed_claim(tmp_path, monkeypatch) -> None:
    root = tmp_path / "portfolio"
    producer = _repo(root, "api", {"schema.graphql": "type Query { health: String }\n"})
    consumer = _repo(root, "client", {"health.graphql": "query Health { health }\n"})

    result, _stored, _listed = _execute(root, [producer, consumer], monkeypatch)

    edge = result["graphql_service_graph"]["edges"][0]
    assert edge == {
        "producer_repo": "api",
        "consumer_repo": "client",
        "operation_type": "query",
        "root_field": "health",
    }
    assert result["runtime_service_trace"]["accepted_manifest_count"] == 0
    assert result["runtime_service_trace"]["matched_edge_count"] == 0


def test_invalid_dynamic_oversize_symlink_identity_and_count_traces_fail_closed(tmp_path, monkeypatch) -> None:
    root = tmp_path / "portfolio"
    api = _repo(
        root,
        "api",
        {
            "openapi.json": json.dumps({
                "openapi": "3.0.3",
                "info": {"title": "API", "version": "1"},
                "servers": [{"url": "https://api.internal"}],
                "paths": {"/v1/items": {"get": {"responses": {"200": {"description": "ok"}}}}},
            }),
        },
    )
    client = _repo(
        root,
        "client",
        {
            "client.py": "requests.get('https://api.internal/v1/items')\n",
            TRACE_NAME: _manifest(
                "client",
                [_observation("client", "api", "http", "GET /v1/items")],
                nonce="4" * 32,
            ),
        },
    )
    forged = json.loads((client / TRACE_NAME).read_text(encoding="utf-8"))
    forged["integrity_sha256"] = "0" * 64
    (client / TRACE_NAME).write_text(json.dumps(forged), encoding="utf-8")

    mismatch = _repo(
        root,
        "mismatch",
        {TRACE_NAME: _manifest("another-repo", [], nonce="5" * 32)},
    )
    dynamic = _repo(
        root,
        "dynamic",
        {
            TRACE_NAME: _manifest(
                "dynamic",
                [_observation("dynamic", "api", "http", "GET ${RUNTIME_PATH}")],
                nonce="6" * 32,
            ),
        },
    )
    oversized = _repo(root, "oversized", {TRACE_NAME: " " * 300_000})
    too_many = _repo(
        root,
        "too-many",
        {
            TRACE_NAME: _manifest(
                "too-many",
                [_observation("too-many", "api", "kafka", f"topic.{index}") for index in range(129)],
                nonce="7" * 32,
            ),
        },
    )
    symlinked = _repo(root, "symlinked", {})
    target = tmp_path / "outside-trace.json"
    target.write_text(_manifest("symlinked", [], nonce="8" * 32), encoding="utf-8")
    os.symlink(target, symlinked / TRACE_NAME)

    result, _stored, _listed = _execute(
        root,
        [api, client, mismatch, dynamic, oversized, too_many, symlinked],
        monkeypatch,
    )

    edge = result["service_graph"]["edges"][0]
    assert "observed" not in edge
    assert "runtime_evidence_count" not in edge
    assert result["service_graph"]["summary"]["edges"] == 1
    assert result["runtime_service_trace"] == {
        "format": TRACE_FORMAT,
        "status": "evaluated",
        "accepted_manifest_count": 0,
        "rejected_manifest_count": 6,
        "observation_count": 0,
        "matched_edge_count": 0,
        "unmatched_observation_count": 0,
        "truncated": False,
    }
    serialized = json.dumps(result, sort_keys=True)
    assert "RUNTIME_PATH" not in serialized
    assert "outside-trace" not in serialized
    assert "0" * 64 not in serialized


def test_runtime_trace_contract_and_limits_are_documented() -> None:
    root = Path(__file__).resolve().parents[1]
    capabilities = (root / "docs" / "CAPABILITIES.md").read_text(encoding="utf-8")
    guide = (root / "docs" / "KULLANIM-KILAVUZU.md").read_text(encoding="utf-8")
    llms = (root / "llms.txt").read_text(encoding="utf-8")

    assert "`sniper-runtime-service-trace.json`" in capabilities
    assert "`sniper-runtime-service-trace/1`" in guide
    assert "256 KB" in guide
    assert "128 observation" in guide
    assert "integrity hash is not a signature" in llms
