"""Altı depolar-arası grafiğin tek bulk sonuç sözleşmesinde birlikte kalması."""
from __future__ import annotations

import json
from pathlib import Path
from unittest import mock

import bulk_scan
import pytest


GRAPH_KEYS = (
    "service_graph",
    "webhook_graph",
    "message_graph",
    "auth_contract_graph",
    "graphql_service_graph",
    "dependency_lineage",
)


def _write(root: Path, relative: str, text: str) -> None:
    target = root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")


def _fixture(tmp_path: Path, monkeypatch) -> tuple[dict, dict, dict]:
    root = tmp_path / "portfolio"
    platform = root / "platform"
    client = root / "client"
    platform.mkdir(parents=True)
    client.mkdir()
    _write(platform, "openapi.json", json.dumps({
        "openapi": "3.0.3",
        "servers": [{"url": "https://platform.internal"}],
        "paths": {
            "/v1/orders/{order_id}": {"get": {"responses": {"200": {"description": "ok"}}}},
            "/webhooks/orders/{event_id}": {
                "post": {"security": [{"signature": []}], "responses": {"204": {"description": "ok"}}},
            },
        },
    }))
    _write(platform, "publish.py", (
        "from kafka import KafkaProducer\n"
        "producer = KafkaProducer(bootstrap_servers=['broker.internal:9092'], sasl_plain_password='do-not-return')\n"
        "producer.send('orders.created', value=payload)\n"
    ))
    _write(client, "consume.py", (
        "import requests\n"
        "from kafka import KafkaConsumer\n"
        "requests.get('https://platform.internal/v1/orders/42')\n"
        "requests.post('https://platform.internal/webhooks/orders/e-7', headers={'X-Signature': digest})\n"
        "consumer = KafkaConsumer('orders.created', bootstrap_servers=['broker.internal:9092'])\n"
    ))
    _write(platform, "requirements.txt", "Django==5.1.4\n")
    _write(client, "requirements.txt", "django==4.2.17\n")
    _write(platform, "schema.graphql", (
        "type Query {\n"
        "  order(id: ID!): Order\n"
        "}\n"
    ))
    _write(client, "order.graphql", "query OrderScreen($id: ID!) { order(id: $id) { id } }\n")
    _write(client, ".graphql-local", "endpoint=https://graphql.internal/api\ntoken=graphql-do-not-return\n")
    issuer = "https://identity.example.test/"
    _write(platform, "sniper-auth-contracts.json", json.dumps({
        "format": "sniper-auth-contracts/1",
        "contracts": [{
            "role": "producer", "issuer": issuer, "audience": "orders-api",
            "scopes": ["orders.read"], "tenant": "tenant-a",
        }],
    }))
    _write(client, "sniper-auth-contracts.json", json.dumps({
        "format": "sniper-auth-contracts/1",
        "contracts": [{
            "role": "consumer", "issuer": issuer, "audience": "orders-api",
            "scopes": ["orders.read", "orders.write"], "tenant": "tenant-b",
        }],
    }))
    data = tmp_path / "data"
    data.mkdir()
    monkeypatch.setenv("SNIPER_DATA_DIR", str(data))
    created = bulk_scan.create_run(
        root, [platform, client], group="all-service-graphs",
        options=bulk_scan.BulkOptions(sca=False, skip_unchanged=False),
    )

    def route(_route: str, payload: dict) -> tuple[int, dict]:
        name = Path(payload["project_path"]).name
        return 201, {"id": "prj_" + name, "project_name": name, "findings": []}

    return created, {"route": route}, {"root": root, "data": data}


def test_all_graphs_coexist_in_execute_persist_public_and_list(tmp_path, monkeypatch) -> None:
    created, runtime, _paths = _fixture(tmp_path, monkeypatch)
    result = bulk_scan.execute(created["id"], runtime["route"])
    stored = bulk_scan.public_run(bulk_scan.get_run(created["id"]) or {})
    listed = bulk_scan.list_runs()[0]

    assert set(GRAPH_KEYS) <= result.keys()
    assert result["service_graph"]["summary"]["edges"] >= 1
    assert result["webhook_graph"]["summary"]["edges"] == 1
    assert result["message_graph"]["summary"]["edges"] == 1
    assert result["auth_contract_graph"]["finding_count"] == 1
    assert result["graphql_service_graph"]["edge_count"] == 1
    assert result["dependency_lineage"]["summary"]["edges"] == 1
    for key in GRAPH_KEYS:
        assert stored[key] == result[key]
        assert key in listed
    rendered = json.dumps(result, sort_keys=True)
    assert "platform.internal" not in rendered
    assert "broker.internal" not in rendered
    assert "do-not-return" not in rendered
    assert "bootstrap_servers" not in rendered
    assert "graphql.internal" not in rendered
    assert "graphql-do-not-return" not in rendered


@pytest.mark.parametrize(("failed_key", "patch_target"), (
    ("service_graph", "bulk_scan.service_trust_graph.build"),
    ("webhook_graph", "bulk_scan.webhook_trust_graph.build"),
    ("message_graph", "bulk_scan.message_trust_graph.build"),
    ("auth_contract_graph", "bulk_scan.audit_auth_contract_graph"),
    ("graphql_service_graph", "bulk_scan.audit_graphql_service_graph"),
    ("dependency_lineage", "bulk_scan.dependency_lineage_graph.build"),
))
def test_one_graph_failure_is_empty_and_does_not_erase_other_graphs(
    tmp_path, monkeypatch, failed_key: str, patch_target: str,
) -> None:
    created, runtime, _paths = _fixture(tmp_path, monkeypatch)
    with mock.patch(patch_target, side_effect=ValueError("must-not-return-secret")):
        result = bulk_scan.execute(created["id"], runtime["route"])

    assert result["status"] == "succeeded"
    failed = result[failed_key]
    if failed_key in {"auth_contract_graph", "graphql_service_graph"}:
        assert failed["status"] == "not_evaluated"
        assert failed["reason"] == "analysis_error"
        assert failed["findings" if failed_key == "auth_contract_graph" else "edges"] == []
    else:
        assert failed["summary"]["edges"] == 0
        assert failed["summary"]["truncated"] is True
        assert failed["nodes"] == []
        assert failed["edges"] == []
    for key in GRAPH_KEYS:
        if key == failed_key:
            continue
        if key == "auth_contract_graph":
            assert result[key]["finding_count"] == 1
        elif key == "graphql_service_graph":
            assert result[key]["edge_count"] == 1
        else:
            assert result[key]["summary"]["edges"] >= 1
    assert "must-not-return-secret" not in json.dumps(result)
