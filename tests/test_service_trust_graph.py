"""Yerel depolar arası OpenAPI üreticisi ve sabit HTTP istemcisi güven grafiği."""
from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import bulk_scan
import service_trust_graph


def _write(root: Path, relative: str, text: str) -> None:
    target = root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")


def _openapi(host: str = "orders.internal:8080") -> str:
    return json.dumps({
        "openapi": "3.0.3",
        "info": {"title": "Orders", "version": "1"},
        "servers": [{"url": f"http://{host}"}],
        "paths": {
            "/v1/orders/{order_id}": {"get": {"responses": {"200": {"description": "ok"}}}},
            "/v1/orders": {"post": {"responses": {"201": {"description": "created"}}}},
        },
    })


class ServiceTrustGraphTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.orders = self.root / "orders-service"
        self.checkout = self.root / "checkout-service"
        self.orders.mkdir()
        self.checkout.mkdir()

    def test_openapi_producer_links_matching_literal_client_call(self):
        _write(self.orders, "openapi.json", _openapi())
        client = (
            "import requests\n"
            "order = requests.get('http://orders.internal:8080/v1/orders/42')\n"
            "ignored = requests.get('http://orders.internal:8080/v1/unknown')\n"
        )
        _write(self.checkout, "src/client.py", client)

        graph = service_trust_graph.build([
            ("orders-service", self.orders),
            ("checkout-service", self.checkout),
        ])

        self.assertEqual(graph["format"], "sniper-service-trust-graph-v1")
        self.assertEqual(graph["summary"], {"repositories": 2, "nodes": 2, "edges": 1, "truncated": False})
        self.assertEqual(graph["nodes"], [
            {"id": "repo:checkout-service", "repository": "checkout-service", "roles": ["consumer"]},
            {"id": "repo:orders-service", "repository": "orders-service", "roles": ["producer"]},
        ])
        self.assertEqual(graph["edges"], [{
            "consumer": "repo:checkout-service",
            "producer": "repo:orders-service",
            "protocol": "http",
            "operation": "GET /v1/orders/{order_id}",
            "evidence": {"file": "src/client.py", "line": 2, "kind": "openapi+literal-client"},
        }])
        rendered = json.dumps(graph, sort_keys=True)
        self.assertNotIn("orders.internal", rendered)
        self.assertNotIn("http://", rendered)

    def test_method_mismatch_self_call_and_dynamic_url_do_not_link(self):
        _write(self.orders, "openapi.json", _openapi())
        _write(self.orders, "self.py", "requests.get('http://orders.internal:8080/v1/orders/7')\n")
        _write(self.checkout, "client.py", (
            "requests.delete('http://orders.internal:8080/v1/orders/7')\n"
            "requests.get(BASE_URL + '/v1/orders/7')\n"
        ))

        graph = service_trust_graph.build([
            ("orders-service", self.orders),
            ("checkout-service", self.checkout),
        ])

        self.assertEqual(graph["edges"], [])
        self.assertEqual(graph["nodes"], [])
        self.assertEqual(graph["summary"]["edges"], 0)

    def test_malformed_and_oversized_contracts_are_ignored_fail_closed(self):
        _write(self.orders, "broken.json", "{not-json")
        _write(self.orders, "large-openapi.json", " " * (service_trust_graph.MAX_CONTRACT_BYTES + 1))
        _write(self.checkout, "client.py", "requests.get('http://orders.internal:8080/v1/orders/7')\n")

        graph = service_trust_graph.build([
            ("orders-service", self.orders),
            ("checkout-service", self.checkout),
        ])

        self.assertEqual(graph["summary"], {"repositories": 2, "nodes": 0, "edges": 0, "truncated": False})


class BulkScanServiceGraphIntegrationTests(unittest.TestCase):
    def test_completed_bulk_run_persists_and_returns_service_graph(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = root / "data"
            data.mkdir()
            orders = root / "orders-service"
            checkout = root / "checkout-service"
            orders.mkdir()
            checkout.mkdir()
            _write(orders, "openapi.json", _openapi())
            _write(checkout, "client.py", "requests.get('http://orders.internal:8080/v1/orders/7')\n")

            def run_route(route, payload):
                self.assertEqual(route, "/api/project-audits")
                name = Path(payload["project_path"]).name
                return 201, {"id": f"prj_{name}", "project_name": name, "findings": []}

            with mock.patch.dict(os.environ, {"SNIPER_DATA_DIR": str(data)}):
                created = bulk_scan.create_run(
                    root,
                    [orders, checkout],
                    group="local-services",
                    options=bulk_scan.BulkOptions(sca=False),
                )
                result = bulk_scan.execute(created["id"], run_route)
                stored = bulk_scan.public_run(bulk_scan.get_run(created["id"]), "succeeded")
                listed = bulk_scan.list_runs()[0]

        self.assertEqual(result["status"], "succeeded")
        self.assertEqual(result["service_graph"]["summary"]["edges"], 1)
        self.assertEqual(stored["service_graph"], result["service_graph"])
        self.assertEqual(listed["service_graph"]["edges"], 1)


if __name__ == "__main__":
    unittest.main()
