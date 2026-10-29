"""Yerel depolar arası webhook producer/receiver korelasyonu."""
from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import bulk_scan
import webhook_trust_graph


def _write(root: Path, relative: str, text: str) -> None:
    target = root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")


def _contract(*, secured: bool = True) -> str:
    operation = {"responses": {"204": {"description": "accepted"}}}
    if secured:
        operation["security"] = [{"webhookSignature": []}]
    return json.dumps({
        "openapi": "3.0.3",
        "info": {"title": "Events", "version": "1"},
        "servers": [{"url": "https://events.internal"}],
        "paths": {
            "/webhooks/orders/{event_id}": {"post": operation},
            "/v1/orders/{order_id}": {"post": operation},
        },
        "components": {"securitySchemes": {"webhookSignature": {"type": "apiKey", "in": "header", "name": "X-Signature"}}},
    })


class WebhookTrustGraphTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.orders = self.root / "orders"
        self.events = self.root / "events"
        self.orders.mkdir()
        self.events.mkdir()

    def test_literal_webhook_post_links_producer_to_receiver_without_raw_origin(self):
        _write(self.events, "openapi.json", _contract())
        _write(self.orders, "publish.py", (
            "import requests\n"
            "requests.post('https://events.internal/webhooks/orders/evt-7', json=payload)\n"
        ))

        graph = webhook_trust_graph.build([("orders", self.orders), ("events", self.events)])

        self.assertEqual(graph["format"], "sniper-webhook-trust-graph-v1")
        self.assertEqual(graph["summary"], {
            "repositories": 2, "nodes": 2, "edges": 1, "review_edges": 1, "truncated": False,
        })
        self.assertEqual(graph["nodes"], [
            {"id": "repo:events", "repository": "events", "roles": ["receiver"]},
            {"id": "repo:orders", "repository": "orders", "roles": ["producer"]},
        ])
        self.assertEqual(graph["edges"], [{
            "producer": "repo:orders",
            "receiver": "repo:events",
            "protocol": "webhook-http",
            "operation": "POST /webhooks/orders/{event_id}",
            "trust_signals": {
                "receiver_auth_declared": True,
                "producer_signature_signal": False,
                "status": "review",
            },
            "evidence": {"file": "publish.py", "line": 2, "kind": "openapi-webhook+literal-post"},
        }])
        rendered = json.dumps(graph, sort_keys=True)
        self.assertNotIn("events.internal", rendered)
        self.assertNotIn("https://", rendered)

    def test_matching_signature_signal_is_recorded_without_claiming_runtime_verification(self):
        _write(self.events, "openapi.json", _contract())
        _write(self.orders, "publish.py", (
            "requests.post('https://events.internal/webhooks/orders/evt-7', "
            "headers={'X-Signature': hmac_digest}, json=payload)\n"
        ))

        graph = webhook_trust_graph.build([("orders", self.orders), ("events", self.events)])

        self.assertEqual(graph["edges"][0]["trust_signals"], {
            "receiver_auth_declared": True,
            "producer_signature_signal": True,
            "status": "signals-present",
        })
        self.assertEqual(graph["summary"]["review_edges"], 0)

    def test_self_call_generic_api_and_dynamic_url_do_not_link(self):
        _write(self.events, "openapi.json", _contract())
        _write(self.events, "self.py", "requests.post('https://events.internal/webhooks/orders/e-1')\n")
        _write(self.orders, "publish.py", (
            "requests.post('https://events.internal/v1/orders/7')\n"
            "requests.post(WEBHOOK_URL, json=payload)\n"
            "requests.get('https://events.internal/webhooks/orders/e-1')\n"
        ))

        graph = webhook_trust_graph.build([("orders", self.orders), ("events", self.events)])

        self.assertEqual(graph["edges"], [])
        self.assertEqual(graph["nodes"], [])

    def test_malformed_and_oversized_contracts_are_ignored(self):
        _write(self.events, "broken-openapi.json", "{broken")
        _write(self.events, "large-openapi.json", " " * (webhook_trust_graph.MAX_CONTRACT_BYTES + 1))
        _write(self.orders, "publish.py", "requests.post('https://events.internal/webhooks/orders/e-1')\n")

        graph = webhook_trust_graph.build([("orders", self.orders), ("events", self.events)])

        self.assertEqual(graph["summary"], {
            "repositories": 2, "nodes": 0, "edges": 0, "review_edges": 0, "truncated": False,
        })


class BulkWebhookGraphIntegrationTests(unittest.TestCase):
    def test_bulk_run_persists_webhook_graph_and_lists_summary(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = root / "data"
            data.mkdir()
            orders = root / "orders"
            events = root / "events"
            orders.mkdir()
            events.mkdir()
            _write(events, "openapi.json", _contract())
            _write(orders, "publish.py", "requests.post('https://events.internal/webhooks/orders/e-1')\n")

            def run_route(route, payload):
                self.assertEqual(route, "/api/project-audits")
                name = Path(payload["project_path"]).name
                return 201, {"id": f"prj_{name}", "project_name": name, "findings": []}

            with mock.patch.dict(os.environ, {"SNIPER_DATA_DIR": str(data)}):
                created = bulk_scan.create_run(
                    root,
                    [orders, events],
                    group="local-webhooks",
                    options=bulk_scan.BulkOptions(sca=False),
                )
                result = bulk_scan.execute(created["id"], run_route)
                stored = bulk_scan.public_run(bulk_scan.get_run(created["id"]), "succeeded")
                listed = bulk_scan.list_runs()[0]

        self.assertEqual(result["webhook_graph"]["summary"]["edges"], 1)
        self.assertEqual(stored["webhook_graph"], result["webhook_graph"])
        self.assertEqual(listed["webhook_graph"]["edges"], 1)


if __name__ == "__main__":
    unittest.main()
