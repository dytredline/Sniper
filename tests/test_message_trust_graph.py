"""Yerel Kafka publisher/consumer graph sözleşmeleri."""
from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import bulk_scan
import message_trust_graph


def _write(root: Path, relative: str, text: str) -> None:
    target = root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")


class MessageTrustGraphTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.orders = self.root / "orders"
        self.billing = self.root / "billing"
        self.orders.mkdir()
        self.billing.mkdir()

    def test_python_kafka_literal_topic_links_different_repositories_without_broker_secrets(self) -> None:
        _write(self.orders, "publish.py", (
            "from kafka import KafkaProducer\n"
            "producer = KafkaProducer(bootstrap_servers=['kafka.internal:9092'], "
            "sasl_plain_password='do-not-return')\n"
            "producer.send('orders.created', value=payload)\n"
        ))
        _write(self.billing, "consume.py", (
            "from kafka import KafkaConsumer\n"
            "consumer = KafkaConsumer('orders.created', bootstrap_servers=['kafka.internal:9092'], "
            "sasl_plain_password='do-not-return')\n"
        ))

        graph = message_trust_graph.build([("orders", self.orders), ("billing", self.billing)])

        self.assertEqual(graph["format"], "sniper-message-trust-graph-v1")
        self.assertEqual(graph["summary"], {
            "repositories": 2, "nodes": 2, "edges": 1, "truncated": False,
        })
        self.assertEqual(graph["nodes"], [
            {"id": "repo:billing", "repository": "billing", "roles": ["consumer"]},
            {"id": "repo:orders", "repository": "orders", "roles": ["publisher"]},
        ])
        self.assertEqual(graph["edges"], [{
            "publisher": "repo:orders",
            "consumer": "repo:billing",
            "broker": "kafka",
            "channel": "orders.created",
            "evidence": {
                "publisher": {"file": "publish.py", "line": 3, "kind": "KafkaProducer.send"},
                "consumer": {"file": "consume.py", "line": 2, "kind": "KafkaConsumer"},
            },
        }])
        rendered = json.dumps(graph, sort_keys=True)
        self.assertNotIn("kafka.internal", rendered)
        self.assertNotIn("do-not-return", rendered)
        self.assertNotIn("bootstrap_servers", rendered)
        self.assertNotIn("sasl", rendered.casefold())

    def test_confluent_produce_and_subscribe_literals_are_correlated(self) -> None:
        _write(self.orders, "publish.py", (
            "from confluent_kafka import Producer\n"
            "events = Producer({'bootstrap.servers': 'broker.local:9092'})\n"
            "events.produce(topic='billing.events', value=payload)\n"
        ))
        _write(self.billing, "consume.py", (
            "from confluent_kafka import Consumer\n"
            "worker = Consumer({'bootstrap.servers': 'broker.local:9092', 'group.id': 'billing'})\n"
            "worker.subscribe(['billing.events'])\n"
        ))

        graph = message_trust_graph.build([("orders", self.orders), ("billing", self.billing)])

        self.assertEqual(graph["summary"]["edges"], 1)
        self.assertEqual(graph["edges"][0]["channel"], "billing.events")
        self.assertEqual(graph["edges"][0]["evidence"]["publisher"]["kind"], "Producer.produce")
        self.assertEqual(graph["edges"][0]["evidence"]["consumer"]["kind"], "Consumer.subscribe")

    def test_self_dynamic_mismatch_and_generic_send_fail_closed(self) -> None:
        _write(self.orders, "both.py", (
            "from kafka import KafkaProducer, KafkaConsumer\n"
            "producer = KafkaProducer()\n"
            "consumer = KafkaConsumer('same.topic')\n"
            "producer.send('same.topic', value=b'x')\n"
            "producer.send(topic_name, value=b'x')\n"
        ))
        _write(self.billing, "other.py", (
            "class Client:\n"
            "    def send(self, channel, value): pass\n"
            "client = Client()\n"
            "client.send('same.topic', b'x')\n"
            "from kafka import KafkaConsumer\n"
            "different = KafkaConsumer('different.topic')\n"
        ))

        graph = message_trust_graph.build([("orders", self.orders), ("billing", self.billing)])

        self.assertEqual(graph["edges"], [])
        self.assertEqual(graph["nodes"], [])

    def test_malformed_and_oversized_python_are_ignored(self) -> None:
        _write(self.orders, "broken.py", "from kafka import KafkaProducer\nif (: broken\n")
        _write(self.orders, "large.py", " " * (message_trust_graph.MAX_SOURCE_BYTES + 1))
        _write(self.billing, "consume.py", (
            "from kafka import KafkaConsumer\nconsumer = KafkaConsumer('orders.created')\n"
        ))

        graph = message_trust_graph.build([("orders", self.orders), ("billing", self.billing)])

        self.assertEqual(graph["summary"], {
            "repositories": 2, "nodes": 0, "edges": 0, "truncated": False,
        })


class BulkMessageGraphIntegrationTests(unittest.TestCase):
    def test_bulk_run_persists_message_graph_and_lists_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = root / "data"
            data.mkdir()
            orders = root / "orders"
            billing = root / "billing"
            orders.mkdir()
            billing.mkdir()
            _write(orders, "publish.py", (
                "from kafka import KafkaProducer\nproducer = KafkaProducer()\n"
                "producer.send('orders.created', value=payload)\n"
            ))
            _write(billing, "consume.py", (
                "from kafka import KafkaConsumer\nconsumer = KafkaConsumer('orders.created')\n"
            ))

            def run_route(route, payload):
                self.assertEqual(route, "/api/project-audits")
                name = Path(payload["project_path"]).name
                return 201, {"id": f"prj_{name}", "project_name": name, "findings": []}

            with mock.patch.dict(os.environ, {"SNIPER_DATA_DIR": str(data)}):
                created = bulk_scan.create_run(
                    root,
                    [orders, billing],
                    group="local-messages",
                    options=bulk_scan.BulkOptions(sca=False),
                )
                result = bulk_scan.execute(created["id"], run_route)
                stored = bulk_scan.public_run(bulk_scan.get_run(created["id"]), "succeeded")
                listed = bulk_scan.list_runs()[0]

        self.assertEqual(result["message_graph"]["summary"]["edges"], 1)
        self.assertEqual(stored["message_graph"], result["message_graph"])
        self.assertEqual(listed["message_graph"]["edges"], 1)


if __name__ == "__main__":
    unittest.main()
