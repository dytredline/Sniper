"""Advanced bounded GraphQL service-graph contracts (Wave 2 / R3)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import bulk_scan


def _repo(root: Path, name: str, files: dict[str, str]) -> Path:
    repo = root / name
    repo.mkdir(parents=True)
    for relative, content in files.items():
        target = repo / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    return repo


def _execute(root: Path, repos: list[Path], monkeypatch) -> dict:
    data = root.parent / "data"
    data.mkdir(exist_ok=True)
    monkeypatch.setenv("SNIPER_DATA_DIR", str(data))
    run = bulk_scan.create_run(
        root,
        repos,
        group="graphql-advanced",
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

    return bulk_scan.execute(run["id"], route)["graphql_service_graph"]


def test_existing_federation_and_stitching_root_extensions_remain_supported(
    tmp_path, monkeypatch,
) -> None:
    root = tmp_path / "portfolio"
    producer = _repo(
        root,
        "federated-api",
        {
            "schema.graphql": """
extend schema @link(url: "https://specs.apollo.dev/federation/v2.7") {
  query: FederatedQuery
}
extend type FederatedQuery @key(fields: "id") { federatedProduct: String }
""",
        },
    )
    stitched = _repo(
        root,
        "stitched-api",
        {"schema.graphql": "extend type Query { stitchedProduct: String }\n"},
    )
    consumer = _repo(
        root,
        "gateway",
        {
            "operations.graphql": """
query Federated { federatedProduct }
query Stitched { stitchedProduct }
""",
        },
    )

    graph = _execute(root, [producer, stitched, consumer], monkeypatch)

    assert graph["edges"] == [
        {
            "producer_repo": "federated-api",
            "consumer_repo": "gateway",
            "operation_type": "query",
            "root_field": "federatedProduct",
        },
        {
            "producer_repo": "stitched-api",
            "consumer_repo": "gateway",
            "operation_type": "query",
            "root_field": "stitchedProduct",
        },
    ]


def test_named_root_fragments_and_subscription_operations_create_exact_edges(
    tmp_path, monkeypatch,
) -> None:
    root = tmp_path / "portfolio"
    producer = _repo(
        root,
        "catalog-api",
        {
            "schema.graphql": """
schema { query: CatalogQuery subscription: CatalogSubscription }
type CatalogQuery { product(id: ID!): Product }
type CatalogSubscription { productChanged: Product }
type Product { id: ID! }
""",
        },
    )
    consumer = _repo(
        root,
        "storefront",
        {
            "operations.graphql": """
fragment ProductRoot on Query { product(id: "1") { id } }
fragment ProductEvents on Subscription { productChanged { id } }
query ProductScreen { ...ProductRoot }
subscription WatchProducts { ...ProductEvents }
""",
        },
    )

    graph = _execute(root, [producer, consumer], monkeypatch)

    assert graph["producer_operation_count"] == 2
    assert graph["consumer_operation_count"] == 2
    assert graph["edges"] == [
        {
            "producer_repo": "catalog-api",
            "consumer_repo": "storefront",
            "operation_type": "query",
            "root_field": "product",
        },
        {
            "producer_repo": "catalog-api",
            "consumer_repo": "storefront",
            "operation_type": "subscription",
            "root_field": "productChanged",
        },
    ]


def test_sha256_verified_apollo_persisted_manifest_creates_consumer_edge(
    tmp_path, monkeypatch,
) -> None:
    root = tmp_path / "portfolio"
    producer = _repo(root, "catalog-api", {"schema.graphql": "type Query { product: String }\n"})
    body = "query PersistedProduct { product }"
    operation_id = hashlib.sha256(body.encode("utf-8")).hexdigest()
    consumer = _repo(
        root,
        "mobile-client",
        {
            "persisted-query-manifest.json": json.dumps({
                "format": "apollo-persisted-query-manifest",
                "version": 1,
                "operations": [{
                    "id": operation_id,
                    "name": "PersistedProduct",
                    "type": "query",
                    "body": body,
                }],
            }),
        },
    )

    graph = _execute(root, [producer, consumer], monkeypatch)

    assert graph["consumer_operation_count"] == 1
    assert graph["edges"] == [{
        "producer_repo": "catalog-api",
        "consumer_repo": "mobile-client",
        "operation_type": "query",
        "root_field": "product",
    }]
    serialized = json.dumps(graph)
    assert operation_id not in serialized
    assert body not in serialized


def test_fragment_cycles_wrong_root_types_and_invalid_persisted_hashes_fail_closed(
    tmp_path, monkeypatch,
) -> None:
    root = tmp_path / "portfolio"
    producer = _repo(root, "catalog-api", {"schema.graphql": "type Query { product: String }\n"})
    invalid_body = "query Forged { product }"
    invalid = _repo(
        root,
        "invalid-client",
        {
            "operations.graphql": """
fragment A on Query { ...B }
fragment B on Query { ...A }
fragment NestedOnly on Product { product }
query Cycle { ...A }
query WrongType { ...NestedOnly }
query Inline { ... on Query { product } }
""",
            "persisted-query-manifest.json": json.dumps({
                "format": "apollo-persisted-query-manifest",
                "version": 1,
                "operations": [{
                    "id": "0" * 64,
                    "name": "Forged",
                    "type": "query",
                    "body": invalid_body,
                }],
            }),
        },
    )
    malformed = _repo(
        root,
        "malformed-client",
        {
            "persisted-query-manifest.json": json.dumps({
                "format": "apollo-persisted-query-manifest",
                "version": 1,
                "operations": [{
                    "id": hashlib.sha256(invalid_body.encode("utf-8")).hexdigest(),
                    "name": "Forged",
                    "type": ["query"],
                    "body": invalid_body,
                }],
            }),
        },
    )

    graph = _execute(root, [producer, invalid, malformed], monkeypatch)

    assert graph["consumer_operation_count"] == 0
    assert graph["edge_count"] == 0
    assert graph["edges"] == []
    assert graph["skipped_file_count"] == 2
    serialized = json.dumps(graph)
    assert invalid_body not in serialized
    assert "0" * 64 not in serialized


def test_graphql_advanced_scope_and_fail_closed_boundaries_are_documented() -> None:
    root = Path(__file__).resolve().parents[1]
    capabilities = (root / "docs" / "CAPABILITIES.md").read_text(encoding="utf-8")
    guide = (root / "docs" / "KULLANIM-KILAVUZU.md").read_text(encoding="utf-8")
    llms = (root / "llms.txt").read_text(encoding="utf-8")

    assert "`Query`/`Mutation`/`Subscription`" in capabilities
    assert "SHA-256 doğrulanmış `persisted-query-manifest.json`" in capabilities
    assert "inline/çözülemeyen/döngülü" in guide
    assert "persisted bodies/IDs" in llms
