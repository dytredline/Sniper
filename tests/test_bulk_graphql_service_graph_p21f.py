"""Cross-repository GraphQL producer/consumer service graph (P2.1f)."""

from __future__ import annotations

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


def _execute(root: Path, repos: list[Path], monkeypatch) -> tuple[dict, dict]:
    data = root.parent / "data"
    data.mkdir(exist_ok=True)
    monkeypatch.setenv("SNIPER_DATA_DIR", str(data))
    run = bulk_scan.create_run(
        root,
        repos,
        group="graphql-services",
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


def test_bulk_execute_links_exact_query_and_mutation_root_fields_without_endpoint_or_token(
    tmp_path, monkeypatch,
) -> None:
    root = tmp_path / "portfolio"
    producer = _repo(
        root,
        "catalog-api",
        {
            "graphql/schema.graphql": """
schema {
  query: CatalogQuery
  mutation: CatalogMutation
}
type CatalogQuery {
  product(id: ID!): Product
  health: Boolean!
}
type CatalogMutation {
  updateProduct(id: ID!, name: String!): Product
}
type Product { id: ID!, name: String! }
""",
        },
    )
    consumer = _repo(
        root,
        "storefront",
        {
            "graphql/catalog.graphql": """
query ProductScreen($id: ID!) {
  selected: product(id: $id) { id name }
}
mutation SaveProduct($id: ID!, $name: String!) {
  updateProduct(id: $id, name: $name) { id }
}
""",
            ".env.local": (
                "GRAPHQL_ENDPOINT=https://graphql.private.example.test/api\n"
                "GRAPHQL_TOKEN=glpat-should-never-appear\n"
            ),
        },
    )

    result, stored = _execute(root, [producer, consumer], monkeypatch)
    graph = result["graphql_service_graph"]

    assert graph["format"] == "sniper-bulk-graphql-service-graph/1"
    assert graph["status"] == "evaluated"
    assert graph["producer_operation_count"] == 3
    assert graph["consumer_operation_count"] == 2
    assert graph["edge_count"] == 2
    assert graph["edges"] == [
        {
            "producer_repo": "catalog-api",
            "consumer_repo": "storefront",
            "operation_type": "mutation",
            "root_field": "updateProduct",
        },
        {
            "producer_repo": "catalog-api",
            "consumer_repo": "storefront",
            "operation_type": "query",
            "root_field": "product",
        },
    ]
    assert stored["graphql_service_graph"] == graph
    summary = bulk_scan.list_runs()[0]["graphql_service_graph"]
    assert summary == {
        "format": "sniper-bulk-graphql-service-graph/1",
        "status": "evaluated",
        "producer_operation_count": 3,
        "consumer_operation_count": 2,
        "edge_count": 2,
        "skipped_file_count": 0,
        "ambiguous_producer_count": 0,
    }
    serialized = json.dumps(result)
    assert "graphql.private.example.test" not in serialized
    assert "glpat-should-never-appear" not in serialized
    assert ".env.local" not in serialized


def test_only_distinct_repo_exact_operation_type_and_root_field_create_edges(tmp_path, monkeypatch) -> None:
    root = tmp_path / "portfolio"
    producer = _repo(
        root,
        "inventory-api",
        {
            "schema.graphql": """
type Query {
  thing(id: ID!): Thing
}
type Mutation {
  updateThing(id: ID!): Thing
}
""",
        },
    )
    exact = _repo(root, "exact-client", {"thing.graphql": "query LoadThing { thing { id } }\n"})
    wrong_type = _repo(root, "wrong-type", {"thing.graphql": "mutation LoadThing { thing { id } }\n"})
    wrong_field = _repo(root, "wrong-field", {"thing.graphql": "query LoadThings { things { id } }\n"})
    self_repo = _repo(
        root,
        "self-contained",
        {
            "schema.graphql": "type Query { selfField: String }\n",
            "operation.graphql": "query ReadSelf { selfField }\n",
        },
    )

    result, _stored = _execute(
        root,
        [producer, exact, wrong_type, wrong_field, self_repo],
        monkeypatch,
    )
    graph = result["graphql_service_graph"]

    assert graph["edge_count"] == 1
    assert graph["edges"] == [{
        "producer_repo": "inventory-api",
        "consumer_repo": "exact-client",
        "operation_type": "query",
        "root_field": "thing",
    }]
    assert all(edge["producer_repo"] != edge["consumer_repo"] for edge in graph["edges"])


def test_dynamic_fragments_only_introspection_oversize_and_ambiguous_producers_fail_closed(
    tmp_path, monkeypatch,
) -> None:
    root = tmp_path / "portfolio"
    producer_a = _repo(root, "api-a", {"schema.graphql": "type Query { publicData: String }\n"})
    producer_b = _repo(root, "api-b", {"schema.graphql": "type Query { publicData: String }\n"})
    consumer = _repo(
        root,
        "client",
        {
            "valid.graphql": "query LoadPublic { publicData }\n",
            "dynamic.graphql": "query Dynamic { ${rootField} }\n",
            "fragment.graphql": "fragment PublicFields on Query { publicData }\n",
            "introspection.graphql": "query Inspect { __schema { queryType { name } } }\n",
            "oversize.graphql": "#" * 128_001,
            "local-token.txt": "eyJhbGciOiJIUzI1NiJ9.secret.signature",
        },
    )

    result, _stored = _execute(root, [producer_a, producer_b, consumer], monkeypatch)
    graph = result["graphql_service_graph"]

    assert graph["edge_count"] == 0
    assert graph["edges"] == []
    assert graph["ambiguous_producer_count"] == 1
    assert graph["skipped_file_count"] == 2
    assert graph["files_truncated"] is False
    serialized = json.dumps(result)
    assert "secret.signature" not in serialized
    assert "rootField" not in serialized


def test_graphql_service_graph_scope_is_documented() -> None:
    root = Path(__file__).resolve().parents[1]
    capabilities = (root / "docs" / "CAPABILITIES.md").read_text(encoding="utf-8")
    guide = (root / "docs" / "KULLANIM-KILAVUZU.md").read_text(encoding="utf-8")

    assert "GraphQL servis grafiği" in capabilities
    assert "exact operation type + root field" in guide
