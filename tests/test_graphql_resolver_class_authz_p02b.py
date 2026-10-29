"""GraphQL-Ruby resolver-class authorization correlation (P0.2b)."""

from __future__ import annotations

from pathlib import Path
import tempfile

import openapi_contract_auditor


SCHEMA = """
type Query {
  order(id: ID!): Order
}

type Order {
  id: ID!
}
"""


def _audit(query_type: str, resolvers: dict[str, str]) -> dict:
    with tempfile.TemporaryDirectory() as raw_base:
        base = Path(raw_base)
        project = base / "project"
        (project / "app/graphql/types").mkdir(parents=True)
        (project / "app/graphql/resolvers").mkdir(parents=True)
        (project / "schema.graphql").write_text(SCHEMA, encoding="utf-8")
        (project / "app/graphql/types/query_type.rb").write_text(query_type, encoding="utf-8")
        for filename, source in resolvers.items():
            (project / "app/graphql/resolvers" / filename).write_text(source, encoding="utf-8")
        return openapi_contract_auditor.audit_project_api_contracts(
            str(project), allowed_roots=(base,)
        )


def _resolver_findings(report: dict) -> list[dict]:
    return [finding for finding in report["findings"] if finding["rule_id"] == "SNIPER-APIT-10"]


def test_unscoped_separate_resolver_class_is_linked_to_schema_field() -> None:
    report = _audit(
        """
module Types
  class QueryType < Types::BaseObject
    field :order,
      resolver: ::Resolvers::OrderResolver
  end
end
""",
        {
            "order_resolver.rb": """
module Resolvers
  class OrderResolver < BaseResolver
    type Types::OrderType, null: true
    argument :id, ID, required: true

    def resolve(id:)
      Order.find(id)
    end
  end
end
"""
        },
    )

    findings = _resolver_findings(report)
    assert len(findings) == 1
    assert findings[0]["location"] == "Query.order -> Resolvers::OrderResolver#resolve"
    assert findings[0]["source_name"] == "app/graphql/resolvers/order_resolver.rb"
    assert findings[0]["lookup"] == "Order.find"
    assert findings[0]["confidence"] == "high"


def test_policy_and_tenant_scoped_resolver_classes_are_passing_controls() -> None:
    policy_report = _audit(
        "field :order, resolver: Resolvers::OrderResolver\n",
        {
            "order_resolver.rb": """
class Resolvers::OrderResolver < Resolvers::BaseResolver
  argument :id, ID, required: true
  def resolve(id:)
    record = Order.find(id)
    authorize(record)
    record
  end
end
"""
        },
    )
    assert _resolver_findings(policy_report) == []

    scoped_report = _audit(
        "field :order, resolver: Resolvers::OrderResolver\n",
        {
            "order_resolver.rb": """
class Resolvers::OrderResolver < Resolvers::BaseResolver
  argument :id, ID, required: true
  def resolve(id:)
    context[:current_user].orders.find(id)
  end
end
"""
        },
    )
    assert _resolver_findings(scoped_report) == []


def test_unreferenced_resolver_class_and_non_root_field_are_not_reported() -> None:
    report = _audit(
        """
module Types
  class QueryType < Types::BaseObject
    field :order, resolver: Resolvers::SafeOrderResolver
    field :admin_order, resolver: Resolvers::AdminOrderResolver
  end
end
""",
        {
            "safe_order_resolver.rb": """
class Resolvers::SafeOrderResolver < Resolvers::BaseResolver
  argument :id, ID, required: true
  def resolve(id:)
    context[:current_user].orders.find(id)
  end
end
""",
            "orphan_order_resolver.rb": """
class Resolvers::OrderResolver < Resolvers::BaseResolver
  argument :id, ID, required: true
  def resolve(id:)
    Order.find(id)
  end
end
""",
            "admin_order_resolver.rb": """
class Resolvers::AdminOrderResolver < Resolvers::BaseResolver
  argument :id, ID, required: true
  def resolve(id:)
    Order.find(id)
  end
end
""",
        },
    )
    assert _resolver_findings(report) == []


def test_method_style_root_resolver_remains_supported() -> None:
    report = _audit(
        """
module Types
  class QueryType < Types::BaseObject
    field :order, Types::OrderType, null: true
    def order(id:)
      Order.find(id)
    end
  end
end
""",
        {},
    )
    findings = _resolver_findings(report)
    assert [finding["location"] for finding in findings] == [
        "Query.order -> Types::QueryType#order"
    ]

