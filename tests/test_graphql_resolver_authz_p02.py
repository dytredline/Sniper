"""Ruby GraphQL resolver authorization/tenant correlation (P0.2)."""

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


def _audit(resolver: str) -> dict:
    with tempfile.TemporaryDirectory() as raw_base:
        base = Path(raw_base)
        project = base / "project"
        (project / "app/graphql/types").mkdir(parents=True)
        (project / "schema.graphql").write_text(SCHEMA, encoding="utf-8")
        (project / "app/graphql/types/query_type.rb").write_text(resolver, encoding="utf-8")
        return openapi_contract_auditor.audit_project_api_contracts(
            str(project), allowed_roots=(base,)
        )


def _resolver_findings(report: dict) -> list[dict]:
    return [finding for finding in report["findings"] if finding["rule_id"] == "SNIPER-APIT-10"]


def test_unscoped_active_record_lookup_is_linked_to_schema_field() -> None:
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
"""
    )

    findings = _resolver_findings(report)
    assert len(findings) == 1
    assert findings[0]["location"] == "Query.order -> Types::QueryType#order"
    assert findings[0]["source_name"] == "app/graphql/types/query_type.rb"
    assert findings[0]["lookup"] == "Order.find"
    assert findings[0]["severity"] == "high"


def test_user_and_tenant_scoped_resolvers_are_passing_controls() -> None:
    report = _audit(
        """
module Types
  class QueryType < Types::BaseObject
    field :order, Types::OrderType, null: true

    def order(id:)
      context[:current_user].orders.find(id)
    end
  end
end
"""
    )
    assert _resolver_findings(report) == []

    tenant_report = _audit(
        """
module Types
  class QueryType < Types::BaseObject
    field :order, Types::OrderType, null: true

    def order(id:)
      Order.find_by!(id: id, account_id: context[:current_account].id)
    end
  end
end
"""
    )
    assert _resolver_findings(tenant_report) == []


def test_non_schema_method_and_explicit_policy_guard_are_not_reported() -> None:
    report = _audit(
        """
module Types
  class QueryType < Types::BaseObject
    field :order, Types::OrderType, null: true

    def order(id:)
      record = Order.find(id)
      authorize(record)
      record
    end

    def maintenance_lookup(id:)
      Order.find(id)
    end
  end
end
"""
    )
    assert _resolver_findings(report) == []

