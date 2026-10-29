"""Combined Rails route and GraphQL-Ruby authorization engine boundaries."""
from __future__ import annotations

from pathlib import Path
import tempfile
import textwrap

import authz_routes
import openapi_contract_auditor
import project_analyzer


def _source(value: str) -> str:
    return textwrap.dedent(value).lstrip("\n")


def test_one_fixture_keeps_rails_routes_and_graphql_resolvers_separate() -> None:
    files = {
        "config/routes.rb": "get '/orders/:id', to: 'orders#show'\n",
        "app/controllers/application_controller.rb": _source("""
            class ApplicationController < ActionController::Base
              before_action :authenticate_user!
            end
        """),
        "app/controllers/orders_controller.rb": _source("""
            class OrdersController < ApplicationController
              def show
                @order = Order.find(params[:id])
              end
            end
        """),
        "schema.graphql": _source("""
            type Query {
              order(id: ID!): Order
            }
            type Order { id: ID! }
        """),
        "app/graphql/types/query_type.rb": _source("""
            module Types
              class QueryType < Types::BaseObject
                field :order, Types::OrderType, null: true
                def order(id:)
                  Order.find(id)
                end
              end
            end
        """),
    }

    direct_routes = authz_routes.analyze_sources(list(files.items()))["routes"]
    assert [(route.framework, route.handler, route.protection) for route in direct_routes] == [
        ("rails", "OrdersController#show", "before_action:authenticate_user!"),
    ]

    with tempfile.TemporaryDirectory() as raw_base:
        base = Path(raw_base)
        project = base / "project"
        for relative, source in files.items():
            destination = project / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(source, encoding="utf-8")

        api_report = openapi_contract_auditor.audit_project_api_contracts(
            str(project), allowed_roots=(base,)
        )
        project_report = project_analyzer.analyze_project(
            str(project), allowed_roots=(base,)
        )

    resolver_findings = [
        item for item in api_report["findings"] if item["rule_id"] == "SNIPER-APIT-10"
    ]
    assert [(item["location"], item["source_name"]) for item in resolver_findings] == [
        ("Query.order -> Types::QueryType#order", "app/graphql/types/query_type.rb"),
    ]
    assert api_report["resolver_finding_count"] == 1

    inventory = project_report["route_inventory"]
    assert inventory["summary"]["total"] == 1
    assert inventory["summary"]["frameworks"] == {"rails": 1}
    assert inventory["routes"][0]["handler"] == "OrdersController#show"
