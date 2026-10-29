"""Rails route inventory and cross-file callback inheritance end-to-end contract."""
from __future__ import annotations

import textwrap
import tempfile
import unittest
from pathlib import Path

import authz_routes
import project_analyzer


def _source(value: str) -> str:
    return textwrap.dedent(value).lstrip("\n")


def _routes(files: dict[str, str]):
    result = authz_routes.analyze_sources(
        [(name, _source(source)) for name, source in files.items()]
    )
    return {
        (route.handler, "/".join(route.methods), route.path): route
        for route in result["routes"]
    }, result


class RailsAuthorizationInheritanceE2ETests(unittest.TestCase):
    def test_project_analyzer_uses_inherited_filter_for_route_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "rails-app"
            (root / "config").mkdir(parents=True)
            controllers = root / "app" / "controllers"
            controllers.mkdir(parents=True)
            (root / "config" / "routes.rb").write_text(
                "get '/orders/:id', to: 'orders#show'\n"
            )
            (controllers / "application_controller.rb").write_text(_source("""
                class ApplicationController < ActionController::Base
                  before_action :authenticate_user!
                end
            """))
            (controllers / "orders_controller.rb").write_text(_source("""
                class OrdersController < ApplicationController
                  def show
                    @order = Order.find(params[:id])
                  end
                end
            """))

            result = project_analyzer.analyze_project(str(root), allowed_roots=(root.parent,))

        inventory = result["route_inventory"]
        self.assertEqual(inventory["summary"]["frameworks"], {"rails": 1})
        self.assertEqual(inventory["routes"][0]["status"], "protected")
        self.assertTrue(inventory["routes"][0]["idor_candidate"])

    def test_namespaced_exact_base_filter_protects_routed_action(self) -> None:
        routes, result = _routes({
            "config/routes.rb": "get '/admin/orders/:id', to: 'admin/orders#show'\n",
            "app/controllers/application_controller.rb": """
                class ApplicationController < ActionController::Base
                end
            """,
            "app/controllers/base_controller.rb": """
                class BaseController < ActionController::Base
                  before_action :unrelated_access_policy
                end
            """,
            "app/controllers/admin/base_controller.rb": """
                class Admin::BaseController < ApplicationController
                  before_action :require_admin
                end
            """,
            "app/controllers/admin/orders_controller.rb": """
                class Admin::OrdersController < BaseController
                  def show
                    @order = Order.find(params[:id])
                  end
                end
            """,
        })

        route = routes[("Admin::OrdersController#show", "GET", "/admin/orders/:id")]
        self.assertEqual(route.protection, "before_action:require_admin")
        self.assertEqual(route.idor["lookup"], "Order.find")
        context = result["rails_controller_contexts"]["Admin::OrdersController"]
        self.assertEqual(
            context.ancestry,
            ("ApplicationController", "Admin::BaseController", "Admin::OrdersController"),
        )
        self.assertNotIn(
            "unrelated_access_policy",
            [item.name for item in context.action("show").effective_filters],
        )

    def test_scoped_skip_reopens_only_selected_action(self) -> None:
        routes, _result = _routes({
            "config/routes.rb": """
                get '/orders/:id', to: 'orders#show'
                patch '/orders/:id', to: 'orders#update'
            """,
            "app/controllers/application_controller.rb": """
                class ApplicationController < ActionController::Base
                  before_action :authenticate_user!, except: :health
                end
            """,
            "app/controllers/orders_controller.rb": """
                class OrdersController < ApplicationController
                  skip_before_action :authenticate_user!, only: :show

                  def show
                    @order = Order.find(params[:id])
                  end

                  def update
                    @order = Order.find(params[:id])
                  end
                end
            """,
        })

        show = routes[("OrdersController#show", "GET", "/orders/:id")]
        update = routes[("OrdersController#update", "PATCH", "/orders/:id")]
        self.assertIsNone(show.protection)
        self.assertEqual(update.protection, "before_action:authenticate_user!")
        self.assertIsNotNone(show.idor)
        self.assertIsNotNone(update.idor)

    def test_dynamic_inherited_filter_is_not_guaranteed_protection(self) -> None:
        routes, result = _routes({
            "config/routes.rb": "get '/reports/:id', to: 'reports#show'\n",
            "app/controllers/application_controller.rb": """
                class ApplicationController < ActionController::Base
                  before_action :authenticate_user!, if: :signed_in?
                end
            """,
            "app/controllers/reports_controller.rb": """
                class ReportsController < ApplicationController
                  def show
                    @report = Report.find(params[:id])
                  end
                end
            """,
        })

        route = routes[("ReportsController#show", "GET", "/reports/:id")]
        self.assertIsNone(route.protection)
        action = result["rails_controller_contexts"]["ReportsController"].action("show")
        self.assertEqual(action.effective_filters, ())
        self.assertEqual([item.name for item in action.uncertain_filters], ["authenticate_user!"])


if __name__ == "__main__":
    unittest.main()

