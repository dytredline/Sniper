"""Rails route/authorization inventory: route DSL, before_action and ActiveRecord ownership scope."""
from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import textwrap
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import authz_routes as az  # noqa: E402
import project_analyzer  # noqa: E402


def _src(text: str) -> str:
    return textwrap.dedent(text).lstrip("\n")


def _analyze(files: dict[str, str]):
    result = az.analyze_sources([(name, _src(source)) for name, source in files.items()])
    routes = {(route.file, route.path, "/".join(route.methods)): route for route in result["routes"]}
    return routes, result["findings"]


def _line(source: str, needle: str) -> int:
    for number, text in enumerate(_src(source).splitlines(), 1):
        if needle in text:
            return number
    raise AssertionError(needle)


ROUTES = """
    Rails.application.routes.draw do
      resources :orders, only: [:show, :update, :destroy]
    end
"""


class RailsAuthorizationInventoryTests(unittest.TestCase):
    def test_authenticated_unscoped_find_is_idor_candidate(self):
        controller = """
            class OrdersController < ApplicationController
              before_action :authenticate_user!

              def show
                @order = Order.find(params[:id])
                render json: @order
              end
            end
        """
        routes, findings = _analyze({
            "config/routes.rb": ROUTES,
            "app/controllers/orders_controller.rb": controller,
        })

        route = routes[("app/controllers/orders_controller.rb", "/orders/:id", "GET")]
        self.assertEqual(route.handler, "OrdersController#show")
        self.assertEqual(route.framework, "rails")
        self.assertEqual(route.protection, "before_action:authenticate_user!")
        self.assertEqual(route.idor, {
            "line": _line(controller, "Order.find(params[:id])"),
            "lookup": "Order.find",
        })
        self.assertEqual(
            [(finding["file"], finding["line"], finding["reference"]) for finding in findings],
            [("app/controllers/orders_controller.rb", _line(controller, "Order.find(params[:id])"), "CWE-639")],
        )

    def test_current_user_tenant_and_policy_controls_suppress_idor(self):
        controller = """
            class OrdersController < ApplicationController
              before_action :authenticate_user!

              def show
                @order = current_user.orders.find(params[:id])
              end

              def update
                @order = Current.tenant.orders.find(params[:id])
                @order.update!(order_params)
              end

              def destroy
                @order = Order.find(params[:id])
                authorize @order
                @order.destroy!
              end
            end
        """
        routes, findings = _analyze({
            "config/routes.rb": ROUTES,
            "app/controllers/orders_controller.rb": controller,
        })

        self.assertEqual(len(routes), 3)
        self.assertTrue(all(route.protection for route in routes.values()))
        self.assertTrue(all(route.idor is None for route in routes.values()))
        self.assertEqual(findings, [])

    def test_before_action_only_does_not_protect_other_action(self):
        controller = """
            class OrdersController < ApplicationController
              before_action :authenticate_user!, only: :show

              def show
                @order = current_user.orders.find(params[:id])
              end

              def destroy
                @order = Order.find(params[:id])
                @order.destroy!
              end
            end
        """
        routes, findings = _analyze({
            "config/routes.rb": ROUTES,
            "app/controllers/orders_controller.rb": controller,
        })

        self.assertEqual(routes[("app/controllers/orders_controller.rb", "/orders/:id", "GET")].protection,
                         "before_action:authenticate_user!")
        self.assertIsNone(routes[("app/controllers/orders_controller.rb", "/orders/:id", "DELETE")].protection)
        self.assertEqual(
            [(finding["line"], finding["reference"]) for finding in findings],
            [(_line(controller, "def destroy"), "CWE-862")],
        )

    def test_before_action_loader_carries_lookup_to_the_routed_action(self):
        controller = """
            class OrdersController < ApplicationController
              before_action :authenticate_user!
              before_action :set_order, only: :show

              def show
                render json: @order
              end

              private

              def set_order
                @order = Order.find(params[:id])
              end
            end
        """
        routes, findings = _analyze({
            "config/routes.rb": ROUTES,
            "app/controllers/orders_controller.rb": controller,
        })

        route = routes[("app/controllers/orders_controller.rb", "/orders/:id", "GET")]
        self.assertEqual(route.idor, {
            "line": _line(controller, "Order.find(params[:id])"),
            "lookup": "Order.find",
        })
        self.assertEqual(
            [(finding["line"], finding["reference"]) for finding in findings],
            [(_line(controller, "Order.find(params[:id])"), "CWE-639")],
        )

    def test_project_analyzer_includes_rails_inventory(self):
        controller = """
            class OrdersController < ApplicationController
              before_action :authenticate_user!
              def show
                @order = Order.find(params[:id])
              end
            end
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "rails-app"
            (root / "config").mkdir(parents=True)
            (root / "app" / "controllers").mkdir(parents=True)
            (root / "config" / "routes.rb").write_text(_src(ROUTES))
            (root / "app" / "controllers" / "orders_controller.rb").write_text(_src(controller))
            result = project_analyzer.analyze_project(str(root), allowed_roots=(root.parent,))

        inventory = result["route_inventory"]
        self.assertEqual(inventory["summary"]["frameworks"], {"rails": 1})
        self.assertEqual(inventory["summary"]["idor_candidates"], 1)
        self.assertEqual(
            [(finding["category"], finding["reference"]) for finding in result["findings"]
             if finding["category"] == "authz"],
            [("authz", "CWE-639")],
        )


if __name__ == "__main__":
    unittest.main()


