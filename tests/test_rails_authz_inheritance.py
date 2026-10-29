"""Cross-file Rails controller callback inheritance for authorization inventory."""
from __future__ import annotations

import textwrap
import unittest

import authz_routes
from rails_authz_inheritance import analyze_rails_controller_inheritance


def _source(value: str) -> str:
    return textwrap.dedent(value).lstrip("\n")


class RailsAuthorizationInheritanceTests(unittest.TestCase):
    def test_route_analyzer_exposes_context_for_rails_adapter(self) -> None:
        result = authz_routes.analyze_sources([
            ("app/controllers/application_controller.rb", _source("""
                class ApplicationController < ActionController::Base
                  before_action :authenticate_user!
                end
            """)),
            ("app/controllers/orders_controller.rb", _source("""
                class OrdersController < ApplicationController
                  def show; end
                end
            """)),
        ])

        context = result["rails_controller_contexts"]["OrdersController"].action("show")
        self.assertEqual([item.name for item in context.effective_filters], ["authenticate_user!"])

    def test_cross_file_namespace_inheritance_skip_only_and_except(self) -> None:
        contexts = analyze_rails_controller_inheritance({
            "app/controllers/application_controller.rb": _source("""
                class ApplicationController < ActionController::Base
                  before_action :authenticate_user!, except: [:health]
                end
            """),
            "app/controllers/base_controller.rb": _source("""
                class BaseController < ActionController::Base
                  before_action :unrelated_tenant_policy
                end
            """),
            "app/controllers/admin/base_controller.rb": _source("""
                class Admin::BaseController < ApplicationController
                  before_action :require_admin, only: [:show, :update]
                  before_action :authorize_member!, except: [:preview]
                end
            """),
            "app/controllers/admin/reports_controller.rb": _source("""
                class Admin::ReportsController < BaseController
                  skip_before_action :authenticate_user!, only: :show
                  before_action :load_report, only: [:show, :update]

                  def show; end
                  def update; end
                  def preview; end
                  def health; end
                end
            """),
        })

        controller = contexts["Admin::ReportsController"]
        self.assertEqual(
            controller.ancestry,
            ("ApplicationController", "Admin::BaseController", "Admin::ReportsController"),
        )
        self.assertTrue(controller.inheritance_complete)

        show = controller.action("show")
        self.assertEqual(
            [item.name for item in show.effective_filters],
            ["require_admin", "authorize_member!", "load_report"],
        )
        self.assertEqual([item.name for item in show.skipped_filters], ["authenticate_user!"])
        self.assertEqual([item.name for item in show.local_filters], ["load_report"])
        self.assertEqual(
            [item.name for item in show.inherited_filters],
            ["require_admin", "authorize_member!"],
        )

        update = controller.action("update")
        self.assertEqual(
            [item.name for item in update.effective_filters],
            ["authenticate_user!", "require_admin", "authorize_member!", "load_report"],
        )
        preview = controller.action("preview")
        self.assertEqual([item.name for item in preview.effective_filters], ["authenticate_user!"])
        health = controller.action("health")
        self.assertEqual([item.name for item in health.effective_filters], ["authorize_member!"])

        all_names = {item.name for action in (show, update, preview, health) for item in action.effective_filters}
        self.assertNotIn("unrelated_tenant_policy", all_names)

    def test_dynamic_callback_is_uncertain_not_a_guaranteed_guard(self) -> None:
        contexts = analyze_rails_controller_inheritance({
            "app/controllers/application_controller.rb": _source("""
                class ApplicationController < ActionController::Base
                  before_action :authenticate_user!, if: :signed_in?
                end
            """),
            "app/controllers/orders_controller.rb": _source("""
                class OrdersController < ApplicationController
                  def show; end
                end
            """),
        })

        action = contexts["OrdersController"].action("show")
        self.assertEqual(action.effective_filters, ())
        self.assertEqual([item.name for item in action.uncertain_filters], ["authenticate_user!"])

    def test_conflicting_superclasses_fail_closed_without_cross_class_leakage(self) -> None:
        contexts = analyze_rails_controller_inheritance({
            "app/controllers/application_controller.rb": _source("""
                class ApplicationController < ActionController::Base
                  before_action :authenticate_user!
                end
            """),
            "app/controllers/legacy_controller.rb": _source("""
                class LegacyController < ActionController::Base
                  before_action :legacy_admin
                end
            """),
            "app/controllers/orders_controller.rb": _source("""
                class OrdersController < ApplicationController
                  def show; end
                end
            """),
            "app/controllers/orders_extension.rb": _source("""
                class OrdersController < LegacyController
                end
            """),
        })

        orders = contexts["OrdersController"]
        self.assertFalse(orders.inheritance_complete)
        self.assertEqual(orders.ancestry, ("OrdersController",))
        self.assertEqual(orders.action("show").effective_filters, ())

    def test_malformed_non_utf8_source_is_ignored(self) -> None:
        contexts = analyze_rails_controller_inheritance({
            "app/controllers/broken_controller.rb": "class BrokenController\n\ud800end",
        })
        self.assertEqual(contexts, {})


if __name__ == "__main__":
    unittest.main()


