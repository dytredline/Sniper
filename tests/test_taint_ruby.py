"""Ruby/Rails taint motoru (taint_goruby): denetleyici kaynakları, ActiveRecord/komut/yönlendirme hedefleri,
ERB görünümleri, before_action, izin listesi korumaları ve Rails 7 yönlendirme koruması."""
from pathlib import Path
import sys
import tempfile
import textwrap
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import taint_goruby as g  # noqa: E402


def _flows(files: dict[str, str]) -> dict[str, list[tuple[str, int]]]:
    res = g.analyze_files({k: textwrap.dedent(v).lstrip("\n") for k, v in files.items()}, "ruby")
    return {k: sorted((f.sink_kind, f.line) for f in v.flows) for k, v in res.items()}


CONTROLLER = """
    class UsersController < ApplicationController
      before_action :set_name, only: [:show]

      def index
        @users = User.where("name = '#{params[:name]}'")
        User.where(name: params[:name])
        User.where("name = ?", params[:name])
        system("ls #{params[:dir]}")
        system("ls", params[:dir])
        redirect_to params[:next]
        redirect_to "/home/#{params[:next]}"
        Marshal.load(Base64.decode64(params[:blob]))
        params[:klass].constantize
        `cat #{params[:file]}`
        User.order(params[:sort].to_i)
      end

      def show
      end

      private

      def set_name
        @name = params[:name]
      end
    end
"""
VIEW = """
    <h1><%= @name %></h1>
    <p><%== @name %></p>
    <p><%= raw @name %></p>
    <p><%= @name.html_safe %></p>
    <%= link_to "home", params[:url] %>
    <%= link_to "home", users_path %>
"""


class RubyTaintTests(unittest.TestCase):
    def test_controller_sinks(self):
        flows = _flows({"app/controllers/users_controller.rb": CONTROLLER})["app/controllers/users_controller.rb"]
        self.assertIn(("sql", 5), flows)
        self.assertNotIn(("sql", 6), flows)
        self.assertNotIn(("sql", 7), flows)
        self.assertIn(("command", 8), flows)
        self.assertNotIn(("command", 9), flows)
        self.assertIn(("redirect", 10), flows)
        self.assertNotIn(("redirect", 11), flows)
        self.assertIn(("deserialize", 12), flows)
        self.assertIn(("eval", 13), flows)
        self.assertIn(("command", 14), flows)
        self.assertNotIn(("sql", 15), flows)

    def test_view_gets_before_action_ivars(self):
        flows = _flows({"app/controllers/users_controller.rb": CONTROLLER,
                        "app/views/users/show.html.erb": VIEW})["app/views/users/show.html.erb"]
        # Aynı kaynaktan aynı türde dosya başına en çok iki hedef raporlanır (4. satır sınır nedeniyle düşer).
        self.assertEqual(flows, [("html", 2), ("html", 3), ("html", 5)])

    def test_cross_file_model_method_and_scope(self):
        files = {
            "app/controllers/reports_controller.rb": """
                class ReportsController < ApplicationController
                  def show
                    Report.by_column(params[:col])
                    Report.run(params[:cmd])
                  end
                end
            """,
            "app/models/report.rb": """
                class Report < ApplicationRecord
                  scope :by_column, ->(col) { select("#{col}") }

                  def self.run(cmd)
                    system("report #{cmd}")
                  end
                end
            """,
        }
        flows = _flows(files)
        self.assertEqual(flows["app/models/report.rb"], [("command", 5), ("sql", 2)])

    def test_allowlist_guards(self):
        src = """
            class ExportsController < ApplicationController
              def a
                name = params[:name]
                return head(:bad_request) unless %w[csv pdf].include?(name)
                Export.send("to_#{name}")
              end

              def b
                kind = params[:kind]
                if Export::KINDS.include?(kind)
                  Export.public_send(kind)
                end
                Export.public_send(kind)
              end
            end
        """
        flows = _flows({"app/controllers/exports_controller.rb": src})["app/controllers/exports_controller.rb"]
        self.assertEqual(flows, [("eval", 13)])

    def test_hash_and_permit_arguments_are_safe(self):
        src = """
            class ItemsController < ApplicationController
              def index
                filters = params.permit(:a, :b).to_h
                Item.where(filters)
                Item.find_by(params.permit(:id))
                Item.where(params[:key] => params[:value])
                Item.where("x" => params[:value])
                Item.exists?(params[:id].to_s)
              end
            end
        """
        flows = _flows({"app/controllers/items_controller.rb": src})["app/controllers/items_controller.rb"]
        self.assertEqual(flows, [("sql", 6)])

    def test_rails7_open_redirect_protection(self):
        files = {
            "config/application.rb": "module App\n  class Application < Rails::Application\n    config.load_defaults 7.1\n  end\nend\n",
            "app/controllers/s_controller.rb": """
                class SController < ApplicationController
                  def a
                    redirect_to params[:next]
                    redirect_to params[:next], allow_other_host: true
                  end
                end
            """,
        }
        self.assertEqual(_flows(files)["app/controllers/s_controller.rb"], [("redirect", 4)])

    def test_non_controller_params_is_not_a_source(self):
        src = """
            class Builder
              def call(params)
                system("x #{params[:a]}")
              end
            end
        """
        self.assertEqual(_flows({"lib/builder.rb": src})["lib/builder.rb"], [])

    def test_sinatra_route_params(self):
        src = """
            require 'sinatra'

            get '/run/:cmd' do |cmd|
              system(cmd)
              `echo #{params[:x]}`
            end
        """
        self.assertEqual(_flows({"app.rb": src})["app.rb"], [("command", 4), ("command", 5)])

    def test_project_analyzer_reports_ruby_and_erb(self):
        import project_analyzer

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "railsapp"
            (root / "app/controllers").mkdir(parents=True)
            (root / "app/views/users").mkdir(parents=True)
            (root / "app/controllers/users_controller.rb").write_text(textwrap.dedent(CONTROLLER).lstrip("\n"))
            (root / "app/views/users/show.html.erb").write_text(textwrap.dedent(VIEW).lstrip("\n"))
            result = project_analyzer.analyze_project(str(root), allowed_roots=(Path(tmp),))
        flows = {(f["file"], f["line"]) for f in result["findings"] if f.get("taint_flow")}
        self.assertIn(("app/controllers/users_controller.rb", 5), flows)
        self.assertIn(("app/views/users/show.html.erb", 2), flows)
        self.assertEqual(result["languages"].get("Ruby"), 2)


if __name__ == "__main__":
    unittest.main()
