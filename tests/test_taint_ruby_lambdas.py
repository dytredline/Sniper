"""Ruby taint motoru (14. tur): saklanan lambda/proc ve yöntem nesneleri (``r.call(x)``, ``EYLEMLER[k].call(x)``,
``method(:ad).call(x)``) çağrıldığında gövdeleri argüman iziyle değerlendirilir."""
from pathlib import Path
import sys
import textwrap
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import taint_goruby as g  # noqa: E402


def _flows(src: str) -> list[tuple[str, int]]:
    res = g.analyze_files({"app/controllers/users_controller.rb": textwrap.dedent(src).lstrip("\n")}, "ruby")
    return sorted({(f.sink_kind, f.line) for a in res.values() for f in a.flows})


class RubyLambdaTests(unittest.TestCase):
    def test_local_lambda_and_do_block_lambda(self):
        src = """
            class UsersController < ApplicationController
              def go
                runner = ->(cmd) { system(cmd) }
                runner.call(params[:c])
                r = lambda do |c|
                  system("echo " + c)
                end
                r.call(params[:d])
              end
            end
        """
        self.assertEqual(_flows(src), [("command", 3), ("command", 6)])

    def test_constant_hash_of_lambdas(self):
        src = """
            class UsersController < ApplicationController
              ACTIONS = { "run" => lambda { |x| system(x) }, "sql" => proc { |q| User.where("name = '#{q}'") } }
              def go
                ACTIONS[params[:a]].call(params[:v])
              end
            end
        """
        self.assertEqual(_flows(src), [("command", 2), ("sql", 2)])

    def test_method_object(self):
        src = """
            class UsersController < ApplicationController
              def go
                m = method(:danger)
                m.call(params[:v])
              end
              private
              def danger(x)
                `ls #{x}`
              end
            end
        """
        self.assertEqual(_flows(src), [("command", 8)])

    def test_safe_lambdas(self):
        src = """
            class UsersController < ApplicationController
              def go
                r = ->(c) { system("echo", c.to_i.to_s) }
                r.call(params[:c])
                q = ->(c) { system("ls") }
                q.call(params[:c])
              end
            end
        """
        self.assertEqual(_flows(src), [])


if __name__ == "__main__":
    unittest.main()
