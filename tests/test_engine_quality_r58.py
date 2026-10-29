"""R58 motor kalite kapisi: olculmus dolayli cagri davranislari.

Ornekler motorun mevcut testlerinden kopyalanmis regresyonlar degildir. Gercek dil
kaliplarini kucuk, calistirilmayan kaynak parcalari olarak olcer: C++ ``std::function``
secimi, Kotlin sabit callable reference ve Ruby sabit adli yansimali cagri.
"""
from __future__ import annotations

import textwrap
import unittest
from pathlib import Path

import eval_metrics
import ground_truth_review
import taint_cfamily
import taint_clike
import taint_goruby


APP = Path(__file__).resolve().parents[1]
R58_REFERENCE_MANIFEST = APP / "docs" / "olcum" / "engine-quality-reference-r58.manifest.json"


def _c(src: str):
    result = taint_cfamily.analyze_files({"callback.cpp": textwrap.dedent(src).lstrip("\n")})
    return [flow for analysis in result.values() for flow in analysis.flows]


def _kotlin(src: str):
    result = taint_clike.analyze_files({"Controller.kt": textwrap.dedent(src).lstrip("\n")})
    return [flow for analysis in result.values() for flow in analysis.flows]


def _ruby(src: str):
    result = taint_goruby.analyze_files(
        {"app/controllers/jobs_controller.rb": textwrap.dedent(src).lstrip("\n")}, "ruby"
    )
    return [flow for analysis in result.values() for flow in analysis.flows]


class CppStdFunctionReference(unittest.TestCase):
    VULNERABLE = r"""
        #include <functional>
        #include <sys/socket.h>
        #include <cstdlib>
        void dangerous(char *value) { system(value); }
        void harmless(char *value) { printf("%s", value); }
        void dispatch(int socket_fd, bool privileged) {
            char request[128];
            recv(socket_fd, request, 127, 0);
            std::function<void(char *)> handler = privileged ? dangerous : harmless;
            handler(request);
        }
    """

    def test_auto_callback_is_a_passing_control(self) -> None:
        source = self.VULNERABLE.replace("std::function<void(char *)>", "auto")
        self.assertEqual([(flow.sink_kind, flow.line) for flow in _c(source)], [("command", 4)])

    def test_std_function_ternary_keeps_the_dangerous_candidate(self) -> None:
        flows = _c(self.VULNERABLE)
        self.assertEqual([(flow.sink_kind, flow.line, flow.via) for flow in flows],
                         [("command", 4, ("dangerous",))])

    def test_std_function_with_only_harmless_candidates_is_clean(self) -> None:
        source = self.VULNERABLE.replace("privileged ? dangerous : harmless", "privileged ? harmless : harmless")
        self.assertEqual(_c(source), [])


class KotlinCallableReference(unittest.TestCase):
    def test_immutable_local_callable_reference_is_resolved(self) -> None:
        flows = _kotlin("""
            @RestController
            class JobsController {
                @GetMapping("/run")
                fun run(@RequestParam command: String) {
                    val action = ::dangerous
                    action(command)
                }
                fun dangerous(value: String) { Runtime.getRuntime().exec(value) }
            }
        """)
        self.assertEqual([(flow.sink_kind, flow.line) for flow in flows], [("command", 8)])

    def test_mutable_or_dynamic_callable_is_not_guessed(self) -> None:
        flows = _kotlin("""
            @RestController
            class JobsController {
                @GetMapping("/run")
                fun run(@RequestParam command: String, choose: (String) -> Unit) {
                    var action = ::dangerous
                    action = choose
                    action(command)
                }
                fun dangerous(value: String) { Runtime.getRuntime().exec(value) }
            }
        """)
        self.assertEqual(flows, [])

    def test_nested_shadow_does_not_replace_the_outer_exact_reference(self) -> None:
        flows = _kotlin("""
            @RestController
            class JobsController {
                @GetMapping("/run")
                fun run(@RequestParam command: String) {
                    val action = ::dangerous
                    run { val action = ::harmless; action(command) }
                    action(command)
                }
                fun dangerous(value: String) { Runtime.getRuntime().exec(value) }
                fun harmless(value: String) { println(value) }
            }
        """)
        self.assertEqual([(flow.sink_kind, flow.line) for flow in flows], [("command", 9)])


class RubyLiteralReflection(unittest.TestCase):
    def test_literal_string_public_send_resolves_a_public_method(self) -> None:
        flows = _ruby("""
            class JobsController < ApplicationController
              def run
                public_send("dangerous", params[:command])
              end
              def dangerous(value)
                system(value)
              end
            end
        """)
        self.assertEqual([(flow.sink_kind, flow.line, flow.via) for flow in flows],
                         [("command", 6, ("dangerous",))])

    def test_public_send_rejects_private_and_protected_targets(self) -> None:
        for visibility in ("private", "protected"):
            with self.subTest(visibility=visibility):
                flows = _ruby(f"""
                    class JobsController < ApplicationController
                      def run
                        public_send("dangerous", params[:command])
                      end
                      {visibility}
                      def dangerous(value)
                        system(value)
                      end
                    end
                """)
                self.assertNotIn("command", {flow.sink_kind for flow in flows})

    def test_send_and_dunder_send_may_resolve_a_private_target(self) -> None:
        for dispatch in ("send", "__send__"):
            with self.subTest(dispatch=dispatch):
                flows = _ruby(f"""
                    class JobsController < ApplicationController
                      def run
                        {dispatch}("dangerous", params[:command])
                      end
                      private
                      def dangerous(value)
                        system(value)
                      end
                    end
                """)
                self.assertEqual([(flow.sink_kind, flow.line, flow.via) for flow in flows],
                                 [("command", 7, ("dangerous",))])

    def test_named_private_modifier_is_honoured_by_public_send(self) -> None:
        flows = _ruby("""
            class JobsController < ApplicationController
              def dangerous(value)
                system(value)
              end
              private :dangerous
              def run
                public_send(:dangerous, params[:command])
              end
            end
        """)
        self.assertNotIn("command", {flow.sink_kind for flow in flows})

    def test_try_and_try_bang_are_not_treated_as_send_aliases(self) -> None:
        for dispatch in ("try", "try!"):
            with self.subTest(dispatch=dispatch):
                flows = _ruby(f"""
                    class JobsController < ApplicationController
                      def run
                        {dispatch}("dangerous", params[:command])
                      end
                      private
                      def dangerous(value)
                        system(value)
                      end
                    end
                """)
                self.assertNotIn("command", {flow.sink_kind for flow in flows})

    def test_parser_tracks_visibility_state_and_public_reset(self) -> None:
        source = textwrap.dedent("""
            class JobsController < ApplicationController
              private
              def hidden(value); value; end
              protected
              def guarded(value); value; end
              public
              def open(value); value; end
            end
        """).lstrip("\n")
        parsed = taint_goruby.parse_ruby_file("app/controllers/jobs_controller.rb", source)
        visibilities = {func.name: func.visibility for func in parsed.funcs if func.kind == "def"}
        self.assertEqual(visibilities, {"hidden": "private", "guarded": "protected", "open": "public"})

    def test_inline_and_singleton_visibility_are_not_lost(self) -> None:
        source = textwrap.dedent("""
            class JobsController < ApplicationController
              private def inline_hidden(value); value; end
              def after_inline(value); value; end
              class << self
                private
                def singleton_hidden(value); value; end
              end
              def self.singleton_open(value); value; end
            end
        """).lstrip("\n")
        parsed = taint_goruby.parse_ruby_file("app/controllers/jobs_controller.rb", source)
        visibilities = {
            (func.name, func.class_method): func.visibility
            for func in parsed.funcs if func.kind == "def"
        }
        self.assertEqual(visibilities, {
            ("inline_hidden", False): "private",
            ("after_inline", False): "public",
            ("singleton_hidden", True): "private",
            ("singleton_open", True): "public",
        })

    def test_private_class_method_wrapped_definition_is_private_at_parse_and_runtime(self) -> None:
        source = textwrap.dedent("""
            class JobsController < ApplicationController
              private_class_method def self.dangerous(value)
                system(value)
              end
              def self.run
                public_send(:dangerous, params[:command])
              end
            end
        """).lstrip("\n")
        parsed = taint_goruby.parse_ruby_file("app/controllers/jobs_controller.rb", source)
        dangerous = [func for func in parsed.funcs if func.name == "dangerous"]
        self.assertEqual([(func.class_method, func.visibility) for func in dangerous], [(True, "private")])
        self.assertNotIn("command", {flow.sink_kind for flow in _ruby(source)})

    def test_bare_private_stops_at_semicolon_before_another_macro(self) -> None:
        source = textwrap.dedent("""
            class JobsController < ApplicationController
              def run
                public_send(:dangerous, params[:command])
              end
              private; register :marker
              def dangerous(value)
                system(value)
              end
            end
        """).lstrip("\n")
        parsed = taint_goruby.parse_ruby_file("app/controllers/jobs_controller.rb", source)
        dangerous = [func for func in parsed.funcs if func.name == "dangerous"]
        self.assertEqual([func.visibility for func in dangerous], ["private"])
        self.assertNotIn("command", {flow.sink_kind for flow in _ruby(source)})

    def test_later_private_redefinition_replaces_public_in_same_class(self) -> None:
        source = textwrap.dedent("""
            class JobsController < ApplicationController
              def dangerous(value)
                system(value)
              end
              private
              def dangerous(value)
                system(value)
              end
              public
              def run
                public_send(:dangerous, params[:command])
              end
            end
        """).lstrip("\n")
        parsed = taint_goruby.parse_ruby_file("app/controllers/jobs_controller.rb", source)
        self.assertEqual(
            [func.visibility for func in parsed.funcs if func.name == "dangerous"],
            ["public", "private"],
        )
        project = taint_goruby.RubyProject({"app/controllers/jobs_controller.rb": source})
        active = project.by_class[("JobsController", False)]["dangerous"]
        self.assertEqual([(func.visibility, func.conditional) for func in active], [("private", False)])
        self.assertNotIn("command", {flow.sink_kind for flow in _ruby(source)})

    def test_later_private_redefinition_replaces_public_after_class_reopen(self) -> None:
        source = textwrap.dedent("""
            class JobsController < ApplicationController
              def dangerous(value)
                system(value)
              end
            end
            class JobsController < ApplicationController
              private
              def dangerous(value)
                system(value)
              end
            end
            class JobsController < ApplicationController
              def run
                public_send(:dangerous, params[:command])
              end
            end
        """).lstrip("\n")
        parsed = taint_goruby.parse_ruby_file("app/controllers/jobs_controller.rb", source)
        self.assertEqual(
            [func.visibility for func in parsed.funcs if func.name == "dangerous"],
            ["public", "private"],
        )
        project = taint_goruby.RubyProject({"app/controllers/jobs_controller.rb": source})
        active = project.by_class[("JobsController", False)]["dangerous"]
        self.assertEqual([(func.visibility, func.conditional) for func in active], [("private", False)])
        self.assertNotIn("command", {flow.sink_kind for flow in _ruby(source)})

    def test_reopened_class_uses_source_loading_order_across_files(self) -> None:
        files = {
            "app/controllers/jobs_public.rb": textwrap.dedent("""
                class JobsController < ApplicationController
                  def dangerous(value)
                    system(value)
                  end
                end
            """).lstrip("\n"),
            "app/controllers/jobs_controller.rb": textwrap.dedent("""
                class JobsController < ApplicationController
                  def run
                    public_send(:dangerous, params[:command])
                  end
                  private
                  def dangerous(value)
                    system(value)
                  end
                end
            """).lstrip("\n"),
        }
        parsed = [taint_goruby.parse_ruby_file(rel, source) for rel, source in files.items()]
        self.assertEqual(
            [func.visibility for ruby_file in parsed for func in ruby_file.funcs if func.name == "dangerous"],
            ["public", "private"],
        )
        project = taint_goruby.RubyProject(files)
        active = project.by_class[("JobsController", False)]["dangerous"]
        self.assertEqual([(func.visibility, func.conditional) for func in active], [("private", False)])
        result = taint_goruby.analyze_files(files, "ruby")
        flows = [flow for analysis in result.values() for flow in analysis.flows]
        self.assertNotIn("command", {flow.sink_kind for flow in flows})

    def test_later_public_redefinition_replaces_private(self) -> None:
        source = textwrap.dedent("""
            class JobsController < ApplicationController
              private
              def dangerous(value)
                system(value)
              end
              public
              def dangerous(value)
                system(value)
              end
              def run
                public_send(:dangerous, params[:command])
              end
            end
        """).lstrip("\n")
        project = taint_goruby.RubyProject({"app/controllers/jobs_controller.rb": source})
        active = project.by_class[("JobsController", False)]["dangerous"]
        self.assertEqual([(func.visibility, func.conditional) for func in active], [("public", False)])
        self.assertIn("command", {flow.sink_kind for flow in _ruby(source)})

    def test_conditional_redefinition_keeps_the_previous_possible_definition(self) -> None:
        source = textwrap.dedent("""
            class JobsController < ApplicationController
              def dangerous(value)
                system(value)
              end
              if feature_enabled?
                private def dangerous(value)
                  system(value)
                end
              end
              def run
                public_send(:dangerous, params[:command])
              end
            end
        """).lstrip("\n")
        project = taint_goruby.RubyProject({"app/controllers/jobs_controller.rb": source})
        active = project.by_class[("JobsController", False)]["dangerous"]
        self.assertEqual(
            [(func.visibility, func.conditional, func.definition_certainty) for func in active],
            [("public", False, "always"), ("private", True, "maybe")],
        )
        self.assertIn("command", {flow.sink_kind for flow in _ruby(source)})

    def test_literal_branch_redefinitions_have_three_state_certainty(self) -> None:
        cases = (
            ("public", "if true", "private", "always", "private", False),
            ("public", "unless false", "private", "always", "private", False),
            ("public", "if false", "private", "never", "public", True),
            ("public", "unless true", "private", "never", "public", True),
            ("private", "if true", "public", "always", "public", True),
            ("private", "if false", "public", "never", "private", False),
        )
        for old_visibility, branch, new_visibility, certainty, active_visibility, command_flow in cases:
            with self.subTest(branch=branch, direction=f"{old_visibility}->{new_visibility}"):
                source = textwrap.dedent(f"""
                    class JobsController < ApplicationController
                      {old_visibility} def dangerous(value)
                        system(value)
                      end
                      {branch}
                        {new_visibility} def dangerous(value)
                          system(value)
                        end
                      end
                      public
                      def run
                        public_send(:dangerous, params[:command])
                      end
                    end
                """).lstrip("\n")
                parsed = taint_goruby.parse_ruby_file("app/controllers/jobs_controller.rb", source)
                definitions = [func for func in parsed.funcs if func.name == "dangerous"]
                self.assertEqual(definitions[-1].definition_certainty, certainty)
                project = taint_goruby.RubyProject({"app/controllers/jobs_controller.rb": source})
                active = project.by_class[("JobsController", False)]["dangerous"]
                self.assertEqual([func.visibility for func in active], [active_visibility])
                has_command = "command" in {flow.sink_kind for flow in _ruby(source)}
                self.assertEqual(has_command, command_flow)

    def test_elsif_chain_keeps_cumulative_remaining_state(self) -> None:
        cases = (
            # A taken first branch makes every later branch unreachable.
            ("public", "if true", "private", "elsif feature_enabled?", "public", "else", "public",
             ["always", "never", "never"], ["private"], False),
            # A literal elsif consumes all paths left by a false first branch.
            ("private", "if false", "private", "elsif true", "public", "else", "private",
             ["never", "always", "never"], ["public"], True),
            # An unknown first branch plus a true elsif still makes else unreachable.
            ("public", "if feature_enabled?", "private", "elsif true", "private", "else", "public",
             ["maybe", "maybe", "never"], ["private", "private"], False),
            ("private", "if feature_enabled?", "public", "elsif true", "public", "else", "private",
             ["maybe", "maybe", "never"], ["public", "public"], True),
        )
        for (old_visibility, first, first_visibility, second, second_visibility, otherwise,
             else_visibility, certainties, active_visibilities, command_flow) in cases:
            with self.subTest(first=first, second=second,
                              direction=f"{old_visibility}->{active_visibilities[0]}"):
                source = textwrap.dedent(f"""
                    class JobsController < ApplicationController
                      {old_visibility} def dangerous(value)
                        system(value)
                      end
                      {first}
                        {first_visibility} def dangerous(value)
                          system(value)
                        end
                      {second}
                        {second_visibility} def dangerous(value)
                          system(value)
                        end
                      {otherwise}
                        {else_visibility} def dangerous(value)
                          system(value)
                        end
                      end
                      public
                      def run
                        public_send(:dangerous, params[:command])
                      end
                    end
                """).lstrip("\n")
                parsed = taint_goruby.parse_ruby_file("app/controllers/jobs_controller.rb", source)
                definitions = [func for func in parsed.funcs if func.name == "dangerous"]
                self.assertEqual(
                    [func.definition_certainty for func in definitions[1:]],
                    certainties,
                )
                project = taint_goruby.RubyProject({"app/controllers/jobs_controller.rb": source})
                active = project.by_class[("JobsController", False)]["dangerous"]
                self.assertEqual([func.visibility for func in active], active_visibilities)
                has_command = "command" in {flow.sink_kind for flow in _ruby(source)}
                self.assertEqual(has_command, command_flow)

    def test_unless_else_chain_uses_only_the_remaining_branch(self) -> None:
        cases = (
            ("public", "unless true", "public", "private", ["never", "always"], "private", False),
            ("private", "unless false", "public", "private", ["always", "never"], "public", True),
        )
        for (old_visibility, branch, branch_visibility, else_visibility, certainties,
             active_visibility, command_flow) in cases:
            with self.subTest(branch=branch, direction=f"{old_visibility}->{active_visibility}"):
                source = textwrap.dedent(f"""
                    class JobsController < ApplicationController
                      {old_visibility} def dangerous(value)
                        system(value)
                      end
                      {branch}
                        {branch_visibility} def dangerous(value)
                          system(value)
                        end
                      else
                        {else_visibility} def dangerous(value)
                          system(value)
                        end
                      end
                      public
                      def run
                        public_send(:dangerous, params[:command])
                      end
                    end
                """).lstrip("\n")
                parsed = taint_goruby.parse_ruby_file("app/controllers/jobs_controller.rb", source)
                definitions = [func for func in parsed.funcs if func.name == "dangerous"]
                self.assertEqual(
                    [func.definition_certainty for func in definitions[1:]],
                    certainties,
                )
                project = taint_goruby.RubyProject({"app/controllers/jobs_controller.rb": source})
                active = project.by_class[("JobsController", False)]["dangerous"]
                self.assertEqual([func.visibility for func in active], [active_visibility])
                has_command = "command" in {flow.sink_kind for flow in _ruby(source)}
                self.assertEqual(has_command, command_flow)

    def test_nested_literal_chains_update_only_the_nearest_branch(self) -> None:
        source = textwrap.dedent("""
            class JobsController < ApplicationController
              public def dangerous(value)
                system(value)
              end
              if true
                if false
                  public def dangerous(value)
                    system(value)
                  end
                elsif true
                  private def dangerous(value)
                    system(value)
                  end
                else
                  public def dangerous(value)
                    system(value)
                  end
                end
              elsif true
                public def dangerous(value)
                  system(value)
                end
              else
                public def dangerous(value)
                  system(value)
                end
              end
              public
              def run
                public_send(:dangerous, params[:command])
              end
            end
        """).lstrip("\n")
        parsed = taint_goruby.parse_ruby_file("app/controllers/jobs_controller.rb", source)
        definitions = [func for func in parsed.funcs if func.name == "dangerous"]
        self.assertEqual(
            [func.definition_certainty for func in definitions],
            ["always", "never", "always", "never", "never", "never"],
        )
        project = taint_goruby.RubyProject({"app/controllers/jobs_controller.rb": source})
        active = project.by_class[("JobsController", False)]["dangerous"]
        self.assertEqual([func.visibility for func in active], ["private"])
        self.assertNotIn("command", {flow.sink_kind for flow in _ruby(source)})

    def test_bare_visibility_directives_follow_branch_certainty(self) -> None:
        cases = (
            ("if false", "private", None, None, ("public",), True),
            ("if true", "private", "else", "public", ("private",), False),
            ("if false", "private", "else", "public", ("public",), True),
            ("if feature_enabled?", "private", None, None, ("public", "private"), True),
            ("if feature_enabled?", "private", "else", "protected", ("protected", "private"), False),
            ("if feature_enabled?", "private", "else", "public", ("public", "private"), True),
        )
        for branch, directive, otherwise, other_directive, expected, command_flow in cases:
            with self.subTest(branch=branch, otherwise=other_directive, expected=expected):
                other = f"{otherwise}\n    {other_directive}" if otherwise else ""
                source = textwrap.dedent(f"""
                    class JobsController < ApplicationController
                      {branch}
                        {directive}
                      {other}
                      end
                      def dangerous(value)
                        system(value)
                      end
                      public
                      def run
                        public_send(:dangerous, params[:command])
                      end
                    end
                """).lstrip("\n")
                parsed = taint_goruby.parse_ruby_file("app/controllers/jobs_controller.rb", source)
                dangerous = next(func for func in parsed.funcs if func.name == "dangerous")
                self.assertEqual(dangerous.possible_visibilities, expected)
                has_command = "command" in {flow.sink_kind for flow in _ruby(source)}
                self.assertEqual(has_command, command_flow)

    def test_named_visibility_directives_follow_branch_certainty(self) -> None:
        cases = (
            ("if false", "private", None, None, ("public",), True),
            ("if true", "private", "else", "public", ("private",), False),
            ("if false", "private", "else", "public", ("public",), True),
            ("if feature_enabled?", "private", None, None, ("public", "private"), True),
            ("if feature_enabled?", "private", "else", "protected", ("protected", "private"), False),
            ("if feature_enabled?", "private", "else", "public", ("public", "private"), True),
        )
        for branch, directive, otherwise, other_directive, expected, command_flow in cases:
            with self.subTest(branch=branch, otherwise=other_directive, expected=expected):
                other = f"{otherwise}\n    {other_directive} :dangerous" if otherwise else ""
                source = textwrap.dedent(f"""
                    class JobsController < ApplicationController
                      def dangerous(value)
                        system(value)
                      end
                      {branch}
                        {directive} :dangerous
                      {other}
                      end
                      def run
                        public_send(:dangerous, params[:command])
                      end
                    end
                """).lstrip("\n")
                parsed = taint_goruby.parse_ruby_file("app/controllers/jobs_controller.rb", source)
                dangerous = next(func for func in parsed.funcs if func.name == "dangerous")
                self.assertEqual(dangerous.possible_visibilities, expected)
                has_command = "command" in {flow.sink_kind for flow in _ruby(source)}
                self.assertEqual(has_command, command_flow)

    def test_nested_bare_and_named_visibility_only_join_their_own_chain(self) -> None:
        templates = (
            """
              if true
                if false
                  private
                else
                  protected
                end
              else
                public
              end
              def dangerous(value)
                system(value)
              end
            """,
            """
              def dangerous(value)
                system(value)
              end
              if true
                if false
                  private :dangerous
                else
                  protected :dangerous
                end
              else
                public :dangerous
              end
            """,
        )
        for body in templates:
            with self.subTest(mode="named" if ":dangerous" in body else "bare"):
                source = "class JobsController < ApplicationController\n" + textwrap.dedent(body) + textwrap.dedent("""
                      public
                      def run
                        public_send(:dangerous, params[:command])
                      end
                    end
                """)
                parsed = taint_goruby.parse_ruby_file("app/controllers/jobs_controller.rb", source)
                dangerous = next(func for func in parsed.funcs if func.name == "dangerous")
                self.assertEqual(dangerous.possible_visibilities, ("protected",))
                self.assertNotIn("command", {flow.sink_kind for flow in _ruby(source)})

    def test_postfix_bare_visibility_uses_if_unless_certainty(self) -> None:
        cases = (
            ("public", "private", "if false", ("public",), True),
            ("private", "public", "if false", ("private",), False),
            ("public", "private", "if true", ("private",), False),
            ("private", "public", "if true", ("public",), True),
            ("public", "private", "unless true", ("public",), True),
            ("private", "public", "unless true", ("private",), False),
            ("public", "private", "unless false", ("private",), False),
            ("private", "public", "unless false", ("public",), True),
            ("public", "private", "if feature_enabled?", ("public", "private"), True),
            ("private", "public", "unless feature_enabled?", ("public", "private"), True),
            ("private", "protected", "if feature_enabled?", ("protected", "private"), False),
        )
        for initial, directive, condition, expected, command_flow in cases:
            with self.subTest(initial=initial, statement=f"{directive} {condition}"):
                source = textwrap.dedent(f"""
                    class JobsController < ApplicationController
                      {initial}
                      {directive} {condition}
                      def dangerous(value)
                        system(value)
                      end
                      public
                      def run
                        public_send(:dangerous, params[:command])
                      end
                    end
                """).lstrip("\n")
                parsed = taint_goruby.parse_ruby_file("app/controllers/jobs_controller.rb", source)
                dangerous = next(func for func in parsed.funcs if func.name == "dangerous")
                self.assertEqual(dangerous.possible_visibilities, expected)
                has_command = "command" in {flow.sink_kind for flow in _ruby(source)}
                self.assertEqual(has_command, command_flow)

    def test_postfix_named_visibility_uses_if_unless_certainty(self) -> None:
        cases = (
            ("public", "private", "if false", ("public",), True),
            ("private", "public", "if false", ("private",), False),
            ("public", "private", "if true", ("private",), False),
            ("private", "public", "if true", ("public",), True),
            ("public", "private", "unless true", ("public",), True),
            ("private", "public", "unless true", ("private",), False),
            ("public", "private", "unless false", ("private",), False),
            ("private", "public", "unless false", ("public",), True),
            ("public", "private", "if feature_enabled?", ("public", "private"), True),
            ("private", "public", "unless feature_enabled?", ("public", "private"), True),
            ("private", "protected", "if feature_enabled?", ("protected", "private"), False),
        )
        for initial, directive, condition, expected, command_flow in cases:
            with self.subTest(initial=initial, statement=f"{directive} :dangerous {condition}"):
                source = textwrap.dedent(f"""
                    class JobsController < ApplicationController
                      {initial} def dangerous(value)
                        system(value)
                      end
                      {directive} :dangerous {condition}
                      public
                      def run
                        public_send(:dangerous, params[:command])
                      end
                    end
                """).lstrip("\n")
                parsed = taint_goruby.parse_ruby_file("app/controllers/jobs_controller.rb", source)
                dangerous = next(func for func in parsed.funcs if func.name == "dangerous")
                self.assertEqual(dangerous.possible_visibilities, expected)
                has_command = "command" in {flow.sink_kind for flow in _ruby(source)}
                self.assertEqual(has_command, command_flow)

    def test_public_send_uses_the_lexically_nearest_constant(self) -> None:
        source = textwrap.dedent("""
            module A
              class Service
                def self.dangerous(value)
                  system(value)
                end
              end
            end
            module B
              class Service
                class << self
                  private
                  def dangerous(value)
                    system(value)
                  end
                end
              end
              class JobsController < ApplicationController
                def run
                  Service.public_send(:dangerous, params[:command])
                end
              end
            end
        """).lstrip("\n")
        project = taint_goruby.RubyProject({"app/controllers/jobs_controller.rb": source})
        caller = next(func for func in project.funcs if func.cls == "B::JobsController" and func.name == "run")
        resolved = project.resolve(caller, "const", "Service", "dangerous", False)
        self.assertEqual([(func.cls, func.visibility) for func in resolved], [("B::Service", "private")])
        self.assertNotIn("command", {flow.sink_kind for flow in _ruby(source)})

    def test_lexical_public_constant_is_not_shadowed_by_another_namespace(self) -> None:
        source = textwrap.dedent("""
            module A
              class Service
                class << self
                  private
                  def dangerous(value)
                    system(value)
                  end
                end
              end
            end
            module B
              class Service
                def self.dangerous(value)
                  system(value)
                end
              end
              class JobsController < ApplicationController
                def run
                  Service.public_send(:dangerous, params[:command])
                end
              end
            end
        """).lstrip("\n")
        self.assertIn("command", {flow.sink_kind for flow in _ruby(source)})

    def test_ambiguous_unqualified_constant_fails_closed(self) -> None:
        source = textwrap.dedent("""
            module A
              class Service
                def self.dangerous(value); system(value); end
              end
            end
            module B
              class Service
                def self.dangerous(value); system(value); end
              end
            end
            class JobsController < ApplicationController
              def run
                Service.public_send(:dangerous, params[:command])
              end
            end
        """).lstrip("\n")
        project = taint_goruby.RubyProject({"app/controllers/jobs_controller.rb": source})
        caller = next(func for func in project.funcs if func.cls == "JobsController" and func.name == "run")
        self.assertEqual(project.resolve(caller, "const", "Service", "dangerous", False), [])
        self.assertNotIn("command", {flow.sink_kind for flow in _ruby(source)})

    def test_public_send_on_an_untyped_variable_fails_closed(self) -> None:
        source = textwrap.dedent("""
            class Service
              def dangerous(value)
                system(value)
              end
            end
            class JobsController < ApplicationController
              def run
                service = Service.new
                service.public_send(:dangerous, params[:command])
              end
            end
        """).lstrip("\n")
        self.assertNotIn("command", {flow.sink_kind for flow in _ruby(source)})

    def test_interpolated_method_name_is_not_resolved_as_a_literal(self) -> None:
        flows = _ruby("""
            class JobsController < ApplicationController
              def run
                public_send("dangerous#{params[:suffix]}", params[:command])
              end
              def dangerous(value)
                system(value)
              end
            end
        """)
        self.assertNotIn("command", {flow.sink_kind for flow in flows})


class SyntheticMeasurement(unittest.TestCase):
    @unittest.skipUnless(R58_REFERENCE_MANIFEST.is_file(), "maintainer reference bundle is not distributed")
    def test_installed_multilanguage_reference_bundle_is_source_pinned(self) -> None:
        app = Path(__file__).resolve().parents[1]
        checked = ground_truth_review.validate_bundle(
            app / "tests" / "fixtures" / "engine-quality-reference-r58",
            app / "docs" / "olcum" / "engine-quality-reference-r58.manifest.json",
            app / "docs" / "olcum" / "engine-quality-reference-r58.ground-truth.json",
            require_attestation=False,
        )
        self.assertEqual(checked["source_profiles"], ["c_cpp", "jvm", "ruby"])
        self.assertEqual((checked["project_count"], checked["label_count"]), (4, 3))

    def test_three_language_reference_slice_scores_at_full_recall(self) -> None:
        app = Path(__file__).resolve().parents[1]
        cpp = _c(CppStdFunctionReference.VULNERABLE)
        cpp_benign = _c((
            app / "tests" / "fixtures" / "engine-quality-reference-r58" /
            "cpp-callback-benign" / "callback.cpp"
        ).read_text(encoding="utf-8"))
        self.assertEqual(cpp_benign, [])
        kt = _kotlin("""
            @RestController
            class C {
              @GetMapping("/run") fun run(@RequestParam command: String) {
                val action = ::dangerous
                action(command)
              }
              fun dangerous(value: String) { Runtime.getRuntime().exec(value) }
            }
        """)
        rb = _ruby("""
            class CController < ApplicationController
              def run
                public_send("dangerous", params[:command])
              end
              def dangerous(value)
                system(value)
              end
            end
        """)
        items = []
        for project, filename, flows in (
            ("cpp-callback", "callback.cpp", cpp),
            ("kotlin-reference", "Controller.kt", kt),
            ("ruby-reflection", "app/controllers/jobs_controller.rb", rb),
        ):
            items.extend((project, filename, flow.line, frozenset({"cmd"}), flow.sink_kind) for flow in flows)
        ground_truth = eval_metrics.normalize_ground_truth({"projects": {
            "cpp-callback": [{"file": "callback.cpp", "lines": [4, 4], "class": "cmd"}],
            "cpp-callback-benign": [],
            "kotlin-reference": [{"file": "Controller.kt", "lines": [7, 7], "class": "cmd"}],
            "ruby-reflection": [{"file": "app/controllers/jobs_controller.rb", "lines": [6, 6], "class": "cmd"}],
        }})
        score = eval_metrics.score_items(ground_truth, items)
        self.assertEqual((score["tp"], score["total"], score["recall"]), (3, 3, 1.0), score)
        self.assertEqual(score["precision_lower_bound"], 1.0, score)


if __name__ == "__main__":
    unittest.main()
