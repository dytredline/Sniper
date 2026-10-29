"""R8: wrapper sanitizers need body-backed, all-return dominance evidence."""

from __future__ import annotations

import os
import json
import textwrap
import unittest
from unittest import mock

import taint_js_ast
from taint_flow import analyze_javascript, analyze_python, analyze_python_files
from tests.test_taint_js_ast import NODE_ENV


def _src(text: str) -> str:
    return textwrap.dedent(text).lstrip("\n")


def _kinds(analysis) -> list[str]:
    return sorted(flow.sink_kind for flow in analysis.flows)


class PythonWrapperDominanceTests(unittest.TestCase):
    def test_recognized_sanitizer_in_body_dominates_async_return_control(self):
        analysis = analyze_python(_src("""
            import os, shlex
            from flask import request

            async def quote_command(value):
                return shlex.quote(value)

            @app.route('/x')
            async def view():
                os.system(await quote_command(request.args['c']))
        """))
        self.assertEqual(_kinds(analysis), [])
        self.assertTrue(analysis.is_clean_sink("command", 9))

    def test_sanitizer_like_name_does_not_clean_async_passthrough(self):
        analysis = analyze_python(_src("""
            import os
            from flask import request

            async def sanitize_command(value):
                return value

            @app.route('/x')
            async def view():
                os.system(await sanitize_command(request.args['c']))
        """))
        self.assertEqual(set(_kinds(analysis)), {"command"})

    def test_conditional_sanitizer_does_not_dominate_bypass_return(self):
        analysis = analyze_python(_src("""
            import os, shlex
            from flask import request

            async def sanitize_command(value, enabled):
                if enabled:
                    return shlex.quote(value)
                return value

            @app.route('/x')
            async def view():
                os.system(await sanitize_command(request.args['c'], request.args.get('safe')))
        """))
        self.assertEqual(_kinds(analysis), ["command"])

    def test_callback_map_does_not_trust_sanitizer_like_name(self):
        analysis = analyze_python(_src("""
            import os
            from flask import request

            def sanitize_command(value):
                return value

            @app.route('/x')
            def view():
                for item in map(sanitize_command, [request.args['c']]):
                    os.system(item)
        """))
        self.assertEqual(_kinds(analysis), ["command"])

    def test_exception_return_prevents_sanitizer_dominance(self):
        analysis = analyze_python(_src("""
            import os, shlex
            from flask import request

            def quote_command(value):
                try:
                    return shlex.quote(value)
                except ValueError:
                    return value

            @app.route('/x')
            def view():
                os.system(quote_command(request.args['c']))
        """))
        self.assertEqual(_kinds(analysis), ["command"])

    def test_cross_file_async_passthrough_keeps_taint(self):
        results = analyze_python_files({
            "helpers.py": _src("""
                async def sanitize_command(value):
                    return value
            """),
            "views.py": _src("""
                import os
                from flask import request
                from helpers import sanitize_command

                @app.route('/x')
                async def view():
                    os.system(await sanitize_command(request.args['c']))
            """),
        })
        self.assertIsNotNone(results)
        self.assertEqual(_kinds(results["views.py"]), ["command"])

    def test_wrapper_respects_locked_sanitizer_version(self):
        source = _src("""
            import bleach
            from flask import request
            def render_safe(value):
                return bleach.clean(value)
            @app.route('/x')
            def view():
                return '<p>' + render_safe(request.args['q']) + '</p>'
        """)
        old = analyze_python_files({"app.py": source, "requirements.txt": "bleach==4.1.0\n"})
        supported = analyze_python_files({"app.py": source, "requirements.txt": "bleach==6.1.0\n"})
        self.assertEqual(_kinds(old["app.py"]), ["html"])
        self.assertEqual(_kinds(supported["app.py"]), [])

    def test_dynamic_dispatch_stays_uncertain_instead_of_clean(self):
        analysis = analyze_python(_src("""
            import os
            from flask import request

            def sanitize_command(value):
                return value

            @app.route('/x')
            def view():
                chosen = sanitize_command if request.args.get('mode') else (lambda value: value)
                os.system(chosen(request.args['c']))
        """))
        self.assertEqual(_kinds(analysis), [])
        self.assertIn(("command", 10), analysis.uncertain_sinks)
        self.assertFalse(analysis.is_unreached_sink("command", 10))

    def test_depth_budget_conservatively_propagates_parameter(self):
        lines = ["import os", "from flask import request"]
        for index in range(34):
            returned = "value" if index == 33 else f"wrap_{index + 1}(value)"
            lines.extend((f"def wrap_{index}(value):", f"    return {returned}"))
        lines.extend(("@app.route('/x')", "def view():", "    os.system(wrap_0(request.args['c']))"))
        analysis = analyze_python("\n".join(lines) + "\n")
        self.assertEqual(_kinds(analysis), ["command"])

    def test_recursive_wrapper_conservatively_propagates_parameter(self):
        analysis = analyze_python(_src("""
            import os
            from flask import request

            def recurse(value, again):
                if again:
                    return recurse(value, request.args.get('again'))
                return value

            @app.route('/x')
            def view():
                os.system(recurse(request.args['c'], request.args.get('start')))
        """))
        self.assertEqual(set(_kinds(analysis)), {"command"})


@unittest.skipIf(NODE_ENV is None, "node bulunamadı")
class JavaScriptWrapperDominanceTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.dict(os.environ, NODE_ENV)
        patcher.start()
        self.addCleanup(patcher.stop)

    def analyze(self, source: str, filename: str = "a.js"):
        analysis = analyze_javascript(_src(source), filename=filename)
        self.assertIsNotNone(analysis)
        return analysis

    def test_recognized_sanitizer_in_body_dominates_await_control(self):
        analysis = self.analyze("""
            async function renderSafe(value) {
              return escapeHtml(value);
            }
            app.get('/x', async (req) => {
              document.body.innerHTML = await renderSafe(req.query.q);
            });
        """)
        self.assertEqual(_kinds(analysis), [])
        self.assertTrue(analysis.is_clean_sink("html", 5))

    def test_sanitizer_like_name_does_not_clean_async_passthrough(self):
        analysis = self.analyze("""
            async function sanitizeHtml(value) {
              return value;
            }
            app.get('/x', async (req) => {
              document.body.innerHTML = await sanitizeHtml(req.query.q);
            });
        """)
        self.assertEqual(set(_kinds(analysis)), {"html"})

    def test_project_function_shadows_builtin_sanitizer_name(self):
        analysis = self.analyze("""
            const { exec } = require('child_process');
            function parseInt(value) { return value; }
            app.get('/x', (req) => {
              exec(parseInt(req.query.q));
            });
        """)
        self.assertEqual(_kinds(analysis), ["command"])

    def test_conditional_sanitizer_does_not_dominate_bypass_return(self):
        analysis = self.analyze("""
            function sanitizeHtml(value, enabled) {
              if (enabled) return escapeHtml(value);
              return value;
            }
            app.get('/x', (req) => {
              document.body.innerHTML = sanitizeHtml(req.query.q, req.query.safe);
            });
        """)
        self.assertEqual(_kinds(analysis), ["html"])

    def test_scheduler_callback_does_not_trust_sanitizer_like_name(self):
        analysis = self.analyze("""
            function sanitizeHtml(value) {
              return value;
            }
            app.get('/x', (req) => {
              setTimeout((value) => { document.body.innerHTML = sanitizeHtml(value); }, 0, req.query.q);
            });
        """)
        self.assertEqual(_kinds(analysis), ["html"])

    def test_catch_return_prevents_sanitizer_dominance(self):
        analysis = self.analyze("""
            function renderSafe(value) {
              try {
                return escapeHtml(value);
              } catch (error) {
                return value;
              }
            }
            app.get('/x', (req) => {
              document.body.innerHTML = renderSafe(req.query.q);
            });
        """)
        self.assertEqual(_kinds(analysis), ["html"])

    def test_cross_file_typescript_async_passthrough_keeps_taint(self):
        results = taint_js_ast.analyze_files({
            "helpers.ts": _src("""
                export async function sanitizeHtml(value: string): Promise<string> {
                  return value;
                }
            """),
            "route.ts": _src("""
                import { sanitizeHtml } from './helpers';
                export async function handler(req: any) {
                  document.body.innerHTML = await sanitizeHtml(req.query.q);
                }
                app.get('/x', handler);
            """),
        })
        self.assertIsNotNone(results)
        self.assertEqual(_kinds(results["route.ts"]), ["html"])

    def test_wrapper_respects_locked_sanitizer_version(self):
        source = _src("""
            import DOMPurify from 'dompurify';
            function renderSafe(value) { return DOMPurify.sanitize(value); }
            app.get('/x', (req) => { document.body.innerHTML = renderSafe(req.query.q); });
        """)

        def run(version: str):
            lock = json.dumps({
                "lockfileVersion": 3,
                "packages": {"node_modules/dompurify": {"version": version}},
            })
            return taint_js_ast.analyze_files({"app.js": source, "package-lock.json": lock})

        old = run("2.3.10")
        supported = run("3.0.0")
        self.assertEqual(_kinds(old["app.js"]), ["html"])
        self.assertEqual(_kinds(supported["app.js"]), [])

    def test_dynamic_dispatch_is_conservative(self):
        analysis = self.analyze("""
            const { exec } = require('child_process');
            function scrub(value) { return value; }
            app.get('/x', (req) => {
              const chosen = req.query.mode ? scrub : (value => value);
              exec(chosen(req.query.q));
            });
        """)
        self.assertEqual(_kinds(analysis), ["command"])

    def test_depth_budget_conservatively_propagates_parameter(self):
        lines = []
        for index in range(34):
            returned = "value" if index == 33 else f"wrap{index + 1}(value)"
            lines.append(f"function wrap{index}(value) {{ return {returned}; }}")
        lines.append("app.get('/x', (req) => { document.body.innerHTML = wrap0(req.query.q); });")
        analysis = self.analyze("\n".join(lines))
        self.assertEqual(_kinds(analysis), ["html"])

    def test_recursive_wrapper_conservatively_propagates_parameter(self):
        analysis = self.analyze("""
            function recurse(value, again) {
              if (again) return recurse(value, window.location.hash);
              return value;
            }
            app.get('/x', (req) => {
              document.body.innerHTML = recurse(req.query.q, req.query.start);
            });
        """)
        self.assertEqual(set(_kinds(analysis)), {"html"})


if __name__ == "__main__":
    unittest.main()
