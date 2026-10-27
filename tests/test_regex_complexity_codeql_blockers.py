from __future__ import annotations

import time
import tempfile
import unittest
from pathlib import Path

import ai_llm_security_auditor as ai_llm
import api_spec_routes
import project_analyzer


LINEAR_BUDGET_SECONDS = 0.10


class CodeQLRegexBlockerTests(unittest.TestCase):
    def assert_fast(self, label: str, operation):
        started = time.perf_counter()
        result = operation()
        elapsed = time.perf_counter() - started
        self.assertLess(elapsed, LINEAR_BUDGET_SECONDS, f"{label} took {elapsed:.3f}s")
        return result

    def test_llm_system_prompt_detection_is_linear_on_unterminated_local_storage_call(self) -> None:
        source = "localStorage.setItem(" + " " * 6_000 + "!"
        report = self.assert_fast(
            "LLM system-prompt exposure parser",
            lambda: ai_llm.audit_ai_llm_inline(source, filename="app.js"),
        )
        self.assertEqual(report["findings"], [])

    def test_llm_system_prompt_detection_preserves_controls_and_comment_edge(self) -> None:
        report = ai_llm.audit_ai_llm_inline(
            'window.SYSTEM_PROMPT = "internal policy"\n'
            'localStorage.setItem("SYSTEM_PROMPT", "internal policy")\n'
            'export const systemPrompt = "internal policy"\n'
            '# window.SYSTEM_PROMPT = "comment only"\n',
            filename="app.js",
        )
        prompt_findings = [item for item in report["findings"] if item["llm_risk"] == "LLM07"]
        self.assertEqual([item["line"] for item in prompt_findings], [1, 2, 3])

    def test_python_class_detection_is_linear_on_missing_colon(self) -> None:
        source = "class A" + "0" * 30_000 + "!"
        qualified, bare = self.assert_fast(
            "Python class-line parser",
            lambda: api_spec_routes._function_index((("handlers.py", source),)),
        )
        self.assertEqual((qualified, bare), (set(), set()))

    def test_python_class_detection_preserves_class_method_and_invalid_edge(self) -> None:
        qualified, bare = api_spec_routes._function_index(
            ((
                "pkg/views.py",
                "class Users(ApiBase):\n"
                "    def get(self):\n"
                "        pass\n"
                "class MissingColon\n"
                "    def ignored(self):\n"
                "        pass\n"
                "def list_users():\n"
                "    pass\n",
            ),)
        )
        self.assertIn("Users.get", qualified)
        self.assertNotIn("MissingColon.ignored", qualified)
        self.assertIn("list_users", bare)

    def test_jwt_algorithm_scan_is_linear_on_unclosed_lists(self) -> None:
        source = "algorithms:[" * 20_000 + "x"
        self.assertFalse(self.assert_fast(
            "JWT algorithm scan",
            lambda: project_analyzer._has_unsafe_jwt_option(source),
        ))

    def test_jwt_algorithm_scan_preserves_unsafe_option_detection(self) -> None:
        cases = (
            ("algorithms: ['HS256', 'none']", True),
            ("algorithms=['HS256', 'none'", True),
            ("algorithms: ['HS256'] then 'none'", False),
            ("algorithms: ['HS256'] algorithms: ['none']", True),
            ("verify = false", True),
            ("verify_signature: false", True),
            ("algorithms: ['HS256']", False),
        )
        for source, expected in cases:
            with self.subTest(source=source):
                self.assertEqual(project_analyzer._has_unsafe_jwt_option(source), expected)

    def test_sql_context_scan_is_linear_on_whitespace(self) -> None:
        source = "db" + " " * 30_000 + "!"
        self.assertIsNone(self.assert_fast(
            "SQL context scan",
            lambda: project_analyzer._SQL_CONTEXT_LINE_RE.search(source),
        ))

    def test_sql_context_scan_preserves_query_calls(self) -> None:
        for source in ("db.execute(q)", "db.cursor.execute(q)", "db . cursor . query (q)"):
            with self.subTest(source=source):
                self.assertIsNotNone(project_analyzer._SQL_CONTEXT_LINE_RE.search(source))
        self.assertIsNone(project_analyzer._SQL_CONTEXT_LINE_RE.search("db.cursor.close(q)"))

    def test_jwt_none_line_rule_remains_active_in_python_and_javascript(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve() / "project"
            root.mkdir()
            (root / "app.py").write_text(
                "jwt.decode(token, key, algorithms=['none'])\n", encoding="utf-8"
            )
            (root / "app.js").write_text("const algorithms = ['none'];\n", encoding="utf-8")
            findings = project_analyzer.analyze_project(
                str(root), allowed_roots=(root.parent,),
            )["findings"]
        detected = {
            item["file"] for item in findings
            if item["title"] == "JWT imza doğrulaması devre dışı veya alg:none izni"
        }
        self.assertEqual(detected, {"app.py", "app.js"})


if __name__ == "__main__":
    unittest.main()
