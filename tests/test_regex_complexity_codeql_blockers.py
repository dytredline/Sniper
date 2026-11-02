from __future__ import annotations

import time
import unittest

import ai_llm_security_auditor as ai_llm
import api_spec_routes


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


if __name__ == "__main__":
    unittest.main()
