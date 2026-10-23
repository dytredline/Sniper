import json
import time
import unittest
from types import SimpleNamespace

import ai_llm_security_auditor as ai_llm
import api_spec_routes
import audit_logging_integrity_auditor as audit_logging
import authorized_tool_targets
import authz_routes


LINEAR_BUDGET_SECONDS = 0.20


class RegexComplexityBatchATests(unittest.TestCase):
    def assert_fast(self, label, operation, budget=LINEAR_BUDGET_SECONDS):
        started = time.perf_counter()
        result = operation()
        elapsed = time.perf_counter() - started
        self.assertLess(elapsed, budget, f"{label} took {elapsed:.3f}s")
        return result

    def assert_raises_fast(self, label, exception, operation, budget=LINEAR_BUDGET_SECONDS):
        started = time.perf_counter()
        with self.assertRaises(exception):
            operation()
        elapsed = time.perf_counter() - started
        self.assertLess(elapsed, budget, f"{label} took {elapsed:.3f}s")

    def test_llm_adversarial_whitespace_is_linear_and_findings_are_preserved(self):
        cases = (
            ("system-prompt", "window." + " " * 250_000 + "!"),
            ("output-assignment", "value = " + " " * 20_000 + "!"),
        )
        for label, source in cases:
            with self.subTest(label=label):
                self.assert_fast(
                    label,
                    lambda source=source: ai_llm.audit_ai_llm_inline(source, filename="app.js"),
                )

        report = ai_llm.audit_ai_llm_inline(
            'window.SYSTEM_PROMPT = "internal policy"\n'
            "completion = response.choices[0].message.content\n"
            "eval(completion)\n",
            filename="app.js",
        )
        risks = {finding["llm_risk"] for finding in report["findings"]}
        self.assertTrue({"LLM07", "LLM05"}.issubset(risks), risks)
        quoted_hash = ai_llm.audit_ai_llm_inline(
            'SYSTEM_PROMPT = "internal#policy"\n', filename="app.js"
        )
        self.assertTrue(any(finding["llm_risk"] == "LLM07" for finding in quoted_hash["findings"]))

    def test_api_spec_adversarial_braces_and_python_indentation_are_linear(self):
        path = "{{|" * 10_000
        spec = json.dumps({"openapi": "3.0.0", "paths": {path: {"get": {}}}})
        cases = (
            ("url-template", lambda: api_spec_routes._url_path("http://example.test/" + "{{" * 20_000)),
            ("path-parameters", lambda: api_spec_routes.parse_spec("openapi.json", spec)),
            (
                "python-class-body",
                lambda: api_spec_routes._function_index((("handlers.py", "class A:\n\t" + "\t" * 30_000),)),
            ),
        )
        for label, operation in cases:
            with self.subTest(label=label):
                self.assert_fast(label, operation)

        self.assertEqual(
            api_spec_routes._url_path("https://example.test/v1/{user_id}?expand=1"),
            "/v1/x",
        )
        parsed = api_spec_routes.parse_spec(
            "openapi.json",
            json.dumps({"openapi": "3.0.0", "paths": {"/users/{id}": {"get": {}}}}),
        )
        self.assertEqual(parsed["param_gaps"], ["GET /users/{id}: yol parametresi 'id' tanımlanmamış"])
        qualified, bare = api_spec_routes._function_index(
            (("pkg/views.py", "def list_users():\n    pass\n\nclass Users:\n    def get(self):\n        pass\n"),)
        )
        self.assertIn("list_users", bare)
        self.assertIn("Users.get", qualified)

    def test_audit_logging_adversarial_signatures_and_routes_are_linear(self):
        cases = (
            ("python-return", lambda: audit_logging._python_body([")->" + " " * 12_000 + "!"], 0)),
            (
                "javascript-route",
                lambda: audit_logging._detect_mutation_routes(
                    ["A" * 250_000 + '.post("/users", handler)'], False
                ),
            ),
            (
                "python-methods",
                lambda: audit_logging._detect_mutation_routes(
                    ["@app.route(" + "methods=(" * 4_000, "def update():", "    pass"], True
                ),
            ),
            (
                "java-auth-function",
                lambda: audit_logging.audit_logging_inline(
                    "public " + "\t" * 8_000 + "!", filename="Auth.java"
                ),
            ),
        )
        for label, operation in cases:
            with self.subTest(label=label):
                self.assert_fast(label, operation)

        self.assertEqual(
            audit_logging._python_body(["def authenticate() -> bool: return True"], 0),
            "return True",
        )
        py_routes = audit_logging._detect_mutation_routes(
            ["@app.route('/users', methods=['POST'])", "def update():", "    pass"], True
        )
        js_routes = audit_logging._detect_mutation_routes(
            ["app.post('/users', (req, res) => {", "  save(req.body);", "});"], False
        )
        self.assertEqual(py_routes[0]["path"], "/users")
        self.assertEqual(js_routes[0]["path"], "/users")
        java = audit_logging.audit_logging_inline(
            "public void authenticateUser(String token) {\n    return;\n}\n",
            filename="Auth.java",
        )
        self.assertTrue(any(f["control_id"] == "SNIPER-LOGG-01" for f in java["findings"]))

    def test_authorized_dns_validation_is_bounded_and_preserves_contract(self):
        adversarial = "https://" + "0" + ".00" * 90
        self.assert_raises_fast(
            "authorized-dns",
            ValueError,
            lambda: authorized_tool_targets.parse_authorized_target("k6", adversarial),
        )

        target = authorized_tool_targets.parse_authorized_target("k6", "https://api.example.test")
        self.assertEqual(target["normalized"], "https://api.example.test:443")
        for invalid in ("https://-bad.example", "https://bad-.example", "https://a..example"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                authorized_tool_targets.parse_authorized_target("k6", invalid)

    @staticmethod
    def _idor_tokens(receiver):
        def token(kind, value):
            return SimpleNamespace(kind=kind, value=value, line=1, parts=[])

        return [
            token("id", receiver),
            token("punct", "."),
            token("id", "get"),
            token("punct", "("),
            token("id", "id"),
            token("punct", ")"),
        ]

    def test_authz_receiver_classification_is_linear_and_equivalent(self):
        receiver = "a" * 16_000 + "!"
        result = self.assert_fast(
            "authz-receiver",
            lambda: authz_routes._js_idor(
                self._idor_tokens(receiver), 0, 6, "/users/:id", ""
            ),
        )
        self.assertIsNone(result)
        self.assertEqual(
            authz_routes._js_idor(
                self._idor_tokens("userRepo"), 0, 6, "/users/:id", ""
            ),
            {"line": 1, "lookup": "userRepo.get"},
        )


if __name__ == "__main__":
    unittest.main()
