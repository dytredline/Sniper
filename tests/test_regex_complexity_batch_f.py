import time
import unittest

import taint_cfamily
import taint_rules_dsl
import web3_iot_firmware_auditor


LINEAR_BUDGET_SECONDS = 0.20


class RegexComplexityBatchFTests(unittest.TestCase):
    def assert_fast(self, label, operation, budget=LINEAR_BUDGET_SECONDS):
        started = time.perf_counter()
        result = operation()
        elapsed = time.perf_counter() - started
        self.assertLess(elapsed, budget, f"{label} took {elapsed:.3f}s")
        return result

    def test_cfamily_preprocessor_adversarial_inputs_are_linear(self):
        cases = (
            ("conditional-comment", lambda: taint_cfamily._cond_value("if", "/*" + "a/*" * 8_000 + "!")),
            ("defined-whitespace", lambda: taint_cfamily._cond_value("if", "defined" + " " * 8_000 + "!")),
            ("numeric-comparison", lambda: taint_cfamily._cond_value("if", "0" * 32_000)),
            ("directive-whitespace", lambda: taint_cfamily.preprocess("#define X" + " " * 100_000)),
            ("define-comment", lambda: taint_cfamily.preprocess("#define X /*" + "a/*" * 8_000 + "!")),
            ("escaped-quote", lambda: taint_cfamily.preprocess('#define X "' + '\\"' * 32_000)),
            ("function-macro-name", lambda: taint_cfamily.preprocess("#define " + "A" * 100_000)),
        )
        for label, operation in cases:
            with self.subTest(label=label):
                self.assert_fast(label, operation)

    def test_cfamily_preprocessor_keeps_comment_condition_and_macro_contracts(self):
        self.assertIs(taint_cfamily._cond_value("if", "1 /* enabled */"), True)
        self.assertIs(taint_cfamily._cond_value("if", "defined ( FEATURE )", {"FEATURE"}), True)
        self.assertIs(taint_cfamily._cond_value("if", "LEVEL == 2", {"LEVEL"}, values={"LEVEL": "2"}), True)

        function_macros = {}
        _skips, macros = taint_cfamily.preprocess(
            '#define FLAG 1 /* active */\n'
            '#define ALIAS OTHER\n'
            '#define TEXT "a\\"b"\n'
            '#define APPLY(x) x\n',
            function_macros=function_macros,
        )
        self.assertEqual(macros["FLAG"], "1")
        self.assertEqual(macros["ALIAS"], "OTHER")
        self.assertEqual(macros["TEXT"], '"a\\"b"')
        self.assertIn("APPLY", function_macros)

    def test_taint_rule_call_names_are_bounded_and_keep_the_dsl_grammar(self):
        bad = {
            "format": taint_rules_dsl.RULES_FORMAT,
            "name": "bad-call",
            "language": "javascript",
            "sinks": [{"kind": "command", "calls": ["$.$" * 66 + "!"], "args": [0]}],
        }
        with self.assertRaises(taint_rules_dsl.RuleError):
            self.assert_fast("taint-rule-call", lambda: taint_rules_dsl.validate_rule(bad))

        valid = {
            "format": taint_rules_dsl.RULES_FORMAT,
            "name": "js-edge",
            "language": "javascript",
            "sinks": [{"kind": "command", "calls": ["$.client.run()", "*.raw_sql"], "args": [0]}],
            "propagators": ["pkg.step", "pkg.*"],
        }
        rule = taint_rules_dsl.validate_rule(valid)
        self.assertEqual(rule["sinks"][0]["calls"], ["$.client.run()", "*.raw_sql"])
        self.assertEqual(rule["propagators"], ["pkg.step", "pkg.*"])

    def test_iot_adversarial_call_and_acl_inputs_are_linear(self):
        cases = (
            ("scanf-overflow", "fscanf(" + "scanf(" * 8_000 + "!", "fw.c"),
            ("format-whitespace", "syslog(" + " " * 40_000 + "!", "fw.c"),
            ("topic-whitespace", "topic " + "  " * 16_000 + "!", "mosquitto.conf"),
        )
        for label, content, filename in cases:
            with self.subTest(label=label):
                self.assert_fast(
                    label,
                    lambda content=content, filename=filename:
                        web3_iot_firmware_auditor.audit_iot_firmware_inline(content, filename=filename),
                )

    def test_iot_detectors_keep_unsafe_and_safe_call_contracts(self):
        content = (
            'gets(buf);\n'
            'fscanf(file, "%s", buf);\n'
            'fscanf(file, "%15s", buf);\n'
            'printf(user);\n'
            'fprintf(stderr, user);\n'
            'syslog(LOG_ERR, user);\n'
            'snprintf(out, size, user);\n'
            'printf("%s", user);\n'
            'topic readwrite #\n'
            'topic #\n'
        )
        report = web3_iot_firmware_auditor.audit_iot_firmware_inline(content, filename="firmware.c")
        titles = [finding["title"] for finding in report["findings"]]
        self.assertEqual(sum("Buffer Overflow" in title for title in titles), 2)
        self.assertEqual(sum("Format String" in title for title in titles), 4)
        self.assertEqual(sum("joker konu" in title for title in titles), 2)


if __name__ == "__main__":
    unittest.main()
