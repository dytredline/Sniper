"""SARIF kayıtlı rapor araç izin listesi, sürücü adıyla birebir eşleşmeli."""

import unittest

from tool_report_sarif import ALLOWLISTED_TOOLS, parse_sarif_summary


def report(name):
    return {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": name}}, "results": [{"level": "warning"}]}],
    }


class ExactSarifDriverNameTests(unittest.TestCase):
    def test_exact_official_driver_name_keeps_runtime_summary(self):
        result = parse_sarif_summary(report("CodeQL command-line toolchain"))
        self.assertEqual(result["tools"][0]["name"], "CodeQL command-line toolchain")
        self.assertEqual(result["tools"][0]["levels"]["warning"], 1)
        self.assertEqual(result["result_count"], 1)

    def test_every_allowlisted_exact_name_is_accepted(self):
        for name in sorted(ALLOWLISTED_TOOLS):
            with self.subTest(name=name):
                self.assertEqual(parse_sarif_summary(report(name))["tools"][0]["name"], name)

    def test_whitespace_padded_driver_is_not_presented_as_official(self):
        for name in (
            " CodeQL command-line toolchain ",
            "CodeQL command-line toolchain\n",
            " Semgrep",
            "osv-scanner\t",
            "Nuclei ",
            " Trivy",
        ):
            with self.subTest(name=repr(name)), self.assertRaises(ValueError):
                parse_sarif_summary(report(name))

    def test_case_variant_is_still_rejected(self):
        with self.assertRaises(ValueError):
            parse_sarif_summary(report("semgrep"))


if __name__ == "__main__":
    unittest.main()
