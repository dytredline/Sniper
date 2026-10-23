import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dos_resilience_redos_auditor import (  # noqa: E402
    analyze_regex_redos,
    audit_dos_resilience_inline,
    audit_dos_resilience_project,
)
from finding_limits import INLINE_FINDING_LIMIT, cap_findings, summarize_finding_groups  # noqa: E402


class RedosAnalyzerTests(unittest.TestCase):
    def test_nested_and_overlapping_quantifiers_are_high_risk(self):
        for pattern, kind in (("(a+)+$", "nested_quantifier"), ("([a-z]+)*", "nested_quantifier"), ("(a|ab)*c", "overlapping_alternation")):
            result = analyze_regex_redos(pattern)
            self.assertTrue(result["vulnerable"], pattern)
            self.assertEqual(result["risk"], "high", pattern)
            self.assertIn(kind, [issue["kind"] for issue in result["issues"]])

    def test_safe_patterns_are_not_flagged(self):
        for pattern in ("^[a-z0-9]+$", r"^\S+@\S+$", r"^\d{4}-\d{2}-\d{2}$"):
            self.assertFalse(analyze_regex_redos(pattern)["vulnerable"], pattern)

    def test_malformed_and_pathological_patterns_do_not_raise_or_hang(self):
        self.assertEqual(analyze_regex_redos("(")["issues"][0]["kind"], "parse_error")
        started = time.monotonic()
        analyze_regex_redos("(" * 1500 + "a" + ")+" * 1500)
        self.assertLess(time.monotonic() - started, 2.0)
        with self.assertRaises(ValueError):
            analyze_regex_redos("a" * 5001)


class DosResilienceInlineTests(unittest.TestCase):
    def test_missing_timeout_redos_and_decompression_are_flagged(self):
        result = audit_dos_resilience_inline(
            "import requests, re, zlib\nr = requests.get(url)\nP = re.compile(r'(a+)+$')\nzlib.decompress(data)\n"
        )
        controls = {(f["control_id"], f["severity"]) for f in result["findings"]}
        self.assertIn(("SNIPER-DOS-02", "medium"), controls)
        self.assertIn(("SNIPER-DOS-01", "high"), controls)
        self.assertIn(("SNIPER-DOS-03", "medium"), controls)

    def test_safe_code_has_no_findings(self):
        result = audit_dos_resilience_inline(
            "import requests\nimport defusedxml.ElementTree as ET\nr = requests.get(url, timeout=5)\n"
        )
        self.assertEqual(result["finding_count"], 0)
        self.assertFalse(result["findings_truncated"])

    def test_findings_are_capped_but_counted(self):
        result = audit_dos_resilience_inline("requests.get(u)\n" * 2000)
        self.assertGreater(result["finding_count"], INLINE_FINDING_LIMIT)
        self.assertEqual(len(result["findings"]), INLINE_FINDING_LIMIT)
        self.assertTrue(result["findings_truncated"])

    def test_empty_input_raises(self):
        with self.assertRaises(ValueError):
            audit_dos_resilience_inline("")

    def test_project_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            project = base / "svc"
            project.mkdir()
            (project / "client.py").write_text("import requests\nrequests.post(url, json=x)\n", encoding="utf-8")
            result = audit_dos_resilience_project(str(project), allowed_roots=(base,))
        self.assertEqual(result["format"], "sniper-dos-resilience-audit-v1")
        self.assertEqual(result["scanned_files"], 1)
        self.assertGreaterEqual(result["finding_count"], 1)


class FindingLimitTests(unittest.TestCase):
    def test_cap_keeps_most_severe_in_original_order(self):
        findings = [{"severity": "low", "title": "A", "i": 0}, {"severity": "critical", "title": "B", "i": 1}, {"severity": "medium", "title": "C", "i": 2}, {"severity": "high", "title": "D", "i": 3}]
        kept, total, truncated = cap_findings(findings, 2)
        self.assertEqual(total, 4)
        self.assertTrue(truncated)
        self.assertEqual([f["i"] for f in kept], [1, 3])
        same, total, truncated = cap_findings(findings, 10)
        self.assertIs(same, findings)
        self.assertFalse(truncated)

    def test_cap_never_hides_a_distinct_finding_type(self):
        flood = [{"severity": "high", "title": "flood", "i": i} for i in range(1000)]
        rare = {"severity": "low", "title": "rare", "i": 1000}
        kept, total, truncated = cap_findings(flood + [rare], 50)
        self.assertTrue(truncated)
        self.assertEqual(len(kept), 50)
        self.assertIn(rare, kept)
        groups = {g["title"]: g["count"] for g in summarize_finding_groups(flood + [rare])}
        self.assertEqual(groups, {"flood": 1000, "rare": 1})


if __name__ == "__main__":
    unittest.main()
