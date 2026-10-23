"""Sniper çekirdek Opengrep kural paketi: yapı denetimi ve kural başına olumlu/olumsuz örnek.

Kural paketi Sniper için yazıldı; Semgrep Registry kuralları lisans nedeniyle kullanılmaz.
Opengrep ikilisi SHA-256 ile sabitli kurulu değilse çalıştırma testleri atlanır.
"""
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from collections import defaultdict
from pathlib import Path

import yaml

import tool_report_sarif
from semgrep_active import BUILTIN_OPENGREP_RULES, _extract_rulepack_coverage_metadata
from tool_pins import open_pinned, pin_status

APP = Path(__file__).resolve().parents[1]
FIXTURES = APP / "tests" / "fixtures" / "opengrep_rules"
_TURKISH = re.compile(r"[çğıöşüÇĞİÖŞÜ]")


class RulepackStructureTests(unittest.TestCase):
    def setUp(self):
        self.rules = yaml.safe_load(BUILTIN_OPENGREP_RULES.read_text(encoding="utf-8"))["rules"]

    def test_rule_metadata_is_complete_and_turkish(self):
        self.assertGreaterEqual(len(self.rules), 25)
        self.assertLessEqual(len(self.rules), 40)
        ids = [rule["id"] for rule in self.rules]
        self.assertEqual(len(ids), len(set(ids)))
        languages = set()
        for rule in self.rules:
            with self.subTest(rule=rule["id"]):
                self.assertTrue(rule["id"].startswith("sniper."))
                self.assertRegex(rule["metadata"]["cwe"], r"^CWE-\d+: ")
                self.assertIn(rule["severity"], {"ERROR", "WARNING", "INFO"})
                self.assertRegex(rule["message"], _TURKISH)
                self.assertNotIn("$", rule["message"])  # kod parçası taşıyan metavariable yok
                languages.update(rule["languages"])
        self.assertTrue({"python", "javascript", "typescript", "go", "java"} <= languages)

    def test_every_rule_has_positive_and_negative_fixture(self):
        for rule in self.rules:
            with self.subTest(rule=rule["id"]):
                folder = FIXTURES / rule["id"]
                self.assertTrue(any(folder.glob("pos_*")), "olumlu örnek yok")
                self.assertTrue(any(folder.glob("neg_*")), "olumsuz örnek yok")

    def test_builtin_pack_passes_existing_rulepack_validation(self):
        meta = _extract_rulepack_coverage_metadata(BUILTIN_OPENGREP_RULES)
        self.assertEqual(meta["rule_count"], len(self.rules))
        self.assertIn("sql-injection", meta["categories"])
        self.assertFalse(meta["remote_rules_fetched"])

    def test_opengrep_sarif_driver_is_accepted(self):
        report = json.loads((APP / "tests" / "fixtures" / "opengrep_sarif_sample.sarif").read_text(encoding="utf-8"))
        summary = tool_report_sarif.parse_sarif_summary(report)
        self.assertEqual(summary["tools"][0]["name"], "Opengrep OSS")
        self.assertEqual(summary["result_count"], 1)


@unittest.skipUnless(pin_status("opengrep")["state"] == "pinned", "Sabitli Opengrep kurulu değil")
class RulepackExecutionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="sniper_opengrep_rules_")
        root = Path(cls.temp.name)
        # tests/ altındaki dosyalar Opengrep'in varsayılan yok sayma listesinde; kopya taranır.
        shutil.copytree(FIXTURES, root / "fx")
        home = root / "home"
        home.mkdir()
        out = root / "out.json"
        with open_pinned("opengrep") as verified:
            subprocess.run(
                [verified.argv0, "scan", str(root / "fx"), "--config", BUILTIN_OPENGREP_RULES.name, "--json",
                 "--quiet", "--disable-version-check", "--no-git-ignore", "--taint-intrafile",
                 "--jobs", "2", "--output", str(out)],
                **verified.popen_kwargs(cwd=str(BUILTIN_OPENGREP_RULES.parent), timeout=180, check=True,
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                        env={"PATH": "/usr/bin:/bin", "HOME": str(home), "LC_ALL": "C.UTF-8",
                                             "PYTHONUTF8": "1", "XDG_CACHE_HOME": str(home / ".cache")}))
        cls.report = json.loads(out.read_text(encoding="utf-8"))
        cls.hits = defaultdict(set)
        for result in cls.report["results"]:
            path = Path(result["path"])
            cls.hits[(path.parent.name, path.name)].add(result["check_id"])

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_no_engine_errors(self):
        self.assertEqual(self.report["errors"], [])

    def test_each_rule_fires_on_positive_and_not_on_negative(self):
        for folder in sorted(FIXTURES.iterdir()):
            rule_id = folder.name
            for sample in sorted(folder.iterdir()):
                ids = self.hits.get((rule_id, sample.name), set())
                with self.subTest(rule=rule_id, sample=sample.name):
                    if sample.name.startswith("pos_"):
                        self.assertIn(rule_id, ids)
                    else:
                        self.assertNotIn(rule_id, ids)

    def test_rule_ids_have_no_local_path_prefix(self):
        for result in self.report["results"]:
            self.assertTrue(result["check_id"].startswith("sniper."), result["check_id"])


if __name__ == "__main__":
    unittest.main()
