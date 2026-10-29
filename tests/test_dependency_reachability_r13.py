"""Bağımlılık zafiyetlerinde sembol düzeyi erişilebilirlik (13. tur): açıklı fonksiyon kullanılıyor mu?"""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import textwrap
import unittest
from unittest import mock
import zipfile

import dependency_reachability as dr
from dependency_security import analyze_vulnerability_reachability


def _write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text).lstrip("\n"), encoding="utf-8")


class SymbolExtractionTests(unittest.TestCase):
    def test_call_forms_and_function_lists(self):
        self.assertEqual(dr.symbols_from_text(
            "The functions `merge`, `mergeWith`, and `defaultsDeep` could be tricked into adding `Object.prototype` keys.",
            {"lodash"}), {"merge", "mergeWith", "defaultsDeep"})
        self.assertEqual(dr.symbols_from_text("Calling yaml.load(input) with FullLoader runs code.", {"yaml", "pyyaml"}), {"load"})
        self.assertIn("jwt.verify", dr.symbols_from_text("`jwt.verify()` accepts unsigned tokens.", {"jsonwebtoken"}))

    def test_non_functions_are_ignored(self):
        text = "The `xmlattr` filter allows spaces. Set `allowPrototypes: true` in lib/qs.js or `package.json`. `__proto__`."
        self.assertEqual(dr.symbols_from_text(text, {"jinja2", "qs"}), set())


class ReachabilityVerdictTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.root = self.base / "proj"
        self.root.mkdir()

    def run_items(self, findings, **kwargs):
        report = analyze_vulnerability_reachability(str(self.root), findings=findings, allowed_roots=(self.base,), **kwargs)
        return report, {item["package_name"]: item for item in report["items"]}

    def test_python_verdicts_and_priority(self):
        _write(self.root, "app.py", """
            import yaml as y
            from jinja2 import Template
            import jsonwebtoken_like  # alakasız
            data = y.safe_load(open("a"))
            page = Template("x").render()
        """)
        _write(self.root, "jobs.py", """
            from yaml import load
            def run(stream):
                return load(stream)
        """)
        findings = [
            {"package_name": "pyyaml", "vulnerability_id": "V1", "severity": "critical", "summary": "Code execution via `yaml.load()`."},
            {"package_name": "jinja2", "vulnerability_id": "V2", "severity": "high", "summary": "The `xmlattr` filter allows spaces."},
            {"package_name": "jinja2", "vulnerability_id": "V3", "severity": "high", "summary": "Sandbox escape when calling `Environment.from_string()`."},
            {"package_name": "markdown", "vulnerability_id": "V4", "severity": "high", "summary": "`markdown()` ReDoS."},
            {"package_name": "urllib3", "vulnerability_id": "V5", "severity": "high", "summary": "`PoolManager.request()` leaks."},
            {"package_name": "idna", "vulnerability_id": "V6", "severity": "high", "summary": "`encode()` DoS."},
        ]
        _write(self.root, "requirements.txt", "PyYAML==5.1\nJinja2==3.0\nMarkdown==3.0\nrequests==2.0\n")
        _write(self.root, "net.py", "import requests\nrequests.get(u)\n")
        report, _ = self.run_items(findings)
        by_id = {item["vulnerability_id"]: item["reachability"] for item in report["items"]}
        # load() jobs.py'de çağrılıyor → erişilebilir (safe_load eşleşmez)
        self.assertEqual(by_id["V1"]["verdict"], "reachable")
        self.assertEqual(by_id["V1"]["evidence"][0]["file"], "jobs.py")
        self.assertEqual(by_id["V1"]["effective_severity"], "critical")
        # metin var ama sembol yok → bilinmiyor; bilinen-fonksiyon listesine başvurulmaz
        self.assertEqual(by_id["V2"]["verdict"], "unknown")
        self.assertIsNone(by_id["V2"]["symbol_source"])
        # from_string kullanılmıyor → içe aktarılmış ama çağrılmıyor; danışma metni kaynağı önemi düşürmez,
        # yalnız sıralamayı geriye alır (iç fonksiyona genel API üzerinden dolaylı erişim olabilir)
        self.assertEqual(by_id["V3"]["verdict"], "imported_not_called")
        self.assertEqual(by_id["V3"]["effective_severity"], "high")
        # doğrudan listelenmiş ama içe aktarılmıyor → kullanılmıyor, bir derece düşürülür, gizlenmez
        self.assertEqual(by_id["V4"]["verdict"], "not_imported")
        self.assertTrue(by_id["V4"]["direct_dependency"])
        self.assertEqual(by_id["V4"]["effective_severity"], "medium")
        # requests tarafından kullanılan alt bağımlılık → bilinmiyor, önem korunur
        self.assertEqual(by_id["V5"]["verdict"], "unknown")
        self.assertEqual(by_id["V5"]["indirect"]["loader"], "requests")
        self.assertEqual(by_id["V5"]["effective_severity"], "high")
        # bildirimde olmayan (dolaylı) ve yükleyicisi kullanılmayan → kullanılmıyor ama önem korunur
        self.assertEqual(by_id["V6"]["verdict"], "unknown")  # idna da requests alt bağımlılığı
        self.assertEqual(len(report["items"]), 6)
        self.assertEqual(report["symbol_analysis"]["verdict_counts"],
                         {"reachable": 1, "imported_not_called": 1, "not_imported": 1, "unknown": 3})
        order = [x["vulnerability_id"] for x in report["symbol_analysis"]["priority_order"]]
        self.assertEqual(order[0], "V1")
        self.assertLess(order.index("V2"), order.index("V3"))  # aynı önemde: bilinmiyor > çağrılmıyor
        # eski alanlar korunur
        self.assertTrue(report["items"][0]["reachable"])
        self.assertEqual(report["format"], "sniper-vulnerability-reachability-v1")

    def test_transitive_not_imported_keeps_severity(self):
        _write(self.root, "package.json", '{"dependencies": {"express": "4"}}')
        _write(self.root, "a.js", "const express = require('express');\nexpress();\n")
        _, items = self.run_items([{"package_name": "minimist", "vulnerability_id": "T1", "severity": "critical",
                                    "summary": "Prototype pollution."}])
        reach = items["minimist"]["reachability"]
        self.assertEqual(reach["verdict"], "not_imported")
        self.assertFalse(reach["direct_dependency"])
        self.assertEqual(reach["effective_severity"], "critical")

    def test_config_mention_and_loader_count_as_use(self):
        _write(self.root, "package.json", '{"dependencies": {"ejs": "1", "sequelize": "6", "mysql2": "3", "jquery": "2"}}')
        _write(self.root, "app.js", "app.set('view engine', 'ejs');\nconst { Sequelize } = require('sequelize');\nnew Sequelize(u);\n")
        report, items = self.run_items([
            {"package_name": "ejs", "vulnerability_id": "C1", "severity": "critical", "summary": "RCE in `renderFile()`."},
            {"package_name": "mysql2", "vulnerability_id": "C2", "severity": "high", "summary": "Bug."},
            {"package_name": "jquery", "vulnerability_id": "C3", "severity": "medium", "summary": "XSS in `extend()`."},
        ])
        self.assertEqual(items["ejs"]["reachability"]["verdict"], "unknown")
        self.assertEqual(items["ejs"]["reachability"]["indirect"]["via"], "mention")
        self.assertEqual(items["mysql2"]["reachability"]["indirect"], {"via": "loader", "loader": "sequelize"})
        self.assertEqual(items["jquery"]["reachability"]["verdict"], "not_imported")
        self.assertEqual(items["jquery"]["reachability"]["effective_severity"], "low")

    def test_curated_only_without_advisory_text_and_never_downgrades(self):
        _write(self.root, "a.py", "import yaml\nyaml.safe_load('x')\n")
        _, items = self.run_items([{"package_name": "pyyaml", "vulnerability_id": "V9", "severity": "high"}])
        reach = items["pyyaml"]["reachability"]
        self.assertEqual(reach["symbol_source"], "curated")
        self.assertEqual(reach["verdict"], "imported_not_called")
        self.assertEqual(reach["confidence"], "low")
        self.assertEqual(reach["effective_severity"], "high")

    def _js_project(self):
        _write(self.root, "server.js", """
            const _ = require('lodash');
            const { template: tpl } = require('lodash');
            const pick = require('lodash/pick');
            import merge from 'lodash.merge';
            import * as jwt from 'jsonwebtoken';
            _.defaultsDeep({}, req.body);
            pick(req.body, ['a']);
            jwt.sign({}, key);
        """)
        return [
            {"package_name": "lodash", "vulnerability_id": "J1", "severity": "high",
             "summary": "The functions `defaultsDeep`, `merge` and `mergeWith` pollute prototypes."},
            {"package_name": "lodash", "vulnerability_id": "J2", "severity": "high", "summary": "Command injection via `template` function."},
            {"package_name": "jsonwebtoken", "vulnerability_id": "J3", "severity": "high", "summary": "`jwt.verify()` accepts weak keys."},
            {"package_name": "lodash.merge", "vulnerability_id": "J4", "severity": "medium", "summary": "Prototype pollution in `merge()`."},
        ]

    def _check_js(self, report):
        by_id = {item["vulnerability_id"]: item["reachability"] for item in report["items"]}
        self.assertEqual(by_id["J1"]["verdict"], "reachable")
        self.assertIn("defaultsDeep", by_id["J1"]["matched_symbols"])
        self.assertEqual(by_id["J2"]["verdict"], "imported_not_called")  # tpl bağlandı ama çağrılmadı
        self.assertEqual(by_id["J3"]["verdict"], "imported_not_called")
        self.assertEqual(by_id["J3"]["effective_severity"], "high")
        self.assertEqual(by_id["J4"]["verdict"], "imported_not_called")  # merge içe aktarıldı ama çağrılmadı

    def _instance_project(self):
        _write(self.root, "routes.js", """
            var AdmZip = require('adm-zip');
            var marked = require('marked');
            app.locals.marked = marked;
            function imp(buf) {
              var zip = AdmZip(buf);
              zip.extractAllTo('/tmp/x', true);
            }
        """)
        return [
            {"package_name": "adm-zip", "vulnerability_id": "I1", "severity": "high",
             "summary": "Path traversal when calling `extractAllTo()` or `extractEntryTo()`; `Buffer.alloc` is not involved."},
            {"package_name": "marked", "vulnerability_id": "I2", "severity": "high",
             "summary": "ReDoS in the `parse` function. PoC: `alert(1)`."},
        ]

    def _check_instance(self, report):
        by_id = {item["vulnerability_id"]: item["reachability"] for item in report["items"]}
        self.assertEqual(by_id["I1"]["verdict"], "reachable")
        self.assertNotIn("Buffer.alloc", by_id["I1"]["symbols"])
        self.assertEqual(by_id["I2"]["verdict"], "unknown")  # paket şablonlara aktarılıyor
        self.assertNotIn("alert", by_id["I2"]["symbols"])

    def test_instances_and_escaping_bindings_regex(self):
        findings = self._instance_project()
        with mock.patch("taint_js_ast.available", return_value=False):
            report, _ = self.run_items(findings)
        self._check_instance(report)

    def test_instances_and_escaping_bindings_ast(self):
        import taint_js_ast

        if not taint_js_ast.available():
            self.skipTest("Node/Babel köprüsü yok")
        report, _ = self.run_items(self._instance_project())
        self._check_instance(report)

    def test_python_instances(self):
        _write(self.root, "a.py", "import requests\ns = requests.Session()\ns.request('GET', u)\n")
        _, items = self.run_items([{"package_name": "requests", "vulnerability_id": "P1", "severity": "medium",
                                    "summary": "Proxy-Authorization leak in `Session.request()`."}])
        self.assertEqual(items["requests"]["reachability"]["verdict"], "reachable")

    def test_javascript_regex_fallback(self):
        findings = self._js_project()
        with mock.patch("taint_js_ast.available", return_value=False):
            report, _ = self.run_items(findings)
        self.assertIn("javascript-regex", report["symbol_analysis"]["engines"])
        self._check_js(report)

    def test_javascript_ast(self):
        import taint_js_ast

        if not taint_js_ast.available():
            self.skipTest("Node/Babel köprüsü yok")
        report, _ = self.run_items(self._js_project())
        self.assertIn("javascript-ast", report["symbol_analysis"]["engines"])
        self._check_js(report)

    def test_offline_osv_symbols_go(self):
        osv_root = self.base / "osv"
        archive = osv_root / "generations" / "Go" / "20261020T000000Z-aaaaaaaaaaaa" / "db-cache" / "osv-scalibr" / "Go" / "all.zip"
        archive.parent.mkdir(parents=True)
        record = {"id": "GO-2026-0001", "affected": [{"package": {"name": "golang.org/x/net", "ecosystem": "Go"},
                  "ecosystem_specific": {"imports": [{"path": "golang.org/x/net/html", "symbols": ["Parse", "Tokenizer.Next"]}]}}]}
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("GO-2026-0001.json", json.dumps(record))
        _write(self.root, "main.go", """
            package main
            import (
                h "golang.org/x/net/html"
                "strings"
            )
            func f(s string) { h.Parse(strings.NewReader(s)) }
        """)
        with mock.patch.dict("os.environ", {"SNIPER_OSV_DB_ROOT": str(osv_root)}):
            _, items = self.run_items([{"package_name": "golang.org/x/net", "vulnerability_id": "GO-2026-0001", "severity": "high"}])
        reach = items["golang.org/x/net"]["reachability"]
        self.assertEqual(reach["symbol_source"], "osv")
        self.assertEqual(reach["confidence"], "high")
        self.assertEqual(reach["verdict"], "reachable")
        self.assertEqual(reach["evidence"][0]["file"], "main.go")

    def test_offline_osv_rejects_bad_ids(self):
        osv = dr.OfflineOSV(archives=[])
        self.assertIsNone(osv.record("../../etc/passwd"))
        self.assertIsNone(osv.record("GHSA-xxxx-yyyy-zzzz"))

    def test_is_lockfile_patched_multi_branch(self):
        self.assertFalse(dr.is_lockfile_patched("7.18.2, 8.3.0", {"8.1.0"}))
        self.assertTrue(dr.is_lockfile_patched("7.18.2, 8.3.0", {"8.3.0"}))
        self.assertTrue(dr.is_lockfile_patched("7.18.2, 8.3.0", {"7.19.0"}))
        self.assertFalse(dr.is_lockfile_patched("7.18.2, 8.3.0", {"7.18.0"}))

    def test_empty_findings_list_does_not_fallback_to_inventory(self):
        _write(self.root, "package.json", '{"dependencies": {"lodash": "4.17.21"}}')
        _write(self.root, "index.js", 'const _ = require("lodash");\n_.chunk([1, 2], 1);\n')
        res, _ = self.run_items([])
        self.assertEqual(res["items"], [])
        self.assertEqual(res["reachable_count"], 0)

    def test_advisory_reachability_synchronizes_top_level_reachable(self):
        _write(self.root, "app.py", "import requests\nrequests.post('https://example.com')\n")
        res, items = self.run_items(
            [
                {
                    "package_name": "requests",
                    "vulnerability_id": "GHSA-test-0001",
                    "severity": "high",
                    "title": "Vulnerability in requests.get()",
                    "source": "osv",
                }
            ]
        )
        self.assertEqual(len(res["items"]), 1)
        item = items["requests"]
        self.assertEqual(item["reachability"]["verdict"], "imported_not_called")
        self.assertFalse(item["reachable"])
        self.assertEqual(res["reachable_count"], 0)


if __name__ == "__main__":
    unittest.main()
