"""Ölçüm hattı: zemin gerçeği, puanlama, CodeQL, geçmiş, regresyon, güven notu, triyaj istatistiği ve API."""
from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest import mock
import urllib.request

from http.server import ThreadingHTTPServer

import eval_metrics as em

APP_ROOT = Path(__file__).resolve().parents[1]
VULN = 'import os\nfrom flask import request\n\ndef run():\n    os.system("ping " + request.args["h"])\n'
SAFE = "def run():\n    return 1\n"


def _gt(**extra):
    raw = {"meta": {}, "projects": {"p": [{"file": "app.py", "lines": [5, 5], "class": "cmd", "kind": "direct"},
                                          {"file": "views.py", "lines": [10, 12], "class": "xss", "kind": "stored",
                                           "alt": [["t.html", 3, 3]]}]}}
    raw.update(extra)
    return em.normalize_ground_truth(raw)


class GroundTruthTests(unittest.TestCase):
    def test_old_format_is_normalized(self):
        gt = _gt()
        self.assertEqual(gt["format"], em.GT_FORMAT)
        self.assertEqual(gt["projects"]["p"][1]["alt"], [["t.html", 3, 3]])
        self.assertEqual(gt["adjudicated"], {})

    def test_invalid_entries_rejected(self):
        for bad in ({}, {"projects": {"p": [{"file": "a", "lines": [1], "class": "sql"}]}},
                    {"projects": {"p": [{"file": "a", "lines": [1, 1], "class": "bilinmez"}]}},
                    {"format": "x/2", "projects": {}},
                    {"projects": {}, "adjudicated": {"p": [{"file": "a", "line": 1, "class": "sql", "verdict": "belki"}]}}):
            with self.subTest(bad=bad), self.assertRaises(em.EvalError):
                em.normalize_ground_truth(bad)

    def test_matching_rules(self):
        gt = _gt()
        self.assertEqual(em.match_ground_truth(gt, "p", "app.py", 8, {"cmd"}), [0])
        self.assertEqual(em.match_ground_truth(gt, "p", "app.py", 9, {"cmd"}), [])  # ±3 dışında
        self.assertEqual(em.match_ground_truth(gt, "p", "app.py", 5, {"sql"}), [])  # sınıf farklı
        self.assertEqual(em.match_ground_truth(gt, "p", "t.html", 3, {"xss"}), [1])  # alternatif konum


class ScoringTests(unittest.TestCase):
    def test_score_with_adjudication(self):
        gt = _gt(adjudicated={"p": [{"file": "other.py", "line": 7, "class": "path", "verdict": "true_positive"},
                                    {"file": "x.js", "line": 2, "class": "xss", "verdict": "false_positive"}]})
        items = [("p", "app.py", 5, frozenset({"cmd"}), "t"), ("p", "other.py", 8, frozenset({"path"}), "t"),
                 ("p", "x.js", 2, frozenset({"xss"}), "t"), ("p", "y.py", 1, frozenset({"sql"}), "t")]
        scored = em.score_items(gt, items)
        self.assertEqual((scored["tp"], scored["total"], scored["fn"]), (1, 2, 1))
        self.assertEqual(scored["correct_findings"], 2)
        self.assertEqual(scored["false_positives"], 1)
        self.assertEqual(scored["unclassified"], 1)
        self.assertAlmostEqual(scored["precision"], 2 / 3, places=3)
        self.assertAlmostEqual(scored["precision_lower_bound"], 0.5)
        self.assertEqual(scored["missed_classes"], {"xss/stored": 1})
        precision = em.class_precision({"s": {"verified": scored}})
        self.assertEqual(precision["cmd"]["precision"], 1.0)
        self.assertEqual(precision["xss"]["precision"], 0.0)
        self.assertEqual(precision["xss"]["recall"], 0.0)

    def test_without_ground_truth_only_keys(self):
        scored = em.score_items(None, [("p", "a.py", 3, frozenset({"sql"}), "t")])
        self.assertEqual(scored["keys"], ["p|a.py:3|sql"])
        self.assertNotIn("tp", scored)

    def test_sniper_classes_and_flags(self):
        self.assertEqual(em.sniper_classes("CWE-89"), {"sql"})
        self.assertEqual(em.sniper_classes("OWASP"), frozenset())
        self.assertEqual(em.sniper_classes("CWE-94"), {"code", "ssti"})  # CodeQL code-injection ile simetrik
        self.assertEqual(em.sniper_classes("CWE-95"), {"code", "ssti"})
        self.assertTrue(em.is_verified_flow({"title": "Doğrulanmış veri akışı: x"}))
        self.assertTrue(em.is_second_order_flow({"title": "İkinci derece veri akışı: x"}))

    def test_memory_format_classes_and_language_specific_codeql_rules(self):
        # 8. set: C/C++ bellek güvenliği ve biçim dizgesi sınıfları; dile özgü adlı CodeQL taint kuralları.
        self.assertEqual(em.sniper_classes("CWE-120"), {"mem"})
        self.assertEqual(em.sniper_classes("CWE-416"), {"mem"})
        self.assertEqual(em.sniper_classes("CWE-134"), {"fmt"})
        self.assertEqual(em.codeql_classes("cpp/unbounded-write"), {"mem"})
        self.assertEqual(em.codeql_classes("cpp/tainted-format-string"), {"fmt"})
        self.assertEqual(em.codeql_classes("go/command-injection"), {"cmd"})
        self.assertEqual(em.codeql_classes("java/ssrf"), {"ssrf"})
        self.assertEqual(em.codeql_classes("java/xml/xpath-injection"), {"xpath"})
        self.assertEqual(em.codeql_classes("rb/server-side-template-injection"), {"ssti"})
        self.assertEqual(em.codeql_classes("cs/web/unvalidated-url-redirection"), {"redirect"})
        self.assertEqual(em.codeql_classes("java/log-injection"), frozenset())
        gt = em.normalize_ground_truth({"projects": {"p": [{"file": "a.c", "lines": [3, 3], "class": "mem"}]}})
        self.assertEqual(gt["projects"]["p"][0]["class"], "mem")

    def test_codeql_sarif_and_agreement(self):
        with tempfile.TemporaryDirectory() as tmp:
            sarif = {"runs": [{"results": [
                {"ruleId": "py/sql-injection", "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a.py"}, "region": {"startLine": 4}}}]},
                {"ruleId": "js/xss-through-dom", "locations": [{"physicalLocation": {"artifactLocation": {"uri": "b.js"}, "region": {"startLine": 1}}}]},
                {"ruleId": "py/clear-text-logging", "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a.py"}, "region": {"startLine": 1}}}]},
            ]}]}
            Path(tmp, "proj-py.sarif").write_text(json.dumps(sarif))
            Path(tmp, "diger-js.sarif").write_text(json.dumps(sarif))
            rows = em.codeql_items(tmp, ["proj"])
        self.assertEqual([(r[0], r[1], r[2]) for r in rows], [("proj", "a.py", 4), ("proj", "b.js", 1)])
        sniper = [("proj", "a.py", 6, frozenset({"sql"}), "t"), ("proj", "c.py", 1, frozenset({"cmd"}), "t")]
        self.assertEqual(em.agreement(sniper, rows[:1]), {"both": 1, "only_sniper": 1, "only_codeql": 0})


class HistoryAndRegressionTests(unittest.TestCase):
    def record(self, found, unmatched=(), seconds=1.0, keys=(), benign_keys=(), bench=82.9):
        return {"format": em.HISTORY_FORMAT, "config_name": "c", "label": "x", "created_at": "t", "created_epoch": 1.0,
                "sets": {"gt": {"kind": "vulnerable", "projects": {"p": {"seconds": seconds}},
                                "verified": {"found": found, "unmatched": [{"key": k, "verdict": v, "project": "p"} for k, v in unmatched]}},
                         "free": {"kind": "vulnerable", "projects": {}, "verified": {"keys": list(keys)}},
                         "olgun": {"kind": "benign", "projects": {}, "verified": {"keys": list(benign_keys)}}},
                "benchmarks": {"owasp_python_all": {"score": bench}}}

    def test_regressions_and_warnings(self):
        old = self.record({"p": [0, 1]}, keys=["a", "b"], unmatched=[("k1", "unclassified")])
        new = self.record({"p": [0]}, unmatched=[("k1", "unclassified"), ("k2", "unclassified"), ("k3", "true_positive")],
                          seconds=5.0, keys=["a", "c"], benign_keys=["fp"], bench=80.0)
        regressions, warnings = em.compare_records(new, old)
        types = sorted(r["type"] for r in regressions)
        self.assertEqual(types, ["benchmark_drop", "benign_new_flow", "flow_lost", "new_unmatched_finding", "tp_lost"])
        self.assertEqual(sorted(w["type"] for w in warnings), ["flow_new", "slowdown"])
        self.assertEqual(em.compare_records(old, old), ([], []))

    def test_history_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp) / "h"
            first = em.write_history({**self.record({}), "created_epoch": 100.0, "label": "r 1/../x"}, directory)
            second = em.write_history({**self.record({}), "created_epoch": 200.0, "label": "r2"}, directory)
            self.assertEqual(os.stat(first).st_mode & 0o777, 0o600)
            self.assertNotIn("/", first.name[:-5].split("-", 1)[1])
            self.assertEqual(em.list_history(directory), [first, second])
            self.assertEqual(em.previous_record(directory, "c", exclude=second)["label"], "r 1/../x")
            self.assertIsNone(em.previous_record(directory, "başka"))
            (directory / "bozuk.json").write_text("{")
            self.assertIsNone(em.read_history(directory / "bozuk.json"))

    def test_confidence_annotation(self):
        with tempfile.TemporaryDirectory() as tmp:
            record = {**self.record({}), "label": "r12", "class_precision": {
                "cmd": {"precision": 0.9, "judged": 10}, "sql": {"precision": 1.0, "judged": 2}}}
            em.write_history(record, Path(tmp))
            findings = [{"title": "Doğrulanmış veri akışı: komut", "reference": "CWE-78"},
                        {"title": "Doğrulanmış veri akışı: sql", "reference": "CWE-89"},
                        {"title": "Tehlikeli API", "reference": "CWE-78"}]
            em.annotate_confidence(findings, {"SNIPER_EVAL_HISTORY_DIR": tmp})
        self.assertEqual(findings[0]["confidence"]["measured_precision"], 0.9)
        self.assertIn("%90", findings[0]["confidence"]["note"])
        self.assertNotIn("confidence", findings[1])  # yetersiz örnek
        self.assertNotIn("confidence", findings[2])  # akış değil


class TriageStatsTests(unittest.TestCase):
    def test_rule_false_positive_rate(self):
        from storage import Store

        with tempfile.TemporaryDirectory() as tmp:
            store = Store(Path(tmp) / "sniper.db")
            base = {"created_at": "2026-10-20T00:00:00Z", "project_path": "/x", "project_name": "x", "score": 90,
                    "grade": "A", "file_count": 1, "bytes_scanned": 1}
            finding = {"category": "data_query", "severity": "high", "title": "SQL — a.py", "file": "a.py", "line": 1,
                       "evidence": "gizli kanıt", "recommendation": "", "reference": "CWE-89"}
            audit = store.create_project_audit({**base, "findings": [finding, finding, {**finding, "reference": "CWE-79", "title": "XSS"}]})
            for index, disposition in ((0, "false_positive"), (1, "confirmed"), (2, "needs_review")):
                store.update_project_audit_finding_triage(audit_id=audit["id"], finding_index=index, disposition=disposition, note="")
            stats = em.triage_rule_stats(store.path)
        self.assertEqual(stats["reviewed"], 2)
        self.assertEqual(stats["rules"], [{"reference": "CWE-89", "rule": "SQL", "reviewed": 2, "false_positive": 1, "confirmed": 1,
                                           "accepted_risk": 0, "false_positive_rate": 0.5}])
        self.assertNotIn("gizli", json.dumps(stats))
        self.assertEqual(em.triage_rule_stats(Path("/yok/sniper.db"))["rules"], [])


class PipelineEndToEndTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.vuln = base / "vuln"
        (self.vuln / "p").mkdir(parents=True)
        (self.vuln / "p" / "app.py").write_text(VULN)
        (base / "benign" / "ok").mkdir(parents=True)
        (base / "benign" / "ok" / "main.py").write_text(SAFE)
        gt = {"format": em.GT_FORMAT, "projects": {"p": [{"file": "app.py", "lines": [5, 5], "class": "cmd"}]}}
        (base / "gt.json").write_text(json.dumps(gt))
        self.config = base / "config.json"
        self.config.write_text(json.dumps({"name": "test", "sets": [
            {"name": "s", "kind": "vulnerable", "root": "vuln", "projects": ["p"], "ground_truth": "gt.json"},
            {"name": "olgun", "kind": "benign", "root": "benign"}]}))
        self.history = base / "history"

    def run_pipeline(self, *extra):
        import importlib.util
        import io
        import contextlib

        spec = importlib.util.spec_from_file_location("eval_pipeline", APP_ROOT / "scripts" / "eval_pipeline.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = module.main(["--config", str(self.config), "--history-dir", str(self.history), "--no-benchmarks", *extra])
        return code, out.getvalue()

    def test_run_compare_and_regression(self):
        code, out = self.run_pipeline("--label", "ilk")
        self.assertEqual(code, 0, out)
        self.assertIn("TP 1/1", out)
        paths = em.list_history(self.history)
        self.assertEqual(len(paths), 1)
        record = em.read_history(paths[0])
        self.assertEqual(record["file"], paths[0].name)
        self.assertEqual(record["sets"]["s"]["verified"]["precision"], 1.0)
        self.assertEqual(record["class_precision"]["cmd"]["judged"], 1)
        self.assertNotIn("request.args", json.dumps(record))  # kaynak satırı saklanmaz
        code, _ = self.run_pipeline("--label", "ikinci")
        self.assertEqual(code, 0)
        paths = em.list_history(self.history)
        self.assertEqual(len(paths), 2)
        self.assertEqual([em.read_history(path)["file"] for path in paths], [path.name for path in paths])
        (self.vuln / "p" / "app.py").write_text(SAFE + "\n" * 5)  # açık kayboldu
        code, out = self.run_pipeline("--label", "ucuncu")
        self.assertEqual(code, 1)
        self.assertIn("tp_lost", out)

    def test_no_write_control_creates_no_history_record(self):
        code, out = self.run_pipeline("--label", "dry-run", "--no-write")
        self.assertEqual(code, 0, out)
        self.assertIn("TP 1/1", out)
        self.assertEqual(em.list_history(self.history), [])
        self.assertFalse(self.history.exists())

    def test_bad_config_exit_code(self):
        self.config.write_text(json.dumps({"sets": [{"name": "s", "root": "yok"}]}))
        code, _ = self.run_pipeline()
        self.assertEqual(code, 2)

    def test_absolute_quality_gate_rejects_too_small_or_inaccurate_measurement(self):
        raw = json.loads(self.config.read_text())
        raw["sets"][0]["quality_gate"] = {
            "min_projects": 2,
            "min_labels": 2,
            "min_recall": 1.0,
            "min_precision": 1.0,
            "max_errors": 0,
        }
        self.config.write_text(json.dumps(raw))
        code, out = self.run_pipeline("--label", "quality-fail")
        self.assertEqual(code, 1, out)
        self.assertIn("quality_gate_failed", out)
        record = em.read_history(em.list_history(self.history)[0])
        gate = record["sets"]["s"]["quality_gate"]
        self.assertFalse(gate["passed"])
        self.assertEqual({failure["metric"] for failure in gate["failures"]}, {"projects", "labels"})

    def test_absolute_quality_gate_passes_and_invalid_thresholds_are_config_errors(self):
        raw = json.loads(self.config.read_text())
        raw["sets"][0]["quality_gate"] = {
            "min_projects": 1,
            "min_labels": 1,
            "min_recall": 1.0,
            "min_precision": 1.0,
            "max_errors": 0,
        }
        self.config.write_text(json.dumps(raw))
        code, out = self.run_pipeline("--label", "quality-pass")
        self.assertEqual(code, 0, out)
        self.assertIn("KALİTE KAPISI: GEÇTİ", out)

        raw["sets"][0]["quality_gate"]["min_recall"] = 1.1
        self.config.write_text(json.dumps(raw))
        code, _ = self.run_pipeline("--label", "quality-invalid")
        self.assertEqual(code, 2)


class EvalApiTests(unittest.TestCase):
    def test_eval_routes(self):
        import server
        from storage import Store

        with tempfile.TemporaryDirectory() as tmp:
            history = Path(tmp) / "history"
            record = {**HistoryAndRegressionTests().record({"p": [0]}), "label": "r12",
                      "class_precision": {"cmd": {"precision": 1.0, "judged": 6}},
                      "regressions": [{"type": "tp_lost", "set": "gt", "detail": [1]}], "warnings": []}
            record["sets"]["gt"]["verified"].update({"tp": 1, "total": 2, "recall": 0.5, "precision": 1.0,
                                                     "per_project": {"p": {"tp": 1, "total": 2}}})
            em.write_history(record, history)
            previous = server.STORE
            server.STORE = Store(Path(tmp) / "data" / "sniper.db")
            httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.SniperHandler)
            threading.Thread(target=httpd.serve_forever, daemon=True).start()
            try:
                with mock.patch.dict(os.environ, {"SNIPER_EVAL_HISTORY_DIR": str(history)}):
                    base = f"http://127.0.0.1:{httpd.server_address[1]}"
                    latest = json.loads(urllib.request.urlopen(base + "/api/eval/latest", timeout=10).read())
                    hist = json.loads(urllib.request.urlopen(base + "/api/eval/history", timeout=10).read())
                    rules = json.loads(urllib.request.urlopen(base + "/api/eval/rule-false-positives", timeout=10).read())
            finally:
                httpd.shutdown()
                httpd.server_close()
                server.STORE = previous
        self.assertEqual(latest["latest"]["label"], "r12")
        self.assertEqual(latest["latest"]["sets"]["gt"]["tp"], 1)
        self.assertEqual(latest["regressions"][0]["type"], "tp_lost")
        self.assertEqual(len(hist["history"]), 1)
        self.assertEqual(rules["rules"], [])

    def test_analyzer_attaches_measured_confidence(self):
        import project_analyzer

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "proj"
            root.mkdir()
            (root / "app.py").write_text(VULN)
            em.write_history({"format": em.HISTORY_FORMAT, "config_name": "c", "label": "r12", "created_at": "t",
                              "created_epoch": 1.0, "sets": {}, "class_precision": {"cmd": {"precision": 0.95, "judged": 20}}},
                             Path(tmp) / "h")
            with mock.patch.dict(os.environ, {"SNIPER_EVAL_HISTORY_DIR": str(Path(tmp) / "h")}):
                result = project_analyzer.analyze_project(str(root), allowed_roots=(Path(tmp),))
        flows = [f for f in result["findings"] if em.is_verified_flow(f)]
        self.assertTrue(flows)
        self.assertEqual(flows[0]["confidence"]["measured_precision"], 0.95)
        self.assertEqual(result["measurement"]["label"], "r12")




class IacClassTests(unittest.TestCase):
    """9. set: IaC bulguları 'iac' sınıfıyla yalnız tüm-sınıf puanlamasına girer (doğrulanmış akış değildir)."""

    def test_iac_findings_map_to_iac_class(self):
        import eval_metrics as em
        findings = [
            {"category": "container", "file": "k8s/pod.yaml", "line": 8, "title": "privileged", "reference": "CWE-250"},
            {"category": "iac", "file": "main.tf", "line": 5, "title": "public bucket", "reference": "CWE-732"},
            {"category": "code", "file": "a.py", "line": 3, "title": "Doğrulanmış veri akışı: x", "reference": "CWE-89"},
        ]
        all_rows = em.sniper_items("p", findings, verified_only=False)
        self.assertEqual([sorted(r[3]) for r in all_rows], [["iac"], ["iac"], ["sql"]])
        self.assertEqual(len(em.sniper_items("p", findings, verified_only=True)), 1)
        gt = em.normalize_ground_truth({"projects": {"p": [
            {"file": "k8s/pod.yaml", "lines": [8, 8], "class": "iac"}]}})
        self.assertEqual(em.score_items(gt, all_rows[:1])["tp"], 1)


class ScaScoringTests(unittest.TestCase):
    """10. set: SCA paket@sürüm düzeyi duyarlılık; ad/sürüm normalleştirme; ürün sözleşmesi yoksa 'unsupported'."""

    def test_score_sca_matches_normalized_package_and_ids(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "gt.json"
            path.write_text(json.dumps({"format": "sniper-sca-ground-truth/1", "projects": {"p": [
                {"ecosystem": "PyPI", "package": "PyYAML", "version": "5.3.1", "ids": ["CVE-2020-14343"]},
                {"ecosystem": "Go", "package": "github.com/dgrijalva/jwt-go", "version": "v3.2.0+incompatible", "ids": ["GO-2020-0017"]},
                {"ecosystem": "npm", "package": "lodash", "version": "4.17.20", "ids": ["CVE-2021-23337"]}]}}))
            gt = em.load_sca_ground_truth(path)
        findings = {"p": [
            {"ecosystem": "pypi", "name": "pyyaml", "version": "5.3.1", "ids": ["PYSEC-2021-142", "CVE-2020-14343"]},
            {"ecosystem": "go", "name": "github.com/dgrijalva/jwt-go", "version": "3.2.0", "ids": ["GHSA-W73W-5M7G-F7QC"]}]}
        scored = em.score_sca(gt, findings)
        self.assertEqual((scored["tp"], scored["total"], scored["id_match"]), (2, 3, 1))
        self.assertEqual(scored["found"], {"p": [0, 1]})
        self.assertEqual(scored["missed_classes"], {"sca/npm": 1})

    def test_unsupported_without_product_contract(self):
        import dependency_security
        with mock.patch.object(dependency_security, "offline_vulnerability_findings", None, create=True):
            self.assertEqual(em.sniper_sca_findings("/nonexistent", Path("/")), ([], "unsupported"))


if __name__ == "__main__":
    unittest.main()
