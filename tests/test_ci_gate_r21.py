"""21. tur CI kapısı: politika doğrulama, karar kuralları, istisnalar, SARIF/GitLab üretimi ve uçtan uca çalıştırma."""
from __future__ import annotations

import datetime as dt
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

APP = Path(__file__).resolve().parents[1]
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

import ci_gate  # noqa: E402
import finding_tracking  # noqa: E402

TODAY = dt.date(2026, 10, 21)
SQLI = ('from flask import request\nimport sqlite3\n\ndef q():\n    db = sqlite3.connect("x")\n'
        '    return db.execute("SELECT * FROM u WHERE n=\'" + request.args["n"] + "\'")\n')


def code(severity="high", **extra):
    base = {"category": "query", "severity": severity, "title": "SQL sorgusunda veri birleştirme", "file": "app.py",
            "line": 6, "cwe": "CWE-89", "evidence": "x | <b>", "recommendation": "parametre kullanın"}
    base.update(extra)
    return base


def sca(severity="high", malicious=False, **extra):
    base = {"_kind": "sca", "category": "dependency", "severity": severity, "title": "örnek açık",
            "file": "requirements.txt", "line": 3, "package_name": "django", "installed_version": "2.0.0",
            "ecosystem": "PyPI", "vulnerability_id": "GHSA-aaaa-bbbb-cccc", "aliases": ["CVE-2020-1"],
            "fixed_version": "2.0.1", "malicious": malicious, "cwe": "CWE-506" if malicious else "CWE-1395",
            "recommendation": "yükseltin", "priority": {"tier": "plan"}, "usage": "used"}
    base.update(extra)
    return base


class PolicyTests(unittest.TestCase):
    def test_defaults_and_shorthand(self):
        policy = ci_gate.validate_policy({"fail_on": "critical"})
        self.assertEqual(policy["fail_on"], {"default": "critical"})
        self.assertFalse(policy["new_only"])
        self.assertTrue(policy["license_denied"])

    def test_rejections(self):
        bad = [
            {"unknown": 1}, {"fail_on": {"default": "hgh"}}, {"fail_on": {"malicious": "none"}},
            {"fail_on": {"nope": "high"}}, {"new_only": "yes"}, {"version": 2},
            {"baseline": {"sarif": "a", "git_ref": "b"}}, {"exceptions": [{"id": "CWE-89", "reason": "kısa"}]},
            {"exceptions": [{"id": "CWE-89", "reason": "yeterince uzun gerekçe"}]},  # bitiş tarihi yok
            {"exceptions": [{"id": "bad id!", "reason": "yeterince uzun gerekçe", "expires": "2026-12-01"}]},
            {"exceptions": [{"id": "CWE-89", "reason": "yeterince uzun gerekçe", "expires": "31.12.2026"}]},
        ]
        for raw in bad:
            with self.subTest(raw=raw), self.assertRaises(ci_gate.PolicyError):
                ci_gate.validate_policy(raw)

    def test_yaml_and_json_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".sniper-policy.yml").write_text("fail_on:\n  default: medium\n  iac: none\nnew_only: true\n")
            policy, source = ci_gate.load_policy(None, root)
            self.assertEqual(source, ".sniper-policy.yml")
            self.assertEqual(policy["fail_on"], {"default": "medium", "iac": None})
            (root / "p.json").write_text("{bozuk")
            with self.assertRaises(ci_gate.PolicyError):
                ci_gate.load_policy(root / "p.json", root)
            self.assertEqual(ci_gate.load_policy(None, Path(tmp) / "x")[1], "varsayılan")


class DecisionTests(unittest.TestCase):
    def policy(self, **raw):
        return ci_gate.validate_policy(raw)

    def test_malicious_always_fails(self):
        findings = [sca("critical", malicious=True)]
        policy = self.policy(fail_on="none", exceptions=[{"id": "package:django", "reason": "susturma denemesi uzun",
                                                           "expires": "2030-01-01"}])
        ci_gate.apply_exceptions(findings, policy["exceptions"], TODAY)
        self.assertNotIn("exception", findings[0])
        decision = ci_gate.evaluate(findings, policy, compared=False)
        self.assertFalse(decision["passed"])
        self.assertIn("kötü amaçlı", decision["failing"][0]["_why"])

    def test_group_thresholds_and_flags(self):
        findings = [code("high"), sca("medium", priority={"tier": "fix_first"}),
                    {"category": "license", "severity": "high", "title": "Yasak lisans: GPL", "file": "package.json"},
                    {"category": "container", "severity": "critical", "title": "Konteyner root", "file": "Dockerfile",
                     "iac": {"check": "DF-003"}}]
        decision = ci_gate.evaluate(findings, self.policy(fail_on={"default": "critical", "iac": "none"}), compared=False)
        self.assertEqual([f["_why"] for f in decision["failing"]], ["yasak lisans"])
        decision = ci_gate.evaluate(findings, self.policy(fail_on="critical", license_denied=False, sca_fix_first=True),
                                    compared=False)
        self.assertEqual(sorted(f["_why"] for f in decision["failing"]),
                         sorted(["SCA 'Önce düzelt' katmanı", "Altyapı (IaC): critical ≥ critical"]))

    def test_new_only_needs_comparison(self):
        old, new = code("high", is_new=False), code("high", file="b.py", is_new=True)
        policy = self.policy(new_only=True)
        self.assertEqual(len(ci_gate.evaluate([old, new], policy, compared=True)["failing"]), 1)
        self.assertEqual(len(ci_gate.evaluate([old, new], policy, compared=False)["failing"]), 2)

    def test_exceptions_expiry_and_path(self):
        findings = [code("high"), code("high", file="vendor/x.py")]
        policy = self.policy(exceptions=[
            {"id": "CWE-89", "reason": "geçiş dönemi istisnası", "expires": "2026-12-31", "path": "vendor/*"},
            {"id": "CWE-79", "reason": "süresi geçmiş istisna", "expires": "2026-01-01"},
        ])
        info = ci_gate.apply_exceptions(findings, policy["exceptions"], TODAY)
        self.assertNotIn("exception", findings[0])
        self.assertEqual(findings[1]["exception"]["id"], "CWE-89")
        self.assertEqual(info["expired"], ["CWE-79"])
        self.assertEqual(len(ci_gate.evaluate(findings, policy, compared=False)["failing"]), 1)

    def test_triaged_findings_ignored(self):
        finding = code("critical", triage={"disposition": "false_positive"})
        self.assertTrue(ci_gate.evaluate([finding], self.policy(), compared=False)["passed"])

    def test_sla_reason(self):
        decision = ci_gate.evaluate([], self.policy(sla_breach=True), compared=False, sla_breaches=3)
        self.assertFalse(decision["passed"])
        self.assertIn("SLA", decision["reasons"][0])


class ReportTests(unittest.TestCase):
    def findings(self):
        flow = {"source": "request.args", "source_file": "app.py", "source_line": 6, "sink": "execute", "sink_kind": "sql",
                "source_label": "request", "via": []}
        return [
            code("critical", taint_flow=flow, is_new=True),
            code("medium", title="Konteyner root", category="container", file="Dockerfile", line=1, cwe="CWE-250",
                 iac={"check": "DF-003", "framework": "dockerfile", "resource": "", "checkov": "CKV_DOCKER_8"}),
            sca("high"),
            sca("critical", malicious=True, package_name="evil", vulnerability_id="MAL-2025-1", aliases=[]),
            code("low", exception={"id": "CWE-89", "reason": "geçici", "expires": "2026-12-31"}),
        ]

    def test_sarif_valid_and_stable(self):
        findings = self.findings()
        doc = ci_gate.build_sarif(findings, version="2.0.1-r21")
        self.assertEqual(ci_gate.validate_sarif(doc), [])
        run = doc["runs"][0]
        ids = [r["ruleId"] for r in run["results"]]
        self.assertEqual(ids[:4], ["sniper/code/taint-sql", "sniper/iac/DF-003", "sniper/sca/GHSA-aaaa-bbbb-cccc",
                                   "sniper/malicious/MAL-2025-1"])
        self.assertEqual(run["results"][0]["partialFingerprints"]["sniperTrack/v1"],
                         finding_tracking.fingerprint(findings[0]))
        self.assertIn("codeFlows", run["results"][0])
        self.assertEqual(run["results"][0]["baselineState"], "new")
        self.assertEqual(run["results"][4]["suppressions"][0]["status"], "accepted")
        rules = {r["id"]: r for r in run["tool"]["driver"]["rules"]}
        self.assertIn("external/cwe/cwe-89", rules["sniper/code/taint-sql"]["properties"]["tags"])
        self.assertEqual(rules["sniper/malicious/MAL-2025-1"]["properties"]["security-severity"], "9.5")
        self.assertEqual(ci_gate.build_sarif(self.findings(), version="2.0.1-r21"), doc)  # deterministik

    def test_sarif_validator_catches_errors(self):
        doc = ci_gate.build_sarif(self.findings())
        doc["runs"][0]["results"][0]["ruleId"] = "yok"
        doc["runs"][0]["results"][1]["locations"][0]["physicalLocation"]["region"]["startLine"] = 0
        problems = ci_gate.validate_sarif(doc)
        self.assertTrue(any("ruleId" in p for p in problems))
        self.assertTrue(any("startLine" in p for p in problems))
        self.assertEqual(ci_gate.validate_sarif({"version": "2.0.0"}), ["version '2.1.0' olmalı"])

    def test_gitlab_reports(self):
        start = dt.datetime(2026, 10, 21, 1, 2, 3, tzinfo=dt.timezone.utc)
        sast = ci_gate.build_gitlab_sast(self.findings(), root=None, start=start, end=start)
        dep = ci_gate.build_gitlab_dependency(self.findings(), start=start, end=start)
        self.assertEqual(ci_gate.validate_gitlab(sast, "sast"), [])
        self.assertEqual(ci_gate.validate_gitlab(dep, "dependency_scanning"), [])
        self.assertEqual(len(sast["vulnerabilities"]), 2)  # istisnalı ve SCA bulguları SAST raporunda yok
        self.assertEqual(len(dep["vulnerabilities"]), 2)
        self.assertEqual(sast["scan"]["start_time"], "2026-10-21T01:02:03")
        types = {i["type"] for i in dep["vulnerabilities"][0]["identifiers"]}
        self.assertTrue({"ghsa", "cve", "sniper_rule"} <= types)
        self.assertEqual(dep["dependency_files"][0]["package_manager"], "pip")

    def test_markdown_escapes(self):
        report = {"project_name": "p|x", "policy_source": "varsayılan", "baseline": None,
                  "decision": ci_gate.evaluate([code("high", title="a | <script>")], ci_gate.validate_policy({}), compared=False),
                  "counts": {g: {s: 0 for s in ci_gate.SEVERITIES} for g in ci_gate.GROUPS}, "warnings": [], "exceptions": {}}
        text = ci_gate.markdown_summary(report)
        self.assertIn("p\\|x", text)
        self.assertIn("&lt;script>", text)
        self.assertNotIn("<script>", text)


class EndToEndTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.root = self.base / "proj"
        self.root.mkdir()
        (self.root / "app.py").write_text(SQLI)
        (self.root / "requirements.txt").write_text("flask==2.0.0\n")
        patch = mock.patch.dict(os.environ, {"SNIPER_OSV_DB_ROOT": str(self.base / "osv-yok"),
                                             "SNIPER_DATA_DIR": str(self.base / "data")})
        patch.start()
        self.addCleanup(patch.stop)
        os.environ.pop("GITHUB_STEP_SUMMARY", None)

    def options(self, **extra):
        values = dict(project=str(self.root), allowed_roots=(self.base,), today=TODAY,
                      sarif=self.base / "out.sarif", gitlab_dir=self.base / "gl", summary=self.base / "s.md")
        values.update(extra)
        return ci_gate.CiOptions(**values)

    def test_full_run_outputs_and_failure(self):
        code_, report = ci_gate.run(self.options())
        self.assertEqual(code_, ci_gate.EXIT_POLICY, report)
        self.assertFalse(report["sca_available"])
        self.assertTrue(any("OSV" in w for w in report["warnings"]))
        sarif = json.loads((self.base / "out.sarif").read_text())
        self.assertEqual(ci_gate.validate_sarif(sarif), [])
        self.assertTrue((self.base / "gl" / "gl-sast-report.json").is_file())
        self.assertIn("BAŞARISIZ", (self.base / "s.md").read_text())

    def test_require_osv_and_bad_policy(self):
        (self.root / ".sniper-policy.json").write_text(json.dumps({"require_osv": True}))
        self.assertEqual(ci_gate.run(self.options())[0], ci_gate.EXIT_ERROR)
        (self.root / ".sniper-policy.json").write_text(json.dumps({"fail_on": "kötü"}))
        self.assertEqual(ci_gate.run(self.options())[0], ci_gate.EXIT_CONFIG)

    def test_baseline_sarif_new_only_passes(self):
        ci_gate.run(self.options())
        (self.root / ".sniper-policy.json").write_text(json.dumps({"new_only": True}))
        code_, report = ci_gate.run(self.options(baseline_sarif=self.base / "out.sarif", sarif=self.base / "out2.sarif"))
        self.assertEqual(code_, ci_gate.EXIT_PASS, report.get("decision"))
        self.assertTrue(report["compared"])

    @unittest.skipUnless(shutil.which("git"), "git yok")
    def test_git_ref_baseline_marks_changed_files_new(self):
        env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@e", GIT_COMMITTER_NAME="t",
                   GIT_COMMITTER_EMAIL="t@e", GIT_CONFIG_NOSYSTEM="1", HOME=str(self.base))
        for args in (["init", "-q"], ["add", "-A"], ["commit", "-qm", "taban"]):
            subprocess.run(["git", *args], cwd=self.root, check=True, env=env, capture_output=True)
        (self.root / "yeni.py").write_text(SQLI)
        (self.root / ".sniper-policy.json").write_text(json.dumps({"new_only": True}))
        code_, report = ci_gate.run(self.options(baseline_ref="HEAD"))
        self.assertEqual(code_, ci_gate.EXIT_POLICY, report)
        files = {f.get("file") for f in report["decision"]["failing"]}
        self.assertEqual(files, {"yeni.py"})

    def test_cli_exit_codes(self):
        (self.root / ".sniper-policy.json").write_text(json.dumps({"fail_on": "none"}))
        env = dict(os.environ)
        done = subprocess.run([sys.executable, str(APP / "cli_reports.py"), "ci", str(self.root), "--no-sca",
                               "--json", str(self.base / "r.json")], capture_output=True, text=True, env=env, timeout=300)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn("GEÇTİ", done.stdout)
        self.assertTrue(json.loads((self.base / "r.json").read_text())["decision"]["passed"])
        (self.root / ".sniper-policy.json").write_text("{bozuk")
        done = subprocess.run([sys.executable, str(APP / "cli_reports.py"), "ci", str(self.root), "--no-sca"],
                              capture_output=True, text=True, env=env, timeout=300)
        self.assertEqual(done.returncode, 2, done.stdout + done.stderr)


if __name__ == "__main__":
    unittest.main()


class TemplateTests(unittest.TestCase):
    def test_example_policy_and_templates(self):
        policy = ci_gate.validate_policy(json.loads((APP / "docs/ci/sniper-policy.example.json").read_text()))
        self.assertTrue(policy["new_only"])
        for name in ("github-actions-sniper-gate.yml", "gitlab-ci-sniper.yml", "Jenkinsfile.sniper", "pre-commit-sniper-gate.sh"):
            text = (APP / "docs/ci" / name).read_text()
            self.assertIn("cli_reports.py\" ci", text.replace("cli_reports.py ci", "cli_reports.py\" ci"))
            self.assertNotIn("curl", text)  # çevrimdışı: indirme yok
