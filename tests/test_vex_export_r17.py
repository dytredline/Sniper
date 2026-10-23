"""17. tur: Go modül/paket duyarlı sembol erişilebilirliği ve VEX (CycloneDX 1.5 / OpenVEX 0.2.0) üretimi ve içe aktarımı."""
from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import textwrap
import threading
import unittest
from unittest import mock
import urllib.error
import urllib.request
import zipfile

from http.server import ThreadingHTTPServer

import dependency_reachability as dr
from dependency_security import analyze_vulnerability_reachability
import project_analyzer
import vex_export as vx


def _write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text).lstrip("\n"), encoding="utf-8")


def _osv_archive(base: Path, records: dict[str, dict]) -> Path:
    root = base / "osv"
    archive = root / "generations" / "Go" / "20261020T000000Z-aaaaaaaaaaaa" / "db-cache" / "osv-scalibr" / "Go" / "all.zip"
    archive.parent.mkdir(parents=True)
    with zipfile.ZipFile(archive, "w") as zf:
        for key, record in records.items():
            zf.writestr(f"{key}.json", json.dumps(record))
    return root


class GoModuleReachabilityTests(unittest.TestCase):
    """Eski hata: "golang.org" alan adı kökü ve son parça ("net") başka modüllerin kullanımını eşliyordu."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.root = self.base / "proj"
        _write(self.root, "main.go", """
            package main
            import (
                "golang.org/x/text/language"
                tok "golang.org/x/net/html"
                "github.com/foo/bar/baz"
            )
            func f(s string) { language.Parse(s); baz.Do(); z := tok.NewTokenizer(nil); _ = z }
        """)
        rec = lambda pkg, path, syms: {"affected": [{"package": {"name": pkg},  # noqa: E731
                                                     "ecosystem_specific": {"imports": [{"path": path, "symbols": syms}]}}]}
        osv_root = _osv_archive(self.base, {
            "GO-1": rec("golang.org/x/crypto", "golang.org/x/crypto/ssh", ["Dial"]),
            "GO-2": rec("github.com/other/lib", "github.com/other/lib", ["Run"]),
            "GO-3": rec("golang.org/x/text", "golang.org/x/text/encoding", ["Parse"]),
            "GO-4": rec("golang.org/x/text", "golang.org/x/text/language", ["Parse"]),
            "GO-5": rec("golang.org/x/net", "golang.org/x/net/html", ["Tokenizer.Next"]),
        })
        patcher = mock.patch.dict(os.environ, {"SNIPER_OSV_DB_ROOT": str(osv_root)})
        patcher.start()
        self.addCleanup(patcher.stop)

    def verdicts(self):
        findings = [{"package_name": p, "vulnerability_id": v, "severity": "high"} for p, v in (
            ("golang.org/x/crypto", "GO-1"), ("github.com/other/lib", "GO-2"), ("golang.org/x/text", "GO-3"),
            ("golang.org/x/text", "GO-4"), ("golang.org/x/net", "GO-5"))]
        report = analyze_vulnerability_reachability(str(self.root), findings=findings, allowed_roots=(self.base,))
        return {it["vulnerability_id"]: it for it in report["items"]}

    def test_other_modules_are_not_attributed(self):
        items = self.verdicts()
        self.assertEqual(items["GO-1"]["reachability"]["verdict"], "not_imported")  # golang.org/x/crypto
        self.assertFalse(items["GO-1"]["reachable"])
        self.assertEqual(items["GO-2"]["reachability"]["verdict"], "not_imported")  # github.com/other/lib

    def test_package_path_qualified_symbols(self):
        items = self.verdicts()
        self.assertTrue(items["GO-3"]["reachable"])  # alt paket içe aktarması modülün kullanımıdır
        self.assertEqual(items["GO-3"]["reachability"]["verdict"], "imported_not_called")  # encoding.Parse ≠ language.Parse
        self.assertEqual(items["GO-4"]["reachability"]["verdict"], "reachable")
        self.assertEqual(items["GO-4"]["reachability"]["matched_symbols"], ["language.Parse"])

    def test_method_symbols_are_uncertain_not_downgraded(self):
        reach = self.verdicts()["GO-5"]["reachability"]
        self.assertEqual(reach["verdict"], "unknown")
        self.assertEqual(reach["effective_severity"], "high")
        self.assertEqual(reach["uncertain_symbols"], ["html.Tokenizer.Next"])

    def test_symbols_from_osv_qualification(self):
        record = {"affected": [{"package": {"name": "golang.org/x/net"}, "ecosystem_specific": {"imports": [
            {"path": "golang.org/x/net", "symbols": ["Root"]}, {"path": "golang.org/x/net/http2/hpack", "symbols": ["Decode"]},
            {"path": "golang.org/x/text", "symbols": ["Other"]}]}}]}
        self.assertEqual(dr.symbols_from_osv(record, "golang.org/x/net"), {"Root", "http2.hpack.Decode"})
        self.assertEqual(dr.symbols_from_osv({"affected": [{"package": {"name": "lodash"}, "ecosystem_specific": {
            "imports": [{"symbols": ["merge"]}]}}]}, "lodash"), {"merge"})
        self.assertTrue(dr.is_go_module("gopkg.in/yaml.v3"))
        for name in ("lodash/merge", "@babel/core", "requests", "org.apache:commons", "./x/y", "yaml.load"):
            self.assertFalse(dr.is_go_module(name), name)


class PurlTests(unittest.TestCase):
    def test_round_trip(self):
        cases = [("npm", "@babel/core", "7.1.0"), ("maven", "org.apache.commons:commons-text", "1.9"),
                 ("golang", "golang.org/x/net", "v0.17.0"), ("cargo", "serde", "1.0.0"), ("rubygems", "rails", "7.0")]
        for eco, name, version in cases:
            parsed = vx.parse_purl(vx.package_url(eco, name, version))
            self.assertEqual((parsed["ecosystem"], parsed["name"], parsed["version"]), (eco, name, version))
        self.assertEqual(vx.package_url("PyPI", "PyYAML_x", "5.1"), "pkg:pypi/pyyaml-x@5.1")
        self.assertIsNone(vx.parse_purl("not-a-purl"))
        self.assertEqual(vx.normalize_ecosystem("app/package-lock.json"), "npm")
        self.assertEqual(vx.normalize_ecosystem("Python (pip)"), "pypi")


def _finding(fid="f1", package="lodash", version="4.17.0", vid="GHSA-aaaa-bbbb-cccc", **extra):
    return {"id": fid, "package_name": package, "installed_version": version, "vulnerability_id": vid,
            "severity": "high", "fixed_version": "4.17.21", "source": "osv", "title": "Prototype pollution",
            "target": "npm", "status": "open", "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-1234"], **extra}


class DecisionTests(unittest.TestCase):
    def statement(self, finding, verdict="", components=None, override=None, **reach):
        reachability = {"items": [{**finding, "reachability": {"verdict": verdict, **reach}}]} if verdict else {}
        overrides = {finding["id"]: override} if override else {}
        return vx.build_statements([finding], reachability, overrides, components)[0]

    def test_auto_rules_are_conservative(self):
        st = self.statement(_finding(), "reachable", matched_symbols=["merge"])
        self.assertEqual((st["status"], st["action_statement"]), ("affected", "lodash paketini 4.17.21 ya da üstüne yükseltin."))
        self.assertEqual(st["aliases"], ["CVE-2026-1234"])
        # Açıklı fonksiyon kaynakta çağrılmıyor olsa bile (OSV sembolüyle dahi) otomatik "etkilenmiyor" yok.
        st = self.statement(_finding(), "imported_not_called", symbol_source="osv", symbols=["merge"])
        self.assertEqual(st["status"], "under_investigation")
        self.assertIn("çağrılmıyor", st["status_notes"])
        self.assertEqual(self.statement(_finding(), "not_imported")["status"], "under_investigation")
        self.assertEqual(self.statement(_finding(), "unknown")["status"], "under_investigation")
        self.assertEqual(self.statement(_finding(status="resolved"))["status"], "fixed")
        st = self.statement(_finding(status="risk_accepted", resolution_notes="iç ağ"), "reachable")
        self.assertEqual(st["status"], "affected")
        self.assertTrue(st["action_statement"].startswith("Risk kabul edildi: iç ağ"))

    def test_component_not_present_requires_complete_lockfile(self):
        lock = [{"ecosystem": "npm", "name": "express", "version": "4.0.0", "manifest": "package-lock.json"}]
        st = self.statement(_finding(), "not_imported", components=lock)
        self.assertEqual((st["status"], st["justification"]), ("not_affected", "component_not_present"))
        # Yalnız requirements.txt: dolaylı paketler listelenmez → kanıt değil.
        reqs = [{"ecosystem": "PyPI", "name": "flask", "version": "2.0", "manifest": "requirements.txt"}]
        st = self.statement(_finding(package="jinja2", target="pypi"), "not_imported", components=reqs)
        self.assertEqual(st["status"], "under_investigation")
        # Paket kilitte (başka sürüm) varsa ya da kaynak kullanıyorsa "yok" denmez.
        other = lock + [{"ecosystem": "npm", "name": "lodash", "version": "4.17.21", "manifest": "package-lock.json"}]
        self.assertEqual(self.statement(_finding(), "not_imported", components=other)["status"], "under_investigation")
        self.assertEqual(self.statement(_finding(), "reachable", components=lock)["status"], "affected")

    def test_dev_only_dependency_and_dedupe(self):
        lock = [{"ecosystem": "npm", "name": "lodash", "version": "4.17.0", "manifest": "package-lock.json", "scope": "optional"}]
        st = self.statement(_finding(), "not_imported", components=lock)
        self.assertEqual(st["status"], "under_investigation")  # varsayılan: yalnız not
        self.assertTrue(st["dev_only"])
        self.assertIn("geliştirme bağımlılığı", st["status_notes"])
        st = vx.build_statements([_finding()], {"items": [{**_finding(), "reachability": {"verdict": "not_imported"}}]}, {},
                                 lock, dev_not_affected=True)[0]
        self.assertEqual((st["status"], st["justification"], st["basis"]), ("not_affected", "component_not_present", "policy"))
        # Kod kullanıyorsa (erişilebilir) dev işareti kararı değiştirmez.
        st = vx.build_statements([_finding()], {"items": [{**_finding(), "reachability": {"verdict": "reachable"}}]}, {},
                                 lock, dev_not_affected=True)[0]
        self.assertEqual(st["status"], "affected")
        # Aynı açık iki kaynaktan (OSV + Trivy): tek ifade, temkinli durum, iki bulgu kimliği.
        both = vx.build_statements([_finding("a", status="resolved"), _finding("b", source="trivy")], None)
        self.assertEqual(len(both), 1)
        self.assertEqual((both[0]["status"], both[0]["finding_ids"]), ("under_investigation", ["a", "b"]))

    def test_analyst_override_and_validation(self):
        decision = vx.validate_decision({"status": "not_affected", "justification": "inline_mitigations_already_exist",
                                         "impact_statement": "Girdi şemayla doğrulanıyor, __proto__ anahtarı reddediliyor."})
        st = self.statement(_finding(), "reachable", override={**decision, "basis": "analyst", "author": "ali"})
        self.assertEqual((st["status"], st["basis"], st["author"]), ("not_affected", "analyst", "ali"))
        for bad in ({"status": "x"}, {"status": "not_affected", "justification": "inline_mitigations_already_exist"},
                    {"status": "not_affected", "impact_statement": "uzun bir açıklama metni"},
                    {"status": "affected"}, {"status": "fixed", "justification": "component_not_present"}):
            with self.subTest(bad=bad), self.assertRaises(vx.VexError):
                vx.validate_decision(bad)


class DocumentTests(unittest.TestCase):
    def setUp(self):
        mitigated = vx.validate_decision({"status": "not_affected", "justification": "vulnerable_code_not_in_execute_path",
                                          "impact_statement": "Yalnız derleme betiğinde kullanılıyor."})
        self.statements = vx.build_statements(
            [_finding(), _finding("f2", "@scope/pkg", "1.0.0", "CVE-2026-0002"), _finding("f3", vid="GHSA-zzzz-yyyy-xxxx", status="resolved")],
            {"items": [{**_finding(), "reachability": {"verdict": "reachable", "matched_symbols": ["merge"]}}]},
            {"f2": {**mitigated, "basis": "analyst"}})

    def test_cyclonedx(self):
        doc = vx.render(self.statements, "cyclonedx", project_name="demo", timestamp="2026-10-20T00:00:00Z", tool_version="2.0.1")
        self.assertEqual((doc["bomFormat"], doc["specVersion"]), ("CycloneDX", "1.5"))
        by_id = {v["id"]: v for v in doc["vulnerabilities"]}
        self.assertEqual(by_id["GHSA-aaaa-bbbb-cccc"]["analysis"]["state"], "exploitable")
        self.assertEqual(by_id["GHSA-aaaa-bbbb-cccc"]["analysis"]["response"], ["update"])
        self.assertEqual(by_id["CVE-2026-0002"]["analysis"], {"state": "not_affected", "justification": "code_not_reachable",
                                                              "detail": "Yalnız derleme betiğinde kullanılıyor."})
        self.assertEqual(by_id["CVE-2026-0002"]["affects"][0], {"ref": "pkg:npm/%40scope/pkg@1.0.0",
                                                               "versions": [{"version": "1.0.0", "status": "unaffected"}]})
        self.assertEqual(by_id["GHSA-zzzz-yyyy-xxxx"]["analysis"]["state"], "resolved")
        refs = {c["bom-ref"] for c in doc["components"]}
        self.assertTrue(all(a["ref"] in refs for v in doc["vulnerabilities"] for a in v["affects"]))
        again = vx.render(self.statements, "cyclonedx", project_name="demo", timestamp="2027-01-01T00:00:00Z")
        self.assertEqual(doc["serialNumber"], again["serialNumber"])  # içerikten deterministik

    def test_openvex(self):
        doc = vx.render(self.statements, "openvex", project_name="demo", timestamp="2026-10-20T00:00:00Z", author="ali")
        self.assertEqual(doc["@context"], "https://openvex.dev/ns/v0.2.0")
        self.assertTrue(doc["@id"].startswith("urn:uuid:"))
        for st in doc["statements"]:
            self.assertIn(st["status"], vx.STATUSES)
            if st["status"] == "not_affected":
                self.assertIn(st["justification"], vx.JUSTIFICATIONS)
            if st["status"] == "affected":
                self.assertTrue(st["action_statement"])
        self.assertEqual(doc["statements"][0]["vulnerability"]["aliases"], ["CVE-2026-1234"])
        with self.assertRaises(vx.VexError):
            vx.render(self.statements, "spdx", project_name="demo", timestamp="t")

    def test_import_round_trip_and_matching(self):
        findings = [_finding(), _finding("f2", "@scope/pkg", "1.0.0", "CVE-2026-0002")]
        upstream = {"@context": "https://openvex.dev/ns/v0.2.0", "author": "Tedarikçi", "statements": [
            {"vulnerability": {"name": "CVE-2026-1234"}, "products": [{"@id": "pkg:npm/lodash@4.17.0"}],
             "status": "not_affected", "justification": "vulnerable_code_not_present", "impact_statement": "Yamalı yapı."},
            {"vulnerability": {"name": "CVE-2026-0002"}, "products": [{"@id": "pkg:npm/%40scope/pkg@9.9.9"}],
             "status": "not_affected", "justification": "vulnerable_code_not_present"},   # sürüm uymuyor
            {"vulnerability": {"name": "CVE-2026-0002"}, "products": [{"@id": "pkg:npm/pkg@1.0.0"}],
             "status": "fixed"},                                                          # kapsamsız ad: başka paket
            {"vulnerability": {"name": "GHSA-aaaa-bbbb-cccc"}, "products": [{"@id": "pkg:npm/lodash"}],
             "status": "not_affected"}]}                                                   # gerekçesiz: alınmaz
        fmt, source, statements = vx.parse_document(upstream)
        self.assertEqual((fmt, source, len(statements)), ("openvex", "Tedarikçi", 4))
        decisions, unmatched = vx.match_imported(statements, findings)
        self.assertEqual(list(decisions), ["f1"])  # takma ad (CVE) üzerinden eşleşti
        self.assertEqual(decisions["f1"]["justification"], "vulnerable_code_not_present")
        self.assertEqual(unmatched, 3)
        # Kendi CycloneDX çıktımız geri okunabilir.
        own = vx.render(vx.build_statements(findings, None, {"f2": {"status": "affected", "action_statement": "Yükselt.",
                                                                    "basis": "analyst"}}), "cyclonedx",
                        project_name="demo", timestamp="t")
        _, _, parsed = vx.parse_document(own)
        decisions, _ = vx.match_imported(parsed, findings)
        self.assertEqual(decisions["f2"]["status"], "affected")
        with self.assertRaises(vx.VexError):
            vx.parse_document({"foo": 1})


class VexApiTests(unittest.TestCase):
    def setUp(self):
        import server
        from storage import Store

        self.server = server
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.data_dir = base / "data"
        self.data_dir.mkdir()
        self.root = base / "proj"
        _write(self.root, "package-lock.json", json.dumps({"lockfileVersion": 3, "packages": {
            "": {"name": "demo"}, "node_modules/lodash": {"version": "4.17.0"}, "node_modules/qs": {"version": "6.0.0"}}}))
        _write(self.root, "package.json", json.dumps({"name": "demo", "dependencies": {"lodash": "4.17.0"}}))
        _write(self.root, "app.js", "const _ = require('lodash');\nmodule.exports = (a, b) => _.merge(a, b);\n")
        self.previous_store = server.STORE
        server.STORE = Store(self.data_dir / "sniper-test.db")
        resolved = str(self.root.resolve())
        report = {"project_path": resolved, "source": "osv", "source_path": "osv.json", "source_timestamp": "2026-10-20T00:00:00Z",
                  "document_hash": "a" * 64, "findings": [
                      {"project_path": resolved, "source": "osv", "vulnerability_id": vid, "package_name": pkg,
                       "installed_version": ver, "severity": "high", "fixed_version": fix, "title": title, "summary": summ,
                       "target": "npm", "references": []}
                      for vid, pkg, ver, fix, title, summ in (
                          ("GHSA-1111-2222-3333", "lodash", "4.17.0", "4.17.21", "Prototype pollution",
                           "The `merge` function is vulnerable."),
                          ("GHSA-4444-5555-6666", "minimist", "0.0.1", "1.2.6", "Prototype pollution", ""),
                          ("GHSA-7777-8888-9999", "qs", "6.0.0", "6.10.3", "DoS", ""))]}
        server.STORE.import_dependency_findings(report)
        patches = [
            mock.patch.dict(os.environ, {"SNIPER_DATA_DIR": str(self.data_dir), "SNIPER_OSV_DB_ROOT": str(base / "no-osv")}),
            mock.patch.object(project_analyzer, "_allowed_roots", return_value=(base,)),
            mock.patch.object(server, "LIMITER", server.RateLimiter(limit=100000)),
        ]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.SniperHandler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.base_url = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.server.STORE = self.previous_store

    def call(self, path, body=None):
        request = urllib.request.Request(
            self.base_url + path, method="POST" if body is not None else "GET",
            data=json.dumps(body).encode() if body is not None else None,
            headers={"Content-Type": "application/json"} if body is not None else {})
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return response.status, json.loads(response.read()), response.headers
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read() or b"{}"), exc.headers

    def test_generate_decide_import(self):
        path = str(self.root)
        self.assertEqual(self.call("/api/dependency-security/vex", {"project_path": path})[0], 400)  # onaysız
        status, result, _ = self.call("/api/dependency-security/vex", {"project_path": path, "confirm_local": True})
        self.assertEqual(status, 200, result)
        by_pkg = {s["package"]: s for s in result["statements"]}
        self.assertEqual(by_pkg["lodash"]["status"], "affected")             # merge kodda kullanılıyor
        self.assertEqual(by_pkg["minimist"]["status"], "not_affected")       # tam kilit dosyasında yok
        self.assertEqual(by_pkg["minimist"]["justification"], "component_not_present")
        self.assertEqual(by_pkg["qs"]["status"], "under_investigation")      # dolaylı; içe aktarılmıyor
        self.assertEqual(result["document"]["@context"], vx.OPENVEX_CONTEXT)

        status, doc, headers = self.call("/api/dependency-security/vex", {"project_path": path, "confirm_local": True,
                                                                         "format": "cyclonedx", "download": True})
        self.assertEqual((status, doc["bomFormat"]), (200, "CycloneDX"))
        self.assertIn("cdx-vex.json", headers.get("Content-Disposition", ""))

        status, listing, _ = self.call("/api/dependency-security/vex-decisions?project_path=" + urllib.request.quote(path))
        self.assertEqual(status, 200)
        qs_id = next(f["id"] for f in listing["findings"] if f["package_name"] == "qs")
        lodash_id = next(f["id"] for f in listing["findings"] if f["package_name"] == "lodash")
        bad = {"confirm": True, "finding_id": qs_id, "status": "not_affected", "justification": "component_not_present"}
        self.assertEqual(self.call("/api/dependency-security/vex-decisions", bad)[0], 400)  # etki açıklaması yok
        good = {**bad, "justification": "vulnerable_code_not_in_execute_path",
                "impact_statement": "qs yalnız geliştirme sunucusunda yükleniyor; üretimde yok."}
        status, saved, _ = self.call("/api/dependency-security/vex-decisions", good)
        self.assertEqual((status, saved["basis"]), (200, "analyst"))
        actions = [e["action"] for e in self.server.STORE.recent_audit_log()]
        self.assertIn("dependency_vex.decided", actions)

        upstream = {"@context": "https://openvex.dev/ns/v0.2.0", "author": "Üst proje", "statements": [
            {"vulnerability": {"name": "GHSA-7777-8888-9999"}, "products": [{"@id": "pkg:npm/qs@6.0.0"}], "status": "affected",
             "action_statement": "6.10.3'e yükseltin."},
            {"vulnerability": {"name": "GHSA-1111-2222-3333"}, "products": [{"@id": "pkg:npm/lodash@4.17.0"}],
             "status": "fixed"}]}
        status, imported, _ = self.call("/api/dependency-security/vex-import", {"confirm": True, "project_path": path,
                                                                                "document": upstream})
        self.assertEqual(status, 200, imported)
        self.assertEqual((imported["applied"], imported["skipped_analyst"], imported["unmatched"]), (1, 1, 0))
        status, result, _ = self.call("/api/dependency-security/vex", {"project_path": path, "confirm_local": True})
        by_pkg = {s["package"]: s for s in result["statements"]}
        self.assertEqual((by_pkg["qs"]["status"], by_pkg["qs"]["basis"]), ("not_affected", "analyst"))  # analist korunur
        self.assertEqual((by_pkg["lodash"]["status"], by_pkg["lodash"]["basis"]), ("fixed", "imported"))
        status, cleared, _ = self.call("/api/dependency-security/vex-decisions", {"confirm": True, "finding_id": lodash_id,
                                                                                  "clear": True})
        self.assertEqual((status, cleared["cleared"]), (200, True))
        self.assertEqual(self.call("/api/dependency-security/vex-decisions", {"confirm": True, "finding_id": "depfnd_yok",
                                                                              "status": "fixed"})[0], 404)
        self.assertEqual(self.call("/api/dependency-security/vex", {"project_path": path, "confirm_local": True,
                                                                    "format": "spdx"})[0], 400)

    def test_cli_export(self):
        import cli_reports

        out = Path(self.tmp.name) / "out" / "vex.cdx.json"
        result = cli_reports.export_dependency_vex(str(self.root), out, "cyclonedx", db_path=self.data_dir / "sniper-test.db")
        document = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(document["bomFormat"], "CycloneDX")
        self.assertEqual(len(document["vulnerabilities"]), result["summary"]["total"])
        self.assertIn("dependency_vex.exported", [e["action"] for e in self.server.STORE.recent_audit_log()])


if __name__ == "__main__":
    unittest.main()
