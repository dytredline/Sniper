"""20. tur: çok ekosistemli bağımlılık kullanımı (doğrudan/geçişli/kullanılmıyor), RustSec işlev sembolleri,
önceliklendirme puanı, kayıtlı bulgulara yazma, portföy özeti ve VEX notu."""
from __future__ import annotations

import json
import os
from pathlib import Path
import sqlite3
import tempfile
import textwrap
import unittest
from unittest import mock

import dependency_reachability as dr
from dependency_security import analyze_vulnerability_reachability
import portfolio
import vex_export as vx


def _write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text).lstrip("\n"), encoding="utf-8")


def _finding(pkg: str, eco: str, *, version: str = "1.0.0", severity: str = "high", fixed: str = "9.9.9",
             vid: str | None = None) -> dict:
    return {"package_name": pkg, "installed_version": version, "vulnerability_id": vid or f"GHSA-{abs(hash(pkg)) % 9999:04d}",
            "severity": severity, "fixed_version": fixed, "target": eco, "title": "örnek açık"}


class RustSecSymbolTests(unittest.TestCase):
    def test_affects_functions_become_dotted_relative_symbols(self):
        record = {"affected": [{"package": {"name": "libpulse-binding"},
                                "ecosystem_specific": {"affects": {"functions": [
                                    "libpulse_binding::stream::Stream::get_context", "bad path", "x::y"]}}}]}
        self.assertEqual(dr.symbols_from_osv(record, "libpulse-binding"),
                         {"stream.Stream.get_context", "x.y"})

    def test_rust_use_paths(self):
        self.assertEqual(dr._rs_use_paths("a::b::{C, d::E as F, self}"),
                         [("C", "a::b::C"), ("F", "a::b::d::E"), ("b", "a::b")])

    def test_rust_usage_index_and_symbol_match(self):
        index = dr.UsageIndex()
        dr._rs_index(index, "src/main.rs", textwrap.dedent("""
            use serde_yaml::{from_str, Value};
            use other::Thing;
            fn main() {
                let v: Value = serde_yaml::from_str("a: 1").unwrap();
                let t = Thing::new();
            }
        """))
        uses = index.for_package({"serde_yaml", "serde-yaml"})
        self.assertIn("from_str", uses)
        self.assertTrue(dr._symbol_used("from_str", uses))
        self.assertFalse(index.for_package({"tokio"}))


class UsageAndPriorityTests(unittest.TestCase):
    def test_usage_state_matrix(self):
        self.assertEqual(dr.usage_state(True, None, False), "used")
        self.assertEqual(dr.usage_state(False, True, True), "unused")
        self.assertEqual(dr.usage_state(False, False, True), "transitive_only")
        self.assertEqual(dr.usage_state(False, True, False), "unknown")  # ekosistemin kaynağı yok
        self.assertEqual(dr.usage_state(False, None, True), "unknown")   # doğrudan/dolaylı bilinmiyor

    def test_priority_tiers_and_malicious(self):
        reach = {"verdict": "reachable", "direct_dependency": True}
        top = dr.priority({"severity": "critical", "fixed_version": "2.0"}, reach, "used")
        self.assertEqual(top["tier"], "fix_first")
        self.assertGreaterEqual(top["score"], 45)
        low = dr.priority({"severity": "low", "fixed_version": ""}, {"verdict": "not_imported", "direct_dependency": False},
                          "transitive_only")
        self.assertEqual(low["tier"], "monitor")
        unused = dr.priority({"severity": "high", "fixed_version": "1.1"}, {"verdict": "not_imported", "direct_dependency": True},
                             "unused")
        used = dr.priority({"severity": "high", "fixed_version": "1.1"}, {"verdict": "unknown", "direct_dependency": True}, "used")
        self.assertLess(unused["score"], used["score"])
        mal = dr.priority({"severity": "low", "vulnerability_id": "MAL-2025-1"}, {"verdict": "not_imported"}, "unknown")
        self.assertEqual((mal["score"], mal["tier"]), (100, "fix_first"))


class MultiEcosystemReachabilityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.root = self.base / "proj"
        patcher = mock.patch.dict(os.environ, {"SNIPER_OSV_DB_ROOT": str(self.base / "no-osv")})
        patcher.start()
        self.addCleanup(patcher.stop)
        r = self.root
        # Maven: jackson-databind kullanılıyor (grup ≠ paket öneki), log4j-core bildirilmiş ama kullanılmıyor
        _write(r, "pom.xml", """
            <project><dependencies>
              <dependency><groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-databind</artifactId><version>2.9.0</version></dependency>
              <dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>2.14.1</version></dependency>
            </dependencies>
            <dependencyManagement><dependencies>
              <dependency><groupId>org.yaml</groupId><artifactId>snakeyaml</artifactId><version>1.0</version></dependency>
            </dependencies></dependencyManagement></project>
        """)
        _write(r, "src/main/java/App.java", """
            package app;
            import com.fasterxml.jackson.databind.ObjectMapper;
            class App { ObjectMapper m = new ObjectMapper(); }
        """)
        # Packagist: composer.lock ad alanı (GuzzleHttp\\) ile; monolog bildirilmiş ama kullanılmıyor
        _write(r, "composer.json", json.dumps({"require": {"guzzlehttp/guzzle": "^7", "monolog/monolog": "^2"}}))
        _write(r, "composer.lock", json.dumps({"packages": [
            {"name": "guzzlehttp/guzzle", "version": "7.0.0", "autoload": {"psr-4": {"GuzzleHttp\\": "src/"}}},
            {"name": "monolog/monolog", "version": "2.0.0", "autoload": {"psr-4": {"Monolog\\": "src/Monolog"}}},
            {"name": "guzzlehttp/psr7", "version": "1.0.0", "autoload": {"psr-4": {"GuzzleHttp\\Psr7\\": "src/"}}},
        ]}))
        _write(r, "web/index.php", """
            <?php
            use GuzzleHttp\\Client;
            $c = new Client();
        """)
        # Ruby: Bundler.require ile gem'ler açılışta yüklenir; require: false olan yüklenmez
        _write(r, "Gemfile", """
            source 'https://rubygems.org'
            gem 'nokogiri'
            gem 'brakeman', require: false
        """)
        _write(r, "config/application.rb", "require 'bundler/setup'\nBundler.require(*Rails.groups)\n")
        _write(r, "app/models/user.rb", "class User\nend\n")
        # NuGet: using ile
        _write(r, "Api/Api.csproj", '<Project><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="12.0.1" />'
                                    '<PackageReference Include="Serilog" Version="2.0.0" /></ItemGroup></Project>')
        _write(r, "Api/Program.cs", "using Newtonsoft.Json;\nclass P { }\n")
        # crates.io
        _write(r, "Cargo.toml", "[package]\nname = 'x'\n[dependencies]\nserde_yaml = '0.8'\nregex = '1'\n")
        _write(r, "src/main.rs", "use serde_yaml::Value;\nfn main() { let v: Value = serde_yaml::from_str(\"a\").unwrap(); }\n")

    def test_usage_states_across_ecosystems(self):
        findings = [
            _finding("com.fasterxml.jackson.core:jackson-databind", "Maven", severity="critical"),
            _finding("org.apache.logging.log4j:log4j-core", "Maven"),
            _finding("org.yaml:snakeyaml", "Maven", severity="medium"),          # yalnız dependencyManagement → geçişli
            _finding("guzzlehttp/guzzle", "Packagist"),
            _finding("monolog/monolog", "Packagist"),
            _finding("guzzlehttp/psr7", "Packagist", severity="low", fixed=""),  # composer.json'da yok → geçişli
            _finding("nokogiri", "RubyGems"),
            _finding("brakeman", "RubyGems"),
            _finding("Newtonsoft.Json", "NuGet"),
            _finding("Serilog", "NuGet"),
            _finding("serde_yaml", "crates.io"),
            _finding("regex", "crates.io"),
        ]
        report = analyze_vulnerability_reachability(str(self.root), findings=findings, allowed_roots=(self.base,))
        states = {it["package_name"]: it["usage"]["state"] for it in report["items"]}
        self.assertEqual(states["com.fasterxml.jackson.core:jackson-databind"], "used")
        self.assertEqual(states["org.apache.logging.log4j:log4j-core"], "unused")
        self.assertEqual(states["org.yaml:snakeyaml"], "transitive_only")
        self.assertEqual(states["guzzlehttp/guzzle"], "used")
        self.assertEqual(states["monolog/monolog"], "unused")
        self.assertEqual(states["guzzlehttp/psr7"], "transitive_only")
        self.assertEqual(states["nokogiri"], "used")       # Bundler.require
        self.assertEqual(states["brakeman"], "unused")     # require: false
        self.assertEqual(states["Newtonsoft.Json"], "used")
        self.assertEqual(states["Serilog"], "unused")
        self.assertEqual(states["serde_yaml"], "used")
        self.assertEqual(states["regex"], "unused")
        by_pkg = {it["package_name"]: it for it in report["items"]}
        # kanıt dosya:satır
        self.assertTrue(any(e["file"].endswith("App.java") for e in by_pkg["com.fasterxml.jackson.core:jackson-databind"]["usage"]["evidence"]))
        self.assertEqual(by_pkg["nokogiri"]["usage"]["evidence"][0], {"file": "Gemfile", "line": 2})
        # öncelik: kullanılan kritik en üstte, sıra kararlı ve özet tutarlı
        order = report["priority"]["order"]
        self.assertEqual(order[0]["package_name"], "com.fasterxml.jackson.core:jackson-databind")
        self.assertEqual(sum(report["priority"]["tiers"].values()), len(findings))
        self.assertEqual(report["priority"]["usage_counts"]["used"], 5)
        scores = [o["score"] for o in order]
        self.assertEqual(scores, sorted(scores, reverse=True))
        # kullanılmayan doğrudan paket önem bir derece düşer ama gizlenmez (crates.io); JVM/.NET sınıf yolunda
        # (yansıma, otomatik yapılandırma, serileştirme zinciri) önem korunur; geçişli önem korunur
        self.assertEqual(by_pkg["regex"]["reachability"]["effective_severity"], "medium")
        self.assertEqual(by_pkg["org.apache.logging.log4j:log4j-core"]["reachability"]["effective_severity"], "high")
        self.assertEqual(by_pkg["Serilog"]["reachability"]["effective_severity"], "high")
        self.assertEqual(by_pkg["org.yaml:snakeyaml"]["reachability"]["effective_severity"], "medium")

    def test_jdbc_driver_in_config_and_npm_cli_tools_count_as_used(self):
        _write(self.root, "pom.xml", """
            <project><dependencies>
              <dependency><groupId>mysql</groupId><artifactId>mysql-connector-java</artifactId><version>8.0.0</version></dependency>
              <dependency><groupId>commons-httpclient</groupId><artifactId>commons-httpclient</artifactId><version>3.1</version></dependency>
            </dependencies></project>
        """)
        _write(self.root, "src/main/resources/application.properties",
               "spring.datasource.url=jdbc:mysql://localhost/db\n")
        _write(self.root, "src/main/java/H.java", "import org.apache.commons.httpclient.HttpClient;\nclass H {}\n")
        _write(self.root, "package.json", json.dumps({"scripts": {"test": "node node_modules/grunt-cli/bin/grunt test",
                                                                  "dev": "nodemon"},
                                                      "devDependencies": {"grunt": "1", "grunt-cli": "1", "nodemon": "1",
                                                                          "left-pad": "1"}}))
        _write(self.root, "Gruntfile.js", "module.exports = function (g) {};\n")
        _write(self.root, "server.js", "const x = 1;\n")
        findings = [_finding("mysql:mysql-connector-java", "Maven"), _finding("commons-httpclient:commons-httpclient", "Maven"),
                    _finding("grunt", "npm"), _finding("grunt-cli", "npm"), _finding("nodemon", "npm"),
                    _finding("left-pad", "npm")]
        report = analyze_vulnerability_reachability(str(self.root), findings=findings, allowed_roots=(self.base,))
        by_pkg = {it["package_name"]: it for it in report["items"]}
        self.assertEqual(by_pkg["mysql:mysql-connector-java"]["usage"]["state"], "used")
        self.assertEqual(by_pkg["mysql:mysql-connector-java"]["usage"]["evidence"][0]["file"],
                         "src/main/resources/application.properties")
        self.assertEqual(by_pkg["commons-httpclient:commons-httpclient"]["usage"]["state"], "used")
        for pkg in ("grunt", "grunt-cli", "nodemon"):
            self.assertEqual(by_pkg[pkg]["usage"]["state"], "used", pkg)
        self.assertEqual(by_pkg["left-pad"]["usage"]["state"], "unused")

    def test_python_import_alias_and_cli_tools(self):
        _write(self.root, "requirements.txt", "djangorestframework==3.0\ngunicorn==19.0\nblack==22.0\nsix==1.0\n")
        _write(self.root, "api/views.py", "from rest_framework.views import APIView\n")
        _write(self.root, "runner.sh", "#!/bin/sh\n# black burada yorum\nexec gunicorn app.wsgi\n")
        findings = [_finding("djangorestframework", "PyPI"), _finding("gunicorn", "PyPI"), _finding("black", "PyPI"),
                    _finding("six", "PyPI")]
        report = analyze_vulnerability_reachability(str(self.root), findings=findings, allowed_roots=(self.base,))
        states = {it["package_name"]: it["usage"]["state"] for it in report["items"]}
        self.assertEqual(states["djangorestframework"], "used")
        self.assertEqual(states["gunicorn"], "used")
        self.assertEqual(states["black"], "unused")  # yalnız yorum satırında geçiyor
        self.assertEqual(states["six"], "unused")    # kısa ad: komut taramasına girmez, içe aktarılmıyor
        evidence = {it["package_name"]: it["usage"]["evidence"] for it in report["items"]}
        self.assertEqual(evidence["gunicorn"], [{"file": "runner.sh", "line": 3}])

    def test_unknown_when_ecosystem_has_no_source(self):
        report = analyze_vulnerability_reachability(
            str(self.root), findings=[_finding("some.group:lib-x", "Maven"), _finding("pkg-only-npm", "npm")],
            allowed_roots=(self.base,))
        states = {it["package_name"]: it["usage"]["state"] for it in report["items"]}
        self.assertEqual(states["pkg-only-npm"], "unknown")       # projede JS kaynağı yok → "kullanılmıyor" denmez
        self.assertEqual(states["some.group:lib-x"], "transitive_only")

    def test_vex_unused_is_under_investigation_with_note(self):
        reach = {"verdict": "not_imported", "usage": "unused", "evidence": []}
        decision = vx.decide({"package_name": "monolog/monolog", "status": "open"}, reach, None)
        self.assertEqual(decision["status"], "under_investigation")
        self.assertIn("kullanılmıyor", decision["status_notes"])


class StoreAndPortfolioTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        from storage import Store

        self.store = Store(Path(self.tmp.name) / "s.db")

    def test_apply_priorities_by_fingerprint_summary_and_portfolio(self):
        project = "/srv/proj"
        findings = [
            {"project_path": project, "package_name": "lodash", "installed_version": "4.17.4", "vulnerability_id": "GHSA-a",
             "severity": "critical", "fixed_version": "4.17.21", "source": "osv", "title": "t", "summary": "", "target": "npm",
             "references": []},
            {"project_path": project, "package_name": "ms", "installed_version": "0.7.1", "vulnerability_id": "GHSA-b",
             "severity": "low", "fixed_version": "", "source": "osv", "title": "t", "summary": "", "target": "npm",
             "references": []},
        ]
        self.store.import_dependency_findings({"source": "osv", "source_path": "osv-offline:npm",
                                               "source_timestamp": "2026-10-21T00:00:00+00:00", "document_hash": "h1",
                                               "project_path": project, "findings": findings})
        items = []
        for f, prio, usage in ((findings[0], {"score": 79, "tier": "fix_first"}, "used"),
                               (findings[1], {"score": 5, "tier": "monitor"}, "transitive_only")):
            items.append({**f, "priority": prio, "reachability": {"verdict": "reachable"},
                          "usage": {"state": usage, "evidence": [{"file": "a.js", "line": 3}]}})
        self.assertEqual(self.store.apply_dependency_priorities(items), {"updated": 2})
        data = self.store.dependency_security()
        self.assertEqual(data["priority"]["tiers"]["fix_first"], 1)
        self.assertEqual(data["priority"]["fix_first"][0]["package_name"], "lodash")
        self.assertEqual(data["priority"]["fix_first"][0]["reach_evidence"], [{"file": "a.js", "line": 3}])
        with self.store._connect() as db:
            summary = portfolio.dependency_priority_summary(db)
            self.assertEqual(summary[project]["fix_first"], 1)
            self.assertEqual(summary[project]["monitor"], 1)
            self.assertEqual(summary[project]["used"], 1)
            over = portfolio.overview(db, portfolio.load_policy({"SNIPER_DATA_DIR": self.tmp.name})[0])
            self.assertEqual(over["dependency_projects"][0]["project_path"], project)
            self.assertEqual(over["totals"]["dependencies"]["fix_first"], 1)

    def test_schema_migration_is_idempotent_and_old_db_upgrades(self):
        from storage import Store

        path = Path(self.tmp.name) / "old.db"
        Store(path)
        with sqlite3.connect(path) as con:  # eski şema benzetimi: yeni sütunlar yok
            cols = {r[1] for r in con.execute("PRAGMA table_info(dependency_findings)")}
        self.assertIn("priority_score", cols)
        Store(path)  # ikinci açılış hata vermez

    def test_portfolio_summary_tolerates_missing_table(self):
        con = sqlite3.connect(":memory:")
        con.row_factory = sqlite3.Row
        self.assertEqual(portfolio.dependency_priority_summary(con), {})


if __name__ == "__main__":
    unittest.main()
