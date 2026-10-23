"""20. tur: SBOM dışa aktarma (CycloneDX + SPDX 2.3, bağımlılık ilişkileri), dış SBOM okuma/tarama, VEX ve
yerel paket önbelleklerinden lisans."""
from __future__ import annotations

import json
import os
from http.server import ThreadingHTTPServer
from pathlib import Path
import tempfile
import threading
import unittest
from unittest import mock
from urllib.error import HTTPError
from urllib.request import Request, urlopen
import zipfile

import dependency_security
import license_compliance
import sbom_formats
import sbom_scan


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


NPM_V3 = {
    "lockfileVersion": 3,
    "packages": {
        "": {"name": "app", "dependencies": {"express": "^4", "lodash": "^4"}, "devDependencies": {"jest": "^29"}},
        "node_modules/express": {"version": "4.17.1", "dependencies": {"debug": "2.6.9", "qs": "6.7.0"}},
        "node_modules/debug": {"version": "2.6.9", "dependencies": {"ms": "2.0.0"}},
        "node_modules/ms": {"version": "2.0.0"},
        "node_modules/qs": {"version": "6.7.0"},
        "node_modules/lodash": {"version": "4.17.20", "license": "MIT"},
        "node_modules/jest": {"version": "29.0.0", "dev": True, "dependencies": {"ms": "^2.1"}},
        "node_modules/jest/node_modules/ms": {"version": "2.1.3", "dev": True},
    },
}


class DependencyGraphTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "proj"
        self.root.mkdir()

    def tearDown(self):
        self.temp.cleanup()

    def purl(self, eco, name, version):
        return dependency_security._package_url(eco, name, version)

    def test_npm_v3_nested_resolution_and_direct(self):
        _write(self.root / "package-lock.json", json.dumps(NPM_V3))
        comps = [{"ecosystem": "npm", "name": "x", "version": "1", "manifest": "package-lock.json"}]
        edges, direct, used = sbom_formats.dependency_graph(self.root, comps)
        self.assertEqual(used, ["package-lock.json"])
        self.assertIn(self.purl("npm", "express", "4.17.1"), direct)
        self.assertIn(self.purl("npm", "jest", "29.0.0"), direct)  # kökün geliştirme bağımlılığı
        self.assertEqual(edges[self.purl("npm", "debug", "2.6.9")], {self.purl("npm", "ms", "2.0.0")})
        # iç içe node_modules: jest kendi ms 2.1.3'üne bağlanır
        self.assertEqual(edges[self.purl("npm", "jest", "29.0.0")], {self.purl("npm", "ms", "2.1.3")})

    def test_npm_v1_cargo_poetry_composer_gemfile_gomod(self):
        _write(self.root / "a" / "package-lock.json", json.dumps({"lockfileVersion": 1, "dependencies": {
            "express": {"version": "4.0.0", "requires": {"qs": "^6"}, "dependencies": {"qs": {"version": "6.0.0"}}},
            "qs": {"version": "6.9.0"}}}))
        _write(self.root / "Cargo.lock", '[[package]]\nname = "app"\nversion = "0.1.0"\ndependencies = ["serde", "rand 0.8.5"]\n\n'
               '[[package]]\nname = "serde"\nversion = "1.0.0"\nsource = "registry+x"\n\n'
               '[[package]]\nname = "rand"\nversion = "0.8.5"\nsource = "registry+x"\ndependencies = ["serde"]\n')
        _write(self.root / "poetry.lock", '[[package]]\nname = "flask"\nversion = "2.0.0"\n[package.dependencies]\njinja2 = ">=3"\n\n'
               '[[package]]\nname = "jinja2"\nversion = "3.0.0"\n')
        _write(self.root / "composer.json", json.dumps({"require": {"slim/slim": "^4"}}))
        _write(self.root / "composer.lock", json.dumps({"packages": [
            {"name": "slim/slim", "version": "4.0.0", "require": {"psr/log": "^1", "php": ">=7"}},
            {"name": "psr/log", "version": "1.1.0"}]}))
        _write(self.root / "Gemfile.lock", "GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.0.0)\n"
               "      rack (>= 2)\n    rack (2.2.3)\n\nDEPENDENCIES\n  rails\n")
        _write(self.root / "go.mod", "module m\n\nrequire (\n\tgithub.com/a/b v1.0.0\n\tgithub.com/c/d v2.0.0 // indirect\n)\n")
        manifests = ["a/package-lock.json", "Cargo.lock", "poetry.lock", "composer.lock", "Gemfile.lock", "go.mod"]
        comps = [{"ecosystem": "x", "name": "x", "version": "1", "manifest": m} for m in manifests]
        edges, direct, used = sbom_formats.dependency_graph(self.root, comps)
        self.assertEqual(sorted(used), sorted(manifests))
        self.assertIn(self.purl("npm", "qs", "6.0.0"), edges[self.purl("npm", "express", "4.0.0")])  # iç kapsam önce
        self.assertIn(self.purl("cargo", "serde", "1.0.0"), direct)
        self.assertEqual(edges[self.purl("cargo", "rand", "0.8.5")], {self.purl("cargo", "serde", "1.0.0")})
        self.assertEqual(edges[self.purl("PyPI", "flask", "2.0.0")], {self.purl("PyPI", "jinja2", "3.0.0")})
        self.assertIn(self.purl("PyPI", "flask", "2.0.0"), direct)
        self.assertEqual(edges[self.purl("Packagist", "slim/slim", "4.0.0")], {self.purl("Packagist", "psr/log", "1.1.0")})
        self.assertIn(self.purl("Packagist", "slim/slim", "4.0.0"), direct)
        self.assertEqual(edges[self.purl("RubyGems", "rails", "7.0.0")], {self.purl("RubyGems", "rack", "2.2.3")})
        self.assertIn(self.purl("Golang", "github.com/a/b", "v1.0.0"), direct)
        self.assertNotIn(self.purl("Golang", "github.com/c/d", "v2.0.0"), direct)


class ExportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "proj"
        self.root.mkdir()
        _write(self.root / "package-lock.json", json.dumps(NPM_V3))
        _write(self.root / "requirements.txt", "flask==2.0.0\n")

    def tearDown(self):
        self.temp.cleanup()

    def test_cyclonedx_dependencies_and_spdx_are_valid_and_deterministic(self):
        doc = dependency_security.generate_cyclonedx_sbom(str(self.root), allowed_roots=(self.root.parent,))
        self.assertEqual(doc, dependency_security.generate_cyclonedx_sbom(str(self.root), allowed_roots=(self.root.parent,)))
        self.assertEqual(sbom_formats.validate_cyclonedx(doc), [])
        self.assertEqual(doc["metadata"]["tools"][0]["vendor"], "Sniper")
        root_entry = doc["dependencies"][0]
        self.assertEqual(root_entry["ref"], "sniper-root")
        express = self.purl = dependency_security._package_url("npm", "express", "4.17.1")
        self.assertIn(express, root_entry["dependsOn"])
        flask = dependency_security._package_url("PyPI", "flask", "2.0.0")
        self.assertIn(flask, root_entry["dependsOn"])  # ilişkisi bilinmeyen manifest köke bağlanır
        lodash = next(c for c in doc["components"] if c["name"] == "lodash")
        self.assertEqual(lodash["licenses"], [{"license": {"id": "MIT"}}])

        spdx = sbom_formats.cyclonedx_to_spdx(doc, created="2026-10-21T01:02:03+00:00", namespace_seed="x")
        self.assertEqual(sbom_formats.validate_spdx(spdx), [])
        self.assertEqual(spdx["creationInfo"]["created"], "2026-10-21T01:02:03Z")
        names = {p["name"] for p in spdx["packages"]}
        self.assertTrue({"express", "debug", "ms", "lodash", "flask", "proj"} <= names)
        lodash_pkg = next(p for p in spdx["packages"] if p["name"] == "lodash")
        self.assertEqual(lodash_pkg["licenseDeclared"], "MIT")
        self.assertEqual(lodash_pkg["externalRefs"][0]["referenceType"], "purl")
        depends = [r for r in spdx["relationships"] if r["relationshipType"] == "DEPENDS_ON"]
        self.assertGreaterEqual(len(depends), 6)
        self.assertEqual(spdx["relationships"][0]["relationshipType"], "DESCRIBES")

    def test_named_license_becomes_extracted_license_ref(self):
        cdx = {"bomFormat": "CycloneDX", "specVersion": "1.5", "metadata": {"component": {"name": "p"}},
               "components": [{"type": "library", "name": "a", "version": "1", "purl": "pkg:npm/a@1", "bom-ref": "pkg:npm/a@1",
                               "licenses": [{"license": {"name": "Özel Şirket Lisansı"}}]}]}
        spdx = sbom_formats.cyclonedx_to_spdx(cdx, created="2026-10-21T00:00:00Z")
        pkg = next(p for p in spdx["packages"] if p["name"] == "a")
        self.assertTrue(pkg["licenseDeclared"].startswith("LicenseRef-"))
        self.assertEqual(spdx["hasExtractedLicensingInfos"][0]["licenseId"], pkg["licenseDeclared"])
        self.assertEqual(sbom_formats.validate_spdx(spdx), [])

    def test_validators_catch_broken_documents(self):
        self.assertTrue(sbom_formats.validate_cyclonedx({"bomFormat": "X"}))
        bad = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [{"type": "library", "name": "a", "bom-ref": "r"}],
               "dependencies": [{"ref": "r", "dependsOn": ["yok"]}]}
        self.assertTrue(any("dependsOn" in e for e in sbom_formats.validate_cyclonedx(bad)))
        self.assertTrue(sbom_formats.validate_spdx({"spdxVersion": "SPDX-2.2"}))


CDX_XML = """<?xml version="1.0"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.5" version="1">
  <components>
    <component type="library"><group>org.apache.logging.log4j</group><name>log4j-core</name><version>2.14.1</version>
      <purl>pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1</purl>
      <licenses><license><id>Apache-2.0</id></license></licenses></component>
    <component type="library"><name>noname-purl</name><version>1</version></component>
  </components>
</bom>"""

SPDX_TAG = """SPDXVersion: SPDX-2.3
DataLicense: CC0-1.0
DocumentName: demo-app
PackageName: django
PackageVersion: 2.0.0
ExternalRef: PACKAGE-MANAGER purl pkg:pypi/django@2.0.0
PackageLicenseDeclared: BSD-3-Clause
PackageComment: <text>çok
satırlı PackageName: sahte</text>
PackageName: openssl
PackageVersion: 3.0.11-1~deb12u2
ExternalRef: PACKAGE-MANAGER purl pkg:deb/debian/openssl@3.0.11-1~deb12u2?arch=amd64&distro=debian-12
"""


class ParseTests(unittest.TestCase):
    def test_cyclonedx_json_nested_and_xml_and_spdx(self):
        cdx = {"bomFormat": "CycloneDX", "specVersion": "1.4", "metadata": {"component": {"name": "app"}},
               "components": [{"type": "library", "name": "a", "version": "1", "purl": "pkg:npm/a@1",
                               "components": [{"type": "library", "name": "b", "version": "2", "purl": "pkg:npm/b@2"}]}]}
        parsed = sbom_formats.parse_sbom_bytes(json.dumps(cdx).encode())
        self.assertEqual(parsed["format"], "cyclonedx-json")
        self.assertEqual([c["name"] for c in parsed["components"]], ["a", "b"])
        xml = sbom_formats.parse_sbom_bytes(CDX_XML.encode())
        self.assertEqual(xml["format"], "cyclonedx-xml")
        self.assertEqual(xml["spec_version"], "1.5")
        self.assertEqual(xml["components"][0]["license"], "Apache-2.0")
        tag = sbom_formats.parse_sbom_bytes(SPDX_TAG.encode())
        self.assertEqual(tag["name"], "demo-app")
        self.assertEqual([c["name"] for c in tag["components"]], ["django", "openssl"])  # <text> içi yok sayılır
        spdx = {"spdxVersion": "SPDX-2.3", "name": "d", "documentDescribes": ["SPDXRef-root"], "packages": [
            {"SPDXID": "SPDXRef-root", "name": "uygulama"},
            {"SPDXID": "SPDXRef-x", "name": "lodash", "versionInfo": "4.17.20", "licenseConcluded": "MIT",
             "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                               "referenceLocator": "pkg:npm/lodash@4.17.20"}]}]}
        parsed = sbom_formats.parse_sbom_bytes(json.dumps(spdx).encode())
        self.assertEqual([c["name"] for c in parsed["components"]], ["lodash"])  # kök paket atlanır

    def test_xml_entities_and_unknown_formats_rejected(self):
        evil = '<?xml version="1.0"?><!DOCTYPE bom [<!ENTITY x SYSTEM "file:///etc/passwd">]><bom>&x;</bom>'
        with self.assertRaises(sbom_formats.SbomError):
            sbom_formats.parse_sbom_bytes(evil.encode())
        for data in (b"merhaba", b'{"a": 1}', b"[1,2]"):
            with self.assertRaises(sbom_formats.SbomError):
                sbom_formats.parse_sbom_bytes(data)
        with mock.patch.object(sbom_formats, "MAX_SBOM_BYTES", 10):
            with self.assertRaises(sbom_formats.SbomError):
                sbom_formats.parse_sbom_bytes(b"{" + b" " * 20 + b"}")


def _osv_doc(name, version, eco, vid, fixed):
    return {"document": {"results": [{"source": {"path": "x", "type": "inventory"}, "packages": [{
        "package": {"name": name, "version": version, "ecosystem": eco},
        "vulnerabilities": [{"id": vid, "aliases": ["CVE-2021-44228"], "summary": "örnek",
                             "affected": [{"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fixed}]}]}]}],
    }]}]}, "coverage": [{"ecosystem": eco, "status": "ok"}], "skipped": {}, "warnings": [], "oldest_db_retrieved_utc": ""}


class ScanTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path.home())
        self.base = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_scan_language_and_os_components_tracking_and_vex(self):
        import container_scan
        import osv_offline
        from storage import Store

        sbom = _write(self.base / "bom.xml", CDX_XML)
        doc = _osv_doc("org.apache.logging.log4j:log4j-core", "2.14.1", "Maven", "GHSA-jfh8-c2jp-5v3q", "2.15.0")
        with mock.patch.object(osv_offline, "match_components", return_value=doc) as matcher:
            result = sbom_scan.scan_sbom(str(sbom), allowed_roots=(self.base,))
        components = matcher.call_args[0][0]
        self.assertEqual(components, [{"ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core", "version": "2.14.1"}])
        self.assertEqual(result["audit_kind"], "sbom")
        self.assertEqual(len(result["findings"]), 1)
        finding = result["findings"][0]
        self.assertEqual(finding["file"], "bom.xml")
        self.assertEqual(finding["fixed_version"], "2.15.0")
        self.assertEqual(result["sbom"]["unsupported"], {"purl_yok": 1})
        self.assertEqual(result["sbom"]["dependency_findings"][0]["vulnerability_id"], "GHSA-jfh8-c2jp-5v3q")

        vex = sbom_scan.vex_for_audit(result, "openvex")
        statements = vex["document"]["statements"]
        self.assertEqual(statements[0]["vulnerability"]["name"], "GHSA-jfh8-c2jp-5v3q")
        self.assertIn("CVE-2021-44228", json.dumps(vex["document"]))

        # İşletim sistemi paketi: distro niteleyicisi → Debian:12 dizini
        tag = _write(self.base / "bom.spdx", SPDX_TAG)
        seen = {}

        def fake_load(ecosystem, root=None):
            seen["eco"] = ecosystem
            return {}, {"retrieved_utc": "2026-10-21T00:00:00Z"}

        def fake_match(packages, index, package_type, ignore_unfixed=False):
            seen["packages"] = packages
            return [container_scan._finding(packages[0]["source"], packages[0]["source_version"], packages,
                                            {"id": "DSA-1", "aliases": [], "severity": "high", "summary": "s",
                                             "severity_source": "debian"}, "3.0.13-1~deb12u1")]

        empty = {"document": {"results": []}, "coverage": [], "skipped": {}, "warnings": [], "oldest_db_retrieved_utc": ""}
        with mock.patch.object(osv_offline, "match_components", return_value=empty), \
                mock.patch.object(container_scan, "load_index", side_effect=fake_load), \
                mock.patch.object(container_scan, "match_packages", side_effect=fake_match):
            os_result = sbom_scan.scan_sbom(str(tag), allowed_roots=(self.base,))
        self.assertEqual(seen["eco"], "Debian:12")
        self.assertEqual(seen["packages"][0]["name"], "openssl")
        self.assertEqual(os_result["project_name"], "demo-app")
        self.assertEqual(os_result["findings"][0]["category"], sbom_scan.CATEGORY)
        self.assertIn("(SBOM)", os_result["findings"][0]["title"])

        # Bulgu takibi: ikinci taramada açık kaybolursa "düzeldi"
        store = Store(self.base / "data" / "sniper.db")
        first = store.create_project_audit(result)
        clean = dict(result)
        clean["findings"] = []
        clean["sbom"] = dict(result["sbom"], dependency_findings=[])
        second = store.create_project_audit(clean)
        self.assertTrue(first["id"] and second["id"])
        tracked = store.get_project_audit(second["id"]).get("tracking") or {}
        self.assertEqual(tracked.get("fixed_count"), 1)
        self.assertEqual(tracked.get("not_rescanned_count"), 0)
        listed = next(a for a in store.list_project_audits() if a["id"] == first["id"])
        self.assertNotIn("dependency_findings", listed["sbom"])

    def test_path_rules(self):
        with self.assertRaises(sbom_scan.SbomScanError):
            sbom_scan.scan_sbom(str(self.base / "yok.json"), allowed_roots=(self.base,))
        outside = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        outside.write(b"{}")
        outside.close()
        self.addCleanup(os.unlink, outside.name)
        with self.assertRaises(sbom_scan.SbomScanError):
            sbom_scan.scan_sbom(outside.name, allowed_roots=(self.base,))
        real = _write(self.base / "real.json", "{}")
        link = self.base / "link.json"
        link.symlink_to(real)
        with self.assertRaises(sbom_scan.SbomScanError):
            sbom_scan.scan_sbom(str(link), allowed_roots=(self.base,))


class LicenseCacheTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.home = Path(self.temp.name) / "home"
        self.root = Path(self.temp.name) / "proj"
        self.root.mkdir(parents=True)
        self.env = mock.patch.dict(os.environ, {"SNIPER_LICENSE_CACHE_HOME": str(self.home)})
        self.env.start()
        os.environ.pop("GOMODCACHE", None)
        os.environ.pop("GEM_HOME", None)
        os.environ.pop("NUGET_PACKAGES", None)

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def test_caches_fill_missing_licenses(self):
        m2 = self.home / ".m2" / "repository"
        _write(m2 / "org/acme/lib/1.0/lib-1.0.pom",
               "<project><parent><groupId>org.acme</groupId><artifactId>parent</artifactId><version>3</version></parent></project>")
        _write(m2 / "org/acme/parent/3/parent-3.pom",
               "<project><licenses><license><name>Apache License, Version 2.0</name></license></licenses></project>")
        _write(self.home / ".cargo/registry/src/index.crates.io-1/serde-1.0.0/Cargo.toml",
               '[package]\nname = "serde"\nversion = "1.0.0"\nlicense = "MIT OR Apache-2.0"\n')
        _write(self.home / ".nuget/packages/newtonsoft.json/13.0.1/newtonsoft.json.nuspec",
               '<package><metadata><license type="expression">MIT</license></metadata></package>')
        zpath = self.home / "go/pkg/mod/cache/download/github.com/!acme/lib/@v/v1.2.0.zip"
        zpath.parent.mkdir(parents=True)
        with zipfile.ZipFile(zpath, "w") as zf:
            zf.writestr("github.com/Acme/lib@v1.2.0/LICENSE",
                        "Permission is hereby granted, free of charge, to any person obtaining a copy of this software "
                        "THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND MIT License")
        _write(self.home / ".gem/ruby/3.2.0/specifications/rack-2.2.3.gemspec", 's.licenses = ["MIT"]\n')
        comps = [
            {"ecosystem": "Maven", "name": "org.acme:lib", "version": "1.0", "manifest": "pom.xml"},
            {"ecosystem": "cargo", "name": "serde", "version": "1.0.0", "manifest": "Cargo.lock"},
            {"ecosystem": "NuGet", "name": "Newtonsoft.Json", "version": "13.0.1", "manifest": "a.csproj"},
            {"ecosystem": "Golang", "name": "github.com/Acme/lib", "version": "v1.2.0", "manifest": "go.mod"},
            {"ecosystem": "RubyGems", "name": "rack", "version": "2.2.3", "manifest": "Gemfile.lock"},
        ]
        items, _project, _exhausted = license_compliance.collect(self.root, [], comps)
        got = {(i["ecosystem"], i["name"]): i["expression"] for i in items}
        self.assertEqual(got[("Maven", "org.acme:lib")], "Apache-2.0")
        self.assertEqual(got[("cargo", "serde")], "MIT OR Apache-2.0")
        self.assertEqual(got[("NuGet", "Newtonsoft.Json")], "MIT")
        self.assertEqual(got[("RubyGems", "rack")], "MIT")
        self.assertIn(("Golang", "github.com/Acme/lib"), got)
        sources = {i["name"]: i["source"] for i in items}
        self.assertTrue(sources["org.acme:lib"].startswith("~/.m2/"))

    def test_disabled_caches_and_symlink_escape(self):
        secret = Path(self.temp.name) / "secret.pom"
        secret.write_text("<project><licenses><license><name>MIT</name></license></licenses></project>")
        target = self.home / ".m2" / "repository" / "org/acme/lib/1.0"
        target.mkdir(parents=True)
        (target / "lib-1.0.pom").symlink_to(secret)
        comps = [{"ecosystem": "Maven", "name": "org.acme:lib", "version": "1.0", "manifest": "pom.xml"}]
        items, _p, _e = license_compliance.collect(self.root, [], comps)
        self.assertEqual(items, [])  # önbellek kökü dışına çıkan sembolik bağ okunmaz
        with mock.patch.dict(os.environ, {"SNIPER_LICENSE_CACHE_HOME": ""}):
            secret_in = _write(self.home / ".m2/repository/org/b/c/1/c-1.pom",
                               "<project><licenses><license><name>MIT</name></license></licenses></project>")
            self.assertTrue(secret_in.is_file())
            items, _p, _e = license_compliance.collect(self.root, [], [{"ecosystem": "Maven", "name": "org.b:c", "version": "1"}])
            self.assertEqual(items, [])

    def test_project_parent_pom_and_subdir_composer(self):
        _write(self.root / "parent" / "pom.xml",
               "<project><licenses><license><name>MIT License</name></license></licenses></project>")
        _write(self.root / "pom.xml", "<project><parent><groupId>g</groupId><artifactId>p</artifactId><version>1</version>"
               "<relativePath>parent/pom.xml</relativePath></parent></project>")
        _write(self.root / "web" / "composer.lock", json.dumps({"packages": [{"name": "a/b", "version": "1.0", "license": ["MIT"]}]}))
        items, project, _e = license_compliance.collect(self.root, ["web/composer.lock"], None)
        self.assertEqual(project["expression"], "MIT")
        self.assertEqual(items[0]["source"], "web/composer.lock")


class ApiTests(unittest.TestCase):
    def setUp(self):
        import server
        from storage import Store

        self.server = server
        self.temp = tempfile.TemporaryDirectory(dir=Path.home())
        self.base = Path(self.temp.name)
        self.project = self.base / "project"
        _write(self.project / "requirements.txt", "flask==2.0.0\n")
        self.previous_store = server.STORE
        server.STORE = Store(self.base / "data" / "sniper.db")
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.SniperHandler)
        self.httpd.daemon_threads = True
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.base_url = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.server.STORE = self.previous_store
        self.temp.cleanup()

    def call(self, path, payload=None):
        body = None if payload is None else json.dumps(payload).encode()
        request = Request(self.base_url + path, data=body, method="GET" if payload is None else "POST",
                          headers={"Content-Type": "application/json"} if body else {})
        try:
            with urlopen(request, timeout=10) as response:
                return response.status, json.loads(response.read()), dict(response.headers)
        except HTTPError as exc:
            return exc.code, json.loads(exc.read() or b"{}"), {}

    def test_spdx_download_scan_and_vex_routes(self):
        status, sbom, _ = self.call("/api/dependency-security/sbom", {"project_path": str(self.project)})
        self.assertEqual(status, 201)
        status, spdx, headers = self.call(f"/api/dependency-sboms/{sbom['id']}?format=spdx")
        self.assertEqual(status, 200)
        self.assertEqual(spdx["spdxVersion"], "SPDX-2.3")
        self.assertEqual(sbom_formats.validate_spdx(spdx), [])
        self.assertIn("spdx.json", headers.get("Content-Disposition", ""))
        status, cdx, _ = self.call(f"/api/dependency-sboms/{sbom['id']}")
        self.assertTrue(cdx["metadata"]["timestamp"])
        self.assertEqual(self.call(f"/api/dependency-sboms/{sbom['id']}?format=xml")[0], 400)

        bom = _write(self.base / "bom.json", json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.5",
                                                          "components": [{"type": "library", "name": "flask", "version": "2.0.0",
                                                                          "purl": "pkg:pypi/flask@2.0.0"}]}))
        self.assertEqual(self.call("/api/dependency-security/sbom-scan", {"sbom_path": str(bom)})[0], 400)  # onaysız
        self.assertEqual(self.call("/api/dependency-security/sbom-scan", {"confirm": True})[0], 400)  # 22. tur QA: eksik sbom_path 500 değil 400
        import osv_offline
        doc = _osv_doc("flask", "2.0.0", "PyPI", "PYSEC-2023-62", "2.2.5")
        with mock.patch.object(sbom_scan, "validate_sbom_path", return_value=bom), \
                mock.patch.object(osv_offline, "match_components", return_value=doc):
            status, audit, _ = self.call("/api/dependency-security/sbom-scan", {"sbom_path": str(bom), "confirm": True})
        self.assertEqual(status, 201, audit)
        self.assertEqual(audit["audit_kind"], "sbom")
        status, vex, _ = self.call(f"/api/dependency-security/sbom-scans/{audit['id']}/vex?format=cyclonedx")
        self.assertEqual(status, 200)
        self.assertEqual(vex["bomFormat"], "CycloneDX")
        self.assertEqual(self.call("/api/dependency-security/sbom-scans/prj_000000000000/vex")[0], 404)


if __name__ == "__main__":
    unittest.main()
