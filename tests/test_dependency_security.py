import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from dependency_security import (
    DependencySecurityError,
    generate_cyclonedx_sbom,
    import_report,
    parse_osv,
    parse_trivy,
    query_osv_batch_via_tor,
)
from storage import Store


class DependencySecurityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path.home())
        self.base = Path(self.temp.name)
        self.project = self.base / "project"
        self.project.mkdir()
        self.allowed = (self.base.resolve(),)

    def tearDown(self):
        self.temp.cleanup()

    def test_native_cyclonedx_is_deterministic_and_schema_complete(self):
        (self.project / "requirements.txt").write_text("flask==3.1.0\nrequests>=2\n", encoding="utf-8")
        (self.project / "package-lock.json").write_text(json.dumps({
            "packages": {"node_modules/lodash": {"name": "lodash", "version": "4.17.20"}}
        }), encoding="utf-8")
        first = generate_cyclonedx_sbom(str(self.project), allowed_roots=self.allowed)
        second = generate_cyclonedx_sbom(str(self.project), allowed_roots=self.allowed)
        self.assertEqual(first, second)
        self.assertEqual(first["bomFormat"], "CycloneDX")
        self.assertEqual(first["specVersion"], "1.5")
        self.assertTrue(first["serialNumber"].startswith("urn:uuid:"))
        self.assertEqual([item["name"] for item in first["components"]], ["lodash", "flask", "requests"])
        flask = first["components"][1]
        self.assertEqual(flask["version"], "3.1.0")
        self.assertEqual(flask["purl"], "pkg:pypi/flask@3.1.0")

    def test_saved_sbom_delta_runtime_result(self):
        temp_dir = tempfile.TemporaryDirectory(dir=Path.home())
        base = Path(temp_dir.name)
        project = base / "myproj"
        project.mkdir()
        allowed = (base.resolve(),)
        
        # Build two deterministic CycloneDX documents
        doc1 = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": "urn:uuid:11111111-1111-1111-1111-111111111111",
            "components": [
                {"name": "requests", "version": "2.28.0", "purl": "pkg:pypi/requests@2.28.0"},
                {"name": "flask", "version": "2.0.0", "purl": "pkg:pypi/flask@2.0.0"},
                {"name": "numpy", "version": "1.24.0", "purl": "pkg:pypi/numpy@1.24.0"}
            ]
        }
        doc2 = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": "urn:uuid:22222222-2222-2222-2222-222222222222",
            "components": [
                {"name": "requests", "version": "2.28.1", "purl": "pkg:pypi/requests@2.28.1"},
                {"name": "flask", "version": "2.0.0", "purl": "pkg:pypi/flask@2.0.0"},
                {"name": "click", "version": "8.1.0", "purl": "pkg:pypi/click@8.1.0"}
            ]
        }

        store = Store(base / "sniper.db")
        # Save both documents
        saved1 = store.save_dependency_sbom(str(project), doc1)
        saved2 = store.save_dependency_sbom(str(project), doc2)

        # Test delta
        result = store.compare_dependency_sboms(saved1["id"], saved2["id"])
        self.assertIsNotNone(result)
        self.assertEqual(result["before_id"], saved1["id"])
        self.assertEqual(result["after_id"], saved2["id"])
        self.assertEqual(result["project_path"], str(project))
        # expected: requests 2.28.0->2.28.1 as changed; numpy 1.24.0 removed; click added
        self.assertEqual(result["summary"], {"added": 1, "removed": 1, "changed": 1})
        self.assertEqual(len(result["added"]), 1)
        self.assertEqual(len(result["removed"]), 1)
        self.assertEqual(len(result["changed"]), 1)

        changed = result["changed"][0]
        self.assertEqual(changed["name"], "requests")
        self.assertEqual(changed["from_version"], "2.28.0")
        self.assertEqual(changed["to_version"], "2.28.1")

        added = result["added"][0]
        self.assertEqual(added["name"], "click")
        self.assertEqual(added["version"], "8.1.0")

        removed = result["removed"][0]
        self.assertEqual(removed["name"], "numpy")
        self.assertEqual(removed["version"], "1.24.0")

        # Same ID returns empty differences
        same_result = store.compare_dependency_sboms(saved1["id"], saved1["id"])
        self.assertEqual(same_result["summary"], {"added": 0, "removed": 0, "changed": 0})

        # Missing ID
        missing_result = store.compare_dependency_sboms("unknown-id", saved1["id"])
        self.assertIsNone(missing_result)

        # Cross-project raises
        other_project = base / "other"
        other_project.mkdir()
        doc3 = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": "urn:uuid:33333333-3333-3333-3333-333333333333",
            "components": [{"name": "requests", "version": "2.28.0", "purl": "pkg:pypi/requests@2.28.0"}]
        }
        saved3 = store.save_dependency_sbom(str(other_project), doc3)
        with self.assertRaises(ValueError):
            store.compare_dependency_sboms(saved1["id"], saved3["id"])

        # Verify stored documents unchanged
        fresh1 = store.get_dependency_sbom(saved1["id"])
        fresh2 = store.get_dependency_sbom(saved2["id"])
        self.assertEqual(fresh1["document"], doc1)
        self.assertEqual(fresh2["document"], doc2)

        temp_dir.cleanup()

    def test_trivy_uses_package_fields_and_accepts_string_references(self):
        findings = parse_trivy({"Results": [{
            "Target": "requirements.txt",
            "Vulnerabilities": [{
                "VulnerabilityID": "CVE-2026-0001", "PkgName": "demo-lib",
                "InstalledVersion": "1.0", "FixedVersion": "1.2", "Severity": "HIGH",
                "Title": "Demo", "References": ["https://example.test/cve", {"url": "https://osv.dev/x"}],
            }],
        }]}, str(self.project))
        self.assertEqual(findings[0]["package_name"], "demo-lib")
        self.assertEqual(findings[0]["installed_version"], "1.0")
        self.assertEqual(findings[0]["fixed_version"], "1.2")
        self.assertEqual(findings[0]["references"], ["https://example.test/cve", "https://osv.dev/x"])

    def test_osv_scanner_schema_extracts_fixed_version(self):
        findings = parse_osv({"results": [{"packages": [{
            "package": {"name": "demo", "version": "1.0", "ecosystem": "PyPI"},
            "vulnerabilities": [{
                "id": "GHSA-demo", "summary": "Özet", "details": "Ayrıntı",
                "database_specific": {"severity": "MODERATE"},
                "affected": [{"ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.1"}]}]}],
                "references": [{"type": "ADVISORY", "url": "https://osv.dev/GHSA-demo"}],
            }],
        }]}]}, str(self.project))
        self.assertEqual(findings[0]["vulnerability_id"], "GHSA-demo")
        self.assertEqual(findings[0]["fixed_version"], "1.1")
        self.assertEqual(findings[0]["severity"], "unknown")

    def test_import_rejects_malformed_and_oversized_reports(self):
        (self.project / "requirements.txt").write_text("demo==1.0\n", encoding="utf-8")
        malformed = self.base / "bad.json"
        malformed.write_text("{not-json", encoding="utf-8")
        with self.assertRaisesRegex(DependencySecurityError, "geçerli UTF-8 JSON"):
            import_report(str(malformed), str(self.project), allowed_roots=self.allowed)
        oversized = self.base / "large.json"
        with oversized.open("wb") as handle:
            handle.truncate(8_000_001)
        with self.assertRaisesRegex(DependencySecurityError, "8 MB"):
            import_report(str(oversized), str(self.project), allowed_roots=self.allowed)

    def test_import_persists_across_store_instances_and_preserves_lifecycle(self):
        (self.project / "requirements.txt").write_text("demo==1.0\n", encoding="utf-8")
        report_path = self.base / "trivy.json"
        report_path.write_text(json.dumps({"Results": [{"Target": "requirements.txt", "Vulnerabilities": [{
            "VulnerabilityID": "CVE-2026-0002", "PkgName": "demo", "InstalledVersion": "1.0",
            "FixedVersion": "1.1", "Severity": "CRITICAL", "References": ["https://example.test/2"],
        }]}]}), encoding="utf-8")
        report = import_report(str(report_path), str(self.project), allowed_roots=self.allowed)
        db_path = self.base / "data" / "sniper.db"
        first_store = Store(db_path)
        imported = first_store.import_dependency_findings(report)
        finding = first_store.dependency_security()["findings"][0]
        first_store.update_dependency_finding(finding["id"], status="in_progress", resolution_notes="1.1 hazırlanıyor")
        second_store = Store(db_path)
        persisted = second_store.dependency_security()["findings"][0]
        self.assertEqual(persisted["status"], "in_progress")
        self.assertEqual(persisted["resolution_notes"], "1.1 hazırlanıyor")
        duplicate = second_store.import_dependency_findings(report)
        self.assertTrue(duplicate["deduplicated"])
        self.assertEqual(imported["id"], duplicate["id"])
        self.assertEqual(len(second_store.dependency_security()["findings"]), 1)

    @patch("dependency_security.subprocess.run")
    @patch("dependency_security.socket.create_connection")
    def test_online_osv_requires_local_tor_and_posts_querybatch(self, connect, run):
        connect.return_value.__enter__ = MagicMock()
        connect.return_value.__exit__ = MagicMock(return_value=False)
        run.return_value = MagicMock(returncode=0, stdout='{"results":[{"vulns":[]}]}', stderr="")
        result = query_osv_batch_via_tor([{"name": "demo", "version": "1.0", "ecosystem": "PyPI"}])
        self.assertEqual(result, {"results": [{"vulns": []}]})
        command = run.call_args.args[0]
        self.assertIn("socks5h://127.0.0.1:9050", command)
        self.assertEqual(command[1], "--disable")
        self.assertEqual(command[command.index("--data-binary") + 1], "@-")
        payload = json.loads(run.call_args.kwargs["input"])
        self.assertEqual(payload["queries"][0]["package"]["name"], "demo")
        self.assertEqual(payload["queries"][0]["version"], "1.0")
        with self.assertRaisesRegex(DependencySecurityError, "yalnızca yerel Tor"):
            query_osv_batch_via_tor([], proxy="http://127.0.0.1:8080")

    @patch("dependency_security.subprocess.run")
    @patch("dependency_security.socket.create_connection")
    def test_online_osv_large_batch_payload_stays_off_argv(self, connect, run):
        connect.return_value.__enter__ = MagicMock()
        connect.return_value.__exit__ = MagicMock(return_value=False)
        components = [{"name": "p" * 200 + str(i), "version": "1." + str(i), "ecosystem": "npm"} for i in range(1000)]
        run.return_value = MagicMock(returncode=0, stdout=json.dumps({"results": [{} for _ in components]}), stderr="")
        result = query_osv_batch_via_tor(components)
        self.assertEqual(len(result["results"]), 1000)
        command = run.call_args.args[0]
        self.assertLess(sum(len(part) for part in command), 1000)
        self.assertEqual(len(json.loads(run.call_args.kwargs["input"])["queries"]), 1000)

    def test_multilang_native_cyclonedx_extracts_all_ecosystems_and_purls(self):
        (self.project / "go.mod").write_text(
            "module example.com/app\n\ngo 1.22\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.1\n)\nrequire golang.org/x/crypto v0.21.0\n",
            encoding="utf-8",
        )
        (self.project / "Cargo.lock").write_text(
            '[[package]]\nname = "serde"\nversion = "1.0.197"\n',
            encoding="utf-8",
        )
        (self.project / "pnpm-lock.yaml").write_text(
            "lockfileVersion: '6.0'\npackages:\n  /axios@1.6.8:\n    resolution: {integrity: sha512-x}\n",
            encoding="utf-8",
        )
        (self.project / "yarn.lock").write_text(
            '"chalk@^5.0.0":\n  version "5.3.0"\n',
            encoding="utf-8",
        )
        (self.project / "pom.xml").write_text(
            "<project><dependencies><dependency>"
            "<groupId>org.springframework</groupId>"
            "<artifactId>spring-core</artifactId>"
            "<version>6.1.5</version>"
            "</dependency></dependencies></project>",
            encoding="utf-8",
        )
        (self.project / "Gemfile.lock").write_text(
            "GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (3.0.9)\n      other (= 1.0.0)\n",
            encoding="utf-8",
        )
        (self.project / "composer.lock").write_text(
            json.dumps({
                "packages": [{"name": "monolog/monolog", "version": "v3.5.0"}],
                "packages-dev": [{"name": "phpunit/phpunit", "version": "10.5.0"}],
            }),
            encoding="utf-8",
        )
        (self.project / "pubspec.lock").write_text(
            'packages:\n  http:\n    dependency: "direct main"\n    version: "1.2.1"\n',
            encoding="utf-8",
        )

        sbom = generate_cyclonedx_sbom(str(self.project), allowed_roots=self.allowed)
        purls = {item["purl"] for item in sbom["components"]}
        self.assertIn("pkg:golang/github.com/gin-gonic/gin@1.9.1", purls)
        self.assertIn("pkg:golang/golang.org/x/crypto@0.21.0", purls)
        self.assertIn("pkg:cargo/serde@1.0.197", purls)
        self.assertIn("pkg:npm/axios@1.6.8", purls)
        self.assertIn("pkg:npm/chalk@5.3.0", purls)
        self.assertIn("pkg:maven/org.springframework:spring-core@6.1.5", purls)
        self.assertIn("pkg:gem/rack@3.0.9", purls)
        self.assertIn("pkg:composer/monolog/monolog@3.5.0", purls)
        self.assertIn("pkg:composer/phpunit/phpunit@10.5.0", purls)
        self.assertIn("pkg:pub/http@1.2.1", purls)

        # Verify XXE / DOCTYPE rejection in pom.xml
        (self.project / "pom.xml").write_text(
            "<!DOCTYPE project [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><project/>",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(DependencySecurityError, "DTD/ENTITY"):
            generate_cyclonedx_sbom(str(self.project), allowed_roots=self.allowed)

    def test_openapi_and_graphql_contract_auditor(self):
        from openapi_contract_auditor import audit_api_contract, audit_project_api_contracts

        openapi_doc = {
            "openapi": "3.0.3",
            "info": {"title": "Demo API", "version": "1.0.0"},
            "servers": [{"url": "http://api.example.com/v1"}],
            "paths": {
                "/users/{user_id}": {
                    "post": {
                        "security": [],
                        "parameters": [
                            {"name": "user_id", "in": "path", "required": True, "schema": {"type": "string"}},
                            {"name": "tags", "in": "query", "schema": {"type": "array", "items": {"type": "string"}}},
                        ],
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {"username": {"type": "string", "maxLength": 64}},
                                    }
                                }
                            }
                        },
                        "responses": {
                            "200": {
                                "description": "OK",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {
                                                "id": {"type": "string"},
                                                "password": {"type": "string"},
                                                "api_key": {"type": "string"},
                                            },
                                        }
                                    }
                                },
                            }
                        },
                    }
                }
            },
        }
        oa_result = audit_api_contract(json.dumps(openapi_doc), source_name="openapi.json")
        self.assertEqual(oa_result["format"], "sniper-api-contract-audit-v1")
        self.assertEqual(oa_result["contract_type"], "openapi3")
        oa_rules = {f["rule_id"] for f in oa_result["findings"]}
        self.assertIn("SNIPER-CRYP-02", oa_rules)
        self.assertIn("SNIPER-APIT-02", oa_rules)
        self.assertIn("SNIPER-APIT-03", oa_rules)
        self.assertIn("SNIPER-APIT-05", oa_rules)
        self.assertIn("SNIPER-APIT-09", oa_rules)

        gql_sdl = """
        type Query {
            user(id: ID!): User
        }
        type Mutation {
            deleteUser(id: ID!): Boolean
            updateProfile(name: String!): User @auth
        }
        type User {
            id: ID!
            passwordHash: String
            friends: [User!]!
        }
        """
        gql_result = audit_api_contract(gql_sdl, source_name="schema.graphql")
        self.assertEqual(gql_result["contract_type"], "graphql")
        gql_rules = {f["rule_id"] for f in gql_result["findings"]}
        self.assertEqual(gql_rules, {"SNIPER-APIT-02", "SNIPER-APIT-06", "SNIPER-APIT-09"})

        (self.project / "openapi.json").write_text(json.dumps(openapi_doc), encoding="utf-8")
        (self.project / "schema.graphql").write_text(gql_sdl, encoding="utf-8")
        proj_audit = audit_project_api_contracts(str(self.project), allowed_roots=self.allowed)
        self.assertEqual(proj_audit["contracts_audited"], 2)
        self.assertGreaterEqual(proj_audit["finding_count"], 8)

    def test_vulnerability_reachability_analyzer(self):
        from dependency_security import analyze_vulnerability_reachability

        (self.project / "requirements.txt").write_text(
            "pyyaml==6.0.1\nrequests==2.31.0\nurllib3==2.0.7\n",
            encoding="utf-8",
        )
        (self.project / "app.py").write_text(
            "import yaml\nfrom requests import Session\n",
            encoding="utf-8",
        )
        findings = [
            {"package_name": "pyyaml", "vulnerability_id": "CVE-2026-1001", "severity": "high"},
            {"package_name": "requests", "vulnerability_id": "CVE-2026-1002", "severity": "medium"},
            {"package_name": "urllib3", "vulnerability_id": "CVE-2026-1003", "severity": "low"},
        ]
        report = analyze_vulnerability_reachability(
            str(self.project),
            findings=findings,
            allowed_roots=self.allowed,
        )
        self.assertEqual(report["format"], "sniper-vulnerability-reachability-v1")
        self.assertEqual(report["scanned_source_files"], 1)
        self.assertEqual(report["total_evaluated"], 3)
        self.assertEqual(report["reachable_count"], 2)
        self.assertEqual(report["transitive_only_count"], 1)
        by_pkg = {item["package_name"]: item for item in report["items"]}
        self.assertTrue(by_pkg["pyyaml"]["reachable"])
        self.assertEqual(by_pkg["pyyaml"]["reachability_status"], "reachable_in_source")
        self.assertEqual(by_pkg["pyyaml"]["call_sites"][0], {"file": "app.py", "line": 1})
        self.assertTrue(by_pkg["requests"]["reachable"])
        self.assertFalse(by_pkg["urllib3"]["reachable"])
        self.assertEqual(by_pkg["urllib3"]["reachability_status"], "not_imported_in_source")

    def test_audit_chain_verifier_and_provenance_envelope(self):
        from audit_chain_verifier import (
            GENESIS_HASH,
            build_signed_provenance_envelope,
            verify_audit_log_chain,
        )

        events = [
            {"id": 2, "occurred_at": "2026-10-18T12:01:00Z", "action": "sbom_saved", "entity_id": "sbom-1", "details": {"count": 4}},
            {"id": 1, "occurred_at": "2026-10-18T12:00:00Z", "action": "scan_started", "entity_id": "scan-1", "details": {"target": "local"}},
        ]
        chain = verify_audit_log_chain(events)
        self.assertEqual(chain["format"], "sniper-audit-chain-verification-v1")
        self.assertTrue(chain["verified"])
        self.assertEqual(chain["event_count"], 2)
        self.assertEqual(chain["genesis_hash"], GENESIS_HASH)
        self.assertNotEqual(chain["head_hash"], GENESIS_HASH)
        self.assertEqual([e["id"] for e in chain["chain_tail"]], [1, 2])

        # Verify tamper detection when recorded entry_hash does not match
        tampered_events = [
            dict(events[1], entry_hash="f" * 64),
            dict(events[0]),
        ]
        tampered_chain = verify_audit_log_chain(tampered_events)
        self.assertFalse(tampered_chain["verified"])
        self.assertIn(1, tampered_chain["tampered_ids"])

        envelope = build_signed_provenance_envelope(
            {"report": "demo", "findings": 2},
            audit_head_hash=chain["head_hash"],
            scope_label="sbom-export",
        )
        self.assertEqual(envelope["format"], "sniper-provenance-envelope-v1")
        self.assertEqual(envelope["scope_label"], "sbom-export")
        self.assertEqual(envelope["audit_head_hash"], chain["head_hash"])
        self.assertEqual(len(envelope["payload_sha256"]), 64)
        self.assertEqual(len(envelope["envelope_sha256"]), 64)

    def test_mobile_gradle_cocoapods_swiftpm_sbom_and_reachability(self):
        from dependency_security import analyze_vulnerability_reachability

        (self.project / "gradle.lockfile").write_text(
            "# Gradle lockfile\ncom.squareup.okhttp3:okhttp:4.12.0=compileClasspath,runtimeClasspath\nempty=\n",
            encoding="utf-8",
        )
        (self.project / "build.gradle.kts").write_text(
            'dependencies {\n    implementation("io.coil-kt:coil:2.6.0")\n}\n',
            encoding="utf-8",
        )
        (self.project / "Podfile.lock").write_text(
            "PODS:\n  - Alamofire (5.9.1):\n    - Alamofire/Core (= 5.9.1)\n  - SDWebImage (5.19.0)\n\nDEPENDENCIES:\n  - Alamofire\n",
            encoding="utf-8",
        )
        (self.project / "Package.resolved").write_text(
            json.dumps({
                "pins": [
                    {
                        "identity": "swift-crypto",
                        "location": "https://github.com/apple/swift-crypto.git",
                        "state": {"revision": "abc", "version": "3.3.0"},
                    }
                ],
                "version": 2,
            }),
            encoding="utf-8",
        )

        sbom = generate_cyclonedx_sbom(str(self.project), allowed_roots=self.allowed)
        purls = {item["purl"] for item in sbom["components"]}
        self.assertIn("pkg:maven/com.squareup.okhttp3:okhttp@4.12.0", purls)
        self.assertIn("pkg:maven/io.coil-kt:coil@2.6.0", purls)
        self.assertIn("pkg:cocoapods/Alamofire@5.9.1", purls)
        self.assertIn("pkg:cocoapods/SDWebImage@5.19.0", purls)
        self.assertIn("pkg:swift/swift-crypto@3.3.0", purls)

        (self.project / "MainActivity.kt").write_text(
            "package com.example.app\nimport okhttp3.OkHttpClient\n",
            encoding="utf-8",
        )
        (self.project / "NetworkManager.swift").write_text(
            "@testable import Alamofire\n",
            encoding="utf-8",
        )
        (self.project / "Bridge.m").write_text(
            "#import <SDWebImage/UIImageView+WebCache.h>\n",
            encoding="utf-8",
        )
        (self.project / "main.dart").write_text(
            "import 'package:http/http.dart' as http;\n",
            encoding="utf-8",
        )

        mobile_findings = [
            {"package_name": "com.squareup.okhttp3:okhttp", "vulnerability_id": "CVE-2026-2001", "severity": "high"},
            {"package_name": "io.coil-kt:coil", "vulnerability_id": "CVE-2026-2002", "severity": "low"},
            {"package_name": "Alamofire", "vulnerability_id": "CVE-2026-2003", "severity": "medium"},
            {"package_name": "SDWebImage", "vulnerability_id": "CVE-2026-2004", "severity": "medium"},
            {"package_name": "http", "vulnerability_id": "CVE-2026-2005", "severity": "low"},
        ]
        reach = analyze_vulnerability_reachability(
            str(self.project),
            findings=mobile_findings,
            allowed_roots=self.allowed,
        )
        by_pkg = {item["package_name"]: item for item in reach["items"]}
        self.assertTrue(by_pkg["com.squareup.okhttp3:okhttp"]["reachable"])
        self.assertFalse(by_pkg["io.coil-kt:coil"]["reachable"])
        self.assertTrue(by_pkg["Alamofire"]["reachable"])
        self.assertTrue(by_pkg["SDWebImage"]["reachable"])
        self.assertTrue(by_pkg["http"]["reachable"])


if __name__ == "__main__":
    unittest.main()


