import hashlib
import json
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import server
from scanner import normalize_target
from storage import Store


class KalanIslerHttpContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path.home())
        self.base = Path(self.temp.name)
        self.previous_store = server.STORE
        server.STORE = Store(self.base / "data" / "sniper.db")
        if hasattr(server, "LIMITER") and hasattr(server.LIMITER, "_events"):
            server.LIMITER._events.clear()
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.SniperHandler)
        self.httpd.daemon_threads = True
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)
        server.STORE = self.previous_store
        self.temp.cleanup()

    def post_json(self, path: str, payload: dict) -> tuple[int, dict]:
        body = json.dumps(payload).encode("utf-8")
        req = Request(
            self.base_url + path,
            data=body,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with urlopen(req, timeout=5) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except HTTPError as err:
            try:
                return err.code, json.loads(err.read().decode("utf-8"))
            finally:
                err.close()

    def get_json(self, path: str) -> tuple[int, dict]:
        req = Request(self.base_url + path, method="GET")
        try:
            with urlopen(req, timeout=5) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except HTTPError as err:
            try:
                return err.code, json.loads(err.read().decode("utf-8"))
            finally:
                err.close()

    def test_nmap_tcp_scan_service_version_http_contract(self):
        target = server.STORE.create_target(normalize_target("https://example.com"))
        engagement = server.STORE.create_engagement(
            target_id=target["id"],
            name="nmap-sv-test",
            authorization_ref="AUTH-SV-1",
            scope_notes="authorized scope",
            out_of_scope="",
            test_window="",
            special_approvals={},
        )
        mock_result = {
            "target_id": target["id"],
            "engagement_id": engagement["id"],
            "profile": "bounded-tcp-connect-v1",
            "host_count": 1,
            "up_host_count": 1,
            "open_port_count": 1,
            "open_ports": [22],
            "report_sha256": hashlib.sha256(b"nmap-sv").hexdigest(),
            "service_version_enabled": True,
            "service_versions": [
                {
                    "port": 22,
                    "protocol": "tcp",
                    "state": "open",
                    "service": "ssh",
                    "product": "OpenSSH",
                    "version": "9.6",
                }
            ],
        }

        with patch("server.run_bounded_tcp_connect_scan", return_value=mock_result) as scan_mock:
            status, body = self.post_json(
                "/api/nmap/tcp-scan",
                {
                    "target_id": target["id"],
                    "engagement_id": engagement["id"],
                    "confirm_authorized": True,
                    "service_version": True,
                },
            )
            self.assertEqual(status, 200)
            self.assertIs(body.get("service_version_enabled"), True)
            self.assertEqual(body["service_versions"][0]["product"], "OpenSSH")
            scan_mock.assert_called_once_with(
                target_id=target["id"],
                engagement_id=engagement["id"],
                hostname=target["hostname"],
                port=int(target["port"]),
                service_version=True,
            )

        with patch("server.run_bounded_tcp_connect_scan") as scan_mock:
            status, body = self.post_json(
                "/api/nmap/tcp-scan",
                {
                    "target_id": target["id"],
                    "engagement_id": engagement["id"],
                    "confirm_authorized": True,
                    "service_version": "invalid",
                },
            )
            self.assertEqual(status, 400)
            self.assertIn("error", body)
            scan_mock.assert_not_called()

    def test_nuclei_verification_coverage_http_contract(self):
        jsonl_line = json.dumps(
            {
                "template-id": "http/misconfiguration/test-header",
                "type": "http",
                "info": {"name": "Test Header", "severity": "low"},
            }
        )
        status, body = self.post_json(
            "/api/tool-reports/nuclei/verification-coverage",
            {
                "report": jsonl_line + "\n",
                "executed_template_ids": [
                    "http/misconfiguration/test-header",
                    "http/exposures/unmatched-check",
                ],
            },
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["finding_count"], 1)
        self.assertEqual(body["unverified_finding_count"], 1)
        self.assertEqual(body["executed_template_count"], 2)
        self.assertEqual(body["unmatched_executed_template_count"], 1)
        self.assertEqual(body["coverage_scope"], "bounded_template_subset_only")
        self.assertEqual(
            body["findings"][0]["verification_state"],
            "independent_confirmation_required",
        )

        bad_status, bad_body = self.post_json(
            "/api/tool-reports/nuclei/verification-coverage",
            {
                "report": jsonl_line,
                "executed_template_ids": ["../traversal-template"],
            },
        )
        self.assertEqual(bad_status, 400)
        self.assertIn("error", bad_body)

    def test_burp_sitemap_handoff_manifest_http_contract(self):
        sitemap_xml = (
            "<items>"
            "<item>"
            "<url>https://example.com/api/items?id=1</url>"
            "<host>example.com</host>"
            "<method>GET</method>"
            "<status>200</status>"
            "<mimetype>JSON</mimetype>"
            "</item>"
            "</items>"
        )
        status, body = self.post_json(
            "/api/tool-reports/burp-sitemap/handoff-manifest",
            {
                "report": sitemap_xml,
                "allowed_host": "example.com",
            },
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["format"], "burp-manual-handoff-v1")
        self.assertEqual(body["automation_mode"], "manual_operator_guided_only")
        self.assertEqual(body["in_scope_endpoint_count"], 1)
        self.assertEqual(body["parameterized_endpoint_count"], 1)
        self.assertIn("manifest_sha256", body)

        bad_status, bad_body = self.post_json(
            "/api/tool-reports/burp-sitemap/handoff-manifest",
            {
                "report": sitemap_xml,
                "allowed_host": "other.example.org",
            },
        )
        self.assertEqual(bad_status, 400)
        self.assertIn("error", bad_body)

    def test_dependencies_remediation_plan_http_contract(self):
        npm_report = json.dumps(
            {
                "auditReportVersion": 2,
                "vulnerabilities": {
                    "lodash": {
                        "name": "lodash",
                        "severity": "high",
                        "fixAvailable": True,
                    }
                },
            }
        )
        dependabot_report = json.dumps(
            {
                "alerts": [
                    {
                        "state": "open",
                        "dependency": {"package": {"name": "urllib3", "ecosystem": "pip"}},
                        "security_advisory": {"severity": "critical"},
                        "security_vulnerability": {
                            "package": {"name": "urllib3", "ecosystem": "pip"},
                            "first_patched_version": None,
                        },
                    }
                ]
            }
        )
        status, body = self.post_json(
            "/api/tool-reports/dependencies/remediation-plan",
            {
                "npm_audit_report": npm_report,
                "dependabot_report": dependabot_report,
            },
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["format"], "dependency-remediation-plan-v1")
        self.assertIs(body["mutates_lockfile"], False)
        self.assertEqual(body["network_sync"], "offline_saved_reports_only")
        self.assertEqual(body["total_advisories"], 2)
        self.assertEqual(len(body["package_actions"]), 2)
        self.assertIn("plan_sha256", body)

        bad_status, bad_body = self.post_json(
            "/api/tool-reports/dependencies/remediation-plan",
            {},
        )
        self.assertEqual(bad_status, 400)
        self.assertIn("error", bad_body)

    def test_secret_bundle_validate_http_contract(self):
        status, body = self.post_json(
            "/api/tool-runs/secret-bundle/validate",
            {
                "files": [
                    {
                        "relative_path": "src/settings.py",
                        "content": "API_TOKEN = 'redacted-placeholder'\n",
                    }
                ]
            },
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["format"], "secret-scan-bundle-manifest-v1")
        self.assertEqual(body["scope"], "explicit_in_memory_bundle_only")
        self.assertEqual(body["file_count"], 1)
        self.assertIn("bundle_sha256", body)

        bad_status, bad_body = self.post_json(
            "/api/tool-runs/secret-bundle/validate",
            {
                "files": [
                    {
                        "relative_path": "../etc/passwd",
                        "content": "root:x:0:0",
                    }
                ]
            },
        )
        self.assertEqual(bad_status, 400)
        self.assertIn("error", bad_body)

    def test_tls_trivy_boundary_verify_http_contract_all_modes(self):
        ssllabs_report = json.dumps(
            {
                "status": "READY",
                "endpoints": [{"grade": "A"}],
            }
        )
        status, body = self.post_json(
            "/api/tool-reports/tls-trivy/boundary-verify",
            {
                "mode": "ssllabs-saved-report",
                "report": ssllabs_report,
            },
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["mode"], "ssllabs-saved-report")
        self.assertEqual(body["execution_policy"], "offline_saved_report_only")
        self.assertIs(body["live_query_allowed"], False)

        bad_ssllabs_status, _ = self.post_json(
            "/api/tool-reports/tls-trivy/boundary-verify",
            {
                "mode": "ssllabs-saved-report",
                "target": "https://example.com",
                "report": ssllabs_report,
            },
        )
        self.assertEqual(bad_ssllabs_status, 400)

        loopback_status, loopback_body = self.post_json(
            "/api/tool-reports/tls-trivy/boundary-verify",
            {
                "mode": "testssl-loopback",
                "target": "127.0.0.1:8443",
            },
        )
        self.assertEqual(loopback_status, 200)
        self.assertEqual(loopback_body["mode"], "testssl-loopback")
        self.assertEqual(loopback_body["execution_policy"], "loopback_only")
        self.assertIs(loopback_body["external_https_allowed"], False)

        bad_loopback_status, _ = self.post_json(
            "/api/tool-reports/tls-trivy/boundary-verify",
            {
                "mode": "testssl-loopback",
                "target": "https://example.com:443",
            },
        )
        self.assertEqual(bad_loopback_status, 400)

        trivy_meta = json.dumps(
            {
                "Version": 2,
                "UpdatedAt": "2026-10-16T00:00:00Z",
                "NextUpdate": "2026-10-17T00:00:00Z",
            }
        )
        trivy_status, trivy_body = self.post_json(
            "/api/tool-reports/tls-trivy/boundary-verify",
            {
                "mode": "trivy-db-freshness",
                "metadata_json": trivy_meta,
                "reference_utc": "2026-10-17T12:00:00Z",
                "max_age_hours": 72,
            },
        )
        self.assertEqual(trivy_status, 200)
        self.assertEqual(trivy_body["format"], "trivy-db-freshness-v1")
        self.assertIs(trivy_body["is_fresh"], True)
        self.assertEqual(trivy_body["freshness_state"], "fresh")

        bad_trivy_status, _ = self.post_json(
            "/api/tool-reports/tls-trivy/boundary-verify",
            {
                "mode": "trivy-db-freshness",
                "metadata_json": trivy_meta,
                "reference_utc": "2026-10-15T00:00:00Z",
            },
        )
        self.assertEqual(bad_trivy_status, 400)

    def test_web_infra_dns_and_discovery_http_contracts(self):
        status, body = self.post_json(
            "/api/web-infra/dns-email-audit",
            {
                "hostname": "example.com",
                "txt_records": ["v=spf1 +all", "v=DMARC1; p=none"],
                "caa_records": [],
                "cname_target": "legacy-app.herokuapp.com",
            },
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["format"], "sniper-dns-email-security-v1")
        self.assertGreaterEqual(body["finding_count"], 3)

        disc_status, disc_body = self.post_json(
            "/api/web-infra/discovery-audit",
            {
                "target_url": "https://example.com",
                "robots_txt": "User-agent: *\nDisallow: /.env\nDisallow: /admin\n",
                "openid_config": {
                    "issuer": "http://example.com",
                    "response_types_supported": ["code", "token"],
                    "id_token_signing_alg_values_supported": ["RS256", "none"],
                },
                "jwks_doc": {"keys": [{"kty": "RSA", "kid": "1", "d": "leaked-private-exponent"}]},
                "graphql_response": {"data": {"__schema": {"types": []}}},
                "response_headers": {"Cross-Origin-Opener-Policy": "unsafe-none"},
            },
        )
        self.assertEqual(disc_status, 200)
        self.assertEqual(disc_body["format"], "sniper-web-discovery-deep-audit-v1")
        self.assertGreaterEqual(disc_body["finding_count"], 4)

    def test_openapi_security_and_auto_evidence_sync_http_contracts(self):
        contract = json.dumps(
            {
                "openapi": "3.0.3",
                "info": {"title": "Orders API", "version": "1.0.0"},
                "servers": [{"url": "http://api.example.com"}],
                "paths": {
                    "/users/{user_id}": {
                        "post": {
                            "security": [],
                            "parameters": [
                                {"name": "user_id", "in": "path", "required": True, "schema": {"type": "string"}},
                                {"name": "items", "in": "query", "schema": {"type": "array"}},
                            ],
                            "requestBody": {
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {"role": {"type": "string"}},
                                        }
                                    }
                                }
                            },
                            "responses": {
                                "200": {
                                    "description": "ok",
                                    "content": {
                                        "application/json": {
                                            "schema": {
                                                "type": "object",
                                                "properties": {"password": {"type": "string"}},
                                            }
                                        }
                                    },
                                }
                            },
                        }
                    }
                },
            }
        )
        status, body = self.post_json(
            "/api/openapi-security/audit",
            {"raw_content": contract, "contract_type": "openapi", "source_name": "orders-openapi.json"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["format"], "sniper-api-contract-audit-v1")
        self.assertGreaterEqual(body["finding_count"], 4)

        target = server.STORE.create_target(normalize_target("https://example.com"))
        engagement = server.STORE.create_engagement(
            target_id=target["id"],
            name="auto-sync-test",
            authorization_ref="AUTH-SYNC-1",
            scope_notes="authorized scope",
            out_of_scope="",
            test_window="",
            special_approvals={},
        )
        sync_status, sync_body = self.post_json(
            f"/api/engagements/{engagement['id']}/auto-evidence-sync",
            {"overwrite_manual": False},
        )
        self.assertEqual(sync_status, 200)
        self.assertEqual(sync_body["format"], "sniper-wstg-auto-evidence-sync-v1")
        self.assertEqual(sync_body["engagement_id"], engagement["id"])

        plug_status, plug_body = self.post_json(
            "/api/plugins/enable-builtins",
            {"confirm_enable": True},
        )
        self.assertEqual(plug_status, 200)
        self.assertIs(plug_body["enabled"], True)
        self.assertGreaterEqual(plug_body["loaded"], 4)
        server.PLUGIN_MANAGER.enabled = False
        server.PLUGIN_MANAGER.plugins = []

    def test_phase2_enterprise_capabilities_http_contracts(self):
        chain_status, chain_body = self.get_json("/api/audit-log/verify")
        self.assertEqual(chain_status, 200)
        self.assertEqual(chain_body["format"], "sniper-audit-chain-verification-v1")
        self.assertIs(chain_body["verified"], True)

        with tempfile.TemporaryDirectory(dir=str(Path.home())) as tmpdir:
            root = Path(tmpdir)
            (root / "main.tf").write_text(
                'resource "aws_security_group" "web" {\n  ingress {\n    cidr_blocks = ["0.0.0.0/0"]\n    from_port = 22\n    to_port = 22\n  }\n}\n',
                encoding="utf-8",
            )
            (root / "nginx.conf").write_text("server {\n  autoindex on;\n}\n", encoding="utf-8")
            (root / "requirements.txt").write_text("urllib3==2.0.0\n", encoding="utf-8")
            (root / "app.py").write_text("import urllib3\nprint('ok')\n", encoding="utf-8")

            audit1_status, audit1 = self.post_json("/api/project-audits", {"project_path": str(root)})
            self.assertEqual(audit1_status, 201)
            (root / "nginx.conf").write_text("server {\n  server_tokens off;\n}\n", encoding="utf-8")
            audit2_status, audit2 = self.post_json("/api/project-audits", {"project_path": str(root)})
            self.assertEqual(audit2_status, 201)

            diff_status, diff_body = self.post_json(
                "/api/project-audits/diff",
                {"before_id": audit1["id"], "after_id": audit2["id"]},
            )
            self.assertEqual(diff_status, 200)
            self.assertEqual(diff_body["format"], "sniper-project-audit-diff-v1")
            self.assertGreaterEqual(diff_body["resolved_count"], 1)

            sarif_status, sarif_body = self.get_json(f"/api/project-audits/{audit1['id']}/report.sarif")
            self.assertEqual(sarif_status, 200)
            self.assertEqual(sarif_body["version"], "2.1.0")

            comp_status, comp_body = self.get_json(f"/api/project-audits/{audit1['id']}/compliance-matrix")
            self.assertEqual(comp_status, 200)
            self.assertEqual(comp_body["format"], "sniper-compliance-crosswalk-v1")
            fw_ids = [fw["id"] for fw in comp_body["frameworks"]]
            self.assertIn("PCI-DSS-4.0", fw_ids)

            reach_status, reach_body = self.post_json(
                "/api/dependency-security/reachability",
                {
                    "project_path": str(root),
                    "confirm_local_scan": True,
                    "vulnerable_packages": [{"name": "urllib3", "ecosystem": "PyPI", "vuln_id": "CVE-2026-0001"}],
                },
            )
            self.assertEqual(reach_status, 200)
            self.assertEqual(reach_body["format"], "sniper-vulnerability-reachability-v1")
            self.assertEqual(reach_body["reachable_count"], 1)

            gate_status, gate_body = self.post_json(
                "/api/quality-gate/evaluate",
                {"project_audit_id": audit2["id"]},
            )
            self.assertEqual(gate_status, 200)
            self.assertEqual(gate_body["format"], "sniper-quality-gate-v1")
            self.assertIn(gate_body["passed"], (True, False))

    def test_mobile_security_suite_http_contracts(self) -> None:
        import zipfile

        manifest_status, manifest_body = self.post_json(
            "/api/mobile-security/audit-manifest",
            {
                "filename": "AndroidManifest.xml",
                "app_profile": "finance",
                "raw_content": (
                    '<manifest package="com.example.fin">'
                    '<application android:debuggable="true" android:allowBackup="true" '
                    'android:usesCleartextTraffic="true">'
                    '<activity android:name=".MainActivity" android:exported="true"/>'
                    "</application></manifest>"
                ),
            },
        )
        self.assertEqual(manifest_status, 200)
        self.assertEqual(manifest_body["format"], "sniper-mobile-manifest-audit-v1")
        self.assertGreaterEqual(manifest_body["finding_count"], 3)

        with tempfile.TemporaryDirectory(dir=str(Path.home())) as tmp:
            root = Path(tmp)
            (root / "AndroidManifest.xml").write_text(
                '<manifest package="com.example.app"><application android:debuggable="true"/></manifest>',
                encoding="utf-8",
            )
            (root / "MainActivity.kt").write_text(
                'fun run() { webView.settings.javaScriptEnabled = true\nwebView.addJavascriptInterface(Bridge(), "AndroidBridge") }\n',
                encoding="utf-8",
            )
            proj_status, proj_body = self.post_json(
                "/api/mobile-security/audit-project",
                {"project_path": str(root), "app_profile": "all", "confirm_local": True},
            )
            self.assertEqual(proj_status, 200)
            self.assertEqual(proj_body["format"], "sniper-mobile-security-audit-v1")
            self.assertIn("masvs_summary", proj_body)
            self.assertIn("mobile_top10_summary", proj_body)
            self.assertIn("domain_risk_summary", proj_body)

            apk_path = root / "sample.apk"
            with zipfile.ZipFile(apk_path, "w") as zf:
                zf.writestr("classes.dex", b"dex\n035\x00const-string https://example.com ai_live_secret")
                zf.writestr("assets/.env", b"API_SECRET=super_secret_token_123456\n")
            pkg_status, pkg_body = self.post_json(
                "/api/mobile-security/audit-package",
                {"package_path": str(apk_path), "confirm_local": True},
            )
            self.assertEqual(pkg_status, 200)
            self.assertEqual(pkg_body["format"], "sniper-mobile-package-audit-v1")
            self.assertEqual(pkg_body["package_type"], "apk")
            self.assertGreaterEqual(pkg_body["finding_count"], 1)

    def test_next_gen_8_security_modules_http_contracts(self) -> None:
        ai_status, ai_body = self.post_json(
            "/api/ai-llm-security/audit",
            {
                "filename": "agent.py",
                "raw_content": (
                    'import torch\n'
                    'model = torch.load("model.pt")\n'
                    'prompt = f"System: execute {user_input}"\n'
                    'eval(llm_output)\n'
                ),
            },
        )
        self.assertEqual(ai_status, 200)
        self.assertEqual(ai_body["format"], "sniper-ai-llm-inline-audit-v1")
        self.assertGreaterEqual(ai_body["finding_count"], 2)

        iam_status, iam_body = self.post_json(
            "/api/cloud-iam-security/audit",
            {
                "filename": "policy.json",
                "raw_content": '{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*","Principal":"*"}]}',
            },
        )
        self.assertEqual(iam_status, 200)
        self.assertEqual(iam_body["format"], "sniper-cloud-iam-rbac-audit-v1")
        self.assertGreaterEqual(iam_body["finding_count"], 1)

        proto_status, proto_body = self.post_json(
            "/api/protocol-security/audit",
            {
                "protocol_type": "grpc",
                "filename": "auth.proto",
                "raw_content": 'syntax = "proto3";\nmessage LoginRequest { string password = 1; repeated string items = 2; }\n',
            },
        )
        self.assertEqual(proto_status, 200)
        self.assertEqual(proto_body["format"], "sniper-realtime-protocol-audit-v1")
        self.assertGreaterEqual(proto_body["finding_count"], 1)

        auth_status, auth_body = self.post_json(
            "/api/auth-protocol/audit",
            {
                "artifact_type": "jwt",
                "raw_content": "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwicGFzc3dvcmQiOiJzZWNyZXQifQ.",
            },
        )
        self.assertEqual(auth_status, 200)
        self.assertEqual(auth_body["format"], "sniper-auth-protocol-audit-v1")
        self.assertGreaterEqual(auth_body["finding_count"], 2)

        chain_status, chain_body = self.post_json(
            "/api/attack-paths/correlate",
            {
                "findings": [
                    {"category": "cors", "severity": "high", "title": "CORS *"},
                    {"category": "session", "severity": "medium", "title": "Missing HttpOnly"},
                ]
            },
        )
        self.assertEqual(chain_status, 200)
        self.assertEqual(chain_body["format"], "sniper-attack-path-correlation-v1")
        self.assertIn("mermaid_diagram", chain_body)

        patch_status, patch_body = self.post_json(
            "/api/remediation/auto-patch",
            {
                "findings": [
                    {"category": "headers", "severity": "medium", "title": "HSTS eksik", "reference": "OWASP"},
                    {"category": "container", "severity": "high", "title": "USER root", "reference": "CWE-250"},
                ]
            },
        )
        self.assertEqual(patch_status, 200)
        self.assertEqual(patch_body["format"], "sniper-auto-remediation-patches-v1")
        self.assertGreaterEqual(patch_body["patch_count"], 1)

        # 23. tur: veri olmadan şablon rapor üretilmez (400); gerçek bir manuel denetimle 200.
        exec_status, exec_body = self.post_json(
            "/api/reports/executive-pentest",
            {"include_patches": True},
        )
        self.assertEqual(exec_status, 400)
        target = server.STORE.create_target(normalize_target("https://example.com"))
        engagement = server.STORE.create_engagement(
            target_id=target["id"], name="Yönetici raporu denetimi", authorization_ref="AUTH-EXEC-1",
            scope_notes="yetkili kapsam", out_of_scope="", test_window="", special_approvals={},
        )
        exec_status, exec_body = self.post_json(
            "/api/reports/executive-pentest",
            {"include_patches": True, "engagement_id": engagement["id"]},
        )
        self.assertEqual(exec_status, 200, exec_body)
        self.assertEqual(exec_body["format"], "sniper-executive-pentest-report-v1")
        self.assertIn("markdown_report", exec_body)
        self.assertEqual(exec_body["data_basis"]["kind"], "real")

    def test_advanced_8_security_modules_http_contracts(self) -> None:
        bl_status, bl_body = self.post_json(
            "/api/business-logic/audit",
            {
                "filename": "wallet.py",
                "raw_content": (
                    "def withdraw(user, amount):\n"
                    "    amt = float(amount)\n"
                    "    if user.balance >= amt:\n"
                    "        user.balance -= amt\n"
                    "        user.save()\n"
                ),
            },
        )
        self.assertEqual(bl_status, 200)
        self.assertEqual(bl_body["format"], "sniper-business-logic-inline-audit-v1")
        self.assertGreaterEqual(bl_body["finding_count"], 1)

        db_status, db_body = self.post_json(
            "/api/database-security/audit",
            {
                "filename": "schema.sql",
                "raw_content": (
                    "CREATE TABLE customer_payments (\n"
                    "  id SERIAL PRIMARY KEY,\n"
                    "  tenant_id UUID NOT NULL,\n"
                    "  card_number VARCHAR(32),\n"
                    "  ssn TEXT\n"
                    ");\n"
                    "GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO app_user;\n"
                ),
            },
        )
        self.assertEqual(db_status, 200)
        self.assertEqual(db_body["format"], "sniper-database-schema-inline-audit-v1")
        self.assertGreaterEqual(db_body["finding_count"], 2)

        pqc_status, pqc_body = self.post_json(
            "/api/crypto-cbom-pqc/audit",
            {
                "filename": "crypto_service.py",
                "raw_content": (
                    "import hashlib\n"
                    "from cryptography.hazmat.primitives.asymmetric import rsa, ec\n"
                    "key = rsa.generate_private_key(public_exponent=65537, key_size=1024)\n"
                    "digest = hashlib.md5(b'data').hexdigest()\n"
                ),
            },
        )
        self.assertEqual(pqc_status, 200)
        self.assertEqual(pqc_body["format"], "sniper-crypto-cbom-pqc-inline-v1")
        self.assertIn("cyclonedx_cbom", pqc_body)
        self.assertGreaterEqual(pqc_body["finding_count"], 2)

        sol_status, sol_body = self.post_json(
            "/api/web3-iot-security/audit",
            {
                "filename": "Vault.sol",
                "raw_content": (
                    "pragma solidity ^0.8.0;\n"
                    "contract Vault {\n"
                    "  mapping(address => uint256) public balances;\n"
                    "  function withdraw(uint256 amount) public {\n"
                    "    require(tx.origin == msg.sender);\n"
                    '    (bool ok, ) = msg.sender.call{value: amount}("");\n'
                    "    require(ok);\n"
                    "    balances[msg.sender] -= amount;\n"
                    "  }\n"
                    "}\n"
                ),
            },
        )
        self.assertEqual(sol_status, 200)
        self.assertEqual(sol_body["format"], "sniper-smart-contract-audit-v1")
        self.assertGreaterEqual(sol_body["finding_count"], 2)

        tm_status, tm_body = self.post_json(
            "/api/threat-model/generate",
            {
                "findings": [
                    {"category": "ssrf", "severity": "high", "title": "SSRF", "reference": "CWE-918"},
                    {"category": "secrets", "severity": "critical", "title": "Leaked Key", "reference": "CWE-798"},
                ]
            },
        )
        self.assertEqual(tm_status, 200)
        self.assertEqual(tm_body["format"], "sniper-stride-mitre-threat-model-v1")
        self.assertIn("stride_matrix", tm_body)
        self.assertIn("dfd_mermaid", tm_body)

        slsa_status, slsa_body = self.post_json(
            "/api/supply-chain-slsa/audit",
            {
                "components": [
                    {"name": "reqeusts", "version": "2.31.0", "ecosystem": "PyPI", "license": "AGPL-3.0"},
                    {"name": "corp-internal-auth", "version": "1.0.0", "ecosystem": "npm"},
                ],
                "workflow_content": "name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n",
            },
        )
        self.assertEqual(slsa_status, 200)
        self.assertEqual(slsa_body["format"], "sniper-supply-chain-slsa-audit-v1")
        self.assertGreaterEqual(slsa_body["finding_count"], 2)

        bt_status, bt_body = self.post_json(
            "/api/blue-team/synthesize-rules",
            {
                "target_domain": "bank.example.com",
                "findings": [
                    {"category": "data_query", "severity": "critical", "title": "SQL Injection", "reference": "CWE-89"},
                    {"category": "ssrf", "severity": "high", "title": "SSRF", "reference": "CWE-918"},
                ],
            },
        )
        self.assertEqual(bt_status, 200)
        self.assertEqual(bt_body["format"], "sniper-blue-team-rules-v1")
        self.assertGreaterEqual(bt_body["rule_count"], 3)

    def test_advanced_suite_v3_http_contracts(self) -> None:
        fake_aws = "AKIA" + "Z7Q2K4M9P1X5R8T3"
        sec_status, sec_body = self.post_json(
            "/api/secret-intelligence/audit",
            {"filename": "settings.py", "raw_content": f"AWS_ACCESS_KEY_ID = '{fake_aws}'\n"},
        )
        self.assertEqual(sec_status, 200)
        self.assertEqual(sec_body["format"], "sniper-secret-intelligence-inline-v1")
        self.assertGreaterEqual(sec_body["finding_count"], 1)
        self.assertNotIn(fake_aws, json.dumps(sec_body))

        priv_status, priv_body = self.post_json(
            "/api/privacy-dataflow/audit",
            {"filename": "views.py", "raw_content": "def signup(user):\n    logger.info(f'new user {user.tc_kimlik} {user.email}')\n"},
        )
        self.assertEqual(priv_status, 200)
        self.assertEqual(priv_body["format"], "sniper-privacy-dataflow-inline-v1")
        self.assertGreaterEqual(priv_body["finding_count"], 1)
        self.assertIn("ropa", priv_body)

        host_status, host_body = self.post_json(
            "/api/host-hardening/audit",
            {"filename": "sshd_config", "raw_content": "PermitRootLogin yes\nPasswordAuthentication yes\nPermitEmptyPasswords yes\n"},
        )
        self.assertEqual(host_status, 200)
        self.assertEqual(host_body["format"], "sniper-host-cis-hardening-inline-v1")
        self.assertGreaterEqual(host_body["finding_count"], 3)

        dos_status, dos_body = self.post_json(
            "/api/dos-resilience/audit",
            {"filename": "client.py", "raw_content": "import requests\nresp = requests.get(url)\n"},
        )
        self.assertEqual(dos_status, 200)
        self.assertEqual(dos_body["format"], "sniper-dos-resilience-inline-v1")
        self.assertGreaterEqual(dos_body["finding_count"], 1)

        redos_status, redos_body = self.post_json("/api/dos-resilience/audit", {"regex": "(a+)+$"})
        self.assertEqual(redos_status, 200)
        self.assertTrue(redos_body["vulnerable"])

        log_status, log_body = self.post_json(
            "/api/audit-logging/audit",
            {"filename": "api.py", "raw_content": "from flask import request\nlogger.info('login for ' + request.args.get('user'))\n"},
        )
        self.assertEqual(log_status, 200)
        self.assertEqual(log_body["format"], "sniper-audit-logging-inline-v1")
        self.assertGreaterEqual(log_body["finding_count"], 1)

        chain_status, chain_body = self.post_json("/api/audit-logging/audit", {"entries": []})
        self.assertEqual(chain_status, 200)
        self.assertEqual(chain_body["format"], "sniper-hash-chained-log-verification-v1")

        ext_status, ext_body = self.post_json(
            "/api/browser-extension-pwa/audit",
            {
                "filename": "manifest.json",
                "raw_content": json.dumps(
                    {"manifest_version": 3, "name": "x", "version": "1", "permissions": ["debugger", "cookies"], "host_permissions": ["<all_urls>"]}
                ),
            },
        )
        self.assertEqual(ext_status, 200)
        self.assertEqual(ext_body["format"], "sniper-browser-extension-manifest-audit-v1")
        self.assertGreaterEqual(ext_body["finding_count"], 2)

        zt_status, zt_body = self.post_json(
            "/api/zero-trust-mesh/audit",
            {
                "filename": "mesh.yaml",
                "raw_content": (
                    "apiVersion: security.istio.io/v1beta1\n"
                    "kind: PeerAuthentication\n"
                    "metadata:\n"
                    "  name: default\n"
                    "  namespace: payments\n"
                    "spec:\n"
                    "  mtls:\n"
                    "    mode: PERMISSIVE\n"
                ),
            },
        )
        self.assertEqual(zt_status, 200)
        self.assertEqual(zt_body["format"], "sniper-zero-trust-mesh-inline-v1")
        self.assertGreaterEqual(zt_body["finding_count"], 1)

        cvss_status, cvss_body = self.post_json(
            "/api/cvss-ssvc/prioritize",
            {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
        )
        self.assertEqual(cvss_status, 200)
        self.assertEqual(cvss_body["base_score"], 9.8)

        cvss40_status, cvss40_body = self.post_json(
            "/api/cvss-ssvc/prioritize",
            {"vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"},
        )
        self.assertEqual(cvss40_status, 200)
        self.assertEqual(cvss40_body["score"], 9.3)
        self.assertEqual(cvss40_body["severity"], "Critical")
        bad40_status, _bad40_body = self.post_json(
            "/api/cvss-ssvc/prioritize", {"vector": "CVSS:4.0/AV:N/AC:L"}
        )
        self.assertEqual(bad40_status, 400)

        prio_status, prio_body = self.post_json(
            "/api/cvss-ssvc/prioritize",
            {
                "findings": [
                    {"title": "SQL Injection", "severity": "critical", "category": "data_query", "cwe": "CWE-89"},
                    {"title": "Missing header", "severity": "low", "category": "headers", "cwe": "CWE-693"},
                ],
                "exploitation": "active",
                "mission_prevalence": "essential",
            },
        )
        self.assertEqual(prio_status, 200)
        self.assertEqual(prio_body["format"], "sniper-cvss-ssvc-prioritization-v1")
        self.assertEqual(prio_body["prioritized_findings"][0]["title"], "SQL Injection")

        gate_status, _gate_body = self.post_json(
            "/api/secret-intelligence/audit", {"project_path": str(self.base)}
        )
        self.assertEqual(gate_status, 400)

        bad_vec_status, _bad_vec_body = self.post_json("/api/cvss-ssvc/prioritize", {"vector": "CVSS:3.1/AV:X"})
        self.assertEqual(bad_vec_status, 400)


if __name__ == "__main__":
    unittest.main()




