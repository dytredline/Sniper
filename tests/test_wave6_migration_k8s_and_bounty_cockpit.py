"""Wave 6 Workstream 3 — Veritabanı Şema Göçü/RLS Denetçisi, K8s/eBPF Sıfır-Güven Sentezleyici ve Bounty Hazırlık Kokpiti Testleri."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest

APP_DIR = Path(__file__).resolve().parent.parent
if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))

from bounty_readiness_cockpit import evaluate_end_to_end_bounty_readiness
from k8s_admission_netpol_synthesizer import synthesize_zero_trust_k8s_and_ebpf_policies
from schema_migration_security_auditor import audit_database_schema_migrations


class Wave6MigrationK8sAndBountyCockpitTests(unittest.TestCase):
    def test_schema_migration_auditor_detects_vulnerable_sql_and_passes_safe_migration(self) -> None:
        vulnerable_sql = """
        -- 0002_update_tenants.sql
        ALTER TABLE tenant_invoices DISABLE ROW LEVEL SECURITY;
        ALTER TABLE tenant_invoices DROP COLUMN tenant_id;
        ALTER TABLE users ADD COLUMN api_key VARCHAR(255);
        """
        vuln_report = audit_database_schema_migrations(
            vulnerable_sql,
            filename="0002_update_tenants.sql",
        )
        self.assertEqual(vuln_report["format"], "sniper-schema-migration-security-audit/1")
        self.assertEqual(vuln_report["filename"], "0002_update_tenants.sql")
        self.assertEqual(vuln_report["finding_count"], 3)

        by_rule = {f["rule_id"]: f for f in vuln_report["findings"]}
        self.assertIn("SNIPER-MIG-RLS-01", by_rule)
        self.assertIn("SNIPER-MIG-TENANT-DROP-02", by_rule)
        self.assertIn("SNIPER-MIG-CLEARTEXT-03", by_rule)

        rls_finding = by_rule["SNIPER-MIG-RLS-01"]
        self.assertEqual(rls_finding["cwe"], "CWE-284")
        self.assertEqual(rls_finding["severity"], "critical")
        self.assertEqual(rls_finding["category"], "authz")
        self.assertIn("Row-Level Security (RLS)", rls_finding["title"])

        tenant_finding = by_rule["SNIPER-MIG-TENANT-DROP-02"]
        self.assertEqual(tenant_finding["cwe"], "CWE-639")
        self.assertEqual(tenant_finding["severity"], "high")
        self.assertEqual(tenant_finding["category"], "authz")

        secret_finding = by_rule["SNIPER-MIG-CLEARTEXT-03"]
        self.assertEqual(secret_finding["cwe"], "CWE-312")
        self.assertEqual(secret_finding["severity"], "high")
        self.assertEqual(secret_finding["category"], "crypto")

        safe_sql = """
        CREATE TABLE tenant_invoices (
            id UUID PRIMARY KEY,
            tenant_id UUID NOT NULL,
            api_key_hash TEXT NOT NULL,
            password_digest TEXT NOT NULL
        );
        ALTER TABLE tenant_invoices ENABLE ROW LEVEL SECURITY;
        CREATE POLICY tenant_isolation_policy ON tenant_invoices
            USING (tenant_id = current_setting('app.current_tenant')::uuid);
        """
        safe_report = audit_database_schema_migrations(
            safe_sql,
            filename="0003_safe_tenants.sql",
        )
        self.assertEqual(safe_report["finding_count"], 0)
        self.assertEqual(safe_report["findings"], [])

    def test_schema_migration_auditor_supports_alembic_and_rails_migrations(self) -> None:
        alembic_and_rails = """
        def upgrade():
            op.drop_column("projects", "organization_id")
            op.add_column("users", sa.Column("raw_password", sa.String(128)))
        """
        report = audit_database_schema_migrations(
            alembic_and_rails,
            filename="versions/004_alembic_unsafe.py",
        )
        rule_ids = {f["rule_id"] for f in report["findings"]}
        self.assertIn("SNIPER-MIG-TENANT-DROP-02", rule_ids)
        self.assertIn("SNIPER-MIG-CLEARTEXT-03", rule_ids)

    def test_synthesize_zero_trust_k8s_and_ebpf_policies_builds_netpol_cel_and_tetragon(self) -> None:
        findings = [
            {
                "id": "SNIPER-CMDI-01",
                "cwe": "CWE-78",
                "severity": "critical",
                "category": "command_data",
                "title": "OS Command Injection in Report Exporter",
            },
            {
                "id": "SNIPER-LFI-02",
                "cwe": "CWE-22",
                "severity": "high",
                "category": "command_data",
                "title": "Path Traversal in Artifact Reader",
            },
        ]
        service_graph = {
            "format": "sniper-runtime-correlated-service-graph/1",
            "edges": [
                {
                    "producer": "repo:api-gateway",
                    "consumer": "repo:billing-service",
                    "protocol": "http",
                    "port": 8080,
                    "verification_state": "runtime_confirmed",
                },
                {
                    "producer": "repo:legacy-cron",
                    "consumer": "repo:billing-service",
                    "protocol": "http",
                    "port": 8080,
                    "verification_state": "contradicted",
                },
            ],
        }

        result = synthesize_zero_trust_k8s_and_ebpf_policies(
            findings,
            service_graph=service_graph,
            namespace="production",
            app_name="billing-service",
        )
        self.assertEqual(result["format"], "sniper-k8s-ebpf-zero-trust-synthesis/1")
        self.assertEqual(result["namespace"], "production")
        self.assertEqual(result["app_name"], "billing-service")
        self.assertEqual(result["network_policy_count"], 2)
        self.assertEqual(result["cel_expression_count"], 4)

        netpols = result["kubernetes_network_policies"]
        self.assertEqual(netpols[0]["metadata"]["name"], "default-deny-all")
        self.assertEqual(netpols[0]["spec"]["podSelector"], {})
        self.assertEqual(netpols[0]["spec"]["policyTypes"], ["Ingress", "Egress"])

        edge_pol = netpols[1]
        self.assertEqual(edge_pol["spec"]["podSelector"]["matchLabels"]["app"], "billing-service")
        ingress_rule = edge_pol["spec"]["ingress"][0]
        self.assertEqual(
            ingress_rule["from"][0]["podSelector"]["matchLabels"]["app"],
            "api-gateway",
        )
        self.assertEqual(ingress_rule["ports"][0], {"protocol": "TCP", "port": 8080})

        admission = result["validating_admission_policy"]
        self.assertEqual(admission["apiVersion"], "admissionregistration.k8s.io/v1")
        self.assertEqual(admission["kind"], "ValidatingAdmissionPolicy")
        cel_expressions = "\n".join(v["expression"] for v in admission["spec"]["validations"])
        self.assertIn("privileged", cel_expressions)
        self.assertIn("NET_ADMIN", cel_expressions)
        self.assertIn("/var/run/docker.sock", cel_expressions)
        self.assertIn("runAsNonRoot", cel_expressions)

        tetragon = result["tetragon_ebpf_tracing_policy"]
        self.assertEqual(tetragon["apiVersion"], "cilium.io/v1alpha1")
        self.assertEqual(tetragon["kind"], "TracingPolicy")
        kprobes = {kp["call"]: kp for kp in tetragon["spec"]["kprobes"]}
        self.assertIn("sys_execve", kprobes)
        self.assertIn("security_file_open", kprobes)
        exec_values = kprobes["sys_execve"]["selectors"][0]["matchArgs"][0]["values"]
        self.assertIn("/bin/sh", exec_values)
        self.assertIn("curl", exec_values)
        file_values = kprobes["security_file_open"]["selectors"][0]["matchArgs"][0]["values"]
        self.assertIn("/etc/shadow", file_values)
        self.assertIn("/proc/self/environ", file_values)

    def test_bounty_readiness_cockpit_approves_verified_novel_finding_and_blocks_unsat_or_duplicate(self) -> None:
        novel_finding = {
            "id": "SNIPER-IDOR-2026-01",
            "cwe": "CWE-862",
            "severity": "critical",
            "title": "Cross-Tenant Organization Invoice Read via Unscoped GraphQL Resolver",
            "file": "app/graphql/resolvers/invoice_resolver.rb",
            "package": "gitlab-ee",
            "ecosystem": "rubygems",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N",
            "patch": "--- a/app/graphql/resolvers/invoice_resolver.rb\n+++ b/app/graphql/resolvers/invoice_resolver.rb",
            "corroborated_engines": ["ast_taint", "symbolic_z3", "autorize_matrix"],
        }

        # Case A: SAT symbolic proof + Loopback runtime proof + clean patch -> READY_FOR_SUBMISSION
        ready = evaluate_end_to_end_bounty_readiness(
            novel_finding,
            upstream_advisories=[],
            symbolic_proof={"status": "SAT", "reachable": True},
            runtime_proof={"reproduced": True, "vulnerability_detected": True, "mode": "autorize_matrix"},
            program_handle="gitlab",
            structured_scope_id="55897",
        )
        self.assertEqual(ready["format"], "sniper-bounty-readiness-cockpit/1")
        self.assertGreaterEqual(ready["readiness_score"], 85)
        self.assertEqual(ready["submission_verdict"], "READY_FOR_SUBMISSION")
        self.assertEqual(ready["blocking_reasons"], [])
        self.assertIsNotNone(ready["submission_bundle"])
        self.assertEqual(len(ready["submission_bundle"]["ghsa_payloads"]), 1)
        self.assertEqual(len(ready["submission_bundle"]["hackerone_payloads"]), 1)
        self.assertEqual(
            ready["submission_bundle"]["hackerone_payloads"][0]["program_handle"],
            "gitlab",
        )

        # Case B1: UNSAT symbolic proof -> BLOCKED_DUPLICATE_OR_UNSAT
        blocked_unsat = evaluate_end_to_end_bounty_readiness(
            novel_finding,
            symbolic_proof={"status": "UNSAT", "reachable": False},
            runtime_proof={"reproduced": True},
        )
        self.assertEqual(blocked_unsat["submission_verdict"], "BLOCKED_DUPLICATE_OR_UNSAT")
        self.assertIn("UNSAT_UNREACHABLE_PATH", blocked_unsat["blocking_reasons"])
        self.assertIsNone(blocked_unsat["submission_bundle"])

        # Case B2: Duplicate upstream CVE -> BLOCKED_DUPLICATE_OR_UNSAT
        blocked_dup = evaluate_end_to_end_bounty_readiness(
            novel_finding,
            upstream_advisories=[
                {
                    "cve_id": "CVE-2026-99999",
                    "cwe": "CWE-862",
                    "patched_files": ["app/graphql/resolvers/invoice_resolver.rb"],
                }
            ],
            symbolic_proof={"status": "SAT"},
            runtime_proof={"reproduced": True},
        )
        self.assertEqual(blocked_dup["submission_verdict"], "BLOCKED_DUPLICATE_OR_UNSAT")
        self.assertIn("DUPLICATE_UPSTREAM_ADVISORY", blocked_dup["blocking_reasons"])
        self.assertIsNone(blocked_dup["submission_bundle"])


if __name__ == "__main__":
    unittest.main()
