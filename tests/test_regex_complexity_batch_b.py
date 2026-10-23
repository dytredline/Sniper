"""CodeQL polynomial-ReDoS batch B runtime and semantic regressions."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import time
import unittest

import browser_extension_pwa_auditor as browser
import business_logic_auditor as business
import cloud_iam_rbac_auditor as cloud
import database_rls_schema_auditor as database
import desktop_protocol_security_auditor as desktop
import dos_resilience_redos_auditor as resilience


ROOT = Path(__file__).resolve().parents[1]


class RegexComplexityBatchBTests(unittest.TestCase):
    ADVERSARIAL = {
        "alert_384_browser_precache": """
import browser_extension_pwa_auditor as m
m.audit_service_worker_inline('c.addAll([\\"auth' + 'auth' * 60000)
""",
        "alert_385_browser_cache_put": """
import browser_extension_pwa_auditor as m
m.audit_service_worker_inline('cache.put(request, response); \\"auth' + 'auth' * 60000)
""",
        "alert_386_browser_postmessage": """
import browser_extension_pwa_auditor as m
m.audit_service_worker_inline('.postMessage(' * 10000)
""",
        "alert_388_business_mutation": """
import business_logic_auditor as m
m.audit_business_logic_inline('balance =' + ' ' * 350000)
""",
        "alert_389_business_state_guard": """
import business_logic_auditor as m
m._has_state_guard('if' + ' ' * 350000)
""",
        "alert_390_cloud_verbs": """
import cloud_iam_rbac_auditor as m
m.audit_cloud_iam_and_k8s_rbac('verbs:\\n' + '\\n' * 180000)
""",
        "alert_391_cloud_terraform": """
import cloud_iam_rbac_auditor as m
m.audit_cloud_iam_and_k8s_rbac('resource \\"aws_ebs_volume\\" \\"!\\" {' + 'resource \\"aws_ebs_volume\\" \\"!\\" {|' * 4000)
""",
        "alert_392_database_policy": """
import database_rls_schema_auditor as m
m.audit_database_schema_inline('create policy :' + ' ' * 180000)
""",
        "alert_393_database_table": """
import database_rls_schema_auditor as m
m.audit_database_schema_inline('create table \\"(' + 'create table \\"(a' * 9000)
""",
        "alert_394_database_model": """
import database_rls_schema_auditor as m
m.audit_database_schema_inline('model 0{' + 'model 0{|' * 12000)
""",
        "alert_395_database_copy": """
import database_rls_schema_auditor as m
m.audit_database_schema_inline('COPY' + ' ' * 280000)
""",
        "alert_396_database_drop": """
import database_rls_schema_auditor as m
m.audit_database_schema_inline('DROP TABLE' + ' ' * 280000)
""",
        "alert_397_desktop_origin": """
import desktop_protocol_security_auditor as m
m.audit_realtime_and_binary_protocols('checkorigin' * 28000, protocol_type='websocket', filename='ws.go')
""",
        "alert_398_resilience_concat": """
import dos_resilience_redos_auditor as m
m.audit_dos_resilience_inline('re.compile(\\"x\\")' + ' ' * 350000, filename='app.py')
""",
        "alert_399_resilience_js_literal": """
import dos_resilience_redos_auditor as m
m.audit_dos_resilience_inline('(/[/' * 45000, filename='app.js')
""",
    }

    def test_codeql_adversarial_inputs_complete_with_linear_budget(self):
        for name, body in self.ADVERSARIAL.items():
            script = "import json,time\nt=time.monotonic()\n" + body + "\nprint(json.dumps({'elapsed': time.monotonic()-t}))\n"
            with self.subTest(auditor=name):
                started = time.monotonic()
                run = subprocess.run(
                    [sys.executable, "-c", script], cwd=ROOT, text=True, capture_output=True,
                    timeout=2.0, check=False,
                )
                wall = time.monotonic() - started
                self.assertEqual(run.returncode, 0, run.stderr)
                measured = json.loads(run.stdout)["elapsed"]
                self.assertLess(measured, 1.0, (name, measured, wall))

    def test_hardened_detectors_preserve_positive_and_negative_controls(self):
        risky_worker = browser.audit_service_worker_inline(
            "c.addAll(['/index.html', '/api/me']);\n"
            "cache.put(request, response); // auth profile\n"
            "client.postMessage(secret, '*');\n"
        )
        worker_titles = {item["title"] for item in risky_worker["findings"]}
        self.assertTrue(any("önbelle" in title for title in worker_titles), worker_titles)
        self.assertTrue(any("postMessage" in title for title in worker_titles), worker_titles)

        logic = business.audit_business_logic_inline(
            "def debit(account, amount):\n    account.balance -= amount\n"
            "def settle(order):\n    order.status = 'paid'\n"
        )
        logic_controls = {item["control_id"] for item in logic["findings"]}
        self.assertIn("SNIPER-BUSL-01", logic_controls)
        self.assertIn("SNIPER-BUSL-03", logic_controls)
        guarded_logic = business.audit_business_logic_inline(
            "with transaction.atomic():\n"
            "    account = Account.objects.select_for_update().get()\n"
            "    account.balance -= amount\n"
            "if order.status == 'pending':\n"
            "    order.status = 'paid'\n"
        )
        guarded_controls = {item["control_id"] for item in guarded_logic["findings"]}
        self.assertNotIn("SNIPER-BUSL-01", guarded_controls)
        self.assertNotIn("SNIPER-BUSL-03", guarded_controls)

        cloud_report = cloud.audit_cloud_iam_and_k8s_rbac(
            'resource "aws_ebs_volume" "data" { size = 8 }\n'
            "kind: ClusterRole\nrules:\n- verbs:\n  - '*'\n"
        )
        cloud_titles = {item["title"] for item in cloud_report["findings"]}
        self.assertTrue(any("şifreleme" in title for title in cloud_titles), cloud_titles)
        self.assertTrue(any("wildcard" in title for title in cloud_titles), cloud_titles)
        safe_cloud = cloud.audit_cloud_iam_and_k8s_rbac(
            'resource "aws_ebs_volume" "data" { encrypted = true }\n'
            "kind: ClusterRole\nrules:\n- verbs: ['get', 'list']\n"
        )
        safe_cloud_titles = {item["title"] for item in safe_cloud["findings"]}
        self.assertFalse(any("şifreleme" in title for title in safe_cloud_titles), safe_cloud_titles)
        self.assertFalse(any("wildcard" in title for title in safe_cloud_titles), safe_cloud_titles)
        multiline_verbs = cloud.audit_cloud_iam_and_k8s_rbac(
            "kind: ClusterRole\nrules:\n- verbs:\n  [\n    '*'\n  ]\n"
        )
        self.assertTrue(any("wildcard" in item["title"] for item in multiline_verbs["findings"]))

        db_report = database.audit_database_schema_inline(
            "CREATE TABLE app.orders (id INT, tenant_id UUID);\n"
            "CREATE POLICY tenant_policy ON app.orders USING (true);\n"
            "model Customer { tenantId String }\n"
            "COPY users FROM PROGRAM 'id';\n"
            "DROP TABLE old_orders CASCADE;\n"
        )
        db_controls = {item["control_id"] for item in db_report["findings"]}
        self.assertIn("SNIPER-CONF-08", db_controls)
        self.assertIn("SNIPER-INFR-03", db_controls)
        self.assertFalse([
            item for item in db_report["findings"]
            if item["control_id"] == "SNIPER-AUTHZ-04" and "orders" in item["title"]
        ])
        multiline_grant = database.audit_database_schema_inline("GRANT\nALL PRIVILEGES ON app.* TO worker;\n")
        self.assertIn("SNIPER-CONF-08", {item["control_id"] for item in multiline_grant["findings"]})

        ws_open = desktop.audit_realtime_and_binary_protocols(
            "func CheckOrigin(r *http.Request) bool { return true }\n",
            protocol_type="websocket", filename="ws.go",
        )
        self.assertTrue(any("Origin" in item["title"] for item in ws_open["findings"]))
        ws_checked = desktop.audit_realtime_and_binary_protocols(
            'func CheckOrigin(r *http.Request) bool { return r.Header.Get("Origin") == "https://app.example" }\n'
            "maxPayload = 65536\n",
            protocol_type="websocket", filename="ws.go",
        )
        self.assertFalse(any("Origin" in item["title"] for item in ws_checked["findings"]))
        ws_multiline_wildcard = desktop.audit_realtime_and_binary_protocols(
            "allowed_origins = [\n  '*'\n]\nmaxPayload = 65536\n",
            protocol_type="websocket", filename="ws.py",
        )
        self.assertTrue(any("Origin" in item["title"] for item in ws_multiline_wildcard["findings"]))

        extracted = resilience._extract_regex_literals(
            "const a = /a[\\/]b+/gi; const bad = new RegExp(user); return /(x|y)+$/;", "js",
        )
        self.assertEqual([item[1] for item in extracted], [r"a[\/]b+", "(x|y)+$"])
        self.assertEqual(resilience._extract_regex_literals("const x = (a / b);", "js"), [])
        self.assertEqual(resilience._extract_regex_literals('re.compile("(a+)+" + suffix)', "python"), [])

    def test_desktop_origin_scan_keeps_unicode_casefold_offsets_local(self):
        report = desktop.audit_realtime_and_binary_protocols(
            "// Straße\n"
            "func CheckOrigin(r *http.Request) bool { return true }\n"
            "maxPayload = 65536\n",
            protocol_type="websocket",
            filename="ws.go",
        )

        self.assertTrue(any("Origin" in item["title"] for item in report["findings"]))

    def test_postfix_if_is_not_a_state_transition_guard(self):
        content = (
            'probe = status == "pending" if condition else False\n'
            'order.status = "paid"\n'
        )

        self.assertFalse(business._has_state_guard(content))
        report = business.audit_business_logic_inline(content, filename="payment.py")
        self.assertIn("SNIPER-BUSL-03", {item["control_id"] for item in report["findings"]})


if __name__ == "__main__":
    unittest.main()
