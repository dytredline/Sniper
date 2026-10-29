"""Wave 6 Workstream 4 — Full System Integration Tests (MCP, LSP, CLI Reports, Project Analyzer & Web UI)."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent.parent
if sys.path[:1] != [str(APP_DIR)]:
    if str(APP_DIR) in sys.path:
        sys.path.remove(str(APP_DIR))
    sys.path.insert(0, str(APP_DIR))

import importlib
import cli_reports
import lsp_server
import mcp_triage_server
import project_analyzer

importlib.reload(cli_reports)
importlib.reload(lsp_server)
importlib.reload(mcp_triage_server)
importlib.reload(project_analyzer)


class TestWave6FullIntegrationMcpLspUi(unittest.TestCase):
    def test_mcp_burp_and_bounty_tools_in_community_mode(self) -> None:
        server = mcp_triage_server.TriageMCPServer(None, mode="authenticated")
        listed = server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        self.assertIsNotNone(listed)
        tool_names = {t["name"] for t in listed["result"]["tools"]}
        for expected in (
            "run_burp_repeater_diff",
            "run_autorize_matrix",
            "run_token_sequencer",
            "run_traffic_decoder",
            "evaluate_bounty_readiness",
        ):
            self.assertIn(expected, tool_names)

        # 1. run_burp_repeater_diff
        rep_res = server.call_tool(
            "run_burp_repeater_diff",
            {
                "baseline_response": {"status": 200, "body": {"role": "user", "price": 100}},
                "mutated_response": {"status": 200, "body": {"role": "admin", "price": 0}},
            },
        )
        self.assertFalse(rep_res.get("isError"))
        rep_data = json.loads(rep_res["content"][0]["text"])
        self.assertEqual(rep_data["format"], "sniper-http-repeater-comparer/1")
        self.assertGreaterEqual(len(rep_data.get("findings") or []), 1)

        # 2. run_autorize_matrix
        aut_res = server.call_tool(
            "run_autorize_matrix",
            {
                "probes": [
                    {
                        "endpoint": "GET /api/v1/invoices/99",
                        "owner_response": {"status": 200, "body": {"invoice_id": 99, "secret": "inv_data"}},
                        "other_user_response": {"status": 200, "body": {"invoice_id": 99, "secret": "inv_data"}},
                    }
                ]
            },
        )
        self.assertFalse(aut_res.get("isError"))
        aut_data = json.loads(aut_res["content"][0]["text"])
        self.assertEqual(aut_data["format"], "sniper-autorize-matrix-report/1")
        self.assertGreaterEqual(aut_data.get("finding_count", 0), 1)

        # 3. run_token_sequencer
        seq_res = server.call_tool(
            "run_token_sequencer",
            {"tokens": ["sess_1001", "sess_1002", "sess_1003", "sess_1004"], "token_label": "session_id"},
        )
        self.assertFalse(seq_res.get("isError"))
        seq_data = json.loads(seq_res["content"][0]["text"])
        self.assertEqual(seq_data["format"], "sniper-token-sequencer-report/1")
        self.assertTrue(seq_data.get("is_sequential"))

        # 4. run_traffic_decoder
        dec_res = server.call_tool(
            "run_traffic_decoder",
            {"raw_value": "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA=="},
        )
        self.assertFalse(dec_res.get("isError"))
        dec_data = json.loads(dec_res["content"][0]["text"])
        self.assertEqual(dec_data["format"], "sniper-traffic-decoder/1")
        self.assertIn("java_serialized_object_base64", dec_data.get("signals") or [])

        # 5. evaluate_bounty_readiness
        bounty_res = server.call_tool(
            "evaluate_bounty_readiness",
            {
                "finding": {
                    "id": "F-101",
                    "title": "Cross-Tenant IDOR in Invoice Export",
                    "cwe": "CWE-639",
                    "severity": "critical",
                    "file": "api/invoices.py",
                    "line": 42,
                    "remediation": "Filter invoice query by current_user.tenant_id.",
                },
                "runtime_proof": {"reproduced": True, "status_code": 200},
                "symbolic_proof": {"satisfiability": "SAT", "witness_input": {"invoice_id": 99}},
            },
        )
        self.assertFalse(bounty_res.get("isError"))
        bounty_data = json.loads(bounty_res["content"][0]["text"])
        self.assertEqual(bounty_data["format"], "sniper-bounty-readiness-cockpit/1")
        self.assertEqual(bounty_data["submission_verdict"], "READY_FOR_SUBMISSION")

    def test_lsp_quickfixes_for_postmessage_and_rls(self) -> None:
        js_source = 'window.parent.postMessage(payload, "*");\n'
        js_actions = lsp_server.build_verified_quickfix_actions("file:///tmp/widget.js", js_source)
        self.assertTrue(js_actions)
        self.assertTrue(any("window.location.origin" in str(a) for a in js_actions))
        self.assertTrue(all(a["data"]["closed_loop_verified"] for a in js_actions))

        sql_source = "ALTER TABLE orders DISABLE ROW LEVEL SECURITY;\n"
        sql_actions = lsp_server.build_verified_quickfix_actions("file:///tmp/0002_orders.sql", sql_source)
        self.assertTrue(sql_actions)
        self.assertTrue(any("ENABLE ROW LEVEL SECURITY" in str(a) for a in sql_actions))
        self.assertTrue(all(a["data"]["closed_loop_verified"] for a in sql_actions))

    def test_cli_reports_wave6_json_exporters(self) -> None:
        sample_report = {
            "project_name": "sample-service",
            "path_guards": ["x > 10", "x < 20"],
            "raw_content": "ALTER TABLE accounts DISABLE ROW LEVEL SECURITY;\n",
            "git_diff": (
                "diff --git a/auth.py b/auth.py\n"
                "--- a/auth.py\n"
                "+++ b/auth.py\n"
                "@@ -1,3 +1,3 @@\n"
                "-jwt.decode(token, key, options={'verify_signature': True})\n"
                "+jwt.decode(token, key, options={'verify_signature': False})\n"
            ),
            "findings": [
                {
                    "id": "F-202",
                    "title": "Command Injection in Runner",
                    "cwe": "CWE-78",
                    "severity": "critical",
                    "category": "command_data",
                    "file": "runner.py",
                    "line": 18,
                    "remediation": "Use subprocess.run with shell=False.",
                }
            ],
            "runtime_proof": {"reproduced": True},
            "symbolic_proof": {"satisfiability": "SAT"},
        }

        sym = json.loads(cli_reports.export_symbolic_path_proof_json(sample_report))
        self.assertEqual(sym["format"], "sniper-symbolic-path-constraint-proof/1")
        self.assertEqual(sym["satisfiability"], "SAT")

        bin_rep = json.loads(cli_reports.export_binary_hardening_audit_json(sample_report))
        self.assertEqual(bin_rep["format"], "sniper-binary-security-hardening-audit/1")

        pr_rep = json.loads(cli_reports.export_pr_diff_review_json(sample_report))
        self.assertEqual(pr_rep["format"], "sniper-pr-diff-security-review/1")
        self.assertGreaterEqual(pr_rep.get("finding_count", 0), 1)

        st_rep = json.loads(cli_reports.export_stateful_protocol_audit_json(sample_report))
        self.assertEqual(st_rep["format"], "sniper-stateful-protocol-audit/1")

        mig_rep = json.loads(cli_reports.export_schema_migration_audit_json(sample_report))
        self.assertEqual(mig_rep["format"], "sniper-schema-migration-security-audit/1")
        self.assertGreaterEqual(mig_rep.get("finding_count", 0), 1)

        k8s_rep = json.loads(cli_reports.export_k8s_ebpf_synthesis_json(sample_report))
        self.assertEqual(k8s_rep["format"], "sniper-k8s-ebpf-zero-trust-synthesis/1")

        bounty_rep = json.loads(cli_reports.export_bounty_readiness_cockpit_json(sample_report))
        self.assertEqual(bounty_rep["format"], "sniper-bounty-readiness-cockpit/1")
        self.assertEqual(bounty_rep["submission_verdict"], "READY_FOR_SUBMISSION")

    def test_project_analyzer_wave6_hooks_and_web_ui_workbench(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "migrations").mkdir()
            (root / "migrations" / "0001_init.sql").write_text(
                "ALTER TABLE tenants DISABLE ROW LEVEL SECURITY;\n",
                encoding="utf-8",
            )
            report = project_analyzer.analyze_project(str(root), allowed_roots=(root.parent,))
            titles = " ".join(str(f.get("title") or "") for f in report.get("findings") or [])
            self.assertIn("Row-Level Security", titles)

        index_html = (APP_DIR / "static" / "index.html").read_text(encoding="utf-8")
        app_js = (APP_DIR / "static" / "app.js").read_text(encoding="utf-8")
        self.assertIn('id="burp-workbench-modal"', index_html)
        self.assertIn('id="burp-workbench-form"', index_html)
        self.assertIn("initBurpAndWave6WorkbenchModal", app_js)
        self.assertIn('data-action="open-burp-workbench"', app_js)


if __name__ == "__main__":
    unittest.main()
