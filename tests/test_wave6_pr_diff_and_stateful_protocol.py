"""Wave 6 Workstream 2 — PR Diff Güvenlik Botu ve Durum Bilgili (Stateful) Protokol Denetçisi Birim Testleri."""

from __future__ import annotations

import unittest

from pr_diff_security_bot import audit_git_diff_security_regressions
from stateful_protocol_fuzzer_auditor import (
    audit_stateful_protocol_state_machine,
    simulate_out_of_order_state_sequence,
)


class TestWave6PrDiffAndStatefulProtocol(unittest.TestCase):
    """PR Diff Security Bot ve Stateful Protocol State-Machine Auditor testleri."""

    def test_pr_removing_preauthorize_or_ssrf_filter_flags_guard_removed(self) -> None:
        diff_text = """diff --git a/src/AdminController.java b/src/AdminController.java
--- a/src/AdminController.java
+++ b/src/AdminController.java
@@ -14,5 +14,4 @@ public class AdminController {
-    @PreAuthorize("hasRole('ADMIN')")
     @PostMapping("/users/delete")
     public ResponseEntity<Void> deleteUser(@RequestParam String id) {
         userService.delete(id);
"""
        result = audit_git_diff_security_regressions(diff_text)
        self.assertEqual(result["format"], "sniper-pr-diff-security-review/1")
        self.assertEqual(result["files_changed"], 1)
        self.assertEqual(result["merge_decision"], "BLOCK_MERGE")
        self.assertGreaterEqual(result["finding_count"], 1)

        rule_ids = [f["rule_id"] for f in result["findings"]]
        self.assertIn("SNIPER-PR-GUARD-REMOVED-01", rule_ids)
        finding = next(
            f for f in result["findings"] if f["rule_id"] == "SNIPER-PR-GUARD-REMOVED-01"
        )
        self.assertEqual(finding["cwe"], "CWE-862")
        self.assertEqual(finding["severity"], "critical")
        self.assertEqual(finding["path"], "src/AdminController.java")
        self.assertTrue(
            any("```suggestion" in c["body"] for c in result["review_comments"])
        )

    def test_pr_adding_shell_true_sink_generates_suggestion(self) -> None:
        diff_text = """diff --git a/app/tasks/exporter.py b/app/tasks/exporter.py
--- a/app/tasks/exporter.py
+++ b/app/tasks/exporter.py
@@ -22,3 +22,4 @@ def run_export(cmd: str) -> None:
     logger.info("Starting export")
+    subprocess.run(cmd, shell=True)
     return None
"""
        result = audit_git_diff_security_regressions(diff_text)
        self.assertEqual(result["merge_decision"], "BLOCK_MERGE")
        rule_ids = [f["rule_id"] for f in result["findings"]]
        self.assertIn("SNIPER-PR-NEW-SINK-02", rule_ids)

        finding = next(
            f for f in result["findings"] if f["rule_id"] == "SNIPER-PR-NEW-SINK-02"
        )
        self.assertEqual(finding["cwe"], "CWE-78")
        self.assertEqual(finding["severity"], "high")
        self.assertEqual(finding["line"], 23)

        self.assertEqual(len(result["review_comments"]), 1)
        comment = result["review_comments"][0]
        self.assertEqual(comment["path"], "app/tasks/exporter.py")
        self.assertEqual(comment["line"], 23)
        self.assertIn("```suggestion", comment["body"])
        self.assertIn("shell=False", comment["body"])

    def test_pr_fixing_one_file_flags_unpatched_sibling(self) -> None:
        diff_text = """diff --git a/src/converters/ConvertHtmlToPDF.java b/src/converters/ConvertHtmlToPDF.java
--- a/src/converters/ConvertHtmlToPDF.java
+++ b/src/converters/ConvertHtmlToPDF.java
@@ -30,4 +30,5 @@ public class ConvertHtmlToPDF {
     public byte[] convert(String rawHtml) {
+        String safeHtml = customHtmlSanitizer.sanitize(rawHtml);
-        return processExecutor.runWeasyprint(rawHtml);
+        return processExecutor.runWeasyprint(safeHtml);
     }
"""
        sibling_files = {
            "src/converters/ConvertWebsiteToPDF.java": (
                "public class ConvertWebsiteToPDF {\n"
                "    public byte[] convertUrl(String targetUrl) {\n"
                "        return processExecutor.runWeasyprint(targetUrl);\n"
                "    }\n"
                "}\n"
            )
        }
        result = audit_git_diff_security_regressions(
            diff_text,
            sibling_files=sibling_files,
        )
        self.assertEqual(result["merge_decision"], "BLOCK_MERGE")
        rule_ids = [f["rule_id"] for f in result["findings"]]
        self.assertIn("SNIPER-PR-INCOMPLETE-SIBLING-03", rule_ids)

        sib_finding = next(
            f
            for f in result["findings"]
            if f["rule_id"] == "SNIPER-PR-INCOMPLETE-SIBLING-03"
        )
        self.assertEqual(sib_finding["cwe"], "CWE-863")
        self.assertEqual(
            sib_finding["sibling_file"],
            "src/converters/ConvertWebsiteToPDF.java",
        )
        self.assertEqual(
            sib_finding["patched_file"],
            "src/converters/ConvertHtmlToPDF.java",
        )

    def test_clean_pr_parameterized_query_approves_merge(self) -> None:
        diff_text = """diff --git a/app/db/users.py b/app/db/users.py
--- a/app/db/users.py
+++ b/app/db/users.py
@@ -10,3 +10,4 @@ def get_user_by_id(cursor, user_id: int):
+    cursor.execute("SELECT id, email FROM users WHERE id = %s", (user_id,))
     return cursor.fetchone()
"""
        result = audit_git_diff_security_regressions(diff_text)
        self.assertEqual(result["finding_count"], 0)
        self.assertEqual(result["merge_decision"], "APPROVE")
        self.assertEqual(result["review_comments"], [])

    def test_vulnerable_websocket_handler_flags_state_skip(self) -> None:
        ws_code = """
ws.on("message", async (raw) => {
    const msg = JSON.parse(raw.toString());
    switch (msg.type) {
        case "CONNECT":
            ws.state = "CONNECTED";
            break;
        case "AUTH":
            if (verifyToken(msg.token)) {
                ws.isAuthenticated = true;
                ws.state = "AUTHENTICATED";
            }
            break;
        case "TRANSFER_FUNDS":
            await wallet.transfer(msg.toAccount, msg.amount);
            break;
    }
});
"""
        result = audit_stateful_protocol_state_machine(
            ws_code,
            filename="wallet_ws.ts",
        )
        self.assertEqual(result["format"], "sniper-stateful-protocol-audit/1")
        self.assertIn("AUTH", result["detected_states"])
        self.assertIn("TRANSFER_FUNDS", result["detected_states"])
        self.assertIn("TRANSFER_FUNDS", result["unprotected_terminal_actions"])

        rule_ids = [f["rule_id"] for f in result["findings"]]
        self.assertIn("SNIPER-STATE-SKIP-01", rule_ids)
        self.assertIn("SNIPER-STATE-REPLAY-02", rule_ids)

    def test_guarded_websocket_handler_has_zero_findings(self) -> None:
        guarded_ws_code = """
ws.on("message", async (raw) => {
    const msg = JSON.parse(raw.toString());
    if (msg.seq <= ws.lastSeq) {
        return;
    }
    ws.lastSeq = msg.seq;
    switch (msg.type) {
        case "AUTH":
            if (verifyToken(msg.token)) {
                ws.isAuthenticated = true;
            }
            break;
        case "TRANSFER_FUNDS":
            if (!ws.isAuthenticated) {
                return;
            }
            await wallet.transfer(msg.toAccount, msg.amount);
            break;
    }
});
"""
        result = audit_stateful_protocol_state_machine(
            guarded_ws_code,
            filename="wallet_ws_safe.ts",
        )
        self.assertEqual(result["finding_count"], 0)
        self.assertEqual(result["unprotected_terminal_actions"], [])

    def test_simulate_out_of_order_state_sequence_finds_bypass(self) -> None:
        vulnerable_spec = {
            "initial_state": "CONNECTED",
            "required_predecessors": {
                "AUTHENTICATED": ["CONNECTED"],
                "MFA_VERIFIED": ["AUTHENTICATED"],
                "TRANSFER_FUNDS": ["MFA_VERIFIED"],
            },
            "enforced_guards": {
                "AUTHENTICATED": ["CONNECTED"],
                "MFA_VERIFIED": ["AUTHENTICATED"],
                "TRANSFER_FUNDS": [],
            },
        }
        res = simulate_out_of_order_state_sequence(vulnerable_spec)
        self.assertEqual(res["format"], "sniper-stateful-sequence-fuzz-proof/1")
        self.assertTrue(res["bypass_found"])
        self.assertIn(["CONNECTED", "TRANSFER_FUNDS"], res["bypass_sequences"])
        self.assertIn(
            ["CONNECTED", "AUTHENTICATED", "TRANSFER_FUNDS"],
            res["bypass_sequences"],
        )

        safe_spec = {
            "initial_state": "CONNECTED",
            "required_predecessors": {
                "AUTHENTICATED": ["CONNECTED"],
                "MFA_VERIFIED": ["AUTHENTICATED"],
                "TRANSFER_FUNDS": ["MFA_VERIFIED"],
            },
            "enforced_guards": {
                "AUTHENTICATED": ["CONNECTED"],
                "MFA_VERIFIED": ["AUTHENTICATED"],
                "TRANSFER_FUNDS": ["MFA_VERIFIED"],
            },
        }
        safe_res = simulate_out_of_order_state_sequence(safe_spec)
        self.assertFalse(safe_res["bypass_found"])
        self.assertEqual(safe_res["bypass_sequences"], [])


if __name__ == "__main__":
    unittest.main()
