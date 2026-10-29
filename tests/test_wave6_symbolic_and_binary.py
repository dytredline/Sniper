from __future__ import annotations

import unittest

from binary_security_hardening_auditor import audit_binary_security_hardening
from symbolic_path_constraint_solver import (
    filter_unreachable_attack_chains,
    solve_path_constraints_and_synthesize_input,
)


class SymbolicPathConstraintSolverTests(unittest.TestCase):
    def test_sat_numeric_string_and_startswith_synthesizes_valid_witness(self) -> None:
        guards = [
            "10 < x <= 20",
            "x != 11",
            "amount < 0",
            "role != 'admin'",
            "path.startswith('/api/v1/')",
            "mode in ('fast', 'safe')",
            "mode != 'fast'",
        ]
        res = solve_path_constraints_and_synthesize_input(
            guards,
            route_params=["tenant_id"],
        )
        self.assertEqual(res["format"], "sniper-symbolic-path-constraint-proof/1")
        self.assertEqual(res["status"], "SAT")
        self.assertTrue(res["satisfiable"])
        self.assertFalse(res["false_positive_eliminated"])
        self.assertEqual(res["contradictions"], [])
        self.assertEqual(len(res["evidence_sha256"]), 64)

        witness = res["concrete_witness"]
        self.assertGreater(witness["x"], 10)
        self.assertLessEqual(witness["x"], 20)
        self.assertNotEqual(witness["x"], 11)
        self.assertEqual(witness["x"], 12)
        self.assertLess(witness["amount"], 0)
        self.assertEqual(witness["amount"], -1)
        self.assertNotEqual(witness["role"], "admin")
        self.assertTrue(str(witness["path"]).startswith("/api/v1/"))
        self.assertEqual(witness["mode"], "safe")
        self.assertIn("tenant_id", witness)

    def test_unsat_conflicting_numeric_bounds(self) -> None:
        res = solve_path_constraints_and_synthesize_input(
            ["amount > 500", "amount <= 100"]
        )
        self.assertEqual(res["status"], "UNSAT")
        self.assertFalse(res["satisfiable"])
        self.assertTrue(res["false_positive_eliminated"])
        self.assertEqual(res["concrete_witness"], {})
        self.assertGreaterEqual(len(res["contradictions"]), 1)

    def test_unsat_conflicting_string_role_constraints(self) -> None:
        res = solve_path_constraints_and_synthesize_input(
            ['role == "admin"', 'role == "guest"']
        )
        self.assertEqual(res["status"], "UNSAT")
        self.assertFalse(res["satisfiable"])
        self.assertTrue(res["false_positive_eliminated"])
        self.assertEqual(res["concrete_witness"], {})
        self.assertGreaterEqual(len(res["contradictions"]), 1)

    def test_multiline_source_snippet_and_boolean_contradiction(self) -> None:
        snippet = """
        if is_authenticated is True and step >= 2:
            if not is_authenticated:
                pass
        """
        res = solve_path_constraints_and_synthesize_input(snippet)
        self.assertEqual(res["status"], "UNSAT")
        self.assertTrue(res["false_positive_eliminated"])

    def test_filter_unreachable_attack_chains_separates_sat_and_unsat(self) -> None:
        chains = [
            {
                "chain_id": "CHAIN-REACHABLE-01",
                "guards": ["role == 'user'", "amount < 0", "step >= 2"],
                "steps": [{"guard": "path.startswith('/api/v1/')"}],
            },
            {
                "chain_id": "CHAIN-UNREACHABLE-02",
                "guards": ["amount > 500", "amount <= 100"],
            },
            {
                "chain_id": "CHAIN-UNREACHABLE-03",
                "steps": [
                    {"condition": "role == 'admin'"},
                    {"condition": "role != 'admin'"},
                ],
            },
        ]
        filtered = filter_unreachable_attack_chains(chains)
        self.assertEqual(filtered["format"], "sniper-symbolic-chain-filter/1")
        self.assertEqual(filtered["total_chains"], 3)
        self.assertEqual(filtered["reachable_count"], 1)
        self.assertEqual(filtered["eliminated_unsat_count"], 2)

        reachable = filtered["reachable_chains"][0]
        self.assertEqual(reachable["chain_id"], "CHAIN-REACHABLE-01")
        self.assertEqual(reachable["symbolic_status"], "SAT")
        self.assertEqual(reachable["concrete_witness"]["role"], "user")
        self.assertLess(reachable["concrete_witness"]["amount"], 0)
        self.assertGreaterEqual(reachable["concrete_witness"]["step"], 2)
        self.assertTrue(reachable["concrete_witness"]["path"].startswith("/api/v1/"))

        eliminated_ids = [c["chain_id"] for c in filtered["eliminated_unsat_chains"]]
        self.assertEqual(eliminated_ids, ["CHAIN-UNREACHABLE-02", "CHAIN-UNREACHABLE-03"])
        for c in filtered["eliminated_unsat_chains"]:
            self.assertEqual(c["symbolic_status"], "UNSAT")
            self.assertTrue(c["false_positive_eliminated"])
            self.assertTrue(len(c["contradictions"]) >= 1)


class BinarySecurityHardeningAuditorTests(unittest.TestCase):
    def test_hardened_elf_binary_produces_zero_findings(self) -> None:
        hardened_elf = (
            b"\x7fELF\x02\x01\x01\x00"
            b"__stack_chk_fail\x00"
            b"BIND_NOW\x00"
            b"GNU_RELRO\x00"
            b"__snprintf_chk\x00"
            b"__memcpy_chk\x00"
            b"RPATH=/usr/lib:/usr/local/lib\x00"
            b"GNU_STACK RW\x00"
        )
        report = audit_binary_security_hardening(hardened_elf, filename="libhardened.so")
        self.assertEqual(report["format"], "sniper-binary-security-hardening-audit/1")
        self.assertEqual(report["filename"], "libhardened.so")
        self.assertEqual(report["binary_format"], "ELF")
        self.assertTrue(report["hardening_features"]["stack_canary"])
        self.assertTrue(report["hardening_features"]["nx_enabled"])
        self.assertTrue(report["hardening_features"]["relro"])
        self.assertTrue(report["hardening_features"]["fortify_source"])
        self.assertEqual(report["finding_count"], 0)
        self.assertEqual(report["findings"], [])

    def test_unhardened_vulnerable_elf_detects_all_four_security_classes(self) -> None:
        raw_secret = "sk-live_super_secret_token_9876543210abcdef"
        vulnerable_elf = (
            b"\x7fELF\x02\x01\x01\x00"
            b"strcpy\x00"
            b"gets\x00"
            b"RPATH=/tmp:.:/opt/lib\x00"
            b"GNU_STACK RWE\x00"
            + raw_secret.encode("ascii")
            + b"\x00"
        )
        report = audit_binary_security_hardening(vulnerable_elf, filename="libvuln.so")
        self.assertEqual(report["binary_format"], "ELF")
        self.assertFalse(report["hardening_features"]["stack_canary"])
        self.assertFalse(report["hardening_features"]["nx_enabled"])
        self.assertFalse(report["hardening_features"]["relro"])
        self.assertEqual(report["finding_count"], 4)

        by_id = {f["id"]: f for f in report["findings"]}
        self.assertIn("SNIPER-BIN-HARDEN-01", by_id)
        self.assertIn("SNIPER-BIN-RPATH-02", by_id)
        self.assertIn("SNIPER-BIN-UNSAFE-SYM-03", by_id)
        self.assertIn("SNIPER-BIN-RODATA-SECRET-04", by_id)

        self.assertEqual(by_id["SNIPER-BIN-HARDEN-01"]["cwe"], "CWE-693")
        self.assertEqual(by_id["SNIPER-BIN-HARDEN-01"]["severity"], "medium")

        self.assertEqual(by_id["SNIPER-BIN-RPATH-02"]["cwe"], "CWE-426")
        self.assertEqual(by_id["SNIPER-BIN-RPATH-02"]["severity"], "high")

        self.assertEqual(by_id["SNIPER-BIN-UNSAFE-SYM-03"]["cwe"], "CWE-676")
        self.assertEqual(by_id["SNIPER-BIN-UNSAFE-SYM-03"]["severity"], "high")
        self.assertIn("strcpy", by_id["SNIPER-BIN-UNSAFE-SYM-03"]["unsafe_symbols"])
        self.assertIn("gets", by_id["SNIPER-BIN-UNSAFE-SYM-03"]["unsafe_symbols"])

        secret_finding = by_id["SNIPER-BIN-RODATA-SECRET-04"]
        self.assertEqual(secret_finding["cwe"], "CWE-798")
        self.assertEqual(secret_finding["severity"], "critical")
        self.assertEqual(secret_finding["category"], "secrets")
        self.assertNotIn(raw_secret, secret_finding["evidence"])
        self.assertIn("redacted:sha256:", secret_finding["evidence"])


if __name__ == "__main__":
    unittest.main()
