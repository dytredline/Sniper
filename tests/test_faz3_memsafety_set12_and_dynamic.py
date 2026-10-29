"""Faz 3 — C/C++ Bellek Güvenliği Bağımsız Heldout Set 12, İzole Dinamik ASan Koşucusu ve Raporlama Testleri."""
from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest

APP_DIR = Path(__file__).resolve().parent.parent
if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))

import cli_reports
import memsafety_c
import memsafety_dynamic


HELDOUT_SET_12_VULNERABLE: list[tuple[str, str, str]] = [
    (
        "set12_uaf.c",
        "CWE-416",
        """
#include <stdlib.h>
int set12_vuln_uaf(void) {
    int *slot = (int *)malloc(sizeof(int) * 4);
    if (!slot) return -1;
    slot[0] = 42;
    free(slot);
    return slot[0];
}
""",
    ),
    (
        "set12_double_free.c",
        "CWE-415",
        """
#include <stdlib.h>
void set12_vuln_double_free(void) {
    char *pkt = (char *)malloc(64);
    if (!pkt) return;
    free(pkt);
    free(pkt);
}
""",
    ),
    (
        "set12_heap_overflow.c",
        "CWE-122",
        """
#include <stdlib.h>
#include <string.h>
char *set12_vuln_heap_overflow(void) {
    char *buf = (char *)malloc(8);
    if (!buf) return NULL;
    strcpy(buf, "0123456789ABCDEF");
    return buf;
}
""",
    ),
    (
        "set12_int_overflow_alloc.c",
        "CWE-190",
        """
#include <stdlib.h>
int *set12_vuln_int_overflow_alloc(size_t count) {
    int *records = (int *)malloc(count * sizeof(int));
    return records;
}
""",
    ),
    (
        "set12_non_base_free.c",
        "CWE-761",
        """
#include <stdlib.h>
void set12_vuln_non_base_free(void) {
    char *buf = (char *)malloc(64);
    if (!buf) return;
    free(buf + 4);
}
""",
    ),
    (
        "set12_wchar_underalloc.c",
        "CWE-122",
        """
#include <stdlib.h>
#include <wchar.h>
wchar_t *set12_vuln_wchar_underalloc(const wchar_t *src) {
    wchar_t *dst = (wchar_t *)malloc(wcslen(src) + 1);
    if (!dst) return NULL;
    wcscpy(dst, src);
    return dst;
}
""",
    ),
]

HELDOUT_SET_12_SAFE: list[tuple[str, str]] = [
    (
        "set12_safe_uaf.c",
        """
#include <stdlib.h>
int set12_safe_uaf(void) {
    int *slot = (int *)malloc(sizeof(int) * 4);
    if (!slot) return -1;
    slot[0] = 42;
    int val = slot[0];
    free(slot);
    slot = NULL;
    return val;
}
""",
    ),
    (
        "set12_safe_double_free.c",
        """
#include <stdlib.h>
void set12_safe_double_free(void) {
    char *pkt = (char *)malloc(64);
    if (!pkt) return;
    free(pkt);
    pkt = NULL;
}
""",
    ),
    (
        "set12_safe_heap_overflow.c",
        """
#include <stdio.h>
#include <stdlib.h>
char *set12_safe_heap_overflow(void) {
    char *buf = (char *)malloc(32);
    if (!buf) return NULL;
    snprintf(buf, 32, "%s", "0123456789ABCDEF");
    return buf;
}
""",
    ),
    (
        "set12_safe_int_overflow_alloc.c",
        """
#include <stdint.h>
#include <stdlib.h>
int *set12_safe_int_overflow_alloc(size_t count) {
    if (count > SIZE_MAX / sizeof(int)) {
        return NULL;
    }
    int *records = (int *)malloc(count * sizeof(int));
    return records;
}
""",
    ),
    (
        "set12_safe_non_base_free.c",
        """
#include <stdlib.h>
void set12_safe_non_base_free(void) {
    char *buf = (char *)malloc(64);
    if (!buf) return;
    char *payload = buf + 4;
    payload[0] = 'X';
    free(buf);
}
""",
    ),
    (
        "set12_safe_wchar_underalloc.c",
        """
#include <stdlib.h>
#include <wchar.h>
wchar_t *set12_safe_wchar_underalloc(const wchar_t *src) {
    size_t n = wcslen(src);
    if (n > 4096) return NULL;
    wchar_t *dst = (wchar_t *)calloc(n + 1, sizeof(wchar_t));
    if (!dst) return NULL;
    wmemcpy(dst, src, n);
    dst[n] = L'\\0';
    return dst;
}
""",
    ),
]


class TestFaz3MemsafetySet12AndDynamic(unittest.TestCase):
    def test_heldout_set12_recall_and_zero_false_positives(self) -> None:
        detected = 0
        for fname, expected_cwe, code in HELDOUT_SET_12_VULNERABLE:
            findings = memsafety_c.analyze_c_memory(code, fname)
            cwes = {f.cwe for f in findings}
            self.assertIn(expected_cwe, cwes, f"{fname} içinde {expected_cwe} tespit edilemedi: {findings}")
            detected += 1

        recall = detected / len(HELDOUT_SET_12_VULNERABLE)
        self.assertGreaterEqual(recall, 0.90)
        self.assertEqual(detected, 6)

        false_positives = 0
        for fname, safe_code in HELDOUT_SET_12_SAFE:
            findings = memsafety_c.analyze_c_memory(safe_code, fname)
            self.assertEqual(findings, [], f"Güvenli {fname} için yanlış pozitif üretildi: {findings}")
            false_positives += len(findings)
        self.assertEqual(false_positives, 0)

    def test_extended_c_memory_hazards_pointer_increment_and_struct_memset(self) -> None:
        code_ptr_inc = """
#include <stdlib.h>
void bad_cursor_free(void) {
    char *p = (char *)malloc(32);
    if (!p) return;
    p++;
    free(p);
}
"""
        ext = memsafety_c.detect_extended_c_memory_hazards(code_ptr_inc, "cursor.c")
        self.assertTrue(any(f.kind == "non_base_free" and f.cwe == "CWE-761" for f in ext))

        fn_zeroed = """
void init_packet(struct Packet *pkt) {
    memset(&pkt->buf, 0, sizeof(pkt->buf));
}
"""
        self.assertTrue(memsafety_c.is_struct_field_memset_zeroed(fn_zeroed, "pkt->buf"))
        self.assertFalse(memsafety_c.is_struct_field_memset_zeroed("int x = 0;", "pkt->buf"))

    def test_isolated_asan_dynamic_proof_requires_human_approval(self) -> None:
        with self.assertRaises(PermissionError):
            memsafety_dynamic.run_isolated_asan_dynamic_proof(
                "int main(void) { return 0; }",
                human_approved=False,
            )

    def test_isolated_asan_dynamic_proof_reproduces_uaf_and_passes_clean(self) -> None:
        uaf_c = """
#include <stdlib.h>
volatile int sink;
int main(void) {
    int *p = (int *)malloc(sizeof(int) * 4);
    if (!p) return 1;
    p[0] = 99;
    free(p);
    sink = p[0];
    return 0;
}
"""
        proof = memsafety_dynamic.run_isolated_asan_dynamic_proof(
            uaf_c,
            human_approved=True,
            timeout_sec=5,
            memory_limit_mb=256,
        )
        self.assertEqual(proof["format"], "sniper-isolated-asan-dynamic-proof/1")
        self.assertTrue(proof["human_approved"])
        self.assertEqual(proof["sandbox_profile"]["landlock_abi"], 8)
        self.assertTrue(proof["sandbox_profile"]["no_new_privs"])
        self.assertTrue(proof["reproduced"])
        self.assertIn("use-after-free", proof["asan_error_kind"])
        self.assertEqual(len(proof["evidence_sha256"]), 64)

        clean_c = """
#include <stdlib.h>
int main(void) {
    int *p = (int *)malloc(sizeof(int) * 4);
    if (!p) return 1;
    p[0] = 7;
    int r = p[0];
    free(p);
    return r == 7 ? 0 : 2;
}
"""
        clean_proof = memsafety_dynamic.run_isolated_asan_dynamic_proof(
            clean_c,
            human_approved=True,
            timeout_sec=5,
            memory_limit_mb=256,
        )
        self.assertFalse(clean_proof["reproduced"])
        self.assertEqual(clean_proof["exit_code"], 0)

    def test_cli_reports_faz1_to_faz3_exports(self) -> None:
        sample_report = {
            "project_name": "gitlab-demo",
            "findings": [
                {
                    "id": "F-1",
                    "stage": "entry",
                    "cwe": "CWE-20",
                    "severity": "high",
                    "title": "Untrusted OAuth redirect_uri parameter",
                    "file": "app/controllers/oauth_controller.rb",
                    "line": 14,
                    "shared_state_keys": ["oauth_token"],
                    "e2e_red_green_verified": True,
                    "confidence": 0.98,
                },
                {
                    "id": "F-2",
                    "stage": "impact",
                    "cwe": "CWE-78",
                    "severity": "critical",
                    "title": "Command execution via leaked oauth_token",
                    "file": "app/services/runner_service.rb",
                    "line": 88,
                    "shared_state_keys": ["oauth_token"],
                },
            ],
        }
        ag = json.loads(cli_reports.export_shared_state_attack_graph_json(sample_report))
        self.assertEqual(ag["format"], "sniper-shared-state-attack-graph/1")
        self.assertGreaterEqual(ag["chain_count"], 1)

        cve_bundle = json.loads(cli_reports.export_cve_submission_bundle_json(sample_report))
        self.assertEqual(cve_bundle["format"], "sniper-cve-submission-payloads/1")
        self.assertEqual(len(cve_bundle["ghsa_payloads"]), 2)
        self.assertEqual(len(cve_bundle["hackerone_payloads"]), 2)

        tiers = json.loads(cli_reports.export_evidence_tiered_triage_json(sample_report))
        self.assertEqual(len(tiers), 2)
        self.assertEqual(tiers[0]["evidence_tier"], "VERIFIED_PRODUCT_E2E_RED_GREEN")
        self.assertTrue(tiers[0]["auto_promote_allowed"])
        self.assertEqual(tiers[1]["evidence_tier"], "STATIC_CANDIDATE")
        self.assertFalse(tiers[1]["auto_promote_allowed"])


if __name__ == "__main__":
    unittest.main()
