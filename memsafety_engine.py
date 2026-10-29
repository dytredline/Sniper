"""Sniper Unified C/C++ Memory Safety Engine (memsafety_engine.py).

Re-exports and unifies static C/C++ memory safety analysis (`memsafety_c`) and
human-approved isolated dynamic ASan/UBSan verification (`memsafety_dynamic`).
"""
from __future__ import annotations

from typing import Any

from memsafety_c import (
    MemFinding,
    analyze_c_memory,
    analyze_text,
    detect_extended_c_memory_hazards,
    is_struct_field_memset_zeroed,
)
from memsafety_dynamic import run_isolated_asan_dynamic_proof

__all__ = [
    "MemFinding",
    "analyze_c_memory",
    "analyze_text",
    "detect_extended_c_memory_hazards",
    "is_struct_field_memset_zeroed",
    "run_isolated_asan_dynamic_proof",
    "evaluate_heldout_set_recall_and_fp",
]


def evaluate_heldout_set_recall_and_fp(
    vulnerable_cases: list[tuple[str, str, str]],
    safe_cases: list[tuple[str, str]],
) -> dict[str, Any]:
    """Evaluates recall and false-positive rate on a heldout C/C++ memory safety set."""
    detected = 0
    missed: list[str] = []
    for filename, expected_cwe, code in vulnerable_cases:
        findings = analyze_c_memory(code, filename)
        cwes = {f.cwe for f in findings}
        if expected_cwe in cwes:
            detected += 1
        else:
            missed.append(f"{filename}:{expected_cwe}")

    false_positives = 0
    fp_files: list[str] = []
    for filename, safe_code in safe_cases:
        findings = analyze_c_memory(safe_code, filename)
        if findings:
            false_positives += len(findings)
            fp_files.append(filename)

    total_vuln = max(1, len(vulnerable_cases))
    recall = round(detected / total_vuln, 4)
    return {
        "format": "sniper-memsafety-heldout-eval/1",
        "vulnerable_total": len(vulnerable_cases),
        "vulnerable_detected": detected,
        "recall": recall,
        "safe_total": len(safe_cases),
        "false_positives": false_positives,
        "gate_passed": recall >= 0.90 and false_positives == 0,
        "missed": missed,
        "fp_files": fp_files,
    }
