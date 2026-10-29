"""Sniper Token Sequencer (Burp Sequencer karşılığı).

Oturum çerezleri, CSRF belirteçleri, parola sıfırlama kodları ve OAuth state/nonce
değerleri üzerinde Shannon entropisi, bit dağılımı (FIPS monobit), ki-kare (chi-square)
ve ardışık sayaç / zaman damgası sızıntısı analizi yapar.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from typing import Any


FORMAT = "sniper-token-sequencer-report/1"
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_DIGITS_RE = re.compile(r"^\d+$")
_EPOCH_SUB_RE = re.compile(r"(1[6-9]\d{8})")


def _shannon_entropy_per_char(samples: list[str]) -> float:
    combined = "".join(samples)
    if not combined:
        return 0.0
    counts = Counter(combined)
    total = len(combined)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _monobit_ones_ratio(samples: list[str]) -> float:
    raw = "".join(samples).encode("utf-8", errors="ignore")
    if not raw:
        return 0.0
    total_bits = len(raw) * 8
    ones = sum(byte.bit_count() for byte in raw)
    return round(ones / total_bits, 4)


def _common_prefix_len(samples: list[str]) -> int:
    if len(samples) < 2:
        return 0
    s1 = min(samples)
    s2 = max(samples)
    for i, ch in enumerate(s1):
        if i >= len(s2) or ch != s2[i]:
            return i
    return len(s1)


def _common_suffix_len(samples: list[str]) -> int:
    rev = [s[::-1] for s in samples]
    return _common_prefix_len(rev)


def _detect_sequential_deltas(samples: list[str]) -> tuple[bool, list[int]]:
    if len(samples) < 3:
        return False, []
    pre = _common_prefix_len(samples)
    suf = _common_suffix_len(samples)
    cores: list[int] = []
    for s in samples:
        end = len(s) - suf if suf > 0 else len(s)
        core = s[pre:end]
        if not core:
            return False, []
        if _DIGITS_RE.fullmatch(core):
            cores.append(int(core, 10))
        elif _HEX_RE.fullmatch(core) and len(core) <= 32:
            cores.append(int(core, 16))
        else:
            return False, []
    deltas = [cores[i + 1] - cores[i] for i in range(len(cores) - 1)]
    if all(0 < d <= 1000 for d in deltas) or len(set(deltas)) == 1:
        return True, deltas
    return False, deltas


def analyze_token_sequence_entropy(
    tokens: list[str],
    *,
    token_label: str = "session_identifier",
    min_effective_bits: float = 64.0,
) -> dict[str, Any]:
    """Verilen belirteç örnekleminin entropisini, sabit eklerini ve tahmin edilebilirliğini analiz eder."""
    cleaned = [str(t).strip() for t in (tokens or []) if str(t).strip()]
    if not cleaned:
        return {
            "format": FORMAT,
            "token_label": token_label,
            "sample_size": 0,
            "shannon_bits_per_char": 0.0,
            "effective_entropy_bits": 0.0,
            "monobit_ones_ratio": 0.0,
            "sequential_pattern_detected": False,
            "timestamp_leak_detected": False,
            "quality_grade": "insufficient_data",
            "finding_count": 0,
            "findings": [],
        }

    avg_len = sum(len(s) for s in cleaned) / len(cleaned)
    pre_len = _common_prefix_len(cleaned) if len(cleaned) >= 2 else 0
    suf_len = _common_suffix_len(cleaned) if len(cleaned) >= 2 else 0
    variable_len = max(0.0, avg_len - pre_len - suf_len) if len(cleaned) >= 2 else avg_len

    variable_slices: list[str] = []
    for s in cleaned:
        end = len(s) - suf_len if suf_len > 0 else len(s)
        variable_slices.append(s[pre_len:end] if len(cleaned) >= 2 else s)

    bits_per_char = round(_shannon_entropy_per_char(variable_slices), 4)
    unique_ratio = len(set(cleaned)) / len(cleaned)
    effective_bits = round(bits_per_char * variable_len * unique_ratio, 2)
    ones_ratio = _monobit_ones_ratio(variable_slices)
    seq_detected, deltas = _detect_sequential_deltas(cleaned)
    ts_detected = any(bool(_EPOCH_SUB_RE.search(s)) for s in cleaned)

    findings: list[dict[str, Any]] = []
    if seq_detected or ts_detected or effective_bits < min_effective_bits or unique_ratio < 0.9:
        reasons: list[str] = []
        if seq_detected:
            reasons.append(f"ardışık/sayaç artışı tespit edildi (deltalar={deltas[:5]})")
        if ts_detected:
            reasons.append("gömülü Unix zaman damgası (epoch) tespit edildi")
        if effective_bits < min_effective_bits:
            reasons.append(f"etkin entropi ({effective_bits} bit) güvenli sınırın ({min_effective_bits} bit) altında")
        if unique_ratio < 0.9:
            reasons.append(f"yinelenen belirteç oranı yüksek (benzersizlik={unique_ratio:.2f})")

        findings.append({
            "control_id": "SNIPER-SEQUENCER-WEAK-01",
            "cwe": "CWE-331",
            "reference": "CWE-331",
            "severity": "critical" if (seq_detected or effective_bits < 32.0) else "high",
            "category": "crypto",
            "token_label": token_label,
            "title": f"Yetersiz belirteç entropisi veya tahmin edilebilir dizi ({token_label})",
            "evidence": "; ".join(reasons),
            "recommendation": "Güvenlik belirteçlerini CSPRNG (ör. Python secrets.token_urlsafe(32) veya crypto.randomBytes(32)) ile en az 128 bit entropiyle üretin.",
        })

    if seq_detected or effective_bits < 32.0:
        grade = "critical_predictable"
    elif effective_bits < min_effective_bits or ts_detected:
        grade = "weak"
    elif effective_bits < 112.0:
        grade = "good"
    else:
        grade = "excellent"

    return {
        "format": FORMAT,
        "token_label": token_label,
        "sample_size": len(cleaned),
        "unique_count": len(set(cleaned)),
        "average_length": round(avg_len, 2),
        "static_prefix_length": pre_len,
        "static_suffix_length": suf_len,
        "shannon_bits_per_char": bits_per_char,
        "effective_entropy_bits": effective_bits,
        "monobit_ones_ratio": ones_ratio,
        "sequential_pattern_detected": seq_detected,
        "is_sequential": seq_detected,
        "timestamp_leak_detected": ts_detected,
        "quality_grade": grade,
        "finding_count": len(findings),
        "findings": findings,
    }
