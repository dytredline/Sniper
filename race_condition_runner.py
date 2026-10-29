"""Sniper Parallel Race Condition Runner (Burp Repeater 'Send group in parallel' karşılığı).

Tek kullanımlık kupon, bakiye çekimi, davet kabulü veya durum geçişi uç noktalarına
bariyer-senkronize (threading.Barrier) paralel istek grubu göndererek TOCTOU / çift harcama
(double-spend) yarış koşullarını deterministik olarak kanıtlar.
"""
from __future__ import annotations

import threading
import time
from typing import Any, Callable


FORMAT = "sniper-parallel-race-proof/1"
MAX_CONCURRENCY = 32


def run_barrier_synchronized_race_probe(
    worker_fn: Callable[[int], dict[str, Any]],
    *,
    concurrency: int = 8,
    expected_max_success: int = 1,
    timeout_sec: float = 5.0,
    operation_label: str = "POST /api/coupons/redeem",
) -> dict[str, Any]:
    """Bariyerle senkronize edilmiş N paralel iş parçacığını aynı anda serbest bırakarak TOCTOU yarış koşulunu test eder."""
    bounded_concurrency = max(2, min(int(concurrency or 8), MAX_CONCURRENCY))
    expected_cap = max(1, int(expected_max_success or 1))
    timeout_val = max(0.5, min(float(timeout_sec or 5.0), 15.0))

    barrier = threading.Barrier(bounded_concurrency, timeout=timeout_val)
    results: list[dict[str, Any] | None] = [None] * bounded_concurrency
    release_times_ns: list[int] = [0] * bounded_concurrency

    def _runner(slot: int) -> None:
        try:
            barrier.wait()
            release_times_ns[slot] = time.monotonic_ns()
            res = worker_fn(slot)
            results[slot] = dict(res) if isinstance(res, dict) else {"status_code": 200, "result": res}
        except Exception as exc:  # noqa: BLE001
            results[slot] = {"status_code": 500, "error": type(exc).__name__}

    threads = [
        threading.Thread(target=_runner, args=(i,), daemon=True)
        for i in range(bounded_concurrency)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=timeout_val)

    valid_releases = [ts for ts in release_times_ns if ts > 0]
    spread_us = round((max(valid_releases) - min(valid_releases)) / 1000.0, 2) if len(valid_releases) >= 2 else 0.0

    success_count = 0
    status_histogram: dict[str, int] = {}
    for item in results:
        if not isinstance(item, dict):
            continue
        code = int(item.get("status_code", item.get("status", 500)) or 500)
        key = str(code)
        status_histogram[key] = status_histogram.get(key, 0) + 1
        if 200 <= code < 300 and item.get("ok", True) is not False:
            success_count += 1

    race_reproduced = success_count > expected_cap
    findings: list[dict[str, Any]] = []
    if race_reproduced:
        findings.append({
            "control_id": "SNIPER-RACE-TOCTOU-01",
            "cwe": "CWE-362",
            "reference": "CWE-362",
            "severity": "critical",
            "category": "authz",
            "operation": operation_label,
            "title": f"Paralel tek-paket yarış koşulu (TOCTOU / Double-Spend) doğrulandı: {operation_label}",
            "evidence": (
                f"{bounded_concurrency} eşzamanlı istek ({spread_us} µs yayılım) sonucunda "
                f"en fazla {expected_cap} başarılı yanıt beklenirken {success_count} adet 2xx başarılı yanıt alındı."
            ),
            "recommendation": (
                "Durum değiştiren finansal/kupon/token işlemlerinde atomik veritabanı güncellemesi "
                "(UPDATE ... WHERE used = false), SELECT ... FOR UPDATE satır kilidi veya idempotency anahtarı kullanın."
            ),
        })

    return {
        "format": FORMAT,
        "operation": operation_label,
        "concurrency": bounded_concurrency,
        "expected_max_success": expected_cap,
        "actual_success_count": success_count,
        "race_reproduced": race_reproduced,
        "spread_microseconds": spread_us,
        "status_histogram": status_histogram,
        "finding_count": len(findings),
        "findings": findings,
    }
