"""Aggregate-only reader for an already generated Playwright JSON reporter file.

Does not run a browser, visit a target, retain a report, or disclose test details.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

MAX_BYTES = 60_000
MAX_FILES = 50
MAX_TESTS = 1_000
MAX_DEPTH = 16
STATUSES = ("expected", "skipped", "unexpected", "flaky")


def _nonnegative_int(value: Any, limit: int) -> bool:
    return type(value) is int and 0 <= value <= limit


def parse_playwright_json_summary(report: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(report, dict) or not isinstance(report.get("config"), dict):
        raise ValueError("Geçersiz Playwright JSON raporu")
    suites = report.get("suites")
    stats = report.get("stats")
    if not isinstance(suites, list) or not 1 <= len(suites) <= MAX_FILES:
        raise ValueError("Geçersiz Playwright JSON test grupları")
    if not isinstance(report.get("errors"), list) or not isinstance(stats, dict):
        raise ValueError("Geçersiz Playwright JSON rapor meta verisi")
    try:
        canonical = json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError, RecursionError) as exc:
        raise ValueError("Geçersiz Playwright JSON'u") from exc
    raw = canonical.encode("utf-8")
    if len(raw) > MAX_BYTES:
        raise ValueError("Playwright JSON raporu çok büyük")

    counts = {status: 0 for status in STATUSES}
    count = 0
    stack: list[tuple[Any, int]] = [(suite, 1) for suite in suites]
    while stack:
        suite, depth = stack.pop()
        if depth > MAX_DEPTH or not isinstance(suite, dict):
            raise ValueError("Geçersiz Playwright JSON test grubu")
        specs = suite.get("specs")
        children = suite.get("suites", [])
        if not isinstance(specs, list) or not isinstance(children, list):
            raise ValueError("Geçersiz Playwright JSON test grubu yapısı")
        if len(stack) + len(children) > MAX_TESTS:
            raise ValueError("Çok fazla Playwright test grubu")
        for child in children:
            stack.append((child, depth + 1))
        for spec in specs:
            if not isinstance(spec, dict) or not isinstance(spec.get("tests"), list):
                raise ValueError("Geçersiz Playwright JSON belirtimi")
            for test in spec["tests"]:
                count += 1
                if count > MAX_TESTS or not isinstance(test, dict):
                    raise ValueError("Geçersiz Playwright JSON testi")
                status = test.get("status")
                if status not in STATUSES or not isinstance(test.get("results"), list):
                    raise ValueError("Geçersiz Playwright JSON test sonucu")
                counts[status] += 1
    if count == 0:
        raise ValueError("Boş Playwright JSON raporu")
    for status in STATUSES:
        if not _nonnegative_int(stats.get(status), MAX_TESTS) or stats[status] != counts[status]:
            raise ValueError("Tutarsız Playwright JSON istatistikleri")
    return {
        "format": "playwright-json",
        "file_count": len(suites),
        "test_count": count,
        "outcome_counts": counts,
        "report_sha256": hashlib.sha256(raw).hexdigest(),
    }
