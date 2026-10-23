"""Bounded preview of k6's classic ``handleSummary(data)`` JSON output.

This is a report reader. It never invokes k6, stores the report, or returns
user-controlled metric, threshold, group, URL, or check names.
"""

from __future__ import annotations

import hashlib
import json
import math
from typing import Any


MAX_METRICS = 500
MAX_THRESHOLDS = 500
MAX_SAFE_COUNT = 2**53 - 1
MAX_DURATION_MS = 1_000_000_000


def _object(value: Any) -> bool:
    return isinstance(value, dict)


def parse_k6_handle_summary_json(report: dict[str, Any]) -> dict[str, Any]:
    """Return only fixed aggregate fields from classic k6 summary data.

    The new ``--new-machine-readable-summary`` format is intentionally not
    accepted. Classic ``handleSummary(data)`` includes root_group, state and a
    metrics mapping; accepting only the metrics key would make the two formats
    easy to confuse as they evolve.
    """
    if not _object(report) or any(key in report for key in ("$schema", "schema_version", "version")):
        raise ValueError("Desteklenmeyen k6 özet biçimi")
    if not _object(report.get("root_group")) or not _object(report.get("state")):
        raise ValueError("Klasik k6 handleSummary verisi gerekli")
    metrics = report.get("metrics")
    if not _object(metrics) or not 1 <= len(metrics) <= MAX_METRICS:
        raise ValueError("Geçersiz k6 metrikleri")

    http_reqs = metrics.get("http_reqs")
    if not _object(http_reqs) or http_reqs.get("type") != "counter":
        raise ValueError("http_reqs sayacı gerekli")
    req_values = http_reqs.get("values")
    if not _object(req_values):
        raise ValueError("Geçersiz http_reqs değerleri")
    request_count = req_values.get("count")
    if type(request_count) is not int or not 0 <= request_count <= MAX_SAFE_COUNT:
        raise ValueError("Geçersiz http_reqs sayısı")

    duration_p95: int | float | None = None
    if "http_req_duration" in metrics:
        duration = metrics["http_req_duration"]
        if not _object(duration) or duration.get("type") != "trend" or duration.get("contains") != "time":
            raise ValueError("Geçersiz http_req_duration metriği")
        values = duration.get("values")
        if not _object(values):
            raise ValueError("Geçersiz http_req_duration değerleri")
        if "p(95)" in values:
            candidate = values["p(95)"]
            if type(candidate) not in (int, float) or not math.isfinite(candidate) or not 0 <= candidate <= MAX_DURATION_MS:
                raise ValueError("Geçersiz http_req_duration p(95)")
            duration_p95 = candidate

    threshold_counts = {"passed": 0, "failed": 0}
    threshold_total = 0
    for metric in metrics.values():
        if not _object(metric):
            raise ValueError("Geçersiz k6 metriği")
        thresholds = metric.get("thresholds", {})
        if not _object(thresholds):
            raise ValueError("Geçersiz k6 eşikleri")
        threshold_total += len(thresholds)
        if threshold_total > MAX_THRESHOLDS:
            raise ValueError("Çok fazla k6 eşiği")
        for threshold in thresholds.values():
            if not _object(threshold) or type(threshold.get("ok")) is not bool:
                raise ValueError("Geçersiz k6 eşiği")
            threshold_counts["passed" if threshold["ok"] else "failed"] += 1

    try:
        canonical = json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ValueError("Geçersiz k6 JSON'u") from exc
    return {
        "format": "k6-handle-summary-json",
        "http_requests": request_count,
        "duration_p95_ms": duration_p95,
        "threshold_counts": threshold_counts,
        "report_sha256": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
    }

# The official k6-summary v1 JSON is separate from classic handleSummary data.
# Keep this reader narrow: it exposes only fixed numeric aggregates and a hash.
def _machine_number(value: Any, minimum: int | float | None = None) -> bool:
    if type(value) is int:
        return minimum is None or value >= minimum
    if type(value) is float:
        return math.isfinite(value) and (minimum is None or value >= minimum)
    return False


def _machine_metric(metric: Any) -> None:
    if not _object(metric) or not {"name", "type", "contains", "values"} <= set(metric):
        raise ValueError("Geçersiz k6 v1 metriği")
    name = metric["name"]
    kind = metric["type"]
    contains = metric["contains"]
    values = metric["values"]
    if not isinstance(name, str) or not name or len(name) > 512:
        raise ValueError("Geçersiz k6 v1 metrik adı")
    if kind not in ("counter", "gauge", "rate", "trend") or contains not in ("default", "time", "data"):
        raise ValueError("Geçersiz k6 v1 metrik türü")
    if not _object(values):
        raise ValueError("Geçersiz k6 v1 metrik değerleri")
    if kind == "counter":
        if set(values) != {"count"} or not _machine_number(values["count"], 0):
            raise ValueError("Geçersiz k6 v1 sayacı")
    elif kind == "gauge":
        if set(values) != {"value", "min", "max"} or not all(_machine_number(v) for v in values.values()):
            raise ValueError("Geçersiz k6 v1 göstergesi")
    elif kind == "rate":
        if set(values) != {"matches", "total", "rate"}:
            raise ValueError("Geçersiz k6 v1 oranı")
        matches, total, rate = values["matches"], values["total"], values["rate"]
        if (type(matches) is not int or type(total) is not int or
                matches < 0 or total < 0 or matches > total or
                not _machine_number(rate, 0) or rate > 1):
            raise ValueError("Geçersiz k6 v1 oranı")
    else:
        allowed = {"avg", "min", "med", "max", "p(90)", "p(95)"}
        if not set(values) <= allowed or not all(_machine_number(v) for v in values.values()):
            raise ValueError("Geçersiz k6 v1 eğilimi")


def parse_k6_machine_summary_v1(report: dict[str, Any]) -> dict[str, Any]:
    """Summarize official k6-summary 1.0.0 without exposing names or paths.

    The v1 metric schema carries no threshold results. Zero/zero below means
    unavailable, not that any threshold was evaluated or passed.
    """
    import re
    from datetime import datetime

    if not _object(report) or set(report) != {"version", "metadata", "config", "results"}:
        raise ValueError("Geçersiz k6 v1 özeti")
    if report["version"] != "1.0.0":
        raise ValueError("Desteklenmeyen k6 özet sürümü")
    metadata, config, results = report["metadata"], report["config"], report["results"]
    if not _object(metadata):
        raise ValueError("Geçersiz k6 v1 meta verisi")
    keys = set(metadata)
    if keys == {"generatedAt", "k6Version"}:
        generated_at, k6_version = metadata["generatedAt"], metadata["k6Version"]
    elif keys == {"generated_at", "k6_version"}:
        generated_at, k6_version = metadata["generated_at"], metadata["k6_version"]
    else:
        raise ValueError("Geçersiz k6 v1 meta verisi")
    if not isinstance(generated_at, str) or not re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})", generated_at):
        raise ValueError("Geçersiz k6 v1 zaman damgası")
    try:
        datetime.fromisoformat(generated_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("Geçersiz k6 v1 zaman damgası") from exc
    if not isinstance(k6_version, str) or not re.fullmatch(
            r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?",
            k6_version):
        raise ValueError("Geçersiz k6 sürümü")
    if not _object(config) or not {"execution", "duration"} <= set(config) or not set(config) <= {"execution", "duration", "script"}:
        raise ValueError("Geçersiz k6 v1 yapılandırması")
    if config["execution"] not in ("local", "cloud") or not _machine_number(config["duration"], 0):
        raise ValueError("Geçersiz k6 v1 yürütmesi")
    if "script" in config and not isinstance(config["script"], str):
        raise ValueError("Geçersiz k6 v1 betiği")
    if not _object(results) or not {"metrics"} <= set(results) or not set(results) <= {"metrics", "checks"}:
        raise ValueError("Geçersiz k6 v1 sonuçları")
    metrics = results["metrics"]
    if not isinstance(metrics, list) or not 1 <= len(metrics) <= MAX_METRICS:
        raise ValueError("Geçersiz k6 v1 metrikleri")

    by_name: dict[str, dict[str, Any]] = {}
    for metric in metrics:
        _machine_metric(metric)
        if metric["name"] in by_name:
            raise ValueError("Yinelenen k6 v1 metriği")
        by_name[metric["name"]] = metric

    requests = by_name.get("http_reqs")
    if requests is None or requests["type"] != "counter":
        raise ValueError("http_reqs sayacı gerekli")
    request_count = requests["values"]["count"]
    if type(request_count) is not int or not 0 <= request_count <= MAX_SAFE_COUNT:
        raise ValueError("Geçersiz http_reqs sayısı")

    duration_p95: int | float | None = None
    duration = by_name.get("http_req_duration")
    if duration is not None:
        if duration["type"] != "trend" or duration["contains"] != "time":
            raise ValueError("Geçersiz http_req_duration metriği")
        if "p(95)" in duration["values"]:
            candidate = duration["values"]["p(95)"]
            if not _machine_number(candidate, 0) or candidate > MAX_DURATION_MS:
                raise ValueError("Geçersiz http_req_duration p(95)")
            duration_p95 = candidate

    checks = results.get("checks")
    if checks is not None:
        if not _object(checks) or not set(checks) <= {"metrics", "results"}:
            raise ValueError("Geçersiz k6 v1 denetimleri")
        check_metrics = checks.get("metrics", [])
        check_results = checks.get("results", [])
        if (not isinstance(check_metrics, list) or len(check_metrics) > MAX_METRICS or
                not isinstance(check_results, list) or len(check_results) > MAX_THRESHOLDS):
            raise ValueError("Çok fazla k6 v1 denetimi")
        for metric in check_metrics:
            _machine_metric(metric)
        for check in check_results:
            if not _object(check) or set(check) != {"name", "passes", "fails"}:
                raise ValueError("Geçersiz k6 v1 denetimi")
            if (not isinstance(check["name"], str) or
                    type(check["passes"]) is not int or type(check["fails"]) is not int or
                    not 0 <= check["passes"] <= MAX_SAFE_COUNT or
                    not 0 <= check["fails"] <= MAX_SAFE_COUNT):
                raise ValueError("Geçersiz k6 v1 denetimi")

    try:
        canonical = json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError, RecursionError) as exc:
        raise ValueError("Geçersiz k6 v1 JSON'u") from exc
    return {
        "format": "k6-machine-summary-v1",
        "http_requests": request_count,
        "duration_p95_ms": duration_p95,
        "threshold_counts": {"passed": 0, "failed": 0},
        "report_sha256": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
    }
