from __future__ import annotations

import hashlib
import json
from typing import Any

ALLOWED_STATES = {"open", "dismissed", "fixed", "auto_dismissed"}
ALLOWED_SEVERITIES = {"low", "medium", "high", "critical"}
DISMISSED_REASONS = ("fix_started", "inaccurate", "no_bandwidth", "not_used", "tolerable_risk", "unspecified")
MAX_ALERTS = 500


def _count_states(alerts: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"open": 0, "dismissed": 0, "fixed": 0, "auto_dismissed": 0}
    for alert in alerts:
        if not isinstance(alert, dict):
            raise ValueError("Her uyarı bir nesne olmalı")
        state_raw = alert.get("state")
        if not isinstance(state_raw, str):
            raise ValueError("state bir metin olmalı")
        # Reject any non-exact lowercase match
        if state_raw not in ALLOWED_STATES:
            raise ValueError("Geçersiz durum")
        counts[state_raw] += 1
    return counts


def _count_severities(alerts: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    for alert in alerts:
        if not isinstance(alert, dict):
            raise ValueError("Her uyarı bir nesne olmalı")
        advisory = alert.get("security_advisory")
        if not isinstance(advisory, dict):
            raise ValueError("security_advisory bir nesne olmalı")
        severity_raw = advisory.get("severity")
        if not isinstance(severity_raw, str):
            raise ValueError("security_advisory.severity bir metin olmalı")
        # Reject any non-exact lowercase match
        if severity_raw not in ALLOWED_SEVERITIES:
            raise ValueError("Geçersiz önem")
        counts[severity_raw] += 1
    return counts


def _count_open_severities(alerts: list[dict[str, Any]]) -> dict[str, int]:
    # State and advisory severity are validated before this aggregate is built.
    counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    for alert in alerts:
        if alert["state"] == "open":
            counts[alert["security_advisory"]["severity"]] += 1
    return counts


def _count_open_alerts_with_available_patched_version(alerts: list[dict[str, Any]]) -> int:
    count = 0
    for alert in alerts:
        if not isinstance(alert, dict):
            continue
        state_raw = alert.get("state")
        if not isinstance(state_raw, str) or state_raw != "open":
            continue
        vuln = alert.get("security_vulnerability")
        if not isinstance(vuln, dict):
            continue
        first_patched = vuln.get("first_patched_version")
        if not isinstance(first_patched, dict):
            continue
        identifier = first_patched.get("identifier")
        if not isinstance(identifier, str) or not identifier.strip():
            continue
        count += 1
    return count


def _count_dismissed_reasons(alerts: list[dict[str, Any]]) -> dict[str, int]:
    counts = {reason: 0 for reason in DISMISSED_REASONS}
    for alert in alerts:
        if alert["state"] != "dismissed":
            continue
        reason = alert.get("dismissed_reason")
        if reason is None:
            reason = "unspecified"
        elif not isinstance(reason, str) or reason not in counts or reason == "unspecified":
            raise ValueError("Geçersiz kapatma nedeni")
        counts[reason] += 1
    return counts


def parse_dependabot_alerts_summary(payload: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("payload bir JSON nesnesi olmalı")

    alerts = payload.get("alerts")
    if not isinstance(alerts, list):
        raise ValueError("alerts bir liste olmalı")

    if len(alerts) > MAX_ALERTS:
        raise ValueError("Çok fazla uyarı")

    alert_count = len(alerts)
    state_counts = _count_states(alerts)
    severity_counts = _count_severities(alerts)
    open_severity_counts = _count_open_severities(alerts)
    dismissed_reason_counts = _count_dismissed_reasons(alerts)
    open_alerts_with_available_patched_version = _count_open_alerts_with_available_patched_version(alerts)

    canonical = json.dumps(alerts, sort_keys=True, separators=(",", ":"))
    report_sha256 = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    return {
        "format": "dependabot-alerts",
        "alert_count": alert_count,
        "state_counts": state_counts,
        "severity_counts": severity_counts,
        "open_severity_counts": open_severity_counts,
        "dismissed_reason_counts": dismissed_reason_counts,
        "open_alerts_with_available_patched_version": open_alerts_with_available_patched_version,
        "report_sha256": report_sha256
    }
