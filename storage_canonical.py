"""
Shared canonical comparison helpers for storage.py and scan_diff.py.

Tek kaynak: önem derecesi normalizasyonu, sıralama anahtarı, bulgu kimliği,
küme karşılaştırması, sayım ve filtre burada tanımlanır. storage.py ve
scan_diff.py yalnızca bu yardımcıları kullanır; kopya üretmez.
"""
import json
from typing import Any


# Önem derecesi sıralaması (Critical → High → Medium → Low → Info)
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
KNOWN_SEVERITIES = tuple(SEVERITY_ORDER)


def _normalize_severity(value: Any) -> str:
    """Return a safe, canonical severity value for sorting and counting."""
    if value is None:
        return "info"
    normalized = str(value).strip().lower()
    return normalized or "info"


def _severity_key(severity: Any) -> tuple:
    """Önem derecesine göre deterministik sıralama anahtarı; bilinmeyenler en sona."""
    normalized = _normalize_severity(severity)
    order = SEVERITY_ORDER.get(normalized, 5)
    return (order, normalized)


def _finding_sort_key(finding: dict) -> tuple:
    """Bulgu listeleri için kararlı sıralama: önem, başlık, kimlik."""
    return (
        _severity_key(finding.get("severity", "info")),
        str(finding.get("title") or "").casefold(),
        str(finding.get("id") or ""),
    )


def _finding_key(finding: Any) -> tuple[str, str]:
    """Build a stable identity even when imported findings have no id."""
    if not isinstance(finding, dict):
        return ("invalid", json.dumps(finding, ensure_ascii=False, sort_keys=True, default=str))

    raw_id = finding.get("id")
    normalized_id = str(raw_id).strip() if raw_id is not None else ""
    if normalized_id:
        return ("id", normalized_id)

    fingerprint = {
        field: finding.get(field)
        for field in ("title", "category", "affected_asset", "description")
    }
    return ("fingerprint", json.dumps(fingerprint, ensure_ascii=False, sort_keys=True, default=str))


def _compare_finding_sets(
    previous_findings: list,
    current_findings: list,
    *,
    sort_key=_finding_sort_key,
) -> tuple:
    """
    Canonical finding comparison - single source for set operations.

    Returns:
        (new_findings, resolved_findings, persistent_findings)
        Each is a sorted list of findings (new/persistent from current, resolved from previous).
    """
    # Index by explicit ID, with a stable content fingerprint for imported
    # findings that do not carry one. Do not silently drop such findings.
    by_id_prev = {_finding_key(f): f for f in previous_findings if isinstance(f, dict)}
    by_id_curr = {_finding_key(f): f for f in current_findings if isinstance(f, dict)}

    # Set operations
    new_ids = by_id_curr.keys() - by_id_prev.keys()
    resolved_ids = by_id_prev.keys() - by_id_curr.keys()
    persistent_ids = by_id_prev.keys() & by_id_curr.keys()

    # Build lists and sort
    new_findings = [by_id_curr[i] for i in new_ids]
    resolved_findings = [by_id_prev[i] for i in resolved_ids]
    persistent_findings = [by_id_curr[i] for i in persistent_ids]

    # Deterministic sorting
    new_findings.sort(key=sort_key)
    resolved_findings.sort(key=sort_key)
    persistent_findings.sort(key=sort_key)

    return new_findings, resolved_findings, persistent_findings


def _count_by_severity(findings: list) -> dict:
    """Count findings by severity; unknown or missing values count as info."""
    counts = {severity: 0 for severity in KNOWN_SEVERITIES}
    for f in findings:
        severity = _normalize_severity(f.get("severity") if isinstance(f, dict) else None)
        if severity in counts:
            counts[severity] += 1
        else:
            counts["info"] += 1
    return counts


def _filter_by_severity(findings: list, severity_filter: Any) -> list:
    """Return findings matching the requested severity; None or empty returns all."""
    if severity_filter is None or str(severity_filter).strip() == "":
        return list(findings)
    wanted = _normalize_severity(severity_filter)
    return [f for f in findings if isinstance(f, dict) and _normalize_severity(f.get("severity")) == wanted]


def _count_filtered_by_severity(findings: list, severity_filter: Any) -> dict:
    """
    Count filtered findings by severity; returns counts matching the filtered list.
    
    If severity_filter is None or empty, returns counts of all findings.
    If severity_filter is set, returns counts only for the filtered severity
    (to match the filtered finding list returned by _filter_by_severity).
    """
    if severity_filter is None or str(severity_filter).strip() == "":
        return _count_by_severity(findings)
    
    # For filtered results, only the filtered severity should have a non-zero count
    # to match the filtered finding list
    wanted = _normalize_severity(severity_filter)
    filtered_findings = _filter_by_severity(findings, severity_filter)
    counts = {severity: 0 for severity in KNOWN_SEVERITIES}
    
    # Count the filtered findings (which should all be of the wanted severity)
    for f in filtered_findings:
        severity = _normalize_severity(f.get("severity") if isinstance(f, dict) else None)
        if severity in counts:
            counts[severity] += 1
        else:
            counts["info"] += 1
    
    return counts
