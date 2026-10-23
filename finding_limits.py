from __future__ import annotations

from contextvars import ContextVar
import functools
from typing import Any, Callable, TypeVar


INLINE_FINDING_LIMIT = 300
PROJECT_FINDING_LIMIT = 2_000
MAX_FINDING_GROUPS = 500

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_PROJECT_SCOPE_DEPTH: ContextVar[int] = ContextVar("sniper_project_scope_depth", default=0)

_F = TypeVar("_F", bound=Callable[..., Any])


def project_scan_scope(func: _F) -> _F:
    """Decorate project-level auditors so nested per-file caps are deferred."""

    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        token = _PROJECT_SCOPE_DEPTH.set(_PROJECT_SCOPE_DEPTH.get() + 1)
        try:
            return func(*args, **kwargs)
        finally:
            _PROJECT_SCOPE_DEPTH.reset(token)

    return wrapper  # type: ignore[return-value]


def _severity_rank(finding: dict[str, Any]) -> int:
    return _SEVERITY_RANK.get(str(finding.get("severity", "")).lower(), 5)


def _group_key(finding: dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(finding.get("title", "")),
        str(finding.get("control_id", "")),
        str(finding.get("cwe", "") or finding.get("reference", "")),
    )


def cap_findings(
    findings: list[dict[str, Any]],
    limit: int = INLINE_FINDING_LIMIT,
) -> tuple[list[dict[str, Any]], int, bool]:
    """Bound response size without hiding any distinct finding type.

    Selection order:
    1. the first occurrence of every distinct finding type (title/control/CWE),
       most severe types first, so a single flooded rule can never push a
       different issue out of the response;
    2. remaining slots filled by severity, then original order.

    Returns ``(kept, total, truncated)``. Kept findings preserve their original
    relative order. Scores must be computed on the full list before calling.
    Use :func:`summarize_finding_groups` on the full list to report counts for
    every type, including the occurrences that were not returned.
    """
    total = len(findings)
    if total <= limit:
        return findings, total, False
    if limit < PROJECT_FINDING_LIMIT and _PROJECT_SCOPE_DEPTH.get() > 0:
        # Inside a project scan the per-file cap is deferred to the project-level
        # cap so aggregated counts and groups stay exact.
        return findings, total, False
    first_index: dict[tuple[str, str, str], int] = {}
    for index, finding in enumerate(findings):
        first_index.setdefault(_group_key(finding), index)
    representatives = sorted(first_index.values(), key=lambda index: (_severity_rank(findings[index]), index))
    selected = set(representatives[:limit])
    if len(selected) < limit:
        remaining = sorted(
            (index for index in range(total) if index not in selected),
            key=lambda index: (_severity_rank(findings[index]), index),
        )
        selected.update(remaining[: limit - len(selected)])
    kept = [findings[index] for index in sorted(selected)]
    return kept, total, True


def summarize_finding_groups(
    findings: list[dict[str, Any]],
    max_groups: int = MAX_FINDING_GROUPS,
) -> list[dict[str, Any]]:
    """Count every distinct finding type in the full (uncapped) list."""
    groups: dict[tuple[str, str, str], dict[str, Any]] = {}
    for finding in findings:
        key = _group_key(finding)
        group = groups.get(key)
        if group is None:
            group = {
                "title": key[0],
                "control_id": key[1],
                "cwe": key[2],
                "severity": str(finding.get("severity", "")),
                "count": 0,
                "first_location": (
                    f"{finding.get('file', '')}:{finding.get('line', '')}"
                    if finding.get("file") else str(finding.get("evidence", ""))[:160]
                ),
            }
            groups[key] = group
        group["count"] += 1
        if _severity_rank(finding) < _SEVERITY_RANK.get(group["severity"].lower(), 5):
            group["severity"] = str(finding.get("severity", ""))
    ordered = sorted(groups.values(), key=lambda item: (_SEVERITY_RANK.get(item["severity"].lower(), 5), -item["count"], item["title"]))
    return ordered[:max_groups]
