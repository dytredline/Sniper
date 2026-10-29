"""Deterministic, bounded planning for changed-only project analysis.

This module is deliberately pure: callers collect source text through their
descriptor-pinned project tree and pass only repository-relative names here.
The returned public summary contains hashes and counts, never source text or
per-file hashes.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
from typing import Any

import project_audit_diff


FORMAT = "sniper-incremental-scan-plan/1"
TOOL_VERSION = "incremental-call-cone-v2-jvm-dotnet"
MAX_CANDIDATE_FILES = 10_000
MAX_FILE_BYTES = 1_000_000
MAX_TOTAL_BYTES = 64_000_000
MAX_DEPENDENCY_DEPTH = 32
_SAFE_RELATIVE_RE = re.compile(r"[^\x00-\x1f\\]{1,1024}\Z")


@dataclass(frozen=True)
class IncrementalPlan:
    """Internal selected-file set plus its redacted public telemetry."""

    selected_files: frozenset[str] | None
    public: dict[str, Any]


def _safe_relative(path: object) -> str | None:
    if not isinstance(path, str) or not _SAFE_RELATIVE_RE.fullmatch(path):
        return None
    normalized = path.replace("\\", "/")
    if normalized.startswith("/") or normalized.endswith("/") or "//" in normalized:
        return None
    if any(part in {"", ".", "..", ".git"} for part in normalized.split("/")):
        return None
    return normalized


def _sha256_json(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def build(
    file_sources: dict[str, str],
    changed_files: set[str] | frozenset[str],
    *,
    config: dict[str, Any],
    inventory_complete: bool,
    tool_version: str = TOOL_VERSION,
) -> IncrementalPlan:
    """Build a fail-safe plan; incomplete/depth-truncated input selects a full scan."""
    normalized_sources: dict[str, str] = {}
    total_bytes = 0
    complete = bool(inventory_complete)
    if not isinstance(file_sources, dict) or len(file_sources) > MAX_CANDIDATE_FILES:
        complete = False
    else:
        for raw_path, raw_text in sorted(file_sources.items()):
            path = _safe_relative(raw_path)
            if path is None or not isinstance(raw_text, str) or path in normalized_sources:
                complete = False
                continue
            size = len(raw_text.encode("utf-8", errors="replace"))
            if size > MAX_FILE_BYTES or total_bytes + size > MAX_TOTAL_BYTES:
                complete = False
                continue
            total_bytes += size
            normalized_sources[path] = raw_text

    direct_changed = {
        path for raw in changed_files
        if (path := _safe_relative(raw)) is not None
    }
    cone = project_audit_diff.compute_incremental_scan_cone(
        normalized_sources,
        sorted(direct_changed),
        max_depth=MAX_DEPENDENCY_DEPTH,
    )
    depth_truncated = bool(cone.get("depth_truncated"))
    complete = complete and not depth_truncated
    affected_sources = set(cone["affected_cone_files"])
    selected = frozenset(direct_changed | affected_sources) if complete else None

    content_rows = [
        [path, digest]
        for path, digest in sorted(cone["file_hashes"].items())
    ]
    content_sha256 = _sha256_json(content_rows)
    config_payload = {
        "format": FORMAT,
        "config": config,
        "inventory_complete": complete,
        "limits": {
            "candidate_files": MAX_CANDIDATE_FILES,
            "file_bytes": MAX_FILE_BYTES,
            "total_bytes": MAX_TOTAL_BYTES,
            "dependency_depth": MAX_DEPENDENCY_DEPTH,
        },
    }
    config_sha256 = _sha256_json(config_payload)
    tool_sha256 = hashlib.sha256(tool_version.encode("utf-8")).hexdigest()
    invalidation_sha256 = _sha256_json({
        "content_sha256": content_sha256,
        "config_sha256": config_sha256,
        "tool_sha256": tool_sha256,
    })

    candidate_count = len(normalized_sources)
    cone_count = candidate_count if selected is None else len(affected_sources)
    dependent_count = len(set(normalized_sources) - direct_changed) if selected is None \
        else len(affected_sources - direct_changed)
    skipped_count = 0 if selected is None else max(0, candidate_count - len(affected_sources))
    public = {
        "format": FORMAT,
        "inventory_complete": complete,
        "fallback_full_scan": selected is None,
        "fallback_reason": (
            "dependency-depth" if depth_truncated else "inventory-limit"
        ) if selected is None else "",
        "candidate_file_count": candidate_count,
        "changed_file_count": len(direct_changed),
        "cone_file_count": cone_count,
        "dependent_file_count": dependent_count,
        "skipped_unchanged_file_count": skipped_count,
        "scanned_file_count": 0,
        "scanned_byte_count": 0,
        "cone_reduction_ratio": 0.0 if selected is None else float(cone["cone_reduction_ratio"]),
        "max_dependency_depth": int(cone.get("max_depth_observed") or 0),
        "content_sha256": content_sha256,
        "config_sha256": config_sha256,
        "tool_sha256": tool_sha256,
        "invalidation_sha256": invalidation_sha256,
    }
    return IncrementalPlan(selected, public)


def expand_cone_with_di_bindings(
    file_sources: dict[str, str],
    changed_files: set[str] | list[str],
) -> dict[str, Any]:
    """Expand the incremental scan cone across DI interface <-> concrete implementation boundaries."""
    import authz_jvm_dotnet

    if not isinstance(file_sources, dict):
        return {
            "format": "sniper-incremental-di-cone/1",
            "affected_files": [],
            "affected_cone_files": [],
            "di_expanded_files": [],
            "skipped_unchanged_files": [],
            "bindings": [],
        }

    normalized_sources: dict[str, str] = {
        str(k): str(v or "") for k, v in sorted(file_sources.items())
    }
    seed_changed: list[str] = [str(item) for item in (changed_files or []) if isinstance(item, str)]

    base_cone = project_audit_diff.compute_incremental_scan_cone(
        normalized_sources,
        sorted(set(seed_changed)),
        max_depth=MAX_DEPENDENCY_DEPTH,
    )
    affected_set: set[str] = set(base_cone.get("affected_cone_files") or [])

    di_resolution = authz_jvm_dotnet.resolve_di_interface_implementations(normalized_sources)
    bindings = list(di_resolution.get("bindings") or [])

    di_added: set[str] = set()
    changed_progress = True
    while changed_progress:
        changed_progress = False
        for binding in bindings:
            iface_name = str(binding.get("interface") or "")
            impl_name = str(binding.get("implementation") or "")
            iface_file = str(binding.get("interface_file") or "")
            impl_file = str(binding.get("implementation_file") or "")
            controllers = [str(c) for c in (binding.get("controllers") or []) if c]

            impl_triggered = bool(impl_file and impl_file in affected_set)
            if not impl_triggered and impl_name:
                impl_re = re.compile(rf"\b{re.escape(impl_name)}\b")
                impl_triggered = any(
                    impl_re.search(normalized_sources.get(f, "")) for f in affected_set
                )

            iface_triggered = bool(iface_file and iface_file in affected_set)

            if impl_triggered or iface_triggered:
                candidates: set[str] = set(controllers)
                if iface_file and iface_file in normalized_sources:
                    candidates.add(iface_file)
                if impl_file and impl_file in normalized_sources:
                    candidates.add(impl_file)
                if iface_name:
                    iface_token_re = re.compile(rf"\b{re.escape(iface_name)}\b")
                    for path, content in normalized_sources.items():
                        if iface_token_re.search(content):
                            candidates.add(path)
                new_items = candidates - affected_set
                if new_items:
                    affected_set.update(new_items)
                    di_added.update(new_items)
                    changed_progress = True

    if di_added:
        expanded_cone = project_audit_diff.compute_incremental_scan_cone(
            normalized_sources,
            sorted(affected_set),
            max_depth=MAX_DEPENDENCY_DEPTH,
        )
        affected_set.update(expanded_cone.get("affected_cone_files") or [])

    affected_files = sorted(affected_set)
    skipped_unchanged = sorted(set(normalized_sources.keys()) - affected_set)
    return {
        "format": "sniper-incremental-di-cone/1",
        "affected_files": affected_files,
        "affected_cone_files": affected_files,
        "di_expanded_files": sorted(di_added),
        "skipped_unchanged_files": skipped_unchanged,
        "bindings": bindings,
    }

