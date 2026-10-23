"""Bounded, read-only preview of saved ECS-aligned JSON Lines evidence.

Only the three selected ECS fields required by this narrow profile are
validated. ``ecs.version`` and ``event.kind`` may each appear either nested
(``{"ecs": {"version": ...}}``) or as a flat dotted key (``{"ecs.version": ...}``);
a record that supplies both forms for the same field is rejected as ambiguous.
This is not a full ECS validator or an Elastic Security connector.
No event content is returned or retained by this parser.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from datetime import datetime


MAX_BYTES = 60_000
MAX_RECORDS = 500
KINDS = ("alert", "asset", "enrichment", "event", "metric", "state", "pipeline_error", "signal")
VERSION = re.compile(r"^[0-9]+\.[0-9]+(?:\.[0-9]+)?$")
STAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Yinelenen JSON anahtarı")
        result[key] = value
    return result


def _bad_constant(_value: str) -> None:
    raise ValueError("Sonlu olmayan JSON sayısı")


def _finite_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError("Sonlu olmayan JSON sayısı")
    return parsed


_ABSENT = object()


def _ecs_field(record: dict[str, object], parent: str, child: str) -> object:
    """Return one ECS field given nested or flat dotted, never both.

    Presence (not value) decides ambiguity: ``{"event": {"kind": "a"},
    "event.kind": "a"}`` is rejected even when the values agree, and a flat
    key next to a non-object parent (``{"event": "x", "event.kind": ...}``)
    is rejected as a conflicting shape. A nested parent object that lacks the
    child (``{"event": {"action": ...}, "event.kind": ...}``) is not a
    conflict for this field. Error texts are fixed and never echo content.
    """
    dotted = f"{parent}.{child}"
    container = record.get(parent, _ABSENT)
    if dotted in record:
        if container is not _ABSENT and (not isinstance(container, dict) or child in container):
            raise ValueError(f"İç içe ve düz {dotted} alanları çakışıyor")
        return record[dotted]
    if isinstance(container, dict):
        return container.get(child, _ABSENT)
    return _ABSENT


def parse_siem_ecs_ndjson_summary(report: str) -> dict[str, object]:
    """Count fixed event kinds in a local, saved, minimal ECS JSONL profile."""
    if not isinstance(report, str):
        raise ValueError("report bir JSON Lines metni olmalı")
    try:
        raw = report.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError("Geçersiz UTF-8 rapor") from exc
    if not 1 <= len(raw) <= MAX_BYTES or "\x00" in report:
        raise ValueError("Geçersiz rapor boyutu veya içeriği")
    # JSON Lines records are delimited by LF, not Unicode line separators
    # that may appear inside an otherwise valid JSON string.
    lines = report.split("\n")
    if lines[-1] == "":
        lines.pop()
    lines = [line[:-1] if line.endswith("\r") else line for line in lines]
    if not 1 <= len(lines) <= MAX_RECORDS or any(not line.strip() for line in lines):
        raise ValueError("Geçersiz JSON Lines kayıt sayısı")

    counts = {kind: 0 for kind in KINDS}
    for line in lines:
        try:
            record = json.loads(line, object_pairs_hook=_unique_object,
                                parse_constant=_bad_constant, parse_float=_finite_float)
        except (json.JSONDecodeError, RecursionError, ValueError) as exc:
            raise ValueError("Geçersiz ECS JSON Lines kaydı") from exc
        if not isinstance(record, dict):
            raise ValueError("Her JSON Lines kaydı bir nesne olmalı")
        version = _ecs_field(record, "ecs", "version")
        kind = _ecs_field(record, "event", "kind")
        if version is _ABSENT:
            raise ValueError("ecs.version gerekli")
        if not isinstance(version, str) or not 1 <= len(version) <= 32 or not VERSION.fullmatch(version):
            raise ValueError("Geçersiz ecs.version")
        timestamp = record.get("@timestamp")
        if not isinstance(timestamp, str) or not STAMP.fullmatch(timestamp):
            raise ValueError("Geçersiz @timestamp")
        try:
            parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("Geçersiz @timestamp") from exc
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError("@timestamp bir saat dilimi içermeli")
        if not isinstance(kind, str) or kind not in counts:
            raise ValueError("Geçersiz event.kind")
        counts[kind] += 1

    return {
        "format": "ecs-ndjson",
        "record_count": len(lines),
        "kind_counts": counts,
        "report_sha256": hashlib.sha256(raw).hexdigest(),
    }
