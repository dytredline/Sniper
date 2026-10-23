"""Create an offline AF plan from a registered Sniper target and engagement.

This module never resolves DNS, starts ZAP, writes files, or contacts a target.
It requires a machine-readable scope inside the existing engagement scope_notes
field because free-form notes cannot prove a requested path was authorized.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
import re
from typing import Any, Mapping
from urllib.parse import urlsplit

from scanner import TargetRejected, normalize_target
from zap_scope_plan import (
    PlanError,
    ScanSettings,
    PassiveScanSettings,
    _canonical_origin,
    _canonical_path,
    build_scoped_plan,
)


_WINDOW = re.compile(
    r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)/(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\Z"
)
_EXCLUSION = re.compile(r"/[A-Za-z0-9_~-]+(?:/[A-Za-z0-9_~-]+)*\Z", re.ASCII)
_REQUEST_KEYS_ACTIVE = {
    "target_id", "engagement_id", "selected_path", "confirm_authorized", "confirm_crawl", "confirm_active"
}
_REQUEST_KEYS_PASSIVE = {
    "target_id", "engagement_id", "selected_path", "confirm_authorized", "confirm_crawl", "mode"
}
_SCOPE_KEYS = {"authorized_origin", "authorized_path"}


@dataclass(frozen=True, slots=True)
class RegisteredPlanArtifact:
    plan_yaml: str
    scope_receipt_json: str


def _within(parent: str, child: str) -> bool:
    return parent == "/" or child == parent or child.startswith(parent + "/")


def _nonempty_id(value: Any) -> bool:
    return isinstance(value, str) and 0 < len(value) <= 80 and value == value.strip()


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PlanError("scope_notes yinelenen JSON anahtarları içeriyor")
        result[key] = value
    return result


def _registered_scope(notes: Any) -> tuple[str, str]:
    if not isinstance(notes, str) or not notes or len(notes) > 1024:
        raise PlanError("scope_notes kayıtlı AF kapsamını içeren sıkıştırılmış bir JSON nesnesi içermeli")
    try:
        record = json.loads(notes, object_pairs_hook=_unique_object)
    except (ValueError, TypeError) as error:
        raise PlanError("scope_notes geçerli kayıtlı AF kapsam JSON'u olmalı") from error
    if not isinstance(record, dict) or set(record) != _SCOPE_KEYS:
        raise PlanError("scope_notes yalnız authorized_origin ve authorized_path içermeli")
    return _canonical_origin(record["authorized_origin"]), _canonical_path(record["authorized_path"])


def _exclusions(value: Any) -> list[str]:
    if value == "":
        return []
    if not isinstance(value, str) or len(value) > 5000:
        raise PlanError("out_of_scope boş bir metin veya JSON yol listesi olmalı")
    try:
        paths = json.loads(value)
    except (ValueError, TypeError) as error:
        raise PlanError("out_of_scope geçerli JSON olmalı") from error
    if not isinstance(paths, list) or not 1 <= len(paths) <= 16:
        raise PlanError("out_of_scope 1 ile 16 arasında yol içermeli")
    seen: set[str] = set()
    for path in paths:
        if not isinstance(path, str) or not _EXCLUSION.fullmatch(path) or path in seen:
            raise PlanError("out_of_scope geçersiz veya yinelenen bir yol içeriyor")
        seen.add(path)
    return paths


def _validated_window(value: Any, now: datetime, plan_seconds: int) -> None:
    if not isinstance(value, str) or len(value) != 41:
        raise PlanError("test_window tam bir UTC aralığı olmalı")
    match = _WINDOW.fullmatch(value)
    if not match:
        raise PlanError("test_window tam bir UTC aralığı olmalı")
    try:
        start, end = (datetime.strptime(part, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
                      for part in match.groups())
    except ValueError as error:
        raise PlanError("test_window geçersiz bir UTC zaman damgası içeriyor") from error
    if not start < end or end - start > timedelta(days=1):
        raise PlanError("test_window süresi geçersiz")
    if not start <= now or end < now + timedelta(seconds=plan_seconds):
        raise PlanError("test_window şu andan itibaren planlanan sürenin tamamını kapsamalı")


def build_registered_af_plan(
    *,
    target: Mapping[str, Any],
    engagement: Mapping[str, Any],
    request: Mapping[str, Any],
    settings: ScanSettings | PassiveScanSettings | None = None,
    now: datetime | None = None,
) -> RegisteredPlanArtifact:
    """Return only a bounded plan and source-binding receipt; perform no scan."""
    if not all(isinstance(item, Mapping) for item in (target, engagement, request)):
        raise PlanError("target, engagement ve request birer eşleme olmalı")
    mode = request.get("mode", "ACTIVE_ROOT")
    expected_keys = _REQUEST_KEYS_PASSIVE if mode == "PASSIVE_ONLY" else _REQUEST_KEYS_ACTIVE
    if set(request) != expected_keys:
        raise PlanError("request eksik veya beklenmeyen alanlar içeriyor")
    for key in ("target_id", "engagement_id"):
        if not _nonempty_id(request[key]):
            raise PlanError(f"{key} geçersiz")
    confirmations = ("confirm_authorized", "confirm_crawl")
    if mode == "ACTIVE_ROOT":
        confirmations += ("confirm_active",)
    if any(request[key] is not True for key in confirmations):
        raise PlanError("ayrı yetki ve kipe özgü tarama onayları gerekli")
    if target.get("id") != request["target_id"] or engagement.get("id") != request["engagement_id"]:
        raise PlanError("istek tanımlayıcıları kayıtlı kayıtlarla eşleşmiyor")
    if engagement.get("status") != "active" or engagement.get("target_id") != target.get("id"):
        raise PlanError("etkin görev kayıtlı hedefe ait olmalı")
    if not isinstance(target.get("url"), str):
        raise PlanError("kayıtlı hedef URL'si eksik")
    try:
        normalized = normalize_target(target["url"])
    except TargetRejected as error:
        raise PlanError("kayıtlı hedef URL'si geçersiz") from error
    if normalized.url != target["url"] or normalized.scheme != "https":
        raise PlanError("kayıtlı hedef kanonik bir HTTPS URL'si olmalı")
    for field in ("scheme", "hostname", "port", "path"):
        if target.get(field) != getattr(normalized, field):
            raise PlanError("kayıtlı hedef alanları URL'si ile eşleşmiyor")
    if engagement.get("target_url") != normalized.url or engagement.get("target_hostname") != normalized.hostname:
        raise PlanError("görev hedef bağlantısı tutarsız")
    parsed_url = urlsplit(normalized.url)
    origin = _canonical_origin(f"{parsed_url.scheme}://{parsed_url.netloc}")
    target_path = _canonical_path(normalized.path)
    registered_origin, registered_path = _registered_scope(engagement.get("scope_notes"))
    if registered_origin != origin or not _within(target_path, registered_path):
        raise PlanError("kayıtlı AF kapsamı kayıtlı hedefin içinde olmalı")
    selected_path = _canonical_path(request["selected_path"])
    if not _within(registered_path, selected_path):
        raise PlanError("seçilen yol kayıtlı AF kapsamının içinde olmalı")
    # Active scanning reached outside /app in an isolated ZAP 2.17 trial.
    # Passive plans are independently authorized and contain no activeScan job.
    if mode == "ACTIVE_ROOT" and (
        target_path != "/" or registered_path != "/" or selected_path != "/"
    ):
        raise PlanError("birleşik aktif AF planı kök hedef, kayıtlı ve seçilen yollar gerektirir")
    excluded_paths = _exclusions(engagement.get("out_of_scope"))
    if mode == "ACTIVE_ROOT" and excluded_paths:
        raise PlanError("birleşik aktif AF kök planı out_of_scope yol hariç tutmalarını uygulayamaz")
    if mode == "PASSIVE_ONLY" and any(
        _within(excluded, selected_path) or _within(selected_path, excluded)
        for excluded in excluded_paths
    ):
        raise PlanError("pasif AF seçili yolu hariç tutulan bir yolla kesişiyor")
    reference = engagement.get("authorization_ref")
    if not isinstance(reference, str) or not reference.strip():
        raise PlanError("görev authorization_ref eksik")
    settings_type = ScanSettings if mode == "ACTIVE_ROOT" else PassiveScanSettings
    limits = settings if settings is not None else settings_type()
    if not isinstance(limits, settings_type):
        raise PlanError(f"{mode} ayarları {settings_type.__name__} olmalı")
    current = now if now is not None else datetime.now(timezone.utc)
    if not isinstance(current, datetime) or current.tzinfo is None or current.utcoffset() != timedelta(0):
        raise PlanError("now saat dilimi bilgili bir UTC tarih-saati olmalı")
    _validated_window(engagement.get("test_window"), current, limits.plan_max_duration_seconds)

    permission = "active_scan_permitted" if mode == "ACTIVE_ROOT" else "crawl_permitted"
    artifact = build_scoped_plan(
        authorized_origin=origin,
        selected_path=selected_path,
        authorization_input={
            "authorized_origin": registered_origin,
            "authorized_path": selected_path,
            "authorization_reference": reference,
            permission: True,
        },
        settings=limits,
        mode=mode,
    )
    receipt = json.loads(artifact.scope_receipt_json)
    receipt["builder_schema"] = receipt["schema"]
    receipt["schema"] = ("sniper.zap.registered-af-receipt.v2" if mode == "ACTIVE_ROOT"
                         else "sniper.zap.registered-af-receipt.v3")
    if mode == "ACTIVE_ROOT":
        receipt["active_scope_basis"] = "full-origin root; no path exclusions"
    else:
        receipt["passive_scope_basis"] = "selected subtree; no intersecting path exclusions"
    receipt["registered_scope"] = {
        "target_id": target["id"],
        "engagement_id": engagement["id"],
        "target_url": normalized.url,
        "authorized_origin": registered_origin,
        "authorized_path": registered_path,
        "selected_path": selected_path,
        "disjoint_excluded_paths": excluded_paths,
        "test_window": engagement["test_window"],
    }
    receipt["plan_sha256"] = sha256(artifact.plan_yaml.encode("utf-8")).hexdigest()
    return RegisteredPlanArtifact(
        plan_yaml=artifact.plan_yaml,
        scope_receipt_json=json.dumps(receipt, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
    )
