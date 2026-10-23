"""Redacted, read-only preview of a registered ZAP AF active or passive plan.

No scanner, DNS lookup, subprocess or database write occurs here. The registered
integration binds records to authorizations; this layer independently checks
its exact output shape before exposing a plan summary.
"""
from __future__ import annotations

import json
from dataclasses import asdict
from hashlib import sha256
from typing import Any, Mapping

from zap_af_integration import build_registered_af_plan, _within
from zap_scope_plan import ScanSettings, PassiveScanSettings, _scope_patterns

_ACTIVE_FIELDS = frozenset({
    "target_id", "engagement_id", "selected_path",
    "confirm_authorized", "confirm_crawl", "confirm_active",
})
_PASSIVE_FIELDS = frozenset({
    "target_id", "engagement_id", "selected_path",
    "confirm_authorized", "confirm_crawl", "mode",
})
_ENV_PARAMETERS = ("failOnError", "failOnWarning", "continueOnFailure",
                   "progressToStdout", "maxDuration")


def build_preview_payload(
    *, target: Mapping[str, Any], engagement: Mapping[str, Any],
    request: Mapping[str, Any],
) -> dict[str, Any]:
    """Return a bounded scope/job summary; never return a plan or auth ref."""
    if not isinstance(request, Mapping):
        raise ValueError("geçersiz önizleme isteği")
    mode = request.get("mode", "ACTIVE_ROOT")
    expected_fields = _PASSIVE_FIELDS if mode == "PASSIVE_ONLY" else _ACTIVE_FIELDS
    if set(request) != expected_fields:
        raise ValueError("geçersiz önizleme isteği alanları")
    path = request["selected_path"]
    if mode == "ACTIVE_ROOT" and path != "/":
        raise ValueError("birleşik aktif AF önizlemesi tam köken kök kapsamı gerektirir")
    artifact = build_registered_af_plan(
        target=target, engagement=engagement, request=request,
    )
    plan = json.loads(artifact.plan_yaml)
    receipt = json.loads(artifact.scope_receipt_json)
    scope = receipt["scope"]
    registered = receipt["registered_scope"]
    authorization = receipt["authorization_input"]
    expected_schema = ("sniper.zap.registered-af-receipt.v2" if mode == "ACTIVE_ROOT"
                       else "sniper.zap.registered-af-receipt.v3")
    builder_schema = ("sniper.zap.scope-receipt.v1" if mode == "ACTIVE_ROOT"
                      else "sniper.zap.scope-receipt.v2")
    if (receipt.get("plan_only") is not True
            or receipt.get("plan_sha256") != sha256(artifact.plan_yaml.encode("utf-8")).hexdigest()
            or receipt.get("schema") != expected_schema
            or receipt.get("builder_schema") != builder_schema
            or set(plan) != {"env", "jobs"}
            or set(plan["env"]) != {"contexts", "parameters"}
            or len(plan["env"]["contexts"]) != 1):
        raise ValueError("AF planı ile kapsam makbuzu tutarsız")
    if mode == "PASSIVE_ONLY":
        if (receipt.get("mode") != "PASSIVE_ONLY"
                or receipt.get("passive_scope_basis") != "selected subtree; no intersecting path exclusions"
                or "active_scope_basis" in receipt):
            raise ValueError("tutarsız pasif AF makbuzu")
    elif ("mode" in receipt or "passive_scope_basis" in receipt
          or receipt.get("active_scope_basis") != "full-origin root; no path exclusions"):
        raise ValueError("tutarsız aktif AF makbuzu")
    context = plan["env"]["contexts"][0]
    origin = scope["origin"]
    selected_url = origin + ("/" if path == "/" else path)
    exclusions = registered["disjoint_excluded_paths"]
    if (scope["selected_path"] != path
            or scope["selected_url"] != selected_url
            or registered["target_id"] != request["target_id"]
            or registered["engagement_id"] != request["engagement_id"]
            or registered["target_url"] != target.get("url")
            or registered["authorized_origin"] != origin
            or registered["selected_path"] != path
            or registered["test_window"] != engagement.get("test_window")
            or not _within(registered["authorized_path"], path)
            or authorization["canonical_authorized_origin"] != origin
            or authorization["canonical_authorized_path"] != path
            or context["name"] != scope["context_name"]
            or context["urls"] != [selected_url]):
        raise ValueError("AF planı ile kayıtlı kapsam tutarsız")
    if mode == "ACTIVE_ROOT":
        if (path != "/" or registered["authorized_path"] != "/"
                or exclusions != []
                or authorization.get("active_scan_permitted") is not True
                or "crawl_permitted" in authorization):
            raise ValueError("tutarsız aktif kök kapsamı")
    else:
        if (not isinstance(exclusions, list)
                or any(not isinstance(excluded, str)
                       or _within(excluded, path) or _within(path, excluded)
                       for excluded in exclusions)
                or authorization.get("crawl_permitted") is not True
                or "active_scan_permitted" in authorization):
            raise ValueError("tutarsız pasif yol kapsamı")
    include_regex, exclude_regex = _scope_patterns(origin, path)
    if (scope["include_regex"] != include_regex
            or scope["exclude_regex"] != exclude_regex
            or context["includePaths"] != [include_regex]
            or context["excludePaths"] != [exclude_regex]
            or set(context) != {"name", "urls", "includePaths", "excludePaths"}):
        raise ValueError("AF bağlam kapsam ifadeleri tutarsız")
    limits = ScanSettings() if mode == "ACTIVE_ROOT" else PassiveScanSettings()
    canonical = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":"))
    if canonical(receipt["settings"]) != canonical(asdict(limits)):
        raise ValueError("AF önizleme ayarları değişti")
    expected_jobs = [
        {"type": "spider", "parameters": {
            "context": scope["context_name"], "url": selected_url,
            "maxDuration": limits.spider_max_duration_minutes,
            "postForm": False, "processForm": False, "logoutAvoidance": True,
        }},
        {"type": "passiveScan-wait", "parameters": {
            "maxDuration": limits.passive_wait_max_duration_minutes,
        }},
    ]
    if mode == "ACTIVE_ROOT":
        expected_jobs.append({"type": "activeScan", "parameters": {
            "context": scope["context_name"], "url": selected_url,
            "maxScanDurationInMins": limits.active_scan_max_duration_minutes,
            "maxRuleDurationInMins": limits.max_rule_duration_minutes,
            "threadPerHost": limits.thread_per_host,
            "delayInMs": limits.delay_in_ms,
            "maxAlertsPerRule": limits.max_alerts_per_rule,
        }})
    expected_jobs.append({"type": "passiveScan-wait", "parameters": {
        "maxDuration": limits.passive_wait_max_duration_minutes,
    }})
    expected_env_parameters = {
        "failOnError": True, "failOnWarning": True,
        "continueOnFailure": False, "progressToStdout": True,
        "maxDuration": limits.plan_max_duration_seconds,
    }
    if (set(plan["env"]["parameters"]) != set(_ENV_PARAMETERS)
            or canonical(plan["env"]["parameters"]) != canonical(expected_env_parameters)
            or canonical(plan["jobs"]) != canonical(expected_jobs)):
        raise ValueError("AF önizleme iş sınırları veya ortamı değişti")
    jobs = []
    for job in plan["jobs"]:
        kind, params = job["type"], job["parameters"]
        if kind == "spider":
            jobs.append({"type": kind, "max_duration_minutes": params["maxDuration"],
                         "submit_forms": params["postForm"], "process_forms": params["processForm"]})
        elif kind == "activeScan":
            jobs.append({"type": kind, "max_duration_minutes": params["maxScanDurationInMins"],
                         "threads_per_host": params["threadPerHost"], "delay_ms": params["delayInMs"]})
        elif kind == "passiveScan-wait":
            jobs.append({"type": kind, "max_duration_minutes": params["maxDuration"]})
        else:
            raise ValueError("beklenmeyen AF iş türü")
    response = {
        "schema": "sniper.zap.af-plan-preview.v1" if mode == "ACTIVE_ROOT" else "sniper.zap.af-plan-preview.v2",
        "plan_only": True,
        "traffic_generated": False,
        "execution_ready": False,
        "runtime_egress_containment_verified": False,
        "scope": {"origin": origin, "selected_path": path, "selected_url": selected_url},
        "jobs": jobs,
        "plan_max_duration_seconds": limits.plan_max_duration_seconds,
        "plan_sha256": receipt["plan_sha256"],
    }
    if mode == "PASSIVE_ONLY":
        response["mode"] = "PASSIVE_ONLY"
    return response
