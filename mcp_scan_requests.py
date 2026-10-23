"""MCP tarama istekleri için yürütmeden ayrılmış, insan onaylı kuyruk.

MCP tarafı yalnız önceden tanımlı profilleri ve önceden yetkilendirilmiş hedefleri görür. ``create_request`` hiçbir
tarayıcıyı çağırmaz. Gerçek iş gövdesindeki açık onay bayrakları yalnız yönetici isteği ``claim_request`` ile
aldığında eklenir; hedefin güncel kapsam/yetki denetimi ayrıca mevcut HTTP rotasında yeniden yapılır.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import stat
from typing import Any
from urllib.parse import urlunsplit

from authorized_tool_targets import parse_authorized_target
from nuclei_aggregate_history import AggregateHistoryError, AggregateHistoryJournal
from nuclei_finding_journal import NucleiFindingJournal, NucleiFindingJournalError
from openssl_authorized_active import normalize_authorized_target as normalize_openssl_authorized_target
from nmap_active import FIXED_PORTS as AUTHORIZED_NMAP_PORTS, normalize_authorized_nmap_target
from nuclei_broad_jobs import normalize_authorized_http_origin
import ops_files
from playwright_authorized import normalize_authorized_target as normalize_playwright_authorized_target
import sandbox_targets
from sandbox_load_tests import validated_schema
from scanner import TargetRejected, normalize_target
from ssllabs_active import normalize_public_hostname
from ssllabs_live import validate_hostname as validate_ssllabs_hostname
from testssl_authorized_active import normalize_authorized_testssl_target
from tool_catalog import mcp_authorized_target_tools
from zap_authorized import normalize_authorized_target as normalize_zap_authorized_target

FILE_NAME = "mcp-scan-requests.json"
FORMAT = "sniper-mcp-scan-requests/1"
AUTHORIZATION_CONSENT_VERSION = "sniper-mcp-target-authorization/1"
AUTHORIZATION_CONSENT_VERSION_V2 = "sniper-mcp-target-authorization/2"
SCHEMA_SPOOL_DIR = "mcp-schema-spool"
MAX_SCHEMA_SPOOL_BYTES = 262_144
LAUNCH_RESERVATION_SECONDS = 300
MAX_REQUESTS = 200
NONTERMINAL_STATUSES = frozenset({"pending", "approved", "launching", "started", "running"})
TERMINAL_STATUSES = frozenset({"completed", "cancelled", "failed"})
MAX_SAFE_COUNT = 2**53 - 1
_REQUEST_ID = re.compile(r"msr_[0-9a-f]{16}\Z")
_JOB_ID = re.compile(r"job_[0-9a-f]{24}\Z")
_NUCLEI_JOB_ID = re.compile(r"[0-9a-f]{16}\Z")

# Serbest hedef MCP profili yalnız mevcut, sabit gövdeli doğrudan rotalara bağlanabilir. Bu tabloya girmeyen
# katalog araçları insan onay makbuzu üretir; keyfi rota, seçenek veya araç argümanı kabul edilmez.
OPERATOR_JOB_DISPATCH = {
    "owasp-zap": "/api/tool-runs/zap-authorized",
    "k6": "/api/tool-runs/k6-authorized",
    "openssl": "/api/tool-runs/openssl-x509-authorized",
    "nmap": "/api/nmap/authorized-target-scan",
    "testssl": "/api/tool-runs/testssl-authorized",
    "browser-tests": "/api/tool-runs/playwright-authorized",
    "nuclei": "/api/nuclei/authorized-origin-scans",
    "ssllabs": "/api/tool-runs/ssllabs-authorized",
    "schemathesis": "/api/tool-runs/schemathesis-authorized",
}


class ScanRequestError(ValueError):
    """Profil, hedef, istek veya durum geçersiz."""


PROFILES: tuple[dict[str, Any], ...] = (
    {
        "id": "nuclei_http_authorized",
        "label": "Yetkili Nuclei HTTP taraması",
        "route": "/api/nuclei/http-scans",
        "target_source": "authorized_engagements",
        "required": ("target_id", "engagement_id"),
        "optional": ("template_ids", "include_excluded"),
        "risk": "active_http",
    },
    {
        "id": "sandbox_k6",
        "label": "Yalıtılmış k6 yük profili",
        "route": "/api/tool-runs/k6-sandbox",
        "target_source": "sandbox_targets",
        "target_tool": "k6",
        "required": ("target",),
        "optional": ("path", "method", "preset"),
        "risk": "bounded_load",
    },
    {
        "id": "operator_authorized_http",
        "label": "İnsan onaylı serbest HTTP(S) hedef planı",
        "route": None,
        "target_source": "operator_input",
        "required": ("tool_id", "target"),
        "optional": ("profile", "options"),
        "risk": "authorized_external",
    },
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _launch_reservation_expired(value: object) -> bool:
    if not isinstance(value, str) or not value.endswith("Z"):
        return True
    try:
        created = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return True
    age = (datetime.now(timezone.utc) - created).total_seconds()
    return age < -60 or age > LAUNCH_RESERVATION_SECONDS


def _data_dir(store_or_path: Any) -> Path:
    value = getattr(store_or_path, "path", store_or_path)
    path = Path(value)
    if hasattr(store_or_path, "path") or path.name == "sniper.db":
        path = path.parent
    if not path.is_absolute() or path.is_symlink() or not path.is_dir():
        raise ScanRequestError("Sniper veri dizini geçersiz.")
    return path


def _env_for(path: Path) -> dict[str, str]:
    return {"SNIPER_DATA_DIR": str(path)}


def _default() -> dict[str, Any]:
    return {"format": FORMAT, "requests": []}


def _profile(profile_id: object) -> dict[str, Any]:
    if not isinstance(profile_id, str):
        raise ScanRequestError("Profil kimliği metin olmalı.")
    profile = next((dict(item) for item in PROFILES if item["id"] == profile_id), None)
    if profile is None:
        raise ScanRequestError("Bilinmeyen tarama profili.")
    return profile


def _public(item: dict[str, Any]) -> dict[str, Any]:
    receipt = item.get("authorization_receipt")
    if receipt is not None and not verify_authorization_receipt(receipt):
        raise ScanRequestError("Yetki beyanı makbuzu bütünlük denetimini geçemedi.")
    if isinstance(receipt, dict) and receipt.get("consent_version") == AUTHORIZATION_CONSENT_VERSION_V2:
        expected = {
            "request_id": item.get("id"), "profile_id": item.get("profile_id"),
            "tool_id": item.get("_tool_id"), "normalized_target": item.get("normalized_target"),
            "effective_profile": item.get("effective_profile"), "scope_summary": item.get("scope_summary"),
            "consent_scope": item.get("consent_scope"), "plan_sha256": item.get("plan_sha256"),
        }
        if any(receipt.get(key) != value for key, value in expected.items()):
            raise ScanRequestError("Yetki beyanı makbuzu kuyruk planıyla eşleşmiyor.")
        if item.get("approved_by") != receipt.get("actor") or item.get("approved_at") != receipt.get("confirmed_at"):
            raise ScanRequestError("Yetki beyanı makbuzu onaylayan yöneticiyle eşleşmiyor.")
        parameters = item.get("parameters")
        if item.get("profile_id") == "operator_authorized_http" and (
            not isinstance(parameters, dict)
            or parameters.get("tool_id") != receipt.get("tool_id")
            or parameters.get("target") != receipt.get("normalized_target")
        ):
            raise ScanRequestError("Yetki beyanı makbuzu görünür istek parametreleriyle eşleşmiyor.")
        if item.get("profile_id") == "operator_authorized_http":
            derived = _operator_public_plan(parameters, str(item.get("id") or ""))
            for key in (
                "tool_id", "normalized_target", "effective_profile", "scope_summary",
                "consent_scope", "plan_sha256",
            ):
                if derived.get(key) != receipt.get(key):
                    raise ScanRequestError("Yetki beyanı makbuzu görünür tarama planıyla eşleşmiyor.")
    return {key: value for key, value in item.items() if not key.startswith("_")}


def _canonical_receipt(receipt: dict[str, Any]) -> bytes:
    body = {key: value for key, value in receipt.items() if key != "receipt_sha256"}
    return json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def verify_authorization_receipt(receipt: object) -> bool:
    legacy_keys = {
        "consent_version", "confirm_authorized", "actor", "confirmed_at", "normalized_target",
        "profile_id", "request_id", "tool_id", "receipt_sha256",
    }
    v2_keys = legacy_keys | {"effective_profile", "scope_summary", "consent_scope", "plan_sha256"}
    if not isinstance(receipt, dict) or set(receipt) not in (legacy_keys, v2_keys):
        return False
    actor = receipt.get("actor")
    digest = receipt.get("receipt_sha256")
    consent_version = receipt.get("consent_version")
    if consent_version not in {AUTHORIZATION_CONSENT_VERSION, AUTHORIZATION_CONSENT_VERSION_V2} \
            or receipt.get("confirm_authorized") is not True \
            or not isinstance(actor, dict) or set(actor) != {"id", "username"} \
            or not all(isinstance(actor.get(key), str) and actor[key] for key in ("id", "username")) \
            or not isinstance(receipt.get("confirmed_at"), str) or not receipt["confirmed_at"].endswith("Z") \
            or not isinstance(receipt.get("normalized_target"), str) \
            or not isinstance(receipt.get("profile_id"), str) \
            or not isinstance(receipt.get("request_id"), str) or not _REQUEST_ID.fullmatch(receipt["request_id"]) \
            or not isinstance(receipt.get("tool_id"), str) \
            or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        return False
    if consent_version == AUTHORIZATION_CONSENT_VERSION and set(receipt) != legacy_keys:
        return False
    if consent_version == AUTHORIZATION_CONSENT_VERSION_V2:
        if set(receipt) != v2_keys \
                or not isinstance(receipt.get("effective_profile"), str) or not receipt["effective_profile"] \
                or not isinstance(receipt.get("scope_summary"), list) or not receipt["scope_summary"] \
                or any(not isinstance(value, str) or not value for value in receipt["scope_summary"]) \
                or not isinstance(receipt.get("consent_scope"), str) or not receipt["consent_scope"] \
                or not isinstance(receipt.get("plan_sha256"), str) \
                or not re.fullmatch(r"[0-9a-f]{64}", receipt["plan_sha256"]):
            return False
    return secrets.compare_digest(hashlib.sha256(_canonical_receipt(receipt)).hexdigest(), digest)


def _authorization_receipt(item: dict[str, Any], actor: dict[str, Any]) -> dict[str, Any]:
    actor_view = {key: str(actor.get(key) or "")[:120] for key in ("id", "username")}
    if not actor_view["id"] or not actor_view["username"]:
        raise ScanRequestError("Yetki beyanı için kimliği bağlı bir yönetici gerekir.")
    receipt = {
        "consent_version": AUTHORIZATION_CONSENT_VERSION_V2,
        "confirm_authorized": True,
        "actor": actor_view,
        "confirmed_at": _utc_now(),
        "normalized_target": item.get("normalized_target"),
        "profile_id": item.get("profile_id"),
        "request_id": item.get("id"),
        "tool_id": item.get("_tool_id"),
        "effective_profile": item.get("effective_profile"),
        "scope_summary": item.get("scope_summary"),
        "consent_scope": item.get("consent_scope"),
        "plan_sha256": item.get("plan_sha256"),
    }
    if not all(isinstance(receipt.get(key), str) and receipt[key] for key in (
        "normalized_target", "profile_id", "request_id", "tool_id", "effective_profile",
    )):
        raise ScanRequestError("Tarama isteği yetki makbuzuna bağlanamıyor.")
    if not isinstance(receipt["scope_summary"], list) or not receipt["scope_summary"] \
            or not isinstance(receipt["consent_scope"], str) or not receipt["consent_scope"] \
            or not isinstance(receipt["plan_sha256"], str) \
            or not re.fullmatch(r"[0-9a-f]{64}", receipt["plan_sha256"]):
        raise ScanRequestError("Tarama isteği kapsam planına bağlanamıyor.")
    receipt["receipt_sha256"] = hashlib.sha256(_canonical_receipt(receipt)).hexdigest()
    return receipt


def _persisted_job(data_dir: Path, job_id: object) -> dict[str, Any] | None:
    if not isinstance(job_id, str) or not _JOB_ID.fullmatch(job_id):
        return None
    path = data_dir / "jobs" / f"{job_id}.json"
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 \
                or info.st_size > 2_065_536:
            return None
        value = json.loads(os.read(fd, info.st_size + 1))
    except (OSError, ValueError, TypeError):
        return None
    finally:
        os.close(fd)
    return value if isinstance(value, dict) and value.get("id") == job_id else None


def _fixed_counts(value: object, keys: tuple[str, ...]) -> dict[str, int] | None:
    """Copy only named non-negative integer counters from an untrusted tool result."""
    if not isinstance(value, dict) or any(
        type(value.get(key)) is not int or not 0 <= value[key] <= MAX_SAFE_COUNT for key in keys
    ):
        return None
    return {key: value[key] for key in keys}


def _fixed_relay(value: object) -> dict[str, int] | None:
    return _fixed_counts(value, ("connections", "refused", "bytes"))


def _sha256(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _bounded_number(value: object, maximum: int | float) -> bool:
    if type(value) is int:
        return 0 <= value <= maximum
    return type(value) is float and math.isfinite(value) and 0 <= value <= maximum


def _masked_outer_summary(item: dict[str, Any], result: object) -> dict[str, Any]:
    """Return a fixed-schema aggregate for a completed non-Nuclei outer job.

    Tool output is an untrusted boundary.  No target field, raw evidence, arbitrary
    mapping key or free-form finding is copied into the MCP queue.
    """
    tool_id = item.get("_tool_id")
    if not isinstance(tool_id, str):
        parameters = item.get("parameters")
        tool_id = parameters.get("tool_id") if isinstance(parameters, dict) else None
    fixed_tools = frozenset({
        "owasp-zap", "k6", "openssl", "nmap", "testssl", "browser-tests", "ssllabs", "schemathesis",
    })
    tool_id = tool_id if isinstance(tool_id, str) and tool_id in fixed_tools else "unknown"
    base = {"state": "completed", "tool_id": tool_id}
    unavailable = {**base, "summary_state": "summary_unavailable"}
    if not isinstance(result, dict):
        return unavailable

    summary: dict[str, Any] = {**base, "summary_state": "available"}
    if tool_id == "owasp-zap":
        counts = _fixed_counts(result, ("site_count", "alert_type_count", "instance_count"))
        risks = _fixed_counts(result.get("risk_counts"), ("informational", "low", "medium", "high"))
        if result.get("format") != "zap-authorized-v1" or counts is None or risks is None \
                or counts["site_count"] > 20 or counts["alert_type_count"] > 500 \
                or counts["instance_count"] > 5_000 \
                or sum(risks.values()) != counts["alert_type_count"] \
                or counts["instance_count"] < counts["alert_type_count"] \
                or not _sha256(result.get("report_sha256")):
            return unavailable
        profile = result.get("profile")
        if profile != "same-origin-authorized-spider-active-v1":
            return unavailable
        summary.update(profile=profile, **counts, risk_counts=risks, report_sha256=result["report_sha256"])
        elapsed = result.get("elapsed_seconds")
        if _bounded_number(elapsed, 86_400):
            summary["elapsed_seconds"] = elapsed
        return summary

    if tool_id == "k6":
        relay = _fixed_relay(result.get("relay"))
        parsed = result.get("summary")
        threshold_counts = _fixed_counts(
            parsed.get("threshold_counts") if isinstance(parsed, dict) else None, ("passed", "failed")
        )
        if result.get("format") != "k6-authorized-target-v1" or result.get("status") != "completed" \
                or type(result.get("thresholds_ok")) is not bool or not _sha256(result.get("script_sha256")) \
                or relay is None or not isinstance(parsed, dict) \
                or parsed.get("format") != "k6-handle-summary-json" \
                or type(parsed.get("http_requests")) is not int \
                or not 0 <= parsed["http_requests"] <= MAX_SAFE_COUNT \
                or not _sha256(parsed.get("report_sha256")) or threshold_counts is None:
            return unavailable
        duration = parsed.get("duration_p95_ms")
        if duration is not None and not _bounded_number(duration, 1_000_000_000):
            return unavailable
        summary.update(
            status="completed", thresholds_ok=result["thresholds_ok"], script_sha256=result["script_sha256"],
            relay=relay,
            result_summary={
                "format": "k6-handle-summary-json", "http_requests": parsed["http_requests"],
                "duration_p95_ms": duration, "threshold_counts": threshold_counts,
                "report_sha256": parsed["report_sha256"],
            },
        )
        return summary

    if tool_id == "openssl":
        verification = result.get("verification")
        if result.get("format") != "openssl-x509-authorized-v1" or verification not in ("passed", "rejected"):
            return unavailable
        summary["verification"] = verification
        if verification == "rejected":
            return summary
        if result.get("validity") not in ("valid", "expiring_soon", "expired", "not_yet_valid") \
                or type(result.get("days_until_expiry")) is not int \
                or not 0 <= result["days_until_expiry"] <= 1_000_000 \
                or not _sha256(result.get("report_sha256")):
            return unavailable
        for key in ("not_before_utc", "not_after_utc"):
            if not isinstance(result.get(key), str) or not re.fullmatch(
                    r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", result[key]):
                return unavailable
        summary.update(
            validity=result["validity"], not_before_utc=result["not_before_utc"],
            not_after_utc=result["not_after_utc"], days_until_expiry=result["days_until_expiry"],
            report_sha256=result["report_sha256"],
        )
        return summary

    if tool_id == "nmap":
        counts = _fixed_counts(result, ("host_count", "up_host_count", "open_port_count"))
        ports = result.get("open_ports")
        profile = result.get("profile")
        if profile not in ("authorized-default-v1", "authorized-service-light-v1") or counts is None \
                or counts["host_count"] > 1 or counts["up_host_count"] > counts["host_count"] \
                or counts["open_port_count"] > len(AUTHORIZED_NMAP_PORTS) \
                or not isinstance(ports, list) or len(ports) != counts["open_port_count"] \
                or any(type(port) is not int or port not in AUTHORIZED_NMAP_PORTS for port in ports) \
                or ports != sorted(set(ports)) \
                or not _sha256(result.get("report_sha256")):
            return unavailable
        summary.update(profile=profile, **counts, open_ports=list(ports), report_sha256=result["report_sha256"])
        if "service_version_enabled" in result:
            if type(result["service_version_enabled"]) is not bool:
                return unavailable
            summary["service_version_enabled"] = result["service_version_enabled"]
        return summary

    if tool_id == "testssl":
        severities = _fixed_counts(
            result.get("severity_counts"),
            ("INFO", "OK", "LOW", "MEDIUM", "HIGH", "CRITICAL", "WARN", "DEBUG", "FATAL"),
        )
        profile = result.get("profile")
        if result.get("format") != "testssl-authorized-v1" \
                or profile not in ("authorized-protocols-v1", "authorized-full-v1") \
                or type(result.get("record_count")) is not int or not 0 <= result["record_count"] <= 500 \
                or severities is None or sum(severities.values()) != result["record_count"] \
                or not _sha256(result.get("report_sha256")):
            return unavailable
        summary.update(
            profile=profile, record_count=result["record_count"], severity_counts=severities,
            report_sha256=result["report_sha256"],
        )
        elapsed = result.get("elapsed_seconds")
        if _bounded_number(elapsed, 86_400):
            summary["elapsed_seconds"] = elapsed
        if "scan_complete" in result:
            if type(result["scan_complete"]) is not bool:
                return unavailable
            summary["scan_complete"] = result["scan_complete"]
        return summary

    if tool_id == "browser-tests":
        relay = _fixed_relay(result.get("relay"))
        findings = result.get("findings")
        if result.get("format") != "playwright-authorized-v1" or result.get("status") != "completed" \
                or not _sha256(result.get("driver_sha256")) or relay is None \
                or not isinstance(findings, list) or len(findings) > 2_000:
            return unavailable
        summary.update(
            status="completed", driver_sha256=result["driver_sha256"], relay=relay,
            finding_count=len(findings),
        )
        return summary

    if tool_id == "ssllabs":
        grades = _fixed_counts(result.get("grade_counts"), ("A+", "A", "A-", "B", "C", "D", "E", "F", "T", "M"))
        digest = result.get("summary_sha256", result.get("report_sha256"))
        if result.get("format") != "ssllabs-v4-host" \
                or result.get("assessment_status") not in ("DNS", "ERROR", "IN_PROGRESS", "READY") \
                or type(result.get("endpoint_count")) is not int or not 0 <= result["endpoint_count"] <= 500 \
                or grades is None or sum(grades.values()) > result["endpoint_count"] or not _sha256(digest):
            return unavailable
        summary.update(
            assessment_status=result["assessment_status"][:40], endpoint_count=result["endpoint_count"],
            grade_counts=grades, summary_sha256=digest,
        )
        if "successful_endpoint_count" in result:
            value = result["successful_endpoint_count"]
            if type(value) is not int or not 0 <= value <= result["endpoint_count"]:
                return unavailable
            summary["successful_endpoint_count"] = value
        return summary

    if tool_id == "schemathesis":
        relay = _fixed_relay(result.get("relay"))
        parsed = result.get("summary")
        if result.get("format") != "schemathesis-authorized-target-v1" or result.get("status") != "completed" \
                or type(result.get("issues_found")) is not bool or not _sha256(result.get("schema_sha256")) \
                or relay is None or not isinstance(parsed, dict):
            return unavailable
        parsed_format = parsed.get("format")
        if parsed_format == "schemathesis-junit-xml":
            counts = _fixed_counts(parsed.get("outcome_counts"), ("passed", "failed", "errors", "skipped"))
            if type(parsed.get("suite_count")) is not int or not 0 <= parsed["suite_count"] <= 20 \
                    or type(parsed.get("testcase_count")) is not int \
                    or not 0 <= parsed["testcase_count"] <= 500 \
                    or counts is None or sum(counts.values()) != parsed["testcase_count"] \
                    or not _sha256(parsed.get("report_sha256")):
                return unavailable
            result_summary = {
                "format": parsed_format, "suite_count": parsed["suite_count"],
                "testcase_count": parsed["testcase_count"], "outcome_counts": counts,
                "report_sha256": parsed["report_sha256"],
            }
        elif parsed_format == "schemathesis-junit-counts":
            counts = _fixed_counts(parsed, ("testcases", "failures", "errors", "skipped"))
            if counts is None or counts["testcases"] > 500 \
                    or counts["failures"] + counts["errors"] + counts["skipped"] > counts["testcases"] \
                    or not _sha256(parsed.get("report_sha256")):
                return unavailable
            result_summary = {"format": parsed_format, **counts, "report_sha256": parsed["report_sha256"]}
        else:
            return unavailable
        summary.update(
            status="completed", issues_found=result["issues_found"], schema_sha256=result["schema_sha256"],
            relay=relay, result_summary=result_summary,
        )
        return summary

    return unavailable


def _refresh_from_persisted_jobs(data_dir: Path, store: Any | None = None) -> None:
    """HTTP iş kaydı ile Nuclei'nin maskeli toplam geçmişini MCP kuyruğuna taşır.

    Ham Nuclei JSONL kaydı, hedef URL'si ya da yetki metni bu dosyaya kopyalanmaz.
    """
    queue_path = data_dir / FILE_NAME
    if not queue_path.is_file() or queue_path.is_symlink():
        return
    try:
        nuclei = dict(AggregateHistoryJournal(data_dir).load())
    except AggregateHistoryError:
        nuclei = {}
    try:
        finding_jobs = {item["job_id"]: item for item in NucleiFindingJournal(data_dir).load()}
    except NucleiFindingJournalError:
        finding_jobs = {}

    def change(data: Any) -> dict[str, Any]:
        rows = data.get("requests", []) if isinstance(data, dict) else []
        for item in rows:
            if not isinstance(item, dict):
                continue
            if item.get("status") == "launching":
                if _launch_reservation_expired(item.get("launching_at")):
                    item.update(
                        status="failed", failed_at=_utc_now(),
                        failure_reason="iş kuyruğu başlatma rezervasyonu zaman aşımına uğradı",
                    )
                continue
            if item.get("status") not in {"started", "running"}:
                continue
            outer = _persisted_job(data_dir, item.get("job_id"))
            scanner_id = item.get("scanner_job_id")
            if outer is None and _launch_reservation_expired(item.get("started_at")):
                item.update(
                    status="failed", failed_at=_utc_now(),
                    failure_reason="kalıcı iş kaydı bulunamadı; tarama başlatılamadı",
                )
                continue
            if outer is not None:
                outer_state = outer.get("state")
                if outer_state == "cancelled":
                    finished_at = outer.get("finished_at")
                    if not isinstance(finished_at, str) or re.fullmatch(
                            r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", finished_at) is None:
                        finished_at = _utc_now()
                    item.update(
                        status="cancelled", cancelled_at=finished_at,
                        cancellation_reason="bağlı dış iş iptal edildi",
                    )
                    continue
                if outer_state in {"failed", "expired", "interrupted"}:
                    item.update(status="failed", failed_at=_utc_now(), failure_reason="tarama işi tamamlanamadı")
                    continue
                if outer_state in {"queued", "running"}:
                    item["status"] = "running"
                parameters = item.get("parameters")
                is_nuclei = item.get("profile_id") == "nuclei_http_authorized" \
                    or (item.get("profile_id") == "operator_authorized_http"
                        and isinstance(parameters, dict) and parameters.get("tool_id") == "nuclei")
                if outer_state == "succeeded" and is_nuclei:
                    result = outer.get("result")
                    candidate = result.get("job_id") if isinstance(result, dict) else None
                    if isinstance(candidate, str) and _NUCLEI_JOB_ID.fullmatch(candidate):
                        scanner_id = candidate
                        item.update(status="running", scanner_job_id=candidate)
                    else:
                        item.update(status="failed", failed_at=_utc_now(),
                                    failure_reason="Nuclei iç iş kimliği doğrulanamadı")
                        continue
                elif outer_state == "succeeded":
                    item.update(status="completed", completed_at=_utc_now(),
                                triage_summary=_masked_outer_summary(item, outer.get("result")))
                    continue
            aggregate = nuclei.get(scanner_id) if isinstance(scanner_id, str) else None
            if not isinstance(aggregate, dict):
                continue
            if aggregate.get("state") == "completed":
                summary = {key: aggregate[key] for key in (
                    "state", "elapsed_seconds", "report_sha256", "record_count",
                    "severity_counts", "unique_template_count",
                ) if key in aggregate}
                finding_job = finding_jobs.get(scanner_id)
                if isinstance(finding_job, dict):
                    findings = finding_job.get("findings", [])
                    summary.update(finding_count=len(findings), findings_truncated=finding_job.get("truncated") is True)
                    if store is not None and hasattr(store, "import_network_scan_findings"):
                        parameters = item.get("parameters") if isinstance(item.get("parameters"), dict) else {}
                        try:
                            if item.get("profile_id") == "operator_authorized_http":
                                store.import_network_direct_scan_findings(
                                    request_id=item["id"], scanner_job_id=scanner_id,
                                    target_sha256=hashlib.sha256(
                                        str(item.get("normalized_target") or "").encode("utf-8")
                                    ).hexdigest(), findings=findings,
                                )
                            else:
                                store.import_network_scan_findings(
                                    request_id=item["id"], scanner_job_id=scanner_id,
                                    target_id=parameters.get("target_id"),
                                    engagement_id=parameters.get("engagement_id"), findings=findings,
                                )
                        except (ValueError, TypeError, OSError):
                            summary["findings_imported"] = False
                        else:
                            summary["findings_imported"] = True
                item.update(status="completed", completed_at=_utc_now(), triage_summary=summary)
            elif aggregate.get("state") == "cancelled":
                item.update(
                    status="cancelled", cancelled_at=_utc_now(),
                    cancellation_reason="Nuclei iç işi iptal edildi",
                )
            elif aggregate.get("state") == "failed":
                item.update(status="failed", failed_at=_utc_now(), failure_reason="Nuclei taraması tamamlanamadı")
        return data

    try:
        ops_files.update_json(FILE_NAME, _default, change, _env_for(data_dir))
    except (ops_files.OpsStoreError, OSError, ValueError):
        return


def _valid_engagement_targets(store) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for engagement in store.list_engagements():
        if engagement.get("status") != "active" or not str(engagement.get("authorization_ref") or "").strip() \
                or not str(engagement.get("scope_notes") or "").strip():
            continue
        target = store.get_target(str(engagement.get("target_id") or ""))
        if not target or target.get("status") != "ready":
            continue
        rows.append({
            "target_id": str(target["id"]),
            "engagement_id": str(engagement["id"]),
            "label": str(target.get("hostname") or "")[:253],
        })
    return sorted(rows, key=lambda row: (row["label"], row["engagement_id"]))


def catalog(store, *, environ: dict[str, str] | None = None) -> dict[str, Any]:
    """Profilleri ve yürütmeye uygun kimlikleri döndürür; sır/yetki metni döndürmez."""
    env = dict(os.environ if environ is None else environ)
    env.setdefault("SNIPER_DATA_DIR", str(_data_dir(store)))
    try:
        sandbox = sandbox_targets.status(env)
    except (OSError, ValueError):
        sandbox = {"targets": []}
    profiles = []
    for source in PROFILES:
        item = {key: source[key] for key in ("id", "label", "risk", "required", "optional")}
        item["required"] = list(item["required"])
        item["optional"] = list(item["optional"])
        if source["target_source"] == "authorized_engagements":
            item["allowed_targets"] = _valid_engagement_targets(store)
        elif source["target_source"] == "sandbox_targets":
            tool = source["target_tool"]
            item["allowed_targets"] = [
                {"target": f"{target['scheme']}://{target['host']}:{target['port']}",
                 "label": str(target.get("label") or target.get("id") or "")[:64],
                 "kind": target.get("kind")}
                for target in sandbox.get("targets", []) if tool in (target.get("tools") or [])
            ]
        else:
            item["free_target_entry"] = True
            item["target_format"] = "http_or_https"
            item["allowed_tools"] = mcp_authorized_target_tools()
        profiles.append(item)
    return {"format": "sniper-mcp-scan-catalog/1", "profiles": profiles, "starts_scans": False,
            "approval_required": True}


def _validate_nuclei(store, parameters: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    target_id, engagement_id = parameters.get("target_id"), parameters.get("engagement_id")
    if not isinstance(target_id, str) or not isinstance(engagement_id, str):
        raise ScanRequestError("target_id ve engagement_id metin olmalı.")
    target, engagement = store.get_target(target_id), store.get_engagement(engagement_id)
    if target is None or engagement is None:
        raise ScanRequestError("Hedef veya denetim bulunamadı.")
    if target.get("status") != "ready" or engagement.get("status") != "active" \
            or engagement.get("target_id") != target_id \
            or not str(engagement.get("authorization_ref") or "").strip() \
            or not str(engagement.get("scope_notes") or "").strip():
        raise ScanRequestError("Etkin, kapsamı ve yetkisi kayıtlı eşleşen hedef/denetim gerekli.")
    requested: dict[str, Any] = {"target_id": target_id, "engagement_id": engagement_id}
    template_ids = parameters.get("template_ids")
    if template_ids is not None:
        if not isinstance(template_ids, list) or len(template_ids) > 1000 \
                or any(not isinstance(value, str) or not value or len(value) > 300 for value in template_ids):
            raise ScanRequestError("template_ids en çok 1000 dolu metin içermeli.")
        requested["template_ids"] = list(template_ids)
    include_excluded = parameters.get("include_excluded")
    if include_excluded is not None:
        if type(include_excluded) is not bool:
            raise ScanRequestError("include_excluded true ya da false olmalı.")
        requested["include_excluded"] = include_excluded
    return requested, {**requested, "confirm_authorized": True}


def _validate_k6(parameters: dict[str, Any], environ: dict[str, str]) -> tuple[dict[str, Any], dict[str, Any]]:
    target = parameters.get("target")
    try:
        resolved = sandbox_targets.resolve_run_target("k6", target, environ)
        preset = sandbox_targets.resolve_preset(parameters.get("preset"), resolved, environ)
    except sandbox_targets.TargetError as exc:
        raise ScanRequestError(str(exc)) from exc
    requested: dict[str, Any] = {"target": target}
    path = parameters.get("path", "/")
    method = parameters.get("method", "GET")
    if not isinstance(path, str) or len(path) > 201 or not path.startswith("/") or "//" in path \
            or "/../" in path + "/" or "/./" in path + "/":
        raise ScanRequestError("Geçersiz k6 yolu.")
    if method not in {"GET", "HEAD"}:
        raise ScanRequestError("k6 yöntemi GET veya HEAD olmalı.")
    requested.update({"path": path, "method": method, "preset": preset["name"]})
    return requested, {**requested, "confirm": True}


def _plan_digest(plan: dict[str, Any]) -> str:
    view = {key: plan.get(key) for key in (
        "mode", "tool_id", "normalized_target", "route", "payload",
        "effective_profile", "scope_summary", "consent_scope",
    )}
    payload = view.get("payload")
    if isinstance(payload, dict) and "schema" in payload:
        payload = dict(payload)
        schema = payload.pop("schema")
        raw = validated_schema(schema)
        payload["schema_sha256"] = hashlib.sha256(raw).hexdigest()
        view["payload"] = payload
    canonical = json.dumps(view, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def operator_dispatch_plan(tool_id: str, target: str, *, profile: object = None,
                           schema: object = None) -> dict[str, Any]:
    """Return the fixed route/payload plan, or an explicit receipt-only plan.

    The input must already be a canonical HTTP(S) URL. Tool-specific parsers are still applied here so a request
    that cannot satisfy the eventual route contract fails before it is written to the approval queue.
    """
    route = OPERATOR_JOB_DISPATCH.get(tool_id)
    if route is None:
        if tool_id != "burp-suite" or profile is not None or schema is not None:
            raise ScanRequestError("Bu araç için yalnız manuel handoff onayı kullanılabilir.")
        try:
            normalized_target = normalize_target(target).url
        except (TargetRejected, UnicodeError, ValueError) as exc:
            raise ScanRequestError(str(exc)) from exc
        plan = {
            "mode": "manual_handoff", "tool_id": tool_id, "normalized_target": normalized_target,
            "route": None, "payload": None, "effective_profile": "burp-manual-handoff-v1",
            "scope_summary": ["Burp Suite için yürütmesiz manuel aktarım makbuzu"],
            "consent_scope": "Bu hedef için yalnız manuel Burp Suite handoff kaydı oluşturulur; iş başlatılmaz.",
        }
        plan["plan_sha256"] = _plan_digest(plan)
        return plan
    try:
        if tool_id == "owasp-zap":
            normalized_target = normalize_zap_authorized_target(target)
            payload = {"target": normalized_target, "confirm_authorized": True}
        elif tool_id == "k6":
            normalized = normalize_target(target)
            host = f"[{normalized.hostname}]" if ":" in normalized.hostname else normalized.hostname
            origin = urlunsplit((normalized.scheme, f"{host}:{normalized.port}", "", "", ""))
            descriptor = parse_authorized_target("k6", origin)
            normalized_target = normalized.url
            payload = {
                "target": descriptor["normalized"],
                "path": normalized.path,
                "method": "GET",
                "preset": "hafif",
                "confirm_authorized": True,
            }
        elif tool_id == "openssl":
            if profile is not None or schema is not None:
                raise ValueError("OpenSSL ek seçenek kabul etmez.")
            normalized_target, _host, _port = normalize_openssl_authorized_target(target)
            payload = {"target": normalized_target, "confirm_authorized": True}
            effective_profile = "openssl-x509-v1"
            scope_summary = ["Tek TLS kökeninde sabit OpenSSL X.509 incelemesi"]
            consent_scope = "Seçilen HTTPS kökeninde sabit X.509 incelemesine yetki veriyorum."
        elif tool_id == "nmap":
            if schema is not None or profile not in (None, "default", "service-light"):
                raise ValueError("Nmap profili default veya service-light olmalı.")
            normalized_target = normalize_authorized_nmap_target(target)
            effective_profile = profile or "default"
            payload = {"target": normalized_target, "profile": effective_profile, "confirm_authorized": True}
            scope_summary = [f"Tek host/IP için sabit port seti ({effective_profile})"]
            consent_scope = "Bu yalın host/IP üzerinde sabit, sınırlı Nmap profilini çalıştırmaya yetki veriyorum."
        elif tool_id == "testssl":
            if schema is not None or profile not in (None, "protocols", "full"):
                raise ValueError("testssl profili protocols veya full olmalı.")
            _host, _port, normalized_target = normalize_authorized_testssl_target(target)
            effective_profile = profile or "protocols"
            payload = {"target": normalized_target, "profile": effective_profile, "confirm_authorized": True}
            scope_summary = [f"Tek HOST:PORT için testssl {effective_profile} profili"]
            consent_scope = "Bu HOST:PORT üzerinde seçili testssl profilini çalıştırmaya yetki veriyorum."
        elif tool_id == "browser-tests":
            if profile is not None or schema is not None:
                raise ValueError("Playwright ek seçenek kabul etmez.")
            normalized_target = str(normalize_playwright_authorized_target(target)["normalized"])
            payload = {"target": normalized_target, "confirm_authorized": True}
            effective_profile = "playwright-root-origin-v1"
            scope_summary = ["Tek kök originde sabit Playwright güvenlik profili"]
            consent_scope = "Bu kök originde sabit Playwright güvenlik isteklerine yetki veriyorum."
        elif tool_id == "nuclei":
            if profile is not None or schema is not None:
                raise ValueError("Nuclei ek seçenek kabul etmez.")
            normalized_target = normalize_authorized_http_origin(target)
            payload = {"target_origin": normalized_target, "confirm_authorized": True}
            effective_profile = "nuclei-authorized-origin-v1"
            scope_summary = ["Tek kök originde sabit üç Nuclei HTTP şablonu"]
            consent_scope = "Bu kök originde sabit Nuclei HTTP şablonlarını çalıştırmaya yetki veriyorum."
        elif tool_id == "ssllabs":
            if profile is not None or schema is not None:
                raise ValueError("SSL Labs ek seçenek kabul etmez.")
            normalized_target = validate_ssllabs_hostname(normalize_public_hostname(target))
            payload = {"target": normalized_target, "confirm_authorized": True}
            effective_profile = "ssllabs-public-https-443-v1"
            scope_summary = ["Public DNS HTTPS:443 için Qualys SSL Labs değerlendirmesi"]
            consent_scope = ("Bu public DNS hedefini HTTPS:443 değerlendirmesi için Qualys SSL Labs "
                             "üçüncü taraf hizmetine aktarmaya yetki veriyorum.")
        elif tool_id == "schemathesis":
            if profile is not None or schema is None:
                raise ValueError("Schemathesis inline OpenAPI şeması gerektirir ve profil kabul etmez.")
            descriptor = parse_authorized_target("schemathesis", target)
            normalized_target = str(descriptor["normalized"])
            raw = validated_schema(schema)
            payload = {"target": normalized_target, "schema": json.loads(raw), "confirm_authorized": True}
            effective_profile = "schemathesis-authorized-schema-v1"
            scope_summary = ["Tek kök originde inline şemadaki tüm operasyonlar"]
            consent_scope = ("Bu kök originde şemada tanımlı GET/POST/PUT/PATCH/DELETE dahil operasyonlara "
                             "sınırlı Schemathesis istekleri göndermeye yetki veriyorum (POST/DELETE dahil).")
        else:  # pragma: no cover - tablo ve dallar birlikte tutulur
            raise ScanRequestError("Serbest hedef iş planı uygulanmadı.")
        if tool_id == "owasp-zap":
            if profile is not None or schema is not None:
                raise ValueError("ZAP ek seçenek kabul etmez.")
            effective_profile = "zap-authorized-fixed-v1"
            scope_summary = ["Tek normalize HTTP(S) hedefinde sabit ZAP profili"]
            consent_scope = "Bu hedefte sabit ZAP profilini çalıştırmaya yetki veriyorum."
        elif tool_id == "k6":
            if profile is not None or schema is not None:
                raise ValueError("k6 ek seçenek kabul etmez.")
            effective_profile = "k6-hafif-get-v1"
            scope_summary = [f"Tek hedefte hafif GET yük profili; yol {normalized.path}"]
            consent_scope = "Bu tam hedef yolunda hafif GET yük profilini çalıştırmaya yetki veriyorum."
    except (TargetRejected, UnicodeError, ValueError) as exc:
        raise ScanRequestError(str(exc)) from exc
    plan = {
        "mode": "job", "tool_id": tool_id, "normalized_target": normalized_target,
        "route": route, "payload": payload, "effective_profile": effective_profile,
        "scope_summary": scope_summary, "consent_scope": consent_scope,
    }
    plan["plan_sha256"] = _plan_digest(plan)
    return plan


def _validate_operator_target(parameters: dict[str, Any]) -> tuple[dict[str, Any], str, dict[str, Any], bytes | None]:
    tool_id, target = parameters.get("tool_id"), parameters.get("target")
    allowed = {row["tool_id"] for row in mcp_authorized_target_tools()}
    if not isinstance(tool_id, str) or tool_id not in allowed:
        raise ScanRequestError("Serbest hedef planı için katalogdaki bir ağ aracı seçilmeli.")
    if not isinstance(target, str) or not target or len(target) > 2048:
        raise ScanRequestError("Serbest hedef boş olmayan ve en çok 2048 karakterlik bir metin olmalı.")
    expected = {"tool_id", "target"}
    has_profile = "profile" in parameters
    has_options = "options" in parameters
    profile = parameters.get("profile")
    options = parameters.get("options")
    schema = None
    if tool_id in {"nmap", "testssl"}:
        expected.add("profile")
        if has_options or (has_profile and not isinstance(profile, str)):
            raise ScanRequestError("Bu araç options kabul etmez.")
    elif tool_id == "schemathesis":
        expected.add("options")
        if has_profile or not has_options or not isinstance(options, dict) or set(options) != {"schema"}:
            raise ScanRequestError("Schemathesis yalnız options.schema nesnesini kabul eder.")
        schema = options["schema"]
    elif has_profile or has_options:
        raise ScanRequestError("Bu araç ek profil veya seçenek kabul etmez.")
    if set(parameters) - expected:
        raise ScanRequestError("Araç parametreleri tanınmayan alan içeriyor.")
    plan = operator_dispatch_plan(tool_id, target, profile=profile, schema=schema)
    normalized_target = str(plan["normalized_target"])
    requested: dict[str, Any] = {"tool_id": tool_id, "target": normalized_target}
    if tool_id in {"nmap", "testssl"}:
        requested["profile"] = plan["effective_profile"]
    schema_raw = validated_schema(schema) if tool_id == "schemathesis" else None
    return requested, normalized_target, plan, schema_raw


def _operator_public_plan(parameters: dict[str, Any], request_id: str) -> dict[str, Any]:
    """Rebuild receipt-bound fields from the persisted, public parameter surface.

    Schemathesis schema bytes are deliberately gone after launch, so its digest is rebuilt from the
    receipt-bound schema SHA reference rather than reopening or persisting the schema body.
    """
    tool_id = parameters.get("tool_id")
    target = parameters.get("target")
    if tool_id != "schemathesis":
        expected = {"tool_id", "target", "profile"} if tool_id in {"nmap", "testssl"} \
            else {"tool_id", "target"}
        if set(parameters) != expected or not isinstance(target, str):
            raise ScanRequestError("Yetki beyanı görünür araç parametreleri geçersiz.")
        return operator_dispatch_plan(tool_id, target, profile=parameters.get("profile"))

    if set(parameters) != {"tool_id", "target", "options"} or not isinstance(target, str):
        raise ScanRequestError("Yetki beyanı Schemathesis parametreleri geçersiz.")
    metadata = parameters.get("options")
    expected_ref = f"schema-{request_id}.json"
    if not isinstance(metadata, dict) or set(metadata) != {"schema_ref", "schema_sha256", "schema_size"} \
            or metadata.get("schema_ref") != expected_ref \
            or not isinstance(metadata.get("schema_sha256"), str) \
            or not re.fullmatch(r"[0-9a-f]{64}", metadata["schema_sha256"]) \
            or type(metadata.get("schema_size")) is not int \
            or not 1 <= metadata["schema_size"] <= MAX_SCHEMA_SPOOL_BYTES:
        raise ScanRequestError("Yetki beyanı Schemathesis şema başvurusuyla eşleşmiyor.")
    try:
        normalized_target = str(parse_authorized_target("schemathesis", target)["normalized"])
    except (TargetRejected, UnicodeError, ValueError) as exc:
        raise ScanRequestError(str(exc)) from exc
    if normalized_target != target:
        raise ScanRequestError("Yetki beyanı Schemathesis hedefi kanonik değil.")
    plan = {
        "mode": "job", "tool_id": "schemathesis", "normalized_target": normalized_target,
        "route": OPERATOR_JOB_DISPATCH["schemathesis"],
        "payload": {
            "target": normalized_target, "schema_sha256": metadata["schema_sha256"],
            "confirm_authorized": True,
        },
        "effective_profile": "schemathesis-authorized-schema-v1",
        "scope_summary": ["Tek kök originde inline şemadaki tüm operasyonlar"],
        "consent_scope": (
            "Bu kök originde şemada tanımlı GET/POST/PUT/PATCH/DELETE dahil operasyonlara "
            "sınırlı Schemathesis istekleri göndermeye yetki veriyorum (POST/DELETE dahil)."
        ),
    }
    canonical = json.dumps(plan, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    plan["plan_sha256"] = hashlib.sha256(canonical).hexdigest()
    return plan


def _open_schema_spool(data_dir: Path, *, create: bool) -> int:
    """Open the spool through stable directory descriptors, never mutable path parents."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    data_fd = -1
    try:
        data_fd = os.open(data_dir, flags)
        data_info = os.fstat(data_fd)
        if not stat.S_ISDIR(data_info.st_mode) or data_info.st_uid != os.getuid():
            raise ScanRequestError("Sniper veri dizini güvenli değil.")
        if create:
            try:
                os.mkdir(SCHEMA_SPOOL_DIR, 0o700, dir_fd=data_fd)
            except FileExistsError:
                pass
        spool_fd = os.open(SCHEMA_SPOOL_DIR, flags, dir_fd=data_fd)
    except ScanRequestError:
        raise
    except OSError as exc:
        raise ScanRequestError("Schemathesis şema spool dizini kullanılamıyor.") from exc
    finally:
        if data_fd >= 0:
            os.close(data_fd)
    info = os.fstat(spool_fd)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        os.close(spool_fd)
        raise ScanRequestError("Schemathesis şema spool dizini güvenli değil.")
    return spool_fd


def _write_schema_spool(data_dir: Path, request_id: str, raw: bytes) -> dict[str, Any]:
    if not _REQUEST_ID.fullmatch(request_id) or not raw or len(raw) > MAX_SCHEMA_SPOOL_BYTES:
        raise ScanRequestError("Schemathesis şema spool verisi geçersiz.")
    reference = f"schema-{request_id}.json"
    spool_fd = _open_schema_spool(data_dir, create=True)
    file_fd = -1
    created = False
    try:
        file_fd = os.open(
            reference,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
            0o600,
            dir_fd=spool_fd,
        )
        created = True
        offset = 0
        while offset < len(raw):
            written = os.write(file_fd, raw[offset:])
            if written <= 0:
                raise OSError("short write")
            offset += written
        os.fsync(file_fd)
    except OSError as exc:
        if file_fd >= 0:
            os.close(file_fd)
            file_fd = -1
        if created:
            try:
                os.unlink(reference, dir_fd=spool_fd)
            except OSError:
                pass
        raise ScanRequestError("Schemathesis şeması güvenli spool alanına yazılamadı.") from exc
    finally:
        if file_fd >= 0:
            os.close(file_fd)
        os.close(spool_fd)
    return {"schema_ref": reference, "schema_sha256": hashlib.sha256(raw).hexdigest(), "schema_size": len(raw)}


def _read_schema_spool(data_dir: Path, metadata: object, request_id: str) -> dict[str, Any]:
    expected_ref = f"schema-{request_id}.json"
    if not isinstance(metadata, dict) or set(metadata) != {"schema_ref", "schema_sha256", "schema_size"} \
            or metadata.get("schema_ref") != expected_ref \
            or not isinstance(metadata.get("schema_sha256"), str) \
            or not re.fullmatch(r"[0-9a-f]{64}", metadata["schema_sha256"]) \
            or type(metadata.get("schema_size")) is not int \
            or not 1 <= metadata["schema_size"] <= MAX_SCHEMA_SPOOL_BYTES:
        raise ScanRequestError("Schemathesis şema spool başvurusu geçersiz.")
    spool_fd = _open_schema_spool(data_dir, create=False)
    try:
        fd = os.open(
            expected_ref,
            os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
            dir_fd=spool_fd,
        )
    except OSError as exc:
        os.close(spool_fd)
        raise ScanRequestError("Schemathesis şema spool kaydı okunamadı.") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 \
                or info.st_size != metadata["schema_size"]:
            raise ScanRequestError("Schemathesis şema spool kaydı güvenli değil.")
        raw = os.read(fd, info.st_size + 1)
    finally:
        os.close(fd)
        os.close(spool_fd)
    if len(raw) != metadata["schema_size"] \
            or not secrets.compare_digest(hashlib.sha256(raw).hexdigest(), metadata["schema_sha256"]):
        raise ScanRequestError("Schemathesis şema spool bütünlüğü doğrulanamadı.")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ScanRequestError("Schemathesis şema spool içeriği geçersiz.") from exc
    if validated_schema(value) != raw:
        raise ScanRequestError("Schemathesis şema spool içeriği kanonik değil.")
    return value


def _cleanup_schema_spool(data_dir: Path, item: dict[str, Any]) -> None:
    if item.get("_tool_id") != "schemathesis":
        return
    metadata = item.get("parameters", {}).get("options") if isinstance(item.get("parameters"), dict) else None
    reference = metadata.get("schema_ref") if isinstance(metadata, dict) else None
    if reference != f"schema-{item.get('id')}.json":
        return
    try:
        spool_fd = _open_schema_spool(data_dir, create=False)
    except ScanRequestError:
        return
    try:
        try:
            os.unlink(reference, dir_fd=spool_fd)
        except FileNotFoundError:
            pass
        except OSError:
            pass
    finally:
        os.close(spool_fd)


def _cleanup_orphan_schema_spools(data_dir: Path, rows: list[Any]) -> None:
    try:
        spool_fd = _open_schema_spool(data_dir, create=False)
    except ScanRequestError:
        return
    active = {
        f"schema-{row.get('id')}.json" for row in rows
        if isinstance(row, dict) and row.get("status") in {"pending", "launching"}
        and row.get("_tool_id") == "schemathesis"
    }
    try:
        children = os.listdir(spool_fd)
    except OSError:
        os.close(spool_fd)
        return
    try:
        for name in children:
            if not re.fullmatch(r"schema-msr_[0-9a-f]{16}\.json", name) or name in active:
                continue
            try:
                info = os.stat(name, dir_fd=spool_fd, follow_symlinks=False)
                if stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid():
                    os.unlink(name, dir_fd=spool_fd)
            except OSError:
                continue
    finally:
        os.close(spool_fd)


def preview_request(store, profile_id: object, parameters: object,
                    *, environ: dict[str, str] | None = None) -> dict[str, Any]:
    """Validate and canonicalize a scan request without persisting or launching it.

    The returned parameters are valid input for ``create_request`` and the plan
    digest is the same digest that the eventual persisted request will carry.
    """
    if not isinstance(parameters, dict):
        raise ScanRequestError("parameters bir nesne olmalı.")
    profile = _profile(profile_id)
    allowed = set(profile["required"]) | set(profile["optional"])
    if set(parameters) - allowed or not set(profile["required"]) <= set(parameters):
        raise ScanRequestError("Profil parametreleri eksik veya tanınmayan alan içeriyor.")
    data_dir = _data_dir(store)
    env = dict(os.environ if environ is None else environ)
    env.setdefault("SNIPER_DATA_DIR", str(data_dir))
    if profile["id"] == "nuclei_http_authorized":
        requested, launch = _validate_nuclei(store, parameters)
        target = store.get_target(requested["target_id"])
        normalized_target = str(target.get("url") or "") if isinstance(target, dict) else ""
        tool_id = "nuclei"
        request_parameters = requested
        effective_profile = profile["id"]
        scope_summary = [profile["label"]]
        consent_scope = profile["label"]
        execution = "job"
        route = profile["route"]
        plan_sha256 = hashlib.sha256(
            json.dumps({"route": route, "payload": launch}, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
    elif profile["id"] == "sandbox_k6":
        requested, launch = _validate_k6(parameters, env)
        normalized_target = requested["target"]
        tool_id = "k6"
        request_parameters = requested
        effective_profile = profile["id"]
        scope_summary = [profile["label"]]
        consent_scope = profile["label"]
        execution = "job"
        route = profile["route"]
        plan_sha256 = hashlib.sha256(
            json.dumps({"route": route, "payload": launch}, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
    elif profile["id"] == "operator_authorized_http":
        requested, normalized_target, plan, schema_raw = _validate_operator_target(parameters)
        request_parameters = dict(requested)
        if schema_raw is not None:
            request_parameters["options"] = {"schema": json.loads(schema_raw)}
        tool_id = requested["tool_id"]
        effective_profile = plan["effective_profile"]
        scope_summary = list(plan["scope_summary"])
        consent_scope = plan["consent_scope"]
        execution = plan["mode"]
        route = plan.get("route")
        plan_sha256 = plan["plan_sha256"]
    else:  # pragma: no cover - profile table and branches are kept together
        raise ScanRequestError("Profil uygulanmadı.")
    return {
        "profile_id": profile["id"],
        "parameters": request_parameters,
        "normalized_target": normalized_target,
        "tool_id": tool_id,
        "execution": execution,
        "route": route,
        "effective_profile": effective_profile,
        "scope_summary": scope_summary,
        "consent_scope": consent_scope,
        "scan_plan_sha256": plan_sha256,
    }


def create_request(store, profile_id: object, parameters: object, *, requester: dict[str, Any],
                   confirm_request: object, environ: dict[str, str] | None = None) -> dict[str, Any]:
    if confirm_request is not True:
        raise ScanRequestError("Tarama isteği için confirm_request tam olarak true olmalı.")
    if not isinstance(requester, dict) or requester.get("role") not in {"analyst", "admin"}:
        raise ScanRequestError("Tarama isteği için analist veya yönetici gerekir.")
    if not isinstance(parameters, dict):
        raise ScanRequestError("parameters bir nesne olmalı.")
    profile = _profile(profile_id)
    allowed = set(profile["required"]) | set(profile["optional"])
    if set(parameters) - allowed or not set(profile["required"]) <= set(parameters):
        raise ScanRequestError("Profil parametreleri eksik veya tanınmayan alan içeriyor.")
    data_dir = _data_dir(store)
    env = dict(os.environ if environ is None else environ)
    env.setdefault("SNIPER_DATA_DIR", str(data_dir))
    request_id = "msr_" + secrets.token_hex(8)
    schema_spooled = False
    if profile["id"] == "nuclei_http_authorized":
        requested, launch = _validate_nuclei(store, parameters)
        target = store.get_target(requested["target_id"])
        normalized_target = str(target.get("url") or "") if isinstance(target, dict) else ""
        tool_id = "nuclei"
    elif profile["id"] == "sandbox_k6":
        requested, launch = _validate_k6(parameters, env)
        normalized_target = requested["target"]
        tool_id = "k6"
    elif profile["id"] == "operator_authorized_http":
        requested, normalized_target, plan, schema_raw = _validate_operator_target(parameters)
        if schema_raw is not None:
            requested["options"] = _write_schema_spool(data_dir, request_id, schema_raw)
            schema_spooled = True
        # Operatör planı onayda görünür alanlardan yeniden türetilir. Özellikle inline şema
        # kuyruğa gömülmez; persisted rota/payload yürütme otoritesi değildir.
        launch = None
        profile["route"] = plan.get("route")
        tool_id = requested["tool_id"]
    else:  # pragma: no cover - profil tablosu ve dallar birlikte tutulur
        raise ScanRequestError("Profil uygulanmadı.")
    item = {
        "id": request_id,
        "profile_id": profile["id"],
        "status": "pending",
        "parameters": requested,
        "normalized_target": normalized_target,
        "requested_by": {key: str(requester.get(key) or "")[:120] for key in ("id", "username")},
        "created_at": _utc_now(),
        "_route": profile["route"],
        "_launch_payload": launch,
        "_tool_id": tool_id,
        "effective_profile": plan.get("effective_profile", profile["id"]) if profile["id"] == "operator_authorized_http" else profile["id"],
        "scope_summary": plan.get("scope_summary", [profile["label"]]) if profile["id"] == "operator_authorized_http" else [profile["label"]],
        "consent_scope": plan.get("consent_scope", profile["label"]) if profile["id"] == "operator_authorized_http" else profile["label"],
        "plan_sha256": plan.get("plan_sha256") if profile["id"] == "operator_authorized_http" else hashlib.sha256(
            json.dumps({"route": profile["route"], "payload": launch}, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
    }
    def change(data: Any) -> dict[str, Any]:
        if not isinstance(data, dict) or data.get("format") != FORMAT or not isinstance(data.get("requests"), list):
            data = _default()
        active = [row for row in data["requests"]
                  if isinstance(row, dict) and isinstance(row.get("status"), str)
                  and row.get("status") in NONTERMINAL_STATUSES]
        duplicate = next((row for row in active if row.get("profile_id") == item["profile_id"] and (
            row.get("parameters") == item["parameters"]
            or (item["profile_id"] == "operator_authorized_http"
                and row.get("plan_sha256") == item.get("plan_sha256"))
        )), None)
        if duplicate:
            raise ScanRequestError("Aynı profil ve hedef için bekleyen bir istek zaten var.")
        rows = list(data["requests"])
        remove_count = max(0, len(rows) + 1 - MAX_REQUESTS)
        terminal = sorted(
            (
                (str(row.get("created_at") or ""), index)
                for index, row in enumerate(rows)
                if isinstance(row, dict) and isinstance(row.get("status"), str)
                and row.get("status") in TERMINAL_STATUSES
            ),
            key=lambda candidate: (candidate[0], candidate[1]),
        )
        if len(terminal) < remove_count:
            raise ScanRequestError("Tarama isteği kuyruğu etkin işlerle dolu; terminal bir iş tamamlanmadan yeni istek alınamaz.")
        removed = {index for _created_at, index in terminal[:remove_count]}
        data["requests"] = [row for index, row in enumerate(rows) if index not in removed] + [item]
        return data

    try:
        ops_files.update_json(FILE_NAME, _default, change, _env_for(data_dir))
    except Exception:
        if schema_spooled:
            _cleanup_schema_spool(data_dir, item)
        raise
    return _public(item)


def list_requests(store_or_path: Any, *, requester: dict[str, Any] | None = None,
                  status: str | None = None) -> list[dict[str, Any]]:
    data_dir = _data_dir(store_or_path)
    store = store_or_path if hasattr(store_or_path, "import_network_scan_findings") else None
    _refresh_from_persisted_jobs(data_dir, store)
    data = ops_files.read_json(FILE_NAME, _default, _env_for(data_dir))
    rows = data.get("requests", []) if isinstance(data, dict) else []
    _cleanup_orphan_schema_spools(data_dir, rows)
    allowed_statuses = {"pending", "approved", "launching", "started", "running", "completed", "cancelled", "failed"}
    if status is not None and status not in allowed_statuses:
        raise ScanRequestError("Geçersiz istek durumu.")
    result = []
    for row in rows:
        if not isinstance(row, dict) or not _REQUEST_ID.fullmatch(str(row.get("id") or "")):
            continue
        if requester and requester.get("role") != "admin" \
                and row.get("requested_by", {}).get("id") != requester.get("id"):
            continue
        if status is None or row.get("status") == status:
            result.append(_public(row))
    return list(reversed(result))


def _request_for_user(store, request_id: object, requester: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(request_id, str) or not _REQUEST_ID.fullmatch(request_id) \
            or not isinstance(requester, dict) or requester.get("role") not in {"reader", "analyst", "admin"}:
        raise ScanRequestError("Geçersiz tarama isteği erişimi.")
    item = next((row for row in list_requests(store, requester=requester) if row["id"] == request_id), None)
    is_registered = item is not None and item.get("profile_id") == "nuclei_http_authorized"
    is_direct = item is not None and item.get("profile_id") == "operator_authorized_http" \
        and item.get("parameters", {}).get("tool_id") == "nuclei"
    if item is None or not (is_registered or is_direct):
        raise ScanRequestError("Tarama isteği bulunamadı veya erişim yok.")
    return item


def list_findings(store, request_id: object, *, requester: dict[str, Any]) -> list[dict[str, Any]]:
    """Kullanıcının görebildiği Nuclei isteğinin maskeli, kalıcı bulgularını döndür."""
    item = _request_for_user(store, request_id, requester)
    if item.get("status") != "completed":
        raise ScanRequestError("Tarama bulguları yalnız tamamlanan isteklerde kullanılabilir.")
    if item.get("profile_id") == "operator_authorized_http":
        return store.list_network_direct_scan_findings(item["id"])
    return store.list_network_scan_findings(item["id"])


def submit_finding_triage(
    store,
    request_id: object,
    finding_id: object,
    *,
    requester: dict[str, Any],
    verdict: object,
    confidence: object,
    rationale: object,
    agent: object = "",
    model: object = "",
) -> dict[str, Any]:
    """Kararı değiştirmeden Nuclei bulgusu için analist/ajan önerisi kaydet."""
    if not isinstance(requester, dict) or requester.get("role") not in {"analyst", "admin"}:
        raise ScanRequestError("Triyaj önerisi için analist veya yönetici gerekir.")
    item = _request_for_user(store, request_id, requester)
    direct = item.get("profile_id") == "operator_authorized_http"
    expected_id = r"nsd_[0-9a-f]{12}" if direct else r"nsf_[0-9a-f]{12}"
    if not isinstance(finding_id, str) or not re.fullmatch(expected_id, finding_id):
        raise ScanRequestError("Geçersiz ağ taraması bulgu kimliği.")
    list_method = store.list_network_direct_scan_findings if direct else store.list_network_scan_findings
    finding = next((row for row in list_method(item["id"])
                    if row["id"] == finding_id), None)
    if finding is None:
        raise ScanRequestError("Ağ taraması bulgusu bu isteğe ait değil.")
    try:
        method = store.record_network_direct_scan_triage if direct else store.record_network_scan_triage
        return method(
            finding_id, verdict=verdict, confidence=confidence, rationale=rationale,
            agent=agent if isinstance(agent, str) else "", model=model if isinstance(model, str) else "",
            submitted_by=str(requester.get("id") or "")[:120],
        )
    except (TypeError, ValueError) as exc:
        raise ScanRequestError(str(exc)) from exc


def _registered_claim_plan(store_or_path: Any, item: dict[str, Any], data_dir: Path) -> dict[str, Any]:
    """Rebuild legacy registered-profile launch data without trusting persisted private fields."""
    profile_id = item.get("profile_id")
    parameters = item.get("parameters")
    if not isinstance(parameters, dict):
        raise ScanRequestError("Tarama isteği parametreleri geçersiz.")
    if profile_id == "nuclei_http_authorized":
        if set(parameters) - {"target_id", "engagement_id", "template_ids", "include_excluded"} \
                or not {"target_id", "engagement_id"} <= set(parameters):
            raise ScanRequestError("Kayıtlı Nuclei parametreleri geçersiz.")
        if hasattr(store_or_path, "get_target"):
            requested, payload = _validate_nuclei(store_or_path, parameters)
        else:
            target_id, engagement_id = parameters.get("target_id"), parameters.get("engagement_id")
            if not isinstance(target_id, str) or not target_id \
                    or not isinstance(engagement_id, str) or not engagement_id:
                raise ScanRequestError("Kayıtlı Nuclei parametreleri geçersiz.")
            requested = dict(parameters)
            payload = {**requested, "confirm_authorized": True}
        route, tool_id = "/api/nuclei/http-scans", "nuclei"
        normalized_target = item.get("normalized_target")
    elif profile_id == "sandbox_k6":
        if set(parameters) - {"target", "path", "method", "preset"} or "target" not in parameters:
            raise ScanRequestError("Kayıtlı k6 parametreleri geçersiz.")
        requested, payload = _validate_k6(parameters, _env_for(data_dir))
        route, tool_id = "/api/tool-runs/k6-sandbox", "k6"
        normalized_target = requested["target"]
    else:
        raise ScanRequestError("Tarama profili onayda yeniden türetilemedi.")
    if not isinstance(normalized_target, str) or not normalized_target:
        raise ScanRequestError("Tarama hedefi onayda yeniden türetilemedi.")
    metadata = {
        "effective_profile": str(profile_id),
        "scope_summary": [_profile(profile_id)["label"]],
        "consent_scope": _profile(profile_id)["label"],
    }
    plan_sha256 = hashlib.sha256(
        json.dumps({"route": route, "payload": payload}, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return {
        "mode": "job", "tool_id": tool_id, "normalized_target": normalized_target,
        "route": route, "payload": payload, "plan_sha256": plan_sha256, **metadata,
    }


def claim_request(store_or_path: Any, request_id: object, *, approved_by: dict[str, Any],
                  confirm_authorized: object) -> dict[str, Any]:
    if not isinstance(request_id, str) or not _REQUEST_ID.fullmatch(request_id):
        raise ScanRequestError("Geçersiz tarama isteği kimliği.")
    if not isinstance(approved_by, dict) or approved_by.get("role") != "admin":
        raise ScanRequestError("Tarama başlatmak için ayrı yönetici onayı gerekir.")
    if confirm_authorized is not True:
        raise ScanRequestError("Hedef yetkisi için confirm_authorized tam olarak true olmalı.")
    data_dir = _data_dir(store_or_path)
    selected: dict[str, Any] = {}
    transient_plan: dict[str, Any] = {}
    validation_failure: list[str] = []

    def change(data: Any) -> dict[str, Any]:
        if not isinstance(data, dict) or not isinstance(data.get("requests"), list):
            raise ScanRequestError("Tarama istek kuyruğu geçersiz.")
        item = next((row for row in data["requests"] if isinstance(row, dict) and row.get("id") == request_id), None)
        if item is None:
            raise ScanRequestError("Tarama isteği bulunamadı.")
        if item.get("status") != "pending":
            raise ScanRequestError("Yalnız bekleyen tarama isteği başlatılabilir.")
        if item.get("profile_id") == "operator_authorized_http":
            try:
                parameters = item.get("parameters")
                if not isinstance(parameters, dict):
                    raise ScanRequestError("Tarama isteği parametreleri geçersiz.")
                tool_id = parameters.get("tool_id")
                schema = None
                if tool_id == "schemathesis":
                    schema = _read_schema_spool(data_dir, parameters.get("options"), request_id)
                plan = operator_dispatch_plan(
                    str(tool_id), str(parameters.get("target") or ""),
                    profile=parameters.get("profile"), schema=schema,
                )
                if item.get("plan_sha256") != plan["plan_sha256"]:
                    raise ScanRequestError("Tarama planı bütünlük denetimini geçemedi.")
            except ScanRequestError as exc:
                item.update(status="failed", failed_at=_utc_now(), failure_reason=str(exc)[:160])
                selected.update(item)
                validation_failure.append(str(exc))
                return data
            transient_plan.update(plan)
            item.update(
                _route=plan["route"], _launch_payload=None,
                _tool_id=plan["tool_id"], normalized_target=plan["normalized_target"],
                effective_profile=plan["effective_profile"], scope_summary=plan["scope_summary"],
                consent_scope=plan["consent_scope"],
            )
        else:
            try:
                plan = _registered_claim_plan(store_or_path, item, data_dir)
                existing_digest = item.get("plan_sha256")
                if existing_digest is not None and existing_digest != plan["plan_sha256"]:
                    raise ScanRequestError("Kayıtlı tarama planı bütünlük denetimini geçemedi.")
            except ScanRequestError as exc:
                item.update(status="failed", failed_at=_utc_now(), failure_reason=str(exc)[:160])
                selected.update(item)
                validation_failure.append(str(exc))
                return data
            transient_plan.update(plan)
            item.update(
                _route=plan["route"], _launch_payload=None, _tool_id=plan["tool_id"],
                normalized_target=plan["normalized_target"], effective_profile=plan["effective_profile"],
                scope_summary=plan["scope_summary"], consent_scope=plan["consent_scope"],
                plan_sha256=plan["plan_sha256"],
            )
        item["status"] = "approved" if item.get("_route") is None else "launching"
        if item["status"] == "launching":
            item["launching_at"] = _utc_now()
        item["approved_by"] = {key: str(approved_by.get(key) or "")[:120] for key in ("id", "username")}
        item["authorization_receipt"] = _authorization_receipt(item, approved_by)
        item["approved_at"] = item["authorization_receipt"]["confirmed_at"]
        selected.update(item)
        return data

    ops_files.update_json(FILE_NAME, _default, change, _env_for(data_dir))
    if validation_failure:
        _cleanup_schema_spool(data_dir, selected)
        raise ScanRequestError(validation_failure[0])
    public = _public(selected)
    if selected.get("_route") is None:
        return {**public, "dispatch": {
            "mode": "manual_handoff",
            "tool_id": selected["_tool_id"],
            "target": selected["normalized_target"],
        }}
    launch_payload = transient_plan.get("payload")
    if not isinstance(launch_payload, dict) or transient_plan.get("route") != selected.get("_route"):
        raise ScanRequestError("Tarama planı yalnız onay işlemi içinde tutulamadı.")
    return {**public, "launch": {"route": selected["_route"], "payload": dict(launch_payload)}}


def _transition(store_or_path: Any, request_id: str, expected: str | set[str], status: str,
                **fields: Any) -> dict[str, Any]:
    data_dir = _data_dir(store_or_path)
    selected: dict[str, Any] = {}

    def change(data: Any) -> dict[str, Any]:
        rows = data.get("requests", []) if isinstance(data, dict) else []
        item = next((row for row in rows if isinstance(row, dict) and row.get("id") == request_id), None)
        expected_statuses = {expected} if isinstance(expected, str) else expected
        if item is None or item.get("status") not in expected_statuses:
            raise ScanRequestError("Tarama isteği beklenen durumda değil.")
        item.update(status=status, **fields)
        selected.update(item)
        return data

    ops_files.update_json(FILE_NAME, _default, change, _env_for(data_dir))
    if status in {"started", "failed", "cancelled"}:
        _cleanup_schema_spool(data_dir, selected)
    return _public(selected)


def mark_started(store_or_path: Any, request_id: str, job_id: str) -> dict[str, Any]:
    if not isinstance(job_id, str) or not job_id or len(job_id) > 120:
        raise ScanRequestError("Geçersiz iş kimliği.")
    return _transition(store_or_path, request_id, "launching", "started", job_id=job_id, started_at=_utc_now())


def mark_failed(store_or_path: Any, request_id: str, reason: str) -> dict[str, Any]:
    return _transition(store_or_path, request_id, {"pending", "approved", "launching", "started"}, "failed",
                       failed_at=_utc_now(), failure_reason=str(reason)[:160])


def inspect_cancel_request(store_or_path: Any, request_id: str, *, cancelled_by: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(cancelled_by, dict) or cancelled_by.get("role") != "admin":
        raise ScanRequestError("Tarama isteğini iptal etmek için yönetici gerekir.")
    if not isinstance(request_id, str) or not _REQUEST_ID.fullmatch(request_id):
        raise ScanRequestError("Geçersiz tarama isteği.")
    item = next((row for row in list_requests(store_or_path, requester=cancelled_by)
                 if row.get("id") == request_id), None)
    if item is None or not isinstance(item.get("status"), str) \
            or item.get("status") not in NONTERMINAL_STATUSES:
        raise ScanRequestError("Tarama isteği iptal edilebilir durumda değil.")
    return item


def cancel_request(
    store_or_path: Any,
    request_id: str,
    *,
    cancelled_by: dict[str, Any],
    cancelled_job_id: str | None = None,
    cancelled_scanner_job_id: str | None = None,
) -> dict[str, Any]:
    """Persist cancellation only after the matching runtime job accepted it."""
    if not isinstance(cancelled_by, dict) or cancelled_by.get("role") != "admin":
        raise ScanRequestError("Tarama isteğini iptal etmek için yönetici gerekir.")
    if not isinstance(request_id, str) or not _REQUEST_ID.fullmatch(request_id):
        raise ScanRequestError("Geçersiz tarama isteği.")
    data_dir = _data_dir(store_or_path)
    selected: dict[str, Any] = {}

    def change(data: Any) -> dict[str, Any]:
        rows = data.get("requests", []) if isinstance(data, dict) else []
        item = next((row for row in rows if isinstance(row, dict) and row.get("id") == request_id), None)
        if item is None or not isinstance(item.get("status"), str) \
                or item.get("status") not in NONTERMINAL_STATUSES:
            raise ScanRequestError("Tarama isteği iptal edilebilir durumda değil.")
        status = item.get("status")
        if status in {"started", "running"}:
            scanner_id = item.get("scanner_job_id")
            if scanner_id is not None:
                parameters = item.get("parameters")
                is_nuclei = item.get("profile_id") == "nuclei_http_authorized" \
                    or (item.get("profile_id") == "operator_authorized_http"
                        and isinstance(parameters, dict) and parameters.get("tool_id") == "nuclei")
                if not is_nuclei or cancelled_scanner_job_id != scanner_id:
                    raise ScanRequestError("Nuclei iç işi iptal edilmeden istek kapatılamaz.")
            elif not isinstance(item.get("job_id"), str) or cancelled_job_id != item.get("job_id"):
                raise ScanRequestError("Dış iş iptal edilmeden istek kapatılamaz.")
        elif cancelled_job_id is not None or cancelled_scanner_job_id is not None:
            raise ScanRequestError("Bekleyen istek için iş iptal kanıtı beklenmiyor.")
        item.update(
            status="cancelled", cancelled_at=_utc_now(),
            cancelled_by={key: str(cancelled_by.get(key) or "")[:120] for key in ("id", "username")},
        )
        selected.update(item)
        return data

    ops_files.update_json(FILE_NAME, _default, change, _env_for(data_dir))
    _cleanup_schema_spool(data_dir, selected)
    return _public(selected)
