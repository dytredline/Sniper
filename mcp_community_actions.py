"""Community sürümü için MCP ürün eylemi adaptörleri.

Bu modül tarayıcı ya da yeni bir analiz motoru değildir. Yerel Sniper ürün
sözleşmelerini küçük, makine-okunur sonuçlara bağlar. Durum okuma dışındaki
eylemler önce süreli bir plan üretir; plan yalnız ``user_confirmed is True`` ve
aynı planın tam SHA-256 özetiyle bir kez yürütülebilir.

Dış hedef eylemi özellikle farklıdır: önce ``mcp_scan_requests`` kaydını
oluşturur, sonra aynı onaylı plan kimliği ve SHA-256 ile enjekte edilmiş gerçek
iş launcher'ına devreder. Bu modül kendisi ağ çağrısı yapmaz.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import stat
import threading
import time
from typing import Any, Callable


CAPABILITIES_FORMAT = "sniper-community-capabilities-v1"
PLAN_FORMAT = "sniper-community-action-plan-v1"
RESULT_FORMAT = "sniper-community-action-result-v1"
DEFAULT_PLAN_TTL_SECONDS = 300.0
MAX_PLANS = 512

_PLAN_ID = re.compile(r"plan_[0-9a-f]{24}\Z")
_JOB_ID = re.compile(r"job_[0-9a-f]{24}\Z")
_SCAN_REQUEST_ID = re.compile(r"msr_[0-9a-f]{16}\Z")
_PROJECT_AUDIT_ID = re.compile(r"prj_[0-9a-f]{12}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_EXPORT_FORMATS = frozenset({"json", "sarif", "html", "csv"})
_SBOM_FORMATS = frozenset({"cyclonedx", "spdx"})
_COMPARISON_KINDS = frozenset({"project_audit", "network_scan"})

COMMUNITY_TOOLS: list[dict[str, Any]] = [
    {
        "name": "list_community_capabilities",
        "description": "Community MCP ürün eylemlerinin gerçek readiness durumunu listeler; eylem çalıştırmaz.",
        "annotations": {"readOnlyHint": True, "destructiveHint": False,
                        "idempotentHint": True, "openWorldHint": False},
        "inputSchema": {"type": "object", "additionalProperties": False, "properties": {}},
    },
    {
        "name": "community_job_status",
        "description": "Bağlı Sniper iş kuyruğundaki bir işin güvenli durum özetini döndürür.",
        "annotations": {"readOnlyHint": True, "destructiveHint": False,
                        "idempotentHint": True, "openWorldHint": False},
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["job_id"],
            "properties": {"job_id": {"type": "string", "pattern": "^job_[0-9a-f]{24}$"}},
        },
    },
    {
        "name": "prepare_action",
        "description": (
            "Community ürün eylemini çalıştırmadan süreli, tek kullanımlık ve tam normalize parametrelere "
            "SHA-256 bağlı bir plan hazırlar."
        ),
        "annotations": {"readOnlyHint": False, "destructiveHint": False,
                        "idempotentHint": False, "openWorldHint": False},
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["action", "parameters"],
            "properties": {
                "action": {
                    "type": "string",
                    "enum": [
                        "analyze_local_project",
                        "generate_sbom",
                        "compare_saved_scans",
                        "export_saved_audit",
                        "suggest_fix",
                        "verify_fix",
                        "apply_fix",
                        "cancel_job",
                        "request_external_scan",
                    ],
                },
                "parameters": {"type": "object"},
            },
        },
    },
    {
        "name": "execute_action",
        "description": (
            "Önceden hazırlanan planı yalnız kullanıcı sohbet onayı tam true ve plan SHA-256 eşleşiyorsa bir kez "
            "yürütür."
        ),
        "annotations": {"readOnlyHint": False, "destructiveHint": True,
                        "idempotentHint": False, "openWorldHint": True},
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["plan_id", "plan_sha256", "user_confirmed"],
            "properties": {
                "plan_id": {"type": "string", "pattern": "^plan_[0-9a-f]{24}$"},
                "plan_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                "user_confirmed": {"type": "boolean"},
            },
        },
    },
]


class CommunityActionError(ValueError):
    """Community eylemi güvenli biçimde planlanamadı veya yürütülemedi."""


class PlanRejected(CommunityActionError):
    """Plan kimliği, özeti, süresi veya girdileri geçerli değil."""


class ConfirmationRequired(CommunityActionError):
    """Sohbette açık kullanıcı onayı verilmedi."""


class ActionUnavailable(CommunityActionError):
    """İstenen davranışın gerçek ürün adaptörü bu oturumda hazır değil."""


def _canonical_json(value: Any) -> str:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise PlanRejected("Plan parametreleri geçerli JSON olmalıdır.") from exc


def _json_copy(value: Any) -> Any:
    return json.loads(_canonical_json(value))


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _module_ready(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, AttributeError, ValueError):
        return False


def _has_methods(value: Any, *names: str) -> bool:
    return value is not None and all(callable(getattr(value, name, None)) for name in names)


def _text(value: Any, field: str, *, maximum: int = 4096) -> str:
    if not isinstance(value, str):
        raise PlanRejected(f"{field} metin olmalıdır.")
    cleaned = value.strip()
    if not cleaned or len(cleaned) > maximum or "\x00" in cleaned:
        raise PlanRejected(f"{field} geçersiz.")
    return cleaned


def _strict_bool(value: Any, field: str) -> bool:
    if type(value) is not bool:
        raise PlanRejected(f"{field} true ya da false olmalıdır.")
    return value


def _strict_int(value: Any, field: str, *, minimum: int, maximum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
        raise PlanRejected(f"{field} {minimum} ile {maximum} arasında tamsayı olmalıdır.")
    return value


def _only(parameters: dict[str, Any], allowed: set[str]) -> None:
    extras = sorted(set(parameters) - allowed)
    if extras:
        raise PlanRejected("Desteklenmeyen parametreler: " + ", ".join(extras))


class CommunityActions:
    """Mevcut Sniper işlevlerini onay kapılı MCP eylemlerine uyarlar.

    ``store`` ve ``queue`` bilerek enjekte edilir. Eksik bağımlılık için geçici
    başarı üretilmez; ``list_capabilities`` o eylemi ``unavailable`` bildirir ve
    planlama aynı nedenle reddedilir.
    """

    def __init__(
        self,
        *,
        store: Any | None = None,
        queue: Any | None = None,
        allowed_roots: tuple[Path, ...] | None = None,
        requester: dict[str, Any] | None = None,
        scan_launcher: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
        clock: Callable[[], float] = time.time,
        plan_ttl_seconds: float = DEFAULT_PLAN_TTL_SECONDS,
    ) -> None:
        if isinstance(plan_ttl_seconds, bool) or not isinstance(plan_ttl_seconds, (int, float)) \
                or not 0 < float(plan_ttl_seconds) <= 3600:
            raise ValueError("plan_ttl_seconds 0 ile 3600 saniye arasında olmalıdır.")
        self.store = store
        self.queue = queue
        self.requester = deepcopy(requester) if isinstance(requester, dict) else None
        self.scan_launcher = scan_launcher
        self.clock = clock
        self.plan_ttl_seconds = float(plan_ttl_seconds)
        self.allowed_roots = self._normalize_roots(allowed_roots)
        self._plans: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _normalize_roots(roots: tuple[Path, ...] | None) -> tuple[Path, ...] | None:
        if roots is None:
            return None
        normalized: list[Path] = []
        for root in roots:
            try:
                resolved = Path(root).expanduser().resolve(strict=True)
            except (OSError, RuntimeError, ValueError) as exc:
                raise ValueError("İzinli yerel kök bulunamadı.") from exc
            if not resolved.is_dir():
                raise ValueError("İzinli yerel kök klasör olmalıdır.")
            normalized.append(resolved)
        if not normalized:
            raise ValueError("allowed_roots boş olamaz.")
        return tuple(normalized)

    def _inside_allowed_root(self, path: Path) -> bool:
        if self.allowed_roots is None:
            return True
        return any(path == root or root in path.parents for root in self.allowed_roots)

    def _local_directory(self, value: Any, field: str, *, output: bool = False) -> str:
        raw = _text(value, field)
        try:
            path = Path(raw).expanduser().resolve(strict=not output)
        except (OSError, RuntimeError, ValueError) as exc:
            raise ActionUnavailable(f"{field} yerel klasörü bulunamadı.") from exc
        if output:
            if not path.exists() or not path.is_dir() or path.is_symlink():
                raise ActionUnavailable(f"{field} mevcut, normal bir yerel klasör olmalıdır.")
        elif not path.is_dir():
            raise ActionUnavailable(f"{field} yerel klasörü bulunamadı.")
        if not self._inside_allowed_root(path):
            raise ActionUnavailable(f"{field} izinli yerel köklerin dışında.")
        return str(path)

    def _readiness(self) -> dict[str, tuple[bool, str]]:
        analyzer = _module_ready("project_analyzer")
        dependency = _module_ready("dependency_security") and _module_ready("sbom_formats")
        store_read = _has_methods(self.store, "get_project_audit")
        compare = store_read and callable(getattr(self.store, "compare_scans", None))
        export = store_read and getattr(self.store, "path", None) is not None and _module_ready("cli_reports")
        queue_read = _has_methods(self.queue, "get")
        queue_cancel = queue_read and callable(getattr(self.queue, "cancel", None))
        fix_tools = store_read and _module_ready("taint_autofix") and _module_ready("fix_verification")
        requester_ok = isinstance(self.requester, dict) and self.requester.get("role") in {"analyst", "admin"}
        external_request = requester_ok and self.store is not None and _module_ready("mcp_scan_requests") \
            and callable(self.scan_launcher)
        return {
            "analyze_local_project": (
                analyzer,
                "project_analyzer.analyze_project hazır."
                if analyzer else "project_analyzer.analyze_project yüklenemiyor.",
            ),
            "generate_sbom": (
                dependency,
                "Yerel CycloneDX üretimi ve SPDX dönüşümü hazır."
                if dependency else "dependency_security/sbom_formats yüklenemiyor.",
            ),
            "compare_saved_scans": (
                bool(compare),
                "Kayıtlı proje ve ağ taraması karşılaştırma sözleşmeleri hazır."
                if compare else "Karşılaştırma yapabilen kayıt deposu bağlı değil.",
            ),
            "export_saved_audit": (
                bool(export),
                "cli_reports.export_project ve kayıtlı depo yolu hazır."
                if export else "Kayıtlı denetim deposu veya cli_reports dışa aktarıcısı hazır değil.",
            ),
            "suggest_fix": (
                bool(store_read and _module_ready("taint_autofix")),
                "Salt-okunur unified diff önericisi hazır."
                if store_read and _module_ready("taint_autofix")
                else "Kayıtlı denetim deposu veya taint_autofix hazır değil.",
            ),
            "verify_fix": (
                bool(fix_tools),
                "fix_verification sandbox doğrulayıcısı hazır."
                if fix_tools else "Kayıtlı denetim deposu veya fix_verification hazır değil.",
            ),
            "apply_fix": (
                bool(fix_tools),
                "Preimage bağlı, sandbox doğrulamalı atomik tek dosya düzeltmesi hazır."
                if fix_tools else "Kayıtlı denetim deposu veya düzeltme/doğrulama adaptörü hazır değil.",
            ),
            "job_status": (
                queue_read,
                "job_queue durum adaptörü hazır." if queue_read else "İş kuyruğu bağlı değil.",
            ),
            "cancel_job": (
                bool(queue_cancel),
                "job_queue iptal adaptörü hazır." if queue_cancel else "İptal edilebilir iş kuyruğu bağlı değil.",
            ),
            "request_external_scan": (
                bool(external_request),
                "mcp_scan_requests kaydı ve onaylı iş launcher devri hazır."
                if external_request
                else "Analist/yönetici isteği, depo, mcp_scan_requests veya iş launcher adaptörü hazır değil.",
            ),
        }

    def list_capabilities(self) -> dict[str, Any]:
        readiness = self._readiness()
        descriptions = {
            "analyze_local_project": "İzinli yerel proje klasörünü Sniper ile analiz eder.",
            "generate_sbom": "İzinli yerel proje için CycloneDX 1.5 veya SPDX 2.3 SBOM üretir.",
            "compare_saved_scans": "İki kayıtlı proje denetimini veya iki kayıtlı ağ taramasını karşılaştırır.",
            "export_saved_audit": "Kayıtlı proje denetimini JSON, SARIF, HTML veya CSV olarak dışa aktarır.",
            "suggest_fix": "Kayıtlı bulgu için dosyayı değiştirmeden unified diff önerir.",
            "verify_fix": "Önerilen düzeltmeyi geçici sandbox kopyasında doğrular; proje dosyasını değiştirmez.",
            "apply_fix": "Yalnız doğrulanmış ve SHA-256 preimage'a bağlı düzeltmeyi tek dosyaya atomik uygular.",
            "job_status": "Bağlı iş kuyruğundaki işin gerçek durumunu döndürür.",
            "cancel_job": "Bağlı iş kuyruğundaki işi kullanıcı onayından sonra iptal eder.",
            "request_external_scan": "Onaylı dış hedef planını MCP isteği üzerinden gerçek iş launcher'ına devreder.",
        }
        capabilities = []
        for name in descriptions:
            ready, reason = readiness[name]
            item: dict[str, Any] = {
                "name": name,
                "status": "ready" if ready else "unavailable",
                "reason": reason,
                "description": descriptions[name],
                "requires_confirmation": name != "job_status",
            }
            if name == "request_external_scan":
                item["execution"] = "approved_job_launch"
            capabilities.append(item)
        return {
            "format": CAPABILITIES_FORMAT,
            "offline": True,
            "capabilities": capabilities,
        }

    def readiness(self) -> dict[str, Any]:
        """MCP katmanı için açık isimli readiness takma adı."""
        return self.list_capabilities()

    def call(self, name: str, args: Any) -> dict[str, Any]:
        """MCP sunucusunun doğrudan bağlayabileceği kararlı dispatcher yüzeyi."""
        if not isinstance(name, str):
            raise PlanRejected("Araç adı metin olmalıdır.")
        if not isinstance(args, dict):
            raise PlanRejected("Araç argümanları nesne olmalıdır.")
        if name == "list_community_capabilities":
            _only(args, set())
            return self.list_capabilities()
        if name == "community_job_status":
            _only(args, {"job_id"})
            return self.job_status(args.get("job_id"))
        if name == "prepare_action":
            _only(args, {"action", "parameters"})
            if "action" not in args or "parameters" not in args:
                raise PlanRejected("action ve parameters gereklidir.")
            return self.plan_action(args["action"], args["parameters"])
        if name == "execute_action":
            _only(args, {"plan_id", "plan_sha256", "user_confirmed"})
            if any(key not in args for key in ("plan_id", "plan_sha256", "user_confirmed")):
                raise PlanRejected("plan_id, plan_sha256 ve user_confirmed gereklidir.")
            return self.execute_plan(
                args["plan_id"],
                plan_sha256=args["plan_sha256"],
                user_confirmed=args["user_confirmed"],
            )
        raise PlanRejected(f"Desteklenmeyen Community aracı: {name}")

    def job_status(self, job_id: str) -> dict[str, Any]:
        if not _has_methods(self.queue, "get"):
            return {"status": "unavailable", "reason": "İş kuyruğu bağlı değil."}
        if not isinstance(job_id, str) or _JOB_ID.fullmatch(job_id) is None:
            raise PlanRejected("Geçersiz iş kimliği.")
        result = self.queue.get(job_id)
        if result is None:
            return {"status": "unavailable", "reason": "İş bulunamadı.", "job_id": job_id}
        if not isinstance(result, dict):
            raise ActionUnavailable("İş kuyruğu geçerli durum döndürmedi.")
        return self._job_view(result)

    @staticmethod
    def _job_view(result: dict[str, Any]) -> dict[str, Any]:
        safe = {
            key: deepcopy(result[key])
            for key in (
                "id", "route", "state", "created_at", "started_at", "finished_at", "http_status",
                "cancel_requested", "queue_position", "error",
            )
            if key in result
        }
        progress = result.get("progress")
        if isinstance(progress, dict):
            safe["progress"] = {
                key: progress[key]
                for key in ("stage", "percent", "done", "total")
                if key in progress and isinstance(progress[key], (str, int, float)) and not isinstance(progress[key], bool)
            }
        return safe

    def _require_ready(self, action: str) -> None:
        readiness = self._readiness()
        if action not in readiness:
            raise PlanRejected(f"Desteklenmeyen eylem: {action}")
        ready, reason = readiness[action]
        if not ready:
            raise ActionUnavailable(reason)

    def _normalize_parameters(self, action: str, raw: Any) -> dict[str, Any]:
        if not isinstance(raw, dict):
            raise PlanRejected("parameters nesne olmalıdır.")
        parameters = dict(raw)

        if action == "analyze_local_project":
            _only(parameters, {"path", "max_files", "persist"})
            result = {
                "path": self._local_directory(parameters.get("path"), "path"),
                "max_files": _strict_int(parameters.get("max_files", 500), "max_files", minimum=1, maximum=100_000),
                "persist": _strict_bool(parameters.get("persist", True), "persist"),
            }
            if result["persist"] and not _has_methods(self.store, "create_project_audit"):
                raise ActionUnavailable("Analizi kaydetmek için yazılabilir proje denetim deposu bağlı değil.")
            return result

        if action == "generate_sbom":
            _only(parameters, {"path", "format"})
            fmt = _text(parameters.get("format", "cyclonedx"), "format", maximum=20).lower()
            if fmt not in _SBOM_FORMATS:
                raise PlanRejected("SBOM formatı cyclonedx ya da spdx olmalıdır.")
            return {"path": self._local_directory(parameters.get("path"), "path"), "format": fmt}

        if action == "compare_saved_scans":
            _only(parameters, {"kind", "before_id", "after_id"})
            kind = _text(parameters.get("kind"), "kind", maximum=40)
            if kind not in _COMPARISON_KINDS:
                raise PlanRejected("Karşılaştırma türü project_audit ya da network_scan olmalıdır.")
            before = _text(parameters.get("before_id"), "before_id", maximum=120)
            after = _text(parameters.get("after_id"), "after_id", maximum=120)
            if before == after:
                raise PlanRejected("Aynı kayıt karşılaştırılamaz.")
            if kind == "project_audit" and (
                _PROJECT_AUDIT_ID.fullmatch(before) is None or _PROJECT_AUDIT_ID.fullmatch(after) is None
            ):
                raise PlanRejected("Geçersiz proje denetimi kimliği.")
            return {"kind": kind, "before_id": before, "after_id": after}

        if action == "export_saved_audit":
            _only(parameters, {"audit_id", "format", "target_dir"})
            audit_id = _text(parameters.get("audit_id"), "audit_id", maximum=120)
            fmt = _text(parameters.get("format"), "format", maximum=20).lower()
            if _PROJECT_AUDIT_ID.fullmatch(audit_id) is None:
                raise PlanRejected("Geçersiz proje denetimi kimliği.")
            if fmt not in _EXPORT_FORMATS:
                raise PlanRejected("Dışa aktarma formatı json, sarif, html ya da csv olmalıdır.")
            target_dir = self._local_directory(parameters.get("target_dir"), "target_dir", output=True)
            return {"audit_id": audit_id, "format": fmt, "target_dir": target_dir}

        if action in {"suggest_fix", "verify_fix"}:
            _only(parameters, {"audit_id", "finding_index"})
            audit_id = _text(parameters.get("audit_id"), "audit_id", maximum=120)
            if _PROJECT_AUDIT_ID.fullmatch(audit_id) is None:
                raise PlanRejected("Geçersiz proje denetimi kimliği.")
            index = _strict_int(parameters.get("finding_index"), "finding_index", minimum=0, maximum=100_000)
            return {"audit_id": audit_id, "finding_index": index}

        if action == "apply_fix":
            _only(parameters, {"audit_id", "finding_index", "expected_source_sha256"})
            audit_id = _text(parameters.get("audit_id"), "audit_id", maximum=120)
            if _PROJECT_AUDIT_ID.fullmatch(audit_id) is None:
                raise PlanRejected("Geçersiz proje denetimi kimliği.")
            index = _strict_int(parameters.get("finding_index"), "finding_index", minimum=0, maximum=100_000)
            expected = _text(parameters.get("expected_source_sha256"), "expected_source_sha256", maximum=64).lower()
            if _SHA256.fullmatch(expected) is None:
                raise PlanRejected("expected_source_sha256 64 haneli SHA-256 olmalıdır.")
            return {"audit_id": audit_id, "finding_index": index, "expected_source_sha256": expected}

        if action == "cancel_job":
            _only(parameters, {"job_id"})
            job_id = _text(parameters.get("job_id"), "job_id", maximum=120)
            if _JOB_ID.fullmatch(job_id) is None:
                raise PlanRejected("Geçersiz iş kimliği.")
            if self.queue.get(job_id) is None:
                raise ActionUnavailable("İş bulunamadı.")
            return {"job_id": job_id}

        if action == "request_external_scan":
            _only(parameters, {"profile_id", "parameters"})
            profile_id = _text(parameters.get("profile_id"), "profile_id", maximum=80)
            scan_parameters = parameters.get("parameters")
            if not isinstance(scan_parameters, dict):
                raise PlanRejected("Tarama parameters alanı nesne olmalıdır.")
            import mcp_scan_requests

            try:
                preview = mcp_scan_requests.preview_request(self.store, profile_id, _json_copy(scan_parameters))
            except mcp_scan_requests.ScanRequestError as exc:
                raise PlanRejected(str(exc)) from exc
            return {
                "profile_id": preview["profile_id"],
                "parameters": preview["parameters"],
                "normalized_target": preview["normalized_target"],
                "tool_id": preview["tool_id"],
                "execution": preview["execution"],
                "effective_profile": preview["effective_profile"],
                "scope_summary": preview["scope_summary"],
                "scan_consent_scope": preview["consent_scope"],
                "scan_plan_sha256": preview["scan_plan_sha256"],
            }

        raise PlanRejected(f"Desteklenmeyen eylem: {action}")

    def _trim_plans(self, now: float) -> None:
        if len(self._plans) < MAX_PLANS:
            return
        removable = sorted(
            (
                (float(entry["plan"]["created_at"]), plan_id)
                for plan_id, entry in self._plans.items()
                if entry["state"] != "ready" or now > float(entry["plan"]["expires_at"])
            ),
        )
        for _created, plan_id in removable:
            self._plans.pop(plan_id, None)
            if len(self._plans) < MAX_PLANS:
                return
        raise ActionUnavailable("Plan kapasitesi dolu; eski planların süresinin dolmasını bekleyin.")

    @staticmethod
    def _consent(action: str, parameters: dict[str, Any]) -> tuple[str, list[str]]:
        """Return the exact user-visible scope and material effects covered by the plan hash."""
        if action == "analyze_local_project":
            effects = ["read_local_source"]
            if parameters["persist"]:
                effects.append("write_local_database")
            return (
                f"Analyze local project {parameters['path']} (max_files={parameters['max_files']}, "
                f"persist={str(parameters['persist']).lower()}).",
                effects,
            )
        if action == "generate_sbom":
            return f"Read local project {parameters['path']} and generate {parameters['format']} SBOM data.", [
                "read_local_source",
            ]
        if action == "compare_saved_scans":
            return (
                f"Compare saved {parameters['kind']} records {parameters['before_id']} and {parameters['after_id']}.",
                ["read_local_database"],
            )
        if action == "export_saved_audit":
            return (
                f"Export audit {parameters['audit_id']} as {parameters['format']} into "
                f"{parameters['target_dir']}.",
                ["read_local_database", "write_report_file"],
            )
        if action == "suggest_fix":
            return (
                f"Read audit {parameters['audit_id']} finding {parameters['finding_index']} and propose a diff; "
                "do not modify source files.",
                ["read_local_source", "read_local_database"],
            )
        if action == "verify_fix":
            return (
                f"Verify audit {parameters['audit_id']} finding {parameters['finding_index']} in a temporary sandbox; "
                "do not modify the project.",
                ["read_local_source", "run_local_verification"],
            )
        if action == "apply_fix":
            return (
                f"Atomically update the one source file bound to audit {parameters['audit_id']} finding "
                f"{parameters['finding_index']} only if its SHA-256 is {parameters['expected_source_sha256']}.",
                ["read_local_database", "run_local_verification", "write_project_file"],
            )
        if action == "cancel_job":
            return f"Request cancellation of local job {parameters['job_id']}.", ["stop_local_job"]
        if action == "request_external_scan":
            return (
                str(parameters["scan_consent_scope"]),
                (["write_local_database"] if parameters["execution"] == "manual_handoff"
                 else ["write_local_database", "send_network_requests"]),
            )
        raise PlanRejected(f"Desteklenmeyen eylem: {action}")

    def plan_action(self, action: str, parameters: Any) -> dict[str, Any]:
        action = _text(action, "action", maximum=80)
        if action == "job_status":
            raise PlanRejected("job_status salt okunurdur; doğrudan job_status kullanın.")
        self._require_ready(action)
        normalized = self._normalize_parameters(action, parameters)
        now = float(self.clock())
        if now != now or now in {float("inf"), float("-inf")}:
            raise ActionUnavailable("Güvenilir plan saati alınamadı.")
        consent_scope, effects = self._consent(action, normalized)
        plan = {
            "format": PLAN_FORMAT,
            "plan_id": "plan_" + secrets.token_hex(12),
            "action": action,
            "parameters": normalized,
            "consent_scope": consent_scope,
            "effects": effects,
            "created_at": now,
            "expires_at": now + self.plan_ttl_seconds,
        }
        digest = _sha256_json(plan)
        with self._lock:
            self._trim_plans(now)
            self._plans[plan["plan_id"]] = {"plan": deepcopy(plan), "sha256": digest, "state": "ready"}
        return {**deepcopy(plan), "plan_sha256": digest}

    def execute_plan(
        self,
        plan_id: str,
        *,
        plan_sha256: str,
        user_confirmed: bool,
    ) -> dict[str, Any]:
        if user_confirmed is not True:
            raise ConfirmationRequired("Eylem için açık kullanıcı sohbet onayı gerekir.")
        if not isinstance(plan_id, str) or _PLAN_ID.fullmatch(plan_id) is None:
            raise PlanRejected("Geçersiz plan kimliği.")
        if not isinstance(plan_sha256, str) or _SHA256.fullmatch(plan_sha256) is None:
            raise PlanRejected("Geçersiz plan SHA-256 değeri.")
        now = float(self.clock())
        with self._lock:
            entry = self._plans.get(plan_id)
            if entry is None:
                raise PlanRejected("Plan bulunamadı.")
            if entry["state"] != "ready":
                raise PlanRejected("Plan daha önce kullanılmış.")
            if now > float(entry["plan"]["expires_at"]):
                entry["state"] = "expired"
                raise PlanRejected("Planın süresi dolmuş.")
            if not secrets.compare_digest(plan_sha256, entry["sha256"]):
                raise PlanRejected("Plan SHA-256 değeri eşleşmiyor.")
            # Tek kullanım garantisi: ürün çağrısı hata verse de aynı yetki yeniden oynatılamaz.
            entry["state"] = "executing"
            plan = deepcopy(entry["plan"])
        try:
            result = self._execute(plan, plan_sha256)
        finally:
            with self._lock:
                entry["state"] = "used"
        return {
            "format": RESULT_FORMAT,
            "plan_id": plan_id,
            "plan_sha256": plan_sha256,
            "action": plan["action"],
            "status": "completed",
            "result": result,
        }

    def _execute(self, plan: dict[str, Any], plan_sha256: str) -> Any:
        action = plan["action"]
        parameters = plan["parameters"]
        # Hazırlık durumu plan ile yürütme arasında değişmiş olabilir; sahte başarı yerine yeniden denetle.
        self._require_ready(action)
        if action == "analyze_local_project":
            return self._analyze_local_project(parameters)
        if action == "generate_sbom":
            return self._generate_sbom(parameters)
        if action == "compare_saved_scans":
            return self._compare_saved_scans(parameters)
        if action == "export_saved_audit":
            return self._export_saved_audit(parameters)
        if action == "suggest_fix":
            return self._suggest_fix(parameters)
        if action == "verify_fix":
            return self._verify_fix(parameters)
        if action == "apply_fix":
            return self._apply_fix(parameters)
        if action == "cancel_job":
            return self._cancel_job(parameters)
        if action == "request_external_scan":
            return self._request_external_scan(parameters, plan=plan, plan_sha256=plan_sha256)
        raise PlanRejected(f"Desteklenmeyen eylem: {action}")

    def _analyze_local_project(self, parameters: dict[str, Any]) -> dict[str, Any]:
        from project_analyzer import analyze_project

        result = analyze_project(
            parameters["path"],
            allowed_roots=self.allowed_roots,
            max_files=parameters["max_files"],
        )
        if not isinstance(result, dict):
            raise ActionUnavailable("Proje analizörü geçerli sonuç döndürmedi.")
        if parameters["persist"]:
            saved = self.store.create_project_audit(result)
            if not isinstance(saved, dict) or not isinstance(saved.get("id"), str):
                raise ActionUnavailable("Proje analizi depoya kaydedilemedi.")
            result = saved
        counts = result.get("finding_counts") if isinstance(result.get("finding_counts"), dict) else {}
        findings = result.get("findings") if isinstance(result.get("findings"), list) else []
        return {
            **({"id": result["id"]} if isinstance(result.get("id"), str) else {}),
            "project_name": str(result.get("project_name") or "")[:200],
            "score": result.get("score"),
            "grade": result.get("grade"),
            "file_count": result.get("file_count"),
            "bytes_scanned": result.get("bytes_scanned"),
            "finding_count": len(findings),
            "finding_counts": deepcopy(counts),
            "persisted": bool(parameters["persist"]),
        }

    def _generate_sbom(self, parameters: dict[str, Any]) -> dict[str, Any]:
        from dependency_security import generate_cyclonedx_sbom

        cyclonedx = generate_cyclonedx_sbom(parameters["path"], allowed_roots=self.allowed_roots)
        if not isinstance(cyclonedx, dict) or cyclonedx.get("bomFormat") != "CycloneDX":
            raise ActionUnavailable("CycloneDX üreticisi geçerli belge döndürmedi.")
        document = cyclonedx
        if parameters["format"] == "spdx":
            from sbom_formats import cyclonedx_to_spdx

            document = cyclonedx_to_spdx(
                cyclonedx,
                namespace_seed=hashlib.sha256(parameters["path"].encode("utf-8")).hexdigest(),
            )
        return {
            "format": parameters["format"],
            "component_count": len(cyclonedx.get("components") or []),
            "document_sha256": _sha256_json(document),
            "document": document,
        }

    def _compare_saved_scans(self, parameters: dict[str, Any]) -> dict[str, Any]:
        if parameters["kind"] == "project_audit":
            from project_audit_diff import compare_project_audits

            result = compare_project_audits(self.store, parameters["before_id"], parameters["after_id"])
        else:
            result = self.store.compare_scans(
                parameters["before_id"],
                parameters["after_id"],
                include_details=True,
            )
        if not isinstance(result, dict):
            raise ActionUnavailable("Karşılaştırma adaptörü geçerli sonuç döndürmedi.")
        allowed = {
            "format", "audit_1_id", "audit_2_id", "scan_1_id", "scan_2_id", "project_name", "target_id",
            "score_1", "score_2", "score_delta", "scan_1_score", "scan_2_score", "grade_1", "grade_2",
            "new_count", "resolved_count", "persistent_count", "new_by_severity", "resolved_by_severity",
            "persistent_by_severity", "scan_1_finished_at", "scan_2_finished_at",
        }
        return {key: deepcopy(value) for key, value in result.items() if key in allowed}

    def _export_saved_audit(self, parameters: dict[str, Any]) -> dict[str, Any]:
        from cli_reports import export_project

        try:
            path = export_project(
                parameters["audit_id"],
                parameters["format"],
                Path(parameters["target_dir"]),
                db_path=Path(self.store.path),
            )
        except OSError as exc:
            raise ActionUnavailable("Dışa aktarım hedefi güvenli değil; sembolik bağlar reddedilir.") from exc
        if path is None:
            raise ActionUnavailable("Kayıtlı proje denetimi bulunamadı; dışa aktarım yapılmadı.")
        try:
            resolved = Path(path).resolve(strict=True)
            payload = resolved.read_bytes()
        except (OSError, RuntimeError, ValueError) as exc:
            raise ActionUnavailable("Dışa aktarılan rapor doğrulanamadı.") from exc
        target = Path(parameters["target_dir"])
        if target not in resolved.parents:
            raise ActionUnavailable("Dışa aktarıcı hedef klasör dışında dosya döndürdü.")
        return {
            "filename": resolved.name,
            "format": parameters["format"],
            "bytes": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
        }

    def _suggest_fix(self, parameters: dict[str, Any]) -> dict[str, Any]:
        from taint_autofix import suggest_for_finding

        audit, _finding, _kind, _root, _target, raw, _text_value, _info = self._fix_context(parameters)
        result = suggest_for_finding(
            audit,
            parameters["finding_index"],
            allowed_roots=self.allowed_roots,
        )
        if not isinstance(result, dict):
            raise ActionUnavailable("Düzeltme önericisi geçerli sonuç döndürmedi.")
        # Adaptör hiçbir koşulda dosya uygulaması iddia etmez.
        result = deepcopy(result)
        result["applied"] = False
        result["source_sha256"] = hashlib.sha256(raw).hexdigest()
        if result.get("mode") == "diff" and not str(result.get("diff") or "").startswith("--- a/"):
            raise ActionUnavailable("Düzeltme önericisi geçerli unified diff döndürmedi.")
        import ai_triage

        for key in ("diff", "snippet", "title"):
            if isinstance(result.get(key), str):
                result[key] = ai_triage.redact_text(result[key])
        if isinstance(result.get("notes"), list):
            result["notes"] = [ai_triage.redact_text(str(item)) for item in result["notes"][:20]]
        return result

    def _stored_audit(self, audit_id: str) -> dict[str, Any]:
        audit = self.store.get_project_audit(audit_id)
        if not isinstance(audit, dict):
            raise ActionUnavailable("Kayıtlı proje denetimi bulunamadı.")
        return audit

    def _verify_fix(self, parameters: dict[str, Any]) -> dict[str, Any]:
        import ai_triage
        import fix_verification
        import taint_autofix

        audit, _finding, _kind, _root, _target, raw, _text_value, _info = self._fix_context(parameters)
        try:
            result = fix_verification.verify_finding_fix(
                audit,
                parameters["finding_index"],
                allowed_roots=self.allowed_roots,
            )
        except (fix_verification.AutofixError, OSError, ValueError) as exc:
            raise ActionUnavailable(str(exc) or "Düzeltme doğrulanamadı.") from exc
        if not isinstance(result, dict) or result.get("verdict") not in {"verified", "partial", "failed"}:
            raise ActionUnavailable("Düzeltme doğrulayıcısı geçerli verdict döndürmedi.")
        files: list[str] = []
        for value in result.get("files") or []:
            try:
                relative = taint_autofix.safe_relative(str(value))
            except taint_autofix.AutofixError:
                continue
            files.append(str(relative))
        reasons = [
            ai_triage.redact_text(str(value))[:500]
            for value in (result.get("reasons") or [])[:20]
        ]
        return {
            "format": str(result.get("format") or fix_verification.FORMAT),
            "verdict": result["verdict"],
            "verdict_label": str(result.get("verdict_label") or "")[:80],
            "reasons": reasons,
            "finding_index": parameters["finding_index"],
            "files": files,
            "source_sha256": hashlib.sha256(raw).hexdigest(),
            "applied_to_project": False,
        }

    def _fix_context(
        self,
        parameters: dict[str, Any],
    ) -> tuple[dict[str, Any], dict[str, Any], str, Path, Path, bytes, str, os.stat_result]:
        import taint_autofix
        from safe_file_read import read_bytes_bounded

        audit = self._stored_audit(parameters["audit_id"])
        try:
            finding, kind = taint_autofix.finding_at(audit, parameters["finding_index"])
            relative = taint_autofix.safe_relative(str(finding.get("file") or ""))
            root = taint_autofix.project_root(audit, self.allowed_roots)
        except taint_autofix.AutofixError as exc:
            raise ActionUnavailable(str(exc)) from exc

        parent = root
        try:
            for part in relative.parts[:-1]:
                parent = parent / part
                info = os.lstat(parent)
                if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                    raise ActionUnavailable("Düzeltme yolu sembolik bağlantı veya normal olmayan dizin içeriyor.")
            parent = parent.resolve(strict=True)
        except ActionUnavailable:
            raise
        except (OSError, RuntimeError, ValueError) as exc:
            raise ActionUnavailable("Düzeltme dosyasının üst dizini doğrulanamadı.") from exc
        if parent != root and root not in parent.parents:
            raise ActionUnavailable("Düzeltme dosyası proje kökü dışında.")
        target = parent / relative.name
        try:
            info = os.lstat(target)
        except OSError as exc:
            raise ActionUnavailable("Düzeltme dosyası okunamadı.") from exc
        if stat.S_ISLNK(info.st_mode):
            raise ActionUnavailable("Düzeltme dosyası sembolik bağlantı olamaz.")
        if not stat.S_ISREG(info.st_mode):
            raise ActionUnavailable("Düzeltme hedefi normal dosya olmalıdır.")
        raw = read_bytes_bounded(target, taint_autofix.MAX_SOURCE_BYTES)
        if raw is None:
            raise ActionUnavailable("Düzeltme dosyası okunamadı veya boyut sınırını aşıyor.")
        try:
            text = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise ActionUnavailable("Düzeltme dosyası geçerli UTF-8 olmalıdır.") from exc
        return audit, finding, kind, root, target, raw, text, info

    @staticmethod
    def _write_atomic(
        target: Path,
        payload: bytes,
        source_info: os.stat_result,
        parent_info: os.stat_result,
    ) -> None:
        fd = -1
        temporary = ""
        directory_fd = -1
        try:
            directory_fd = os.open(
                target.parent,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
            )
            opened_parent = os.fstat(directory_fd)
            if not stat.S_ISDIR(opened_parent.st_mode) or (
                opened_parent.st_dev,
                opened_parent.st_ino,
            ) != (parent_info.st_dev, parent_info.st_ino):
                raise ActionUnavailable("Düzeltme üst dizini doğrulama sırasında değişmiş.")
            current = os.stat(target.name, dir_fd=directory_fd, follow_symlinks=False)
            if not stat.S_ISREG(current.st_mode) or (
                current.st_dev,
                current.st_ino,
            ) != (source_info.st_dev, source_info.st_ino):
                raise ActionUnavailable("Düzeltme dosyası doğrulama sırasında değişmiş.")
            for _attempt in range(20):
                temporary = ".sniper-fix-" + secrets.token_hex(12) + ".tmp"
                try:
                    fd = os.open(
                        temporary,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                        stat.S_IMODE(source_info.st_mode) & 0o777,
                        dir_fd=directory_fd,
                    )
                    break
                except FileExistsError:
                    continue
            else:
                raise ActionUnavailable("Güvenli geçici düzeltme dosyası oluşturulamadı.")
            os.fchmod(fd, stat.S_IMODE(source_info.st_mode) & 0o777)
            with os.fdopen(fd, "wb") as handle:
                fd = -1
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            current = os.stat(target.name, dir_fd=directory_fd, follow_symlinks=False)
            if not stat.S_ISREG(current.st_mode) or (
                current.st_dev,
                current.st_ino,
            ) != (source_info.st_dev, source_info.st_ino):
                raise ActionUnavailable("Düzeltme dosyası yazma sırasında değişmiş.")
            os.replace(
                temporary,
                target.name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
            )
            temporary = ""
            try:
                os.fsync(directory_fd)
            except OSError:
                # Rename tamamlandı; her dosya sistemi dizin fsync'ini desteklemez.
                pass
        except OSError as exc:
            raise ActionUnavailable("Düzeltme dosyası güvenli ve atomik yazılamadı.") from exc
        finally:
            if fd >= 0:
                os.close(fd)
            if temporary and directory_fd >= 0:
                try:
                    os.unlink(temporary, dir_fd=directory_fd)
                except OSError:
                    pass
            if directory_fd >= 0:
                os.close(directory_fd)

    def _apply_fix(self, parameters: dict[str, Any]) -> dict[str, Any]:
        import fix_verification
        import taint_autofix
        from safe_file_read import read_bytes_bounded

        audit, finding, kind, _root, target, raw, text, source_info = self._fix_context(parameters)
        before_sha = hashlib.sha256(raw).hexdigest()
        if not secrets.compare_digest(before_sha, parameters["expected_source_sha256"]):
            raise ActionUnavailable("Kaynak dosya planlandıktan sonra değişmiş veya beklenen SHA-256 yanlış.")
        flow = finding.get("taint_flow") if isinstance(finding.get("taint_flow"), dict) else None
        relative = str(taint_autofix.safe_relative(str(finding.get("file") or "")))
        try:
            line = int(finding.get("line") or 0)
            suggestion, new_text = taint_autofix.compute_fix(text, relative, line, kind, flow=flow)
        except (taint_autofix.AutofixError, TypeError, ValueError) as exc:
            raise ActionUnavailable(str(exc) or "Düzeltme yeniden üretilemedi.") from exc
        if new_text is None or new_text == text or not isinstance(suggestion, dict):
            raise ActionUnavailable("Bulgu için uygulanabilir otomatik düzeltme üretilemedi.")

        try:
            verification = fix_verification.verify_finding_fix(
                audit,
                parameters["finding_index"],
                allowed_roots=self.allowed_roots,
            )
        except (fix_verification.AutofixError, OSError, ValueError) as exc:
            raise ActionUnavailable(str(exc) or "Düzeltme sandbox içinde doğrulanamadı.") from exc
        if not isinstance(verification, dict) or verification.get("verdict") != "verified":
            raise ActionUnavailable("Düzeltme sandbox tarafından doğrulanmadı; yalnız verified verdict uygulanabilir.")
        if verification.get("diff") != suggestion.get("diff"):
            raise ActionUnavailable("Doğrulanan düzeltme yeniden üretilen düzeltmeyle eşleşmiyor.")

        # Sandbox doğrulaması sürerken dosya değişmişse eski öneriyi yazma.
        fresh = read_bytes_bounded(target, taint_autofix.MAX_SOURCE_BYTES)
        try:
            fresh_info = os.lstat(target)
            parent_info = os.lstat(target.parent)
        except OSError as exc:
            raise ActionUnavailable("Kaynak dosya doğrulamadan sonra okunamadı.") from exc
        if fresh is None or stat.S_ISLNK(fresh_info.st_mode) or not stat.S_ISREG(fresh_info.st_mode) \
                or stat.S_ISLNK(parent_info.st_mode) or not stat.S_ISDIR(parent_info.st_mode) \
                or (fresh_info.st_dev, fresh_info.st_ino) != (source_info.st_dev, source_info.st_ino) \
                or not secrets.compare_digest(hashlib.sha256(fresh).hexdigest(), before_sha):
            raise ActionUnavailable("Kaynak dosya doğrulama sırasında değişmiş; düzeltme uygulanmadı.")

        encoded = new_text.encode("utf-8")
        self._write_atomic(target, encoded, source_info, parent_info)
        return {
            "file": relative,
            "before_sha256": before_sha,
            "after_sha256": hashlib.sha256(encoded).hexdigest(),
            "verification_verdict": "verified",
        }

    def _cancel_job(self, parameters: dict[str, Any]) -> dict[str, Any]:
        result = self.queue.cancel(parameters["job_id"])
        if not isinstance(result, dict):
            raise ActionUnavailable("İş bulunamadı veya iptal adaptörü sonuç döndürmedi.")
        state = result.get("state")
        if state not in {"cancelled", "succeeded", "failed", "expired", "interrupted"}:
            raise ActionUnavailable("İş kuyruğu iptal isteğini kabul etmedi.")
        return self._job_view(result)

    def _request_external_scan(
        self,
        parameters: dict[str, Any],
        *,
        plan: dict[str, Any],
        plan_sha256: str,
    ) -> dict[str, Any]:
        import mcp_scan_requests

        item = mcp_scan_requests.create_request(
            self.store,
            parameters["profile_id"],
            parameters["parameters"],
            requester=deepcopy(self.requester),
            confirm_request=True,
        )
        if not isinstance(item, dict) or item.get("status") != "pending" \
                or not isinstance(item.get("id"), str) or _SCAN_REQUEST_ID.fullmatch(item["id"]) is None:
            raise ActionUnavailable("MCP tarama isteği bekleyen durumda oluşturulmadı.")
        approved_plan = {
            "format": "sniper-community-scan-launch-v1",
            "plan_id": plan["plan_id"],
            "plan_sha256": plan_sha256,
            "action": plan["action"],
            "parameters": deepcopy(plan["parameters"]),
            "request": deepcopy(item),
        }

        def mark_launch_failed() -> None:
            try:
                mcp_scan_requests.mark_failed(
                    self.store,
                    item["id"],
                    "Community launcher onaylı planı başlatamadı",
                )
            except (OSError, ValueError, mcp_scan_requests.ScanRequestError):
                pass

        try:
            launch = self.scan_launcher(approved_plan)
            if not isinstance(launch, dict):
                raise ActionUnavailable("Tarama launcher geçerli iş sonucu döndürmedi.")
            if launch.get("execution") == "manual_handoff" and launch.get("state") == "approved":
                return {
                    "request_id": str(item.get("id") or ""),
                    "state": "approved",
                    "execution": "manual_handoff",
                    "tool_id": str(launch.get("tool_id") or parameters.get("tool_id") or ""),
                    "message": str(launch.get("message") or "Yetki makbuzu manuel aktarım için oluşturuldu."),
                }
            job = launch.get("job") if isinstance(launch.get("job"), dict) else launch
            job_id = job.get("job_id") if isinstance(job.get("job_id"), str) else job.get("id")
            state = job.get("state")
            if not isinstance(job_id, str) or _JOB_ID.fullmatch(job_id) is None \
                    or state not in {"queued", "running", "succeeded"}:
                raise ActionUnavailable("Tarama launcher işi kuyruğa aldığını kanıtlamadı.")
        except Exception:
            mark_launch_failed()
            raise
        return {
            "request_id": str(item.get("id") or ""),
            "job_id": job_id,
            "state": state,
            "execution": "launched",
            "message": "Onaylı tarama planı iş launcher adaptörüne devredildi.",
        }


__all__ = [
    "ActionUnavailable",
    "COMMUNITY_TOOLS",
    "CommunityActionError",
    "CommunityActions",
    "ConfirmationRequired",
    "PlanRejected",
]
