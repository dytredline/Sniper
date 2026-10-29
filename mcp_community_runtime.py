"""Community MCP'nin onaylanmış dış tarama planlarını sabit iş rotalarına bağla.

Bu katman hedef, araç argümanı veya rota icat etmez. ``mcp_scan_requests``
tarafından planlama ve onay anında yeniden türetilen sabit rota/gövdeyi, kalıcı
``JobQueue`` üzerinden mevcut ``job_worker.py`` yürütücüsüne teslim eder.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from types import SimpleNamespace
from typing import Any, Callable

from job_queue import JobQueue
import mcp_scan_requests


APP_DIR = Path(__file__).resolve().parent
JOB_WORKER = APP_DIR / "job_worker.py"
MAX_WORKER_OUTPUT = 4_000_000
_PLAN_ID = re.compile(r"plan_[0-9a-f]{24}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_REQUEST_ID = re.compile(r"msr_[0-9a-f]{16}\Z")

# Yalnız ürün kataloğunun önceden tanımladığı rotalar. Claim sonucu dahi olsa
# bunun dışında kalan bir değer iş kuyruğuna giremez.
ALLOWED_SCAN_ROUTES = frozenset(
    {str(profile["route"]) for profile in mcp_scan_requests.PROFILES if profile.get("route")}
    | set(mcp_scan_requests.OPERATOR_JOB_DISPATCH.values())
)


class CommunityRuntimeError(ValueError):
    """Onaylanmış plan güvenli bir Community işine dönüştürülemedi."""


def _canonical(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise CommunityRuntimeError("Tarama planı geçerli JSON değil.") from exc


def _data_dir(store: Any) -> Path:
    raw = getattr(store, "path", None)
    if raw is None:
        raise CommunityRuntimeError("Kalıcı Sniper deposu bağlı değil.")
    try:
        path = Path(raw).expanduser().resolve(strict=False)
    except (OSError, RuntimeError, ValueError) as exc:
        raise CommunityRuntimeError("Sniper veri yolu çözümlenemedi.") from exc
    if path.name != "sniper.db" or not path.is_absolute() or path.parent.is_symlink() or not path.parent.is_dir():
        raise CommunityRuntimeError("Community iş kuyruğu güvenli bir sniper.db veri dizini gerektirir.")
    return path.parent


def _dedupe_key(route: str, payload: dict[str, Any]) -> str:
    digest = hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()
    return f"{route}|{digest}"


class CommunityScanLauncher:
    """Chat plan onayını mevcut yetki makbuzu ve kalıcı iş kuyruğuna bağlar."""

    def __init__(
        self,
        store: Any,
        *,
        queue: Any | None = None,
        actor: dict[str, Any],
        worker: Callable[[str, dict[str, Any], dict[str, Any], Any], tuple[int, Any]] | None = None,
    ) -> None:
        if not isinstance(actor, dict) or actor.get("role") != "admin" \
                or not all(isinstance(actor.get(key), str) and actor[key] for key in ("id", "username")):
            raise CommunityRuntimeError("Community tarama launcher'ı bağlı yerel yönetici kimliği gerektirir.")
        self.store = store
        self.data_dir = _data_dir(store)
        self.actor = {"id": actor["id"], "username": actor["username"], "role": "admin"}
        self.queue = queue or JobQueue(store_dir=self.data_dir / "jobs")
        self.worker = worker or self._run_worker

    def __call__(self, approved_plan: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(approved_plan, dict) or approved_plan.get("action") != "request_external_scan":
            raise CommunityRuntimeError("Onaylı dış tarama planı gerekli.")
        plan_id = approved_plan.get("plan_id")
        plan_sha256 = approved_plan.get("plan_sha256")
        if not isinstance(plan_id, str) or _PLAN_ID.fullmatch(plan_id) is None \
                or not isinstance(plan_sha256, str) or _SHA256.fullmatch(plan_sha256) is None:
            raise CommunityRuntimeError("Onaylı plan kimliği veya SHA-256 geçersiz.")
        parameters = approved_plan.get("parameters")
        request = approved_plan.get("request")
        if not isinstance(parameters, dict) or not isinstance(request, dict):
            raise CommunityRuntimeError("Onaylı planın istek bağı eksik.")
        request_id = request.get("id")
        if not isinstance(request_id, str) or _REQUEST_ID.fullmatch(request_id) is None:
            raise CommunityRuntimeError("Tarama isteği kimliği geçersiz.")
        scan_plan_sha256 = parameters.get("scan_plan_sha256")
        normalized_target = parameters.get("normalized_target")
        if not isinstance(parameters.get("profile_id"), str) \
                or not isinstance(scan_plan_sha256, str) or _SHA256.fullmatch(scan_plan_sha256) is None \
                or not isinstance(normalized_target, str) or not normalized_target:
            raise CommunityRuntimeError("Onaylı tarama planının bağlayıcı metadatası eksik.")
        if request.get("profile_id") != parameters.get("profile_id") \
                or request.get("plan_sha256") != scan_plan_sha256 \
                or request.get("normalized_target") != normalized_target:
            raise CommunityRuntimeError("Tarama isteği onaylı plan parametreleriyle eşleşmiyor.")

        claim = mcp_scan_requests.claim_request(
            self.store,
            request_id,
            approved_by=self.actor,
            confirm_authorized=True,
        )
        if "dispatch" in claim:
            dispatch = claim.get("dispatch")
            if not isinstance(dispatch, dict) or dispatch.get("mode") != "manual_handoff":
                raise CommunityRuntimeError("Manuel aktarım makbuzu geçersiz.")
            return {
                "execution": "manual_handoff",
                "state": "approved",
                "request_id": request_id,
                "tool_id": dispatch.get("tool_id"),
                "message": "Yetki makbuzu oluşturuldu; bu araç otomatik Community işi sunmuyor.",
            }

        launch = claim.get("launch")
        route = launch.get("route") if isinstance(launch, dict) else None
        payload = launch.get("payload") if isinstance(launch, dict) else None
        if not isinstance(route, str) or route not in ALLOWED_SCAN_ROUTES or not isinstance(payload, dict):
            self._mark_failed(request_id, "claim route is not allowed")
            raise CommunityRuntimeError("Claim route izinli sabit Community tarama kataloğunda değil.")

        started: dict[str, Any] = {}

        def before_enqueue(job: Any) -> None:
            started.update(mcp_scan_requests.mark_started(self.store, request_id, job.id))

        def runner(job: Any) -> tuple[int, Any]:
            return self.worker(route, payload, self.actor, job)

        try:
            job = self.queue.submit(
                route,
                runner,
                dedupe_key=_dedupe_key(route, payload),
                label=f"MCP {claim.get('tool_id') or claim.get('profile_id') or 'scan'}",
                before_enqueue=before_enqueue,
            )
        except Exception as exc:
            self._mark_failed(request_id, type(exc).__name__)
            raise
        state = self.queue.get(job.id)
        receipt = started.get("authorization_receipt") or claim.get("authorization_receipt")
        return {
            "execution": "launched",
            "state": state.get("state", "queued") if isinstance(state, dict) else "queued",
            "request_id": request_id,
            "job_id": job.id,
            "route": route,
            "receipt_sha256": receipt.get("receipt_sha256") if isinstance(receipt, dict) else None,
            "message": "Kullanıcının sohbet onayı sabit tarama planına bağlandı ve iş kuyruğa alındı.",
        }

    def _mark_failed(self, request_id: str, reason: str) -> None:
        try:
            mcp_scan_requests.mark_failed(self.store, request_id, reason)
        except (OSError, ValueError, mcp_scan_requests.ScanRequestError):
            pass

    def _run_worker(
        self,
        route: str,
        payload: dict[str, Any],
        actor: dict[str, Any],
        job: Any,
    ) -> tuple[int, Any]:
        request = json.dumps(
            {
                "route": route,
                "payload": payload,
                "headers": [["Host", "127.0.0.1"]],
                "actor": actor,
                "client_address": ["127.0.0.1", 0],
                "server_port": 0,
            },
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        env = {
            **os.environ,
            "SNIPER_DATA_DIR": str(self.data_dir),
            "SNIPER_SCHEDULER": "0",
            "SNIPER_JOB_PERSIST": "0",
        }
        process = subprocess.Popen(
            [sys.executable, str(JOB_WORKER)],
            cwd=str(APP_DIR),
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=None,
            start_new_session=True,
        )
        output, _ = process.communicate(request)
        if process.returncode != 0 or len(output) > MAX_WORKER_OUTPUT:
            raise CommunityRuntimeError("Community tarama işçisi tamamlanamadı.")
        try:
            result = json.loads(output)
            status = int(result["status"])
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise CommunityRuntimeError("Community tarama işçisi geçersiz sonuç döndürmedi.") from exc
        return status, result.get("body")


def build_community_runtime(store: Any, *, actor: dict[str, Any]) -> tuple[Any, CommunityScanLauncher]:
    """MCP sunucusu için aynı kuyruğu paylaşan actions + launcher ikilisini kur."""
    from mcp_community_actions import CommunityActions

    launcher = CommunityScanLauncher(store, actor=actor)
    actions = CommunityActions(store=store, queue=launcher.queue, requester=actor, scan_launcher=launcher)
    return actions, launcher
