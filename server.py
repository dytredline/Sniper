from __future__ import annotations

import io
import html
import ipaddress
import hashlib
import json
import math
import mimetypes
import os
import re
import signal
import subprocess
import sys
import threading
import time
import traceback
from collections import defaultdict, deque
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from datetime import date
import http.client
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from scanner import (
    NormalizedTarget,
    TargetRejected,
    calculate_score,
    normalize_target,
    run_baseline_scan,
    utc_now,
)
from core.plugin_manager import PluginManager
from exporter.metrics import Metrics
from methodology import CATEGORIES, TEST_CATALOG
from tool_runtime_readiness import nuclei_broad_runtime_paths, runtime_readiness_payload
from project_analyzer import ProjectRejected, analyze_project, validate_project_path
import container_scan
import sbom_scan
import bulk_scan
import project_progress
import ui_assets
import scan_scope
import community_release_info
import ai_triage
import finding_tracking
import portfolio
from safe_file_read import read_bytes_bounded


MAX_STATIC_FILE_BYTES = 8 * 1024 * 1024
import notifications
import ops_files
import license_compliance
import system_health
import data_retention
import mcp_scan_requests
import runtime_proof
import dast_runtime
import asan_selftest
import asan_project_proof
import scheduler as sniper_scheduler
import auth_routes
import request_context
from risk import calculate_cvss31, normalize_cwe
from storage import Store, _guard_live_path
from job_queue import DuplicateJob, JobQueue, JobQueueError, QueueFull
from tool_catalog import tooling_payload
from dependency_security import DependencySecurityError, generate_cyclonedx_sbom, import_report
from tool_report_sarif import parse_sarif_summary
from tool_report_schemathesis_junit import parse_schemathesis_junit_summary
from schemathesis_active import (run_schemathesis_synthetic_local, SchemathesisUnavailable, SchemathesisBusy, SchemathesisExecutionError)
from schemathesis_loopback_active import run_schemathesis_loopback
from tool_report_k6_summary import parse_k6_handle_summary_json, parse_k6_machine_summary_v1
from tool_report_playwright_json import parse_playwright_json_summary
from playwright_local_fixture_transport import (
    run_local_playwright_fixture,
    PlaywrightFixtureUnavailable,
    PlaywrightFixtureBusy,
    PlaywrightFixtureFailed,
)
from k6_loopback_active import (
    run_k6_loopback,
    K6Unavailable,
    K6Busy,
    K6ExecutionError,
)
from tool_report_siem_ecs import parse_siem_ecs_ndjson_summary
from tool_report_npm_audit import parse_npm_audit_v2_summary
from tool_report_zap import parse_zap_traditional_json_summary
from zap_passive_active import (
    run_zap_self_passive,
    ZapUnavailable,
    ZapBusy,
    ZapExecutionError,
)
from zap_target_active import run_zap_target_active
from zap_target_spider import run_zap_target_spider, validate_exclusions
from tool_report_dependabot import parse_dependabot_alerts_summary
from tool_sync_dependabot import DependabotSyncError, sync_dependabot_summary
from tool_report_burp_logger_csv import parse_burp_logger_csv_summary
from semgrep_tls_verify_filter import filter_direct_requests_tls_findings
from report_provenance import build_engagement_provenance
from tool_report_testssl import parse_testssl_json_summary
from testssl_active import run_testssl_loopback
from testssl_authorized_active import run_testssl_authorized
from tool_report_gitleaks import parse_gitleaks_json_summary
from tool_report_trufflehog import parse_trufflehog_json_summary

from trufflehog_active import run_local_trufflehog_filesystem
from trufflehog_git_active import run_local_trufflehog_git_history, GitHistoryInvalid, GitHistoryUnavailable, GitHistoryBusy, GitHistoryExecution
from tool_report_trivy import parse_trivy_native_json_summary
from trivy_active import run_local_trivy_secret
from trivy_vuln_active import (
    run_local_trivy_vulnerability,
    TrivyVulnInvalidInput,
    TrivyVulnUnavailable,
    TrivyVulnBusy,
    TrivyVulnExecutionError,
)
from trivy_image_archive_active import run_local_trivy_image_archive_vulnerability, TrivyImageArchiveInvalidInput
from trivy_npm_active import run_local_trivy_npm_vulnerability
from trivy_go_mod_active import run_local_trivy_go_mod_vulnerability
from trivy_cargo_active import run_local_trivy_cargo_lock_vulnerability
from trivy_pnpm_active import run_local_trivy_pnpm_vulnerability
from trivy_yarn_active import run_local_trivy_yarn_vulnerability
from trivy_maven_active import run_local_trivy_maven_vulnerability
from trivy_ruby_active import run_local_trivy_ruby_vulnerability
from trivy_db_freshness import (
    SUPPORTED_TRIVY_VULN_PROFILES,
    TRIVY_VULN_PROFILE_IDS,
    TRIVY_VULN_PROFILE_ROUTES,
    TrivyDBFreshnessError,
    require_trusted_db_freshness,
)
from zap_af_preview import build_preview_payload
from zap_scope_plan import PlanError
from zap_selected_path_scope import run_zap_selected_path_spider, validate_selected_paths
from zap_site_active import run_zap_site_active
from zap_authorized import (
    authorization_receipt as zap_authorization_receipt,
    normalize_authorized_target,
    run_zap_authorized,
    runtime_readiness as zap_authorized_runtime_readiness,
)
from nmap_service_fingerprint import run_bounded_tcp_service_fingerprint, validate_service_ports
from gitleaks_git_active import (
    run_local_gitleaks_git_history,
    GitleaksGitInvalid,
    GitleaksGitUnavailable,
    GitleaksGitBusy,
    GitleaksGitExecution,
)
from npm_audit_active import run_local_npm_audit_local, NpmAuditUnavailable, NpmAuditBusy, NpmAuditExecutionError
from osv_active import run_local_osv_scanner, OSVUnavailable, OSVBusy, OSVExecutionError
from trivy_config_active import (
    run_local_trivy_terraform,
    run_local_trivy_dockerfile,
    TrivyConfigUnavailable,
    TrivyConfigBusy,
    TrivyConfigExecutionError,
)
from trivy_terraform_active import (
    run_local_trivy_terraform_batch,
    TrivyConfigUnavailable as TrivyTerraformUnavailable,
    TrivyConfigBusy as TrivyTerraformBusy,
    TrivyConfigExecutionError as TrivyTerraformExecutionError,
)
from trivy_kubernetes_active import run_local_trivy_kubernetes, run_local_trivy_kubernetes_batch
from tool_report_nuclei import parse_nuclei_jsonl_summary
from nuclei_active import run_nuclei_loopback, NucleiUnavailable, NucleiBusy, NucleiExecutionError
from nuclei_broad_jobs import BroadNucleiJobs, NucleiBroadUnavailable, NucleiBroadBusy
from tool_report_semgrep import parse_semgrep_native_json_summary
from semgrep_active import run_local_semgrep
from gitleaks_active import run_local_gitleaks
from tool_report_ssllabs import parse_ssllabs_host_summary, preview_ssllabs_target_name
import ssllabs_rate_state
from ssllabs_active import (
    SSLLabsBusy,
    SSLLabsInvalidResponse,
    SSLLabsUnavailable,
    SSLLabsUpstreamError,
    live_query_enabled,
    normalize_public_hostname,
    operator_token_matches,
    run_ssllabs_cached_query,
)
from ssllabs_live import (
    SSLLabsInvalid as SSLLabsLiveInvalid,
    SSLLabsBusy as SSLLabsLiveBusy,
    SSLLabsUnavailable as SSLLabsLiveUnavailable,
    SSLLabsUpstreamError as SSLLabsLiveUpstreamError,
    SSLLabsRateLimited as SSLLabsLiveRateLimited,
    fetch_ssllabs_info,
    run_ssllabs_live,
    validate_hostname as validate_ssllabs_hostname,
    validate_registered_email,
    validate_stored_tls_target,
)
from tool_report_openssl_x509 import parse_openssl_x509_summary, parse_openssl_x509_batch_summary
from openssl_loopback_active import (run_openssl_x509_loopback, OpenSSLUnavailable, OpenSSLBusy, OpenSSLExecutionError)
from openssl_authorized_active import (
    CONSENT_VERSION as OPENSSL_AUTHORIZED_CONSENT_VERSION,
    run_openssl_x509_authorized,
)
import qa_broker_client
import sandbox_targets
from sandbox_load_tests import (
    run_k6_authorized,
    run_k6_sandbox,
    run_schemathesis_authorized,
    run_schemathesis_sandbox,
)
from authorized_tool_targets import CONSENT_VERSION as AUTHORIZED_TARGET_CONSENT_VERSION
from sandbox_browser_tests import run_playwright_sandbox
from playwright_authorized import authorized_params, authorization_receipt, run_playwright_authorized
from tool_sandbox import SandboxBusy, SandboxExecutionError, SandboxUnavailable
from tool_report_burp_sitemap import parse_burp_sitemap_summary
from tool_report_nmap import parse_nmap_inline_summary
from nmap_active import (
    run_authorized_nmap_scan,
    run_bounded_tcp_connect_scan,
    validate_custom_ports,
    validate_service_version,
    NMAP_LOCK,
)
run_nmap_active_scan = run_bounded_tcp_connect_scan
from scan_diff import ScanDiff
from storage_canonical import KNOWN_SEVERITIES, _normalize_severity, _count_filtered_by_severity


def _parse_strict_json_dict(raw_str: str) -> dict:
    if not isinstance(raw_str, str) or not raw_str.strip() or "\x00" in raw_str:
        raise ValueError("Geçersiz yapılandırma JSON metni.")
    if len(raw_str.encode("utf-8")) > 262_144:
        raise ValueError("Yapılandırma JSON metni azami boyut sınırını aşıyor.")

    def _no_dups(pairs):
        out = {}
        for k, v in pairs:
            if k in out:
                raise ValueError(f"Yinelenen JSON anahtarı '{k}' kabul edilmez.")
            out[k] = v
        return out

    parsed = json.loads(
        raw_str,
        object_pairs_hook=_no_dups,
        parse_constant=lambda c: (_ for _ in ()).throw(ValueError(f"Geçersiz JSON sabiti: {c}")),
    )
    if not isinstance(parsed, dict) or not parsed:
        raise ValueError("Yapılandırma JSON'u boş olmayan bir nesneye çözülmeli.")
    return parsed

DEPENDABOT_SYNC_TRANSPORT = None


def _build_dependabot_offline_transport(pages: list[dict] | None = None):
    page_list = list(pages or [])
    idx = {"i": 0}

    def _transport(url: str, headers: dict[str, str]) -> tuple[int, dict[str, str], bytes]:
        if idx["i"] >= len(page_list):
            return 200, {}, b"[]"
        entry = page_list[idx["i"]]
        idx["i"] += 1
        status = int(entry.get("status", 200))
        resp_headers = {str(k): str(v) for k, v in (entry.get("headers") or {}).items()}
        body_obj = entry.get("alerts") if "alerts" in entry else entry.get("body", [])
        if isinstance(body_obj, (bytes, bytearray)):
            raw_body = bytes(body_obj)
        elif isinstance(body_obj, str):
            raw_body = body_obj.encode("utf-8")
        else:
            raw_body = json.dumps(body_obj, separators=(",", ":")).encode("utf-8")
        return status, resp_headers, raw_body

    return _transport


def _sanitize_error_message(message: str, default: str = "Geçersiz yerel proje dizini veya girdi.") -> str:
    home_str = str(Path.home())
    if "/home/" in message or (home_str and home_str in message):
        return default
    return message


def _list_scans_page(store, limit: int = 50, offset: int = 0, anchor: int | None = None) -> dict:
    limit = max(1, min(limit, 200))
    offset = max(0, offset)
    if hasattr(store, "list_scans_page"):
        return store.list_scans_page(limit, offset, anchor)
    raw_store = getattr(store, "_store", store)
    if offset == 0 and anchor is None and (
        "list_scans" in getattr(store, "__dict__", {})
        or "list_scans" in getattr(raw_store, "__dict__", {})
        or not hasattr(store, "_connect")
    ):
        scans = store.list_scans(limit)
        return {
            "scans": scans,
            "anchor": len(scans),
            "has_more": False,
            "next_offset": None,
        }
    with store._connect() as db:
        if anchor is None:
            anchor_row = db.execute("SELECT COALESCE(MAX(rowid), 0) AS anchor FROM scans").fetchone()
            anchor = int(anchor_row["anchor"]) if anchor_row else 0
        rows = db.execute(
            """
            SELECT s.*, t.url AS target_url, t.hostname AS target_hostname
            FROM scans s
            JOIN targets t ON t.id = s.target_id
            WHERE s.rowid <= ?
            ORDER BY s.created_at DESC, s.rowid DESC
            LIMIT ? OFFSET ?
            """,
            (anchor, limit + 1, offset),
        ).fetchall()
        has_more = len(rows) > limit
        page_rows = rows[:limit]
        scans = []
        for row in page_rows:
            item = store._scan_dict(row, include_findings=False)
            item["comparison"] = store._scan_comparison(db, row, include_details=False)
            scans.append(item)
    return {
        "scans": scans,
        "anchor": anchor,
        "has_more": has_more,
        "next_offset": offset + len(scans) if has_more else None,
    }


def _active_test_window_valid(engagement: dict) -> bool:
    import re
    from datetime import datetime, timezone, timedelta
    raw = engagement.get("test_window")
    if not isinstance(raw, str) or len(raw) != 41:
        return False
    match = re.fullmatch(
        r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)/(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)",
        raw,
    )
    if not match:
        return False
    try:
        start_str, end_str = match.groups()
        start = datetime.fromisoformat(start_str.replace("Z", "+00:00"))
        end = datetime.fromisoformat(end_str.replace("Z", "+00:00"))
    except ValueError:
        return False
    now = datetime.now(timezone.utc)
    return (
        start < end
        and start <= now
        and end >= now + timedelta(seconds=300)
        and (end - start) <= timedelta(hours=24)
    )


BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
DATA_DIR = Path(os.getenv("SNIPER_DATA_DIR", BASE_DIR / "data")).resolve()
PORT = int(os.getenv("SNIPER_PORT", "8787"))
HOST = os.getenv("SNIPER_HOST", "127.0.0.1")


class _LazyStore:
    """Veri deposunu ilk kullanımda açan, iş parçacığı güvenli vekil.

    `import server` (ör. `from server import render_report` veya test keşfi) veri dizini oluşturmamalı,
    SQLite/WAL dosyası açmamalıdır. Canlı yol koruması yine içe aktarma anında, dosya açmadan çalışır;
    gerçek `Store` ilk öznitelik erişiminde ya da sunucu dinlemeye başlamadan önce `main()` içinde açılır.

    Vekilin kendi adları (`_OWN_FIELDS`, sınıfta tanımlı `materialize`/`_is_proxy_name` gibi adlar) ve dunder
    adlar dışındaki öznitelik yazma/silme işlemleri gerçek `Store` örneğine iletilir. Böylece
    `patch.object(server.STORE, "_connect", ...)` ya da `patch.object(server.STORE, "get_scan", ...)` gibi test
    kalıpları, deponun `self.<ad>` üzerinden çağırdığı yöntemlerde de etkili olur (ör. `compare_scans` →
    `self.get_scan`) ve çıkışta `delattr` ile geri alınır. `patch.object(server.STORE, "materialize", ...)` ise
    vekilde kalır ve depoyu açtırmaz. `server.STORE.path = ...` gerçek depoya düşer, ancak canlı Sniper yolu
    oluşturmadaki korumayla, depo açılmadan ve hiçbir dosyaya dokunulmadan `LiveDataProtected` ile reddedilir.
    """

    _OWN_FIELDS = frozenset({"_path", "_lock", "_store"})
    _GUARDED_PATH_FIELDS = frozenset({"path", "_path"})

    def __init__(self, path: Path):
        _guard_live_path(path)  # canlı Sniper yolunu içe aktarmada reddet (yalnız yol hesabı)
        object.__setattr__(self, "_path", path)
        object.__setattr__(self, "_lock", threading.Lock())
        object.__setattr__(self, "_store", None)

    def materialize(self) -> Store:
        store = self._store
        if store is None:
            with self._lock:
                store = self._store
                if store is None:
                    store = Store(self._path)
                    object.__setattr__(self, "_store", store)
        return store

    def __getattr__(self, name: str):
        # Yalnız vekilde (sınıf veya örnek sözlüğünde) bulunmayan adlar buraya düşer; dunder ve vekilin kendi
        # alanları depoyu açtırmaz (ör. __init__ çalışmadan oluşturulmuş kopyada sonsuz özyinelemeyi önler).
        if _LazyStore._is_proxy_name(name):
            raise AttributeError(name)
        return getattr(self.materialize(), name)

    @staticmethod
    def _is_proxy_name(name: str) -> bool:
        """Vekilin kendisine ait adlar: kendi alanları, sınıfında tanımlı adlar (`materialize`, `_is_proxy_name`,
        `_OWN_FIELDS`...) ve dunder adlar. Bunlar depoyu açtırmaz ve depoya iletilmez."""
        return (
            name in _LazyStore._OWN_FIELDS
            or (name.startswith("__") and name.endswith("__"))
            or any(name in vars(klass) for klass in _LazyStore.__mro__)
        )

    def __setattr__(self, name: str, value) -> None:
        if name in _LazyStore._GUARDED_PATH_FIELDS:
            # Depo açılmadan önce reddet; iletilen `path` ayrıca `Store.__setattr__` korumasından geçer.
            _guard_live_path(Path(value))
        if _LazyStore._is_proxy_name(name):
            object.__setattr__(self, name, value)
        else:
            setattr(self.materialize(), name, value)

    def __delattr__(self, name: str) -> None:
        if _LazyStore._is_proxy_name(name):
            object.__delattr__(self, name)
        else:
            delattr(self.materialize(), name)

    def __repr__(self) -> str:
        state = "açık" if self._store is not None else "henüz açılmadı"
        return f"<_LazyStore {self._path} ({state})>"


STORE = _LazyStore(DATA_DIR / "sniper.db")
# Süreç açılırken kurulu sürüm kaydı (güncelleme dosyaları değiştirse de çalışan sürüm budur; bkz. community_release_info).
RUNNING_RELEASE = None
EXECUTOR = ThreadPoolExecutor(max_workers=2, thread_name_prefix="sniper-scan")
SCAN_LOCK = threading.Lock()
ACTIVE_TARGETS: set[str] = set()
METRICS = Metrics()
SCAN_DIFF = ScanDiff(STORE)
BROAD_NUCLEI_JOBS: BroadNucleiJobs | None = None
BROAD_NUCLEI_JOBS_LOCK = threading.Lock()


def get_broad_nuclei_jobs() -> BroadNucleiJobs:
    """Initialize the pinned runtime only when an authorized job is requested."""
    global BROAD_NUCLEI_JOBS
    if BROAD_NUCLEI_JOBS is None:
        with BROAD_NUCLEI_JOBS_LOCK:
            if BROAD_NUCLEI_JOBS is None:
                binary, catalog = nuclei_broad_runtime_paths()
                BROAD_NUCLEI_JOBS = BroadNucleiJobs(
                    data_dir=DATA_DIR,
                    binary=binary,
                    binary_sha256="f27098e0be0cc370af52274611608ad61896d7f0a024e35b136327d39e725477",
                    catalog_root=catalog,
                    pin_path=catalog / "SNIPER-HTTP-CATALOG-PIN-v2.json",
                    expected_pin_sha256="6ebcb6355094e859aa474760fa41cffdf395a0d925841090b1a62b1608bc903e",
                    expected_index_sha256="3fdf439545e40caab9b7cd6256c8099abb8734da0eff6654c29abe05d628dc36",
                    expected_template_count=11655,
                    mapping_sha256="201335d35f4ebf4dee6b15fc879bacb6b24d41870168191bce3e613e523e05b6",
                )
    return BROAD_NUCLEI_JOBS


def _inject_local_home_config(body: bytes) -> bytes:
    """Attach the resolved service-home policy as inert, escaped index metadata."""
    marker = b"<head>"
    if marker not in body:
        return body
    try:
        value = str(Path.home().resolve())
    except (OSError, RuntimeError):
        return body
    if (not value.startswith("/") or value == "/" or len(value) > 1024
            or "//" in value or "\\" in value or re.search(r"[\x00-\x1f\x7f]", value)):
        return body
    escaped = html.escape(value, quote=True).encode("utf-8")
    meta = b'<meta name="sniper-local-home" content="' + escaped + b'">'
    return body.replace(marker, marker + meta, 1)


DIRECT_TARGET_CONSENT_VERSION = "direct-target-authorization-v1"
SSLLABS_THIRD_PARTY_CONSENT_VERSION = "ssllabs-third-party-authorization-v1"


def _direct_target_authorization_receipt() -> dict:
    actor = request_context.current_actor() or {
        "id": "local-operator",
        "username": "yerel",
        "role": "operator",
    }
    return {
        "actor": {key: actor.get(key) for key in ("id", "username", "role")},
        "confirmed_at": utc_now(),
        "consent_version": DIRECT_TARGET_CONSENT_VERSION,
        "confirm_authorized": True,
    }


def _ssllabs_authorization_receipt(normalized_target: str) -> dict:
    actor = request_context.current_actor() or {
        "id": "local-operator",
        "username": "yerel",
        "role": "operator",
    }
    return {
        "actor": {key: actor.get(key) for key in ("id", "username", "role")},
        "confirmed_at": utc_now(),
        "consent_version": SSLLABS_THIRD_PARTY_CONSENT_VERSION,
        "confirm_authorized": True,
        "normalized_target": normalized_target,
        "third_party": "Qualys SSL Labs",
    }


PLUGIN_MANAGER = PluginManager(
    BASE_DIR / "plugins" / "user",
    enabled=os.getenv("SNIPER_ENABLE_PLUGINS", "0") == "1",
)


class RateLimiter:
    # 16. tur: arayüz ilk yüklemede ~90 istek yapıyordu (sınır 90/dk → hızlı tıklamada 429). Statik varlıklar artık
    # sayılmıyor (_rate_limit), API sınırı 240/dk.
    def __init__(self, limit: int = 240, window: int = 60):
        self.limit = limit
        self.window = window
        self.events: dict[str, deque[float]] = defaultdict(deque)
        self.lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self.lock:
            if not hasattr(self, '_last_prune') or now - self._last_prune > self.window:
                self._last_prune = now
                for k in list(self.events.keys()):
                    q = self.events[k]
                    while q and q[0] <= now - self.window:
                        q.popleft()
                    if not q:
                        del self.events[k]
            queue = self.events[key]
            while queue and queue[0] <= now - self.window:
                queue.popleft()
            if len(queue) >= self.limit:
                return False
            queue.append(now)
            return True


LIMITER = RateLimiter()


def _is_static_asset_path(path: str) -> bool:
    """Arayüz varlıkları: /static/ altındaki dosyalar (.. içermeyen), ana sayfa, giriş sayfası ve favicon."""
    if path in ("/", "/index.html", "/login.html", "/favicon.ico"):
        return True
    if ".." in path or "//" in path:
        return False
    if path.startswith("/static/"):
        return True
    # Arayüz betikleri kök yoldan da sunulur (/app.js, /job_queue.js …): tek düzey, bilinen varlık uzantısı.
    return path.count("/") == 1 and path.rsplit(".", 1)[-1] in ("js", "mjs", "css", "tsv", "svg", "png", "ico", "woff2")

# Uzun süren aktif araç rotaları: POST /api/jobs ile arka plan iş kuyruğunda çalıştırılabilir.
# Önizleme/doğrulama gibi hızlı rotalar bilerek dışarıda bırakıldı.
JOB_ROUTES = frozenset({
    "/api/nuclei/http-scans", "/api/project-audits", "/api/dependency-security/sbom", "/api/container-images",
    "/api/web-infra/dns-email-audit", "/api/web-infra/discovery-audit",
    "/api/tool-runs/gitleaks", "/api/tool-runs/gitleaks-git-history", "/api/tools/gitleaks/git-history",
    "/api/tool-runs/trufflehog-filesystem", "/api/tool-runs/trufflehog-git-history",
    "/api/tool-runs/semgrep", "/api/tool-runs/osv-scanner-local", "/api/tool-runs/npm-audit-local",
    "/api/tool-runs/nuclei-loopback", "/api/tool-runs/openssl-x509-loopback",
    "/api/tool-runs/openssl-x509-authorized", "/api/tool-runs/qa-broker-probe",
    "/api/tool-runs/k6-authorized", "/api/tool-runs/schemathesis-authorized",
    "/api/nmap/authorized-target-scan", "/api/tool-runs/testssl-authorized",
    "/api/tool-runs/playwright-authorized", "/api/nuclei/authorized-origin-scans",
    "/api/tool-runs/ssllabs-authorized",
    "/api/tool-runs/k6-sandbox", "/api/tool-runs/schemathesis-sandbox", "/api/tool-runs/playwright-sandbox",
    "/api/tool-runs/testssl-full", "/api/tool-runs/testssl-protocols",
    "/api/tool-runs/schemathesis-local", "/api/tool-runs/schemathesis-loopback",
    "/api/tool-runs/k6-loopback", "/api/tool-runs/k6-loopback-smoke", "/api/tools/k6/loopback",
    "/api/tool-runs/playwright-local-fixture", "/api/tools/playwright/local-fixture",
    "/api/tool-runs/ssllabs-cached-query", "/api/tools/ssllabs/cached-query",
    "/api/tool-runs/ssllabs-live", "/api/tools/ssllabs/live",
    "/api/tool-runs/zap-self-passive", "/api/tool-runs/zap-site-active", "/api/tools/zap/site-active",
    "/api/tool-runs/zap-target-active", "/api/tool-runs/zap-target-spider",
    "/api/tool-runs/zap-authorized",
    "/api/tool-runs/zap-target-spider-scope", "/api/tools/zap/selected-path-scope",
    "/api/tools/nmap/active", "/api/tools/nmap/service-fingerprint", "/api/tool-runs/joern-deep",
    "/api/tool-runs/trivy-vulnerability", "/api/tool-runs/trivy-npm-vulnerability",
    "/api/tool-runs/trivy-image-archive-vulnerability", "/api/tool-runs/trivy-secret",
    "/api/tool-runs/trivy-dockerfile-config", "/api/tool-runs/trivy-terraform-config",
    "/api/tool-runs/trivy-terraform-config-batch", "/api/tools/trivy/terraform-batch",
    "/api/tool-runs/trivy-kubernetes-config", "/api/tool-runs/trivy-kubernetes-config-batch",
    "/api/tool-runs/trivy-cargo-lock", "/api/tool-runs/trivy-cargo-lock-vulnerability", "/api/tools/trivy/cargo-lock",
    "/api/tool-runs/trivy-go-mod", "/api/tool-runs/trivy-go-mod-vulnerability", "/api/tools/trivy/go-mod",
    "/api/tool-runs/trivy-maven-pom", "/api/tool-runs/trivy-maven-vulnerability", "/api/tools/trivy/maven-pom",
    "/api/tool-runs/trivy-pnpm-lock", "/api/tool-runs/trivy-pnpm-vulnerability", "/api/tools/trivy/pnpm-lock",
    "/api/tool-runs/trivy-ruby-gemfile-lock", "/api/tool-runs/trivy-ruby-vulnerability", "/api/tools/trivy/ruby-gemfile-lock",
    "/api/tool-runs/trivy-yarn-lock", "/api/tool-runs/trivy-yarn-vulnerability", "/api/tools/trivy/yarn-lock",
})
# Çift çalıştırma denetiminde hedefi tanımlayan gövde alanları.
_JOB_TARGET_KEYS = (
    "target_id", "engagement_id", "url", "target", "host", "hostname", "path", "project_path",
    "repo_path", "image_path", "dockerfile_path", "archive_path", "directory", "directories", "file", "scope", "sbom_path",
)


def _job_label(route: str, payload: dict) -> str | None:
    """İş listesinde gösterilecek kısa ad: proje analizlerinde proje klasörünün adı (tam yol değil)."""
    value = payload.get("project_path") if isinstance(payload, dict) else None
    if route == "/api/container-images" and isinstance(payload, dict):
        value = payload.get("image_path")
    if route == "/api/dependency-security/sbom-scan" and isinstance(payload, dict):
        value = payload.get("sbom_path")
    if route in ("/api/project-audits", "/api/dependency-security/sbom", "/api/container-images",
                 "/api/dependency-security/offline-scan", "/api/dependency-security/sbom-scan") \
            and isinstance(value, str) and value.strip():
        return Path(value.strip().rstrip("/")).name[:120] or None
    return None


def _job_dedupe_key(route: str, payload: dict) -> str:
    identity = {key: payload[key] for key in _JOB_TARGET_KEYS if key in payload} or payload
    encoded = json.dumps(identity, sort_keys=True, ensure_ascii=False, default=str)
    return route + "|" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _job_finished(job) -> None:
    try:
        STORE.log("job.finished", job.id, {"route": job.route, "state": job.state, "http_status": job.http_status})
    except Exception:
        traceback.print_exc()
    _ops_job_finished(job)


# ---------------------------------------------------------------------------
# İşletim: zamanlanmış taramalar ve yerel bildirimler (scheduler.py, notifications.py)
# ---------------------------------------------------------------------------
SCHEDULER: "sniper_scheduler.Scheduler | None" = None
_SCHEDULER_LOCK = threading.Lock()


def _ops_job_finished(job) -> None:
    """İş bitişi: planın son durumunu güncelle; yerel tarama başarısızsa bildirim üret."""
    try:
        schedule = SCHEDULER.on_job_finished(job.id, job.state, job.finished_at) if SCHEDULER else None
        if job.route in sniper_scheduler.SCAN_ROUTES and job.state in {"failed", "expired", "interrupted"}:
            notifications.on_scan_failed(job.route, job.id, job.state, schedule=schedule)
        elif job.route == "/api/project-audits" and job.state == "succeeded" and schedule is None:
            # Arka planda başlatılan proje analizi bitti (sayfa kapalı olabilir); planlı taramalar zaten
            # yeni/düzelen bulgu bildirimi üretir.
            notifications.on_project_analysis_finished(job.id, job.label, job.result)
    except ops_files.OpsStoreError:
        pass  # veri dizini yok (testler / geçici çalıştırma)
    except Exception:
        traceback.print_exc()


def _license_policy_payload() -> dict:
    policy, customized = license_compliance.load_policy()
    return {"policy": policy, "customized": customized, "default": license_compliance.DEFAULT_POLICY,
            "categories": license_compliance.CATEGORY_LABELS}


def _system_health_report(*, refresh: bool = False) -> dict:
    """Öz sağlık raporu (system_health.py; salt okunur)."""
    return system_health.build_report(
        data_dir=DATA_DIR, app_root=BASE_DIR, store=STORE, jobs=JOBS.list(), job_stats=JOBS.stats(),
        running_release=RUNNING_RELEASE, refresh=refresh,
    )


def _system_health_daily() -> None:
    """Zamanlayıcı turunda çağrılır; günde bir öz sağlık denetimi, sorun varsa bildirim. Saklama politikası açık ve
    "günlük otomatik" seçiliyse (varsayılan kapalı) günde en çok bir kez saklama planı da yürütülür."""
    system_health.daily_check(_system_health_report)
    try:
        data_retention.daily_auto(DATA_DIR, log=lambda action, entity, details: STORE.log(action, entity, details))
    except (ops_files.OpsStoreError, data_retention.RetentionError):
        pass
    except Exception:  # bakım hatası zamanlayıcıyı durdurmaz
        traceback.print_exc()


_RETENTION_LIST_LIMIT = 200


def _retention_payload() -> dict:
    """Saklama politikası + kuru çalıştırma planı (uzun listeler yanıtta kırpılır; plan_id tam plandan hesaplanır)."""
    plan = data_retention.build_plan(DATA_DIR)
    plan["truncated"] = {}
    for name, items in plan["categories"].items():
        if len(items) > _RETENTION_LIST_LIMIT:
            plan["truncated"][name] = len(items)
            plan["categories"][name] = items[:_RETENTION_LIST_LIMIT]
    return {"policy": plan["policy"], "default": data_retention.DEFAULT_POLICY, "plan": plan,
            "labels": data_retention.CATEGORY_LABELS}


def _backups_payload() -> dict:
    """Read-only Community database-backup status."""
    return {
        "db_backups": data_retention.list_db_backups(DATA_DIR),
        "summary": data_retention.backup_summary(DATA_DIR),
        "update_backups": [],
        "restore_commands": {},
        "ui_restore": False,
    }

def _tracking_auth_enabled() -> bool:
    import auth as _auth

    return _auth.manager_for(DATA_DIR).enabled()


def _tracking_assignees() -> dict:
    """Atanabilir kişiler: giriş açıkken etkin kullanıcılar, kapalıyken daha önce kullanılan serbest metin adlar."""
    import auth as _auth

    manager = _auth.manager_for(DATA_DIR)
    if manager.enabled():
        users = [{key: user[key] for key in ("id", "username", "role", "role_label")}
                 for user in manager.list_users() if not user.get("disabled")]
        return {"auth_enabled": True, "users": users, "names": []}
    return {"auth_enabled": False, "users": [], "names": STORE.tracked_assignee_names()}


def _resolve_tracking_assignee(assignee_id, assignee_name) -> tuple[str | None, str]:
    """Giriş açıkken yalnız etkin kullanıcı kimliği, kapalıyken yalnız serbest metin ad. İkisi de boş → kaldır."""
    import auth as _auth

    manager = _auth.manager_for(DATA_DIR)
    if manager.enabled():
        if assignee_name not in (None, ""):
            raise finding_tracking.TrackingError("Giriş açıkken sorumlu kullanıcı kimliğiyle (assignee_id) seçilir.")
        if assignee_id in (None, ""):
            return None, ""
        if not isinstance(assignee_id, str) or len(assignee_id) > 64:
            raise finding_tracking.TrackingError("Geçersiz kullanıcı kimliği.")
        user = manager.get_user(assignee_id)
        if not user or user.get("disabled"):
            raise finding_tracking.TrackingError("Kullanıcı bulunamadı ya da kapalı.")
        return user["id"], user["username"]
    if assignee_id not in (None, ""):
        raise finding_tracking.TrackingError("Giriş kapalıyken sorumlu adı (assignee_name) serbest metin olarak yazılır.")
    if assignee_name in (None, ""):
        return None, ""
    return None, finding_tracking.clean_assignee_name(assignee_name)


def _due_date_check(now) -> None:
    """Zamanlayıcının saatlik denetimi: son tarihi yaklaşan/geçen bulgular için bildirim (bulgu takibi);
    17. tur: süresi dolan risk kabullerini yeniden açma ve SLA ihlali bildirimi."""
    try:
        notifications.check_due_dates(STORE, now=now)
    except ops_files.OpsStoreError:
        pass  # veri dizini yok (testler / geçici çalıştırma)
    try:
        notifications.check_sla(STORE, now=now)
    except ops_files.OpsStoreError:
        pass
    try:
        notifications.check_osv_stale(now=now)  # 21. tur: günde en çok bir kez
    except ops_files.OpsStoreError:
        pass
    except Exception:  # noqa: BLE001 — denetim hatası zamanlayıcıyı durdurmaz
        traceback.print_exc()


def _sla_policy_payload() -> dict:
    policy, customized = portfolio.load_policy()
    return {"policy": policy, "customized": customized, "default": portfolio.DEFAULT_POLICY,
            "severities": list(portfolio.SEVERITIES)}


def _scheduler_for(server) -> "sniper_scheduler.Scheduler":
    """Süreç başına tek zamanlayıcı; işleri canlı istekle aynı yoldan (iş kuyruğu) gönderir."""
    global SCHEDULER
    with _SCHEDULER_LOCK:
        if SCHEDULER is not None:
            return SCHEDULER
        port = int(getattr(server, "server_port", PORT))
        header_items = [("Host", f"127.0.0.1:{port}")]
        client_address = ("127.0.0.1", 0)

        def submit(schedule: dict) -> str:
            route, payload = sniper_scheduler.job_request(schedule)
            if route == BULK_ROUTE:
                # 25. tur: kök dizindeki tüm depolar keşfedilir (boyut sınırını aşanlar hariç) ve tek işte taranır.
                found = bulk_scan.discover(payload["root"])
                paths = [item["path"] for item in found["candidates"] if item["selected"]]
                if not paths:
                    raise bulk_scan.BulkScanError("Kök dizinde taranacak depo bulunamadı.")
                _run, job = _bulk_submit(server, client_address, header_items, root=payload["root"], paths=paths,
                                         options=bulk_scan.BulkOptions(), group=None, actor=None,
                                         trigger=f"schedule:{schedule['id']}")
                return job.id

            def runner(job) -> tuple[int, object]:
                if route in SUBPROCESS_JOB_ROUTES:
                    return _run_post_subprocess(server, client_address, header_items, route, payload,
                                                progress=job.set_progress)
                return _run_post_capture(server, client_address, header_items, route, payload)

            job = JOBS.submit(route, runner, dedupe_key=_job_dedupe_key(route, payload), label=_job_label(route, payload))
            STORE.log("job.created", job.id, {"route": route, "schedule_id": schedule["id"]})
            return job.id

        def job_state(job_id: str):
            job = JOBS.get(job_id)
            return job.get("state") if job else None

        SCHEDULER = sniper_scheduler.Scheduler(
            submit=submit, job_state=job_state,
            log=lambda action, entity, details: STORE.log(action, entity, details),
            maintenance=_system_health_daily,
            periodic=_due_date_check,
        )
        return SCHEDULER


BULK_ROUTE = "/api/bulk-scans"


def _bulk_submit(server, client_address, header_items: list[tuple[str, str]], *, root: str, paths: list[str],
                 options: "bulk_scan.BulkOptions", group: str | None, actor: dict | None, trigger: str = "manual"):
    """25. tur: toplu depo taramasını tek iş olarak kuyruğa al. Her depo, canlı istekle aynı doğrulama/yürütme
    yolundan (ayrı iş sürecinde) proje analizi + çevrimdışı SCA olarak çalışır; iptal çalışan alt süreci durdurur."""
    root_path, repos = bulk_scan.validate_selection(root, paths)
    group_name = bulk_scan.validate_group(group, root_path)
    run = bulk_scan.create_run(root_path, repos, group=group_name, options=options,
                               actor=(actor or {}).get("username") if actor else None, trigger=trigger)
    run_id = run["id"]

    def runner(job) -> tuple[int, object]:
        started = utc_now()

        def run_route(route: str, payload: dict) -> tuple[int, object]:
            try:
                return _run_post_subprocess(server, client_address, header_items, route, payload, actor=actor)
            except RuntimeError:
                if job.cancel_requested or job.expired or route != "/api/project-audits":
                    raise
                # Büyük analiz sonucu iş çıktısı sınırını aşabilir; analiz yine de kaydedilmiştir.
                for audit in STORE.list_project_audits(20):
                    if audit.get("project_path") == payload.get("project_path") and str(audit.get("created_at") or "") >= started:
                        return 201, audit
                raise

        with request_context.acting_as(actor):
            return 200, bulk_scan.execute(run_id, run_route, job=job)

    label = f"Toplu: {root_path.name} ({len(repos)} depo)"
    try:
        job = JOBS.submit(BULK_ROUTE, runner, dedupe_key=BULK_ROUTE + "|" + hashlib.sha256(str(root_path).encode()).hexdigest(),
                          label=label, timeout_seconds=_env_number("SNIPER_BULK_TIMEOUT_SECONDS", 6 * 3600, 60, 24 * 3600))
    except JobQueueError:
        bulk_scan.discard_run(run_id)
        raise
    bulk_scan.attach_job(run_id, job.id)
    STORE.log("bulk_scan.created", run_id, {"job_id": job.id, "root": str(root_path), "repo_count": len(repos),
                                            "group": group_name, "options": options.public(), "trigger": trigger})
    return dict(run, job_id=job.id), job


def _env_number(name: str, default: float, minimum: float, maximum: float) -> float:
    try:
        value = float(os.environ.get(name, default))
    except ValueError:
        return default
    return min(maximum, max(minimum, value))


# Saf Python rotaları (iş parçacığı zorla durdurulamaz): iş kuyruğunda ayrı süreçte (job_worker.py)
# çalışır; iptal/süre aşımı süreç grubunu öldürür.
SUBPROCESS_JOB_ROUTES = frozenset({
    "/api/project-audits", "/api/dependency-security/sbom", "/api/container-images",
    "/api/web-infra/dns-email-audit", "/api/web-infra/discovery-audit",
})
JOB_WORKER_OUTPUT_LIMIT = 4_000_000
JOB_WORKER_SCRIPT = BASE_DIR / "job_worker.py"


def _job_time_budget_env() -> dict[str, str]:
    """İş sürecine proje analizi süre bütçesi: iş süre sınırından önce durup kısmi sonucu kaydetsin (aksi halde iş
    öldürülür ve hiçbir şey kaydedilmez). Ortamda açıkça verilmişse ona dokunulmaz."""
    if os.environ.get("SNIPER_PROJECT_TIME_BUDGET_SECONDS", "").strip():
        return {}
    budget = max(60.0, JOBS.timeout_seconds * 0.85 - 30.0)
    return {"SNIPER_PROJECT_TIME_BUDGET_SECONDS": str(int(budget))}


def _read_progress_pipe(read_fd: int, progress) -> None:
    """İş sürecinin ilerleme borusunu satır satır oku (yalnız doğrulanmış alanlar işe yazılır)."""
    try:
        with os.fdopen(read_fd, "rb") as handle:
            for raw in handle:
                data = project_progress.parse_line(raw[:4096])
                if data is not None:
                    try:
                        progress(data)
                    except Exception:  # noqa: BLE001 - ilerleme işi etkilemez
                        pass
    except OSError:
        pass


def _run_post_subprocess(server, client_address, header_items: list[tuple[str, str]], route: str, payload: dict,
                         *, actor: dict | None = None, progress=None) -> tuple[int, object]:
    request = json.dumps({
        "route": route, "payload": payload, "headers": header_items, "actor": actor,
        "client_address": list(client_address or ("127.0.0.1", 0)),
        "server_port": int(getattr(server, "server_port", PORT)),
    }, ensure_ascii=False).encode("utf-8")
    env = {**os.environ, **_job_time_budget_env()}
    pass_fds: tuple[int, ...] = ()
    reader = None
    if progress is not None:
        read_fd, write_fd = os.pipe()
        env["SNIPER_PROGRESS_FD"] = str(write_fd)
        pass_fds = (write_fd,)
    try:
        process = subprocess.Popen(
            [sys.executable, str(JOB_WORKER_SCRIPT)], cwd=str(BASE_DIR), env=env, pass_fds=pass_fds,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=None, start_new_session=True,
        )
    except BaseException:
        if progress is not None:
            os.close(read_fd)
        raise
    finally:
        if progress is not None:
            os.close(write_fd)  # yazma ucu yalnız iş sürecinde açık kalır; süreç bitince okuyucu EOF görür
    if progress is not None:
        reader = threading.Thread(target=_read_progress_pipe, args=(read_fd, progress), daemon=True,
                                  name="sniper-job-progress")
        reader.start()
    output, _ = process.communicate(request)
    if reader is not None:
        reader.join(timeout=2.0)
    if process.returncode != 0 or len(output) > JOB_WORKER_OUTPUT_LIMIT:
        raise RuntimeError("iş süreci başarısız oldu veya durduruldu")
    data = json.loads(output)
    return int(data["status"]), data.get("body")


def _job_store_dir() -> Path | None:
    raw = os.environ.get("SNIPER_DATA_DIR", "")
    if not raw or os.environ.get("SNIPER_JOB_PERSIST", "1") == "0":
        return None
    return Path(raw) / "jobs"


JOBS = JobQueue(
    store_dir=_job_store_dir(),
    workers=int(_env_number("SNIPER_JOB_WORKERS", 2, 1, 8)),
    max_queued=int(_env_number("SNIPER_JOB_MAX_QUEUED", 20, 1, 200)),
    timeout_seconds=_env_number("SNIPER_JOB_TIMEOUT_SECONDS", 1800, 30, 6 * 3600),
    on_finish=_job_finished,
)


def _run_post_capture(server, client_address, header_items: list[tuple[str, str]], route: str, payload: dict) -> tuple[int, object]:
    """POST rotasını soketsiz bir işleyicide, canlı istekle aynı doğrulama/yürütme yolundan çalıştır."""
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    headers = http.client.HTTPMessage()
    for key, value in header_items:
        if key.lower() not in {"content-length", "transfer-encoding", "content-type"}:
            headers[key] = value
    headers["Content-Type"] = "application/json"
    headers["Content-Length"] = str(len(body))
    handler = SniperHandler.__new__(SniperHandler)
    handler.server = server
    handler.client_address = client_address
    handler.command = "POST"
    handler.path = route
    handler.request_version = "HTTP/1.1"
    handler.requestline = f"POST {route} HTTP/1.1 (iş kuyruğu)"
    handler.headers = headers
    handler.rfile = io.BytesIO(body)
    handler.wfile = io.BytesIO()
    handler.close_connection = True
    handler._request_started = time.monotonic()
    handler._metrics_recorded = False
    handler._response_started = False
    handler._dispatch_post(payload)
    raw = handler.wfile.getvalue()
    head, _sep, content = raw.partition(b"\r\n\r\n")
    status = int(head.split(b" ", 2)[1])
    try:
        return status, json.loads(content) if content else {}
    except (json.JSONDecodeError, UnicodeDecodeError):
        return status, {"content_bytes": len(content)}


def scan_worker(scan_id: str, target_record: dict) -> None:
    target_id = target_record["id"]
    try:
        STORE.mark_scan_running(scan_id)
        target = NormalizedTarget(
            url=target_record["url"],
            scheme=target_record["scheme"],
            hostname=target_record["hostname"],
            port=int(target_record["port"]),
            path=target_record["path"],
        )
        result = run_baseline_scan(target)
        plugin_findings = PLUGIN_MANAGER.scan_all(target.url)
        if plugin_findings:
            result["findings"].extend(plugin_findings)
            result["findings"].sort(
                key=lambda item: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(
                    item.get("severity", "info"), 5
                )
            )
            score, grade, counts = calculate_score(result["findings"])
            result.update(score=score, grade=grade, counts=counts)
            result.setdefault("metadata", {})["plugin_findings"] = len(plugin_findings)
        STORE.complete_scan(scan_id, result)
        METRICS.record_scan("completed")
    except Exception as exc:
        STORE.fail_scan(scan_id, 'Scan failed due to an internal error')
        METRICS.record_scan("failed")
    finally:
        with SCAN_LOCK:
            ACTIVE_TARGETS.discard(target_id)


def clean_text(payload: dict, key: str, *, maximum: int, required: bool = False) -> str:
    value = payload.get(key)
    if value is None:
        value = ""
    else:
        if not isinstance(value, str):
            raise ValueError(f"{key} alanı metin olmalıdır.")
        value = value.strip()
        if '\x00' in value:
            raise ValueError(f"{key} alanı geçersiz karakter içeriyor.")
    if required and not value:
        raise ValueError(f"{key} alanı zorunludur.")
    if len(value) > maximum:
        raise ValueError(f"{key} alanı en fazla {maximum} karakter olabilir.")
    return value


def clean_number(
    payload: dict,
    key: str,
    *,
    minimum: float,
    maximum: float,
    integer: bool = True,
) -> int | float:
    try:
        raw_value = payload.get(key)
        if integer:
            if isinstance(raw_value, float) or isinstance(raw_value, bool):
                raise ValueError(f"{key} alanı geçerli bir sayı olmalıdır.")
            value = int(raw_value)
        else:
            if isinstance(raw_value, bool):
                raise ValueError(f"{key} alanı geçerli bir sayı olmalıdır.")
            value = float(raw_value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{key} alanı geçerli bir sayı olmalıdır.") from exc
    if value != value or value == float('inf') or value == float('-inf'):
        raise ValueError(f"{key} alanı sonlu bir sayı olmalıdır.")
    if value < minimum or value > maximum:
        raise ValueError(f"{key} alanı {minimum:g} ile {maximum:g} arasında olmalıdır.")
    return value


def clean_finding_risk(payload: dict, *, partial: bool = False) -> dict:
    result: dict = {}
    optional_text = {
        "owasp_category": 160,
        "remediation_owner": 180,
        "due_date": 10,
    }
    for key, maximum in optional_text.items():
        if not partial or key in payload:
            result[key] = clean_text(payload, key, maximum=maximum)
    if "due_date" in result and result["due_date"]:
        try:
            parsed = date.fromisoformat(result["due_date"])
            if parsed.isoformat() != result["due_date"]:
                raise ValueError("Geçersiz biçim")
        except ValueError as exc:
            raise ValueError("due_date alanı geçerli bir YYYY-AA-GG tarihi olmalıdır.") from exc
    if not partial or "cwe_id" in payload:
        result["cwe_id"] = normalize_cwe(clean_text(payload, "cwe_id", maximum=24))
    if not partial or "cvss_vector" in payload:
        vector, score = calculate_cvss31(clean_text(payload, "cvss_vector", maximum=180))
        result["cvss_vector"] = vector
        result["cvss_score"] = score
    return result


def build_lab_plan(payload: dict) -> dict:
    forbidden = {
        "password", "passwords", "password_list", "wordlist", "credential", "credentials",
        "username", "email", "target_url", "endpoint", "request_body", "raw_log",
        "extracted_data", "payload", "command",
    }
    if any(k.lower() in forbidden for k in payload):
        raise ValueError("Ham kimlik bilgisi, parola listesi, hedef uç nokta, istek gövdesi veya çıkarılmış veri kaydedilemez.")

    scenario_type = clean_text(payload, "scenario_type", maximum=40, required=True)
    if scenario_type not in {"capacity_plan", "lockout_plan", "external_result"}:
        raise ValueError("Geçersiz laboratuvar senaryosu.")
    environment = clean_text(payload, "environment", maximum=20, required=True)
    if environment not in {"lab", "staging", "production"}:
        raise ValueError("Geçersiz test ortamı.")
    if scenario_type in {"capacity_plan", "lockout_plan"} and environment not in {"lab", "staging"}:
        raise ValueError("Bu plan yalnızca laboratuvar veya staging ortamı için hazırlanabilir.")

    common = {
        "scenario_type": scenario_type,
        "name": clean_text(payload, "name", maximum=160, required=True),
        "environment": environment,
        "authorization_ref": clean_text(payload, "authorization_ref", maximum=240, required=True),
        "engagement_id": clean_text(payload, "engagement_id", maximum=80) or None,
        "evidence_summary": clean_text(payload, "evidence_summary", maximum=4000),
    }
    if common["engagement_id"]:
        engagement = STORE.get_engagement(common["engagement_id"])
        if not engagement:
            raise ValueError("Bağlanmak istenen manuel denetim bulunamadı.")
        required_approval = {
            "capacity_plan": "staging_capacity",
            "lockout_plan": "controlled_lockout",
            "external_result": "redacted_data_proof",
        }[scenario_type]
        if not engagement.get("special_approvals", {}).get(required_approval):
            raise ValueError("Seçilen manuel denetimde bu laboratuvar senaryosu için özel onay bulunmuyor.")

    if scenario_type == "capacity_plan":
        target_rps = clean_number(payload, "target_rps", minimum=1, maximum=100_000)
        duration_seconds = clean_number(payload, "duration_seconds", minimum=1, maximum=86_400)
        baseline_latency_ms = clean_number(payload, "baseline_latency_ms", minimum=1, maximum=600_000)
        assumptions = {
            "target_rps": target_rps,
            "duration_seconds": duration_seconds,
            "baseline_latency_ms": baseline_latency_ms,
            "max_error_percent": clean_number(payload, "max_error_percent", minimum=0, maximum=100, integer=False),
            "abort_latency_ms": clean_number(payload, "abort_latency_ms", minimum=1, maximum=600_000),
            "recovery_seconds": clean_number(payload, "recovery_seconds", minimum=1, maximum=3_600),
            "emergency_contact": clean_text(payload, "emergency_contact", maximum=160, required=True),
        }
        results = {
            "projection_only": True,
            "projected_requests": target_rps * duration_seconds,
            "estimated_concurrency": math.ceil(target_rps * baseline_latency_ms / 1000),
            "traffic_generated": False,
            "requests_generated": 0,
            "notice": "Bu değerler planlama tahminidir; Sniper ağ trafiği üretmedi.",
        }
    elif scenario_type == "lockout_plan":
        max_attempts = clean_number(payload, "max_attempts", minimum=1, maximum=10)
        interval_seconds = clean_number(payload, "interval_seconds", minimum=5, maximum=3_600)
        assumptions = {
            "synthetic_account_alias": clean_text(payload, "synthetic_account_alias", maximum=100, required=True),
            "max_attempts": max_attempts,
            "interval_seconds": interval_seconds,
            "expected_lockout_seconds": clean_number(payload, "expected_lockout_seconds", minimum=1, maximum=86_400),
            "monitoring_signal": clean_text(payload, "monitoring_signal", maximum=240, required=True),
        }
        results = {
            "plan_only": True,
            "minimum_observation_seconds": max(0, max_attempts - 1) * interval_seconds,
            "traffic_generated": False,
            "requests_generated": 0,
            "password_list_stored": False,
            "notice": "Yalnız sentetik hesap için kontrollü gözlem planıdır; Sniper oturum açma isteği göndermedi.",
        }
    else:
        evidence_hash = clean_text(payload, "evidence_hash", maximum=128, required=True)
        if len(evidence_hash) < 12:
            raise ValueError("evidence_hash alanı en az 12 karakter olmalıdır.")
        assumptions = {
            "tool_name": clean_text(payload, "tool_name", maximum=120, required=True),
            "test_window": clean_text(payload, "test_window", maximum=240, required=True),
            "evidence_hash": evidence_hash,
            "control_id": clean_text(payload, "control_id", maximum=80),
        }
        if assumptions["control_id"]:
            if not common["engagement_id"]:
                raise ValueError("Bir kontrolü bağlamak için manuel denetim seçilmelidir.")
            if not any(test["control_id"] == assumptions["control_id"] for test in engagement.get("tests", [])):
                raise ValueError("Seçilen kontrol manuel denetimde bulunamadı.")
        outcome_summary = clean_text(payload, "outcome_summary", maximum=4000, required=True)
        results = {
            "outcome_summary": outcome_summary,
            "masked_evidence_only": True,
            "traffic_generated_by_sniper": False,
            "requests_generated_by_sniper": 0,
            "notice": "Harici test sonucu kaydıdır; ham günlük, kimlik bilgisi veya çıkarılmış veri içermez.",
        }
    return {**common, "assumptions": assumptions, "results": results}


_LOOPBACK_HOST_NAMES = frozenset({"127.0.0.1", "localhost", "[::1]"})
# Satır içi kaynak denetimleri 256 KB'a kadar içerik kabul eder; diğer POST gövdeleri 64 KB ile sınırlı.
_LARGE_BODY_PATHS = frozenset({
    "/api/secret-intelligence/audit", "/api/privacy-dataflow/audit", "/api/host-hardening/audit",
    "/api/dos-resilience/audit", "/api/audit-logging/audit", "/api/browser-extension-pwa/audit",
    "/api/zero-trust-mesh/audit", "/api/business-logic/audit", "/api/database-security/audit",
    "/api/crypto-cbom-pqc/audit", "/api/web3-iot-security/audit", "/api/ai-llm-security/audit",
    "/api/cloud-iam-security/audit", "/api/protocol-security/audit", "/api/auth-protocol/audit",
    "/api/mobile-security/audit-manifest", "/api/taint-rules/try",
})
DEFAULT_MAX_BODY_BYTES = 65_536
LARGE_MAX_BODY_BYTES = 300_000
MAX_CONCURRENT_CONNECTIONS = 64


def _allowed_host_names() -> frozenset[str]:
    """Host başlığında kabul edilen adlar: loopback + SNIPER_ALLOWED_HOSTS (ör. Docker servis adı)."""
    extra = {
        item.strip().lower()
        for item in os.getenv("SNIPER_ALLOWED_HOSTS", "").split(",")
        if item.strip()
    }
    return _LOOPBACK_HOST_NAMES | frozenset(extra)


class SniperHTTPServer(ThreadingHTTPServer):
    """Eşzamanlı bağlantı sayısı sınırlı HTTP sunucusu (yavaş istemci / slowloris koruması)."""

    daemon_threads = True

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._connection_slots = threading.BoundedSemaphore(MAX_CONCURRENT_CONNECTIONS)

    def process_request(self, request, client_address) -> None:
        if not self._connection_slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._connection_slots.release()
            raise

    def process_request_thread(self, request, client_address) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._connection_slots.release()


class SniperHandler(BaseHTTPRequestHandler):
    server_version = "SniperLocal"
    sys_version = ""
    # İstek satırı/başlık/gövde okumasında asılı kalan bağlantılar bu süre sonunda kapanır.
    timeout = 30
    _RESPONSE_HEADER_NAME = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+\Z")

    def send_header(self, keyword: str, value: str) -> None:
        """Reject response-header injection before BaseHTTPRequestHandler buffers it."""
        header_name = str(keyword)
        header_value = str(value)
        if not self._RESPONSE_HEADER_NAME.fullmatch(header_name):
            raise ValueError("Geçersiz HTTP yanıt başlığı adı.")
        if "\r" in header_value or "\n" in header_value:
            raise ValueError("Geçersiz HTTP yanıt başlığı değeri.")
        super().send_header(header_name, header_value)

    def handle_one_request(self) -> None:
        self._request_started = time.monotonic()
        self._metrics_recorded = False
        self._response_started = False
        actor_token = request_context.ACTOR.set(None)  # bağlantı iş parçacığı yeniden kullanılır: istek başına sıfırla
        try:
            super().handle_one_request()
        except (TimeoutError, ConnectionError):
            self.close_connection = True
        except Exception as exc:
            if isinstance(exc, ValueError):
                try:
                    urlsplit(getattr(self, "path", ""))
                except ValueError:
                    self._error(HTTPStatus.BAD_REQUEST, "Geçersiz istek.")
                    return
            # Ayrıntı yalnız sunucu günlüğüne yazılır; istemciye genel mesaj döner.
            traceback.print_exc()
            self.close_connection = True
            if not self._response_started:
                try:
                    self._error(HTTPStatus.INTERNAL_SERVER_ERROR, "Sunucu iç hatası; ayrıntılar sunucu günlüğünde.")
                except Exception:
                    pass
        finally:
            request_context.ACTOR.reset(actor_token)

    def _request_preflight(self) -> bool:
        """Tüm metotlarda: Host doğrulaması (DNS rebinding) ve çapraz site API isteği reddi."""
        hosts = self.headers.get_all("Host") or []
        port = int(getattr(self.server, "server_port", PORT))
        if len(hosts) != 1:
            self._error(HTTPStatus.BAD_REQUEST, "Geçersiz Host başlığı.")
            return False
        host = hosts[0].strip().lower()
        if host.startswith("["):  # IPv6 sabiti: [::1] veya [::1]:port
            end = host.find("]")
            name, rest = (host[: end + 1], host[end + 1 :]) if end > 0 else (host, "!")
            host_port = rest[1:] if rest.startswith(":") else ("" if not rest else "!")
        else:
            name, _sep, host_port = host.partition(":")
        if host_port and not host_port.isdigit():
            self._error(HTTPStatus.BAD_REQUEST, "Geçersiz Host başlığı.")
            return False
        # DNS rebinding koruması ad üzerinden yapılır. Loopback adlar her portla kabul edilir
        # (ör. SSH tüneliyle farklı yerel port); ek adlar (SNIPER_ALLOWED_HOSTS) yalnız sunucu portuyla.
        if name in _LOOPBACK_HOST_NAMES:
            return self._fetch_site_allowed() and auth_routes.gate(self)
        if name not in _allowed_host_names() or not host_port or int(host_port) != port:
            self._error(HTTPStatus.MISDIRECTED_REQUEST, "Host başlığı reddedildi.")
            return False
        # Giriş etkinse oturum/CSRF/rol denetimi (kapalıyken tek stat; davranış değişmez).
        return self._fetch_site_allowed() and auth_routes.gate(self)

    def _fetch_site_allowed(self) -> bool:
        path = urlsplit(self.path).path
        if path == "/metrics" or path == "/api" or path.startswith("/api/"):
            fetch_site = (self.headers.get("Sec-Fetch-Site") or "").strip().lower()
            if fetch_site and fetch_site not in {"same-origin", "none"}:
                self._error(HTTPStatus.FORBIDDEN, "Çapraz site API isteği reddedildi.")
                return False
        return True

    def send_response(self, code: int, message: str | None = None) -> None:
        self._response_started = True
        if not getattr(self, "_metrics_recorded", False):
            METRICS.observe_request(
                getattr(self, "command", "UNKNOWN"),
                getattr(self, "path", "/"),
                int(code),
                time.monotonic() - getattr(self, "_request_started", time.monotonic()),
            )
            self._metrics_recorded = True
        super().send_response(code, message)

    def log_message(self, format: str, *args) -> None:
        if getattr(self, "_bootstrap_capture", False):
            return  # /api/bootstrap alt istekleri ayrıca günlüğe yazılmaz
        if os.getenv("SNIPER_QUIET") != "1":
            super().log_message(format, *args)

    def do_GET(self) -> None:
        if not self._request_preflight() or not self._rate_limit():
            return
        parsed = urlsplit(self.path)
        path = parsed.path
        download_requested = parse_qs(parsed.query).get("download", ["0"])[0] == "1"
        self._report_lang = parse_qs(parsed.query).get("lang", ["tr"])[0]
        # 17. tur: HTML raporlar ?format=pdf ile yalıtılmış Chromium'da PDF'e çevrilir (report_pdf.py).
        self._report_format = parse_qs(parsed.query).get("format", ["html"])[0]
        if path == "/api/bootstrap":
            return self._bootstrap_get()
        if path == "/api/jobs" or path.startswith("/api/jobs/"):
            return self._jobs_get(path)
        if path == "/api/mcp-scan-requests":
            return self._mcp_scan_requests_get()
        if path == "/api/runtime-proofs/dast-profiles":
            return self._json(dast_runtime.catalog())
        if path == "/api/tools/zap/authorized/readiness":
            return self._json(zap_authorized_runtime_readiness())
        if path == "/api/bulk-scans" or path.startswith("/api/bulk-scans/"):  # sabit metin: do_GET/do_POST yalıtılmış testlerde de çalışır
            return self._bulk_get(path)
        if path.startswith("/api/auth/"):
            return auth_routes.handle_get(self, path)
        if path in ("/api/taint-rules", "/api/taint-rules/opengrep"):
            return self._taint_rules_get(path)
        if path == "/api/qa-broker/status":
            return self._json(qa_broker_client.status())
        if path == "/api/sandbox-targets":
            return self._json(sandbox_targets.status())
        if path in ("/api/schedules", "/api/notifications", "/api/notification-settings"):
            return self._ops_get(path, parse_qs(parsed.query))
        if path == "/api/system/version":
            # Salt okunur: sürüm, motor kimliği, kurulum/güncelleme geçmişi, yedekler. Güncelleme arayüzden başlatılamaz.
            return self._json(community_release_info.system_version_payload(
                BASE_DIR, DATA_DIR, running_release=RUNNING_RELEASE
            ))
        if path == "/api/license-policy":
            return self._json(_license_policy_payload())
        if path in ("/api/portfolio", "/api/portfolio/sla-policy", "/api/portfolio/export"):
            return self._portfolio_get(path, parse_qs(parsed.query))
        if path == "/api/system/backups":
            return self._json(_backups_payload())  # yönetici (auth._ADMIN_GET_PREFIXES); salt okunur
        if path == "/api/system/retention":
            try:
                return self._json(_retention_payload())  # yönetici; kuru çalıştırma planı, hiçbir şey silmez
            except ops_files.OpsStoreError as exc:
                return self._error(HTTPStatus.SERVICE_UNAVAILABLE, str(exc))
        if path == "/api/system/health-report":
            # Öz sağlık raporu (salt okunur; hiçbir şeyi silmez/düzeltmez). ?refresh=1 önbelleği atlar.
            refresh = parse_qs(parsed.query).get("refresh", ["0"])[0] == "1"
            return self._json(_system_health_report(refresh=refresh))
        if path == "/api/findings/unified":
            return self._unified_findings_get(parse_qs(parsed.query))
        if path == "/api/scan-scope":
            scope = scan_scope.load_default()
            return self._json({"scope": scope.public(), "is_default": scope.is_default, **scan_scope.describe()})
        if path in ("/api/eval/history", "/api/eval/latest", "/api/eval/rule-false-positives"):
            return self._eval_get(path)
        if path == "/metrics":
            with SCAN_LOCK:
                active_scans = len(ACTIVE_TARGETS)
            return self._text(
                METRICS.render(active_scans=active_scans, loaded_plugins=PLUGIN_MANAGER.loaded_count),
                content_type="text/plain; version=0.0.4; charset=utf-8",
            )
        if path == "/api/health":
            return self._json({
                "status": "ok",
                "service": "sniper-audit",
                "profile": "community-v1",
                "plugins": PLUGIN_MANAGER.public_status(),
            })
        if path == "/api/plugins":
            return self._json(PLUGIN_MANAGER.public_status())
        if path == "/api/dashboard":
            return self._json(STORE.dashboard())
        if path == "/api/targets":
            return self._json({"targets": STORE.list_targets()})
        if path == "/api/scans":
            params = parse_qs(parsed.query, keep_blank_values=True)
            try:
                limit = int(params.get("limit", ["50"])[0])
            except ValueError:
                limit = 50

            def page_integer(name: str, maximum: int) -> int | None:
                raw = params.get(name)
                if raw is None:
                    return None
                if len(raw) != 1 or not raw[0].isascii() or not raw[0].isdigit():
                    raise ValueError(name)
                value = int(raw[0])
                if value < 0 or value > maximum:
                    raise ValueError(name)
                return value

            try:
                offset = page_integer("offset", 1_000_000)
                anchor = page_integer("anchor", 9_223_372_036_854_775_807)
            except ValueError:
                return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz sayfa parametresi.")
            return self._json(_list_scans_page(STORE, limit, offset or 0, anchor))
        if path == "/api/engagements":
            return self._json({"engagements": STORE.list_engagements()})
        if path == "/api/lab-runs":
            return self._json({"lab_runs": STORE.list_lab_runs()})
        if path == "/api/project-audits":
            return self._json({"project_audits": STORE.list_project_audits(), "total": STORE.count_project_audits()})
        if path.startswith("/api/container-images/") and path.endswith("/sbom"):
            # 18. tur: konteyner taramasının CycloneDX SBOM'u (kayıtlı analizden; ağ yok)
            audit_id = path[len("/api/container-images/"):-len("/sbom")]
            audit = STORE.get_project_audit(audit_id) if re.fullmatch(r"prj_[0-9a-f]{12,32}", audit_id) else None
            if not audit or audit.get("audit_kind") != "container":
                return self._error(HTTPStatus.NOT_FOUND, "Konteyner taraması bulunamadı.")
            name = re.sub(r"[^A-Za-z0-9._-]+", "-", str(audit.get("project_name") or "imaj"))[:80]
            return self._sbom_download(container_scan.cyclonedx_sbom(audit), parse_qs(parsed.query), f"sniper-{name}",
                                       str(audit.get("created_at") or ""), audit_id)
        if path.startswith("/api/dependency-security/sbom-scans/") and path.endswith("/vex"):
            # 20. tur: dış SBOM taramasından VEX (OpenVEX / CycloneDX VEX); ağ yok
            audit_id = path[len("/api/dependency-security/sbom-scans/"):-len("/vex")]
            audit = STORE.get_project_audit(audit_id) if re.fullmatch(r"prj_[0-9a-f]{12,32}", audit_id) else None
            if not audit or audit.get("audit_kind") != "sbom":
                return self._error(HTTPStatus.NOT_FOUND, "SBOM taraması bulunamadı.")
            fmt = (parse_qs(parsed.query).get("format") or ["openvex"])[0]
            import vex_export
            if fmt not in vex_export.FORMATS:
                return self._error(HTTPStatus.BAD_REQUEST, "format openvex ya da cyclonedx olmalı.")
            result = sbom_scan.vex_for_audit(audit, fmt)
            name = re.sub(r"[^A-Za-z0-9._-]+", "-", str(audit.get("project_name") or "sbom"))[:80]
            return self._json(result["document"], disposition=f'attachment; filename="sniper-{name}-{fmt}-vex.json"')
        if path == "/api/dependency-security/vex-decisions":
            return self._dependency_vex_decisions_get(parse_qs(parsed.query))
        if path == "/api/dependency-security/offline-db":
            # 18. tur: ekosistem başına çevrimdışı OSV veritabanı durumu (güven denetimiyle; salt okunur)
            import osv_db_refresh
            import osv_offline
            return self._json({"databases": osv_offline.database_status(),
                               "configured": osv_db_refresh.configured_ecosystems()})
        if path in {"/api/dependency-security", "/api/dependency-security/report.json"}:
            disposition = 'attachment; filename="sniper-dependency-security.json"' if path.endswith("report.json") else None
            return self._json(STORE.dependency_security(), disposition=disposition)
        if path == "/api/audit-log":
            return self._json({"events": STORE.recent_audit_log()})
        if path == "/api/audit-log/verify":
            # Kalıcı hash zincirini tüm tablo üzerinde (id ASC, sayfalı) doğrular; yalnız son N kaydı
            # yeniden hesaplayan eski yol saklı hash olmadığı için her zaman verified:true dönüyordu.
            return self._json(STORE.verify_audit_chain())
        if path == "/api/methodology":
            categories = [
                {
                    "slug": slug, "title": title, "reference": reference,
                    "control_count": sum(1 for control in TEST_CATALOG if control["category"] == slug),
                }
                for slug, title, reference in CATEGORIES
            ]
            return self._json({"category_count": len(categories), "control_count": len(TEST_CATALOG), "categories": categories})
        if path == "/api/tooling":
            return self._json(tooling_payload())
        if path == "/api/tooling/readiness":
            return self._json(runtime_readiness_payload())
        if path == "/api/tooling/bundle-manifest":
            from tool_runtime_autodiscover import portable_bundle_manifest
            return self._json(portable_bundle_manifest())
        if path in {"/api/tools/semgrep/rulepack-inventory", "/api/tool-reports/semgrep/rulepack-inventory"}:
            try:
                from semgrep_rulepack_inventory import summarize_trusted_semgrep_rulepack
                rules_env = os.environ.get("SNIPER_SEMGREP_RULES", "")
                params = parse_qs(parsed.query, keep_blank_values=True)
                target_extensions: list[str] | None = None
                if "target_extensions" in params:
                    target_extensions = [
                        part
                        for raw_item in params["target_extensions"]
                        for part in raw_item.split(",")
                    ]
                return self._json(
                    summarize_trusted_semgrep_rulepack(
                        rules_env,
                        target_extensions=target_extensions,
                    )
                )
            except ValueError as exc:
                msg = str(exc)
                if "/" in msg or "\\" in msg:
                    msg = "Geçersiz Semgrep kural paketi."
                return self._error(HTTPStatus.BAD_REQUEST, msg)

        if path in {"/api/tools/trivy/db-freshness", "/api/tool-reports/trivy/db-freshness"}:
            params = parse_qs(parsed.query, keep_blank_values=True)
            profile: str | None = None
            if "profile" in params:
                if len(params["profile"]) != 1 or not params["profile"][0].strip():
                    return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz Trivy güvenlik açığı profili.")
                profile = params["profile"][0].strip()
                if profile not in SUPPORTED_TRIVY_VULN_PROFILES and profile not in TRIVY_VULN_PROFILE_IDS.values():
                    return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz Trivy güvenlik açığı profili.")
            cache_env = os.environ.get("SNIPER_TRIVY_VULN_CACHE_DIR", "").strip()
            if not cache_env:
                return self._error(HTTPStatus.SERVICE_UNAVAILABLE, "Trivy zafiyet veritabanı kullanılamıyor.")
            db_dir = Path(cache_env) / "db"
            try:
                if not (db_dir / "trivy.db").is_file() and not (db_dir / "metadata.json").is_file():
                    return self._error(HTTPStatus.SERVICE_UNAVAILABLE, "Trivy zafiyet veritabanı kullanılamıyor.")
                require_trusted_db_freshness(db_dir, profile=profile)
            except (TrivyDBFreshnessError, OSError, ValueError):
                return self._error(HTTPStatus.SERVICE_UNAVAILABLE, "Trivy zafiyet veritabanı kullanılamıyor.")
            return self._json({
                "format": "trivy-db-freshness-status-v1",
                "status": "ok",
                "freshness_gate_passed": True,
                "policy": os.environ.get("SNIPER_TRIVY_VULN_DB_FRESHNESS_POLICY", "off"),
                "profile": profile,
                "supported_profiles": list(SUPPORTED_TRIVY_VULN_PROFILES),
                "profile_ids": dict(TRIVY_VULN_PROFILE_IDS),
                "profile_routes": dict(TRIVY_VULN_PROFILE_ROUTES),
            })

        if path in {"/api/tools/ssllabs/rate-state", "/api/tool-runs/ssllabs-rate-state"}:
            if not self._is_loopback_client():
                return self._error(HTTPStatus.FORBIDDEN, "Yalnız yerel geri dönüş adresinden izin verilir.")
            params = parse_qs(parsed.query, keep_blank_values=True)
            normalized_host: str | None = None
            if "hostname" in params:
                if len(params["hostname"]) != 1 or not params["hostname"][0].strip():
                    return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz SSL Labs hedef ana bilgisayar adı.")
                try:
                    normalized_host = normalize_public_hostname(params["hostname"][0])
                except ValueError:
                    return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz SSL Labs hedef ana bilgisayar adı.")
            try:
                now = time.time()
                with ssllabs_rate_state._locked() as fd:
                    state = ssllabs_rate_state._read(fd)
                global_until = float(state.get("global_backoff_until", 0.0) or 0.0)
                hosts_map = state.get("hosts") if isinstance(state.get("hosts"), dict) else {}
                rate_payload = {
                    "format": "ssllabs-rate-state-v1",
                    "status": "backoff" if global_until > now else "ready",
                    "global_backoff_active": bool(global_until > now),
                    "tracked_host_count": len(hosts_map),
                    "cooldown_seconds": ssllabs_rate_state.COOLDOWN_SECONDS,
                    "inflight_seconds": ssllabs_rate_state.INFLIGHT_SECONDS,
                    "host_backoff_seconds": ssllabs_rate_state.HOST_BACKOFF_SECONDS,
                    "global_backoff_seconds": ssllabs_rate_state.GLOBAL_BACKOFF_SECONDS,
                }
                if normalized_host is not None:
                    host_entry = hosts_map.get(normalized_host) if isinstance(hosts_map.get(normalized_host), dict) else {}
                    inflight_until = float(host_entry.get("inflight_until", 0.0) or 0.0)
                    backoff_until = float(host_entry.get("backoff_until", 0.0) or 0.0)
                    last_completed = float(host_entry.get("last_completed_at", 0.0) or 0.0)
                    rate_payload["hostname"] = normalized_host
                    rate_payload["host_inflight_active"] = bool(inflight_until > now)
                    rate_payload["host_backoff_active"] = bool(backoff_until > now)
                    rate_payload["host_cooldown_active"] = bool(
                        last_completed > 0.0 and now - last_completed < ssllabs_rate_state.COOLDOWN_SECONDS
                    )
                return self._json(rate_payload)
            except ssllabs_rate_state.RateStateUnavailable:
                return self._error(HTTPStatus.SERVICE_UNAVAILABLE, "SSL Labs hız sınırı durumu kullanılamıyor.")

        parts = [part for part in path.split("/") if part]

        if len(parts) == 4 and parts[:3] == ["api", "nuclei", "http-scans"]:
            job_id = parts[3]
            if len(job_id) != 16 or any(ch not in "0123456789abcdef" for ch in job_id):
                return self._error(HTTPStatus.NOT_FOUND, "Nuclei işi bulunamadı.")
            try:
                return self._json(get_broad_nuclei_jobs().status(job_id))
            except FileNotFoundError:
                return self._error(HTTPStatus.NOT_FOUND, "Nuclei işi bulunamadı.")
            except (NucleiBroadUnavailable, OSError, ValueError):
                return self._error(HTTPStatus.SERVICE_UNAVAILABLE, "Nuclei servisi kullanılamıyor.")

        # Scan Diff endpoints - ÖNCE kontrol edilmeli (daha spesifik route'lar).
        # Tüm diff görünümleri aynı kimlik, hedef, durum ve kronoloji sözleşmesini
        # kullanır; böylece özet ve tekil bulgu uçları farklı hata kodları üretmez.
        if len(parts) in {5, 6} and parts[:2] == ["api", "scans"]:
            action = parts[2]
            scan_id_1, scan_id_2 = parts[3], parts[4]
            diff_actions = {"diff", "compare", "new", "resolved", "persistent"}
            # Yalnız tam karşılaştırma indirilebilir rapor üretir: .../diff/A/B/report.json|report.html
            report_requested = len(parts) == 6
            report_format = parts[5] if report_requested else None
            if report_requested and (action not in {"diff", "compare"} or report_format not in {"report.json", "report.html", "report.csv"}):
                return self._error(HTTPStatus.NOT_FOUND, "Karşılaştırma raporu bulunamadı.")

            if action in diff_actions and scan_id_2:
                scan_1 = STORE._scan_snapshot(scan_id_1)
                scan_2 = STORE._scan_snapshot(scan_id_2)

                if not scan_1:
                    return self._error(HTTPStatus.NOT_FOUND, "İlk tarama bulunamadı.")
                if not scan_2:
                    return self._error(HTTPStatus.NOT_FOUND, "İkinci tarama bulunamadı.")
                if scan_id_1 == scan_id_2:
                    return self._error(HTTPStatus.BAD_REQUEST, "Aynı tarama karşılaştırılamaz.")
                if scan_1["target_id"] != scan_2["target_id"]:
                    return self._error(HTTPStatus.BAD_REQUEST, "Aynı hedefe ait taramalar karşılaştırılmalı.")
                if scan_1["status"] != "completed":
                    return self._error(HTTPStatus.BAD_REQUEST, "İlk tarama 'completed' durumda olmalı.")
                if scan_2["status"] != "completed":
                    return self._error(HTTPStatus.BAD_REQUEST, "İkinci tarama 'completed' durumda olmalı.")
                if scan_1["created_at"] >= scan_2["created_at"]:
                    return self._error(HTTPStatus.BAD_REQUEST, "İlk tarama, ikinci taramadan önce olmalı.")

                query = parse_qs(parsed.query, keep_blank_values=True)
                try:
                    if action in ("diff", "compare"):
                        if report_format == "report.html":
                            payload = SCAN_DIFF.compare_scans(scan_id_1, scan_id_2, include_details=True)
                            return self._diff_html_report(payload, scan_1, scan_2, download=download_requested)
                        if report_format == "report.csv":
                            payload = SCAN_DIFF.compare_scans(scan_id_1, scan_id_2, include_details=True)
                            return self._diff_csv_report(payload, scan_id_1, scan_id_2)
                        include_details = query.get("details", ["1"])[0].strip().lower() not in {"0", "false", "no"}
                        payload = SCAN_DIFF.compare_scans(scan_id_1, scan_id_2, include_details=include_details)
                        disposition = None
                        if report_requested:
                            disposition = f'attachment; filename="sniper-diff-{scan_id_1}-{scan_id_2}.json"'
                        return self._json(payload, disposition=disposition)

                    severity_filter = query.get("severity", [None])[0]
                    if severity_filter is not None:
                        if severity_filter.strip() == "":
                            return self._error(
                                HTTPStatus.BAD_REQUEST,
                                "Geçersiz önem derecesi filtresi. Kabul edilen değerler: " + ", ".join(KNOWN_SEVERITIES) + ".",
                            )
                        severity_filter = _normalize_severity(severity_filter)
                        if severity_filter not in KNOWN_SEVERITIES:
                            return self._error(
                                HTTPStatus.BAD_REQUEST,
                                "Geçersiz önem derecesi filtresi. Kabul edilen değerler: " + ", ".join(KNOWN_SEVERITIES) + ".",
                            )

                    if action == "new":
                        compare_result = SCAN_DIFF.compare_scans(scan_id_1, scan_id_2, include_details=True)
                        all_new_findings = compare_result["new_findings"]
                        if severity_filter is not None:
                            findings = [f for f in all_new_findings if _normalize_severity(f.get("severity", "")) == severity_filter]
                        else:
                            findings = all_new_findings
                        resolved_findings = compare_result["resolved_findings"]
                        persistent_findings = compare_result["persistent_findings"]
                        if severity_filter is not None:
                            resolved_findings = [f for f in resolved_findings if _normalize_severity(f.get("severity", "")) == severity_filter]
                            persistent_findings = [f for f in persistent_findings if _normalize_severity(f.get("severity", "")) == severity_filter]
                        return self._json({
                            "new_findings": findings,
                            "count": len(findings),
                            "summary": {
                                "new_by_severity": _count_filtered_by_severity(findings, severity_filter),
                                "resolved_by_severity": _count_filtered_by_severity(resolved_findings, severity_filter),
                                "persistent_by_severity": _count_filtered_by_severity(persistent_findings, severity_filter),
                            }
                        })
                    if action == "resolved":
                        compare_result = SCAN_DIFF.compare_scans(scan_id_1, scan_id_2, include_details=True)
                        all_resolved_findings = compare_result["resolved_findings"]
                        if severity_filter is not None:
                            findings = [f for f in all_resolved_findings if _normalize_severity(f.get("severity", "")) == severity_filter]
                        else:
                            findings = all_resolved_findings
                        new_findings = compare_result["new_findings"]
                        persistent_findings = compare_result["persistent_findings"]
                        if severity_filter is not None:
                            new_findings = [f for f in new_findings if _normalize_severity(f.get("severity", "")) == severity_filter]
                            persistent_findings = [f for f in persistent_findings if _normalize_severity(f.get("severity", "")) == severity_filter]
                        return self._json({
                            "resolved_findings": findings,
                            "count": len(findings),
                            "summary": {
                                "new_by_severity": _count_filtered_by_severity(new_findings, severity_filter),
                                "resolved_by_severity": _count_filtered_by_severity(findings, severity_filter),
                                "persistent_by_severity": _count_filtered_by_severity(persistent_findings, severity_filter),
                            }
                        })
                    compare_result = SCAN_DIFF.compare_scans(scan_id_1, scan_id_2, include_details=True)
                    all_persistent_findings = compare_result["persistent_findings"]
                    if severity_filter is not None:
                        findings = [f for f in all_persistent_findings if _normalize_severity(f.get("severity", "")) == severity_filter]
                    else:
                        findings = all_persistent_findings
                    new_findings = compare_result["new_findings"]
                    resolved_findings = compare_result["resolved_findings"]
                    if severity_filter is not None:
                        new_findings = [f for f in new_findings if _normalize_severity(f.get("severity", "")) == severity_filter]
                        resolved_findings = [f for f in resolved_findings if _normalize_severity(f.get("severity", "")) == severity_filter]
                    return self._json({
                        "persistent_findings": findings,
                        "count": len(findings),
                        "summary": {
                            "new_by_severity": _count_filtered_by_severity(new_findings, severity_filter),
                            "resolved_by_severity": _count_filtered_by_severity(resolved_findings, severity_filter),
                            "persistent_by_severity": _count_filtered_by_severity(findings, severity_filter),
                        }
                    })
                except ValueError as exc:
                    return self._error(HTTPStatus.BAD_REQUEST, str(exc))

        # Scan detail endpoints - daha genel route
        if len(parts) >= 3 and parts[:2] == ["api", "scans"]:
            scan = STORE.get_scan(parts[2])
            if not scan:
                return self._error(HTTPStatus.NOT_FOUND, "Tarama bulunamadı.")
            if len(parts) == 3:
                return self._json(scan)
            if len(parts) == 4 and parts[3] == "report.json":
                return self._json(scan, disposition=f'attachment; filename="sniper-{scan["id"]}.json"')
            if len(parts) == 4 and parts[3] == "report.html":
                return self._html_report(scan, download=download_requested)
            if len(parts) == 4 and parts[3] == "report.sarif":
                return self._sarif_report(scan)

        if len(parts) == 5 and parts[:3] == ["api", "scans", "resolved"]:
            scan_id_1, scan_id_2 = parts[3], parts[4]
            severity_filter = None
            query = parse_qs(parsed.query)
            if "severity" in query:
                severity_filter = query["severity"][0]
            try:
                resolved_findings = SCAN_DIFF.get_resolved_findings(scan_id_1, scan_id_2, severity_filter=severity_filter)
                return self._json({"resolved_findings": resolved_findings, "count": len(resolved_findings)})
            except ValueError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))

        if len(parts) == 5 and parts[:3] == ["api", "scans", "persistent"]:
            scan_id_1, scan_id_2 = parts[3], parts[4]
            severity_filter = None
            query = parse_qs(parsed.query)
            if "severity" in query:
                severity_filter = query["severity"][0]
            try:
                persistent_findings = SCAN_DIFF.get_persistent_findings(scan_id_1, scan_id_2, severity_filter=severity_filter)
                return self._json({"persistent_findings": persistent_findings, "count": len(persistent_findings)})
            except ValueError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))
        if len(parts) == 5 and parts[:2] == ["api", "targets"] and parts[3:] == ["diff", "latest"]:
            target = STORE.get_target(parts[2])
            if not target:
                return self._error(HTTPStatus.NOT_FOUND, "Hedef bulunamadı.")
            pair = STORE.latest_completed_pair(target["id"])
            if pair is None:
                return self._error(HTTPStatus.BAD_REQUEST, "Karşılaştırma için aynı hedefte en az iki tamamlanmış tarama gerekli.")
            include_details = parse_qs(parsed.query).get("details", ["1"])[0].strip().lower() not in {"0", "false", "no"}
            try:
                payload = SCAN_DIFF.compare_scans(pair[0], pair[1], include_details=include_details)
            except ValueError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))
            payload["pair"] = {"previous_scan_id": pair[0], "current_scan_id": pair[1], "target_id": target["id"]}
            payload["links"] = {
                "json": f"/api/scans/diff/{pair[0]}/{pair[1]}",
                "html": f"/api/scans/diff/{pair[0]}/{pair[1]}/report.html",
                "csv": f"/api/scans/diff/{pair[0]}/{pair[1]}/report.csv",
            }
            return self._json(payload)

        if len(parts) == 4 and parts[:2] == ["api", "targets"] and parts[3] == "trend":
            trend = STORE.target_trend(parts[2])
            if not trend:
                return self._error(HTTPStatus.NOT_FOUND, "Hedef bulunamadı.")
            return self._json(trend)

        if len(parts) >= 3 and parts[:2] == ["api", "engagements"]:
            engagement = STORE.get_engagement(parts[2])
            if not engagement:
                return self._error(HTTPStatus.NOT_FOUND, "Manuel denetim bulunamadı.")
            if len(parts) == 3:
                return self._json(engagement)
            if len(parts) == 4 and parts[3] == "report.json":
                return self._json(engagement, disposition=f'attachment; filename="sniper-{engagement["id"]}.json"')
            if len(parts) == 4 and parts[3] == "report.html":
                return self._engagement_html_report(engagement, download=download_requested)
            if len(parts) == 4 and parts[3] == "report.csv":
                return self._engagement_csv_report(engagement)
            if len(parts) == 4 and parts[3] == "report.sarif":
                return self._engagement_sarif_report(engagement)
            if len(parts) == 4 and parts[3] == "provenance":
                try:
                    finding_id = parse_qs(parsed.query).get("finding_id", [None])[0]
                    return self._json(build_engagement_provenance(engagement, finding_id=finding_id))
                except ValueError as exc:
                    return self._error(HTTPStatus.BAD_REQUEST, _sanitize_error_message(str(exc), "Geçersiz kanıt soykütüğü isteği."))
            if len(parts) == 4 and parts[3] == "compliance-matrix":
                from compliance_crosswalk import build_compliance_crosswalk
                audits = STORE.list_project_audits(limit=1)
                latest_audit = STORE.get_project_audit(audits[0]["id"]) if audits else None
                return self._json(build_compliance_crosswalk(engagement=engagement, project_audit=latest_audit))

        if len(parts) == 3 and parts[:2] == ["api", "lab-runs"]:
            lab_run = STORE.get_lab_run(parts[2])
            if not lab_run:
                return self._error(HTTPStatus.NOT_FOUND, "Laboratuvar kaydı bulunamadı.")
            return self._json(lab_run)

        if parts[:2] == ["api", "ai-triage"]:
            return self._ai_triage_get(parts, parse_qs(parsed.query))
        if parts[:2] == ["api", "finding-tracking"]:
            return self._finding_tracking_get(parts, parse_qs(parsed.query))

        if len(parts) >= 3 and parts[:2] == ["api", "project-audits"]:
            audit = STORE.get_project_audit(parts[2])
            if not audit:
                return self._error(HTTPStatus.NOT_FOUND, "Proje analizi bulunamadı.")
            if len(parts) == 3:
                return self._json(audit)
            if len(parts) == 4 and parts[3] == "autofix-groups":
                import fix_verification
                return self._json({"audit_id": audit["id"], "groups": fix_verification.fix_groups(audit)})
            if len(parts) == 6 and parts[3] == "findings" and parts[5] == "autofix.patch":
                import fix_verification
                if not parts[4].isdigit() or str(int(parts[4])) != parts[4]:
                    return self._error(HTTPStatus.BAD_REQUEST, "Bulgu sırası negatif olmayan bir tamsayı olmalı.")
                try:
                    body = fix_verification.patch_for_finding(audit, int(parts[4])).encode("utf-8")
                except fix_verification.AutofixError as exc:
                    return self._error(HTTPStatus.BAD_REQUEST, str(exc))
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "text/x-diff; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Content-Disposition", f'attachment; filename="sniper-fix-{audit["id"]}-{int(parts[4])}.patch"')
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)
                return
            if len(parts) == 4 and parts[3] == "report.sarif":
                from project_audit_diff import render_project_audit_sarif
                return self._json(
                    render_project_audit_sarif(audit),
                    disposition=f'attachment; filename="sniper-project-{audit["id"]}.sarif"',
                )
            if len(parts) == 4 and parts[3] == "executive-summary":
                from project_executive_summary import build_project_executive_summary
                return self._json(build_project_executive_summary(STORE, audit))
            if len(parts) == 4 and parts[3] in ("report.html", "executive-summary.html"):
                from project_audit_diff import render_project_audit_html
                from project_executive_summary import build_project_executive_summary, render_page_html, render_section_html
                executive = build_project_executive_summary(STORE, audit)
                if parts[3] == "executive-summary.html":
                    document = _localized_report(render_page_html(executive), self)
                else:
                    try:
                        dependency_rows = STORE.dependency_findings_for_project(str(audit.get("project_path") or ""))
                    except Exception:  # noqa: BLE001 — eski şema: rapor bağımlılık tablosu olmadan üretilir
                        dependency_rows = []
                    try:  # 25. tur: AI/ajan önerileri ayrı, etiketli bölüm
                        ai_rows = ai_triage.list_suggestions(STORE, project_path=str(audit.get("project_path") or ""),
                                                             limit=200) if audit.get("project_path") else []
                    except Exception:  # noqa: BLE001 — öneri tablosu okunamazsa rapor onsuz üretilir
                        ai_rows = []
                    document = _localized_report(
                        render_project_audit_html(audit, render_section_html(executive), dependency_rows, ai_rows), self)
                kind = "executive" if parts[3] == "executive-summary.html" else "project"
                if self._wants_pdf():
                    return self._pdf_report(document, f"sniper-{kind}-{audit['id']}.html")
                if self._report_format != "html":
                    return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz rapor biçimi (html ya da pdf).")
                body = document.encode("utf-8")
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                if download_requested:
                    self.send_header("Content-Disposition", f'attachment; filename="sniper-{kind}-{audit["id"]}.html"')
                # Önceden var olmayan _security_headers() çağrılıyordu (rota 500/bağlantı kopması veriyordu).
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Content-Security-Policy", ui_assets.report_csp(body.decode("utf-8")))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)
                return
            if len(parts) == 4 and parts[3] == "threat-model":
                return self._project_threat_model(audit)
            if len(parts) == 4 and parts[3] == "compliance-matrix":
                from compliance_crosswalk import build_compliance_crosswalk
                return self._json(build_compliance_crosswalk(project_audit=audit))

        if len(parts) == 5 and parts[:2] == ["api", "dependency-sboms"] and parts[3] == "delta":
            try:
                delta = STORE.compare_dependency_sboms(parts[2], parts[4])
            except ValueError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))
            if delta is None:
                return self._error(HTTPStatus.NOT_FOUND, "Bir veya her iki SBOM kaydı bulunamadı veya farklı proje.")
            return self._json(delta)

        if len(parts) == 3 and parts[:2] == ["api", "dependency-sboms"]:
            sbom = STORE.get_dependency_sbom(parts[2])
            if not sbom:
                return self._error(HTTPStatus.NOT_FOUND, "SBOM kaydı bulunamadı.")
            # 20. tur: ?format=cyclonedx (varsayılan) | spdx (SPDX 2.3 JSON); zaman damgası kayıt anından eklenir
            # (kayıtlı belge deterministik kalır, aynı içerik yeniden kaydedilmez).
            return self._sbom_download(sbom["document"], parse_qs(parsed.query), f"sniper-{sbom['id']}",
                                       str(sbom.get("created_at") or ""), sbom["id"])

        if path == "/api" or path.startswith("/api/"):
            return self._error(HTTPStatus.NOT_FOUND, "API uç noktası bulunamadı.")

        return self._static(path)

    def do_HEAD(self) -> None:
        self.do_GET()

    def do_POST(self) -> None:
        if not self._request_preflight() or not self._rate_limit():
            return
        if not self._origin_allowed():
            return self._error(HTTPStatus.FORBIDDEN, "İstek kaynağı reddedildi.")
        if self.headers.get_content_type() != "application/json":
            return self._error(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "Content-Type application/json olmalı.")
        try:
            payload = self._read_json()
        except ValueError as exc:
            return self._error(HTTPStatus.BAD_REQUEST, str(exc))
        path = urlsplit(self.path).path
        if path.startswith("/api/auth/"):
            return auth_routes.handle_post(self, path, payload)
        if path == "/api/jobs" or path.startswith("/api/jobs/"):
            return self._jobs_post(path, payload)
        if path.startswith("/api/mcp-scan-requests/"):
            return self._mcp_scan_requests_post(path, payload)
        if path == "/api/runtime-proofs/asan-selftest":
            return self._asan_selftest_post(payload)
        if path.startswith("/api/findings/unified/network/"):
            finding_id = path.rsplit("/", 1)[-1]
            if set(payload) != {"confirm", "status", "assignee_name", "due_date"} or payload.get("confirm") is not True:
                return self._error(HTTPStatus.BAD_REQUEST, "Ağ bulgusu güncelleme alanları geçersiz.")
            try:
                return self._json(STORE.update_network_finding(
                    finding_id, status=payload.get("status"), assignee_name=payload.get("assignee_name"),
                    due_date=payload.get("due_date")))
            except ValueError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))
        if path == "/api/bulk-scans" or path.startswith("/api/bulk-scans/"):  # sabit metin: do_GET/do_POST yalıtılmış testlerde de çalışır
            return self._bulk_post(path, payload)
        if path == "/api/taint-rules" or path.startswith("/api/taint-rules/"):
            return self._taint_rules_post(path, payload)
        autofix_parts = [part for part in path.split("/") if part]
        if len(autofix_parts) == 6 and autofix_parts[:2] == ["api", "project-audits"] and autofix_parts[3] == "findings" \
                and autofix_parts[5] == "autofix":
            return self._autofix_post(autofix_parts[2], autofix_parts[4], payload)
        # Düzeltme doğrulama (geçici kopyada; projeye yazılmaz): tek bulgu ve toplu.
        if len(autofix_parts) == 7 and autofix_parts[:2] == ["api", "project-audits"] and autofix_parts[3] == "findings" \
                and autofix_parts[5:] == ["autofix", "verify"]:
            return self._autofix_verify_post(autofix_parts[2], autofix_parts[4], payload)
        if len(autofix_parts) == 7 and autofix_parts[:2] == ["api", "project-audits"] \
                and autofix_parts[3] == "findings" and autofix_parts[5:] == ["runtime-proof", "open-redirect"]:
            if set(payload) != {"target", "path", "parameter", "confirm_local"}:
                return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz çalışma zamanı kanıtı alanları.")
            if not autofix_parts[4].isdigit() or str(int(autofix_parts[4])) != autofix_parts[4]:
                return self._error(HTTPStatus.BAD_REQUEST, "Bulgu sırası negatif olmayan tam sayı olmalı.")
            try:
                result = runtime_proof.verify_open_redirect(
                    STORE, autofix_parts[2], int(autofix_parts[4]), target=payload.get("target"),
                    path=payload.get("path"), parameter=payload.get("parameter"),
                    confirm_local=payload.get("confirm_local"),
                )
                return self._json(result)
            except runtime_proof.RuntimeProofUnavailable as exc:
                return self._error(HTTPStatus.BAD_GATEWAY, str(exc))
            except (runtime_proof.RuntimeProofError, ValueError) as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))
        if len(autofix_parts) == 7 and autofix_parts[:2] == ["api", "project-audits"] \
                and autofix_parts[3] == "findings" and autofix_parts[5:] == ["runtime-proof", "reflected-html"]:
            if set(payload) != {"target", "path", "parameter", "confirm_local"}:
                return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz çalışma zamanı kanıtı alanları.")
            if not autofix_parts[4].isdigit() or str(int(autofix_parts[4])) != autofix_parts[4]:
                return self._error(HTTPStatus.BAD_REQUEST, "Bulgu sırası negatif olmayan tam sayı olmalı.")
            try:
                result = runtime_proof.verify_reflected_html(
                    STORE, autofix_parts[2], int(autofix_parts[4]), target=payload.get("target"),
                    path=payload.get("path"), parameter=payload.get("parameter"),
                    confirm_local=payload.get("confirm_local"),
                )
                return self._json(result)
            except runtime_proof.RuntimeProofUnavailable as exc:
                return self._error(HTTPStatus.BAD_GATEWAY, str(exc))
            except (runtime_proof.RuntimeProofError, ValueError) as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))
        if len(autofix_parts) == 7 and autofix_parts[:2] == ["api", "project-audits"] \
                and autofix_parts[3] == "findings" and autofix_parts[5:] == ["runtime-proof", "asan-binary"]:
            return self._asan_project_proof_post(autofix_parts[2], autofix_parts[4], payload)
        if len(autofix_parts) == 7 and autofix_parts[:2] == ["api", "project-audits"] \
                and autofix_parts[3] == "findings" and autofix_parts[5:] == ["runtime-proof", "asan-source"]:
            return self._asan_project_source_proof_post(autofix_parts[2], autofix_parts[4], payload)
        if len(autofix_parts) == 7 and autofix_parts[:2] == ["api", "project-audits"] \
                and autofix_parts[3] == "findings" \
                and autofix_parts[5:] == ["runtime-proof", "asan-compile-database"]:
            return self._asan_project_compile_database_proof_post(autofix_parts[2], autofix_parts[4], payload)
        if len(autofix_parts) == 7 and autofix_parts[:2] == ["api", "project-audits"] \
                and autofix_parts[3] == "findings" and autofix_parts[5:] == ["runtime-proof", "dast"]:
            return self._dast_runtime_proof_post(autofix_parts[2], autofix_parts[4], payload)
        if len(autofix_parts) == 5 and autofix_parts[:2] == ["api", "project-audits"] and autofix_parts[3:] == ["autofix", "bulk"]:
            return self._autofix_bulk_post(autofix_parts[2], payload)
        return self._dispatch_post(payload)

    def _dispatch_post(self, payload: dict) -> None:
        """Doğrulanmış JSON gövdeli POST rotaları; iş kuyruğu (job_queue) da aynı yolu kullanır.

        İsteğe bağlı ``scope`` alanı (tarama kapsamı: atlanan dizin/dosyaları dahil etme, sınırlar) proje
        yolu alan rotalarda istek boyunca etkinleşir ve rotaya iletilmeden gövdeden çıkarılır."""
        if isinstance(payload.get("project_path"), str) and not getattr(self, "_scan_scope_active", False):
            try:
                scope = scan_scope.parse_scope(payload["scope"]) if "scope" in payload else scan_scope.load_default()
            except scan_scope.ScopeError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))
            inner = {key: value for key, value in payload.items() if key != "scope"}
            self._scan_scope_active = True
            try:
                with scan_scope.scan_scope(scope):
                    return self._dispatch_post(inner)
            finally:
                self._scan_scope_active = False
        path = urlsplit(self.path).path
        if path == "/api/targets":
            try:
                target = normalize_target(str(payload.get("url", "")))
                # Resolve now so unsafe address ranges are rejected before a record is created.
                from scanner import resolve_public_ips
                resolve_public_ips(target.hostname, target.port)
                record = STORE.create_target(target)
                return self._json(record, status=HTTPStatus.CREATED)
            except TargetRejected as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))

        parts = [part for part in path.split("/") if part]
        if path == "/api/nuclei/authorized-origin-scans":
            if set(payload) != {"target_origin", "confirm_authorized"}:
                return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz doğrudan Nuclei tarama alanı.")
            if payload.get("confirm_authorized") is not True:
                return self._error(HTTPStatus.FORBIDDEN, "Bu çalıştırma için açık insan yetki onayı gerekli.")
            origin = payload.get("target_origin")
            if not isinstance(origin, str) or not origin.strip() or len(origin) > 2048:
                return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz HTTP(S) origin.")
            try:
                result = get_broad_nuclei_jobs().start_authorized_origin(origin, True)
            except NucleiBroadBusy:
                return self._error(HTTPStatus.CONFLICT, "Bir Nuclei taraması zaten çalışıyor.")
            except (NucleiBroadUnavailable, OSError, RuntimeError):
                return self._error(HTTPStatus.SERVICE_UNAVAILABLE, "Nuclei servisi kullanılamıyor.")
            except (ValueError, PermissionError):
                return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz doğrudan Nuclei tarama isteği.")
            receipt = _direct_target_authorization_receipt()
            STORE.log(
                "nuclei.direct_authorized.started",
                result["target_sha256"],
                {"profile": result["profile"], "job_id": result["job_id"], "authorization_receipt": receipt},
            )
            return self._json({**result, "authorization_receipt": receipt}, status=HTTPStatus.ACCEPTED)

        if path == "/api/nuclei/http-scans":
            allowed = {"target_id", "engagement_id", "confirm_authorized", "template_ids", "include_excluded"}
            if not set(payload).issubset(allowed):
                return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz Nuclei tarama alanı.")
            target_id = payload.get("target_id")
            engagement_id = payload.get("engagement_id")
            template_ids = payload.get("template_ids")
            include_excluded = payload.get("include_excluded", False)
            if not isinstance(target_id, str) or not target_id or len(target_id) > 80:
                return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz hedef kimliği.")
            if not isinstance(engagement_id, str) or not engagement_id or len(engagement_id) > 80:
                return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz denetim kimliği.")
            if payload.get("confirm_authorized") is not True:
                return self._error(HTTPStatus.FORBIDDEN, "Açık tarama yetkisi onayı gerekli.")
            if template_ids is not None and (not isinstance(template_ids, list) or len(template_ids) > 1000 or not all(isinstance(item, str) for item in template_ids)):
                return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz Nuclei şablon kimlikleri.")
            if not isinstance(include_excluded, bool):
                return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz hariç tutulan şablon seçimi.")
            target = STORE.get_target(target_id)
            if target is None:
                return self._error(HTTPStatus.NOT_FOUND, "Hedef bulunamadı.")
            engagement = STORE.get_engagement(engagement_id)
            if engagement is None:
                return self._error(HTTPStatus.NOT_FOUND, "Denetim bulunamadı.")
            if (engagement.get("status") != "active" or engagement.get("target_id") != target_id
                    or not isinstance(engagement.get("authorization_ref"), str)
                    or not engagement["authorization_ref"].strip()
                    or not isinstance(engagement.get("scope_notes"), str)
                    or not engagement["scope_notes"].strip()):
                return self._error(HTTPStatus.FORBIDDEN, "Etkin, kapsamı ve yetkisi kayıtlı denetim gerekli.")
            try:
                result = get_broad_nuclei_jobs().start(
                    target, engagement, True, template_ids=template_ids,
                    include_excluded=include_excluded,
                )
                return self._json(result, status=HTTPStatus.ACCEPTED)
            except NucleiBroadBusy:
                return self._error(HTTPStatus.CONFLICT, "Bir Nuclei taraması zaten çalışıyor.")
            except (NucleiBroadUnavailable, OSError, RuntimeError):
                return self._error(HTTPStatus.SERVICE_UNAVAILABLE, "Nuclei servisi kullanılamıyor.")
            except (ValueError, PermissionError):
                return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz veya kapsam dışı tarama isteği.")

        if len(parts) == 5 and parts[:3] == ["api", "nuclei", "http-scans"] and parts[4] == "cancel":
            job_id = parts[3]
            if len(job_id) != 16 or any(ch not in "0123456789abcdef" for ch in job_id):
                return self._error(HTTPStatus.NOT_FOUND, "Nuclei işi bulunamadı.")
            if set(payload) != {"confirm_cancel"} or payload.get("confirm_cancel") is not True:
                return self._error(HTTPStatus.FORBIDDEN, "İptal onayı gerekli.")
            try:
                return self._json(get_broad_nuclei_jobs().cancel(job_id))
            except FileNotFoundError:
                return self._error(HTTPStatus.NOT_FOUND, "Nuclei işi bulunamadı.")
            except (NucleiBroadUnavailable, OSError, RuntimeError, ValueError):
                return self._error(HTTPStatus.SERVICE_UNAVAILABLE, "Nuclei servisi kullanılamıyor.")

        if path == "/api/scans":
            target_id = str(payload.get("target_id", ""))
            target_record = STORE.get_target(target_id)
            if not target_record:
                return self._error(HTTPStatus.NOT_FOUND, "Hedef bulunamadı.")
            scan = None
            submit_success = False
            try:
                with SCAN_LOCK:
                    if target_id in ACTIVE_TARGETS:
                        return self._error(HTTPStatus.CONFLICT, "Bu hedef için zaten bir tarama çalışıyor.")
                    ACTIVE_TARGETS.add(target_id)
                scan = STORE.create_scan(target_id)
                EXECUTOR.submit(scan_worker, scan["id"], target_record)
                submit_success = True
            except Exception:
                if scan is not None:
                    try:
                        STORE.fail_scan(scan["id"], "Gönderim başarısız")
                    except Exception:
                        pass
                with SCAN_LOCK:
                    ACTIVE_TARGETS.discard(target_id)
                return self._error(HTTPStatus.SERVICE_UNAVAILABLE, "Tarama başlatılamadı.")
            try:
                return self._json(scan, status=HTTPStatus.ACCEPTED)
            except (BrokenPipeError, ConnectionResetError, OSError):
                # Response write failed after successful submit; scan is queued.
                # Do not send a second response and do not let control fall through
                # to other route handlers. Return silently to preserve queued state.
                return

        if len(parts) == 6 and parts[0] == "api" and parts[1] == "project-audits" and parts[3] == "findings" and parts[5] == "triage":
            audit_id = parts[2]
            try:
                finding_index = int(parts[4])
                if str(finding_index) != parts[4] or finding_index < 0:
                    raise ValueError("finding_index negatif olmayan bir tamsayı olmalı")
            except ValueError:
                return self._error(HTTPStatus.BAD_REQUEST, "finding_index negatif olmayan bir tamsayı olmalı")

            audit = STORE.get_project_audit(audit_id)
            if not audit:
                return self._error(HTTPStatus.NOT_FOUND, "Audit bulunamadı.")

            try:
                disposition = clean_text(payload, "disposition", maximum=32, required=True)
                if disposition not in {"needs_review", "false_positive", "confirmed", "accepted_risk"}:
                    raise ValueError(f"disposition şunlardan biri olmalı: ['accepted_risk', 'confirmed', 'false_positive', 'needs_review']")
                # Explicitly handle note validation per contract:
                # - If 'note' key is absent -> treat as empty string (required=False)
                # - If 'note' key is present but value is None/int/list/other non-string -> reject
                # - If 'note' is string but contains NUL -> reject
                # - If raw length > 2000 -> reject (even if trimmed it would be <=2000)
                if "note" in payload:
                    raw_note = payload["note"]
                    if not isinstance(raw_note, str):
                        raise ValueError("note bir metin olmalı")
                    if "\x00" in raw_note:
                        raise ValueError("note NUL karakteri içermemeli")
                    if len(raw_note) > 2000:
                        raise ValueError("note en fazla 2000 karakter olabilir")
                    note = clean_text(payload, 'note', maximum=2000, required=False)
                else:
                    note = ""
            except ValueError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))

            try:
                result = STORE.update_project_audit_finding_triage(
                    audit_id=audit_id,
                    finding_index=finding_index,
                    disposition=disposition,
                    note=note,
                )
                return self._json(result, status=HTTPStatus.OK)
            except ValueError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))
            except TypeError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))

        if path == "/api/project-audits":
            try:
                project_path = clean_text(payload, "project_path", maximum=1024, required=True)
                base_audit_id = clean_text(payload, "base_audit_id", maximum=80, required=False)
                base_audit = STORE.get_project_audit(base_audit_id) if base_audit_id else None
                if base_audit_id and not base_audit:
                    return self._error(HTTPStatus.NOT_FOUND, "Temel proje analizi bulunamadı.")
                active_scope = scan_scope.current()
                if active_scope.changed_only and active_scope.base_ref.startswith("prj_"):
                    # Yalnız değişenler, taban olarak kayıtlı analiz: tam analiz + kayıtlı bulgularla karşılaştırma.
                    compared_audit = STORE.get_project_audit(active_scope.base_ref)
                    if not compared_audit:
                        return self._error(HTTPStatus.NOT_FOUND, "Karşılaştırılacak proje analizi bulunamadı.")
                    import changed_scan

                    result = changed_scan.analyze_against_audit(project_path, compared_audit, scope=active_scope)
                else:
                    result = analyze_project(project_path)
                if base_audit:
                    # Ek tarama (ör. yalnız atlananlar) aynı projenin önceki analizine bağlanır.
                    if base_audit.get("project_path") != result["project_path"]:
                        return self._error(HTTPStatus.BAD_REQUEST, "Temel analiz başka bir projeye ait.")
                    result["base_audit_id"] = base_audit_id
                project_progress.report("saving", force=True)
                saved = STORE.create_project_audit(result)
                try:
                    notifications.on_project_audit_created(STORE, saved)
                except ops_files.OpsStoreError:
                    pass
                except Exception:  # bildirim hatası analizi geçersiz kılmaz
                    traceback.print_exc()
                return self._json(saved, status=HTTPStatus.CREATED)
            except (ProjectRejected, ValueError) as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))

        if path == "/api/container-images":
            # 18. tur: Docker daemon'suz imaj / rootfs işletim sistemi paket açığı taraması (ağ yok).
            try:
                if not set(payload) <= {"image_path", "dockerfile_path", "ignore_unfixed"}:
                    return self._error(HTTPStatus.BAD_REQUEST, "Yalnız image_path, dockerfile_path ve ignore_unfixed alanları kullanılabilir.")
                image_path = clean_text(payload, "image_path", maximum=1024, required=True)
                dockerfile_path = clean_text(payload, "dockerfile_path", maximum=1024) or None
                ignore_unfixed = payload.get("ignore_unfixed", False)
                if not isinstance(ignore_unfixed, bool):
                    return self._error(HTTPStatus.BAD_REQUEST, "ignore_unfixed true ya da false olmalı.")
                result = container_scan.scan_image(image_path, ignore_unfixed=ignore_unfixed,
                                                   dockerfile_path=dockerfile_path)
                saved = STORE.create_project_audit(result)
                try:
                    notifications.on_project_audit_created(STORE, saved)
                except ops_files.OpsStoreError:
                    pass
                except Exception:  # bildirim hatası taramayı geçersiz kılmaz
                    traceback.print_exc()
                return self._json(saved, status=HTTPStatus.CREATED)
            except (container_scan.ContainerScanError, ValueError) as exc:
                # 22. tur QA: eksik image_path (clean_text ValueError) 500 yerine 400 döner.
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))
            except (OSError, MemoryError):
                return self._error(HTTPStatus.BAD_REQUEST, "İmaj okunamadı (izin, bozuk arşiv ya da bellek sınırı).")

        if path == "/api/dependency-security/sbom-scan":
            # 20. tur: dış SBOM dosyasını (CycloneDX JSON/XML, SPDX JSON/tag-value) çevrimdışı OSV ile tara.
            try:
                if not set(payload) <= {"sbom_path", "confirm"}:
                    return self._error(HTTPStatus.BAD_REQUEST, "Yalnız sbom_path ve confirm alanları kullanılabilir.")
                if payload.get("confirm") is not True:
                    return self._error(HTTPStatus.BAD_REQUEST, "SBOM taraması için onay (confirm: true) gerekli.")
                sbom_path = clean_text(payload, "sbom_path", maximum=1024, required=True)
                result = sbom_scan.scan_sbom(sbom_path)
                saved = STORE.create_project_audit(result)
                try:
                    notifications.on_project_audit_created(STORE, saved)
                except ops_files.OpsStoreError:
                    pass
                except Exception:  # bildirim hatası taramayı geçersiz kılmaz
                    traceback.print_exc()
                return self._json(saved, status=HTTPStatus.CREATED)
            except (sbom_scan.SbomScanError, ValueError) as exc:
                # 22. tur QA: eksik sbom_path (clean_text ValueError) 500 yerine 400 döner.
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))
            except (OSError, MemoryError):
                return self._error(HTTPStatus.BAD_REQUEST, "SBOM okunamadı (izin ya da bellek sınırı).")

        if path == "/api/dependency-security/sbom":
            try:
                project_path = clean_text(payload, "project_path", maximum=1024, required=True)
                document = generate_cyclonedx_sbom(project_path)
                resolved_path = str(Path(os.path.expandvars(os.path.expanduser(project_path))).resolve(strict=True))
                return self._json(STORE.save_dependency_sbom(resolved_path, document), status=HTTPStatus.CREATED)
            except OSError:
                return self._error(HTTPStatus.BAD_REQUEST, "Proje dosyaları okunamadı (izin veya erişim hatası).")
            except (DependencySecurityError, RuntimeError, ValueError) as exc:
                return self._error(HTTPStatus.BAD_REQUEST, _sanitize_error_message(str(exc), "SBOM üretilemedi."))

        if path == "/api/tool-reports/sarif/summary":
            try:
                sarif = payload.get("sarif")
                if not isinstance(sarif, dict):
                    raise ValueError("sarif anahtarı eksik veya geçersiz.")
                result = parse_sarif_summary(sarif)
                return self._json(result)
            except ValueError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))

        if path == "/api/tool-reports/schemathesis-junit/summary":
            try:
                if set(payload) != {"report"}:
                    raise ValueError("Geçersiz Schemathesis JUnit XML.")
                result = parse_schemathesis_junit_summary(payload["report"])
                return self._json(result)
            except ValueError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))

        if path == "/api/tool-runs/schemathesis-loopback":
            if set(payload) != {"confirm_local", "target_url", "schema"} or payload.get("confirm_local") is not True:
                return self._error(HTTPStatus.BAD_REQUEST, "Açık onaylı loopback onayı ve şema gerekli.")
            try:
                return self._json(run_schemathesis_loopback(payload["target_url"], payload["schema"]))
            except ValueError:
                return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz onaylı loopback hedefi veya şeması.")
            except (SchemathesisUnavailable, SchemathesisBusy):
                return self._error(HTTPStatus.SERVICE_UNAVAILABLE, "Onaylı loopback çalıştırıcısı kullanılamıyor veya meşgul.")
            except SchemathesisExecutionError:
                return self._error(HTTPStatus.BAD_GATEWAY, "Sınırlı Schemathesis çalıştırması başarısız oldu.")

        if path == "/api/tool-runs/schemathesis-local":
            if set(payload) != {"confirm_local", "schema"} or payload.get("confirm_local") is not True:
                return self._error(HTTPStatus.BAD_REQUEST, "Açık sentetik yerel onay ve şema gerekli.")
            try:
                return self._json(run_schemathesis_synthetic_local(payload["schema"]))
            except ValueError:
                return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz sentetik OpenAPI şeması.")
            except (SchemathesisUnavailable, SchemathesisBusy):
                return self._error(HTTPStatus.SERVICE_UNAVAILABLE, "Schemathesis yerel fikstürü kullanılamıyor veya meşgul.")
            except SchemathesisExecutionError:
                return self._error(HTTPStatus.BAD_GATEWAY, "Schemathesis sentetik çalıştırması başarısız oldu.")

        if path == "/api/tool-reports/playwright-json/summary":
            try:
                if set(payload) != {"report"}:
                    raise ValueError("Geçersiz Playwright JSON isteği")
                return self._json(parse_playwright_json_summary(payload["report"]))
            except ValueError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))

        if path == "/api/tool-reports/k6-summary-json/summary":
            try:
                report = payload.get("report")
                if not isinstance(report, dict):
                    raise ValueError("report anahtarı eksik veya geçersiz.")
                return self._json(parse_k6_handle_summary_json(report))
            except ValueError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))

        if path == "/api/tool-reports/k6-machine-summary-v1/summary":
            try:
                if set(payload) != {"report"} or not isinstance(payload["report"], dict):
                    raise ValueError("Geçersiz k6 v1 rapor isteği")
                return self._json(parse_k6_machine_summary_v1(payload["report"]))
            except ValueError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))

        if path in ("/api/tools/playwright/local-fixture", "/api/tool-runs/playwright-local-fixture"):
            if "?" in self.path:
                return self._error(HTTPStatus.BAD_REQUEST, "Sorgu veya alternatif tarayıcı fikstür yoluna izin verilmiyor.")
            if not isinstance(payload, dict) or set(payload) != {"confirm_local"} or payload.get("confirm_local") is not True:
                return self._error(HTTPStatus.BAD_REQUEST, "Açık sabit yerel fikstür onayı gerekli.")
            try:
                return self._json(run_local_playwright_fixture())
            except (PlaywrightFixtureUnavailable, PlaywrightFixtureBusy):
                return self._error(HTTPStatus.SERVICE_UNAVAILABLE, "Yerel tarayıcı fikstürü kullanılamıyor veya meşgul.")
            except PlaywrightFixtureFailed:
                return self._error(HTTPStatus.BAD_GATEWAY, "Sınırlı yerel tarayıcı fikstürü başarısız oldu.")

        if path in ("/api/tools/k6/loopback", "/api/tool-runs/k6-loopback-smoke", "/api/tool-runs/k6-loopback"):
            if not isinstance(payload, dict) or set(payload) != {"confirm_local", "target_url", "path"} or payload.get("confirm_local") is not True:
                return self._error(HTTPStatus.BAD_REQUEST, "Açık onaylı loopback onayı, hedef ve yol gerekli.")
            try:
                return self._json(run_k6_loopback(payload["target_url"], payload["path"]))
            except ValueError:
                return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz onaylı loopback hedefi veya yolu.")
            except (K6Unavailable, K6Busy):
                return self._error(HTTPStatus.SERVICE_UNAVAILABLE, "Onaylı loopback k6 çalıştırıcısı kullanılamıyor veya meşgul.")
            except K6ExecutionError:
                return self._error(HTTPStatus.BAD_GATEWAY, "Sınırlı k6 duman testi başarısız oldu.")

        if path == "/api/tool-reports/siem-ecs-ndjson/summary":
            try:
                if set(payload) != {"report"}:
                    raise ValueError("Geçersiz ECS JSONL kanıtı.")
                return self._json(parse_siem_ecs_ndjson_summary(payload["report"]))
            except ValueError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))

        if path == "/api/tool-reports/npm-audit/summary":
            try:
                audit = payload.get("audit")
                if not isinstance(audit, dict):
                    raise ValueError("audit anahtarı eksik veya geçersiz.")
                result = parse_npm_audit_v2_summary(audit)
                return self._json(result)
            except ValueError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))

        if path == "/api/tool-reports/zap/summary":
            try:
                zap_report = payload.get("report")
                if not isinstance(zap_report, dict):
                    raise ValueError("report anahtarı eksik veya geçersiz.")
                result = parse_zap_traditional_json_summary(zap_report)
                return self._json(result)
            except ValueError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))

        if path == "/api/tool-runs/zap-self-passive":
            try:
                if not isinstance(payload, dict) or payload.get("confirm_local") is not True:
                    raise ValueError("confirm_local tam olarak true olmalı")
                if set(payload) != {"confirm_local"}:
                    raise ValueError("Özel ZAP hedefi veya seçeneği kabul edilmez")
                return self._json(run_zap_self_passive(HOST, PORT))
            except ValueError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))
            except (ZapUnavailable, ZapBusy):
                return self._error(HTTPStatus.SERVICE_UNAVAILABLE, "ZAP çalışma zamanı kullanılamıyor veya meşgul.")
            except ZapExecutionError:
                return self._error(HTTPStatus.BAD_GATEWAY, "ZAP çalıştırması başarısız oldu.")

        if path == "/api/tool-runs/zap-authorized":
            if not isinstance(payload, dict) or set(payload) != {"target", "confirm_authorized"}:
                return self._error(HTTPStatus.BAD_REQUEST, "Yetkili ZAP isteği yalnız hedef ve onay alanlarını kabul eder.")
            if payload.get("confirm_authorized") is not True:
                return self._error(HTTPStatus.FORBIDDEN, "Bu hedefi tarama yetkisine sahip olduğunuzu onaylamalısınız.")
            try:
                target_url = normalize_authorized_target(payload.get("target"))
            except ValueError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))
            actor = request_context.current_actor() or {
                "id": "local-admin", "username": "yerel", "role": "admin",
            }
            receipt = zap_authorization_receipt(target_url, actor)
            audit_details = {
                "actor": receipt["actor"],
                "confirmed_at": receipt["confirmed_at"],
                "consent_version": receipt["consent_version"],
                "target": receipt["target"],
                "target_sha256": receipt["target_sha256"],
            }
            try:
                # The durable start receipt must exist before any ZAP process can be launched.
                STORE.log("zap_authorized_run.started", receipt["run_id"], audit_details)
                result = run_zap_authorized(target_url)
                STORE.log(
                    "zap_authorized_run.completed",
                    receipt["run_id"],
                    {
                        "target_sha256": receipt["target_sha256"],
                        "report_sha256": result.get("report_sha256"),
                        "site_count": result.get("site_count"),
                        "alert_type_count": result.get("alert_type_count"),
                        "instance_count": result.get("instance_count"),
                        "elapsed_seconds": result.get("elapsed_seconds"),
                    },
                )
                return self._json({**result, "receipt": receipt})
            except ZapBusy:
                STORE.log("zap_authorized_run.failed", receipt["run_id"], {
                    "target_sha256": receipt["target_sha256"], "reason": "busy",
                })
                return self._error(HTTPStatus.CONFLICT, "Bir ZAP taraması zaten çalışıyor.")
            except ZapUnavailable:
                readiness = zap_authorized_runtime_readiness()
                STORE.log("zap_authorized_run.failed", receipt["run_id"], {
                    "target_sha256": receipt["target_sha256"], "reason": "runtime_unavailable",
                    "missing": readiness.get("missing", []),
                })
                return self._json({
                    "error": "ZAP çalışma zamanı kullanılamıyor.",
                    "readiness": readiness,
                }, status=HTTPStatus.SERVICE_UNAVAILABLE)
            except ZapExecutionError:
                STORE.log("zap_authorized_run.failed", receipt["run_id"], {
                    "target_sha256": receipt["target_sha256"], "reason": "execution_failed",
                })
                return self._error(HTTPStatus.BAD_GATEWAY, "Yetkili ZAP taraması başarısız oldu.")
            except ValueError as exc:
                STORE.log("zap_authorized_run.failed", receipt["run_id"], {
                    "target_sha256": receipt["target_sha256"], "reason": "target_rejected",
                })
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))

        if path == "/api/tool-runs/zap-target-active":
            allowed = {"target_id", "engagement_id", "confirm_authorized", "confirm_active"}
            if set(payload) != allowed:
                return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz ZAP aktif tarama alanı.")
            target_id, engagement_id = payload.get("target_id"), payload.get("engagement_id")
            if (not isinstance(target_id, str) or not target_id or len(target_id) > 80
                    or not isinstance(engagement_id, str) or not engagement_id or len(engagement_id) > 80):
                return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz hedef veya denetim kimliği.")
            if payload.get("confirm_authorized") is not True or payload.get("confirm_active") is not True:
                return self._error(HTTPStatus.FORBIDDEN, "Açık yetki ve aktif tarama onayı gerekli.")
            target = STORE.get_target(target_id)
            engagement = STORE.get_engagement(engagement_id)
            if target is None or engagement is None:
                return self._error(HTTPStatus.NOT_FOUND, "Hedef veya denetim bulunamadı.")
            if (engagement.get("status") != "active" or engagement.get("target_id") != target_id
                    or not isinstance(engagement.get("authorization_ref"), str)
                    or not engagement["authorization_ref"].strip()
                    or not isinstance(engagement.get("scope_notes"), str)
                    or not engagement["scope_notes"].strip()
                    or not isinstance(engagement.get("out_of_scope"), str)
                    or engagement["out_of_scope"].strip()):
                return self._error(HTTPStatus.FORBIDDEN, "Etkin, kapsamı ve yetkisi kayıtlı dışlamasız denetim gerekli.")
            # Validate engagement.test_window before invoking scan
            raw_window = engagement.get("test_window")
            if not isinstance(raw_window, str) or len(raw_window) != 41:
                return self._error(HTTPStatus.FORBIDDEN, "Engagement test_window formatı geçersiz.")
            import re
            from datetime import datetime, timezone, timedelta
            window_match = re.fullmatch(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)/(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)", raw_window)
            if not window_match:
                return self._error(HTTPStatus.FORBIDDEN, "Engagement test_window formatı geçersiz.")
            try:
                start_str, end_str = window_match.groups()
                start_dt = datetime.fromisoformat(start_str.replace("Z", "+00:00"))
                end_dt = datetime.fromisoformat(end_str.replace("Z", "+00:00"))
            except Exception:
                return self._error(HTTPStatus.FORBIDDEN, "Engagement test_window formatı geçersiz.")
            if not (start_dt < end_dt):
                return self._error(HTTPStatus.FORBIDDEN, "Engagement test_window başlangıç bitişten sonra olamaz.")
            now_dt = datetime.now(timezone.utc)
            min_end = now_dt + timedelta(seconds=300)
            if not (start_dt <= now_dt):
                return self._error(HTTPStatus.FORBIDDEN, "Engagement test_window başlangıcı gelecek zaman olamaz.")
            if not (end_dt >= min_end):
                return self._error(HTTPStatus.FORBIDDEN, "Engagement test_window yeterli süre sağlamıyor.")
            duration_seconds = (end_dt - start_dt).total_seconds()
            if duration_seconds > 24 * 60 * 60:
                return self._error(HTTPStatus.FORBIDDEN, "Görev test_window 24 saatten uzun olamaz.")
            try:
                return self._json(run_zap_target_active(target))
            except ZapBusy:
                return self._error(HTTPStatus.CONFLICT, "Bir ZAP taraması zaten çalışıyor.")
            except ZapUnavailable:
                return self._error(HTTPStatus.SERVICE_UNAVAILABLE, "ZAP çalışma zamanı kullanılamıyor.")
            except ZapExecutionError:
                return self._error(HTTPStatus.BAD_GATEWAY, "ZAP çalıştırması başarısız oldu.")
            except ValueError:
                return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz veya güvensiz hedef.")

        if path == "/api/tool-runs/zap-target-spider":
            allowed = {"target_id", "engagement_id", "confirm_authorized", "confirm_crawl"}
            if set(payload) != allowed:
                return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz ZAP spider alanı.")
            target_id, engagement_id = payload.get("target_id"), payload.get("engagement_id")
            if (not isinstance(target_id, str) or not target_id or len(target_id) > 80
                    or not isinstance(engagement_id, str) or not engagement_id or len(engagement_id) > 80):
                return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz hedef veya denetim kimliği.")
            if payload.get("confirm_authorized") is not True or payload.get("confirm_crawl") is not True:
                return self._error(HTTPStatus.FORBIDDEN, "Açık yetki ve spider tarama onayı gerekli.")
            target = STORE.get_target(target_id)
            engagement = STORE.get_engagement(engagement_id)
            if target is None or engagement is None:
                return self._error(HTTPStatus.NOT_FOUND, "Hedef veya denetim bulunamadı.")
            if (engagement.get("status") != "active" or engagement.get("target_id") != target_id
                    or not isinstance(engagement.get("authorization_ref"), str)
                    or not engagement["authorization_ref"].strip()
                    or not isinstance(engagement.get("scope_notes"), str)
                    or not engagement["scope_notes"].strip()):
                return self._error(HTTPStatus.FORBIDDEN, "Etkin, kapsamı ve yetkisi kayıtlı denetim gerekli.")
            # Validate engagement.test_window before invoking spider
            raw_window = engagement.get("test_window")
            if not isinstance(raw_window, str) or len(raw_window) != 41:
                return self._error(HTTPStatus.FORBIDDEN, "Engagement test_window formatı geçersiz.")
            import re
            from datetime import datetime, timezone, timedelta
            window_match = re.fullmatch(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)/(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)", raw_window)
            if not window_match:
                return self._error(HTTPStatus.FORBIDDEN, "Engagement test_window formatı geçersiz.")
            try:
                start_str, end_str = window_match.groups()
                start_dt = datetime.fromisoformat(start_str.replace("Z", "+00:00"))
                end_dt = datetime.fromisoformat(end_str.replace("Z", "+00:00"))
            except Exception:
                return self._error(HTTPStatus.FORBIDDEN, "Engagement test_window formatı geçersiz.")
            if not (start_dt < end_dt):
                return self._error(HTTPStatus.FORBIDDEN, "Engagement test_window başlangıç bitişten sonra olamaz.")
            now_dt = datetime.now(timezone.utc)
            min_end = now_dt + timedelta(seconds=300)
            if not (start_dt <= now_dt):
                return self._error(HTTPStatus.FORBIDDEN, "Engagement test_window başlangıcı gelecek zaman olamaz.")
            if not (end_dt >= min_end):
                return self._error(HTTPStatus.FORBIDDEN, "Engagement test_window yeterli süre sağlamıyor.")
            duration_seconds = (end_dt - start_dt).total_seconds()
            if duration_seconds > 24 * 60 * 60:
                return self._error(HTTPStatus.FORBIDDEN, "Görev test_window 24 saatten uzun olamaz.")
            raw_oos = engagement.get("out_of_scope")
            try:
                if raw_oos == "":
                    out_of_scope = []
                elif isinstance(raw_oos, str):
                    parsed_exclusions = json.loads(raw_oos)
                    if parsed_exclusions == []:
                        raise ValueError("Boş olmayan bir hariç tutma listesi boş olamaz.")
                    out_of_scope = validate_exclusions(parsed_exclusions)
                else:
                    raise ValueError("Geçersiz hariç tutma değeri.")
            except (json.JSONDecodeError, ValueError):
                return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz out_of_scope formatı.")
            try:
                return self._json(run_zap_target_spider(target, out_of_scope))
            except ZapBusy:
                return self._error(HTTPStatus.CONFLICT, "Bir ZAP spider taraması zaten çalışıyor.")
            except ZapUnavailable:
                return self._error(HTTPStatus.SERVICE_UNAVAILABLE, "ZAP çalışma zamanı kullanılamıyor.")
            except ZapExecutionError:
                return self._error(HTTPStatus.BAD_GATEWAY, "ZAP örümcek çalıştırması başarısız oldu.")
            except ValueError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, _sanitize_error_message(str(exc), "Geçersiz ZAP spider isteği."))

        if path in ("/api/tools/zap/af-plan-preview", "/api/zap/af-plan-preview", "/api/tool-plans/zap-af/preview"):
            if not isinstance(payload, dict):
                return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz ZAP AF önizleme alanı.")
            mode = payload.get("mode", "ACTIVE_ROOT")
            active_keys = {"target_id", "engagement_id", "selected_path", "confirm_authorized", "confirm_crawl", "confirm_active"}
            passive_keys = {"target_id", "engagement_id", "selected_path", "confirm_authorized", "confirm_crawl", "mode"}
            if mode == "PASSIVE_ONLY":
                if set(payload) != passive_keys:
                    return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz ZAP AF önizleme alanı.")
                preview_req = payload
            elif mode == "ACTIVE_ROOT":
                if set(payload) not in (active_keys, active_keys | {"mode"}):
                    return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz ZAP AF önizleme alanı.")
                preview_req = {k: v for k, v in payload.items() if k != "mode"}
            else:
                return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz ZAP AF önizleme kipi.")
            target_id, engagement_id = payload.get("target_id"), payload.get("engagement_id")
            if (not isinstance(target_id, str) or not target_id.strip() or len(target_id.strip()) > 80
                    or not isinstance(engagement_id, str) or not engagement_id.strip() or len(engagement_id.strip()) > 80):
                return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz hedef veya denetim kimliği.")
            selected_path = payload.get("selected_path")
            if not isinstance(selected_path, str) or not selected_path.startswith("/"):
                return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz selected_path değeri.")
            target = STORE.get_target(target_id.strip())
            engagement = STORE.get_engagement(engagement_id.strip())
            if target is None or engagement is None:
                return self._error(HTTPStatus.NOT_FOUND, "Hedef veya denetim bulunamadı.")
            try:
                return self._json(build_preview_payload(
                    target=target,
                    engagement=engagement,
                    request={
                        **preview_req,
                        "target_id": target_id.strip(),
                        "engagement_id": engagement_id.strip(),
                    },
                ))
            except (PlanError, ValueError, KeyError, TypeError, IndexError):
                return self._error(
                    HTTPStatus.FORBIDDEN,
                    "Etkin, kapsamı ve yetkisi doğrulanmış ZAP AF önizleme koşulu sağlanmadı.",
                )

        if path in ("/api/tools/zap/selected-path-scope", "/api/zap/selected-path-spider", "/api/tool-runs/zap-target-spider-scope"):
            allowed_scope_keys = (
                {"target_id", "engagement_id", "selected_paths", "confirm_authorized", "confirm_selected_scope"},
                {"target_id", "engagement_id", "selected_paths", "confirm_authorized", "confirm_crawl"},
            )
            if not isinstance(payload, dict) or set(payload) not in allowed_scope_keys:
                return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz ZAP seçili yol spider alanı.")
            target_id, engagement_id = payload.get("target_id"), payload.get("engagement_id")
            if (not isinstance(target_id, str) or not target_id or len(target_id) > 80
                    or not isinstance(engagement_id, str) or not engagement_id or len(engagement_id) > 80):
                return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz hedef veya denetim kimliği.")
            try:
                selected_paths = validate_selected_paths(payload.get("selected_paths"))
            except ValueError:
                return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz selected_paths formatı.")
            scope_confirmed = (
                payload.get("confirm_selected_scope") is True
                if "confirm_selected_scope" in payload
                else payload.get("confirm_crawl") is True
            )
            if payload.get("confirm_authorized") is not True or not scope_confirmed:
                return self._error(HTTPStatus.FORBIDDEN, "Açık yetki ve seçili kapsam spider onayı gerekli.")
            target = STORE.get_target(target_id)
            engagement = STORE.get_engagement(engagement_id)
            if target is None or engagement is None:
                return self._error(HTTPStatus.NOT_FOUND, "Hedef veya denetim bulunamadı.")
            if target.get("path") != "/" or urlsplit(str(target.get("url", ""))).path not in ("", "/"):
                return self._error(HTTPStatus.BAD_REQUEST, "Seçili yol kapsamı yalnız kök hedef kaydında kullanılabilir.")
            if (engagement.get("status") != "active" or engagement.get("target_id") != target_id
                    or not isinstance(engagement.get("authorization_ref"), str)
                    or not engagement["authorization_ref"].strip()
                    or not isinstance(engagement.get("scope_notes"), str)
                    or not engagement["scope_notes"].strip()):
                return self._error(HTTPStatus.FORBIDDEN, "Etkin, kapsamı ve yetkisi kayıtlı denetim gerekli.")
            if not _active_test_window_valid(engagement):
                return self._error(HTTPStatus.FORBIDDEN, "Engagement test_window geçerli ve etkin olmalıdır.")
            raw_oos = engagement.get("out_of_scope")
            try:
                if raw_oos == "":
                    out_of_scope = []
                elif isinstance(raw_oos, str):
                    parsed_exclusions = json.loads(raw_oos)
                    if parsed_exclusions == []:
                        raise ValueError("Boş olmayan bir hariç tutma listesi boş olamaz.")
                    out_of_scope = validate_exclusions(parsed_exclusions)
                else:
                    raise ValueError("Geçersiz hariç tutma değeri.")
            except (json.JSONDecodeError, ValueError):
                return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz out_of_scope formatı.")
            try:
                return self._json(run_zap_selected_path_spider(target, selected_paths, out_of_scope))
            except ZapBusy:
                return self._error(HTTPStatus.CONFLICT, "Bir ZAP spider taraması zaten çalışıyor.")
            except ZapUnavailable:
                return self._error(HTTPStatus.SERVICE_UNAVAILABLE, "ZAP çalışma zamanı kullanılamıyor.")
            except ZapExecutionError:
                return self._error(HTTPStatus.BAD_GATEWAY, "ZAP örümcek çalıştırması başarısız oldu.")
            except ValueError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, _sanitize_error_message(str(exc), "Geçersiz ZAP seçili yol kapsamı."))

        if path in ("/api/tools/zap/site-active", "/api/zap/site-active", "/api/tool-runs/zap-site-active"):
            allowed_site_active = {"target_id", "engagement_id", "confirm_authorized", "confirm_crawl", "confirm_active"}
            if not isinstance(payload, dict) or set(payload) != allowed_site_active:
                return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz ZAP site-active tarama alanı.")
            target_id, engagement_id = payload.get("target_id"), payload.get("engagement_id")
            if (not isinstance(target_id, str) or not target_id or len(target_id) > 80
                    or not isinstance(engagement_id, str) or not engagement_id or len(engagement_id) > 80):
                return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz hedef veya denetim kimliği.")
            if (payload.get("confirm_authorized") is not True
                    or payload.get("confirm_crawl") is not True
                    or payload.get("confirm_active") is not True):
                return self._error(HTTPStatus.FORBIDDEN, "Açık yetki, spider ve aktif tarama onayı gerekli.")
            target = STORE.get_target(target_id)
            engagement = STORE.get_engagement(engagement_id)
            if target is None or engagement is None:
                return self._error(HTTPStatus.NOT_FOUND, "Hedef veya denetim bulunamadı.")
            if (engagement.get("status") != "active" or engagement.get("target_id") != target_id
                    or not isinstance(engagement.get("authorization_ref"), str)
                    or not engagement["authorization_ref"].strip()
                    or not isinstance(engagement.get("scope_notes"), str)
                    or not engagement["scope_notes"].strip()):
                return self._error(HTTPStatus.FORBIDDEN, "Etkin, kapsamı ve yetkisi kayıtlı denetim gerekli.")
            if not _active_test_window_valid(engagement):
                return self._error(HTTPStatus.FORBIDDEN, "Engagement test_window geçerli ve etkin olmalıdır.")
            raw_oos = engagement.get("out_of_scope")
            try:
                if raw_oos == "":
                    exclusions = []
                elif isinstance(raw_oos, str):
                    parsed_exclusions = json.loads(raw_oos)
                    if parsed_exclusions == []:
                        raise ValueError("Boş olmayan bir hariç tutma listesi boş olamaz.")
                    exclusions = validate_exclusions(parsed_exclusions)
                else:
                    raise ValueError("Geçersiz hariç tutma değeri.")
            except (json.JSONDecodeError, ValueError):
                return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz out_of_scope formatı.")
            try:
                return self._json(run_zap_site_active(target, exclusions))
            except ZapBusy:
                return self._error(HTTPStatus.CONFLICT, "Bir ZAP taraması zaten çalışıyor.")
            except ZapUnavailable:
                return self._error(HTTPStatus.SERVICE_UNAVAILABLE, "ZAP çalışma zamanı kullanılamıyor.")
            except ZapExecutionError:
                return self._error(HTTPStatus.BAD_GATEWAY, "ZAP çalıştırması başarısız oldu.")
            except ValueError:
                return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz veya güvensiz hedef.")

        if path == "/api/tool-reports/dependabot/summary":
            try:
                result = parse_dependabot_alerts_summary(payload)
                return self._json(result)
            except ValueError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))

        if path in ("/api/tool-reports/dependabot/offline-sync", "/api/tool-reports/dependabot/sync"):
            if not self._is_loopback_client():
                return self._error(HTTPStatus.FORBIDDEN, "Yalnız yerel geri dönüş adresinden izin verilir.")
            try:
                if not isinstance(payload, dict):
                    raise DependabotSyncError("Dependabot özet eşitlemesi başarısız oldu.")
                allowed_sync_keys = {"owner", "repo", "confirm_sync", "alerts", "pages", "allowed_repositories"}
                if not set(payload.keys()).issubset(allowed_sync_keys):
                    raise DependabotSyncError("Dependabot özet eşitlemesi başarısız oldu.")
                sync_req = {k: payload[k] for k in ("owner", "repo", "confirm_sync") if k in payload}
                owner_str = str(payload.get("owner", "")).strip().lower()
                repo_str = str(payload.get("repo", "")).strip().lower()
                if "allowed_repositories" in payload:
                    raw_allowed = payload["allowed_repositories"]
                    if not isinstance(raw_allowed, list) or not all(isinstance(item, str) and item.strip() for item in raw_allowed):
                        raise DependabotSyncError("Dependabot özet eşitlemesi başarısız oldu.")
                    allowed_repos = {item.strip().lower() for item in raw_allowed}
                elif os.environ.get("SNIPER_GITHUB_DEPENDABOT_REPOSITORY", "").strip():
                    allowed_repos = {
                        item.strip().lower()
                        for item in os.environ["SNIPER_GITHUB_DEPENDABOT_REPOSITORY"].split(",")
                        if item.strip()
                    }
                elif "alerts" in payload or "pages" in payload:
                    allowed_repos = {f"{owner_str}/{repo_str}"} if owner_str and repo_str else set()
                else:
                    allowed_repos = set()

                if "pages" in payload:
                    if not isinstance(payload["pages"], list) or not all(isinstance(p, dict) for p in payload["pages"]):
                        raise DependabotSyncError("Dependabot özet eşitlemesi başarısız oldu.")
                    transport_fn = _build_dependabot_offline_transport(payload["pages"])
                    token_val = os.environ.get("SNIPER_GITHUB_DEPENDABOT_TOKEN", "").strip() or "offline_fixture_sync_token"
                elif "alerts" in payload:
                    if not isinstance(payload["alerts"], list):
                        raise DependabotSyncError("Dependabot özet eşitlemesi başarısız oldu.")
                    transport_fn = _build_dependabot_offline_transport([{"status": 200, "headers": {}, "alerts": payload["alerts"]}])
                    token_val = os.environ.get("SNIPER_GITHUB_DEPENDABOT_TOKEN", "").strip() or "offline_fixture_sync_token"
                elif DEPENDABOT_SYNC_TRANSPORT is not None:
                    transport_fn = DEPENDABOT_SYNC_TRANSPORT
                    token_val = os.environ.get("SNIPER_GITHUB_DEPENDABOT_TOKEN", "").strip()
                elif os.environ.get("SNIPER_GITHUB_DEPENDABOT_OFFLINE_PAGES_JSON", "").strip():
                    raw_pages = json.loads(os.environ["SNIPER_GITHUB_DEPENDABOT_OFFLINE_PAGES_JSON"])
                    if not isinstance(raw_pages, list) or not all(isinstance(p, dict) for p in raw_pages):
                        raise DependabotSyncError("Dependabot özet eşitlemesi başarısız oldu.")
                    transport_fn = _build_dependabot_offline_transport(raw_pages)
                    token_val = os.environ.get("SNIPER_GITHUB_DEPENDABOT_TOKEN", "").strip() or "offline_fixture_sync_token"
                else:
                    transport_fn = _build_dependabot_offline_transport([])
                    token_val = os.environ.get("SNIPER_GITHUB_DEPENDABOT_TOKEN", "").strip()

                result = sync_dependabot_summary(
                    sync_req,
                    allowed_repositories=allowed_repos,
                    credential_provider=lambda _repo: token_val,
                    transport=transport_fn,
                )
                return self._json(result)
            except (DependabotSyncError, ValueError, TypeError):
                return self._error(HTTPStatus.BAD_REQUEST, "Dependabot özet eşitlemesi başarısız oldu.")

        if path == "/api/tool-reports/burp-logger-csv/summary":
            try:
                result = parse_burp_logger_csv_summary(payload)
                return self._json(result)
            except ValueError:
                return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz istek.")

        if path == "/api/tool-reports/semgrep/tls-verify-filter":
            try:
                if not isinstance(payload, dict):
                    raise ValueError("Geçersiz Semgrep TLS filtre yükü")
                allowed_filter_keys = {"results", "report", "project_path", "input_dir"}
                if not set(payload.keys()).issubset(allowed_filter_keys):
                    raise ValueError("Semgrep TLS filtre yükünde beklenmeyen alanlar")
                raw_dir = payload.get("project_path") if "project_path" in payload else payload.get("input_dir")
                if not isinstance(raw_dir, str) or not raw_dir.strip():
                    raise ValueError("project_path gerekli")
                project_root = validate_project_path(raw_dir, allowed_roots=(Path.home().resolve(),))
                if "results" in payload:
                    raw_results = payload["results"]
                elif isinstance(payload.get("report"), dict):
                    raw_results = payload["report"].get("results")
                else:
                    raw_results = None
                if not isinstance(raw_results, list):
                    raise ValueError("results bir liste olmalı")
                filtered = filter_direct_requests_tls_findings(raw_results, project_root)
                sanitized_items = []
                for item in filtered:
                    if isinstance(item, dict):
                        start_obj = item.get("start") if isinstance(item.get("start"), dict) else {}
                        sanitized_items.append({
                            "check_id": str(item.get("check_id") or ""),
                            "line": start_obj.get("line") if isinstance(start_obj.get("line"), int) else None,
                            "col": start_obj.get("col") if isinstance(start_obj.get("col"), int) else None,
                        })
                return self._json({
                    "format": "semgrep-tls-verify-filter-v1",
                    "input_finding_count": len(raw_results),
                    "kept_finding_count": len(filtered),
                    "suppressed_finding_count": len(raw_results) - len(filtered),
                    "results": sanitized_items,
                })
            except (ProjectRejected, ValueError) as exc:
                return self._error(
                    HTTPStatus.BAD_REQUEST,
                    _sanitize_error_message(str(exc), "Geçersiz Semgrep TLS doğrulama filtresi isteği."),
                )

        if path in ("/api/tool-reports/nuclei/verification-coverage", "/api/tool-reports/nuclei/verification-contract"):
            try:
                if not isinstance(payload, dict):
                    raise ValueError("Geçersiz Nuclei doğrulama yükü")
                allowed_keys = {"report", "raw_jsonl", "executed_template_ids"}
                if not set(payload.keys()).issubset(allowed_keys):
                    raise ValueError("Nuclei doğrulama yükünde beklenmeyen alanlar")
                raw_jsonl = payload.get("raw_jsonl") if "raw_jsonl" in payload else payload.get("report")
                if not isinstance(raw_jsonl, str):
                    raise ValueError("Geçersiz Nuclei doğrulama yükü")
                from nuclei_verification_summary import build_nuclei_verification_coverage_summary
                executed_ids = payload.get("executed_template_ids")
                return self._json(build_nuclei_verification_coverage_summary(
                    raw_jsonl, executed_template_ids=executed_ids
                ))
            except ValueError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))

        if path in ("/api/tool-reports/burp-sitemap/handoff-manifest", "/api/tool-reports/burp/handoff-profile"):
            try:
                if not isinstance(payload, dict):
                    raise ValueError("Geçersiz Burp devir yükü")
                allowed_keys = {"sitemap_xml", "report", "allowed_host"}
                if not set(payload.keys()).issubset(allowed_keys):
                    raise ValueError("Burp devir yükünde beklenmeyen alanlar")
                sitemap_xml = payload.get("sitemap_xml") if "sitemap_xml" in payload else payload.get("report")
                allowed_host = payload.get("allowed_host")
                if not isinstance(sitemap_xml, str) or not isinstance(allowed_host, str):
                    raise ValueError("Geçersiz Burp devir yükü")
                from burp_handoff_profile import build_burp_manual_handoff_manifest
                return self._json(build_burp_manual_handoff_manifest(
                    sitemap_xml, allowed_host=allowed_host
                ))
            except ValueError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))

        if path in ("/api/tool-reports/dependencies/remediation-plan", "/api/tool-reports/dependency-remediation-plan"):
            try:
                if not isinstance(payload, dict):
                    raise ValueError("Geçersiz bağımlılık düzeltme yükü")
                allowed_keys = {"npm_audit_raw", "dependabot_raw", "npm_audit_report", "dependabot_report"}
                if not set(payload.keys()).issubset(allowed_keys):
                    raise ValueError("Bağımlılık düzeltme yükünde beklenmeyen alanlar")
                npm_raw = payload.get("npm_audit_raw") if "npm_audit_raw" in payload else payload.get("npm_audit_report")
                dep_raw = payload.get("dependabot_raw") if "dependabot_raw" in payload else payload.get("dependabot_report")
                from dependency_remediation_plan import build_readonly_dependency_remediation_plan
                return self._json(build_readonly_dependency_remediation_plan(
                    npm_audit_raw=npm_raw,
                    dependabot_raw=dep_raw,
                ))
            except ValueError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))

        if path in ("/api/tool-runs/secret-bundle/validate", "/api/tools/secret-bundle/validate"):
            try:
                if not isinstance(payload, dict) or set(payload.keys()) != {"files"}:
                    raise ValueError("Geçersiz sır paketi yükü")
                from secret_bundle_validator import validate_bounded_secret_scan_bundle
                return self._json(validate_bounded_secret_scan_bundle(payload["files"]))
            except ValueError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))

        if path == "/api/tool-reports/ssllabs/cache-contract":
            try:
                if not isinstance(payload, dict):
                    raise ValueError("Geçersiz SSL Labs önbellek sözleşmesi yükü")
                allowed_keys = {"report_json", "report", "target"}
                if not set(payload.keys()).issubset(allowed_keys):
                    raise ValueError("SSL Labs önbellek sözleşmesi yükünde beklenmeyen alanlar")
                raw_rep = payload.get("report_json") if "report_json" in payload else payload.get("report")
                if isinstance(raw_rep, dict):
                    report_json_str = json.dumps(raw_rep, sort_keys=True, separators=(",", ":"))
                elif isinstance(raw_rep, str):
                    report_json_str = raw_rep
                else:
                    raise ValueError("Kayıtlı SSL Labs report_json alanı gerekli")
                from tls_trivy_boundary_verifier import verify_tls_workflow_boundary
                return self._json(verify_tls_workflow_boundary(
                    "ssllabs-saved-report",
                    target=payload.get("target"),
                    report_json=report_json_str,
                ))
            except ValueError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))

        if path == "/api/tool-reports/testssl/boundary-contract":
            try:
                if not isinstance(payload, dict):
                    raise ValueError("Geçersiz testssl sınır sözleşmesi yükü")
                allowed_keys = {"target", "report_json", "report"}
                if not set(payload.keys()).issubset(allowed_keys):
                    raise ValueError("testssl sınır sözleşmesi yükünde beklenmeyen alanlar")
                raw_rep = payload.get("report_json") if "report_json" in payload else payload.get("report")
                from tls_trivy_boundary_verifier import verify_tls_workflow_boundary
                return self._json(verify_tls_workflow_boundary(
                    "testssl-loopback",
                    target=payload.get("target"),
                    report_json=raw_rep,
                ))
            except ValueError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))

        if path == "/api/tool-reports/tls-trivy/boundary-verify":
            try:
                if not isinstance(payload, dict) or not isinstance(payload.get("mode"), str):
                    raise ValueError("Geçersiz TLS/Trivy sınır yükü")
                from tls_trivy_boundary_verifier import verify_tls_workflow_boundary, verify_trivy_offline_db_freshness
                if payload["mode"] == "trivy-db-freshness":
                    return self._json(verify_trivy_offline_db_freshness(
                        payload.get("metadata_json", ""),
                        reference_utc=payload.get("reference_utc", ""),
                        max_age_hours=payload.get("max_age_hours", 168),
                    ))
                return self._json(verify_tls_workflow_boundary(
                    payload["mode"],
                    target=payload.get("target"),
                    report_json=payload.get("report"),
                ))
            except ValueError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))

        if path == "/api/tool-reports/semgrep/rulepack-inventory":
            try:
                if not isinstance(payload, dict):
                    raise ValueError("Geçersiz Semgrep kural paketi envanter yükü")
                rules_path = os.environ.get("SNIPER_SEMGREP_RULES", "")
                if not rules_path:
                    return self._error(HTTPStatus.SERVICE_UNAVAILABLE, "Semgrep kural paketi yapılandırılmamış.")
                from semgrep_rulepack_inventory import summarize_trusted_semgrep_rulepack
                return self._json(summarize_trusted_semgrep_rulepack(
                    rules_path,
                    target_extensions=payload.get("target_extensions"),
                ))
            except ValueError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))

        if path == "/api/tool-reports/testssl/summary":
            try:
                testssl_report = payload.get("report")
                if not isinstance(testssl_report, list):
                    raise ValueError("report anahtarı eksik veya geçersiz.")
                result = parse_testssl_json_summary(testssl_report)
                return self._json(result)
            except ValueError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))

        if len(parts) == 5 and parts[:2] == ["api", "engagements"] and parts[3:] == ["tool-evidence", "testssl-flat-json"]:
            if not isinstance(payload, dict) or set(payload) != {"control_id", "report", "confirm_link"} or payload.get("confirm_link") is not True:
                return self._error(HTTPStatus.BAD_REQUEST, "Açık kanıt bağlama onayı gerekli.")
            engagement = STORE.get_engagement(parts[2])
            if not engagement:
                return self._error(HTTPStatus.NOT_FOUND, "Manuel denetim bulunamadı.")
            if engagement["status"] != "active" or not engagement["authorization_ref"].strip() or not engagement["special_approvals"].get("redacted_data_proof"):
                return self._error(HTTPStatus.FORBIDDEN, "Etkin, yetkili ve maskeli kanıt onaylı denetim gerekli.")
            try:
                control_id = clean_text(payload, "control_id", maximum=80, required=True)
                report = payload["report"]
                if not isinstance(report, list):
                    raise ValueError("Geçersiz testssl.sh raporu.")
                canonical = json.dumps(report, sort_keys=True, separators=(",", ":")).encode("utf-8")
                if len(canonical) > 60_000:
                    raise ValueError("Rapor boyutu sınırı aşıldı.")
                summary = parse_testssl_json_summary(report)
                linked, created = STORE.add_testssl_tool_evidence(parts[2], control_id, summary)
                return self._json(linked, status=HTTPStatus.CREATED if created else HTTPStatus.OK)
            except ValueError:
                return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz testssl.sh kanıtı veya test adımı.")

        if len(parts) == 5 and parts[:2] == ["api", "engagements"] and parts[3:] == ["tool-evidence", "zap-traditional-json"]:
            if not isinstance(payload, dict) or set(payload) != {"control_id", "report", "confirm_link"} or payload.get("confirm_link") is not True:
                return self._error(HTTPStatus.BAD_REQUEST, "Açık kanıt bağlama onayı gerekli.")
            engagement = STORE.get_engagement(parts[2])
            if not engagement:
                return self._error(HTTPStatus.NOT_FOUND, "Manuel denetim bulunamadı.")
            if engagement["status"] != "active" or not engagement["authorization_ref"].strip() or not engagement["special_approvals"].get("redacted_data_proof"):
                return self._error(HTTPStatus.FORBIDDEN, "Etkin, yetkili ve maskeli kanıt onaylı denetim gerekli.")
            try:
                control_id = clean_text(payload, "control_id", maximum=80, required=True)
                report = payload["report"]
                if not isinstance(report, dict):
                    raise ValueError("Geçersiz ZAP raporu.")
                canonical = json.dumps(report, sort_keys=True, separators=(",", ":")).encode("utf-8")
                if len(canonical) > 60_000:
                    raise ValueError("Rapor boyutu sınırı aşıldı.")
                summary = parse_zap_traditional_json_summary(report)
                linked, created = STORE.add_zap_tool_evidence(parts[2], control_id, summary)
                return self._json(linked, status=HTTPStatus.CREATED if created else HTTPStatus.OK)
            except ValueError:
                return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz ZAP kanıtı veya test adımı.")

        if path == "/api/tool-runs/testssl-authorized":
            if not isinstance(payload, dict):
                return self._error(HTTPStatus.BAD_REQUEST, "İstek gövdesi bir JSON nesnesi olmalı.")
            if payload.get("confirm_authorized") is not True:
                return self._error(HTTPStatus.FORBIDDEN, "Bu çalıştırma için açık insan yetki onayı gerekli.")
            if set(payload) != {"target", "profile", "confirm_authorized"}:
                return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz doğrudan testssl tarama alanı.")
            target = payload.get("target")
            profile = payload.get("profile")
            if not isinstance(target, str) or not target.strip() or len(target) > 320:
                return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz testssl hedefi.")
            if profile not in ("protocols", "full"):
                return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz testssl profili.")
            try:
                result = run_testssl_authorized(target, profile=profile)
            except ValueError:
                return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz doğrudan testssl tarama isteği.")
            except RuntimeError as exc:
                message = str(exc).lower()
                if any(token in message for token in ("kilit", "sürüyor", "meşgul", "ikili", "binary", "sha256", "hash")):
                    return self._error(HTTPStatus.SERVICE_UNAVAILABLE, "testssl çalışma zamanı kullanılamıyor veya meşgul.")
                return self._error(HTTPStatus.BAD_GATEWAY, "testssl çalıştırması tamamlanamadı.")
            receipt = _direct_target_authorization_receipt()
            STORE.log(
                "testssl.direct_authorized.completed",
                result["target_sha256"],
                {
                    "profile": result["profile"],
                    "record_count": result["record_count"],
                    "target_sha256": result["target_sha256"],
                    "resolved_ip_sha256": result["resolved_ip_sha256"],
                    "authorization_receipt": receipt,
                },
            )
            return self._json({**result, "authorization_receipt": receipt})

        if path in ("/api/tool-runs/testssl-protocols", "/api/tool-runs/testssl-full"):
            full = path == "/api/tool-runs/testssl-full"
            try:
                if full and (not isinstance(payload, dict) or set(payload) != {"confirm_local", "target"}):
                    raise ValueError("Yalnız confirm_local ve target kabul edilir")
                if not isinstance(payload, dict):
                    raise ValueError("payload bir JSON nesnesi olmalı")
                confirm_local = payload.get("confirm_local")
                if confirm_local is not True:
                    raise ValueError("confirm_local tam olarak true olmalı")
                target = payload.get("target")
                if not isinstance(target, str) or not target.strip():
                    raise ValueError("target IP:PORT biçiminde boş olmayan bir metin olmalı")
                parts = target.rsplit(":", 1)
                if len(parts) != 2:
                    raise ValueError("target IP:PORT biçiminde olmalı")
                ip, port_str = parts
                if not port_str.isdigit():
                    raise ValueError("PORT sayısal olmalı")
                port = int(port_str)
                result = run_testssl_loopback(ip, port, full=True) if full else run_testssl_loopback(ip, port)
                return self._json(result)
            except ValueError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))
            except RuntimeError as exc:
                msg = str(exc)
                if "timeout" in msg.lower() or "timed out" in msg.lower() or "zaman aşımı" in msg.lower():
                    return self._error(HTTPStatus.BAD_GATEWAY, "testssl çalıştırması zaman aşımına uğradı.")
                if "lock" in msg.lower() or "in progress" in msg.lower() or "sürüyor" in msg.lower() or "meşgul" in msg.lower() or "kilit" in msg.lower():
                    return self._error(HTTPStatus.SERVICE_UNAVAILABLE, "Başka bir testssl taraması sürüyor.")
                if "binary" in msg.lower() or "ikili" in msg.lower() or "configured" in msg.lower() or "yapılandırılmamış" in msg.lower() or "hash mismatch" in msg.lower() or "hash değeri uyuşmuyor" in msg.lower():
                    return self._error(HTTPStatus.SERVICE_UNAVAILABLE, "testssl ikilisi yapılandırılmamış veya geçersiz.")
                return self._error(HTTPStatus.BAD_GATEWAY, "testssl çalıştırması başarısız oldu.")

        if path == "/api/tool-reports/gitleaks/summary":
            try:
                gitleaks_report = payload.get("report")
                if not isinstance(gitleaks_report, list):
                    raise ValueError("report anahtarı eksik veya geçersiz.")
                result = parse_gitleaks_json_summary(gitleaks_report)
                return self._json(result)
            except ValueError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))

        if len(parts) == 5 and parts[:2] == ["api", "engagements"] and parts[3:] == ["tool-evidence", "gitleaks-native-json"]:
            if set(payload) != {"control_id", "report", "confirm_link"} or payload.get("confirm_link") is not True:
                return self._error(HTTPStatus.BAD_REQUEST, "Açık kanıt bağlama onayı gerekli.")
            engagement = STORE.get_engagement(parts[2])
            if not engagement:
                return self._error(HTTPStatus.NOT_FOUND, "Manuel denetim bulunamadı.")
            if engagement["status"] != "active" or not engagement["authorization_ref"].strip() or not engagement["special_approvals"].get("redacted_data_proof"):
                return self._error(HTTPStatus.FORBIDDEN, "Etkin, yetkili ve maskeli kanıt onaylı denetim gerekli.")
            try:
                control_id = clean_text(payload, "control_id", maximum=80, required=True)
                report = payload["report"]
                if not isinstance(report, list):
                    raise ValueError("Geçersiz Gitleaks raporu.")
                summary = parse_gitleaks_json_summary(report)
                # Compute canonical SHA-256 after parser validation
                canonical = json.dumps(report, sort_keys=True, separators=(",", ":")).encode("utf-8")
                summary["report_sha256"] = hashlib.sha256(canonical).hexdigest()
                linked, created = STORE.add_gitleaks_tool_evidence(parts[2], control_id, summary)
                return self._json(linked, status=HTTPStatus.CREATED if created else HTTPStatus.OK)
            except ValueError:
                return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz Gitleaks kanıtı veya test adımı.")

        if path == "/api/tool-reports/trufflehog/summary":
            try:
                trufflehog_report = payload.get("report")
                if not isinstance(trufflehog_report, list):
                    raise ValueError("report anahtarı eksik veya geçersiz.")
                result = parse_trufflehog_json_summary(trufflehog_report)
                return self._json(result)
            except ValueError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))

        if path == "/api/tool-reports/trivy-native-json/summary":
            try:
                payload_report = payload.get("report")
                if not isinstance(payload_report, dict):
                    raise ValueError("report bir JSON nesnesi olmalı")
                result = parse_trivy_native_json_summary(payload_report)
                return self._json(result)
            except ValueError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))

        if path == "/api/tool-reports/nuclei-jsonl/summary":
            try:
                payload_report = payload.get("report")
                if not isinstance(payload_report, list):
                    raise ValueError("report bir JSON dizisi olmalı")
                result = parse_nuclei_jsonl_summary(payload_report)
                return self._json(result)
            except ValueError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))

        if len(parts) == 5 and parts[:2] == ["api", "engagements"] and parts[3:] == ["tool-evidence", "nuclei-jsonl"]:
            if set(payload) != {"control_id", "report", "confirm_link"} or payload.get("confirm_link") is not True:
                return self._error(HTTPStatus.BAD_REQUEST, "Açık kanıt bağlama onayı gerekli.")
            engagement = STORE.get_engagement(parts[2])
            if not engagement:
                return self._error(HTTPStatus.NOT_FOUND, "Manuel denetim bulunamadı.")
            if engagement["status"] != "active" or not engagement["authorization_ref"].strip() or not engagement["special_approvals"].get("redacted_data_proof"):
                return self._error(HTTPStatus.FORBIDDEN, "Etkin, yetkili ve maskeli kanıt onaylı denetim gerekli.")
            try:
                control_id = clean_text(payload, "control_id", maximum=80, required=True)
                report = payload["report"]
                if not isinstance(report, list):
                    raise ValueError("Geçersiz Nuclei raporu.")
                summary = parse_nuclei_jsonl_summary(report)
                # Compute canonical SHA-256 after parser validation
                canonical = json.dumps(report, sort_keys=True, separators=(",", ":")).encode("utf-8")
                summary["report_sha256"] = hashlib.sha256(canonical).hexdigest()
                linked, created = STORE.add_nuclei_tool_evidence(parts[2], control_id, summary)
                return self._json(linked, status=HTTPStatus.CREATED if created else HTTPStatus.OK)
            except ValueError:
                return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz Nuclei kanıtı veya test adımı.")

        if path == "/api/tool-runs/nuclei-loopback":
            try:
                if not isinstance(payload, dict) or payload.get("confirm_local") is not True:
                    raise ValueError("confirm_local tam olarak true olmalı")
                if set(payload) != {"confirm_local", "target"}:
                    raise ValueError("Yalnız confirm_local ve target kabul edilir")
                target = payload.get("target")
                if not isinstance(target, str):
                    raise ValueError("target bir loopback ana makinesi ve portu olmalı")
                return self._json(run_nuclei_loopback(target))
            except ValueError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))
            except (NucleiUnavailable, NucleiBusy):
                return self._error(HTTPStatus.SERVICE_UNAVAILABLE, "Nuclei tarayıcısı kullanılamıyor veya meşgul.")
            except NucleiExecutionError:
                return self._error(HTTPStatus.BAD_GATEWAY, "Nuclei çalıştırması başarısız oldu.")

        if path == "/api/tool-runs/joern-deep":
            # Joern derin analiz: uzun sürer; /api/jobs ile arka planda çalıştırılması önerilir. İsteğe bağlı:
            # include_scripting (JS/TS ve Python, hızlı motorun tamamlayıcısı) ve time_budget_seconds (60–3600;
            # bütçe bitince kısmi sonuç + uyarı).
            try:
                if not isinstance(payload, dict) or not {"confirm_local", "project_path"} <= set(payload) or \
                        set(payload) - {"confirm_local", "project_path", "include_scripting", "time_budget_seconds"}:
                    raise ValueError("Yalnız confirm_local, project_path ve isteğe bağlı include_scripting / "
                                     "time_budget_seconds alanları gönderilmeli.")
                if payload.get("confirm_local") is not True:
                    raise ValueError("confirm_local tam olarak true olmalı.")
                project_path = payload.get("project_path")
                if not isinstance(project_path, str) or not project_path.strip():
                    raise ValueError("project_path boş olmayan bir metin olmalı.")
                include_scripting = payload.get("include_scripting")
                if include_scripting is not None and not isinstance(include_scripting, bool):
                    raise ValueError("include_scripting true/false olmalı.")
                budget = payload.get("time_budget_seconds")
                if budget is not None and (isinstance(budget, bool) or not isinstance(budget, int) or not 60 <= budget <= 3600):
                    raise ValueError("time_budget_seconds 60 ile 3600 arasında bir tam sayı olmalı.")
                from joern_active import (DEFAULT_TIMEOUT_SECONDS, JoernBusy, JoernExecutionError, JoernUnavailable,
                                          run_joern_deep)
            except ValueError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))
            try:
                return self._json(run_joern_deep(project_path, scripting=include_scripting,
                                                 timeout=float(budget or DEFAULT_TIMEOUT_SECONDS)))
            except ProjectRejected as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))
            except JoernBusy as exc:
                return self._error(HTTPStatus.CONFLICT, str(exc))
            except JoernUnavailable as exc:
                return self._error(HTTPStatus.SERVICE_UNAVAILABLE, str(exc))
            except JoernExecutionError as exc:
                return self._error(HTTPStatus.BAD_GATEWAY, str(exc))

        if path == "/api/tool-runs/semgrep":
            try:
                if not isinstance(payload, dict):
                    raise ValueError("payload bir JSON nesnesi olmalı")
                confirm_local = payload.get("confirm_local")
                if confirm_local is not True:
                    raise ValueError("confirm_local tam olarak true olmalı")
                project_path = payload.get("project_path")
                if not isinstance(project_path, str) or not project_path.strip():
                    raise ValueError("project_path boş olmayan bir metin olmalı")
                if set(payload) != {"confirm_local", "project_path"}:
                    raise ValueError("payload fazla veya eksik alan içeriyor")
                result = run_local_semgrep(project_path)
                return self._json(result)
            except ValueError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))
            except RuntimeError as exc:
                msg = str(exc)
                if "timeout" in msg.lower() or "timed out" in msg.lower() or "zaman aşımı" in msg.lower():
                    return self._error(HTTPStatus.BAD_GATEWAY, "Semgrep çalıştırması zaman aşımına uğradı.")
                if "lock" in msg.lower() or "in progress" in msg.lower() or "sürüyor" in msg.lower() or "meşgul" in msg.lower() or "kilit" in msg.lower():
                    return self._error(HTTPStatus.SERVICE_UNAVAILABLE, "Başka bir Semgrep taraması sürüyor.")
                if "ikili" in msg:
                    # verified_exec/tool_pins iletileri yol içermez; sabitleme sebebi gösterilir.
                    return self._error(HTTPStatus.SERVICE_UNAVAILABLE, msg)
                if "binary" in msg.lower() or "ikili" in msg.lower() or "rules" in msg.lower() or "kural" in msg.lower():
                    return self._error(HTTPStatus.SERVICE_UNAVAILABLE, "Semgrep ikilisi veya kuralları eksik.")
                return self._error(HTTPStatus.BAD_GATEWAY, "Semgrep çalıştırması başarısız oldu.")

        if len(parts) == 5 and parts[:2] == ["api", "engagements"] and parts[3:] == ["tool-runs", "semgrep-local"]:
            # Run and link in one request. A client-supplied aggregate is never accepted as scan evidence.
            if (set(payload) != {"control_id", "project_path", "confirm_local", "confirm_link"}
                    or payload.get("confirm_local") is not True or payload.get("confirm_link") is not True):
                return self._error(HTTPStatus.BAD_REQUEST, "Açık yerel tarama ve kanıt bağlama onayı gerekli.")
            engagement = STORE.get_engagement(parts[2])
            if not engagement:
                return self._error(HTTPStatus.NOT_FOUND, "Manuel denetim bulunamadı.")
            if (engagement["status"] != "active" or not engagement["authorization_ref"].strip()
                    or not engagement["special_approvals"].get("redacted_data_proof")):
                return self._error(HTTPStatus.FORBIDDEN, "Etkin, yetkili ve maskeli kanıt onaylı denetim gerekli.")
            try:
                control_id = clean_text(payload, "control_id", maximum=80, required=True)
                if control_id not in {test["control_id"] for test in engagement["tests"]}:
                    raise ValueError("Test adımı bulunamadı.")
                project_path = payload["project_path"]
                if not isinstance(project_path, str) or not project_path.strip():
                    raise ValueError("project_path boş olmayan bir metin olmalı")
                summary = run_local_semgrep(project_path)
                linked, created = STORE.add_semgrep_tool_evidence(parts[2], control_id, summary)
                return self._json(linked, status=HTTPStatus.CREATED if created else HTTPStatus.OK)
            except ValueError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))
            except RuntimeError as exc:
                msg = str(exc).lower()
                if "timeout" in msg or "timed out" in msg or "zaman aşımı" in msg:
                    return self._error(HTTPStatus.BAD_GATEWAY, "Semgrep çalıştırması zaman aşımına uğradı.")
                if "lock" in msg or "in progress" in msg or "sürüyor" in msg or "meşgul" in msg or "kilit" in msg:
                    return self._error(HTTPStatus.SERVICE_UNAVAILABLE, "Başka bir Semgrep taraması sürüyor.")
                if "binary" in msg or "ikili" in msg or "rules" in msg or "kural" in msg:
                    return self._error(HTTPStatus.SERVICE_UNAVAILABLE, "Semgrep ikilisi veya kuralları eksik.")
                return self._error(HTTPStatus.BAD_GATEWAY, "Semgrep çalıştırması başarısız oldu.")

        if path == "/api/tool-runs/gitleaks":
            try:
                if not isinstance(payload, dict):
                    raise ValueError("payload bir JSON nesnesi olmalı")
                confirm_local = payload.get("confirm_local")
                if confirm_local is not True:
                    raise ValueError("confirm_local tam olarak true olmalı")
                project_path = payload.get("project_path")
                if not isinstance(project_path, str) or not project_path.strip():
                    raise ValueError("project_path boş olmayan bir metin olmalı")
                if set(payload) != {"confirm_local", "project_path"}:
                    raise ValueError("payload fazla veya eksik alan içeriyor")
                result = run_local_gitleaks(project_path)
                return self._json(result)
            except ValueError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))
            except RuntimeError as exc:
                msg = str(exc)
                if "timeout" in msg.lower() or "timed out" in msg.lower() or "zaman aşımı" in msg.lower():
                    return self._error(HTTPStatus.BAD_GATEWAY, "Gitleaks çalıştırması zaman aşımına uğradı.")
                if "lock" in msg.lower() or "in progress" in msg.lower() or "sürüyor" in msg.lower() or "meşgul" in msg.lower() or "kilit" in msg.lower():
                    return self._error(HTTPStatus.SERVICE_UNAVAILABLE, "Başka bir Gitleaks taraması sürüyor.")
                if "ikili" in msg:
                    return self._error(HTTPStatus.SERVICE_UNAVAILABLE, msg)  # sabitleme sebebi; yol içermez
                if "binary" in msg.lower() or "ikili" in msg.lower() or "configured" in msg.lower() or "yapılandırılmamış" in msg.lower():
                    return self._error(HTTPStatus.SERVICE_UNAVAILABLE, "Gitleaks ikilisi yapılandırılmamış.")
                return self._error(HTTPStatus.BAD_GATEWAY, "Gitleaks çalıştırması başarısız oldu.")

        if path == "/api/tool-runs/osv-scanner-local":
            try:
                if not isinstance(payload, dict) or set(payload) != {"confirm_local", "project_path"}:
                    raise ValueError("Yalnız yerel onay ve project_path alanları bekleniyor.")
                if payload["confirm_local"] is not True:
                    raise ValueError("Yerel kilit dosyası için açık onay gerekli.")
                project_path = payload["project_path"]
                if not isinstance(project_path, str) or not project_path.strip():
                    raise ValueError("project_path boş olmayan bir metin olmalı.")
                return self._json(run_local_osv_scanner(project_path))
            except ValueError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))
            except (OSVUnavailable, OSVBusy):
                return self._error(HTTPStatus.SERVICE_UNAVAILABLE, "OSV-Scanner çalışma zamanı kullanılamıyor veya meşgul.")
            except OSVExecutionError:
                return self._error(HTTPStatus.BAD_GATEWAY, "OSV-Scanner çalıştırması başarısız oldu.")

        if path == "/api/tool-runs/npm-audit-local":
            try:
                if not isinstance(payload, dict) or set(payload) != {
                    "confirm_local", "confirm_registry", "project_path"
                }:
                    raise ValueError("Yalnız confirm_local, confirm_registry ve project_path bekleniyor.")
                if payload["confirm_local"] is not True or payload["confirm_registry"] is not True:
                    raise ValueError("Hem yerel dosya hem npm kayıt defteri onayı gerekli.")
                project_path = payload["project_path"]
                if not isinstance(project_path, str) or not project_path.strip():
                    raise ValueError("project_path boş olmayan bir metin olmalı.")
                return self._json(run_local_npm_audit_local(project_path))
            except ValueError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))
            except (NpmAuditUnavailable, NpmAuditBusy):
                return self._error(HTTPStatus.SERVICE_UNAVAILABLE, "npm audit çalışma zamanı kullanılamıyor veya meşgul.")
            except NpmAuditExecutionError:
                return self._error(HTTPStatus.BAD_GATEWAY, "npm audit çalıştırması başarısız oldu.")

        if path == "/api/tool-runs/trivy-npm-vulnerability":
            try:
                if not isinstance(payload, dict):
                    raise ValueError("payload bir JSON nesnesi olmalı")
                if payload.get("confirm_local") is not True:
                    raise ValueError("confirm_local tam olarak true olmalı")
                project_path = payload.get("project_path")
                if not isinstance(project_path, str) or not project_path.strip():
                    raise ValueError("project_path boş olmayan bir metin olmalı")
                if set(payload) != {"confirm_local", "project_path"}:
                    raise ValueError("payload fazla veya eksik alan içeriyor")
                return self._json(run_local_trivy_npm_vulnerability(project_path))
            except ValueError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, _sanitize_error_message(str(exc)))
            except (TrivyVulnUnavailable, TrivyVulnBusy):
                return self._error(HTTPStatus.SERVICE_UNAVAILABLE, "Trivy zafiyet tarayıcısı kullanılamıyor veya meşgul.")
            except TrivyVulnExecutionError:
                return self._error(HTTPStatus.BAD_GATEWAY, "Trivy zafiyet taraması başarısız oldu.")

        trivy_ecosystem_runners = {
            "/api/tools/trivy/go-mod": run_local_trivy_go_mod_vulnerability,
            "/api/tool-runs/trivy-go-mod-vulnerability": run_local_trivy_go_mod_vulnerability,
            "/api/tool-runs/trivy-go-mod": run_local_trivy_go_mod_vulnerability,
            "/api/tools/trivy/cargo-lock": run_local_trivy_cargo_lock_vulnerability,
            "/api/tool-runs/trivy-cargo-lock-vulnerability": run_local_trivy_cargo_lock_vulnerability,
            "/api/tool-runs/trivy-cargo-lock": run_local_trivy_cargo_lock_vulnerability,
            "/api/tools/trivy/pnpm-lock": run_local_trivy_pnpm_vulnerability,
            "/api/tool-runs/trivy-pnpm-vulnerability": run_local_trivy_pnpm_vulnerability,
            "/api/tool-runs/trivy-pnpm-lock": run_local_trivy_pnpm_vulnerability,
            "/api/tools/trivy/yarn-lock": run_local_trivy_yarn_vulnerability,
            "/api/tool-runs/trivy-yarn-vulnerability": run_local_trivy_yarn_vulnerability,
            "/api/tool-runs/trivy-yarn-lock": run_local_trivy_yarn_vulnerability,
            "/api/tools/trivy/maven-pom": run_local_trivy_maven_vulnerability,
            "/api/tool-runs/trivy-maven-vulnerability": run_local_trivy_maven_vulnerability,
            "/api/tool-runs/trivy-maven-pom": run_local_trivy_maven_vulnerability,
            "/api/tools/trivy/ruby-gemfile-lock": run_local_trivy_ruby_vulnerability,
            "/api/tool-runs/trivy-ruby-vulnerability": run_local_trivy_ruby_vulnerability,
            "/api/tool-runs/trivy-ruby-gemfile-lock": run_local_trivy_ruby_vulnerability,
        }
        if path in trivy_ecosystem_runners:
            try:
                if not isinstance(payload, dict):
                    raise ValueError("payload bir JSON nesnesi olmalı")
                if payload.get("confirm_local") is not True:
                    raise ValueError("confirm_local tam olarak true olmalı")
                project_path = payload.get("project_path")
                if not isinstance(project_path, str) or not project_path.strip():
                    raise ValueError("project_path boş olmayan bir metin olmalı")
                if set(payload) != {"confirm_local", "project_path"}:
                    raise ValueError("payload fazla veya eksik alan içeriyor")
                return self._json(trivy_ecosystem_runners[path](project_path))
            except (ProjectRejected, TrivyVulnInvalidInput, ValueError) as exc:
                return self._error(HTTPStatus.BAD_REQUEST, _sanitize_error_message(str(exc)))
            except (TrivyVulnUnavailable, TrivyVulnBusy):
                return self._error(HTTPStatus.SERVICE_UNAVAILABLE, "Trivy zafiyet tarayıcısı kullanılamıyor veya meşgul.")
            except TrivyVulnExecutionError:
                return self._error(HTTPStatus.BAD_GATEWAY, "Trivy zafiyet taraması başarısız oldu.")

        if path in ("/api/tools/gitleaks/git-history", "/api/tool-runs/gitleaks-git-history"):
            client_ip = self.client_address[0] if getattr(self, "client_address", None) else "127.0.0.1"
            try:
                if not ipaddress.ip_address(client_ip).is_loopback:
                    return self._error(HTTPStatus.FORBIDDEN, "Yalnız yerel geri dönüş adresinden izin verilir.")
            except ValueError:
                return self._error(HTTPStatus.FORBIDDEN, "Yalnız yerel geri dönüş adresinden izin verilir.")
            try:
                if not isinstance(payload, dict) or set(payload) != {"confirm_local", "project_path"}:
                    raise GitleaksGitInvalid("Yalnız confirm_local ve project_path bekleniyor.")
                if payload["confirm_local"] is not True:
                    raise GitleaksGitInvalid("confirm_local tam olarak true olmalı.")
                project_path = payload["project_path"]
                if not isinstance(project_path, str) or not project_path.strip():
                    raise GitleaksGitInvalid("project_path boş olmayan yerel bir dizin olmalı.")
                return self._json(run_local_gitleaks_git_history(project_path))
            except (ProjectRejected, ValueError, GitleaksGitInvalid):
                return self._error(
                    HTTPStatus.BAD_REQUEST,
                    "HOME altında normal bir yerel Git deposu ve açık onay gerekli.",
                )
            except (GitleaksGitUnavailable, GitleaksGitBusy):
                return self._error(
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    "Gitleaks Git geçmişi tarayıcısı kullanılamıyor veya meşgul.",
                )
            except GitleaksGitExecution:
                return self._error(HTTPStatus.BAD_GATEWAY, "Gitleaks Git geçmişi taraması başarısız oldu.")

        if path == "/api/tool-runs/trivy-vulnerability":
            try:
                if not isinstance(payload, dict):
                    raise ValueError("payload bir JSON nesnesi olmalı")
                confirm_local = payload.get("confirm_local")
                if confirm_local is not True:
                    raise ValueError("confirm_local tam olarak true olmalı")
                project_path = payload.get("project_path")
                if not isinstance(project_path, str) or not project_path.strip():
                    raise ValueError("project_path boş olmayan bir metin olmalı")
                # Reject extra fields
                allowed_keys = {"confirm_local", "project_path"}
                if set(payload.keys()) != allowed_keys:
                    raise ValueError("payload fazla veya eksik alan içeriyor")
                result = run_local_trivy_vulnerability(project_path)
                return self._json(result)
            except ValueError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))
            except (TrivyVulnUnavailable, TrivyVulnBusy):
                return self._error(HTTPStatus.SERVICE_UNAVAILABLE, "Trivy zafiyet tarayıcısı kullanılamıyor veya meşgul.")
            except TrivyVulnExecutionError:
                return self._error(HTTPStatus.BAD_GATEWAY, "Trivy zafiyet taraması başarısız oldu.")

        if path == "/api/tool-runs/trivy-image-archive-vulnerability":
            try:
                if not isinstance(payload, dict):
                    raise ValueError("payload bir JSON nesnesi olmalı")
                confirm_local = payload.get("confirm_local")
                if confirm_local is not True:
                    raise ValueError("confirm_local tam olarak true olmalı")
                project_path = payload.get("project_path")
                if not isinstance(project_path, str) or not project_path.strip():
                    raise ValueError("project_path boş olmayan bir metin olmalı")
                archive_name = payload.get("archive_name")
                if not isinstance(archive_name, str) or not archive_name.strip():
                    raise ValueError("archive_name boş olmayan bir metin olmalı")
                # Reject extra fields
                allowed_keys = {"confirm_local", "project_path", "archive_name"}
                if set(payload.keys()) != allowed_keys:
                    raise ValueError("payload fazla veya eksik alan içeriyor")
                result = run_local_trivy_image_archive_vulnerability(project_path, archive_name)
                return self._json(result)
            except ValueError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))
            except (TrivyVulnUnavailable, TrivyVulnBusy):
                return self._error(HTTPStatus.SERVICE_UNAVAILABLE, "Trivy zafiyet tarayıcısı kullanılamıyor veya meşgul.")
            except TrivyVulnExecutionError:
                return self._error(HTTPStatus.BAD_GATEWAY, "Trivy zafiyet taraması başarısız oldu.")
            except TrivyImageArchiveInvalidInput as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))

        if path == "/api/tool-runs/trivy-secret":
            try:
                if not isinstance(payload, dict):
                    raise ValueError("payload bir JSON nesnesi olmalı")
                confirm_local = payload.get("confirm_local")
                if confirm_local is not True:
                    raise ValueError("confirm_local tam olarak true olmalı")
                project_path = payload.get("project_path")
                if not isinstance(project_path, str) or not project_path.strip():
                    raise ValueError("project_path boş olmayan bir metin olmalı")
                if set(payload) != {"confirm_local", "project_path"}:
                    raise ValueError("payload fazla veya eksik alan içeriyor")
                result = run_local_trivy_secret(project_path)
                return self._json(result)
            except ValueError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))
            except RuntimeError as exc:
                msg = str(exc)
                if "timeout" in msg.lower() or "timed out" in msg.lower() or "zaman aşımı" in msg.lower():
                    return self._error(HTTPStatus.BAD_GATEWAY, "Trivy çalıştırması zaman aşımına uğradı.")
                if "lock" in msg.lower() or "in progress" in msg.lower() or "sürüyor" in msg.lower() or "meşgul" in msg.lower() or "kilit" in msg.lower():
                    return self._error(HTTPStatus.SERVICE_UNAVAILABLE, "Başka bir Trivy taraması sürüyor.")
                if "binary" in msg.lower() or "ikili" in msg.lower() or "configured" in msg.lower() or "yapılandırılmamış" in msg.lower():
                    return self._error(HTTPStatus.SERVICE_UNAVAILABLE, "Trivy ikilisi yapılandırılmamış.")
                return self._error(HTTPStatus.BAD_GATEWAY, "Trivy çalıştırılamadı.")

        if path == "/api/tool-runs/trivy-dockerfile-config":
            try:
                if not isinstance(payload, dict) or payload.get("confirm_local") is not True:
                    raise ValueError("confirm_local tam olarak true olmalı")
                project_path = payload.get("project_path")
                if not isinstance(project_path, str) or not project_path.strip():
                    raise ValueError("project_path boş olmayan yerel bir proje dizini olmalı")
                return self._json(run_local_trivy_dockerfile(project_path))
            except (ProjectRejected, ValueError) as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))
            except (TrivyConfigUnavailable, TrivyConfigBusy):
                return self._error(HTTPStatus.SERVICE_UNAVAILABLE, "Trivy yapılandırma tarayıcısı kullanılamıyor veya meşgul.")
            except TrivyConfigExecutionError:
                return self._error(HTTPStatus.BAD_GATEWAY, "Trivy yapılandırma taraması başarısız oldu.")

        if path == "/api/tool-runs/trivy-terraform-config":
            try:
                if not isinstance(payload, dict):
                    raise ValueError("payload bir sözlük olmalı")
                if set(payload.keys()) != {"confirm_local", "project_path", "terraform_file"}:
                    raise ValueError('payload anahtarları tam olarak {"confirm_local", "project_path", "terraform_file"} olmalı')
                if payload.get("confirm_local") is not True:
                    raise ValueError("confirm_local tam olarak true olmalı")
                project_path = payload.get("project_path")
                if not isinstance(project_path, str) or not project_path.strip():
                    raise ValueError("project_path boş olmayan yerel bir proje dizini olmalı")
                terraform_file = payload.get("terraform_file")
                if not isinstance(terraform_file, str) or not terraform_file.strip():
                    raise ValueError("terraform_file boş olmayan bir dosya adı olmalı")
                return self._json(run_local_trivy_terraform(project_path, terraform_file))
            except (ProjectRejected, ValueError) as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))
            except (TrivyConfigUnavailable, TrivyConfigBusy):
                return self._error(HTTPStatus.SERVICE_UNAVAILABLE, "Trivy yapılandırma tarayıcısı kullanılamıyor veya meşgul.")
            except TrivyConfigExecutionError:
                return self._error(HTTPStatus.BAD_GATEWAY, "Trivy yapılandırma taraması başarısız oldu.")

        if path in ("/api/tools/trivy/terraform-batch", "/api/tool-runs/trivy-terraform-config-batch"):
            try:
                if not isinstance(payload, dict):
                    raise ValueError("payload bir JSON nesnesi olmalı")
                if set(payload.keys()) != {"confirm_local", "project_path", "terraform_files"}:
                    raise ValueError("payload anahtarları tam olarak confirm_local, project_path, terraform_files olmalı")
                if payload.get("confirm_local") is not True:
                    raise ValueError("confirm_local tam olarak true olmalı")
                project_path = payload.get("project_path")
                if not isinstance(project_path, str) or not project_path.strip():
                    raise ValueError("project_path boş olmayan yerel bir proje dizini olmalı")
                terraform_files = payload.get("terraform_files")
                if not isinstance(terraform_files, list):
                    raise ValueError("terraform_files dosya adlarından oluşan bir liste olmalı")
                return self._json(run_local_trivy_terraform_batch(project_path, terraform_files))
            except (ProjectRejected, ValueError) as exc:
                return self._error(HTTPStatus.BAD_REQUEST, _sanitize_error_message(str(exc)))
            except (TrivyConfigUnavailable, TrivyConfigBusy, TrivyTerraformUnavailable, TrivyTerraformBusy):
                return self._error(HTTPStatus.SERVICE_UNAVAILABLE, "Trivy yapılandırma tarayıcısı kullanılamıyor veya meşgul.")
            except (TrivyConfigExecutionError, TrivyTerraformExecutionError):
                return self._error(HTTPStatus.BAD_GATEWAY, "Trivy yapılandırma taraması başarısız oldu.")

        if path == "/api/tool-runs/trivy-kubernetes-config":
            try:
                if not isinstance(payload, dict) or payload.get("confirm_local") is not True:
                    raise ValueError("confirm_local tam olarak true olmalı")
                project_path = payload.get("project_path")
                manifest_name = payload.get("manifest_name")
                if not isinstance(project_path, str) or not project_path.strip():
                    raise ValueError("project_path boş olmayan yerel bir proje dizini olmalı")
                return self._json(run_local_trivy_kubernetes(project_path, manifest_name))
            except (ProjectRejected, ValueError) as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))
            except (TrivyConfigUnavailable, TrivyConfigBusy):
                return self._error(HTTPStatus.SERVICE_UNAVAILABLE, "Trivy yapılandırma tarayıcısı kullanılamıyor veya meşgul.")
            except TrivyConfigExecutionError:
                return self._error(HTTPStatus.BAD_GATEWAY, "Trivy Kubernetes yapılandırma taraması başarısız oldu.")

        if path == "/api/tool-runs/trivy-kubernetes-config-batch":
            try:
                if not isinstance(payload, dict):
                    raise ValueError("payload bir JSON nesnesi olmalı")
                required_keys = {"confirm_local", "project_path", "manifest_names"}
                if set(payload.keys()) != required_keys:
                    raise ValueError("payload tam olarak şu anahtarları içermeli: confirm_local, project_path, manifest_names")
                if payload.get("confirm_local") is not True:
                    raise ValueError("confirm_local tam olarak true olmalı")
                project_path = payload.get("project_path")
                manifest_names = payload.get("manifest_names")
                if not isinstance(project_path, str) or not project_path.strip():
                    raise ValueError("project_path boş olmayan yerel bir proje dizini olmalı")
                if not isinstance(manifest_names, list):
                    raise ValueError("manifest_names bir liste olmalı")
                # Validate manifest_names contents before passing to batch function
                try:
                    set(manifest_names)  # triggers TypeError if unhashable items present
                except TypeError:
                    raise ValueError("manifest_names yalnız özetlenebilir öğeler içermeli")
                return self._json(run_local_trivy_kubernetes_batch(project_path, manifest_names))
            except (ProjectRejected, ValueError) as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))
            except (TrivyConfigUnavailable, TrivyConfigBusy):
                return self._error(HTTPStatus.SERVICE_UNAVAILABLE, "Trivy yapılandırma tarayıcısı kullanılamıyor veya meşgul.")
            except TrivyConfigExecutionError:
                return self._error(HTTPStatus.BAD_GATEWAY, "Trivy Kubernetes toplu taraması başarısız oldu.")

        if path == "/api/tool-runs/trufflehog-filesystem":
            try:
                if not isinstance(payload, dict):
                    raise ValueError("payload bir JSON nesnesi olmalı")
                confirm_local = payload.get("confirm_local")
                if confirm_local is not True:
                    raise ValueError("confirm_local tam olarak true olmalı")
                project_path = payload.get("project_path")
                if not isinstance(project_path, str) or not project_path.strip():
                    raise ValueError("project_path boş olmayan bir metin olmalı")
                if set(payload) != {"confirm_local", "project_path"}:
                    raise ValueError("payload fazla veya eksik alan içeriyor")
                result = run_local_trufflehog_filesystem(project_path)
                return self._json(result)
            except ValueError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))
            except RuntimeError as exc:
                msg = str(exc)
                if "timeout" in msg.lower() or "timed out" in msg.lower() or "zaman aşımı" in msg.lower():
                    return self._error(HTTPStatus.BAD_GATEWAY, "TruffleHog çalıştırması zaman aşımına uğradı.")
                if "lock" in msg.lower() or "in progress" in msg.lower() or "sürüyor" in msg.lower() or "meşgul" in msg.lower() or "kilit" in msg.lower():
                    return self._error(HTTPStatus.SERVICE_UNAVAILABLE, "Başka bir TruffleHog taraması sürüyor.")
                if "ikili" in msg:
                    return self._error(HTTPStatus.SERVICE_UNAVAILABLE, msg)  # sabitleme sebebi; yol içermez
                if "binary" in msg.lower() or "ikili" in msg.lower() or "configured" in msg.lower() or "yapılandırılmamış" in msg.lower():
                    return self._error(HTTPStatus.SERVICE_UNAVAILABLE, "TruffleHog ikilisi yapılandırılmamış.")
                return self._error(HTTPStatus.BAD_GATEWAY, "TruffleHog çalıştırması başarısız oldu.")
        if path == "/api/tool-runs/trufflehog-git-history":
            try:
                if not isinstance(payload, dict) or set(payload) != {"confirm_local", "project_path"}:
                    raise GitHistoryInvalid("Yalnız confirm_local ve project_path bekleniyor.")
                if payload["confirm_local"] is not True:
                    raise GitHistoryInvalid("confirm_local tam olarak true olmalı.")
                project_path = payload["project_path"]
                if not isinstance(project_path, str) or not project_path.strip():
                    raise GitHistoryInvalid("project_path boş olmayan yerel bir dizin olmalı.")
                return self._json(run_local_trufflehog_git_history(project_path))
            except (ProjectRejected, GitHistoryInvalid) as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))
            except (GitHistoryUnavailable, GitHistoryBusy):
                return self._error(HTTPStatus.SERVICE_UNAVAILABLE, "TruffleHog Git geçmişi tarayıcısı kullanılamıyor veya meşgul.")
            except GitHistoryExecution:
                return self._error(HTTPStatus.BAD_GATEWAY, "TruffleHog Git geçmişi taraması başarısız oldu.")

        if path == "/api/tool-reports/semgrep-native-json/summary":
            try:
                payload_report = payload.get("report")
                if not isinstance(payload_report, dict):
                    raise ValueError("report bir JSON nesnesi olmalı")
                result = parse_semgrep_native_json_summary(payload_report)
                return self._json(result)
            except ValueError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))

        if len(parts) == 6 and parts[:2] == ["api", "engagements"] and parts[3:] == ["tool-reports", "ssllabs-host", "target-preview"]:
            if not isinstance(payload, dict) or set(payload) != {"report", "confirm_host_preview"} or payload.get("confirm_host_preview") is not True:
                return self._error(HTTPStatus.BAD_REQUEST, "Açık hedef adı önizleme onayı gerekli.")
            engagement = STORE.get_engagement(parts[2])
            if not engagement:
                return self._error(HTTPStatus.NOT_FOUND, "Manuel denetim bulunamadı.")
            if engagement["status"] != "active" or not engagement["authorization_ref"].strip() or not engagement["special_approvals"].get("redacted_data_proof"):
                return self._error(HTTPStatus.FORBIDDEN, "Etkin, yetkili ve maskeli kanıt onaylı denetim gerekli.")
            try:
                report = payload["report"]
                if not isinstance(report, dict):
                    raise ValueError("Geçersiz kayıtlı rapor")
                canonical = json.dumps(report, sort_keys=True, separators=(",", ":")).encode("utf-8")
                if len(canonical) > 60_000:
                    raise ValueError("Kayıtlı rapor çok büyük")
                summary = parse_ssllabs_host_summary(report)
                target = STORE.get_target(engagement["target_id"])
                if not target:
                    raise ValueError("Hedef eksik")
                consistency = preview_ssllabs_target_name(report.get("host"), target)
                return self._json({**summary, **consistency})
            except ValueError:
                return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz SSL Labs hedef adı önizlemesi.")

        if path == "/api/tool-reports/ssllabs-host/summary":
            try:
                payload_report = payload.get("report")
                if not isinstance(payload_report, dict):
                    raise ValueError("report bir JSON nesnesi olmalı")
                result = parse_ssllabs_host_summary(payload_report)
                return self._json(result)
            except ValueError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))

        if path in ("/api/tools/ssllabs/cached-query", "/api/tool-runs/ssllabs-cached-query"):
            if not self._is_loopback_client():
                return self._error(HTTPStatus.FORBIDDEN, "Canlı SSL Labs önbellek sorgusu yalnız yerel istemciden çağrılabilir.")
            if path == "/api/tool-runs/ssllabs-cached-query":
                if not self._ssllabs_local_request_allowed():
                    return self._error(HTTPStatus.FORBIDDEN, "Canlı SSL Labs önbellek sorgusu yalnız yerel istemciden çağrılabilir.")
                auth = self.headers.get("Authorization", "")
                if not auth.startswith("Bearer ") or not operator_token_matches(auth[len("Bearer "):]):
                    return self._error(HTTPStatus.FORBIDDEN, "Geçerli yerel operatör anahtarı gerekli.")
            else:
                auth = self.headers.get("Authorization", "")
                if auth or os.environ.get("SNIPER_SSLLABS_OPERATOR_TOKEN_SHA256", "").strip():
                    if not auth.startswith("Bearer ") or not operator_token_matches(auth[len("Bearer "):]):
                        return self._error(HTTPStatus.FORBIDDEN, "Geçerli yerel operatör anahtarı gerekli.")

            if not isinstance(payload, dict):
                return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz SSL Labs önbellek sorgu isteği.")

            if "hostname" in payload and "engagement_id" not in payload and path == "/api/tools/ssllabs/cached-query":
                if set(payload) != {"hostname", "confirm_qualys"} or payload.get("confirm_qualys") is not True:
                    return self._error(HTTPStatus.BAD_REQUEST, "Açık Qualys önbellek sorgu onayı ve geçerli hedef gerekli.")
                try:
                    hostname = normalize_public_hostname(payload.get("hostname"))
                except ValueError:
                    return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz veya genel olmayan TLS hedefi.")
                if not live_query_enabled():
                    return self._error(HTTPStatus.SERVICE_UNAVAILABLE, "Canlı SSL Labs önbellek sorgusu etkin değil.")
                try:
                    return self._json(run_ssllabs_cached_query(hostname))
                except SSLLabsBusy:
                    return self._error(HTTPStatus.CONFLICT, "SSL Labs önbellek sorgusu bekleme süresinde veya çalışıyor.")
                except SSLLabsUnavailable:
                    return self._error(HTTPStatus.SERVICE_UNAVAILABLE, "Canlı SSL Labs önbellek sorgusu kullanılamıyor.")
                except SSLLabsUpstreamError as exc:
                    return self._error(exc.status, "SSL Labs üst servisi önbellek sorgusunu reddetti veya hazır önbellek yok.")
                except SSLLabsInvalidResponse:
                    return self._error(HTTPStatus.BAD_GATEWAY, "SSL Labs üst servis yanıtı doğrulanamadı.")

            if set(payload) not in ({"engagement_id", "confirm_qualys"}, {"target_id", "engagement_id", "confirm_qualys"}):
                return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz SSL Labs önbellek sorgu isteği.")
            engagement_id = payload.get("engagement_id")
            if (
                not isinstance(engagement_id, str)
                or not engagement_id.strip()
                or len(engagement_id.strip()) > 80
                or payload.get("confirm_qualys") is not True
            ):
                return self._error(HTTPStatus.BAD_REQUEST, "Açık Qualys önbellek sorgu onayı ve geçerli denetim kimliği gerekli.")
            engagement = STORE.get_engagement(engagement_id.strip())
            if not engagement:
                return self._error(HTTPStatus.NOT_FOUND, "Manuel denetim bulunamadı.")
            if "target_id" in payload and payload.get("target_id") != engagement.get("target_id"):
                return self._error(HTTPStatus.FORBIDDEN, "Engagement hedefle eşleşmiyor.")
            target = STORE.get_target(str(engagement.get("target_id") or ""))
            if not target:
                return self._error(HTTPStatus.NOT_FOUND, "Hedef bulunamadı.")
            if (
                engagement.get("status") != "active"
                or not str(engagement.get("authorization_ref") or "").strip()
                or not str(engagement.get("scope_notes") or "").strip()
                or target.get("scheme") != "https"
                or int(target.get("port") or 0) != 443
            ):
                return self._error(HTTPStatus.FORBIDDEN, "Etkin, yetkili ve kapsamlı bir HTTPS:443 denetimi gerekli.")
            try:
                hostname = normalize_public_hostname(target.get("hostname"))
            except ValueError:
                return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz veya genel olmayan TLS hedefi.")
            target_id = str(target["id"])
            audit_meta = {"engagement_id": engagement["id"], "hostname": hostname}
            if not live_query_enabled():
                STORE.log("ssllabs.cached_query.unavailable", target_id, audit_meta)
                return self._error(HTTPStatus.SERVICE_UNAVAILABLE, "Canlı SSL Labs önbellek sorgusu etkin değil.")
            STORE.log("ssllabs.cached_query.started", target_id, audit_meta)
            try:
                summary = run_ssllabs_cached_query(hostname)
            except SSLLabsBusy:
                STORE.log("ssllabs.cached_query.busy", target_id, audit_meta)
                return self._error(HTTPStatus.CONFLICT, "SSL Labs önbellek sorgusu bekleme süresinde veya çalışıyor.")
            except SSLLabsUnavailable:
                STORE.log("ssllabs.cached_query.unavailable", target_id, audit_meta)
                return self._error(HTTPStatus.SERVICE_UNAVAILABLE, "Canlı SSL Labs önbellek sorgusu kullanılamıyor.")
            except SSLLabsUpstreamError as exc:
                STORE.log("ssllabs.cached_query.upstream_error", target_id, {**audit_meta, "status": exc.status})
                return self._error(exc.status, "SSL Labs üst servisi önbellek sorgusunu reddetti veya hazır önbellek yok.")
            except SSLLabsInvalidResponse:
                STORE.log("ssllabs.cached_query.invalid_response", target_id, audit_meta)
                return self._error(HTTPStatus.BAD_GATEWAY, "SSL Labs üst servis yanıtı doğrulanamadı.")
            STORE.log(
                "ssllabs.cached_query.completed",
                target_id,
                {
                    **audit_meta,
                    "assessment_status": summary.get("assessment_status", "READY"),
                    "endpoint_count": summary.get("endpoint_count", 0),
                },
            )
            return self._json(summary)

        if path == "/api/tool-runs/ssllabs-authorized":
            if not self._ssllabs_local_request_allowed():
                return self._error(
                    HTTPStatus.FORBIDDEN,
                    "Canlı SSL Labs değerlendirmesi yalnız yerel istemciden çağrılabilir.",
                )
            if not isinstance(payload, dict) or set(payload) != {"target", "confirm_authorized"}:
                return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz doğrudan SSL Labs isteği.")
            if payload.get("confirm_authorized") is not True:
                return self._error(
                    HTTPStatus.FORBIDDEN,
                    "Hedef yetkisi ve Qualys SSL Labs üçüncü taraf aktarımı için açık insan onayı gerekli.",
                )
            try:
                hostname = validate_ssllabs_hostname(normalize_public_hostname(payload.get("target")))
            except (SSLLabsLiveInvalid, ValueError):
                return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz veya genel olmayan TLS hedefi.")
            raw_email = (
                os.environ.get("SNIPER_SSLLABS_EMAIL", "").strip()
                or os.environ.get("SNIPER_SSLLABS_REGISTERED_EMAIL", "").strip()
            )
            try:
                email = validate_registered_email(raw_email)
            except (SSLLabsLiveInvalid, ValueError):
                return self._error(
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    "Kayıtlı SSL Labs kurum e-postası yapılandırılmamış.",
                )
            if os.environ.get("SNIPER_SSLLABS_LIVE_ENABLED") != "true":
                return self._error(HTTPStatus.SERVICE_UNAVAILABLE, "Canlı SSL Labs değerlendirmesi etkin değil.")
            receipt = _ssllabs_authorization_receipt(hostname)
            target_sha256 = hashlib.sha256(hostname.encode("ascii")).hexdigest()
            STORE.log(
                "ssllabs.direct_authorized.started",
                target_sha256,
                {"authorization_receipt": receipt},
            )
            try:
                summary = run_ssllabs_live(hostname, email)
            except SSLLabsLiveBusy:
                STORE.log("ssllabs.direct_authorized.busy", target_sha256, {"authorization_receipt": receipt})
                return self._error(HTTPStatus.CONFLICT, "SSL Labs canlı sorgusu bekleme süresinde veya çalışıyor.")
            except SSLLabsLiveRateLimited:
                STORE.log(
                    "ssllabs.direct_authorized.rate_limited",
                    target_sha256,
                    {"authorization_receipt": receipt},
                )
                return self._error(HTTPStatus.TOO_MANY_REQUESTS, "SSL Labs hız sınırına ulaşıldı.")
            except SSLLabsLiveUnavailable:
                STORE.log(
                    "ssllabs.direct_authorized.unavailable",
                    target_sha256,
                    {"authorization_receipt": receipt},
                )
                return self._error(HTTPStatus.SERVICE_UNAVAILABLE, "Canlı SSL Labs servisi kullanılamıyor.")
            except SSLLabsLiveUpstreamError:
                STORE.log(
                    "ssllabs.direct_authorized.upstream_error",
                    target_sha256,
                    {"authorization_receipt": receipt},
                )
                return self._error(HTTPStatus.BAD_GATEWAY, "SSL Labs canlı yanıtı doğrulanamadı.")
            STORE.log(
                "ssllabs.direct_authorized.completed",
                target_sha256,
                {
                    "authorization_receipt": receipt,
                    "assessment_status": summary.get("assessment_status"),
                    "endpoint_count": summary.get("endpoint_count"),
                },
            )
            return self._json({**summary, "authorization_receipt": receipt})

        if path in ("/api/tool-runs/ssllabs-live/prepare", "/api/tools/ssllabs/live/prepare"):
            if not self._ssllabs_local_request_allowed():
                return self._error(HTTPStatus.FORBIDDEN, "Canlı SSL Labs hazırlığı yalnız yerel istemciden çağrılabilir.")
            auth = self.headers.get("Authorization", "")
            if auth or os.environ.get("SNIPER_SSLLABS_OPERATOR_TOKEN_SHA256", "").strip():
                if not auth.startswith("Bearer ") or not operator_token_matches(auth[len("Bearer "):]):
                    return self._error(HTTPStatus.FORBIDDEN, "Geçerli yerel operatör anahtarı gerekli.")
            if not isinstance(payload, dict) or set(payload) != {"target_id", "engagement_id"}:
                return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz SSL Labs canlı hazırlık isteği.")
            target_id = payload.get("target_id")
            engagement_id = payload.get("engagement_id")
            if (
                not isinstance(target_id, str)
                or not target_id.strip()
                or len(target_id.strip()) > 80
                or not isinstance(engagement_id, str)
                or not engagement_id.strip()
                or len(engagement_id.strip()) > 80
            ):
                return self._error(HTTPStatus.BAD_REQUEST, "Geçerli hedef ve denetim kimliği gerekli.")
            target = STORE.get_target(target_id.strip())
            engagement = STORE.get_engagement(engagement_id.strip())
            if not target or not engagement:
                return self._error(HTTPStatus.NOT_FOUND, "Hedef veya manuel denetim bulunamadı.")
            if (
                engagement.get("target_id") != target.get("id")
                or engagement.get("status") != "active"
                or not str(engagement.get("authorization_ref") or "").strip()
                or not str(engagement.get("scope_notes") or "").strip()
                or not _active_test_window_valid(engagement)
            ):
                return self._error(HTTPStatus.FORBIDDEN, "Etkin, yetkili ve geçerli test pencereli denetim gerekli.")
            raw_email = (
                os.environ.get("SNIPER_SSLLABS_EMAIL", "").strip()
                or os.environ.get("SNIPER_SSLLABS_REGISTERED_EMAIL", "").strip()
            )
            try:
                hostname = validate_stored_tls_target(target)
                email = validate_registered_email(raw_email)
            except (SSLLabsLiveInvalid, ValueError):
                return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz TLS hedefi veya SSL Labs e-posta yapılandırması.")
            if os.environ.get("SNIPER_SSLLABS_LIVE_ENABLED") != "true":
                return self._error(HTTPStatus.SERVICE_UNAVAILABLE, "Canlı SSL Labs taraması etkin değil.")
            try:
                info = fetch_ssllabs_info(email)
            except SSLLabsLiveBusy:
                return self._error(HTTPStatus.CONFLICT, "SSL Labs canlı sorgusu bekleme süresinde veya çalışıyor.")
            except SSLLabsLiveRateLimited:
                return self._error(HTTPStatus.TOO_MANY_REQUESTS, "SSL Labs hız sınırına ulaşıldı.")
            except SSLLabsLiveUnavailable:
                return self._error(HTTPStatus.SERVICE_UNAVAILABLE, "Canlı SSL Labs servisi kullanılamıyor.")
            except SSLLabsLiveUpstreamError:
                return self._error(HTTPStatus.BAD_GATEWAY, "SSL Labs info yanıtı doğrulanamadı.")
            return self._json({**info, "host": hostname})

        if path in ("/api/tool-runs/ssllabs-live", "/api/tools/ssllabs/live"):
            if not self._ssllabs_local_request_allowed():
                return self._error(HTTPStatus.FORBIDDEN, "Canlı SSL Labs taraması yalnız yerel istemciden çağrılabilir.")
            auth = self.headers.get("Authorization", "")
            if auth or os.environ.get("SNIPER_SSLLABS_OPERATOR_TOKEN_SHA256", "").strip():
                if not auth.startswith("Bearer ") or not operator_token_matches(auth[len("Bearer "):]):
                    return self._error(HTTPStatus.FORBIDDEN, "Geçerli yerel operatör anahtarı gerekli.")
            if not isinstance(payload, dict) or not set(payload).issubset(
                {"target_id", "engagement_id", "confirm_authorized", "confirm_qualys_notice", "confirm_third_party"}
            ):
                return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz SSL Labs canlı tarama isteği.")
            if (
                payload.get("confirm_authorized") is not True
                or payload.get("confirm_qualys_notice") is not True
                or payload.get("confirm_third_party") is not True
            ):
                return self._error(HTTPStatus.BAD_REQUEST, "Açık yetki ve üçüncü taraf onayları gerekli.")
            target_id = payload.get("target_id")
            engagement_id = payload.get("engagement_id")
            if (
                not isinstance(target_id, str)
                or not target_id.strip()
                or len(target_id.strip()) > 80
                or not isinstance(engagement_id, str)
                or not engagement_id.strip()
                or len(engagement_id.strip()) > 80
            ):
                return self._error(HTTPStatus.BAD_REQUEST, "Geçerli hedef ve denetim kimliği gerekli.")
            target = STORE.get_target(target_id.strip())
            engagement = STORE.get_engagement(engagement_id.strip())
            if not target or not engagement:
                return self._error(HTTPStatus.NOT_FOUND, "Hedef veya manuel denetim bulunamadı.")
            if (
                engagement.get("target_id") != target.get("id")
                or engagement.get("status") != "active"
                or not str(engagement.get("authorization_ref") or "").strip()
                or not str(engagement.get("scope_notes") or "").strip()
                or not _active_test_window_valid(engagement)
            ):
                return self._error(HTTPStatus.FORBIDDEN, "Etkin, yetkili ve geçerli test pencereli denetim gerekli.")
            raw_email = (
                os.environ.get("SNIPER_SSLLABS_EMAIL", "").strip()
                or os.environ.get("SNIPER_SSLLABS_REGISTERED_EMAIL", "").strip()
            )
            try:
                hostname = validate_stored_tls_target(target)
                email = validate_registered_email(raw_email)
            except (SSLLabsLiveInvalid, ValueError):
                return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz TLS hedefi veya SSL Labs e-posta yapılandırması.")
            if os.environ.get("SNIPER_SSLLABS_LIVE_ENABLED") != "true":
                return self._error(HTTPStatus.SERVICE_UNAVAILABLE, "Canlı SSL Labs taraması etkin değil.")
            try:
                return self._json(run_ssllabs_live(hostname, email))
            except SSLLabsLiveBusy:
                return self._error(HTTPStatus.CONFLICT, "SSL Labs canlı sorgusu bekleme süresinde veya çalışıyor.")
            except SSLLabsLiveRateLimited:
                return self._error(HTTPStatus.TOO_MANY_REQUESTS, "SSL Labs hız sınırına ulaşıldı.")
            except SSLLabsLiveUnavailable:
                return self._error(HTTPStatus.SERVICE_UNAVAILABLE, "Canlı SSL Labs servisi kullanılamıyor.")
            except SSLLabsLiveUpstreamError:
                return self._error(HTTPStatus.BAD_GATEWAY, "SSL Labs canlı yanıtı doğrulanamadı.")

        if path == "/api/tool-runs/openssl-x509-loopback":
            try:
                if not isinstance(payload, dict) or set(payload) != {"confirm_local", "target"} or payload.get("confirm_local") is not True:
                    raise ValueError("Açık yerel onay ve hedef gerekli")
                return self._json(run_openssl_x509_loopback(payload["target"]))
            except ValueError:
                return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz yerel TLS hedefi veya onayı.")
            except (OpenSSLUnavailable, OpenSSLBusy):
                return self._error(HTTPStatus.SERVICE_UNAVAILABLE, "Yerel TLS doğrulaması kullanılamıyor.")
            except OpenSSLExecutionError:
                return self._error(HTTPStatus.BAD_GATEWAY, "Yerel TLS doğrulaması başarısız.")

        if path == "/api/tool-runs/openssl-x509-authorized":
            try:
                if (not isinstance(payload, dict)
                        or set(payload) != {"confirm_authorized", "target"}
                        or payload.get("confirm_authorized") is not True):
                    raise ValueError("Açık yetki beyanı ve hedef gerekli")
                result = run_openssl_x509_authorized(payload["target"])
            except ValueError:
                return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz yetkili HTTPS hedefi veya yetki beyanı.")
            except (OpenSSLUnavailable, OpenSSLBusy):
                return self._error(HTTPStatus.SERVICE_UNAVAILABLE, "Yetkili TLS doğrulaması kullanılamıyor.")
            except OpenSSLExecutionError:
                return self._error(HTTPStatus.BAD_GATEWAY, "Yetkili TLS doğrulaması başarısız.")
            actor = request_context.actor_summary(request_context.current_actor()) or {
                "id": "local-operator", "username": "local-operator", "role": "local",
            }
            STORE.log(
                "openssl_x509.authorized.completed",
                "openssl-x509-authorized",
                {
                    "actor": actor,
                    "normalized_target": result["normalized_target"],
                    "consent_version": OPENSSL_AUTHORIZED_CONSENT_VERSION,
                    "verification": result["verification"],
                    **({"report_sha256": result["report_sha256"]} if "report_sha256" in result else {}),
                },
            )
            return self._json(result)

        if path == "/api/sandbox-targets":
            return self._sandbox_targets_post(payload)

        if path.startswith("/api/finding-tracking/"):
            return self._finding_tracking_post(path, payload)
        if path.startswith("/api/ai-triage/"):
            return self._ai_triage_post(path, payload)
        if path in ("/api/schedules", "/api/notifications", "/api/notification-settings"):
            return self._ops_post(path, payload)

        if path == "/api/scan-scope":
            # Proje yolu alan tüm yerel taramaların varsayılan kapsamı; istek başına "scope" alanı bunu geçersiz kılar.
            if payload.get("confirm") is not True or not set(payload) <= {"confirm", "scope"}:
                return self._error(HTTPStatus.BAD_REQUEST, "Kapsam değişikliği için yalnız confirm: true ve scope alanları kullanılabilir.")
            try:
                parsed = scan_scope.parse_scope(payload.get("scope"))
                if parsed.skipped_only or parsed.changed_only:
                    raise scan_scope.ScopeError("Yalnız atlananlar / yalnız değişenler modu varsayılan yapılamaz; analiz başlatırken tek seferlik seçilir.")
                scope = scan_scope.save_default(parsed)
            except scan_scope.ScopeError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))
            except OSError:
                return self._error(HTTPStatus.INTERNAL_SERVER_ERROR, "Kapsam ayarı kaydedilemedi.")
            STORE.log("scan_scope.changed", "default", scope.public())
            return self._json({"scope": scope.public(), "is_default": scope.is_default, **scan_scope.describe()})

        if path in ("/api/portfolio/sla-policy", "/api/portfolio/sla-policy/apply"):
            return self._portfolio_post(path, payload)

        if path in ("/api/system/backups", "/api/system/retention/policy", "/api/system/retention/run"):
            return self._retention_post(path, payload)

        if path == "/api/license-policy":
            # Bağımlılık lisans politikası (izinli / dikkat / yasak); yönetici, onaylı. reset: varsayılana dön.
            if payload.get("confirm") is not True or not set(payload) <= {"confirm", "policy", "reset"} \
                    or ("policy" in payload) == (payload.get("reset") is True):
                return self._error(HTTPStatus.BAD_REQUEST, "confirm: true ile ya policy ya da reset: true gönderin.")
            try:
                if payload.get("reset") is True:
                    policy = license_compliance.reset_policy()
                else:
                    policy = license_compliance.save_policy(payload.get("policy"))
            except license_compliance.LicensePolicyError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))
            except ops_files.OpsStoreError as exc:
                return self._error(HTTPStatus.SERVICE_UNAVAILABLE, str(exc))
            STORE.log("license_policy.changed", "license-policy", {
                "reset": payload.get("reset") is True,
                **{key: len(policy[key]) for key in ("allowed", "caution", "denied")},
            })
            return self._json(_license_policy_payload())

        if path in ("/api/tool-runs/k6-sandbox", "/api/tool-runs/schemathesis-sandbox", "/api/tool-runs/playwright-sandbox"):
            runner = {"k6-sandbox": run_k6_sandbox, "schemathesis-sandbox": run_schemathesis_sandbox,
                      "playwright-sandbox": run_playwright_sandbox}[path.rsplit("/", 1)[-1]]
            try:
                result = runner(payload)
            except sandbox_targets.ScopeDisabled as exc:
                return self._error(HTTPStatus.FORBIDDEN, str(exc))
            except ValueError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))
            except SandboxBusy:
                return self._error(HTTPStatus.CONFLICT, "Bu araç için başka bir yalıtılmış çalıştırma sürüyor.")
            except SandboxUnavailable as exc:
                return self._error(HTTPStatus.SERVICE_UNAVAILABLE, f"Yalıtılmış test çalışma zamanı kullanılamıyor ({exc}).")
            except SandboxExecutionError as exc:
                return self._error(HTTPStatus.BAD_GATEWAY, f"Yalıtılmış test tamamlanamadı ({exc}).")
            STORE.log("sandbox_run.completed", path.rsplit("/", 1)[-1],
                      {"target": result.get("target"), "preset": result.get("preset"), "relay": result.get("relay"),
                       **({"findings": len(result["findings"])} if "findings" in result else {})})
            return self._json(result)

        if path in ("/api/tool-runs/k6-authorized", "/api/tool-runs/schemathesis-authorized"):
            if not isinstance(payload, dict) or payload.get("confirm_authorized") is not True:
                return self._error(HTTPStatus.BAD_REQUEST, "confirm_authorized tam olarak true olmalı.")
            runner = {
                "/api/tool-runs/k6-authorized": run_k6_authorized,
                "/api/tool-runs/schemathesis-authorized": run_schemathesis_authorized,
            }[path]
            actor = request_context.current_actor() or {"username": "yerel"}
            confirmed_at = utc_now()
            try:
                result = runner(payload)
            except ValueError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))
            except SandboxBusy:
                return self._error(HTTPStatus.CONFLICT, "Bu araç için başka bir yetkili hedef çalıştırması sürüyor.")
            except SandboxUnavailable as exc:
                return self._error(HTTPStatus.SERVICE_UNAVAILABLE,
                                   f"Yetkili hedef çalışma zamanı kullanılamıyor ({exc}).")
            except SandboxExecutionError as exc:
                return self._error(HTTPStatus.BAD_GATEWAY,
                                   f"Yetkili hedef çalıştırması tamamlanamadı ({exc}).")
            receipt = {
                "actor": str(actor.get("username") or "yerel"),
                "confirmed_at": confirmed_at,
                "consent_version": AUTHORIZED_TARGET_CONSENT_VERSION,
                "normalized_target": result["normalized_target"],
            }
            tool = "k6" if path.endswith("k6-authorized") else "schemathesis"
            STORE.log("authorized_tool_run.completed", tool, {
                **receipt,
                "format": result.get("format"),
                "relay": result.get("relay"),
            })
            return self._json({**result, "authorization_receipt": receipt})

        if path == "/api/tool-runs/playwright-authorized":
            try:
                params = authorized_params(payload)
            except ValueError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))
            actor = request_context.current_actor() or {
                "id": "local-admin", "username": "yerel", "role": "admin",
            }
            receipt = authorization_receipt(params, actor)
            # Onay kaydı koşudan önce kalıcılaşır. Kayıt başarısızsa tarayıcı hiç başlatılmaz.
            STORE.log("playwright_authorized.consent", receipt["run_id"], receipt)
            try:
                result = run_playwright_authorized(payload)
            except SandboxBusy:
                STORE.log("playwright_authorized.busy", receipt["run_id"], receipt)
                return self._json({"error": "Başka bir yetkili Playwright koşusu sürüyor.",
                                   "status": int(HTTPStatus.CONFLICT), "authorization_receipt": receipt},
                                  status=HTTPStatus.CONFLICT)
            except SandboxUnavailable as exc:
                STORE.log("playwright_authorized.unavailable", receipt["run_id"],
                          {**receipt, "prerequisite": str(exc)})
                return self._json({"error": f"Yetkili Playwright çalışma zamanı kullanılamıyor ({exc}).",
                                   "status": int(HTTPStatus.SERVICE_UNAVAILABLE),
                                   "authorization_receipt": receipt}, status=HTTPStatus.SERVICE_UNAVAILABLE)
            except SandboxExecutionError as exc:
                STORE.log("playwright_authorized.failed", receipt["run_id"],
                          {**receipt, "failure": str(exc)})
                return self._json({"error": "Yetkili Playwright koşusu güvenli biçimde tamamlanamadı.",
                                   "status": int(HTTPStatus.BAD_GATEWAY), "authorization_receipt": receipt},
                                  status=HTTPStatus.BAD_GATEWAY)
            STORE.log("playwright_authorized.completed", receipt["run_id"], {
                **receipt, "finding_count": len(result.get("findings") or []),
                "relay": result.get("relay"), "cleanup": result.get("cleanup"),
            })
            return self._json({**result, "authorization_receipt": receipt})

        if path == "/api/tool-runs/qa-broker-probe":
            try:
                if not isinstance(payload, dict) or set(payload) != {"confirm_local", "operation"} or payload.get("confirm_local") is not True:
                    raise ValueError("Açık yerel onay ve işlem gerekli")
                return self._json(qa_broker_client.run_qa_broker_probe(payload["operation"]))
            except ValueError:
                return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz QA aracısı işlemi veya onayı.")
            except qa_broker_client.QABrokerBusy:
                return self._error(HTTPStatus.CONFLICT, "Başka bir QA aracısı isteği sürüyor.")
            except qa_broker_client.QABrokerUnavailable:
                return self._error(HTTPStatus.SERVICE_UNAVAILABLE, "Host QA aracısı kullanılamıyor.")
            except qa_broker_client.QABrokerError:
                return self._error(HTTPStatus.BAD_GATEWAY, "Host QA aracısı yanıtı doğrulanamadı.")

        if path == "/api/tool-reports/openssl-x509/summary":
            try:
                return self._json(parse_openssl_x509_summary(payload.get("report")))
            except ValueError:
                return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz OpenSSL x509 raporu.")

        if path == "/api/tool-reports/openssl-x509/batch-summary":
            try:
                if set(payload.keys()) != {"reports"}:
                    raise ValueError("Geçersiz OpenSSL x509 rapor grubu.")
                raw_reports = payload.get("reports")
                if not isinstance(raw_reports, list):
                    raise ValueError("Geçersiz OpenSSL x509 rapor grubu.")
                if len(raw_reports) < 1 or len(raw_reports) > 8:
                    raise ValueError("Geçersiz OpenSSL x509 rapor grubu.")
                reports = [r for r in raw_reports if isinstance(r, str)]
                if len(reports) != len(raw_reports):
                    raise ValueError("Geçersiz OpenSSL x509 rapor grubu.")
                if not isinstance(reports, list):
                    raise ValueError("Geçersiz OpenSSL x509 rapor grubu.")
                return self._json(parse_openssl_x509_batch_summary(reports))
            except ValueError:
                return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz OpenSSL x509 rapor grubu.")

        if path == "/api/tool-reports/burp-sitemap/summary":
            try:
                payload_report = payload.get("report")
                if not isinstance(payload_report, str):
                    raise ValueError("report bir metin olmalı")
                result = parse_burp_sitemap_summary(payload_report)
                return self._json(result)
            except ValueError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz istek.")

        if len(parts) == 5 and parts[:2] == ["api", "engagements"] and parts[3:] == ["tool-evidence", "burp-sitemap-xml"]:
            if not isinstance(payload, dict) or set(payload) != {"control_id", "report", "confirm_link"} or payload.get("confirm_link") is not True:
                return self._error(HTTPStatus.BAD_REQUEST, "Açık kanıt bağlama onayı gerekli.")
            engagement = STORE.get_engagement(parts[2])
            if not engagement:
                return self._error(HTTPStatus.NOT_FOUND, "Manuel denetim bulunamadı.")
            if engagement["status"] != "active" or not engagement["authorization_ref"].strip() or not engagement["special_approvals"].get("redacted_data_proof"):
                return self._error(HTTPStatus.FORBIDDEN, "Etkin, yetkili ve maskeli kanıt onaylı denetim gerekli.")
            try:
                control_id = clean_text(payload, "control_id", maximum=80, required=True)
                report = payload["report"]
                if not isinstance(report, str):
                    raise ValueError("Geçersiz Burp Site-map XML raporu.")
                summary = parse_burp_sitemap_summary(report)
                linked, created = STORE.add_burp_sitemap_tool_evidence(parts[2], control_id, summary)
                return self._json(linked, status=HTTPStatus.CREATED if created else HTTPStatus.OK)
            except ValueError:
                return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz Burp Site-map XML kanıtı veya test adımı.")

        if path == "/api/tool-reports/nmap/summary":
            try:
                payload_report = payload.get("report")
                if not isinstance(payload_report, str):
                    raise ValueError("report bir metin olmalı")
                result = parse_nmap_inline_summary(payload_report)
                return self._json(result)
            except ValueError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz istek.")

        if len(parts) == 5 and parts[:2] == ["api", "engagements"] and parts[3:] == ["tool-evidence", "trivy-native-json"]:
            if set(payload) != {"control_id", "report", "confirm_link"} or payload.get("confirm_link") is not True:
                return self._error(HTTPStatus.BAD_REQUEST, "Açık kanıt bağlama onayı gerekli.")
            engagement = STORE.get_engagement(parts[2])
            if not engagement:
                return self._error(HTTPStatus.NOT_FOUND, "Manuel denetim bulunamadı.")
            if engagement["status"] != "active" or not engagement["authorization_ref"].strip() or not engagement["special_approvals"].get("redacted_data_proof"):
                return self._error(HTTPStatus.FORBIDDEN, "Etkin, yetkili ve maskeli kanıt onaylı denetim gerekli.")
            try:
                control_id = clean_text(payload, "control_id", maximum=80, required=True)
                report = payload["report"]
                if not isinstance(report, dict):
                    raise ValueError("Geçersiz rapor")
                summary = parse_trivy_native_json_summary(report)
                linked, created = STORE.add_trivy_tool_evidence(parts[2], control_id, summary)
                return self._json(linked, status=HTTPStatus.CREATED if created else HTTPStatus.OK)
            except ValueError:
                return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz Trivy kanıtı veya test adımı.")

        if len(parts) == 5 and parts[:2] == ["api", "engagements"] and parts[3] == "tool-evidence" and parts[4] in {
            "sarif",
            "semgrep-native-json",
            "trufflehog-json",
            "npm-audit-v2",
            "dependabot-alerts",
            "ssllabs-host",
            "openssl-x509",
            "playwright-json",
            "k6-summary-json",
            "k6-machine-summary-v1",
            "schemathesis-junit",
            "siem-ecs-ndjson",
        }:
            slug = parts[4]
            if not isinstance(payload, dict) or payload.get("confirm_link") is not True:
                return self._error(HTTPStatus.BAD_REQUEST, "Açık kanıt bağlama onayı gerekli.")
            allowed_key_sets = {
                "sarif": ({"control_id", "sarif", "confirm_link"}, {"control_id", "report", "confirm_link"}),
                "npm-audit-v2": ({"control_id", "audit", "confirm_link"}, {"control_id", "report", "confirm_link"}),
                "dependabot-alerts": ({"control_id", "alerts", "confirm_link"}, {"control_id", "report", "confirm_link"}),
            }.get(slug, ({"control_id", "report", "confirm_link"},))
            if set(payload) not in allowed_key_sets:
                return self._error(HTTPStatus.BAD_REQUEST, "Açık kanıt bağlama onayı gerekli.")
            engagement = STORE.get_engagement(parts[2])
            if not engagement:
                return self._error(HTTPStatus.NOT_FOUND, "Manuel denetim bulunamadı.")
            if (
                engagement["status"] != "active"
                or not engagement["authorization_ref"].strip()
                or not engagement["special_approvals"].get("redacted_data_proof")
            ):
                return self._error(HTTPStatus.FORBIDDEN, "Etkin, yetkili ve maskeli kanıt onaylı denetim gerekli.")
            try:
                control_id = clean_text(payload, "control_id", maximum=80, required=True)
                if slug == "sarif":
                    raw_report = payload.get("sarif") if "sarif" in payload else payload.get("report")
                    if not isinstance(raw_report, dict):
                        raise ValueError("Geçersiz SARIF raporu")
                    canonical = json.dumps(raw_report, sort_keys=True, separators=(",", ":")).encode("utf-8")
                    if len(canonical) > 60_000:
                        raise ValueError("Rapor çok büyük")
                    summary = parse_sarif_summary(raw_report)
                    tool_identity, note_label = "sarif", "SARIF 2.1.0"
                elif slug == "semgrep-native-json":
                    raw_report = payload["report"]
                    if not isinstance(raw_report, dict):
                        raise ValueError("Geçersiz Semgrep raporu")
                    canonical = json.dumps(raw_report, sort_keys=True, separators=(",", ":")).encode("utf-8")
                    if len(canonical) > 60_000:
                        raise ValueError("Rapor çok büyük")
                    summary = parse_semgrep_native_json_summary(raw_report)
                    tool_identity, note_label = "semgrep-native-json", "Semgrep JSON"
                elif slug == "trufflehog-json":
                    raw_report = payload["report"]
                    if not isinstance(raw_report, list):
                        raise ValueError("Geçersiz TruffleHog raporu")
                    canonical = json.dumps(raw_report, sort_keys=True, separators=(",", ":")).encode("utf-8")
                    if len(canonical) > 60_000:
                        raise ValueError("Rapor çok büyük")
                    summary = parse_trufflehog_json_summary(raw_report)
                    summary["report_sha256"] = hashlib.sha256(canonical).hexdigest()
                    tool_identity, note_label = "trufflehog-native-json-records", "TruffleHog JSONL"
                elif slug == "npm-audit-v2":
                    raw_report = payload.get("audit") if "audit" in payload else payload.get("report")
                    if not isinstance(raw_report, dict):
                        raise ValueError("Geçersiz npm audit raporu")
                    canonical = json.dumps(raw_report, sort_keys=True, separators=(",", ":")).encode("utf-8")
                    if len(canonical) > 60_000:
                        raise ValueError("Rapor çok büyük")
                    summary = parse_npm_audit_v2_summary(raw_report)
                    tool_identity, note_label = "npm-audit-v2", "npm audit v2 JSON"
                elif slug == "dependabot-alerts":
                    if "alerts" in payload:
                        dep_payload = {"alerts": payload["alerts"]}
                    else:
                        raw_rep = payload.get("report")
                        dep_payload = {"alerts": raw_rep} if isinstance(raw_rep, list) else raw_rep
                    if not isinstance(dep_payload, dict):
                        raise ValueError("Geçersiz Dependabot uyarı raporu")
                    canonical = json.dumps(dep_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
                    if len(canonical) > 60_000:
                        raise ValueError("Rapor çok büyük")
                    summary = parse_dependabot_alerts_summary(dep_payload)
                    tool_identity, note_label = "dependabot-alerts", "Dependabot JSON"
                elif slug == "ssllabs-host":
                    raw_report = payload["report"]
                    if not isinstance(raw_report, dict):
                        raise ValueError("Geçersiz SSL Labs raporu")
                    canonical = json.dumps(raw_report, sort_keys=True, separators=(",", ":")).encode("utf-8")
                    if len(canonical) > 60_000:
                        raise ValueError("Rapor çok büyük")
                    summary = parse_ssllabs_host_summary(raw_report)
                    tool_identity, note_label = "ssllabs-v4-host", "SSL Labs Host JSON"
                elif slug == "openssl-x509":
                    raw_report = payload["report"]
                    if not isinstance(raw_report, str):
                        raise ValueError("Geçersiz OpenSSL x509 raporu")
                    summary = parse_openssl_x509_summary(raw_report)
                    tool_identity, note_label = "openssl-x509-dates-fingerprint-v1", "OpenSSL x509"
                elif slug == "playwright-json":
                    raw_report = payload["report"]
                    if not isinstance(raw_report, dict):
                        raise ValueError("Geçersiz Playwright raporu")
                    summary = parse_playwright_json_summary(raw_report)
                    tool_identity, note_label = "playwright-json", "Playwright JSON"
                elif slug == "k6-summary-json":
                    raw_report = payload["report"]
                    if not isinstance(raw_report, dict):
                        raise ValueError("Geçersiz k6 özet raporu")
                    canonical = json.dumps(raw_report, sort_keys=True, separators=(",", ":")).encode("utf-8")
                    if len(canonical) > 60_000:
                        raise ValueError("Rapor çok büyük")
                    summary = parse_k6_handle_summary_json(raw_report)
                    tool_identity, note_label = "k6-handle-summary-json", "k6 handleSummary JSON"
                elif slug == "k6-machine-summary-v1":
                    raw_report = payload["report"]
                    if not isinstance(raw_report, dict):
                        raise ValueError("Geçersiz k6 v1 özet raporu")
                    canonical = json.dumps(raw_report, sort_keys=True, separators=(",", ":")).encode("utf-8")
                    if len(canonical) > 60_000:
                        raise ValueError("Rapor çok büyük")
                    summary = parse_k6_machine_summary_v1(raw_report)
                    tool_identity, note_label = "k6-machine-summary-v1", "k6 v1 JSON"
                elif slug == "schemathesis-junit":
                    raw_report = payload["report"]
                    if not isinstance(raw_report, str):
                        raise ValueError("Geçersiz Schemathesis JUnit XML")
                    summary = parse_schemathesis_junit_summary(raw_report)
                    tool_identity, note_label = "schemathesis-junit-xml", "Schemathesis JUnit XML"
                else:
                    raw_report = payload["report"]
                    if not isinstance(raw_report, str):
                        raise ValueError("Geçersiz SIEM ECS NDJSON")
                    summary = parse_siem_ecs_ndjson_summary(raw_report)
                    tool_identity, note_label = "ecs-ndjson", "SIEM ECS JSONL"
                linked, created = STORE.add_generic_tool_evidence(
                    parts[2], control_id, tool_identity, summary, note_label
                )
                return self._json(linked, status=HTTPStatus.CREATED if created else HTTPStatus.OK)
            except ValueError:
                return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz araç kanıtı veya test adımı.")

        if len(parts) == 5 and parts[:2] == ["api", "engagements"] and parts[3:] == ["tool-evidence", "nmap"]:
            # Explicit user action: the passive preview endpoint never stores evidence.
            if set(payload) != {"control_id", "report", "confirm_link"} or payload.get("confirm_link") is not True:
                return self._error(HTTPStatus.BAD_REQUEST, "Açık kanıt bağlama onayı gerekli.")
            engagement = STORE.get_engagement(parts[2])
            if not engagement:
                return self._error(HTTPStatus.NOT_FOUND, "Manuel denetim bulunamadı.")
            if engagement["status"] != "active" or not engagement["authorization_ref"].strip() or not engagement["special_approvals"].get("redacted_data_proof"):
                return self._error(HTTPStatus.FORBIDDEN, "Etkin, yetkili ve maskeli kanıt onaylı denetim gerekli.")
            try:
                control_id = clean_text(payload, "control_id", maximum=80, required=True)
                report = payload["report"]
                if not isinstance(report, str):
                    raise ValueError("Geçersiz rapor")
                summary = parse_nmap_inline_summary(report)
                linked, created = STORE.add_nmap_tool_evidence(parts[2], control_id, summary)
                return self._json(linked, status=HTTPStatus.CREATED if created else HTTPStatus.OK)
            except ValueError:
                return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz Nmap kanıtı veya test adımı.")

        if path == "/api/nmap/authorized-target-scan":
            if set(payload) != {"target", "profile", "confirm_authorized"}:
                return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz doğrudan Nmap tarama alanı.")
            if payload.get("confirm_authorized") is not True:
                return self._error(HTTPStatus.FORBIDDEN, "Bu çalıştırma için açık insan yetki onayı gerekli.")
            target = payload.get("target")
            profile = payload.get("profile")
            if not isinstance(target, str) or not target.strip() or len(target) > 253:
                return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz Nmap hedefi.")
            if profile not in ("default", "service-light"):
                return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz Nmap profili.")
            with SCAN_LOCK:
                if "nmap-active" in ACTIVE_TARGETS:
                    return self._error(HTTPStatus.CONFLICT, "Zaten bir Nmap taraması çalışıyor.")
                ACTIVE_TARGETS.add("nmap-active")
            try:
                result = run_authorized_nmap_scan(target, profile=profile)
            except ValueError:
                return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz doğrudan Nmap tarama isteği.")
            except (OSError, RuntimeError):
                return self._error(HTTPStatus.SERVICE_UNAVAILABLE, "Nmap çalıştırılamadı.")
            finally:
                with SCAN_LOCK:
                    ACTIVE_TARGETS.discard("nmap-active")
            receipt = _direct_target_authorization_receipt()
            STORE.log(
                "nmap.direct_authorized.completed",
                result["target_sha256"],
                {
                    "profile": result["profile"],
                    "open_port_count": result["open_port_count"],
                    "authorization_receipt": receipt,
                },
            )
            return self._json({**result, "authorization_receipt": receipt})

        if path in ("/api/nmap/tcp-scan", "/api/tools/nmap/active"):
            try:
                target_id = payload.get("target_id")
                engagement_id = payload.get("engagement_id")
                confirm_authorized = payload.get("confirm_authorized")

                # Strict body validation
                if not isinstance(target_id, str) or not target_id:
                    raise ValueError("target_id boş olmayan bir metin olmalı")
                if not isinstance(engagement_id, str) or not engagement_id:
                    raise ValueError("engagement_id boş olmayan bir metin olmalı")
                if confirm_authorized is not True:
                    raise ValueError("confirm_authorized tam olarak true olmalı")
                selected_ports = validate_custom_ports(payload["ports"]) if "ports" in payload else None
                if path == "/api/tools/nmap/active":
                    service_version = validate_service_version(payload.get("service_version", False))
                else:
                    service_version = validate_service_version(payload["service_version"]) if "service_version" in payload else None

                # Lookup target
                target_record = STORE.get_target(target_id)
                if not target_record:
                    return self._error(HTTPStatus.NOT_FOUND, "Hedef bulunamadı.")

                # Lookup engagement and verify active + matching
                engagement = STORE.get_engagement(engagement_id)
                if not engagement:
                    return self._error(HTTPStatus.NOT_FOUND, "Engagement bulunamadı.")

                # Engagement must be active
                if engagement.get("status") != "active":
                    return self._error(HTTPStatus.FORBIDDEN, "Engagement aktif değil.")

                # Engagement must have nonempty authorization_ref and scope_notes
                auth_ref = engagement.get("authorization_ref")
                scope_notes = engagement.get("scope_notes")
                if not isinstance(auth_ref, str) or not auth_ref:
                    return self._error(HTTPStatus.FORBIDDEN, "Görev authorization_ref eksik.")
                if not isinstance(scope_notes, str) or not scope_notes:
                    return self._error(HTTPStatus.FORBIDDEN, "Görev scope_notes eksik.")

                # Engagement must match target
                if engagement.get("target_id") != target_id:
                    return self._error(HTTPStatus.FORBIDDEN, "Engagement hedefle eşleşmiyor.")

                # Concurrent Nmap check (nonblocking)
                with SCAN_LOCK:
                    if "nmap-active" in ACTIVE_TARGETS:
                        return self._error(HTTPStatus.CONFLICT, "Zaten bir Nmap taraması çalışıyor.")
                    ACTIVE_TARGETS.add("nmap-active")

                try:
                    # Run bounded TCP-connect scan
                    scan_args = {
                        "target_id": target_id,
                        "engagement_id": engagement_id,
                        "hostname": target_record["hostname"],
                        "port": int(target_record["port"]),
                    }
                    if selected_ports is not None:
                        scan_args["ports"] = selected_ports
                    if service_version is not None:
                        scan_args["service_version"] = service_version
                    scan_fn = (
                        run_nmap_active_scan
                        if path == "/api/tools/nmap/active" and run_nmap_active_scan is not run_bounded_tcp_connect_scan
                        else run_bounded_tcp_connect_scan
                    )
                    result = scan_fn(**scan_args)
                except RuntimeError as exc:
                    return self._error(HTTPStatus.SERVICE_UNAVAILABLE, "Nmap çalıştırılamadı.")
                finally:
                    with SCAN_LOCK:
                        ACTIVE_TARGETS.discard("nmap-active")

                # Audit sanitized result only
                STORE.log(
                    "nmap.scan.completed",
                    target_id,
                    {
                        "engagement_id": engagement_id,
                        "profile": result["profile"],
                        "open_port_count": result["open_port_count"],
                    },
                )

                return self._json(result)

            except ValueError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz istek.")

        if path in ("/api/tools/nmap/service-fingerprint", "/api/nmap/service-fingerprint", "/api/nmap/tcp-service-fingerprint"):
            try:
                if not isinstance(payload, dict) or set(payload) != {
                    "target_id",
                    "engagement_id",
                    "ports",
                    "confirm_authorized",
                    "confirm_service_probes",
                }:
                    return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz istek.")
                target_id = payload.get("target_id")
                engagement_id = payload.get("engagement_id")
                if not isinstance(target_id, str) or not target_id or len(target_id) > 80:
                    return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz istek.")
                if not isinstance(engagement_id, str) or not engagement_id or len(engagement_id) > 80:
                    return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz istek.")
                if payload.get("confirm_authorized") is not True or payload.get("confirm_service_probes") is not True:
                    return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz istek.")
                selected_ports = validate_service_ports(payload["ports"])

                target_record = STORE.get_target(target_id)
                if not target_record:
                    return self._error(HTTPStatus.NOT_FOUND, "Hedef bulunamadı.")
                engagement = STORE.get_engagement(engagement_id)
                if not engagement:
                    return self._error(HTTPStatus.NOT_FOUND, "Engagement bulunamadı.")
                if engagement.get("status") != "active":
                    return self._error(HTTPStatus.FORBIDDEN, "Engagement aktif değil.")
                auth_ref = engagement.get("authorization_ref")
                scope_notes = engagement.get("scope_notes")
                if not isinstance(auth_ref, str) or not auth_ref.strip():
                    return self._error(HTTPStatus.FORBIDDEN, "Görev authorization_ref eksik.")
                if not isinstance(scope_notes, str) or not scope_notes.strip():
                    return self._error(HTTPStatus.FORBIDDEN, "Görev scope_notes eksik.")
                if engagement.get("target_id") != target_id:
                    return self._error(HTTPStatus.FORBIDDEN, "Engagement hedefle eşleşmiyor.")
                if not _active_test_window_valid(engagement):
                    return self._error(HTTPStatus.FORBIDDEN, "Engagement test_window geçerli ve etkin olmalıdır.")

                with SCAN_LOCK:
                    if "nmap-active" in ACTIVE_TARGETS:
                        return self._error(HTTPStatus.CONFLICT, "Zaten bir Nmap taraması çalışıyor.")
                    ACTIVE_TARGETS.add("nmap-active")
                try:
                    result = run_bounded_tcp_service_fingerprint(
                        target_id=target_id,
                        engagement_id=engagement_id,
                        hostname=target_record["hostname"],
                        port=int(target_record["port"]),
                        ports=selected_ports,
                    )
                except RuntimeError:
                    return self._error(HTTPStatus.SERVICE_UNAVAILABLE, "Nmap çalıştırılamadı.")
                finally:
                    with SCAN_LOCK:
                        ACTIVE_TARGETS.discard("nmap-active")

                STORE.log(
                    "nmap.service_fingerprint.completed",
                    target_id,
                    {
                        "engagement_id": engagement_id,
                        "profile": result.get("profile", "nmap-tcp-service-fingerprint-v1"),
                        "selected_port_count": result.get("selected_port_count", len(selected_ports)),
                        "open_port_count": result.get("open_port_count", 0),
                    },
                )
                return self._json(result)
            except ValueError:
                return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz istek.")


        if path == "/api/dependency-security/offline-scan":
            # 18. tur: kilit dosyalarını yerel (çevrimdışı) OSV veritabanıyla tüm ekosistemlerde eşle ve kaydet.
            try:
                if not isinstance(payload, dict) or set(payload) != {"confirm_local", "project_path"}:
                    raise ValueError("Yalnız confirm_local ve project_path alanları bekleniyor.")
                if payload["confirm_local"] is not True:
                    raise ValueError("Yerel kilit dosyaları için açık onay gerekli.")
                import osv_offline
                report = osv_offline.scan_project(clean_text(payload, "project_path", maximum=1024, required=True))
                imported = STORE.import_dependency_findings({k: report[k] for k in (
                    "source", "source_path", "source_timestamp", "document_hash", "project_path", "findings")})
                # 20. tur: kullanım/erişilebilirlik ve "önce bunları düzelt" puanı (hata taramayı bozmaz)
                priority = {}
                warnings = list(report["warnings"])
                if report["findings"]:
                    try:
                        from dependency_security import analyze_vulnerability_reachability
                        reach = analyze_vulnerability_reachability(report["project_path"], findings=report["findings"])
                        STORE.apply_dependency_priorities(reach["items"], source=report["source"])
                        priority = reach.get("priority") or {}
                    except (DependencySecurityError, ValueError, OSError):
                        warnings.append("Erişilebilirlik/önceliklendirme analizi yapılamadı; bulgular önem sırasıyla listelenir.")
                try:  # 21. tur: kötü amaçlı paket (hemen) ve yeni "Önce düzelt" SCA bildirimleri
                    notifications.on_dependency_scan(report["project_path"], report["findings"], priority)
                except ops_files.OpsStoreError:
                    pass
                except Exception:  # noqa: BLE001 — bildirim hatası taramayı geçersiz kılmaz
                    traceback.print_exc()
                return self._json({**imported, "coverage": report["coverage"], "skipped": report["skipped"],
                                   "warnings": warnings, "component_count": report["component_count"],
                                   "finding_count": len(report["findings"]), "priority": priority},
                                  status=HTTPStatus.CREATED)
            except (DependencySecurityError, ValueError) as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))
            except Exception as exc:  # noqa: BLE001 - osv_offline.OfflineDBError dahil; yol/sır sızdırmaz
                if type(exc).__name__ == "OfflineDBError":
                    return self._error(HTTPStatus.SERVICE_UNAVAILABLE, str(exc))
                raise

        if path == "/api/dependency-security/import":
            try:
                report = import_report(
                    clean_text(payload, "report_path", maximum=1024, required=True),
                    clean_text(payload, "project_path", maximum=1024, required=True),
                    clean_text(payload, "source", maximum=20) or "auto",
                )
                return self._json(STORE.import_dependency_findings(report), status=HTTPStatus.CREATED)
            except (DependencySecurityError, ValueError) as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))

        if path == "/api/engagements":
            try:
                target_id = clean_text(payload, "target_id", maximum=80, required=True)
                target_record = STORE.get_target(target_id)
                if not target_record:
                    return self._error(HTTPStatus.NOT_FOUND, "Hedef bulunamadı.")
                special = payload.get("special_approvals", {})
                if not isinstance(special, dict):
                    raise ValueError("Özel onaylar geçersiz.")
                engagement = STORE.create_engagement(
                    target_id=target_id,
                    name=clean_text(payload, "name", maximum=140, required=True),
                    authorization_ref=clean_text(payload, "authorization_ref", maximum=240),
                    scope_notes=clean_text(payload, "scope_notes", maximum=8000),
                    out_of_scope=clean_text(payload, "out_of_scope", maximum=5000),
                    test_window=clean_text(payload, "test_window", maximum=240),
                    special_approvals=special,
                )
                return self._json(engagement, status=HTTPStatus.CREATED)
            except ValueError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))

        if path == "/api/lab-runs":
            try:
                plan = build_lab_plan(payload)
                lab_run = STORE.create_lab_run(**plan)
                control_id = plan.get("assumptions", {}).get("control_id")
                if plan["scenario_type"] == "external_result" and plan.get("engagement_id") and control_id:
                    engagement = STORE.get_engagement(plan["engagement_id"])
                    linked_test = next((test for test in engagement.get("tests", []) if test["control_id"] == control_id), None) if engagement else None
                    if linked_test and linked_test["status"] == "not_tested":
                        STORE.update_manual_test(
                            plan["engagement_id"], control_id, status="needs_review",
                            notes=f'{plan["assumptions"]["tool_name"]} harici sonucu uzman incelemesi bekliyor.',
                            evidence=f'Harici maskeli kanıt: {plan["assumptions"]["evidence_hash"]}',
                        )
                return self._json(lab_run, status=HTTPStatus.CREATED)
            except ValueError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))

        if len(parts) == 4 and parts[:2] == ["api", "lab-runs"] and parts[3] == "update":
            try:
                status = clean_text(payload, "status", maximum=20, required=True)
                if status not in {"planned", "completed", "cancelled"}:
                    raise ValueError("Geçersiz laboratuvar kaydı durumu.")
                if "evidence_summary" in payload:
                    evidence_summary = clean_text(payload, "evidence_summary", maximum=4000)
                else:
                    evidence_summary = None
                lab_run = STORE.update_lab_run(parts[2], status=status, evidence_summary=evidence_summary)
                if not lab_run:
                    return self._error(HTTPStatus.NOT_FOUND, "Laboratuvar kaydı bulunamadı.")
                return self._json(lab_run)
            except ValueError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))

        if len(parts) == 4 and parts[:2] == ["api", "engagements"] and parts[3] == "update":
            engagement = STORE.get_engagement(parts[2])
            if not engagement:
                return self._error(HTTPStatus.NOT_FOUND, "Manuel denetim bulunamadı.")
            try:
                updates = {}
                limits = {
                    "name": 140, "authorization_ref": 240, "scope_notes": 8000,
                    "out_of_scope": 5000, "test_window": 240, "executive_summary": 12000,
                }
                for key, maximum in limits.items():
                    if key in payload:
                        updates[key] = clean_text(payload, key, maximum=maximum, required=key == "name")
                if "status" in payload:
                    status = clean_text(payload, "status", maximum=20, required=True)
                    if status not in {"active", "paused", "completed"}:
                        raise ValueError("Geçersiz denetim durumu.")
                    updates["status"] = status
                return self._json(STORE.update_engagement(parts[2], updates))
            except ValueError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))

        if len(parts) == 5 and parts[:2] == ["api", "engagements"] and parts[3] == "tests":
            status = str(payload.get("status", ""))
            if status not in {"not_tested", "passed", "failed", "needs_review", "not_applicable"}:
                return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz test durumu.")
            try:
                test = STORE.update_manual_test(
                    parts[2], parts[4], status=status,
                    notes=clean_text(payload, "notes", maximum=12000),
                    evidence=clean_text(payload, "evidence", maximum=12000),
                )
            except ValueError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))
            if not test:
                return self._error(HTTPStatus.NOT_FOUND, "Test adımı bulunamadı.")
            return self._json(test)

        if len(parts) == 4 and parts[:2] == ["api", "engagements"] and parts[3] == "findings":
            if not STORE.get_engagement(parts[2]):
                return self._error(HTTPStatus.NOT_FOUND, "Manuel denetim bulunamadı.")
            severity = str(payload.get("severity", ""))
            if severity not in {"critical", "high", "medium", "low", "info"}:
                return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz bulgu önem derecesi.")
            finding_status = str(payload.get("status", "open"))
            if finding_status not in {"open", "in_progress", "retest_required", "resolved", "reopened", "risk_accepted"}:
                return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz bulgu durumu.")
            try:
                finding = {
                    "severity": severity,
                    "status": finding_status,
                    "title": clean_text(payload, "title", maximum=180, required=True),
                    "affected_asset": clean_text(payload, "affected_asset", maximum=500, required=True),
                    "description": clean_text(payload, "description", maximum=12000, required=True),
                    "impact": clean_text(payload, "impact", maximum=8000, required=True),
                    "evidence": clean_text(payload, "evidence", maximum=12000, required=True),
                    "reproduction": clean_text(payload, "reproduction", maximum=12000, required=True),
                    "recommendation": clean_text(payload, "recommendation", maximum=12000, required=True),
                    "resolution_notes": clean_text(payload, "resolution_notes", maximum=12000),
                    **clean_finding_risk(payload),
                }
                return self._json(STORE.create_manual_finding(parts[2], finding), status=HTTPStatus.CREATED)
            except ValueError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))

        if len(parts) == 4 and parts[:2] == ["api", "findings"] and parts[3] == "update":
            updates = {}
            try:
                field_limits = {
                    "title": 180, "affected_asset": 500, "description": 12000, "impact": 8000,
                    "evidence": 12000, "reproduction": 12000, "recommendation": 12000,
                }
                for key, maximum in field_limits.items():
                    if key in payload:
                        updates[key] = clean_text(payload, key, maximum=maximum, required=True)
                if "severity" in payload:
                    if payload["severity"] not in {"critical", "high", "medium", "low", "info"}:
                        raise ValueError("Geçersiz önem derecesi.")
                    updates["severity"] = payload["severity"]
                if "status" in payload:
                    if payload["status"] not in {"open", "in_progress", "retest_required", "resolved", "reopened", "risk_accepted"}:
                        raise ValueError("Geçersiz bulgu durumu.")
                    updates["status"] = payload["status"]
                if "resolution_notes" in payload:
                    updates["resolution_notes"] = clean_text(payload, "resolution_notes", maximum=12000)
                updates.update(clean_finding_risk(payload, partial=True))
                finding = STORE.update_manual_finding(parts[2], updates)
                if not finding:
                    return self._error(HTTPStatus.NOT_FOUND, "Bulgu bulunamadı.")
                return self._json(finding)
            except ValueError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))

        if len(parts) == 4 and parts[:2] == ["api", "dependency-findings"] and parts[3] == "update":
            status = str(payload.get("status", ""))
            if status not in {"open", "in_progress", "retest_required", "resolved", "reopened", "risk_accepted"}:
                return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz bağımlılık bulgusu durumu.")
            try:
                resolution_notes = payload.get("resolution_notes")
                if resolution_notes is not None:
                    resolution_notes = clean_text(payload, "resolution_notes", maximum=12_000)
                finding = STORE.update_dependency_finding(
                    parts[2], status=status,
                    resolution_notes=resolution_notes,
                )
                if not finding:
                    return self._error(HTTPStatus.NOT_FOUND, "Bağımlılık bulgusu bulunamadı.")
                return self._json(finding)
            except ValueError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))

        if path == "/api/tooling/autodiscover":
            if not isinstance(payload, dict) or payload.get("confirm_bind") is not True:
                return self._error(HTTPStatus.BAD_REQUEST, "Yerel araç bağlama için açık onay (confirm_bind: true) gereklidir.")
            from tool_runtime_autodiscover import autodiscover_and_bind_runtimes
            # Açık onay: diskteki değerler yeni onaylı kayıt olur (bkz. tool_runtime_autodiscover).
            return self._json(autodiscover_and_bind_runtimes(apply_env=True, persist=True, trust_disk=True))

        if path == "/api/web-infra/dns-email-audit":
            try:
                from web_infra_deep_auditor import audit_dns_and_email_security
                hostname = clean_text(payload, "hostname", maximum=255, required=True)
                txt_records = payload.get("txt_records")
                if txt_records is not None and not isinstance(txt_records, list):
                    raise ValueError("txt_records bir dizi olmalıdır.")
                caa_records = payload.get("caa_records")
                if caa_records is not None and not isinstance(caa_records, list):
                    raise ValueError("caa_records bir dizi olmalıdır.")
                cname_target = clean_text(payload, "cname_target", maximum=255) if payload.get("cname_target") else None
                return self._json(
                    audit_dns_and_email_security(
                        hostname,
                        txt_records=txt_records,
                        caa_records=caa_records,
                        cname_target=cname_target,
                    )
                )
            except (ValueError, TargetRejected) as exc:
                return self._error(HTTPStatus.BAD_REQUEST, _sanitize_error_message(str(exc), "Geçersiz alan adı veya DNS girdisi."))

        if path == "/api/web-infra/discovery-audit":
            try:
                from web_infra_deep_auditor import audit_discovery_and_identity_endpoints
                target_url = clean_text(payload, "target_url", maximum=512, required=True)
                robots_txt = clean_text(payload, "robots_txt", maximum=64_000) if payload.get("robots_txt") else None
                openid_config = payload.get("openid_config") if isinstance(payload.get("openid_config"), dict) else None
                jwks_doc = payload.get("jwks_doc") if isinstance(payload.get("jwks_doc"), dict) else None
                graphql_response = payload.get("graphql_response") if isinstance(payload.get("graphql_response"), dict) else None
                response_headers = payload.get("response_headers") if isinstance(payload.get("response_headers"), dict) else None
                return self._json(
                    audit_discovery_and_identity_endpoints(
                        target_url,
                        robots_txt=robots_txt,
                        openid_config=openid_config,
                        jwks_doc=jwks_doc,
                        graphql_response=graphql_response,
                        response_headers=response_headers,
                    )
                )
            except (ValueError, TargetRejected) as exc:
                return self._error(HTTPStatus.BAD_REQUEST, _sanitize_error_message(str(exc), "Geçersiz keşif denetimi girdisi."))

        if path == "/api/openapi-security/audit":
            try:
                from openapi_contract_auditor import audit_api_contract, audit_project_api_contracts
                if payload.get("project_path"):
                    if payload.get("confirm_local") is not True:
                        return self._error(HTTPStatus.BAD_REQUEST, "Yerel API sözleşmesi analizi için açık onay (confirm_local: true) gereklidir.")
                    project_path = clean_text(payload, "project_path", maximum=1024, required=True)
                    return self._json(audit_project_api_contracts(project_path))
                raw_content = clean_text(payload, "raw_content", maximum=64_000, required=True)
                contract_type = clean_text(payload, "contract_type", maximum=32) or "auto"
                source_name = clean_text(payload, "source_name", maximum=120) or "inline-contract"
                return self._json(
                    audit_api_contract(
                        raw_content,
                        contract_type=contract_type,
                        source_name=source_name,
                    )
                )
            except (ValueError, ProjectRejected) as exc:
                return self._error(HTTPStatus.BAD_REQUEST, _sanitize_error_message(str(exc), "Geçersiz OpenAPI / GraphQL sözleşme girdisi."))

        if len(parts) == 4 and parts[:2] == ["api", "engagements"] and parts[3] == "auto-evidence-sync":
            try:
                from wstg_auto_evidence_bridge import synchronize_engagement_auto_evidence
                project_audit_id = clean_text(payload, "project_audit_id", maximum=80) or None
                overwrite_manual = payload.get("overwrite_manual") is True
                return self._json(
                    synchronize_engagement_auto_evidence(
                        STORE,
                        parts[2],
                        project_audit_id=project_audit_id,
                        overwrite_manual=overwrite_manual,
                    )
                )
            except ValueError as exc:
                msg = str(exc)
                status_code = HTTPStatus.NOT_FOUND if "bulunamadı" in msg.lower() else HTTPStatus.BAD_REQUEST
                return self._error(status_code, _sanitize_error_message(msg))

        if path == "/api/plugins/enable-builtins":
            if payload.get("confirm_enable") is not True:
                return self._error(HTTPStatus.BAD_REQUEST, "Yerleşik eklentileri etkinleştirmek için confirm_enable: true gereklidir.")
            PLUGIN_MANAGER.enabled = True
            # Bu uç yalnız SHA-256 ile sabitlenmiş yerleşik eklentileri yükler; kullanıcı
            # eklentileri yalnız süreç düzeyinde SNIPER_ENABLE_USER_PLUGINS=1 ile açılır.
            PLUGIN_MANAGER.allow_user_plugins = False
            PLUGIN_MANAGER.reload()
            return self._json(PLUGIN_MANAGER.public_status())

        if path == "/api/project-audits/diff":
            try:
                from project_audit_diff import compare_project_audits
                audit_1_id = clean_text(payload, "audit_1_id", maximum=80) or clean_text(payload, "before_id", maximum=80, required=True)
                audit_2_id = clean_text(payload, "audit_2_id", maximum=80) or clean_text(payload, "after_id", maximum=80, required=True)
                return self._json(compare_project_audits(STORE, audit_1_id, audit_2_id))
            except ValueError as exc:
                msg = str(exc)
                status_code = HTTPStatus.NOT_FOUND if "bulunamadı" in msg.lower() else HTTPStatus.BAD_REQUEST
                return self._error(status_code, _sanitize_error_message(msg))

        if path in {"/api/dependency-security/vex", "/api/dependency-security/vex-decisions",
                    "/api/dependency-security/vex-import"}:
            return self._dependency_vex_post(path, payload)

        if path == "/api/dependency-security/reachability":
            try:
                if payload.get("confirm_local") is not True and payload.get("confirm_local_scan") is not True:
                    return self._error(HTTPStatus.BAD_REQUEST, "Yerel kod erişilebilirlik analizi için açık onay (confirm_local: true) gereklidir.")
                from dependency_security import analyze_vulnerability_reachability
                project_path = clean_text(payload, "project_path", maximum=1024, required=True)
                dep_sec = STORE.dependency_security()
                raw_findings = payload.get("findings") if isinstance(payload.get("findings"), list) else payload.get("vulnerable_packages")
                findings = raw_findings if isinstance(raw_findings, list) else dep_sec.get("findings")
                result = analyze_vulnerability_reachability(project_path, findings=findings)
                if not isinstance(raw_findings, list):  # 20. tur: kayıtlı bulgulara öncelik/kullanım yazılır
                    result["persisted"] = STORE.apply_dependency_priorities(result.get("items") or [])
                return self._json(result)
            except (ValueError, ProjectRejected) as exc:
                return self._error(HTTPStatus.BAD_REQUEST, _sanitize_error_message(str(exc), "Geçersiz proje yolu veya erişilebilirlik girdisi."))

        if len(parts) == 4 and parts[:2] == ["api", "engagements"] and parts[3] == "verify-retests":
            try:
                from wstg_auto_evidence_bridge import verify_engagement_retests
                project_audit_id = clean_text(payload, "project_audit_id", maximum=80) or None
                auto_resolve = payload.get("auto_resolve", True) is not False
                return self._json(
                    verify_engagement_retests(
                        STORE,
                        parts[2],
                        project_audit_id=project_audit_id,
                        auto_resolve=auto_resolve,
                    )
                )
            except ValueError as exc:
                msg = str(exc)
                status_code = HTTPStatus.NOT_FOUND if "bulunamadı" in msg.lower() else HTTPStatus.BAD_REQUEST
                return self._error(status_code, _sanitize_error_message(msg))

        if path == "/api/quality-gate/evaluate":
            try:
                from quality_gate import evaluate_quality_gate
                target_ref = clean_text(payload, "target_ref", maximum=255) or None
                project_audit_id = clean_text(payload, "project_audit_id", maximum=80) or None
                engagement_id = clean_text(payload, "engagement_id", maximum=80) or None
                min_score = int(payload.get("min_score", 80))
                max_critical = int(payload.get("max_critical", 0))
                max_high = int(payload.get("max_high", 0))
                max_overdue = int(payload.get("max_overdue", 0))
                policy = payload.get("policy") if isinstance(payload.get("policy"), dict) else None
                return self._json(
                    evaluate_quality_gate(
                        STORE,
                        target_ref=target_ref,
                        project_audit_id=project_audit_id,
                        engagement_id=engagement_id,
                        min_score=min_score,
                        max_critical=max_critical,
                        max_high=max_high,
                        max_overdue=max_overdue,
                        policy=policy,
                    )
                )
            except (ValueError, TypeError) as exc:
                msg = str(exc)
                status_code = HTTPStatus.NOT_FOUND if "bulunamadı" in msg.lower() else HTTPStatus.BAD_REQUEST
                return self._error(status_code, _sanitize_error_message(msg))

        if path == "/api/mobile-security/audit-project":
            try:
                if payload.get("confirm_local") is not True and payload.get("confirm_local_scan") is not True:
                    return self._error(HTTPStatus.BAD_REQUEST, "Yerel mobil proje güvenlik analizi için açık onay (confirm_local: true) gereklidir.")
                from mobile_security_auditor import audit_mobile_project
                project_path = clean_text(payload, "project_path", maximum=1024, required=True)
                app_profile = clean_text(payload, "app_profile", maximum=32) or "all"
                return self._json(audit_mobile_project(project_path, app_profile=app_profile))
            except (ValueError, ProjectRejected) as exc:
                return self._error(HTTPStatus.BAD_REQUEST, _sanitize_error_message(str(exc), "Geçersiz mobil proje yolu veya profili."))

        if path == "/api/mobile-security/audit-package":
            try:
                if payload.get("confirm_local") is not True and payload.get("confirm_local_scan") is not True:
                    return self._error(HTTPStatus.BAD_REQUEST, "Yerel mobil paket (.apk/.aab/.ipa) analizi için açık onay (confirm_local: true) gereklidir.")
                from mobile_security_auditor import audit_mobile_package_archive
                package_path = clean_text(payload, "package_path", maximum=1024) or clean_text(payload, "project_path", maximum=1024, required=True)
                return self._json(audit_mobile_package_archive(package_path))
            except (ValueError, ProjectRejected) as exc:
                return self._error(HTTPStatus.BAD_REQUEST, _sanitize_error_message(str(exc), "Geçersiz mobil paket arşivi yolu."))

        if path == "/api/mobile-security/audit-manifest":
            try:
                from mobile_security_auditor import audit_mobile_manifest_inline
                raw_content = clean_text(payload, "raw_content", maximum=256_000, required=True)
                filename = clean_text(payload, "filename", maximum=120) or "AndroidManifest.xml"
                app_profile = clean_text(payload, "app_profile", maximum=32) or "all"
                return self._json(audit_mobile_manifest_inline(raw_content, filename=filename, app_profile=app_profile))
            except ValueError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, _sanitize_error_message(str(exc), "Geçersiz mobil manifest girdisi."))

        if path == "/api/ai-llm-security/audit":
            try:
                from ai_llm_security_auditor import audit_ai_llm_inline, audit_ai_llm_project
                if payload.get("project_path"):
                    if payload.get("confirm_local") is not True and payload.get("confirm_local_scan") is not True:
                        return self._error(HTTPStatus.BAD_REQUEST, "Yerel yapay zeka / LLM güvenlik analizi için açık onay (confirm_local: true) gereklidir.")
                    project_path = clean_text(payload, "project_path", maximum=1024, required=True)
                    return self._json(audit_ai_llm_project(project_path))
                raw_content = clean_text(payload, "raw_content", maximum=256_000, required=True)
                filename = clean_text(payload, "filename", maximum=120) or "agent.py"
                return self._json(audit_ai_llm_inline(raw_content, filename=filename))
            except (ValueError, ProjectRejected) as exc:
                return self._error(HTTPStatus.BAD_REQUEST, _sanitize_error_message(str(exc), "Geçersiz yapay zeka / LLM denetim girdisi."))

        if path == "/api/cloud-iam-security/audit":
            try:
                from cloud_iam_rbac_auditor import audit_cloud_iam_and_k8s_rbac, audit_cloud_iam_project
                if payload.get("project_path"):
                    if payload.get("confirm_local") is not True and payload.get("confirm_local_scan") is not True:
                        return self._error(HTTPStatus.BAD_REQUEST, "Yerel bulut IAM / Kubernetes RBAC analizi için açık onay (confirm_local: true) gereklidir.")
                    project_path = clean_text(payload, "project_path", maximum=1024, required=True)
                    return self._json(audit_cloud_iam_project(project_path))
                raw_content = clean_text(payload, "raw_content", maximum=256_000, required=True)
                filename = clean_text(payload, "filename", maximum=120) or "policy.json"
                return self._json(audit_cloud_iam_and_k8s_rbac(raw_content, filename=filename))
            except (ValueError, ProjectRejected) as exc:
                return self._error(HTTPStatus.BAD_REQUEST, _sanitize_error_message(str(exc), "Geçersiz bulut IAM / RBAC denetim girdisi."))

        if path == "/api/desktop-security/audit":
            try:
                if payload.get("confirm_local") is not True and payload.get("confirm_local_scan") is not True:
                    return self._error(HTTPStatus.BAD_REQUEST, "Yerel masaüstü uygulama (Electron / Tauri) analizi için açık onay (confirm_local: true) gereklidir.")
                from desktop_protocol_security_auditor import audit_desktop_app_project
                project_path = clean_text(payload, "project_path", maximum=1024, required=True)
                return self._json(audit_desktop_app_project(project_path))
            except (ValueError, ProjectRejected) as exc:
                return self._error(HTTPStatus.BAD_REQUEST, _sanitize_error_message(str(exc), "Geçersiz masaüstü proje yolu."))

        if path == "/api/protocol-security/audit":
            try:
                from desktop_protocol_security_auditor import audit_realtime_and_binary_protocols
                raw_content = clean_text(payload, "raw_content", maximum=256_000, required=True)
                protocol_type = clean_text(payload, "protocol_type", maximum=32) or "auto"
                filename = clean_text(payload, "filename", maximum=120) or "service.proto"
                return self._json(audit_realtime_and_binary_protocols(raw_content, protocol_type=protocol_type, filename=filename))
            except ValueError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, _sanitize_error_message(str(exc), "Geçersiz gRPC / WebSocket / Webhook protokol girdisi."))

        if path == "/api/auth-protocol/audit":
            try:
                from auth_protocol_auditor import audit_auth_artifact
                raw_content = clean_text(payload, "raw_content", maximum=256_000, required=True)
                artifact_type = clean_text(payload, "artifact_type", maximum=32) or "auto"
                return self._json(audit_auth_artifact(raw_content, artifact_type=artifact_type))
            except ValueError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, _sanitize_error_message(str(exc), "Geçersiz JWT / OAuth2 / SAML denetim girdisi."))

        if path == "/api/attack-paths/correlate":
            try:
                from attack_path_correlator import correlate_attack_paths
                scan_id = clean_text(payload, "scan_id", maximum=80) or None
                project_audit_id = clean_text(payload, "project_audit_id", maximum=80) or None
                engagement_id = clean_text(payload, "engagement_id", maximum=80) or None
                findings = payload.get("findings") if isinstance(payload.get("findings"), list) else None
                scan_obj = payload.get("scan") if isinstance(payload.get("scan"), dict) else None
                proj_obj = payload.get("project_audit") if isinstance(payload.get("project_audit"), dict) else None
                eng_obj = payload.get("engagement") if isinstance(payload.get("engagement"), dict) else None
                dep_obj = payload.get("dependency_report") if isinstance(payload.get("dependency_report"), dict) else None
                mob_obj = payload.get("mobile_audit") if isinstance(payload.get("mobile_audit"), dict) else None
                return self._json(
                    correlate_attack_paths(
                        STORE,
                        scan_id=scan_id,
                        project_audit_id=project_audit_id,
                        engagement_id=engagement_id,
                        scan=scan_obj,
                        project_audit=proj_obj,
                        engagement=eng_obj,
                        dependency_report=dep_obj,
                        mobile_audit=mob_obj,
                        findings=findings,
                    )
                )
            except ValueError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, _sanitize_error_message(str(exc), "Saldırı zinciri korelasyon hatası."))

        if path == "/api/remediation/auto-patch":
            try:
                from auto_remediation_patcher import generate_remediation_patches
                scan_id = clean_text(payload, "scan_id", maximum=80) or None
                project_audit_id = clean_text(payload, "project_audit_id", maximum=80) or None
                target_stack = clean_text(payload, "target_stack", maximum=40) or "auto"
                findings = payload.get("findings") if isinstance(payload.get("findings"), list) else None
                scan_obj = payload.get("scan") if isinstance(payload.get("scan"), dict) else (STORE.get_scan(scan_id) if scan_id else None)
                proj_obj = payload.get("project_audit") if isinstance(payload.get("project_audit"), dict) else (STORE.get_project_audit(project_audit_id) if project_audit_id else None)
                mob_obj = payload.get("mobile_audit") if isinstance(payload.get("mobile_audit"), dict) else None
                return self._json(
                    generate_remediation_patches(
                        findings=findings,
                        scan=scan_obj,
                        project_audit=proj_obj,
                        mobile_audit=mob_obj,
                        target_stack=target_stack,
                        include_templates=payload.get("include_templates") is True,
                    )
                )
            except ValueError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, _sanitize_error_message(str(exc), "Otomatik yama üretimi hatası."))

        if path == "/api/reports/executive-pentest":
            try:
                from executive_pentest_report import build_executive_pentest_report
                engagement_id = clean_text(payload, "engagement_id", maximum=80) or None
                project_audit_id = clean_text(payload, "project_audit_id", maximum=80) or None
                scan_id = clean_text(payload, "scan_id", maximum=80) or None
                mob_obj = payload.get("mobile_audit") if isinstance(payload.get("mobile_audit"), dict) else None
                include_patches = payload.get("include_patches", True) is not False
                return self._json(
                    build_executive_pentest_report(
                        STORE,
                        engagement_id=engagement_id,
                        project_audit_id=project_audit_id,
                        scan_id=scan_id,
                        mobile_audit=mob_obj,
                        include_patches=include_patches,
                    )
                )
            except ValueError as exc:
                msg = str(exc)
                status_code = HTTPStatus.NOT_FOUND if "bulunamadı" in msg.lower() else HTTPStatus.BAD_REQUEST
                return self._error(status_code, _sanitize_error_message(msg, "Yönetici sızma testi raporu oluşturulamadı."))

        if path == "/api/business-logic/audit":
            try:
                from business_logic_auditor import audit_business_logic_inline, audit_business_logic_project
                if payload.get("project_path"):
                    if payload.get("confirm_local") is not True and payload.get("confirm_local_scan") is not True:
                        return self._error(HTTPStatus.BAD_REQUEST, "Yerel iş mantığı / TOCTOU analizi için açık onay (confirm_local: true) gereklidir.")
                    project_path = clean_text(payload, "project_path", maximum=1024, required=True)
                    return self._json(audit_business_logic_project(project_path))
                raw_content = clean_text(payload, "raw_content", maximum=256_000, required=True)
                filename = clean_text(payload, "filename", maximum=120) or "payment.py"
                return self._json(audit_business_logic_inline(raw_content, filename=filename))
            except (ValueError, ProjectRejected) as exc:
                return self._error(HTTPStatus.BAD_REQUEST, _sanitize_error_message(str(exc), "Geçersiz iş mantığı denetim girdisi."))

        if path == "/api/database-security/audit":
            try:
                from database_rls_schema_auditor import audit_database_schema_inline, audit_database_schema_project
                if payload.get("project_path"):
                    if payload.get("confirm_local") is not True and payload.get("confirm_local_scan") is not True:
                        return self._error(HTTPStatus.BAD_REQUEST, "Yerel veritabanı şeması / RLS analizi için açık onay (confirm_local: true) gereklidir.")
                    project_path = clean_text(payload, "project_path", maximum=1024, required=True)
                    return self._json(audit_database_schema_project(project_path))
                raw_content = clean_text(payload, "raw_content", maximum=256_000, required=True)
                filename = clean_text(payload, "filename", maximum=120) or "schema.sql"
                return self._json(audit_database_schema_inline(raw_content, filename=filename))
            except (ValueError, ProjectRejected) as exc:
                return self._error(HTTPStatus.BAD_REQUEST, _sanitize_error_message(str(exc), "Geçersiz veritabanı şema denetim girdisi."))

        if path == "/api/crypto-cbom-pqc/audit":
            try:
                from crypto_cbom_pqc_auditor import audit_crypto_pqc_inline, audit_crypto_pqc_project
                if payload.get("project_path"):
                    if payload.get("confirm_local") is not True and payload.get("confirm_local_scan") is not True:
                        return self._error(HTTPStatus.BAD_REQUEST, "Yerel kuantum sonrası kriptografi (PQC / CBOM) analizi için açık onay (confirm_local: true) gereklidir.")
                    project_path = clean_text(payload, "project_path", maximum=1024, required=True)
                    return self._json(audit_crypto_pqc_project(project_path))
                raw_content = clean_text(payload, "raw_content", maximum=256_000, required=True)
                filename = clean_text(payload, "filename", maximum=120) or "crypto.py"
                return self._json(audit_crypto_pqc_inline(raw_content, filename=filename))
            except (ValueError, ProjectRejected) as exc:
                return self._error(HTTPStatus.BAD_REQUEST, _sanitize_error_message(str(exc), "Geçersiz PQC / CBOM denetim girdisi."))

        if path == "/api/web3-iot-security/audit":
            try:
                from web3_iot_firmware_auditor import (
                    audit_iot_firmware_inline,
                    audit_smart_contract_inline,
                    audit_web3_and_iot_project,
                )
                if payload.get("project_path"):
                    if payload.get("confirm_local") is not True and payload.get("confirm_local_scan") is not True:
                        return self._error(HTTPStatus.BAD_REQUEST, "Yerel Web3 / IoT gömülü yazılım analizi için açık onay (confirm_local: true) gereklidir.")
                    project_path = clean_text(payload, "project_path", maximum=1024, required=True)
                    return self._json(audit_web3_and_iot_project(project_path))
                raw_content = clean_text(payload, "raw_content", maximum=256_000, required=True)
                filename = clean_text(payload, "filename", maximum=120) or "Vault.sol"
                mode = (clean_text(payload, "audit_mode", maximum=32) or "auto").casefold()
                if mode == "iot" or filename.casefold().endswith((".c", ".cpp", ".cc", ".h", ".hpp", ".ino", ".conf")):
                    return self._json(audit_iot_firmware_inline(raw_content, filename=filename))
                return self._json(audit_smart_contract_inline(raw_content, filename=filename))
            except (ValueError, ProjectRejected) as exc:
                return self._error(HTTPStatus.BAD_REQUEST, _sanitize_error_message(str(exc), "Geçersiz Web3 / IoT denetim girdisi."))

        if path == "/api/threat-model/generate":
            try:
                from threat_model_generator import generate_threat_model
                project_path = clean_text(payload, "project_path", maximum=1024) or None
                if project_path and payload.get("confirm_local") is not True and payload.get("confirm_local_scan") is not True:
                    return self._error(HTTPStatus.BAD_REQUEST, "Yerel proje tehdit modellemesi için açık onay (confirm_local: true) gereklidir.")
                scan_id = clean_text(payload, "scan_id", maximum=80) or None
                project_audit_id = clean_text(payload, "project_audit_id", maximum=80) or None
                engagement_id = clean_text(payload, "engagement_id", maximum=80) or None
                findings = payload.get("findings") if isinstance(payload.get("findings"), list) else None
                return self._json(
                    generate_threat_model(
                        STORE,
                        project_path=project_path,
                        scan_id=scan_id,
                        project_audit_id=project_audit_id,
                        engagement_id=engagement_id,
                        findings=findings,
                    )
                )
            except (ValueError, ProjectRejected) as exc:
                return self._error(HTTPStatus.BAD_REQUEST, _sanitize_error_message(str(exc), "Tehdit modeli oluşturulamadı."))

        if path == "/api/supply-chain-slsa/audit":
            try:
                from supply_chain_slsa_auditor import audit_supply_chain_slsa
                project_path = clean_text(payload, "project_path", maximum=1024) or None
                if project_path and payload.get("confirm_local") is not True and payload.get("confirm_local_scan") is not True:
                    return self._error(HTTPStatus.BAD_REQUEST, "Yerel tedarik zinciri / SLSA analizi için açık onay (confirm_local: true) gereklidir.")
                components = payload.get("components") if isinstance(payload.get("components"), list) else None
                workflow_content = clean_text(payload, "workflow_content", maximum=256_000) or None
                license_policy = clean_text(payload, "license_policy", maximum=32) or "commercial"
                return self._json(
                    audit_supply_chain_slsa(
                        project_path,
                        components=components,
                        workflow_content=workflow_content,
                        license_policy=license_policy,
                        store=STORE,
                    )
                )
            except (ValueError, ProjectRejected) as exc:
                return self._error(HTTPStatus.BAD_REQUEST, _sanitize_error_message(str(exc), "Tedarik zinciri / SLSA denetimi başarısız oldu."))

        if path == "/api/blue-team/synthesize-rules":
            try:
                from blue_team_rule_synthesizer import synthesize_blue_team_rules
                scan_id = clean_text(payload, "scan_id", maximum=80) or None
                project_audit_id = clean_text(payload, "project_audit_id", maximum=80) or None
                target_domain = clean_text(payload, "target_domain", maximum=120) or "app.example.com"
                findings = payload.get("findings") if isinstance(payload.get("findings"), list) else None
                scan_obj = payload.get("scan") if isinstance(payload.get("scan"), dict) else (STORE.get_scan(scan_id) if scan_id else None)
                proj_obj = payload.get("project_audit") if isinstance(payload.get("project_audit"), dict) else (STORE.get_project_audit(project_audit_id) if project_audit_id else None)
                mob_obj = payload.get("mobile_audit") if isinstance(payload.get("mobile_audit"), dict) else None
                return self._json(
                    synthesize_blue_team_rules(
                        findings=findings,
                        scan=scan_obj,
                        project_audit=proj_obj,
                        mobile_audit=mob_obj,
                        target_domain=target_domain,
                        include_baseline=payload.get("include_baseline") is True,
                    )
                )
            except ValueError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, _sanitize_error_message(str(exc), "Mavi ekip kuralları sentezlenemedi."))

        if path in {
            "/api/secret-intelligence/audit",
            "/api/privacy-dataflow/audit",
            "/api/host-hardening/audit",
            "/api/dos-resilience/audit",
            "/api/audit-logging/audit",
            "/api/browser-extension-pwa/audit",
            "/api/zero-trust-mesh/audit",
        }:
            try:
                if path == "/api/secret-intelligence/audit":
                    from secret_intelligence_auditor import audit_secrets_inline as _inline, audit_secrets_project as _project
                    default_name, label = "config.env", "sır istihbaratı"
                elif path == "/api/privacy-dataflow/audit":
                    from privacy_dataflow_auditor import audit_privacy_inline as _inline, audit_privacy_project as _project
                    default_name, label = "app.py", "KVKK / GDPR kişisel veri akışı"
                elif path == "/api/host-hardening/audit":
                    from host_cis_hardening_auditor import audit_host_config_inline, audit_host_config_project as _project
                    config_type = (clean_text(payload, "config_type", maximum=32) or "auto").casefold()
                    def _inline(raw: str, *, filename: str) -> dict:
                        return audit_host_config_inline(raw, filename=filename, config_type=config_type)
                    default_name, label = "sshd_config", "Linux sunucu CIS sertleştirme"
                elif path == "/api/dos-resilience/audit":
                    from dos_resilience_redos_auditor import (
                        analyze_regex_redos,
                        audit_dos_resilience_inline as _inline,
                        audit_dos_resilience_project as _project,
                    )
                    regex_pattern = clean_text(payload, "regex", maximum=5_000)
                    if regex_pattern and not payload.get("project_path") and not payload.get("raw_content"):
                        return self._json({"format": "sniper-redos-regex-analysis-v1", **analyze_regex_redos(regex_pattern)})
                    default_name, label = "app.py", "DoS dayanıklılığı / ReDoS"
                elif path == "/api/audit-logging/audit":
                    from audit_logging_integrity_auditor import (
                        audit_logging_inline as _inline,
                        audit_logging_project as _project,
                        verify_hash_chained_log,
                    )
                    if isinstance(payload.get("entries"), list):
                        return self._json(verify_hash_chained_log(payload["entries"]))
                    default_name, label = "app.py", "denetim izi bütünlüğü"
                elif path == "/api/browser-extension-pwa/audit":
                    from browser_extension_pwa_auditor import (
                        audit_extension_manifest_inline,
                        audit_extension_pwa_project as _project,
                        audit_extension_script_inline,
                        audit_service_worker_inline,
                    )
                    ext_mode = (clean_text(payload, "audit_mode", maximum=32) or "auto").casefold()
                    if ext_mode not in {"auto", "manifest", "script", "sw", "service_worker"}:
                        raise ValueError(
                            "audit_mode auto, manifest, script, sw veya service_worker olmalıdır."
                        )
                    def _inline(raw: str, *, filename: str) -> dict:
                        lowered = filename.casefold()
                        if ext_mode == "manifest" or (ext_mode == "auto" and lowered.endswith("manifest.json")):
                            return audit_extension_manifest_inline(raw, filename=filename)
                        if ext_mode in {"sw", "service_worker"} or (
                            ext_mode == "auto" and (lowered.endswith(("sw.js", "service-worker.js", "serviceworker.js")))
                        ):
                            return audit_service_worker_inline(raw, filename=filename)
                        return audit_extension_script_inline(raw, filename=filename)
                    default_name, label = "manifest.json", "tarayıcı uzantısı / PWA"
                else:
                    from zero_trust_mesh_auditor import audit_zero_trust_inline as _inline, audit_zero_trust_project as _project
                    default_name, label = "networkpolicy.yaml", "sıfır güven / service mesh"
                if payload.get("project_path"):
                    if payload.get("confirm_local") is not True and payload.get("confirm_local_scan") is not True:
                        return self._error(HTTPStatus.BAD_REQUEST, f"Yerel {label} analizi için açık onay (confirm_local: true) gereklidir.")
                    project_path = clean_text(payload, "project_path", maximum=1024, required=True)
                    return self._json(_project(project_path))
                raw_content = clean_text(payload, "raw_content", maximum=256_000, required=True)
                filename = clean_text(payload, "filename", maximum=120) or default_name
                return self._json(_inline(raw_content, filename=filename))
            except (ValueError, ProjectRejected) as exc:
                return self._error(HTTPStatus.BAD_REQUEST, _sanitize_error_message(str(exc), "Geçersiz güvenlik denetim girdisi."))

        if path == "/api/cvss-ssvc/prioritize":
            try:
                from cvss_ssvc_prioritizer import compute_cvss31, prioritize_findings
                vector = clean_text(payload, "vector", maximum=400)
                if vector and not isinstance(payload.get("findings"), list):
                    if vector.startswith("CVSS:4.0/"):
                        from cvss40 import compute_cvss40
                        return self._json(compute_cvss40(vector))
                    return self._json(compute_cvss31(vector))
                findings = payload.get("findings") if isinstance(payload.get("findings"), list) else None
                if findings is None:
                    project_audit_id = clean_text(payload, "project_audit_id", maximum=80) or None
                    project_path = clean_text(payload, "project_path", maximum=1024) or None
                    if project_audit_id:
                        audit = STORE.get_project_audit(project_audit_id)
                        if not audit:
                            return self._error(HTTPStatus.NOT_FOUND, "Proje denetimi bulunamadı.")
                        findings = list(audit.get("findings") or [])
                    elif project_path:
                        if payload.get("confirm_local") is not True and payload.get("confirm_local_scan") is not True:
                            return self._error(HTTPStatus.BAD_REQUEST, "Yerel CVSS / SSVC önceliklendirmesi için açık onay (confirm_local: true) gereklidir.")
                        findings = list(analyze_project(project_path).get("findings") or [])
                    else:
                        return self._error(HTTPStatus.BAD_REQUEST, "findings, vector, project_audit_id veya project_path alanlarından biri gereklidir.")
                sla_policy = payload.get("sla_policy") if isinstance(payload.get("sla_policy"), dict) else None
                return self._json(
                    prioritize_findings(
                        findings,
                        exposure=(clean_text(payload, "exposure", maximum=16) or "internet").casefold(),
                        mission_prevalence=(clean_text(payload, "mission_prevalence", maximum=16) or "support").casefold(),
                        exploitation=(clean_text(payload, "exploitation", maximum=16) or "none").casefold(),
                        sla_policy=sla_policy,
                        discovered_at=clean_text(payload, "discovered_at", maximum=40) or None,
                    )
                )
            except (ValueError, ProjectRejected) as exc:
                return self._error(HTTPStatus.BAD_REQUEST, _sanitize_error_message(str(exc), "CVSS / SSVC önceliklendirmesi başarısız oldu."))

        return self._error(HTTPStatus.NOT_FOUND, "Uç nokta bulunamadı.")

    # -- özel taint kuralları ve otomatik düzeltme önerisi ------------------------------
    def _unified_findings_get(self, query: dict) -> None:
        def values(name: str) -> set[str] | None:
            raw = query.get(name)
            if not raw:
                return None
            parsed = {part.strip() for value in raw for part in str(value).split(",") if part.strip()}
            return parsed or None

        try:
            raw_limit = (query.get("limit") or ["200"])[0]
            raw_offset = (query.get("offset") or ["0"])[0]
            if not all(isinstance(value, str) and value.isdigit() and str(int(value)) == value
                       for value in (raw_limit, raw_offset)):
                raise ValueError("limit ve offset tam sayı olmalı.")
            return self._json(STORE.list_unified_findings(
                sources=values("source"), statuses=values("status"), severities=values("severity"),
                limit=int(raw_limit), offset=int(raw_offset),
            ))
        except ValueError as exc:
            return self._error(HTTPStatus.BAD_REQUEST, str(exc))

    def _finding_tracking_get(self, parts: list[str], query: dict) -> None:
        """Bulgu takibi: /api/finding-tracking[/projects|/summary|/<id>]?project_path=&status=a,b"""
        project_path = (query.get("project_path") or [""])[0]
        if len(parts) == 3 and parts[2] == "projects":
            return self._json({"projects": STORE.list_tracked_projects()})
        if len(parts) == 3 and parts[2] == "assignees":
            return self._json(_tracking_assignees())
        if len(parts) == 3 and parts[2] == "assigned":
            return self._tracking_assigned(query)
        if len(parts) == 2 or (len(parts) == 3 and parts[2] == "summary"):
            if not project_path or len(project_path) > 1024 or "\x00" in project_path:
                return self._error(HTTPStatus.BAD_REQUEST, "project_path sorgu parametresi gerekli.")
            if len(parts) == 3:
                return self._json(STORE.tracked_project_summary(project_path))
            raw_status = (query.get("status") or [""])[0]
            statuses = {item for item in raw_status.split(",") if item} or None
            try:
                items = STORE.list_tracked_findings(project_path, statuses)
            except finding_tracking.TrackingError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))
            return self._json({"project_path": project_path, "findings": items, "total": len(items)})
        if len(parts) == 3:
            item = STORE.get_tracked_finding(parts[2])
            if not item:
                return self._error(HTTPStatus.NOT_FOUND, "Takip edilen bulgu bulunamadı.")
            return self._json(item)
        if len(parts) == 4 and parts[3] == "ai":
            # 25. tur: bulgunun AI/ajan önerileri (okuyucu görür; öneri, karar değildir)
            if not STORE.get_tracked_finding(parts[2]):
                return self._error(HTTPStatus.NOT_FOUND, "Takip edilen bulgu bulunamadı.")
            return self._json({"suggestions": ai_triage.list_suggestions(STORE, tracked_id=parts[2], limit=50),
                               "label": "AI önerisi"})
        return self._error(HTTPStatus.NOT_FOUND, "Uç nokta bulunamadı.")

    def _finding_tracking_post(self, path: str, payload: dict) -> None:
        """Durum değişikliği (tek onay: confirm true) ve isteğe bağlı geriye dönük doldurma; denetim kaydına yazılır."""
        parts = [part for part in path.split("/") if part]
        if payload.get("confirm") is not True:
            return self._error(HTTPStatus.BAD_REQUEST, "İşlem için onay (confirm: true) gerekli.")
        if parts == ["api", "finding-tracking", "backfill"]:
            if set(payload) != {"confirm"}:
                return self._error(HTTPStatus.BAD_REQUEST, "Yalnız confirm alanı kullanılabilir.")
            return self._json(STORE.backfill_finding_tracking())
        if len(parts) >= 4 and parts[3] in {"assign", "due", "comments"}:
            return self._finding_tracking_collab_post(parts, payload)
        if len(parts) >= 5 and parts[3] == "ai":
            return self._ai_triage_finding_post(parts, payload)
        if len(parts) == 4 and parts[3] == "status":
            if not set(payload) <= {"confirm", "status", "note", "expires_at"}:
                return self._error(HTTPStatus.BAD_REQUEST, "Yalnız confirm, status, note ve expires_at alanları kullanılabilir.")
            try:
                result = STORE.set_tracked_finding_status(parts[2], payload.get("status"), payload.get("note") or "",
                                                          payload.get("expires_at"))
            except LookupError as exc:
                return self._error(HTTPStatus.NOT_FOUND, str(exc))
            except finding_tracking.TrackingError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))
            return self._json(result)
        return self._error(HTTPStatus.NOT_FOUND, "Uç nokta bulunamadı.")
    # -- AI/ajan triyajı (25. tur) ---------------------------------------------------------------
    def _ai_triage_get(self, parts: list[str], query: dict) -> None:
        """/api/ai-triage/settings (okuyucu) · /api/ai-triage/suggestions?project_path=&decision= (okuyucu)."""
        first = lambda key: (query.get(key) or [""])[0]  # noqa: E731
        if parts == ["api", "ai-triage", "settings"]:
            settings = ai_triage.public_settings(ai_triage.data_dir_of(STORE))
            project_path = first("project_path")
            if project_path and len(project_path) <= 1024 and "\x00" not in project_path:
                settings["project_external_allowed"] = ai_triage.external_allowed(ai_triage.data_dir_of(STORE), project_path)
            return self._json(settings)
        if parts == ["api", "ai-triage", "suggestions"]:
            project_path = first("project_path")
            if not project_path or len(project_path) > 1024 or "\x00" in project_path:
                return self._error(HTTPStatus.BAD_REQUEST, "project_path sorgu parametresi gerekli.")
            try:
                items = ai_triage.list_suggestions(STORE, project_path=project_path, decision=first("decision") or None)
            except ai_triage.TriageError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))
            return self._json({"project_path": project_path, "suggestions": items, "total": len(items)})
        return self._error(HTTPStatus.NOT_FOUND, "Uç nokta bulunamadı.")

    def _ai_triage_finding_post(self, parts: list[str], payload: dict) -> None:
        """Analist: /api/finding-tracking/<id>/ai/run (yerel model) · /<id>/ai/<öneri>/decision (accept|reject|revert)."""
        tracked_id = parts[2]
        actor = request_context.current_actor()
        try:
            if len(parts) == 5 and parts[4] == "run":
                if not set(payload) <= {"confirm", "force"} or not isinstance(payload.get("force", False), bool):
                    return self._error(HTTPStatus.BAD_REQUEST, "Yalnız confirm ve force (true/false) alanları kullanılabilir.")
                return self._json(ai_triage.run_local(STORE, tracked_id, actor=actor, force=payload.get("force", False)))
            if len(parts) == 6 and parts[5] == "decision":
                if not set(payload) <= {"confirm", "decision", "note"} or "decision" not in payload:
                    return self._error(HTTPStatus.BAD_REQUEST, "confirm, decision (accept|reject|revert) ve isteğe bağlı note gönderin.")
                own = [s["id"] for s in ai_triage.list_suggestions(STORE, tracked_id=tracked_id, limit=2000)]
                if parts[4] not in own:
                    return self._error(HTTPStatus.NOT_FOUND, "Öneri bu bulguya ait değil.")
                return self._json(ai_triage.decide(STORE, parts[4], payload.get("decision"), actor=actor,
                                                   note=payload.get("note") or ""))
        except LookupError as exc:
            return self._error(HTTPStatus.NOT_FOUND, str(exc))
        except (ai_triage.TriageError, finding_tracking.TrackingError) as exc:
            return self._error(HTTPStatus.BAD_REQUEST, str(exc))
        return self._error(HTTPStatus.NOT_FOUND, "Uç nokta bulunamadı.")

    def _ai_triage_post(self, path: str, payload: dict) -> None:
        """Yönetici: proje başına dış ajan izni, otomatik uygulama politikası, yerel model ayarları ve bağlantı testi."""
        if payload.get("confirm") is not True:
            return self._error(HTTPStatus.BAD_REQUEST, "İşlem için onay (confirm: true) gerekli.")
        data_dir = ai_triage.data_dir_of(STORE)
        actor = request_context.current_actor() or {}
        who = actor.get("username") or "yerel"
        try:
            if path == "/api/ai-triage/consent":
                if set(payload) != {"confirm", "project_path", "enabled"}:
                    return self._error(HTTPStatus.BAD_REQUEST, "confirm, project_path ve enabled gönderin.")
                project_path = ai_triage.resolve_project(STORE, payload.get("project_path"))
                policy = ai_triage.set_project_consent(data_dir, project_path, payload.get("enabled"), who)
                STORE.log("ai_triage.consent_changed", project_path, {"external_agents": payload.get("enabled")})
                return self._json({"project_path": project_path, "external_agents_allowed": payload.get("enabled") is True,
                                   "policy": policy})
            if path == "/api/ai-triage/auto-apply":
                if not set(payload) <= {"confirm", "enabled", "min_confidence", "per_agent", "require_consensus",
                                        "consensus_min_confidence"} or "enabled" not in payload:
                    return self._error(HTTPStatus.BAD_REQUEST, "confirm, enabled ve isteğe bağlı min_confidence, per_agent "
                                       "({ajan: {enabled, min_confidence} | null}), require_consensus (false | true | "
                                       "\"auto\"), consensus_min_confidence gönderin.")
                policy = ai_triage.set_auto_apply(data_dir, payload.get("enabled"), payload.get("min_confidence"), who,
                                                  per_agent=payload.get("per_agent"),
                                                  require_consensus=payload.get("require_consensus"),
                                                  consensus_min_confidence=payload.get("consensus_min_confidence"))
                STORE.log("ai_triage.policy_changed", "auto_apply", dict(policy["auto_apply"]))
                return self._json({"policy": policy})
            if path == "/api/ai-triage/local":
                if set(payload) != {"confirm", "settings"} or not isinstance(payload.get("settings"), dict):
                    return self._error(HTTPStatus.BAD_REQUEST, "confirm ve settings nesnesi gönderin.")
                allowed = {"enabled", "endpoint", "model", "timeout_seconds", "max_tokens", "daily_budget"}
                if not set(payload["settings"]) <= allowed:
                    return self._error(HTTPStatus.BAD_REQUEST, "Tanınmayan ayar alanı.")
                local = ai_triage.save_local(data_dir, payload["settings"], who)
                STORE.log("ai_triage.local_changed", "local", {k: local.get(k) for k in ("enabled", "endpoint", "model")})
                return self._json(ai_triage.public_settings(data_dir))
            if path == "/api/ai-triage/local/test":
                if set(payload) != {"confirm"}:
                    return self._error(HTTPStatus.BAD_REQUEST, "Yalnız confirm alanı kullanılabilir.")
                return self._json(ai_triage.test_local(data_dir))
        except LookupError as exc:
            return self._error(HTTPStatus.NOT_FOUND, str(exc))
        except ai_triage.TriageError as exc:
            return self._error(HTTPStatus.BAD_REQUEST, str(exc))
        return self._error(HTTPStatus.NOT_FOUND, "Uç nokta bulunamadı.")

    def _tracking_assigned(self, query: dict) -> None:
        """/api/finding-tracking/assigned?assignee=me|all|<kullanıcı kimliği ya da ad>&status=&severity=&overdue=1&project_path="""
        first = lambda key: (query.get(key) or [""])[0]  # noqa: E731
        assignee = first("assignee").strip()
        if len(assignee) > 200 or "\x00" in assignee:
            return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz sorumlu filtresi.")
        filters: dict = {
            "statuses": {item for item in first("status").split(",") if item} or None,
            "severities": {item for item in first("severity").split(",") if item} or None,
            "overdue_only": first("overdue") == "1",
            "project_path": first("project_path") or None,
        }
        actor = request_context.current_actor()
        if _tracking_auth_enabled():
            if assignee in {"", "me"}:
                if not actor:
                    return self._error(HTTPStatus.UNAUTHORIZED, "Oturum açmanız gerekiyor.")
                filters["assignee_id"] = actor.get("id")
            elif assignee != "all":
                filters["assignee_id"] = assignee
        elif assignee == "me":
            return self._error(HTTPStatus.BAD_REQUEST, "Giriş kapalıyken 'bana atananlar' için sorumlu adını yazın.")
        elif assignee not in {"", "all"}:
            filters["assignee_name"] = assignee
        try:
            items = STORE.list_assigned_findings(**filters)
        except finding_tracking.TrackingError as exc:
            return self._error(HTTPStatus.BAD_REQUEST, str(exc))
        return self._json({"findings": items, "total": len(items), "assignee": assignee or ("me" if actor else "all"),
                           "overdue": sum(1 for item in items if item.get("overdue"))})

    def _finding_tracking_collab_post(self, parts: list[str], payload: dict) -> None:
        """Sorumlu atama, son tarih ve yorumlar (analist; başkasının yorumunu yalnız yönetici siler)."""
        tracked_id = parts[2]
        action = parts[3]
        actor = request_context.current_actor()
        try:
            if action == "assign" and len(parts) == 4:
                if not set(payload) <= {"confirm", "assignee_id", "assignee_name"}:
                    return self._error(HTTPStatus.BAD_REQUEST, "Yalnız confirm, assignee_id ve assignee_name alanları kullanılabilir.")
                assignee_id, assignee_name = _resolve_tracking_assignee(payload.get("assignee_id"), payload.get("assignee_name"))
                outcome = STORE.assign_tracked_finding(tracked_id, assignee_id, assignee_name)
                if outcome["changed"] and assignee_name:
                    try:
                        notifications.on_finding_assigned(outcome["finding"], actor=actor)
                    except ops_files.OpsStoreError:
                        pass
                    except Exception:
                        traceback.print_exc()  # bildirim hatası atamayı geri almaz
                return self._json(outcome["finding"])
            if action == "due" and len(parts) == 4:
                if not set(payload) <= {"confirm", "due_date"} or "due_date" not in payload:
                    return self._error(HTTPStatus.BAD_REQUEST, "confirm ve due_date (YYYY-AA-GG ya da null) gönderin.")
                outcome = STORE.set_tracked_finding_due(tracked_id, finding_tracking.parse_due_date(payload.get("due_date")))
                return self._json(outcome["finding"])
            if action == "comments" and len(parts) == 4:
                if set(payload) != {"confirm", "body"}:
                    return self._error(HTTPStatus.BAD_REQUEST, "Yalnız confirm ve body alanları kullanılabilir.")
                comment = STORE.add_tracked_finding_comment(
                    tracked_id, actor.get("id") if actor else None, actor.get("username", "") if actor else "", payload.get("body"))
                return self._json(comment, status=HTTPStatus.CREATED)
            if action == "comments" and len(parts) == 6 and parts[5] == "delete" and parts[4].isdigit() and len(parts[4]) <= 12:
                if set(payload) != {"confirm"}:
                    return self._error(HTTPStatus.BAD_REQUEST, "Yalnız confirm alanı kullanılabilir.")
                deleted = STORE.delete_tracked_finding_comment(
                    tracked_id, int(parts[4]), actor.get("id") if actor else None, bool(actor and actor.get("role") == "admin"))
                return self._json({"deleted": True, "comment_id": deleted["id"]})
        except LookupError as exc:
            return self._error(HTTPStatus.NOT_FOUND, str(exc))
        except PermissionError as exc:
            return self._error(HTTPStatus.FORBIDDEN, str(exc))
        except finding_tracking.TrackingError as exc:
            return self._error(HTTPStatus.BAD_REQUEST, str(exc))
        return self._error(HTTPStatus.NOT_FOUND, "Uç nokta bulunamadı.")

    # -- portföy, SLA ve dışa aktarım (17. tur) ------------------------------------------------
    def _portfolio_get(self, path: str, query: dict) -> None:
        """/api/portfolio?weeks=12 (okuyucu) · /api/portfolio/sla-policy (okuyucu) ·
        /api/portfolio/export?format=defectdojo|jira|csv&project_path=&status=active (analist; denetim kaydına yazılır)."""
        first = lambda key, default="": (query.get(key) or [default])[0]  # noqa: E731
        policy, _customized = portfolio.load_policy()
        if path == "/api/portfolio/sla-policy":
            return self._json(_sla_policy_payload())
        if path == "/api/portfolio":
            weeks = first("weeks", "12")
            if not weeks.isdigit() or not 1 <= int(weeks) <= 104:
                return self._error(HTTPStatus.BAD_REQUEST, "weeks 1–104 arası tam sayı olmalı.")
            # 25. tur: toplu tarama grubu ve kök dizine göre süzgeç (?group=…&root=…)
            group, root = first("group").strip(), first("root").strip()
            if len(group) > 60 or len(root) > 1024 or "\x00" in group + root or (root and not root.startswith("/")):
                return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz group ya da root süzgeci.")
            keep = bulk_scan.project_filter(group=group or None, root=root or None)
            data = STORE.portfolio_overview(policy, weeks=int(weeks), project_filter=keep)
            data["filter"] = {"group": group or None, "root": root or None}
            data["bulk_groups"] = bulk_scan.groups()
            return self._json(data)
        fmt = first("format")
        if fmt not in portfolio.EXPORT_FORMATS:
            return self._error(HTTPStatus.BAD_REQUEST, "format defectdojo, jira ya da csv olmalı.")
        project_path = first("project_path")
        if len(project_path) > 1024 or "\x00" in project_path:
            return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz project_path.")
        try:
            statuses = portfolio.parse_status_filter(first("status", "active"))
        except finding_tracking.TrackingError as exc:
            return self._error(HTTPStatus.BAD_REQUEST, str(exc))
        items = STORE.portfolio_export_rows(policy, project_path=project_path or None, statuses=statuses)
        body, content_type, extension = portfolio.render_export(fmt, items)
        STORE.log("portfolio.exported", fmt, {"count": len(items), "project_path": project_path or None,
                                              "statuses": sorted(statuses)})
        stamp = date.today().strftime("%Y%m%d")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Disposition", f'attachment; filename="sniper-bulgular-{fmt}-{stamp}.{extension}"')
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _retention_post(self, path: str, payload: dict) -> None:
        """Yönetici: şimdi yedek al, saklama politikasını kaydet, önizlenen planı yürüt (hepsi confirm: true)."""
        if payload.get("confirm") is not True:
            return self._error(HTTPStatus.BAD_REQUEST, "İşlem için onay (confirm: true) gerekli.")
        try:
            if path == "/api/system/backups":
                if set(payload) != {"confirm"}:
                    return self._error(HTTPStatus.BAD_REQUEST, "Yalnız confirm alanı kullanılabilir.")
                result = data_retention.take_backup(DATA_DIR, label="ui")
                STORE.log("system_backup.created", "backup", {"names": [b["name"] for b in result["created"]],
                                                              "integrity": [b["integrity"] for b in result["created"]]})
                return self._json({**result, **_backups_payload()}, status=HTTPStatus.CREATED)
            if path == "/api/system/retention/policy":
                if not set(payload) <= {"confirm", "policy"} or "policy" not in payload:
                    return self._error(HTTPStatus.BAD_REQUEST, "confirm: true ve policy gönderin.")
                policy = data_retention.save_policy(payload["policy"])
                STORE.log("data_retention.policy_changed", "retention", {"enabled": policy["enabled"],
                                                                         "auto_daily": policy["auto_daily"]})
                return self._json(_retention_payload())
            if not set(payload) <= {"confirm", "plan_id"} or not isinstance(payload.get("plan_id"), str):
                return self._error(HTTPStatus.BAD_REQUEST, "confirm: true ve önizlemedeki plan_id gönderin.")
            result = data_retention.execute_plan(DATA_DIR, payload["plan_id"],
                                                 log=lambda action, entity, details: STORE.log(action, entity, details))
            return self._json({**result, **_retention_payload()})
        except data_retention.RetentionError as exc:
            status = HTTPStatus.CONFLICT if "değişti" in str(exc) else HTTPStatus.BAD_REQUEST
            return self._error(status, str(exc))
        except ops_files.OpsStoreError as exc:
            return self._error(HTTPStatus.SERVICE_UNAVAILABLE, str(exc))

    def _portfolio_post(self, path: str, payload: dict) -> None:
        """SLA politikası (yönetici, onaylı; reset: varsayılana dön) ve mevcut bulgulara SLA son tarihi uygulama."""
        if payload.get("confirm") is not True:
            return self._error(HTTPStatus.BAD_REQUEST, "İşlem için onay (confirm: true) gerekli.")
        try:
            if path == "/api/portfolio/sla-policy/apply":
                if set(payload) != {"confirm"}:
                    return self._error(HTTPStatus.BAD_REQUEST, "Yalnız confirm alanı kullanılabilir.")
                policy, _customized = portfolio.load_policy()
                return self._json(STORE.apply_sla_due_dates(policy))
            if not set(payload) <= {"confirm", "policy", "reset"} or ("policy" in payload) == (payload.get("reset") is True):
                return self._error(HTTPStatus.BAD_REQUEST, "confirm: true ile ya policy ya da reset: true gönderin.")
            policy = portfolio.reset_policy() if payload.get("reset") is True else portfolio.save_policy(payload.get("policy"))
        except portfolio.PolicyError as exc:
            return self._error(HTTPStatus.BAD_REQUEST, str(exc))
        except ops_files.OpsStoreError as exc:
            return self._error(HTTPStatus.SERVICE_UNAVAILABLE, str(exc))
        STORE.log("sla_policy.changed", "sla-policy", {"reset": payload.get("reset") is True, **policy})
        return self._json(_sla_policy_payload())

    def _ops_get(self, path: str, query: dict) -> None:
        try:
            if path == "/api/schedules":
                return self._json(sniper_scheduler.public(sniper_scheduler.load()))
            if path == "/api/notifications":
                limit = query.get("limit", ["100"])[0]
                return self._json(notifications.list_items(
                    unread_only=query.get("unread", ["0"])[0] == "1", limit=int(limit) if limit.isdigit() else 100))
            return self._json(notifications.public_settings())
        except ops_files.OpsStoreError as exc:
            return self._error(HTTPStatus.SERVICE_UNAVAILABLE, str(exc))

    def _ops_post(self, path: str, payload: dict) -> None:
        """Zamanlanmış taramalar ve bildirim ayarları: değişiklikler confirm: true ister ve denetim kaydına yazılır."""
        try:
            if path == "/api/notifications":
                if set(payload) - {"action", "ids"} or payload.get("action") != "mark-read":
                    return self._error(HTTPStatus.BAD_REQUEST, "Yalnız {action: 'mark-read', ids: 'all' | [...]} kabul edilir.")
                return self._json({"marked": notifications.mark_read(payload.get("ids", "all"))})
            if payload.get("confirm") is not True:
                # 23. tur: eksik onay bir istek hatasıdır (400); 403 yetki reddi için ayrılmıştır.
                return self._error(HTTPStatus.BAD_REQUEST, "Değişiklik için onay (confirm: true) gerekli.")
            if path == "/api/notification-settings":
                action = payload.get("action", "save")
                if action == "test":
                    if set(payload) - {"confirm", "action"}:
                        return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz alanlar.")
                    item = notifications.send_test()
                    STORE.log("notification.test", item["id"], {"channels": item["channels"]})
                    return self._json(item)
                if action != "save" or set(payload) - {"confirm", "action", "settings", "smtp_password"}:
                    return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz işlem veya alanlar.")
                result = notifications.save_settings(payload.get("settings"), smtp_password=payload.get("smtp_password"))
                channels = result["channels"]
                STORE.log("notification_settings.changed", "default", {
                    "desktop": channels["desktop"]["enabled"], "smtp": channels["smtp"]["enabled"],
                    "webhook": channels["webhook"]["enabled"], "smtp_password_changed": payload.get("smtp_password") is not None,
                    "quiet_hours": result["quiet_hours"]["enabled"],
                })
                return self._json(result)
            action = payload.get("action")
            if action not in {"create", "update", "delete", "enable", "disable", "timezone", "run-now"}:
                return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz işlem.")
            if set(payload) - {"confirm", "action", "id", "schedule", "timezone"}:
                return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz alanlar.")
            if action == "run-now":
                outcome = _scheduler_for(self.server).run_now(str(payload.get("id") or ""))
                return self._json(outcome, status=HTTPStatus.ACCEPTED if outcome.get("status") == "submitted" else HTTPStatus.OK)

            def validate_path(value: str, kind: str = "project") -> str:
                # 21. tur: hedef türüne göre izinli kök doğrulaması (proje dizini, imaj/rootfs, SBOM dosyası)
                try:
                    if kind == "image":
                        return str(container_scan.validate_image_path(value))
                    if kind == "sbom":
                        return str(sbom_scan.validate_sbom_path(value))
                    return str(validate_project_path(value))  # project ve (25. tur) directory: izinli kök altında dizin
                except (ProjectRejected, container_scan.ContainerScanError, sbom_scan.SbomScanError) as exc:
                    raise sniper_scheduler.ScheduleError(str(exc)) from exc

            result = sniper_scheduler.apply_action(action, payload, validate_path=validate_path)
            if action == "timezone":
                STORE.log("schedule.timezone_changed", "default", {"timezone": result["timezone"]})
            else:
                item = result["schedule"]
                STORE.log(f"schedule.{'created' if action == 'create' else 'deleted' if action == 'delete' else 'updated'}",
                          item["id"], {"scan_type": item.get("scan_type"), "frequency": item.get("frequency"),
                                       "enabled": item.get("enabled"), "project_path": item.get("project_path")})
            return self._json({**sniper_scheduler.public(result["data"]), "changed": result.get("schedule") or result.get("timezone")})
        except (sniper_scheduler.ScheduleError, notifications.NotificationError) as exc:
            return self._error(HTTPStatus.BAD_REQUEST, str(exc))
        except ops_files.OpsStoreError as exc:
            return self._error(HTTPStatus.SERVICE_UNAVAILABLE, str(exc))
    def _project_threat_model(self, audit: dict) -> None:
        """Proje analizinin tehdit modeli (STRIDE + DFD SVG). Eski analizlerde model yoksa ve proje klasörü hâlâ
        varsa dosyalardan yeniden çıkarılır (yalnız okuma; kayıt değiştirilmez)."""
        import threat_model

        model = audit.get("threat_model")
        rebuilt = False
        if not isinstance(model, dict):
            try:
                from project_analyzer import _iter_files, validate_project_path

                root = validate_project_path(str(audit.get("project_path") or ""))
                files = ((path.relative_to(root).as_posix(), text, kind) for path, text, kind in _iter_files(root))
                model = threat_model.build_from_paths(root, files, list(audit.get("findings") or []), project_name=root.name)
                rebuilt = True
            except (ProjectRejected, OSError, ValueError):
                return self._error(HTTPStatus.NOT_FOUND, "Bu analiz için tehdit modeli yok ve proje klasörü okunamıyor.")
        return self._json({"audit_id": audit.get("id"), "rebuilt_from_disk": rebuilt, "threat_model": model,
                           "svg": threat_model.render_svg(model)})

    def _sandbox_targets_post(self, payload: dict) -> None:
        """Yalıtılmış test hedefleri: tek onay (confirm: true); her değişiklik imzalı denetim kaydına yazılır."""
        if not isinstance(payload, dict) or payload.get("confirm") is not True:
            return self._error(HTTPStatus.BAD_REQUEST, "Değişiklik için onay (confirm: true) gerekli.")  # 23. tur: 400
        action = payload.get("action")
        fields = set(payload) - {"confirm", "action"}
        allowed = {
            "scope": {"scope", "enabled"}, "add-local": {"port", "tools", "label"}, "remove": {"id"},
            "set-tools": {"id", "tools"},
            "verify-start": {"host", "port", "scheme", "tools", "label"}, "verify": {"id"},
            "preset-set": {"name", "vus", "duration_s", "label"}, "preset-remove": {"name"},
            "limits": {"st_max_time_s", "st_max_examples"},
        }
        if action not in allowed or not fields <= allowed[action]:
            return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz işlem veya alanlar.")
        try:
            if action == "scope":
                scopes = sandbox_targets.set_scope(payload.get("scope"), payload.get("enabled"))
                STORE.log("sandbox_scope.changed", str(payload.get("scope")), {"enabled": payload.get("enabled")})
                result: dict = {"scopes": scopes}
                if payload.get("scope") == "critical" and payload.get("enabled"):
                    result["warning"] = sandbox_targets.CRITICAL_WARNING
            elif action == "add-local":
                entry = sandbox_targets.add_local_target(payload.get("port"), payload.get("tools"), payload.get("label", ""))
                STORE.log("sandbox_target.added", entry["id"], {"tools": entry["tools"], "critical": entry["critical"]})
                result = {"added": entry}
                if entry["critical"]:
                    result["warning"] = sandbox_targets.CRITICAL_WARNING
            elif action == "set-tools":
                entry = sandbox_targets.set_target_tools(payload.get("id"), payload.get("tools"))
                STORE.log("sandbox_target.tools_changed", entry["id"], {"tools": entry["tools"]})
                result = {"updated": entry}
            elif action == "remove":
                if not sandbox_targets.remove_target(payload.get("id")):
                    return self._error(HTTPStatus.NOT_FOUND, "Hedef listede yok.")
                STORE.log("sandbox_target.removed", str(payload.get("id")), {})
                result = {"removed": payload.get("id")}
            elif action == "verify-start":
                item = sandbox_targets.start_verification(payload.get("host"), payload.get("port", 443),
                                                          payload.get("scheme", "https"), payload.get("tools"),
                                                          payload.get("label", ""))
                STORE.log("sandbox_verification.started", item["host"], {"id": item["id"], "port": item["port"]})
                result = {"verification": {k: item[k] for k in ("id", "host", "port", "scheme", "expires_at",
                                                                "http_url", "http_body", "dns_name", "dns_value")}}
            elif action == "verify":
                started = time.time()
                entry = sandbox_targets.check_verification(payload.get("id"))
                STORE.log("sandbox_target.verified", entry["id"], {
                    "method": entry["verification"]["method"], "evidence_sha256": entry["verification"]["evidence_sha256"],
                    "duration_ms": int((time.time() - started) * 1000)})
                result = {"verified": entry}
            elif action == "preset-set":
                preset = sandbox_targets.set_preset(payload.get("name"), payload.get("vus"), payload.get("duration_s"),
                                                    payload.get("label", ""))
                STORE.log("sandbox_preset.set", str(payload.get("name")), preset)
                result = {"preset": preset}
            elif action == "preset-remove":
                if not sandbox_targets.remove_preset(payload.get("name")):
                    return self._error(HTTPStatus.NOT_FOUND, "Profil bulunamadı.")
                STORE.log("sandbox_preset.removed", str(payload.get("name")), {})
                result = {"removed_preset": payload.get("name")}
            else:
                limits = sandbox_targets.set_limits({k: payload[k] for k in fields})
                STORE.log("sandbox_limits.changed", "schemathesis", limits)
                result = {"limits": limits}
        except sandbox_targets.VerificationFailed as exc:
            STORE.log("sandbox_target.verification_failed", str(payload.get("id")), {})
            return self._error(HTTPStatus.UNPROCESSABLE_ENTITY, str(exc))
        except sandbox_targets.ScopeDisabled as exc:
            return self._error(HTTPStatus.FORBIDDEN, str(exc))
        except sandbox_targets.TargetError as exc:
            return self._error(HTTPStatus.BAD_REQUEST, str(exc))
        status = HTTPStatus.CREATED if action in ("add-local", "verify-start") else HTTPStatus.OK
        return self._json({**result, **sandbox_targets.status()}, status=status)

    def _taint_rules_get(self, path: str) -> None:
        import taint_rules_dsl

        if path == "/api/taint-rules/opengrep":
            try:
                rules = [{k: v for k, v in r.items() if not k.startswith("_")} for r in taint_rules_dsl.list_rules()]
            except taint_rules_dsl.RuleError as exc:
                return self._error(HTTPStatus.SERVICE_UNAVAILABLE, str(exc))
            return self._json(taint_rules_dsl.compile_opengrep(rules))
        return self._json(taint_rules_dsl.status())

    def _taint_rules_post(self, path: str, payload: dict) -> None:
        import taint_rules_dsl

        parts = [part for part in path.split("/") if part]
        try:
            if path == "/api/taint-rules/try":
                if not set(payload).issubset({"content", "code", "filename"}):
                    return self._error(HTTPStatus.BAD_REQUEST, "Deneme isteğinde yalnız content, code ve filename kullanılabilir.")
                return self._json(taint_rules_dsl.try_rule(
                    payload.get("content", ""), payload.get("code", ""), str(payload.get("filename") or "")))
            if path == "/api/taint-rules":
                if not set(payload).issubset({"content", "confirm_custom_rules"}):
                    return self._error(HTTPStatus.BAD_REQUEST, "Kural isteğinde yalnız content ve confirm_custom_rules kullanılabilir.")
                if payload.get("confirm_custom_rules") is not True:
                    return self._error(HTTPStatus.BAD_REQUEST, "Özel kural kaydı için açık onay (confirm_custom_rules: true) gerekli.")
                saved = taint_rules_dsl.save_rule(payload.get("content", ""))
                STORE.log("taint_rule.saved", saved["name"], {"language": saved["language"], "sha256": saved["sha256"]})
                return self._json(saved, status=HTTPStatus.CREATED)
            if len(parts) == 4 and parts[3] == "delete":
                if payload.get("confirm_custom_rules") is not True:
                    return self._error(HTTPStatus.BAD_REQUEST, "Kural silmek için açık onay (confirm_custom_rules: true) gerekli.")
                if not taint_rules_dsl.delete_rule(parts[2]):
                    return self._error(HTTPStatus.NOT_FOUND, "Kural bulunamadı.")
                STORE.log("taint_rule.deleted", parts[2], {})
                return self._json({"deleted": parts[2]})
        except taint_rules_dsl.RuleError as exc:
            return self._error(HTTPStatus.BAD_REQUEST, str(exc))
        return self._error(HTTPStatus.NOT_FOUND, "Uç nokta bulunamadı.")

    def _autofix_verify_post(self, audit_id: str, raw_index: str, payload: dict) -> None:
        import fix_verification

        if payload:
            return self._error(HTTPStatus.BAD_REQUEST, "Düzeltme doğrulama isteği gövde alanı almaz.")
        if not raw_index.isdigit() or str(int(raw_index)) != raw_index:
            return self._error(HTTPStatus.BAD_REQUEST, "Bulgu sırası negatif olmayan bir tamsayı olmalı.")
        audit = STORE.get_project_audit(audit_id)
        if not audit:
            return self._error(HTTPStatus.NOT_FOUND, "Proje analizi bulunamadı.")
        try:
            result = fix_verification.verify_finding_fix(audit, int(raw_index))
        except fix_verification.VerificationBusy as exc:
            return self._error(HTTPStatus.TOO_MANY_REQUESTS, str(exc))
        except fix_verification.AutofixError as exc:
            return self._error(HTTPStatus.BAD_REQUEST, str(exc))
        STORE.log("autofix.verified", audit_id, {"finding_index": int(raw_index), "verdict": result["verdict"]})
        return self._json(result)

    def _autofix_bulk_post(self, audit_id: str, payload: dict) -> None:
        import fix_verification

        if not set(payload) <= {"group", "indices"} or ("group" in payload) == ("indices" in payload):
            return self._error(HTTPStatus.BAD_REQUEST, "Toplu düzeltme için yalnız group ya da indices alanlarından biri verilmeli.")
        group = payload.get("group")
        if "group" in payload and (not isinstance(group, str) or not group or len(group) > 400):
            return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz grup anahtarı.")
        audit = STORE.get_project_audit(audit_id)
        if not audit:
            return self._error(HTTPStatus.NOT_FOUND, "Proje analizi bulunamadı.")
        try:
            result = fix_verification.verify_bulk_fix(audit, group=group if "group" in payload else None,
                                                      indices=payload.get("indices") if "indices" in payload else None)
        except fix_verification.VerificationBusy as exc:
            return self._error(HTTPStatus.TOO_MANY_REQUESTS, str(exc))
        except fix_verification.AutofixError as exc:
            return self._error(HTTPStatus.BAD_REQUEST, str(exc))
        STORE.log("autofix.bulk_verified", audit_id, {"count": len(result.get("selected") or []), "verdict": result["verdict"],
                                                      "closed": len(result.get("closed_indices") or [])})
        return self._json(result)

    def _autofix_post(self, audit_id: str, raw_index: str, payload: dict) -> None:
        import taint_autofix

        if payload:
            return self._error(HTTPStatus.BAD_REQUEST, "Düzeltme önerisi isteği gövde alanı almaz.")
        if not raw_index.isdigit() or str(int(raw_index)) != raw_index:
            return self._error(HTTPStatus.BAD_REQUEST, "Bulgu sırası negatif olmayan bir tamsayı olmalı.")
        audit = STORE.get_project_audit(audit_id)
        if not audit:
            return self._error(HTTPStatus.NOT_FOUND, "Proje analizi bulunamadı.")
        try:
            return self._json(taint_autofix.suggest_for_finding(audit, int(raw_index)))
        except taint_autofix.AutofixError as exc:
            return self._error(HTTPStatus.BAD_REQUEST, str(exc))

    def _jobs_post(self, path: str, payload: dict) -> None:
        parts = [part for part in path.split("/") if part]
        if path == "/api/jobs":
            if not set(payload).issubset({"route", "payload"}):
                return self._error(HTTPStatus.BAD_REQUEST, "İş isteğinde yalnız route ve payload alanları kullanılabilir.")
            route = payload.get("route")
            inner = payload.get("payload", {})
            if not isinstance(route, str) or route not in JOB_ROUTES:
                return self._error(HTTPStatus.BAD_REQUEST, "Bu rota iş kuyruğunda çalıştırılamaz.")
            if not isinstance(inner, dict):
                return self._error(HTTPStatus.BAD_REQUEST, "payload bir JSON nesnesi olmalı.")
            if auth_routes.job_submit_denied(self, route):
                return None
            # Oturum çerezi / CSRF belirteci işe taşınmaz; iş, kuyruğa alan kullanıcının kimliğiyle çalışır.
            header_items = auth_routes.job_headers(self.headers)
            client_address = self.client_address
            server = self.server
            actor = request_context.current_actor()

            def runner(job) -> tuple[int, object]:
                with request_context.acting_as(actor):
                    if route in SUBPROCESS_JOB_ROUTES:
                        return _run_post_subprocess(server, client_address, header_items, route, inner, actor=actor,
                                                    progress=job.set_progress)
                    return _run_post_capture(server, client_address, header_items, route, inner)

            try:
                job = JOBS.submit(route, runner, dedupe_key=_job_dedupe_key(route, inner), label=_job_label(route, inner))
            except JobQueueError as exc:
                return self._error(exc.status, str(exc))
            auth_routes.remember_job_owner(job.id)
            STORE.log("job.created", job.id, {"route": route})
            return self._json(job.public(), status=HTTPStatus.ACCEPTED)
        if len(parts) == 4 and parts[3] == "cancel":
            if auth_routes.job_cancel_denied(self, parts[2]):
                return None
            result = JOBS.cancel(parts[2])
            if result is None:
                return self._error(HTTPStatus.NOT_FOUND, "İş bulunamadı.")
            STORE.log("job.cancel_requested", parts[2], {"route": result.get("route"), "state": result.get("state")})
            return self._json(result)
        return self._error(HTTPStatus.NOT_FOUND, "Uç nokta bulunamadı.")

    def _mcp_scan_requests_get(self) -> None:
        """İnsan incelemesi için MCP tarama istekleri; özel çalıştırma gövdesi hiçbir zaman dışarı verilmez."""
        try:
            return self._json({
                "requests": mcp_scan_requests.list_requests(STORE),
                "catalog": mcp_scan_requests.catalog(STORE),
            })
        except (mcp_scan_requests.ScanRequestError, ops_files.OpsStoreError) as exc:
            return self._error(HTTPStatus.SERVICE_UNAVAILABLE, str(exc))

    def _asan_selftest_post(self, payload: dict) -> None:
        if set(payload) != {"confirm_local"}:
            return self._error(HTTPStatus.BAD_REQUEST, "ASan öz sınaması yalnız confirm_local alanını kabul eder.")
        try:
            return self._json(asan_selftest.run(confirm_local=payload.get("confirm_local")))
        except asan_selftest.AsanUnavailable as exc:
            return self._error(HTTPStatus.SERVICE_UNAVAILABLE, str(exc))
        except asan_selftest.AsanSelftestError as exc:
            return self._error(HTTPStatus.BAD_REQUEST, str(exc))

    def _asan_project_proof_post(self, audit_id: str, finding_index: str, payload: dict) -> None:
        if set(payload) != {"binary_relpath", "confirm_local"}:
            return self._error(HTTPStatus.BAD_REQUEST,
                               "ASan proje kanıtı yalnız binary_relpath ve confirm_local alanlarını kabul eder.")
        if not finding_index.isdigit() or str(int(finding_index)) != finding_index:
            return self._error(HTTPStatus.BAD_REQUEST, "Bulgu sırası negatif olmayan tam sayı olmalı.")
        try:
            return self._json(asan_project_proof.run(
                STORE, audit_id, int(finding_index), binary_relpath=payload.get("binary_relpath"),
                confirm_local=payload.get("confirm_local"),
            ))
        except asan_project_proof.AsanProjectProofUnavailable as exc:
            return self._error(HTTPStatus.SERVICE_UNAVAILABLE, str(exc))
        except asan_project_proof.AsanProjectProofError as exc:
            return self._error(HTTPStatus.BAD_REQUEST, str(exc))

    def _asan_project_source_proof_post(self, audit_id: str, finding_index: str, payload: dict) -> None:
        if set(payload) not in ({"source_relpath", "confirm_local"},
                                {"source_relpath", "companion_relpaths", "confirm_local"}):
            return self._error(
                HTTPStatus.BAD_REQUEST,
                "ASan kaynak kanıtı yalnız source_relpath, isteğe bağlı companion_relpaths ve confirm_local alanlarını kabul eder.",
            )
        if not finding_index.isdigit() or str(int(finding_index)) != finding_index:
            return self._error(HTTPStatus.BAD_REQUEST, "Bulgu sırası negatif olmayan tam sayı olmalı.")
        try:
            return self._json(asan_project_proof.run_source(
                STORE, audit_id, int(finding_index), source_relpath=payload.get("source_relpath"),
                companion_relpaths=payload.get("companion_relpaths"), confirm_local=payload.get("confirm_local"),
            ))
        except asan_project_proof.AsanProjectProofUnavailable as exc:
            return self._error(HTTPStatus.SERVICE_UNAVAILABLE, str(exc))
        except (asan_project_proof.AsanProjectProofError, ValueError) as exc:
            return self._error(HTTPStatus.BAD_REQUEST, str(exc))

    def _asan_project_compile_database_proof_post(
        self, audit_id: str, finding_index: str, payload: dict,
    ) -> None:
        expected = {"compile_commands_relpath", "entry_index", "confirm_local"}
        if set(payload) != expected:
            return self._error(
                HTTPStatus.BAD_REQUEST,
                "ASan compile-database kanıtı yalnız compile_commands_relpath, entry_index ve confirm_local alanlarını kabul eder.",
            )
        if not finding_index.isdigit() or str(int(finding_index)) != finding_index:
            return self._error(HTTPStatus.BAD_REQUEST, "Bulgu sırası negatif olmayan tam sayı olmalı.")
        try:
            return self._json(asan_project_proof.run_compile_database(
                STORE, audit_id, int(finding_index),
                compile_commands_relpath=payload.get("compile_commands_relpath"),
                entry_index=payload.get("entry_index"), confirm_local=payload.get("confirm_local"),
            ))
        except asan_project_proof.AsanProjectProofUnavailable as exc:
            return self._error(HTTPStatus.SERVICE_UNAVAILABLE, str(exc))
        except (asan_project_proof.AsanProjectProofError, ValueError) as exc:
            return self._error(HTTPStatus.BAD_REQUEST, str(exc))

    def _dast_runtime_proof_post(self, audit_id: str, finding_index: str, payload: dict) -> None:
        expected = {"profile_id", "target", "path", "parameter", "confirm_local"}
        if set(payload) != expected:
            return self._error(HTTPStatus.BAD_REQUEST, "DAST kanıtı yalnız sabit profil alanlarını kabul eder.")
        if not finding_index.isdigit() or str(int(finding_index)) != finding_index:
            return self._error(HTTPStatus.BAD_REQUEST, "Bulgu sırası negatif olmayan tam sayı olmalı.")
        try:
            return self._json(dast_runtime.run(
                STORE, audit_id, int(finding_index), profile_id=payload.get("profile_id"),
                target=payload.get("target"), path=payload.get("path"), parameter=payload.get("parameter"),
                confirm_local=payload.get("confirm_local"),
            ))
        except dast_runtime.DastRuntimeUnavailable as exc:
            return self._error(HTTPStatus.BAD_GATEWAY, str(exc))
        except dast_runtime.DastRuntimeError as exc:
            return self._error(HTTPStatus.BAD_REQUEST, str(exc))

    def _mcp_scan_requests_post(self, path: str, payload: dict) -> None:
        parts = [part for part in path.split("/") if part]
        if len(parts) != 4 or parts[:2] != ["api", "mcp-scan-requests"] or parts[3] not in {"approve", "cancel"}:
            return self._error(HTTPStatus.NOT_FOUND, "Uç nokta bulunamadı.")
        request_id, action = parts[2], parts[3]
        if action == "cancel" and (set(payload) != {"confirm"} or payload.get("confirm") is not True):
            return self._error(HTTPStatus.BAD_REQUEST, "İptal için confirm tam olarak true olmalı.")
        if action == "approve" and (set(payload) != {"confirm", "confirm_authorized"} \
                or payload.get("confirm") is not True or payload.get("confirm_authorized") is not True):
            return self._error(
                HTTPStatus.BAD_REQUEST,
                "İşlem için confirm ve insan hedef yetkisi beyanı confirm_authorized tam olarak true olmalı.",
            )
        actor = request_context.current_actor() or {"id": "local-admin", "username": "yerel", "role": "admin"}
        try:
            if action == "cancel":
                candidate = mcp_scan_requests.inspect_cancel_request(STORE, request_id, cancelled_by=actor)
                cancelled_job_id = None
                cancelled_scanner_job_id = None
                if candidate.get("status") in {"started", "running"}:
                    scanner_job_id = candidate.get("scanner_job_id")
                    if scanner_job_id is not None:
                        parameters = candidate.get("parameters")
                        is_nuclei = candidate.get("profile_id") == "nuclei_http_authorized" \
                            or (candidate.get("profile_id") == "operator_authorized_http"
                                and isinstance(parameters, dict) and parameters.get("tool_id") == "nuclei")
                        if not is_nuclei or not isinstance(scanner_job_id, str) \
                                or re.fullmatch(r"[0-9a-f]{16}", scanner_job_id) is None:
                            raise mcp_scan_requests.ScanRequestError("Nuclei iç iş kimliği iptal için geçersiz.")
                        try:
                            inner_cancel = get_broad_nuclei_jobs().cancel(scanner_job_id)
                        except (FileNotFoundError, NucleiBroadUnavailable, OSError, RuntimeError, ValueError) as exc:
                            raise mcp_scan_requests.ScanRequestError(
                                "Nuclei iç işi bulunamadı veya iptal kabul etmedi."
                            ) from exc
                        if not isinstance(inner_cancel, dict) \
                                or inner_cancel.get("job_id") != scanner_job_id \
                                or inner_cancel.get("state") != "cancelled":
                            raise mcp_scan_requests.ScanRequestError("Nuclei iç işi artık iptal edilebilir durumda değil.")
                        cancelled_scanner_job_id = scanner_job_id
                    else:
                        job_id = candidate.get("job_id")
                        if not isinstance(job_id, str):
                            raise mcp_scan_requests.ScanRequestError("Dış iş kimliği iptal için geçersiz.")
                        outer = JOBS.get(job_id)
                        if not isinstance(outer, dict) or outer.get("state") not in {"queued", "running"}:
                            raise mcp_scan_requests.ScanRequestError("Dış iş bulunamadı veya artık iptal edilemez.")
                        cancelled = JOBS.cancel(job_id)
                        accepted = isinstance(cancelled, dict) and (
                            cancelled.get("state") == "cancelled"
                            or (cancelled.get("state") in {"queued", "running"}
                                and cancelled.get("cancel_requested") is True)
                        )
                        if not accepted:
                            raise mcp_scan_requests.ScanRequestError("Dış iş iptal isteğini kabul etmedi.")
                        cancelled_job_id = job_id
                item = mcp_scan_requests.cancel_request(
                    STORE, request_id, cancelled_by=actor,
                    cancelled_job_id=cancelled_job_id,
                    cancelled_scanner_job_id=cancelled_scanner_job_id,
                )
                STORE.log("mcp_scan_request.cancelled", request_id, {"profile_id": item.get("profile_id")})
                return self._json({"request": item})

            claim = mcp_scan_requests.claim_request(
                STORE, request_id, approved_by=actor, confirm_authorized=payload.get("confirm_authorized"),
            )
            if "dispatch" in claim:
                STORE.log("mcp_scan_request.authorized", request_id, {
                    "profile_id": claim.get("profile_id"),
                    "tool_id": claim["dispatch"].get("tool_id"),
                    "receipt_sha256": claim.get("authorization_receipt", {}).get("receipt_sha256"),
                })
                return self._json({"request": claim, "dispatch": claim["dispatch"]})
            route = claim["launch"]["route"]
            inner = claim["launch"]["payload"]
            if route not in JOB_ROUTES:
                mcp_scan_requests.mark_failed(STORE, request_id, "profil rotası iş kuyruğunda değil")
                return self._error(HTTPStatus.CONFLICT, "Tarama profili artık kullanılamıyor.")
            if auth_routes.job_submit_denied(self, route):
                mcp_scan_requests.mark_failed(STORE, request_id, "onaylayan kullanıcı iç rota için yetkisiz")
                return None
            header_items = auth_routes.job_headers(self.headers)
            client_address = self.client_address
            server = self.server

            def runner(job) -> tuple[int, object]:
                with request_context.acting_as(actor):
                    if route in SUBPROCESS_JOB_ROUTES:
                        return _run_post_subprocess(server, client_address, header_items, route, inner, actor=actor,
                                                    progress=job.set_progress)
                    return _run_post_capture(server, client_address, header_items, route, inner)

            started_item: dict = {}

            def persist_reserved_job(reserved_job) -> None:
                started_item.update(mcp_scan_requests.mark_started(STORE, request_id, reserved_job.id))

            job = JOBS.submit(
                route, runner, dedupe_key=_job_dedupe_key(route, inner), label=_job_label(route, inner),
                before_enqueue=persist_reserved_job,
            )
            try:
                auth_routes.remember_job_owner(job.id)
            except (OSError, RuntimeError):
                # İş zaten güvenle publish edilmiştir; sahiplik önbelleği hatası yetkili işi
                # 503/failure gibi gösteremez. Kalıcı MCP job_id bağı erişim izini korur.
                pass
            # Unit adapters that replace ``submit`` may not execute the reservation callback;
            # the production JobQueue always does so before publishing the job.
            item = started_item or mcp_scan_requests.mark_started(STORE, request_id, job.id)
            try:
                STORE.log("mcp_scan_request.started", request_id, {"profile_id": item.get("profile_id"),
                                                                   "job_id": job.id, "route": route,
                                                                   "receipt_sha256": item.get(
                                                                       "authorization_receipt", {}
                                                                   ).get("receipt_sha256")})
            except (ops_files.OpsStoreError, OSError, RuntimeError):
                # Audit-log failure after publish is best-effort: returning 503 and compensating
                # the MCP row would falsely claim the already runnable authorized job was stopped.
                pass
            return self._json({"request": item, "job": job.public()}, status=HTTPStatus.ACCEPTED)
        except mcp_scan_requests.ScanRequestError as exc:
            return self._error(HTTPStatus.CONFLICT, str(exc))
        except JobQueueError as exc:
            try:
                mcp_scan_requests.mark_failed(STORE, request_id, str(exc))
            except mcp_scan_requests.ScanRequestError:
                pass
            return self._error(exc.status, str(exc))
        except ops_files.OpsStoreError as exc:
            try:
                failed = mcp_scan_requests.mark_failed(
                    STORE, request_id, "iş kimliği kalıcı kuyruğa bağlanamadı",
                )
                STORE.log("mcp_scan_request.failed", request_id, {
                    "profile_id": failed.get("profile_id"),
                    "reason": "job_link_persistence",
                })
            except (mcp_scan_requests.ScanRequestError, ops_files.OpsStoreError, OSError):
                pass
            return self._error(HTTPStatus.SERVICE_UNAVAILABLE, str(exc))
        except Exception as exc:
            try:
                mcp_scan_requests.mark_failed(STORE, request_id, "iş kuyruğu beklenmeyen hata")
                STORE.log("mcp_scan_request.failed", request_id, {"error_type": type(exc).__name__})
            except (mcp_scan_requests.ScanRequestError, ops_files.OpsStoreError, OSError):
                pass
            return self._error(HTTPStatus.SERVICE_UNAVAILABLE, "Tarama isteği iş kuyruğuna alınamadı.")

    def _eval_get(self, path: str) -> None:
        """Doğruluk panosu (salt okunur): ölçüm geçmişi, son ölçüm ve triyaja göre kural yanlış alarm oranları."""
        import eval_metrics

        if path == "/api/eval/rule-false-positives":
            return self._json(eval_metrics.triage_rule_stats(STORE.path))
        paths = eval_metrics.list_history(eval_metrics.history_dir())
        if not paths.analysis_complete:
            if path == "/api/eval/history":
                return self._json({"history": [], "warnings": [paths.warning]})
            return self._json({"latest": None, "warnings": [paths.warning]})
        if path == "/api/eval/history":
            records = [eval_metrics.read_history(item) for item in paths[-50:]]
            return self._json({"history": [eval_metrics.summarize({**r, "file": r.get("file") or item.name})
                                           for item, r in zip(paths[-50:], records) if r]})
        record = eval_metrics.read_history(paths[-1]) if paths else None
        if not record:
            return self._json({"latest": None})
        summary = eval_metrics.summarize({**record, "file": record.get("file") or paths[-1].name})
        sets = {}
        for name, data in (record.get("sets") or {}).items():
            verified = data.get("verified") or {}
            sets[name] = {
                "per_project": verified.get("per_project") or {name_: {"verified_flows": row.get("verified_flows"),
                                                                        "seconds": row.get("seconds"), "error": row.get("error")}
                                                                for name_, row in (data.get("projects") or {}).items()},
                "missed_classes": verified.get("missed_classes") or {},
                "unmatched": [{k: row.get(k) for k in ("key", "verdict")} for row in verified.get("unmatched") or []][:200],
                "codeql_only": (data.get("codeql") or {}).get("only_codeql") or [],
            }
        return self._json({"latest": summary, "details": sets, "regressions": record.get("regressions") or [],
                           "warnings": record.get("warnings") or []})

    # -- toplu depo taraması (25. tur) -------------------------------------------------------------------
    def _bulk_get(self, path: str) -> None:
        """GET /api/bulk-scans (çalıştırmalar + portföy grupları) · GET /api/bulk-scans/<blk_…> (depo ayrıntısı)."""
        parts = [part for part in path.split("/") if part]
        if path == BULK_ROUTE:
            runs = bulk_scan.list_runs()
            for run in runs:
                job = JOBS.get(run["job_id"]) if run.get("job_id") else None
                run.update({k: v for k, v in bulk_scan.public_run(dict(run, items=[]), (job or {}).get("state")).items()
                            if k == "status"})
                run["progress"] = (job or {}).get("progress")
            return self._json({"runs": runs, "groups": bulk_scan.groups(),
                               "limits": {"max_depth": bulk_scan.HARD_MAX_DEPTH, "max_repos": bulk_scan.HARD_MAX_REPOS,
                                          "max_parallel": bulk_scan.MAX_PARALLEL}})
        if len(parts) == 3:
            run = bulk_scan.get_run(parts[2])
            if run is None:
                return self._error(HTTPStatus.NOT_FOUND, "Toplu tarama bulunamadı.")
            job = JOBS.get(run["job_id"]) if run.get("job_id") else None
            return self._json(dict(bulk_scan.public_run(run, (job or {}).get("state")), progress=(job or {}).get("progress")))
        return self._error(HTTPStatus.NOT_FOUND, "Uç nokta bulunamadı.")

    def _bulk_post(self, path: str, payload: dict) -> None:
        """Analist (CSRF ve confirm zorunlu): POST /api/bulk-scans/discover (önizleme; dosya yazılmaz) ·
        POST /api/bulk-scans (seçilenleri tek işte tara) · POST /api/bulk-scans/<blk_…>/cancel."""
        parts = [part for part in path.split("/") if part]
        if payload.get("confirm") is not True:
            return self._error(HTTPStatus.BAD_REQUEST, "Toplu depo işlemi için onay (confirm: true) gerekli.")
        try:
            if path == BULK_ROUTE + "/discover":
                if set(payload) - {"confirm", "root", "max_depth", "max_repos"}:
                    return self._error(HTTPStatus.BAD_REQUEST, "Yalnız root, max_depth, max_repos ve confirm alanları kullanılabilir.")
                root = clean_text(payload, "root", maximum=1024, required=True)
                found = bulk_scan.discover(root, max_depth=payload.get("max_depth", bulk_scan.DEFAULT_MAX_DEPTH),
                                           max_repos=payload.get("max_repos", bulk_scan.DEFAULT_MAX_REPOS))
                STORE.log("bulk_scan.discovered", "discover", {"root": found["root"], "count": found["count"],
                                                               "truncated": found["truncated"]})
                return self._json(found)
            if path == BULK_ROUTE:
                if set(payload) - {"confirm", "root", "paths", "group", "options"}:
                    return self._error(HTTPStatus.BAD_REQUEST, "Yalnız root, paths, group, options ve confirm alanları kullanılabilir.")
                root = clean_text(payload, "root", maximum=1024, required=True)
                options = bulk_scan.BulkOptions.parse(payload.get("options"))
                for route in ("/api/project-audits", "/api/dependency-security/offline-scan", "/api/container-images"):
                    if auth_routes.job_submit_denied(self, route):
                        return None
                actor = request_context.current_actor()
                run, job = _bulk_submit(self.server, self.client_address, auth_routes.job_headers(self.headers),
                                        root=root, paths=payload.get("paths"), options=options,
                                        group=payload.get("group"), actor=actor)
                auth_routes.remember_job_owner(job.id)
                return self._json({"bulk": bulk_scan.public_run(run, "queued"), "job": job.public()}, status=HTTPStatus.ACCEPTED)
            if len(parts) == 4 and parts[3] == "cancel":
                run = bulk_scan.get_run(parts[2])
                if run is None or not run.get("job_id"):
                    return self._error(HTTPStatus.NOT_FOUND, "Toplu tarama bulunamadı.")
                if auth_routes.job_cancel_denied(self, run["job_id"]):
                    return None
                result = JOBS.cancel(run["job_id"])
                if result is None:
                    return self._error(HTTPStatus.NOT_FOUND, "Toplu taramanın işi bulunamadı (süresi geçmiş olabilir).")
                STORE.log("bulk_scan.cancel_requested", run["id"], {"job_id": run["job_id"], "state": result.get("state")})
                return self._json({"bulk_id": run["id"], "job": result})
        except (bulk_scan.BulkScanError, ProjectRejected, ValueError) as exc:
            return self._error(HTTPStatus.BAD_REQUEST, str(exc))
        except JobQueueError as exc:
            return self._error(exc.status, str(exc))
        except ops_files.OpsStoreError as exc:
            return self._error(HTTPStatus.SERVICE_UNAVAILABLE, str(exc))
        return self._error(HTTPStatus.NOT_FOUND, "Uç nokta bulunamadı.")

    def _jobs_get(self, path: str) -> None:
        parts = [part for part in path.split("/") if part]
        if path == "/api/jobs":
            return self._json({"jobs": JOBS.list(), "limits": JOBS.stats(), "routes": sorted(JOB_ROUTES)})
        if len(parts) == 3:
            job = JOBS.get(parts[2])
            if job is None:
                return self._error(HTTPStatus.NOT_FOUND, "İş bulunamadı.")
            return self._json(job)
        return self._error(HTTPStatus.NOT_FOUND, "Uç nokta bulunamadı.")

    def do_OPTIONS(self) -> None:
        if not self._request_preflight():
            return
        self.send_response(HTTPStatus.NO_CONTENT)
        self.send_header("Allow", "GET, HEAD, POST, OPTIONS")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    # -- VEX (17. tur): bağımlılık zafiyetleri için CycloneDX VEX / OpenVEX ----------------------------------
    def _vex_author(self) -> str:
        actor = request_context.current_actor()
        return str(actor.get("username") or "") if actor else ""

    def _dependency_vex_decisions_get(self, query: dict) -> None:
        import vex_export

        raw = (query.get("project_path") or [""])[0]
        if not raw:
            return self._error(HTTPStatus.BAD_REQUEST, "project_path gerekli.")
        try:
            root, findings = vex_export.project_findings(STORE, raw)
        except (ProjectRejected, ValueError) as exc:
            return self._error(HTTPStatus.BAD_REQUEST, _sanitize_error_message(str(exc), "Geçersiz proje yolu."))
        decisions = STORE.vex_decisions([str(f["id"]) for f in findings])
        return self._json({
            "project_path": root,
            "statuses": list(vex_export.STATUSES), "status_labels": vex_export.STATUS_LABELS,
            "justifications": list(vex_export.JUSTIFICATIONS), "justification_labels": vex_export.JUSTIFICATION_LABELS,
            "findings": [{key: f.get(key) for key in ("id", "package_name", "installed_version", "vulnerability_id",
                                                       "severity", "status", "fixed_version", "title")}
                         | {"vex": decisions.get(str(f["id"]))} for f in findings],
        })

    def _dependency_vex_post(self, path: str, payload: dict) -> None:
        import re

        import vex_export

        try:
            if path == "/api/dependency-security/vex":
                if payload.get("confirm_local") is not True:
                    return self._error(HTTPStatus.BAD_REQUEST, "VEX üretimi yerel kodu okur; açık onay (confirm_local: true) gereklidir.")
                if not set(payload) <= {"confirm_local", "project_path", "format", "download", "dev_as_not_affected"}:
                    return self._error(HTTPStatus.BAD_REQUEST, "Yalnız confirm_local, project_path, format, download ve dev_as_not_affected alanları kullanılabilir.")
                fmt = str(payload.get("format") or "openvex")
                result = vex_export.generate_for_project(STORE, clean_text(payload, "project_path", maximum=1024, required=True),
                                                         fmt, author=self._vex_author(),
                                                         dev_not_affected=payload.get("dev_as_not_affected") is True)
                STORE.log("dependency_vex.exported", result["project_name"][:120],
                          {"format": fmt, "statements": result["summary"]["total"], "statuses": result["summary"]["statuses"],
                           "dev_as_not_affected": result["dev_not_affected"]})
                if payload.get("download") is True:
                    suffix = "openvex.json" if fmt == "openvex" else "cdx-vex.json"
                    safe = re.sub(r"[^A-Za-z0-9._-]+", "-", result["project_name"])[:60] or "proje"
                    return self._json(result["document"], disposition=f'attachment; filename="sniper-{safe}-{suffix}"')
                return self._json(result)
            if path == "/api/dependency-security/vex-import":
                if payload.get("confirm") is not True:
                    return self._error(HTTPStatus.BAD_REQUEST, "VEX içe aktarma için açık onay (confirm: true) gereklidir.")
                if not set(payload) <= {"confirm", "project_path", "document", "overwrite_analyst"}:
                    return self._error(HTTPStatus.BAD_REQUEST, "Yalnız confirm, project_path, document ve overwrite_analyst alanları kullanılabilir.")
                return self._json(vex_export.import_for_project(
                    STORE, clean_text(payload, "project_path", maximum=1024, required=True), payload.get("document"),
                    overwrite_analyst=payload.get("overwrite_analyst") is True))
            # /api/dependency-security/vex-decisions — tek bulgu için analist kararı (ya da kaldırma)
            if payload.get("confirm") is not True:
                return self._error(HTTPStatus.BAD_REQUEST, "VEX kararı için açık onay (confirm: true) gereklidir.")
            finding_id = clean_text(payload, "finding_id", maximum=80, required=True)
            if payload.get("clear") is True:
                if set(payload) - {"confirm", "finding_id", "clear"}:
                    return self._error(HTTPStatus.BAD_REQUEST, "Kaldırmada yalnız confirm, finding_id ve clear kullanılabilir.")
                if not STORE.clear_vex_decision(finding_id):
                    return self._error(HTTPStatus.NOT_FOUND, "Bu bulgu için VEX kararı yok.")
                return self._json({"finding_id": finding_id, "cleared": True})
            allowed = {"confirm", "finding_id", "status", "justification", "impact_statement", "action_statement", "status_notes"}
            if set(payload) - allowed:
                return self._error(HTTPStatus.BAD_REQUEST, "Alanlar: " + ", ".join(sorted(allowed)) + ".")
            decision = vex_export.validate_decision(payload)
            saved = STORE.set_vex_decision(finding_id, decision, basis="analyst", author=self._vex_author())
            if saved is None:
                return self._error(HTTPStatus.NOT_FOUND, "Bağımlılık bulgusu bulunamadı.")
            return self._json(saved)
        except (vex_export.VexError, ProjectRejected, DependencySecurityError, ValueError) as exc:
            return self._error(HTTPStatus.BAD_REQUEST, _sanitize_error_message(str(exc), "Geçersiz VEX isteği."))

    def _rate_limit(self) -> bool:
        if getattr(self, "_bootstrap_capture", False):
            return True  # /api/bootstrap tek istek olarak sayıldı
        if self.command in ("GET", "HEAD") and _is_static_asset_path(urlsplit(self.path).path):
            return True  # salt okunur, önbelleğe alınabilir arayüz dosyaları hız sınırına sayılmaz
        client = self.client_address[0] if self.client_address else "local"
        if LIMITER.allow(client):
            return True
        self._error(HTTPStatus.TOO_MANY_REQUESTS, "Çok fazla istek gönderildi; kısa süre sonra yeniden deneyin.")
        return False

    def _origin_allowed(self) -> bool:
        origins = self.headers.get_all("Origin")
        if not origins:
            return True
        if len(origins) != 1:
            return False
        origin = origins[0]
        try:
            parsed = urlsplit(origin)
            if parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost", "::1"} and parsed.port == PORT:
                return True
            # Giriş etkin ve uzak erişim bilinçli açılmışsa: SNIPER_ALLOWED_HOSTS adlarından gelen aynı port köken.
            extra = _allowed_host_names() - _LOOPBACK_HOST_NAMES
            return bool(extra) and parsed.scheme in {"http", "https"} and parsed.hostname in extra \
                and parsed.port == int(getattr(self.server, "server_port", PORT)) and auth_routes.manager().enabled()
        except ValueError:
            return False

    def _is_loopback_client(self) -> bool:
        client = self.client_address[0] if getattr(self, "client_address", None) else "127.0.0.1"
        try:
            return ipaddress.ip_address(client).is_loopback
        except ValueError:
            return False

    def _ssllabs_local_request_allowed(self) -> bool:
        if not self._is_loopback_client():
            return False
        origins = self.headers.get_all("Origin")
        if not origins:
            return True
        if len(origins) != 1:
            return False
        try:
            parsed = urlsplit(origins[0])
            expected_port = int(getattr(self.server, "server_port", PORT))
            return parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost", "::1"} and parsed.port == expected_port
        except ValueError:
            return False

    def _read_json(self) -> dict:
        def check_duplicates(pairs):
            seen = set()
            for key, _ in pairs:
                if key in seen:
                    raise ValueError("JSON nesnesinde tekrar eden anahtar bulundu.")
                seen.add(key)
            return dict(pairs)

        if "Transfer-Encoding" in self.headers:
            raise ValueError("Transfer-Encoding başlığına izin verilmiyor.")
        cl_headers = self.headers.get_all("Content-Length")
        if not cl_headers:
            raise ValueError("Geçersiz istek uzunluğu.")
        if len(cl_headers) > 1:
            raise ValueError("Geçersiz istek uzunluğu.")
        try:
            length = int(cl_headers[0])
        except ValueError as exc:
            raise ValueError("Geçersiz istek uzunluğu.") from exc
        limit = LARGE_MAX_BODY_BYTES if urlsplit(self.path).path in _LARGE_BODY_PATHS else DEFAULT_MAX_BODY_BYTES
        if length <= 0 or length > limit:
            raise ValueError("İstek gövdesi boş veya çok büyük.")
        try:
            data = self.rfile.read(length)
            if len(data) < length:
                raise ValueError("İstek gövdesi eksik okundu.")
            value = json.loads(data, parse_constant=lambda x: (_ for _ in ()).throw(ValueError("Geçersiz JSON sabiti: " + x)), parse_float=lambda x: (_ for _ in ()).throw(ValueError("Geçersiz JSON sayısı: " + x)) if not math.isfinite(float(x)) else float(x), object_pairs_hook=check_duplicates)
        except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as exc:
            raise ValueError("Geçerli JSON gönderin.") from exc
        if not isinstance(value, dict):
            raise ValueError("JSON nesnesi bekleniyor.")
        return value

    def _json(self, payload, status: int = HTTPStatus.OK, disposition: str | None = None,
              cookies: list[str] | None = None) -> None:
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        for cookie in cookies or ():
            self.send_header("Set-Cookie", cookie)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
        if disposition:
            self.send_header("Content-Disposition", disposition)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _error(self, status: int, message: str) -> None:
        self._json({"error": message, "status": int(status)}, status=status)

    def _text(self, value: str, *, content_type: str) -> None:
        body = value.encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _bootstrap_get(self) -> None:
        """İlk açılış verisi tek istekte (17. tur W3-UI): ``ui_assets.BOOTSTRAP_PATHS`` her biri bu işleyicide ayrı
        GET olarak çalıştırılır ve yanıtı bellekte yakalanır. Her alt yol kendi oturum/rol denetiminden geçer
        (``_request_preflight`` → ``auth_routes.gate``); izin verilmeyen ya da JSON olmayan yanıt pakete girmez,
        istemci o yolu ağdan ister (aynı hata görünür). Hız sınırına tek istek olarak sayılır."""
        if getattr(self, "_bootstrap_capture", False):
            return self._error(HTTPStatus.BAD_REQUEST, "İç içe ön yükleme yok.")
        responses: dict[str, dict] = {}
        original_path, original_wfile, original_close = self.path, self.wfile, self.close_connection
        try:
            self._bootstrap_capture = True
            for sub in ui_assets.BOOTSTRAP_PATHS:
                buffer = io.BytesIO()
                self.wfile = buffer
                self.path = sub
                try:
                    self.do_GET()
                    responses[sub] = ui_assets.parse_captured(buffer.getvalue())
                except Exception:  # alt yanıt hatası paketi bozmaz; istemci ağdan dener
                    responses[sub] = {"status": 500}
                finally:
                    self._headers_buffer = []  # yarım kalmış başlıklar gerçek yanıta sızmasın
        finally:
            self._bootstrap_capture = False
            self.path, self.wfile, self.close_connection = original_path, original_wfile, original_close
            self._report_lang, self._report_format = "tr", "html"
        return self._json({"format": 1, "responses": responses})

    def _sbom_download(self, document: dict, query: dict, stem: str, created_at: str, seed: str) -> None:
        """SBOM indirme: ``format=cyclonedx`` (varsayılan) ya da ``spdx`` (SPDX 2.3 JSON)."""
        import copy

        import sbom_formats
        from scanner import utc_now

        fmt = (query.get("format") or ["cyclonedx"])[0]
        if fmt not in ("cyclonedx", "spdx"):
            return self._error(HTTPStatus.BAD_REQUEST, "format cyclonedx ya da spdx olmalı.")
        created = created_at or utc_now()
        doc = copy.deepcopy(document)
        if isinstance(doc.get("metadata"), dict):
            doc["metadata"].setdefault("timestamp", created)
        if fmt == "spdx":
            try:
                doc = sbom_formats.cyclonedx_to_spdx(doc, created=created, namespace_seed=seed)
            except sbom_formats.SbomError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))
            return self._json(doc, disposition=f'attachment; filename="{stem}-spdx.json"')
        return self._json(doc, disposition=f'attachment; filename="{stem}-cyclonedx.json"')

    def _static(self, path: str) -> None:
        bundled = ui_assets.bundle_asset(STATIC_DIR, path)
        if bundled is not None:
            body, content_type, exact = bundled
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            # İçerik özetli adres: değişmez. Eski özetle istenirse güncel paket önbelleksiz verilir.
            self.send_header("Cache-Control", "private, max-age=31536000, immutable" if exact else "no-cache")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
            )
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
            return
        relative = "index.html" if path in {"", "/"} else path.lstrip("/")
        if relative.startswith("static/"):
            relative = relative[len("static/") :]
        candidate = (STATIC_DIR / relative).resolve()
        if STATIC_DIR.resolve() not in candidate.parents and candidate != STATIC_DIR.resolve():
            return self._error(HTTPStatus.NOT_FOUND, "Dosya bulunamadı.")
        if not candidate.is_file():
            # Client-side routes all resolve to the dashboard shell.
            if "." not in Path(relative).name:
                candidate = (STATIC_DIR / "index.html").resolve()
                if STATIC_DIR.resolve() not in candidate.parents and candidate != STATIC_DIR.resolve():
                    return self._error(HTTPStatus.NOT_FOUND, "Dosya bulunamadı.")
                if not candidate.is_file():
                    return self._error(HTTPStatus.NOT_FOUND, "Dosya bulunamadı.")
            else:
                return self._error(HTTPStatus.NOT_FOUND, "Dosya bulunamadı.")
        body = read_bytes_bounded(candidate, MAX_STATIC_FILE_BYTES, allow_empty=True)
        if body is None:
            return self._error(HTTPStatus.NOT_FOUND, "Dosya bulunamadı.")
        if candidate == (STATIC_DIR / "index.html").resolve():
            body = ui_assets.rewrite_index(STATIC_DIR, body)  # betik/stil paketleri (SNIPER_UI_BUNDLE=0 kapatır)
            body = _inject_local_home_config(body)
        mime = mimetypes.guess_type(candidate.name)[0] or "application/octet-stream"
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", f"{mime}; charset=utf-8" if mime.startswith("text/") or mime == "application/javascript" else mime)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        )
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _wants_pdf(self) -> bool:
        return getattr(self, "_report_format", "html") == "pdf"

    def _pdf_report(self, document: str, html_name: str) -> None:
        """HTML raporu PDF olarak indirir (yalıtılmış, ağsız Chromium). Bileşen yoksa anlaşılır 503."""
        import report_pdf
        try:
            pdf = report_pdf.render_pdf(document)
        except report_pdf.ReportPdfUnavailable as exc:
            return self._error(HTTPStatus.SERVICE_UNAVAILABLE,
                               f"PDF üretimi için yalıtılmış tarayıcı bileşenleri hazır değil ({exc.reason}). "
                               "HTML raporu kullanabilir ya da Araç matrisi › Yalıtılmış test kurulumunu denetleyebilirsiniz.")
        except report_pdf.ReportPdfBusy:
            return self._error(HTTPStatus.SERVICE_UNAVAILABLE, "Başka bir PDF üretiliyor; birkaç saniye sonra yeniden deneyin.")
        except report_pdf.ReportPdfError as exc:
            if exc.reason == "rapor_cok_buyuk":
                return self._error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "Rapor PDF için çok büyük; HTML raporu kullanın.")
            return self._error(HTTPStatus.INTERNAL_SERVER_ERROR, f"PDF üretilemedi ({exc.reason}).")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/pdf")
        self.send_header("Content-Length", str(len(pdf)))
        self.send_header("Content-Disposition", f'attachment; filename="{report_pdf.filename_for(html_name)}"')
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(pdf)

    def _html_report(self, scan: dict, *, download: bool = False) -> None:
        if self._wants_pdf():
            return self._pdf_report(_localized_report(render_report(scan), self), f"sniper-{scan['id']}.html")
        if getattr(self, "_report_format", "html") != "html":
            return self._error(HTTPStatus.BAD_REQUEST, "Geçersiz rapor biçimi (html ya da pdf).")
        body = _localized_report(render_report(scan), self).encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        disposition = "attachment" if download else "inline"
        self.send_header("Content-Disposition", f'{disposition}; filename="sniper-{scan["id"]}.html"')
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", ui_assets.report_csp(body.decode("utf-8")))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _diff_html_report(self, diff: dict, scan_1: dict, scan_2: dict, *, download: bool = False) -> None:
        body = _localized_report(render_diff_report(diff, scan_1, scan_2), self).encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        disposition = "attachment" if download else "inline"
        self.send_header("Content-Disposition", f'{disposition}; filename="sniper-diff-{scan_1["id"]}-{scan_2["id"]}.html"')
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", ui_assets.report_csp(body.decode("utf-8")))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _engagement_html_report(self, engagement: dict, *, download: bool = False) -> None:
        body = _localized_report(render_engagement_report(engagement), self).encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        disposition = "attachment" if download else "inline"
        self.send_header("Content-Disposition", f'{disposition}; filename="sniper-{engagement["id"]}.html"')
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", ui_assets.report_csp(body.decode("utf-8")))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _diff_csv_report(self, diff: dict, scan_id_1: str, scan_id_2: str) -> None:
        body = ("\ufeff" + render_diff_csv(diff)).encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/csv; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Disposition", f'attachment; filename="sniper-diff-{scan_id_1}-{scan_id_2}.csv"')
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _engagement_csv_report(self, engagement: dict) -> None:
        body = ("\ufeff" + render_engagement_csv(engagement)).encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/csv; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Disposition", f'attachment; filename="sniper-{engagement["id"]}.csv"')
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _engagement_sarif_report(self, engagement: dict) -> None:
        body = json.dumps(render_engagement_sarif(engagement), ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/sarif+json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Disposition", f'attachment; filename="sniper-{engagement["id"]}.sarif"')
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _sarif_report(self, scan: dict) -> None:
        body = json.dumps(render_sarif(scan), ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/sarif+json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Disposition", f'attachment; filename="sniper-{scan["id"]}.sarif"')
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)


from report_renderers import (
    DIFF_CSV_FIELDS,
    REPORT_STYLE,
    _combined_engagement_findings,
    _csv_safe,
    finding_status_label,
    render_diff_csv,
    render_diff_report,
    render_engagement_csv,
    render_engagement_report,
    render_engagement_sarif,
    render_report,
    render_sarif,
    test_status_label,
)


def _localized_report(document: str, handler) -> str:
    """HTML raporu ?lang=en isteğinde İngilizceye çevirir (varsayılan Türkçe, belge değişmez)."""
    from i18n_server import localize_html
    return localize_html(document, getattr(handler, "_report_lang", "tr"))


def remote_bind_refusal(host: str, env: Mapping[str, str] | None = None) -> str | None:
    """Loopback dışı dinleme için iki ayrı açık onay iste; reddedilirse Türkçe gerekçe döndür.

    Sniper isteğe bağlı giriş, rol ve TOTP sunar. Uzak bind için giriş etkinse ``SNIPER_REMOTE_AUTH_ACK=1``;
    giriş kapalıysa daha riskli ``SNIPER_ALLOW_UNAUTHENTICATED_REMOTE=1`` gerekir. Uzak erişim için önerilen yol
    SSH tünelidir. Docker'da süreç konteyner içinde 0.0.0.0'a bağlanır; port yalnız 127.0.0.1'e yayımlanıyorsa
    (docker-compose.yml) onay orada verilir.
    """
    env = os.environ if env is None else env
    try:
        is_local_bind = ipaddress.ip_address(host).is_loopback
    except ValueError:
        is_local_bind = host.lower() == "localhost"
    if is_local_bind:
        return None
    if env.get("SNIPER_ALLOW_REMOTE") != "1":
        return ("Güvenlik için uzak ağda dinleme kapalıdır. Yalnızca bilinçli kurulumlarda SNIPER_ALLOW_REMOTE=1 "
                "kullanın.")
    if env.get("SNIPER_ALLOW_UNAUTHENTICATED_REMOTE") != "1" and env.get("SNIPER_REMOTE_AUTH_ACK") == "1":
        # Giriş etkin + operatör TLS/tünel uyarısını onayladı (SNIPER_REMOTE_AUTH_ACK=1): uzak dinlemeye izin.
        import auth as _auth
        data_dir = Path(env.get("SNIPER_DATA_DIR") or DATA_DIR)
        if _auth.manager_for(data_dir).enabled():
            return None
        return ("SNIPER_REMOTE_AUTH_ACK=1 verildi ama giriş etkin değil; önce 'cli_reports.py users create-admin' ile "
                "yönetici oluşturun (uzak erişimde TLS ya da SSH tüneli kullanın).")
    if env.get("SNIPER_ALLOW_UNAUTHENTICATED_REMOTE") != "1":
        return (f"Sniper {host} adresinde dinlemeyi reddetti: uygulamada kimlik doğrulama yok, bu adrese ağdan "
                "ulaşabilen herkes tüm verileri okuyup araç çalıştırabilir. Uzaktan erişim için SSH tüneli "
                "kullanın (ör. ssh -L 8787:127.0.0.1:8787 sunucu). Docker'da portu yalnız 127.0.0.1'e "
                "yayımlıyorsanız (docker-compose.yml: \"127.0.0.1:8787:8787\") bunu bilerek onaylamak için "
                "SNIPER_ALLOW_UNAUTHENTICATED_REMOTE=1 verin.")
    return None


def _sandbox_reverify_loop(interval: float = 3600.0) -> None:
    """Doğrulanmış uzak hedeflerin periyodik sahiplik denetimi (yalnız .well-known yolu / TXT); sonuç denetim kaydına."""
    while True:
        time.sleep(interval)
        try:
            for result in sandbox_targets.reverify_due():
                STORE.log("sandbox_target.reverified" if result["ok"] else "sandbox_target.reverify_failed",
                          result["id"], {"method": result["method"], "evidence_sha256": result["evidence_sha256"]})
        except Exception:  # arka plan döngüsü hiçbir koşulda servisi düşürmez
            pass


def main() -> None:
    refusal = remote_bind_refusal(HOST)
    if refusal:
        raise SystemExit(refusal)
    # İçe aktarma yan etkisizdir; hatalı/korumalı veri dizini yine de dinlemeye başlamadan önce düşer.
    if isinstance(STORE, _LazyStore):
        STORE.materialize()
    if os.getenv("SNIPER_DISABLE_STARTUP_AUTODISCOVER") != "1":
        try:
            from tool_runtime_autodiscover import autodiscover_and_bind_runtimes
            discovered = autodiscover_and_bind_runtimes(apply_env=True, persist=True)
            if discovered.get("pin_mismatches"):
                print(
                    "UYARI: Onaylı araç bağlamalarından farklı dosyalar bulundu; uygulanmadı: "
                    + ", ".join(discovered["pin_mismatches"]),
                    file=sys.stderr,
                )
        except Exception:
            pass
    # Plugins execute in-process, so they stay opt-in: SNIPER_ENABLE_PLUGINS=1 or
    # the explicit POST /api/plugins/enable-builtins confirmation (builtins only).
    # Non-builtin files in plugins/user additionally require SNIPER_ENABLE_USER_PLUGINS=1.
    if os.getenv("SNIPER_ENABLE_PLUGINS") == "1":
        PLUGIN_MANAGER.enabled = True
    PLUGIN_MANAGER.reload()
    server = SniperHTTPServer((HOST, PORT), SniperHandler)
    print(f"Sniper hazır: http://{HOST}:{PORT}", flush=True)
    # Başarılı HTTP bind sonrası, durdurulan taramaları işle (rerun yapma)
    import datetime
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    with STORE._connect() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE scans SET status = ?, finished_at = ?, error = ? WHERE status IN ('queued', 'running')",
            ("failed", now_iso, "yeniden başlatma sırasında kesildi")
        )
        conn.commit()
        if cursor.rowcount > 0:
            print(f"Başlangıçta durdurulan taramalar işlendi: {cursor.rowcount} adet satır.")

    if os.getenv("SNIPER_SANDBOX_REVERIFY", "1") != "0":
        threading.Thread(target=_sandbox_reverify_loop, name="sniper-sandbox-reverify", daemon=True).start()
    if os.getenv("SNIPER_SCHEDULER", "1") != "0" and os.getenv("SNIPER_DATA_DIR"):
        # Zamanlanmış taramalar süreç içinde (systemd zamanlayıcısı yok); kaçırılanlar ilk turda en çok bir kez.
        _scheduler_for(server).start(interval=_env_number("SNIPER_SCHEDULER_TICK_SECONDS", 20, 5, 300))

    parent_pid_value = os.getenv("SNIPER_PARENT_PID", "")
    if parent_pid_value.isdigit():
        parent_pid = int(parent_pid_value)

        def watch_parent() -> None:
            while True:
                time.sleep(1)
                if os.getppid() != parent_pid:
                    server.shutdown()
                    return

        threading.Thread(target=watch_parent, name="sniper-parent-watch", daemon=True).start()

    def shutdown(_signum, _frame):
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)
    try:
        server.serve_forever(poll_interval=0.25)
    finally:
        server.server_close()
        EXECUTOR.shutdown(wait=False, cancel_futures=True)


if __name__ == "__main__":
    main()
