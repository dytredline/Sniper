"""Read-only, conservative preflight for the tool matrix's existing routes.

This reports prerequisites, not permission to scan or proof that a scan will
complete. It never runs a tool, accepts a target, or returns local paths.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import threading
from pathlib import Path

from tool_catalog import CAPABILITY_WORKFLOWS, TOOLS
from tool_pins import PINS, pin_status


_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_ISO_TS_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z\Z")
_TRIVY_VULN_ROUTES = {
    "/api/tool-runs/trivy-vulnerability",
    "/api/tool-runs/trivy-npm-vulnerability",
    "/api/tool-runs/trivy-go-mod-vulnerability",
    "/api/tool-runs/trivy-cargo-lock-vulnerability",
    "/api/tool-runs/trivy-pnpm-vulnerability",
    "/api/tool-runs/trivy-yarn-vulnerability",
    "/api/tool-runs/trivy-maven-vulnerability",
    "/api/tool-runs/trivy-ruby-vulnerability",
    "/api/tool-runs/trivy-image-archive-vulnerability",
}
_TRIVY_CONFIG_ROUTES = {
    "/api/tool-runs/trivy-dockerfile-config",
    "/api/tool-runs/trivy-terraform-config",
    "/api/tool-runs/trivy-terraform-config-batch",
    "/api/tool-runs/trivy-kubernetes-config",
    "/api/tool-runs/trivy-kubernetes-config-batch",
}
_NUCLEI_BROAD_ROUTE = "/api/nuclei/http-scans"
_TRUFFLEHOG_GIT_ROUTE = "/api/tool-runs/trufflehog-git-history"
_SCHEMATHESIS_LOOPBACK_ROUTE = "/api/tool-runs/schemathesis-loopback"
_PIN_REASONS = {
    "mismatch": "binary_digest_mismatch",
    "unpinned": "binary_unpinned",
    "unavailable": "binary_unavailable",
}


def nuclei_broad_runtime_paths() -> tuple[Path, Path]:
    """Return operator-configured broad Nuclei paths without probing or executing them."""
    portable_root = Path(os.environ.get(
        "SNIPER_PORTABLE_RUNTIMES_DIR",
        str(Path.home() / ".local" / "state" / "sniper-tool-runtimes"),
    )).expanduser()
    binary = Path(os.environ.get(
        "SNIPER_NUCLEI_BINARY",
        str(portable_root / "nuclei-3.11.1" / "nuclei"),
    )).expanduser()
    catalog = Path(os.environ.get(
        "SNIPER_NUCLEI_CATALOG_DIR",
        str(portable_root / "nuclei-templates-v10.5.0"),
    )).expanduser()
    return binary, catalog


def _regular(path: str | None, *, executable: bool = False) -> bool:
    if not path:
        return False
    candidate = Path(path)
    try:
        return (candidate.is_absolute() and not candidate.is_symlink()
                and candidate.is_file() and (not executable or os.access(candidate, os.X_OK)))
    except OSError:
        return False


# (yol, aygıt, inode, boyut, mtime_ns, ctime_ns) → SHA-256; büyük ikililer her hazırlık
# isteğinde yeniden hashlenmez. Dosya değişirse kimlik değişir ve yeniden hesaplanır.
_DIGEST_CACHE: dict[tuple, str] = {}
_DIGEST_CACHE_LOCK = threading.Lock()
_DIGEST_CACHE_MAX = 256


def _file_sha256(path: str) -> str | None:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0))
    except OSError:
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            return None
        key = (path, info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        with _DIGEST_CACHE_LOCK:
            cached = _DIGEST_CACHE.get(key)
        if cached is not None:
            return cached
        with os.fdopen(os.dup(fd), "rb") as stream:
            value = hashlib.file_digest(stream, "sha256").hexdigest()
        with _DIGEST_CACHE_LOCK:
            if len(_DIGEST_CACHE) >= _DIGEST_CACHE_MAX:
                _DIGEST_CACHE.clear()
            _DIGEST_CACHE[key] = value
        return value
    except OSError:
        return None
    finally:
        os.close(fd)


def _digest_matches(path: str | None, digest: str | None) -> bool:
    if not _regular(path) or not digest or not _HEX64.fullmatch(digest):
        return False
    return _file_sha256(str(path)) == digest


def _directory(path: str | None) -> bool:
    if not path:
        return False
    candidate = Path(path)
    try:
        return candidate.is_absolute() and not candidate.is_symlink() and candidate.is_dir()
    except OSError:
        return False


def _user_bus_present() -> bool:
    """Check the on-demand ZAP runner's user-systemd bus without connecting."""
    runtime = os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")
    bus = Path(runtime) / "bus"
    try:
        return bus.is_absolute() and not bus.is_symlink() and stat.S_ISSOCK(bus.stat().st_mode)
    except OSError:
        return False


def _trivy_vulnerability_database() -> bool:
    cache = os.environ.get("SNIPER_TRIVY_VULN_CACHE_DIR")
    if not _directory(cache) or not _directory(str(Path(cache) / "db")):
        return False
    db = Path(cache) / "db" / "trivy.db"
    metadata = Path(cache) / "db" / "metadata.json"
    return (_regular(str(metadata)) and _digest_matches(
        str(db), os.environ.get("SNIPER_TRIVY_VULN_DB_SHA256")))


def _trivy_vulnerability_db_metadata() -> dict[str, object] | None:
    cache = os.environ.get("SNIPER_TRIVY_VULN_CACHE_DIR")
    if not _directory(cache):
        return None
    metadata_path = Path(cache) / "db" / "metadata.json"
    if not _regular(str(metadata_path)):
        return None
    try:
        raw = metadata_path.read_bytes()
        if not 1 <= len(raw) <= 4096:
            return None
        doc = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(doc, dict):
        return None
    version = doc.get("Version")
    updated_at = doc.get("UpdatedAt")
    next_update = doc.get("NextUpdate")
    downloaded_at = doc.get("DownloadedAt")
    if (isinstance(version, bool) or not isinstance(version, int) or not 1 <= version <= 100
            or not isinstance(updated_at, str) or not _ISO_TS_RE.fullmatch(updated_at)
            or not isinstance(next_update, str) or not _ISO_TS_RE.fullmatch(next_update)):
        return None
    summary: dict[str, object] = {
        "schema_version": version,
        "updated_at": updated_at,
        "next_update": next_update,
    }
    if isinstance(downloaded_at, str) and _ISO_TS_RE.fullmatch(downloaded_at):
        summary["downloaded_at"] = downloaded_at
    return summary


def _runtime_check(tool_id: str, route: str) -> tuple[bool, str]:
    """Return a prerequisite result and a non-sensitive, stable reason code."""
    if tool_id == "semgrep":
        from semgrep_active import active_engine
        engine, binary, rules = active_engine()
        if not binary or not _regular(rules):
            return False, "binary_or_rules_unavailable"
        state = pin_status(engine, binary)["state"]
        if state != "pinned":
            return False, _PIN_REASONS[state]
        return True, f"pinned_{engine}_and_rules_found"
    if tool_id == "joern":
        # Yalnız dosya/hash denetimleri; JVM başlatılmaz.
        from joern_active import readiness as joern_readiness
        status = joern_readiness()
        if status.get("state") == "ready":
            return True, "pinned_joern_and_jdk_found"
        return False, "joern_or_jdk_unavailable"
    if tool_id == "trivy":
        binary = os.environ.get("SNIPER_TRIVY_BINARY")
        if not _regular(binary, executable=True):
            return False, "binary_unavailable"
        from trivy_config_active import expected_trivy_sha256
        if not _digest_matches(binary, expected_trivy_sha256()):
            return False, "binary_digest_mismatch"
        if route in _TRIVY_VULN_ROUTES and not _trivy_vulnerability_database():
            return False, "pinned_database_unavailable"
        return True, "local_prerequisites_found"
    if tool_id == "syft-grype":
        try:
            from syft_grype_active import readiness as syft_grype_readiness
            status = syft_grype_readiness()
            if status.get("state") == "ready":
                return True, "pinned_binaries_and_offline_database_found"
        except RuntimeError:
            pass
        return False, "pinned_binaries_or_offline_database_unavailable"
    if tool_id == "openssl":
        try:
            from openssl_loopback_active import _pinned_runtime
            _pinned_runtime()  # Local file/hash checks only; no socket or command is started.
            return True, "pinned_ca_and_binary_found"
        except (OSError, RuntimeError):
            return False, "pinned_ca_or_binary_unavailable"
    if tool_id == "testssl":
        binary = os.environ.get("SNIPER_TESTSSL_BINARY")
        in_home = False
        if binary and Path(binary).is_absolute():
            try:
                in_home = Path(binary).resolve().is_relative_to(Path.home().resolve())
            except (OSError, RuntimeError):
                pass
        ok = (in_home and _regular(binary, executable=True)
              and _digest_matches(binary, os.environ.get("SNIPER_TESTSSL_SHA256")))
        return ok, "pinned_binary_found" if ok else "pinned_binary_unavailable"
    if tool_id == "owasp-zap":
        try:
            from zap_passive_active import _trusted_runtime
            _trusted_runtime()  # SHA-pinned local files only; no process is started.
            data = os.environ.get("SNIPER_DATA_DIR")
            ok = (_directory(data) and Path(data).stat().st_uid == os.getuid()
                  and _user_bus_present())
        except (OSError, RuntimeError):
            ok = False
        return ok, "pinned_runtime_found" if ok else "pinned_runtime_unavailable"
    if tool_id == "nmap":
        try:
            from nmap_active import _find_nmap_binary
            path = _find_nmap_binary()  # Same lookup as the run route; no execution.
            ok = path is not None and path.is_file() and os.access(path, os.X_OK)
        except (OSError, RuntimeError):
            ok = False
        return ok, "binary_found" if ok else "binary_unavailable"
    if tool_id == "nuclei":
        try:
            from nuclei_active import _trusted_binary, _trusted_template
            _trusted_binary()
            if route == _NUCLEI_BROAD_ROUTE:
                # The broad runner uses a separate pinned catalog. These are
                # only cheap preconditions; the job verifies the full catalog.
                binary, catalog = nuclei_broad_runtime_paths()
                ok = (_digest_matches(
                    str(binary),
                    "f27098e0be0cc370af52274611608ad61896d7f0a024e35b136327d39e725477")
                    and _directory(str(catalog)) and _digest_matches(
                    str(catalog / "SNIPER-HTTP-CATALOG-PIN-v2.json"),
                    "0458128285de1a22a9b5bbdf247323451663644607bdddf3252ff2b6e31f099e"))
                return ok, "binary_and_catalog_pin_found" if ok else "catalog_pin_unavailable"
            _trusted_template()
            return True, "pinned_binary_and_template_found"
        except (OSError, RuntimeError):
            return False, "pinned_runtime_unavailable"
    if tool_id in ("gitleaks", "trufflehog"):
        state = pin_status(tool_id)["state"]
        if state != "pinned":
            return False, _PIN_REASONS[state]
        if route == _TRUFFLEHOG_GIT_ROUTE and not _regular("/usr/bin/git", executable=True):
            return False, "binary_unavailable"
        return True, "pinned_binary_found"
    if tool_id == "osv-scanner":
        try:
            from osv_active import _trusted_binary, _trusted_launcher, _trusted_db, OSVUnavailable
            _trusted_binary()
            _trusted_launcher()
            _trusted_db()
            return True, "pinned_offline_runtime_and_db_found"
        except (OSError, RuntimeError, OSVUnavailable):
            return False, "pinned_offline_runtime_or_db_unavailable"
    if tool_id == "schemathesis":
        if route == _SCHEMATHESIS_LOOPBACK_ROUTE:
            raw_ports = os.environ.get("SNIPER_SCHEMATHESIS_ALLOWED_PORTS", "")
            if not raw_ports:
                return False, "approved_ports_unconfigured"
            try:
                from schemathesis_loopback_active import _approved_target, _docker_ready
                _approved_target(f"http://127.0.0.1:{raw_ports.split(',')[0]}")
                _docker_ready()  # Read-only image inspect; no scanner process starts.
                return True, "approved_ports_and_pinned_runtime_found"
            except (OSError, RuntimeError, ValueError):
                return False, "approved_ports_or_runtime_unavailable"
        try:
            from schemathesis_active import _pinned_origin, _checked_executable
            _pinned_origin()
            _checked_executable()
            return True, "synthetic_fixture_and_runtime_found"
        except (OSError, RuntimeError, ValueError):
            return False, "synthetic_fixture_or_runtime_unavailable"
    if tool_id == "npm-audit":
        node = _digest_matches(os.environ.get("SNIPER_NODE_BINARY"), os.environ.get("SNIPER_NODE_SHA256"))
        cli = _digest_matches(os.environ.get("SNIPER_NPM_CLI"), os.environ.get("SNIPER_NPM_CLI_SHA256"))
        ok = node and cli and _regular(os.environ.get("SNIPER_NODE_BINARY"), executable=True)
        return ok, "pinned_runtime_found" if ok else "pinned_runtime_unavailable"
    return False, "runtime_check_unavailable"


def taint_engine_status() -> dict:
    """Veri akışı motorunun durumu (yol veya içerik yazılmaz)."""
    import taint_flow
    import taint_js_ast
    import taint_models

    js_available = taint_js_ast.available()
    return {
        "enabled": taint_flow.is_enabled(),
        "python": "interprocedural_ast",
        "javascript": "interprocedural_ast" if js_available else "token_fallback",
        "javascript_parser": "@babel/parser 7.29.9 (SHA-256 sabitli)" if js_available else None,
        # Go ve Ruby/Rails/ERB: saf Python belirteç tabanlı dosyalar arası motor (taint_goruby; harici ikili yok).
        "go": "interprocedural_tokens",
        "ruby": "interprocedural_tokens",
        # Rust ve C/C++: saf Python belirteç tabanlı dosyalar arası motorlar (taint_rust, taint_cfamily).
        "rust": "interprocedural_tokens",
        "c_cpp": "interprocedural_tokens",
        "models": taint_models.model_status(),
    }


def runtime_readiness_payload() -> dict:
    profiles = []
    checks: dict[tuple[str, str], tuple[bool, str]] = {}
    trivy_db_meta: dict[str, object] | None = None
    trivy_db_meta_checked = False
    syft_grype_db_meta: dict[str, object] | None = None
    syft_grype_db_meta_checked = False
    for tool in TOOLS:
        tool_profiles = []
        for mode, label, routes in CAPABILITY_WORKFLOWS[tool["id"]]:
            for route in routes or (None,):
                if mode in {"local", "authorized"}:
                    group = ("trivy_vuln" if route in _TRIVY_VULN_ROUTES else
                             "trivy_config" if route in _TRIVY_CONFIG_ROUTES else
                             "nuclei_broad" if route == _NUCLEI_BROAD_ROUTE else
                             "trufflehog_git" if route == _TRUFFLEHOG_GIT_ROUTE else
                             "schemathesis_loopback" if route == _SCHEMATHESIS_LOOPBACK_ROUTE else
                             "schemathesis_synthetic" if tool["id"] == "schemathesis" else
                             "other")
                    key = (tool["id"], group)
                    if key not in checks:
                        checks[key] = _runtime_check(tool["id"], route or "")
                    available, reason = checks[key]
                    runtime = "precheck_passed" if available else "unavailable"
                    action = ("local_input_required" if mode == "local" else "authorization_required")
                    service = "on_demand"
                elif mode == "built_in":
                    runtime, action, reason = "precheck_passed", "native", "built_in_route"
                    service = "sniper_serving"
                else:
                    runtime, action = "not_applicable", {
                        "report_import": "report_only", "external": "external_only", "manual": "manual"
                    }[mode]
                    reason = "no_local_scan"
                    service = "not_managed"
                entry: dict[str, object] = {
                    "mode": mode, "label": label, "route": route,
                    "runtime": runtime, "action": action, "reason_code": reason,
                    "execution_service": service,
                }
                if route in _TRIVY_VULN_ROUTES and runtime == "precheck_passed":
                    if not trivy_db_meta_checked:
                        trivy_db_meta = _trivy_vulnerability_db_metadata()
                        trivy_db_meta_checked = True
                    if trivy_db_meta is not None:
                        entry["db_metadata"] = dict(trivy_db_meta)
                if tool["id"] == "syft-grype" and runtime == "precheck_passed":
                    if not syft_grype_db_meta_checked:
                        from syft_grype_active import readiness as syft_grype_readiness
                        database = syft_grype_readiness().get("database")
                        if isinstance(database, dict):
                            syft_grype_db_meta = database
                        syft_grype_db_meta_checked = True
                    if syft_grype_db_meta is not None:
                        entry["db_metadata"] = dict(syft_grype_db_meta)
                tool_profiles.append(entry)
        profiles.append({"id": tool["id"], "profiles": tool_profiles})
    from semgrep_active import active_engine
    engine, engine_binary, _rules = active_engine()
    binary_pins = []
    for tool_id in PINS:
        if tool_id in ("semgrep", "opengrep"):
            if tool_id != engine:
                continue
            status = pin_status(tool_id, engine_binary)
        else:
            status = pin_status(tool_id)
        binary_pins.append(status)
    from tool_pins import TREE_PINS, tree_pin_status
    binary_pins.extend(tree_pin_status(name) for name in TREE_PINS)
    return {
        "tools": profiles,
        "binary_pins": binary_pins,
        "taint_engine": taint_engine_status(),
        "policy": "Salt-okunur ön koşul denetimi; hedef izni, yerel girdi ve tarama başarısı ayrıca doğrulanır. "
                  "Sabitlenmemiş veya SHA-256'sı uyuşmayan ikililer çalıştırılmaz.",
    }
