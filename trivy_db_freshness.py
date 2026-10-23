"""Optional, release-pinned freshness gate for the shared offline Trivy DB.

The operator must stage and trust both DB and metadata bytes before enabling
this gate. It performs no network I/O and deliberately returns no metadata.
Supports all five local Trivy vulnerability profiles (python, npm, image,
yarn, and pnpm) as well as advertised runtime readiness prechecks.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from functools import wraps
import hashlib
import hmac
from http import HTTPStatus
import inspect
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any


_METADATA_LIMIT = 65_536
_MAX_STALE_SECONDS = 7 * 24 * 60 * 60
_MAX_UPDATE_INTERVAL = timedelta(days=30)
_MAX_FUTURE_SKEW = timedelta(minutes=5)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_UTC_TIMESTAMP = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z\Z"
)

SUPPORTED_TRIVY_VULN_PROFILES: tuple[str, ...] = (
    "python",
    "npm",
    "image",
    "yarn",
    "pnpm",
)

TRIVY_VULN_PROFILE_IDS: dict[str, str] = {
    "python": "local-python-requirements-v1",
    "npm": "local-npm-package-lock-v1",
    "image": "local-image-archive-offline-v1",
    "yarn": "local-yarn-lock-v1",
    "pnpm": "local-pnpm-lock-v9-v1",
}

TRIVY_VULN_PROFILE_ROUTES: dict[str, str] = {
    "python": "/api/tool-runs/trivy-vulnerability",
    "npm": "/api/tool-runs/trivy-npm-vulnerability",
    "image": "/api/tool-runs/trivy-image-archive-vulnerability",
    "yarn": "/api/tool-runs/trivy-yarn-vulnerability",
    "pnpm": "/api/tool-runs/trivy-pnpm-vulnerability",
}


class TrivyDBFreshnessError(ValueError):
    """Fixed-message unavailable result; never includes cache content or paths."""


def _reject() -> None:
    raise TrivyDBFreshnessError("Trivy zafiyet veritabanı kullanılamıyor.")


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _reject()
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    _reject()


def _parse_utc(value: object) -> datetime:
    if not isinstance(value, str) or not _UTC_TIMESTAMP.fullmatch(value):
        _reject()
    # Trivy metadata can use nanoseconds; datetime stores microseconds.
    raw = value[:-1]
    if "." in raw:
        prefix, fraction = raw.split(".", 1)
        raw = f"{prefix}.{fraction[:6]}"
    try:
        return datetime.fromisoformat(raw + "+00:00")
    except ValueError:
        _reject()


def _read_pinned_metadata(db_dir: Path, expected_sha: str) -> bytes:
    dir_fd = None
    file_fd = None
    try:
        dir_fd = os.open(db_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        file_fd = os.open("metadata.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dir_fd)
        st = os.fstat(file_fd)
        if not stat.S_ISREG(st.st_mode) or not 1 <= st.st_size <= _METADATA_LIMIT:
            _reject()
        data = bytearray()
        while len(data) <= _METADATA_LIMIT:
            chunk = os.read(file_fd, min(8192, _METADATA_LIMIT + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        if len(data) != st.st_size or len(data) > _METADATA_LIMIT:
            _reject()
        if not hmac.compare_digest(hashlib.sha256(data).hexdigest(), expected_sha):
            _reject()
        return bytes(data)
    except (OSError, ValueError):
        _reject()
    finally:
        if file_fd is not None:
            os.close(file_fd)
        if dir_fd is not None:
            os.close(dir_fd)


def require_trusted_db_freshness(db_dir: Path, *, profile: str | None = None) -> None:
    """Reject an expired or untrusted metadata file before the scanner runs.

    Unset or ``off`` preserves the existing offline profile. ``enforce``
    requires a separately trusted metadata SHA alongside the DB SHA already
    checked by each runner, plus an explicit stale grace of 0..604800 seconds.
    """
    if profile is not None and (
        not isinstance(profile, str)
        or (profile not in SUPPORTED_TRIVY_VULN_PROFILES and profile not in TRIVY_VULN_PROFILE_IDS.values())
    ):
        _reject()

    policy = os.environ.get("SNIPER_TRIVY_VULN_DB_FRESHNESS_POLICY", "off")
    if policy == "off":
        return
    if policy != "enforce":
        _reject()

    expected_sha = os.environ.get("SNIPER_TRIVY_VULN_METADATA_SHA256", "")
    grace_raw = os.environ.get("SNIPER_TRIVY_VULN_MAX_STALE_SECONDS", "")
    if not _SHA256.fullmatch(expected_sha):
        _reject()
    if not grace_raw or not grace_raw.isascii() or not grace_raw.isdecimal() or len(grace_raw) > 6:
        _reject()
    grace = int(grace_raw)
    if grace > _MAX_STALE_SECONDS:
        _reject()

    try:
        metadata = json.loads(
            _read_pinned_metadata(Path(db_dir), expected_sha).decode("utf-8"),
            object_pairs_hook=_unique_pairs,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, TypeError):
        _reject()
    if not isinstance(metadata, dict) or type(metadata.get("Version")) is not int or metadata["Version"] != 2:
        _reject()
    updated = _parse_utc(metadata.get("UpdatedAt"))
    next_update = _parse_utc(metadata.get("NextUpdate"))
    now = datetime.now(timezone.utc)
    if updated > now + _MAX_FUTURE_SKEW:
        _reject()
    if next_update <= updated or next_update - updated > _MAX_UPDATE_INTERVAL:
        _reject()
    if now > next_update + timedelta(seconds=grace):
        _reject()


def _wrap_streaming_sha256(orig_fn, unavailable_exc):
    if getattr(orig_fn, "_trivy_freshness_wrapped", False):
        return orig_fn

    @wraps(orig_fn)
    def _wrapped(path: Path) -> str:
        actual_sha = orig_fn(path)
        expected_sha = os.environ.get("SNIPER_TRIVY_VULN_DB_SHA256", "")
        if len(expected_sha) == 64 and actual_sha.lower() == expected_sha.lower():
            cache_dir = os.environ.get("SNIPER_TRIVY_VULN_CACHE_DIR")
            db_dir = Path(cache_dir) / "db" if cache_dir else Path(path).parent
            try:
                require_trusted_db_freshness(db_dir)
            except TrivyDBFreshnessError as exc:
                raise unavailable_exc("Trivy zafiyet veritabanı kullanılamıyor.") from exc
        return actual_sha

    setattr(_wrapped, "_trivy_freshness_wrapped", True)
    return _wrapped


def _wrap_runtime_tuple(orig_fn, unavailable_exc):
    if getattr(orig_fn, "_trivy_freshness_wrapped", False):
        return orig_fn

    @wraps(orig_fn)
    def _wrapped() -> tuple[Path, Path]:
        binary_path, cache_path = orig_fn()
        try:
            require_trusted_db_freshness(Path(cache_path) / "db")
        except TrivyDBFreshnessError as exc:
            raise unavailable_exc("Trivy zafiyet veritabanı kullanılamıyor.") from exc
        return binary_path, cache_path

    setattr(_wrapped, "_trivy_freshness_wrapped", True)
    return _wrapped


def _wrap_readiness_db_check(orig_fn):
    if getattr(orig_fn, "_trivy_freshness_wrapped", False):
        return orig_fn

    @wraps(orig_fn)
    def _wrapped() -> bool:
        if not orig_fn():
            return False
        cache = os.environ.get("SNIPER_TRIVY_VULN_CACHE_DIR")
        if not cache:
            return False
        try:
            require_trusted_db_freshness(Path(cache) / "db")
        except TrivyDBFreshnessError:
            return False
        return True

    setattr(_wrapped, "_trivy_freshness_wrapped", True)
    return _wrapped


def _ensure_server_five_profile_routes() -> None:
    server_mod = sys.modules.get("server")
    if server_mod is None or not hasattr(server_mod, "SniperHandler"):
        return
    handler_cls = server_mod.SniperHandler
    orig_do_post = getattr(handler_cls, "do_POST", None)
    if orig_do_post is None or getattr(orig_do_post, "_trivy_five_profile_wrapped", False):
        return
    try:
        src = inspect.getsource(orig_do_post)
        if "/api/tool-runs/trivy-yarn-vulnerability" in src and "/api/tool-runs/trivy-pnpm-vulnerability" in src:
            return
    except OSError:
        pass

    @wraps(orig_do_post)
    def _do_post(self) -> None:
        install_five_profile_freshness_gate()
        path = self.path.split("?", 1)[0]
        if path in ("/api/tool-runs/trivy-yarn-vulnerability", "/api/tool-runs/trivy-pnpm-vulnerability"):
            if not self._origin_allowed():
                return self._error(HTTPStatus.FORBIDDEN, "Çapraz kaynak isteği reddedildi.")
            if not self._rate_limit():
                return
            try:
                payload = self._read_json()
            except ValueError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))
            from trivy_vuln_active import TrivyVulnBusy, TrivyVulnExecutionError, TrivyVulnUnavailable
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
                if path == "/api/tool-runs/trivy-yarn-vulnerability":
                    from trivy_yarn_active import run_local_trivy_yarn_vulnerability
                    return self._json(run_local_trivy_yarn_vulnerability(project_path))
                from trivy_pnpm_active import run_local_trivy_pnpm_vulnerability
                return self._json(run_local_trivy_pnpm_vulnerability(project_path))
            except ValueError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))
            except (TrivyVulnUnavailable, TrivyVulnBusy):
                return self._error(HTTPStatus.SERVICE_UNAVAILABLE, "Trivy zafiyet tarayıcısı kullanılamıyor veya meşgul.")
            except TrivyVulnExecutionError:
                return self._error(HTTPStatus.BAD_GATEWAY, "Trivy zafiyet taraması başarısız oldu.")
        return orig_do_post(self)

    setattr(_do_post, "_trivy_five_profile_wrapped", True)
    setattr(handler_cls, "do_POST", _do_post)


def install_five_profile_freshness_gate() -> None:
    """Idempotently wire the trusted DB freshness gate across all 5 Trivy vuln profiles."""
    try:
        import trivy_vuln_active
        if hasattr(trivy_vuln_active, "_streaming_sha256") and hasattr(trivy_vuln_active, "TrivyVulnUnavailable"):
            trivy_vuln_active._streaming_sha256 = _wrap_streaming_sha256(
                trivy_vuln_active._streaming_sha256,
                trivy_vuln_active.TrivyVulnUnavailable,
            )
    except ImportError:
        return

    for mod_name in ("trivy_npm_active", "trivy_image_archive_active"):
        try:
            mod = __import__(mod_name)
            if hasattr(mod, "_streaming_sha256"):
                mod._streaming_sha256 = _wrap_streaming_sha256(
                    mod._streaming_sha256,
                    trivy_vuln_active.TrivyVulnUnavailable,
                )
        except ImportError:
            pass

    for mod_name in ("trivy_yarn_active", "trivy_pnpm_active"):
        try:
            mod = __import__(mod_name)
            if hasattr(mod, "_runtime"):
                mod._runtime = _wrap_runtime_tuple(
                    mod._runtime,
                    trivy_vuln_active.TrivyVulnUnavailable,
                )
        except ImportError:
            pass

    try:
        import tool_runtime_readiness
        if hasattr(tool_runtime_readiness, "_trivy_vulnerability_database"):
            tool_runtime_readiness._trivy_vulnerability_database = _wrap_readiness_db_check(
                tool_runtime_readiness._trivy_vulnerability_database
            )
            orig_payload = getattr(tool_runtime_readiness, "runtime_readiness_payload", None)
            if orig_payload is not None and not getattr(orig_payload, "_trivy_freshness_wrapped", False):
                @wraps(orig_payload)
                def _wrapped_payload(*args, **kwargs):
                    _ensure_server_five_profile_routes()
                    return orig_payload(*args, **kwargs)
                setattr(_wrapped_payload, "_trivy_freshness_wrapped", True)
                tool_runtime_readiness.runtime_readiness_payload = _wrapped_payload
    except ImportError:
        pass

    _ensure_server_five_profile_routes()


def run_freshness_checked_trivy_profile(
    profile: str,
    project_path: str,
    *,
    archive_name: str | None = None,
) -> dict[str, Any]:
    """Run one of the 5 local Trivy vulnerability profiles with DB freshness enforced."""
    install_five_profile_freshness_gate()
    from trivy_vuln_active import TrivyVulnUnavailable, run_local_trivy_vulnerability

    if profile not in SUPPORTED_TRIVY_VULN_PROFILES:
        raise TrivyVulnUnavailable("Trivy zafiyet veritabanı kullanılamıyor.")

    if profile == "python":
        return run_local_trivy_vulnerability(project_path)
    if profile == "npm":
        from trivy_npm_active import run_local_trivy_npm_vulnerability
        return run_local_trivy_npm_vulnerability(project_path)
    if profile == "image":
        from trivy_image_archive_active import run_local_trivy_image_archive_vulnerability
        return run_local_trivy_image_archive_vulnerability(project_path, archive_name or "image.tar")
    if profile == "yarn":
        from trivy_yarn_active import run_local_trivy_yarn_vulnerability
        return run_local_trivy_yarn_vulnerability(project_path)
    from trivy_pnpm_active import run_local_trivy_pnpm_vulnerability
    return run_local_trivy_pnpm_vulnerability(project_path)


install_five_profile_freshness_gate()
