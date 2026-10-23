"""Her koşuda insan onayı isteyen genel HTTP(S) Playwright güvenlik incelemesi.

Bu profil hedef kaydı/allowlist kullanmaz. Bunun yerine tam ``confirm_authorized:
true`` beyanını, sabit bütçeleri, tek-hedef TCP aktarıcısını, bwrap/seccomp süreç
sınırlarını ve Chromium'un kendi renderer sandbox'ını birlikte zorunlu tutar.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
import secrets
from typing import Any
from urllib.parse import urlsplit

from sandbox_browser_tests import (
    MAX_PATHS,
    _path,
    _plan,
    _read_facts,
    derive_findings,
)
from sandbox_load_tests import _relay_summary
from scanner import utc_now
from tool_sandbox import AUTHORIZED_DRIVER, SandboxExecutionError, run_job

FORMAT = "playwright-authorized-v1"
CONSENT_VERSION = "sniper-playwright-authorized-consent-v1"
MAX_CONNECTIONS = 2_000
MAX_BYTES = 128 * 1024 * 1024
_DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")


def normalize_authorized_target(value: object) -> dict[str, Any]:
    """HTTP(S) kökenini kanonikleştir; kayıt/allowlist veya adres sınıfı koşulu uygulama."""
    if type(value) is not str or not value or len(value) > 300 or any(ord(ch) < 33 for ch in value):
        raise ValueError("Geçersiz HTTP(S) hedefi.")
    try:
        parts = urlsplit(value)
        scheme = parts.scheme.lower()
        host = parts.hostname
        port = parts.port or (443 if scheme == "https" else 80)
    except (ValueError, UnicodeError) as exc:
        raise ValueError("Geçersiz HTTP(S) hedefi.") from exc
    if (scheme not in {"http", "https"} or not host or parts.username is not None or parts.password is not None
            or parts.path not in {"", "/"} or parts.query or parts.fragment or not 1 <= port <= 65535
            or "%" in host or "\\" in value):
        raise ValueError("Hedef yalnız http(s)://ana-makine[:port] kökeni olmalı.")
    host = host.rstrip(".").lower()
    if not host:
        raise ValueError("Geçersiz HTTP(S) hedefi.")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        try:
            host = host.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise ValueError("Geçersiz hedef ana makinesi.") from exc
        if len(host) > 253 or any(not _DNS_LABEL.fullmatch(label) for label in host.split(".")):
            raise ValueError("Geçersiz hedef ana makinesi.")
        display_host = host
    else:
        if address.is_unspecified or address.is_multicast:
            raise ValueError("Belirsiz veya çok noktaya yayın hedefi kabul edilmez.")
        host = address.compressed
        display_host = f"[{host}]" if address.version == 6 else host
    default_port = 443 if scheme == "https" else 80
    normalized = f"{scheme}://{display_host}" + ("" if port == default_port else f":{port}")
    digest = hashlib.sha256(normalized.encode("ascii")).hexdigest()
    return {"id": f"authorized:{digest[:16]}", "kind": "authorized", "host": host, "port": port,
            "scheme": scheme, "critical": False, "normalized": normalized}


def authorized_params(payload: object) -> dict[str, Any]:
    allowed = {"confirm_authorized", "target", "paths", "reflection_probe", "screenshot",
               "ignore_https_errors", "timeout_s"}
    if type(payload) is not dict or set(payload) - allowed or payload.get("confirm_authorized") is not True:
        raise ValueError("Her koşu için confirm_authorized tam olarak true olmalı ve alanlar geçerli olmalı.")
    target = normalize_authorized_target(payload.get("target"))
    paths = payload.get("paths", ["/"])
    if type(paths) is not list or not 1 <= len(paths) <= MAX_PATHS:
        raise ValueError(f"1–{MAX_PATHS} yol verilmelidir.")
    paths = list(dict.fromkeys(_path(item) for item in paths))
    flags: dict[str, bool] = {}
    for name in ("reflection_probe", "screenshot", "ignore_https_errors"):
        value = payload.get(name, False)
        if type(value) is not bool:
            raise ValueError(f"{name} true/false olmalı.")
        flags[name] = value
    timeout = payload.get("timeout_s", 20)
    if type(timeout) is not int or not 5 <= timeout <= 60:
        raise ValueError("Sayfa süresi 5–60 sn olmalı.")
    return {"target": target, "paths": paths, "timeout": timeout, **flags}


def authorization_receipt(params: dict[str, Any], actor: dict[str, Any] | None) -> dict[str, Any]:
    principal = actor or {"id": "local-admin", "username": "yerel", "role": "admin"}
    normalized = params["target"]["normalized"]
    return {
        "run_id": "pwauth_" + secrets.token_hex(8),
        "actor": {key: principal.get(key) for key in ("id", "username", "role")},
        "confirmed_at_utc": utc_now(),
        "consent_version": CONSENT_VERSION,
        "confirm_authorized": True,
        "target_sha256": hashlib.sha256(normalized.encode("ascii")).hexdigest(),
    }


def authorized_driver_sha256() -> str:
    return hashlib.sha256(AUTHORIZED_DRIVER.read_bytes()).hexdigest()


def run_playwright_authorized(payload: object) -> dict[str, Any]:
    params = authorized_params(payload)
    plan, _probe = _plan(params)
    pages = len(params["paths"]) * (2 if params["reflection_probe"] else 1)
    env = {"PATH": "/usr/bin:/bin", "HOME": "/tmp", "LANG": "C.UTF-8", "TMPDIR": "/tmp",
           "PLAYWRIGHT_SKIP_VALIDATE_HOST_REQUIREMENTS": "1", "NODE_OPTIONS": "--max-old-space-size=256"}
    argv = ["/opt/node/node", "/sbx/driver.cjs", "/job/plan.json"]
    outer = run_job(
        "playwright", params["target"]["normalized"], argv=argv, env=env,
        timeout=min(900, 60 + pages * (params["timeout"] + 10)), files={"plan.json": plan},
        max_connections=MAX_CONNECTIONS, max_bytes=MAX_BYTES, reader=_read_facts, authorized=True,
    )
    inner = outer.get("inner") or {}
    if outer.get("timed_out") or inner.get("timed_out"):
        raise SandboxExecutionError("sure_asildi")
    if inner.get("exit_code") != 0:
        raise SandboxExecutionError("playwright_basarisiz")
    facts = outer["parsed"]
    findings = derive_findings(facts, params["target"]["scheme"] == "https")
    return {
        "format": FORMAT, "status": "completed", "target": params["target"]["normalized"],
        "paths": params["paths"], "reflection_probe": params["reflection_probe"],
        "driver_sha256": authorized_driver_sha256(), "relay": _relay_summary(outer),
        "isolation": {"bwrap_namespaces": True, "network": "relay_only", "seccomp_denylist": True,
                      "chromium_internal_sandbox": True},
        "limits": {"timeout_s": params["timeout"], "max_connections": MAX_CONNECTIONS,
                   "max_bytes": MAX_BYTES, "max_paths": MAX_PATHS},
        "cleanup": {"ephemeral_workdir_removed": True}, "findings": findings, "facts": facts,
    }
