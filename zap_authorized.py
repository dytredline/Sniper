"""Human-authorized, bounded ZAP spider plus active scan for one HTTP(S) target.

This path deliberately does not depend on Sniper target or engagement records.
The API caller supplies one target and an exact per-run authorization boolean.
The target is still canonicalized, resolved once, pinned to the transient unit,
and confined to one same-origin path subtree by a fixed Automation Framework
plan.  Callers cannot provide ZAP arguments, rules, headers, credentials, or a
plan.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import socket
import stat
import subprocess
import tempfile
import time
import uuid
from pathlib import Path
from urllib.parse import unquote_to_bytes, urlsplit

from scanner import TargetRejected, normalize_target, utc_now
from tool_report_zap import parse_zap_traditional_json_summary
from zap_passive_active import (
    MAX_REPORT_BYTES,
    PINNED_FILES,
    RUNTIME,
    SYSTEMCTL,
    SYSTEMCTL_SHA256,
    SYSTEMD_RUN,
    SYSTEMD_RUN_SHA256,
    ZapBusy,
    ZapExecutionError,
    ZapUnavailable,
    _lock_scan,
    _stop_unit,
    _trusted_runtime,
)


CONSENT_VERSION = "zap-authorized-consent-v1"
RUN_TIMEOUT_SECONDS = 240
MAX_RESOLVED_IPS = 16


def normalize_authorized_target(raw: object) -> str:
    """Return the canonical HTTP(S) URL accepted by the authorized run path."""
    if not isinstance(raw, str) or len(raw) > 2048:
        raise ValueError("Geçerli bir HTTP(S) hedefi gerekli.")
    try:
        normalized = normalize_target(raw)
    except (TargetRejected, UnicodeError, ValueError) as exc:
        raise ValueError("Geçerli bir HTTP(S) hedefi gerekli.") from exc
    path = normalized.path or "/"
    try:
        path.encode("ascii")
        decoded = unquote_to_bytes(path).decode("utf-8")
    except (UnicodeError, ValueError) as exc:
        raise ValueError("Hedef yolu kanonik olmalı.") from exc
    if decoded != path or any(c in path for c in ("%", "\\", ";")) or "//" in path:
        raise ValueError("Hedef yolu kanonik olmalı.")
    if any(ord(c) < 0x20 or ord(c) == 0x7f for c in path):
        raise ValueError("Hedef yolu kanonik olmalı.")
    if any(part in (".", "..") for part in path.split("/")):
        raise ValueError("Hedef yolu nokta bölümü içeremez.")
    return normalized.url


def resolve_authorized_ips(target_url: str) -> list[str]:
    """Resolve one canonical target, permitting public, private and loopback unicast.

    This is a per-run transport pin rather than a product allowlist.  Multicast
    and unspecified destinations are not usable HTTP targets and remain invalid.
    """
    parsed = urlsplit(target_url)
    hostname = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        rows = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise ValueError("Yetkili hedef çözümlenemedi.") from exc
    addresses: set[str] = set()
    for row in rows:
        try:
            value = str(ipaddress.ip_address(row[4][0]))
        except (IndexError, ValueError) as exc:
            raise ValueError("Yetkili hedef geçersiz bir adrese çözümlendi.") from exc
        address = ipaddress.ip_address(value)
        if address.is_multicast or address.is_unspecified:
            raise ValueError("Yetkili hedef kullanılamayan bir adrese çözümlendi.")
        addresses.add(value)
    if not addresses or len(addresses) > MAX_RESOLVED_IPS:
        raise ValueError("Yetkili hedef için bir ile on altı arasında adres gerekli.")
    return sorted(addresses)


def _scope_pattern(target_url: str) -> str:
    parsed = urlsplit(target_url)
    origin = re.escape(f"{parsed.scheme}://{parsed.netloc}")
    path = parsed.path or "/"
    if path == "/":
        return f"^{origin}(?:/.*)?(?:\\?.*)?$"
    return f"^{origin}{re.escape(path)}(?:/.*)?(?:\\?.*)?$"


def build_plan(target_url: str, report_dir: Path) -> str:
    """Create the non-configurable same-origin/path-subtree ZAP AF plan."""
    canonical = normalize_authorized_target(target_url)
    if canonical != target_url:
        raise ValueError("Yetkili hedef kanonik olmalı.")
    target = json.dumps(canonical, ensure_ascii=True)
    include = json.dumps(_scope_pattern(canonical), ensure_ascii=True)
    report = json.dumps(str(report_dir), ensure_ascii=True)
    return f"""env:
  contexts:
    - name: sniper-human-authorized
      urls:
        - {target}
      includePaths:
        - {include}
  parameters:
    failOnError: true
    failOnWarning: false
    continueOnFailure: false
    progressToStdout: true
    maxDuration: 210
jobs:
  - type: passiveScan-config
    parameters:
      scanOnlyInScope: true
      maxAlertsPerRule: 20
      maxBodySizeInBytesToScan: 65536
  - type: spider
    parameters:
      context: sniper-human-authorized
      maxDuration: 1
      maxDepth: 3
      maxChildren: 50
      threadCount: 1
      postForm: false
      processForm: false
      parseRobotsTxt: false
      parseSitemapXml: false
      parseGit: false
      parseDsStore: false
      parseSVNEntries: false
      maxParseSizeBytes: 65536
      acceptCookies: false
  - type: passiveScan-wait
    parameters:
      maxDuration: 1
  - type: activeScan
    parameters:
      context: sniper-human-authorized
      maxRuleDurationInMins: 1
      maxScanDurationInMins: 2
      delayInMs: 1000
      threadPerHost: 1
      maxAlertsPerRule: 20
      scanHeadersAllRequests: true
  - type: report
    parameters:
      template: traditional-json
      reportDir: {report}
      reportFile: report.json
      displayReport: false
"""


def authorization_receipt(target_url: str, actor: object) -> dict:
    canonical = normalize_authorized_target(target_url)
    if not isinstance(actor, dict):
        actor = {}
    safe_actor = {
        "id": str(actor.get("id") or "local-admin")[:80],
        "username": str(actor.get("username") or "yerel")[:80],
        "role": str(actor.get("role") or "admin")[:24],
    }
    return {
        "format": "zap-authorization-receipt-v1",
        "run_id": "zaprun_" + uuid.uuid4().hex[:16],
        "actor": safe_actor,
        "confirmed_at": utc_now(),
        "consent_version": CONSENT_VERSION,
        "target": canonical,
        "target_sha256": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
    }


def _readiness_check(path: Path, expected_sha256: str, *, executable: bool = False) -> dict:
    item = {"path": str(path), "ready": False, "reason": "missing"}
    try:
        info = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(info.st_mode):
            item["reason"] = "not_regular_or_symlink"
            return item
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected_sha256:
            item["reason"] = "sha256_mismatch"
            return item
        if executable and not os.access(path, os.X_OK):
            item["reason"] = "not_executable"
            return item
    except OSError:
        return item
    item.update({"ready": True, "reason": "ok"})
    return item


def runtime_readiness() -> dict:
    checks = [
        {"id": "systemd-run", **_readiness_check(SYSTEMD_RUN, SYSTEMD_RUN_SHA256, executable=True)},
        {"id": "systemctl", **_readiness_check(SYSTEMCTL, SYSTEMCTL_SHA256, executable=True)},
    ]
    for name, digest in PINNED_FILES.items():
        checks.append({
            "id": name,
            **_readiness_check(RUNTIME / name, digest, executable=(name in {"zap/zap.sh", "java17/bin/java"})),
        })
    raw_data_dir = os.environ.get("SNIPER_DATA_DIR", "")
    data_check = {"id": "SNIPER_DATA_DIR", "path": raw_data_dir, "ready": False, "reason": "missing"}
    if raw_data_dir:
        path = Path(raw_data_dir)
        try:
            info = path.lstat()
            if path.is_symlink() or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
                data_check["reason"] = "not_owned_directory_or_symlink"
            elif not os.access(path, os.W_OK | os.X_OK):
                data_check["reason"] = "not_writable"
            else:
                data_check.update({"ready": True, "reason": "ok"})
        except OSError:
            data_check["reason"] = "missing"
    checks.append(data_check)
    missing = [f"{row['id']}:{row['reason']}:{row['path']}" for row in checks if not row["ready"]]
    return {
        "format": "zap-authorized-readiness-v1",
        "ready": not missing,
        "runtime": "owasp-zap-2.17.0-java17",
        "checks": checks,
        "missing": missing,
    }


def run_zap_authorized(target_url: str) -> dict:
    canonical = normalize_authorized_target(target_url)
    if canonical != target_url:
        raise ValueError("Yetkili hedef kanonik olmalı.")
    resolved_ips = resolve_authorized_ips(canonical)
    binary, runtime = _trusted_runtime()
    lock_fd = _lock_scan()
    try:
        data_dir_raw = os.environ.get("SNIPER_DATA_DIR")
        if not data_dir_raw:
            raise ZapUnavailable("SNIPER_DATA_DIR eksik.")
        data_dir = Path(data_dir_raw)
        try:
            info = data_dir.lstat()
        except OSError as exc:
            raise ZapUnavailable("SNIPER_DATA_DIR kullanılamıyor.") from exc
        if data_dir.is_symlink() or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
            raise ZapUnavailable("SNIPER_DATA_DIR kullanılamıyor.")
        with tempfile.TemporaryDirectory(prefix="sniper_zap_authorized_", dir=data_dir) as temp:
            work = Path(temp)
            plan_path = work / "plan.yaml"
            plan_path.write_text(build_plan(canonical, work), encoding="utf-8")
            unit = "sniper-zap-authorized-" + uuid.uuid4().hex[:16]
            command = [
                binary, "--user", "--wait", "--collect", "--pipe", "--unit=" + unit,
                "-p", "PrivateTmp=yes", "-p", "ProtectSystem=strict",
                "-p", "ProtectHome=read-only", "-p", "ReadWritePaths=" + str(work),
                "-p", "NoNewPrivileges=yes", "-p", "RestrictSUIDSGID=yes",
                "-p", "LockPersonality=yes", "-p", "RestrictRealtime=yes",
                "-p", "MemoryMax=2G", "-p", "TasksMax=256",
                "-p", "CPUQuota=200%", "-p", "RuntimeMaxSec=240",
                "-p", "IPAddressDeny=any",
                "-p", "IPAddressAllow=" + " ".join(resolved_ips),
                "-E", "HOME=" + str(work),
                "-E", "JAVA_HOME=" + str(runtime / "java17"),
                str(runtime / "zap/zap.sh"), "-Xmx1024m", "-cmd", "-autorun", str(plan_path),
            ]
            started = time.monotonic()
            try:
                with (work / "zap.log").open("wb") as log:
                    process = subprocess.Popen(
                        command,
                        stdin=subprocess.DEVNULL,
                        stdout=log,
                        stderr=subprocess.STDOUT,
                        env={
                            "PATH": "/usr/bin:/bin",
                            "HOME": str(work),
                            "LANG": "C.UTF-8",
                            "XDG_RUNTIME_DIR": os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}"),
                        },
                    )
                    try:
                        exit_code = process.wait(timeout=RUN_TIMEOUT_SECONDS + 10)
                    except subprocess.TimeoutExpired as exc:
                        _stop_unit(unit)
                        process.kill()
                        process.wait(timeout=5)
                        raise ZapExecutionError("Yetkili ZAP taraması zaman aşımına uğradı.") from exc
            except OSError as exc:
                raise ZapExecutionError("Yetkili ZAP taraması başlatılamadı.") from exc
            if exit_code:
                raise ZapExecutionError("Yetkili ZAP taraması başarısız oldu.")
            report = work / "report.json"
            try:
                report_info = report.lstat()
                if report.is_symlink() or not stat.S_ISREG(report_info.st_mode) or report_info.st_size > MAX_REPORT_BYTES:
                    raise ValueError("Geçersiz ZAP raporu.")
                data = json.loads(report.read_text(encoding="utf-8"))
                summary = parse_zap_traditional_json_summary(data)
            except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
                raise ZapExecutionError("ZAP raporu doğrulamadan geçemedi.") from exc
            summary["format"] = "zap-authorized-v1"
            summary["profile"] = "same-origin-authorized-spider-active-v1"
            summary["elapsed_seconds"] = round(time.monotonic() - started, 3)
            return summary
    finally:
        os.close(lock_fd)


__all__ = [
    "CONSENT_VERSION",
    "ZapBusy",
    "ZapExecutionError",
    "ZapUnavailable",
    "authorization_receipt",
    "build_plan",
    "normalize_authorized_target",
    "resolve_authorized_ips",
    "run_zap_authorized",
    "runtime_readiness",
]
