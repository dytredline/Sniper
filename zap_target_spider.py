"""Bounded, explicitly authorized ZAP traditional spider of one stored public origin root."""

from __future__ import annotations

import ipaddress
import json
import os
import re
import stat
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

from scanner import TargetRejected, normalize_target, resolve_public_ips, _is_public_ip
from tool_report_zap import parse_zap_traditional_json_summary
from zap_passive_active import (
    MAX_REPORT_BYTES,
    ZapExecutionError,
    ZapUnavailable,
    _lock_scan,
    _stop_unit,
    _trusted_runtime,
)


RUN_TIMEOUT_SECONDS = 240


def _validated_target(target: dict) -> tuple[str, list[str]]:
    if not isinstance(target, dict) or not isinstance(target.get("url"), str):
        raise ValueError("Kayıtlı hedef eksik.")
    try:
        normalized = normalize_target(target["url"])
        if normalized.url != target["url"]:
            raise ValueError("Kayıtlı hedef kanonik biçimde değil.")
        for key in ("scheme", "hostname", "port", "path"):
            if target.get(key) != getattr(normalized, key):
                raise ValueError("Kayıtlı hedef alanları URL ile eşleşmiyor.")
        addresses = resolve_public_ips(normalized.hostname, normalized.port)
    except TargetRejected as exc:
        raise ValueError("Kayıtlı hedef güvenli değil.") from exc
    if not addresses or len(addresses) > 16:
        raise ValueError("Kayıtlı hedefin DNS kaydı kullanılamıyor.")
    canonical_ips: list[str] = []
    for value in addresses:
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError("Kayıtlı hedefin DNS kaydı geçersiz.") from exc
        if not _is_public_ip(str(address)):
            raise ValueError("Kayıtlı hedef genel İnternet dışına çözümlendi.")
        canonical_ips.append(str(address))
    return normalized.url, sorted(set(canonical_ips))


def validate_exclusions(exclusions: object) -> list[str]:
    """Accept only literal, segment-bounded public URL path prefixes."""
    if not isinstance(exclusions, list) or len(exclusions) > 16:
        raise ValueError("Geçersiz hariç tutma listesi.")
    seen: set[str] = set()
    for item in exclusions:
        if (not isinstance(item, str)
                or re.fullmatch(r"/[A-Za-z0-9_~-]+(?:/[A-Za-z0-9_~-]+)*", item, re.ASCII) is None
                or item in seen):
            raise ValueError("Geçersiz hariç tutma yolu.")
        seen.add(item)
    return exclusions


def _plan(target_url: str, report_dir: Path, exclusions: list[str]) -> str:
    """Build a same-origin, bounded traditional spider plan."""
    from urllib.parse import urlsplit
    parsed = urlsplit(target_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc or parsed.path != "/":
        raise ValueError("Örümcek hedefi genel bir köken kökü olmalı.")
    validated = validate_exclusions(exclusions)
    origin = re.escape(f"{parsed.scheme}://{parsed.netloc}")
    include = json.dumps(f"^{origin}(?:/.*)?$", ensure_ascii=True)
    exclusions_yaml = ""
    if validated:
        entries = "".join(
            "        - " + json.dumps(
                f"^{origin}{re.escape(prefix)}(?:/.*|\\?.*)?$", ensure_ascii=True
            ) + "\n"
            for prefix in validated
        )
        exclusions_yaml = "      excludePaths:\n" + entries
    target = json.dumps(target_url, ensure_ascii=True)
    report = json.dumps(str(report_dir), ensure_ascii=True)
    return f"""env:
  contexts:
    - name: sniper-authorized-root
      urls:
        - {target}
      includePaths:
        - {include}
{exclusions_yaml}  parameters:
    failOnError: true
    failOnWarning: false
    continueOnFailure: false
    progressToStdout: true
    maxDuration: 210
jobs:
  - type: spider
    parameters:
      context: sniper-authorized-root
      maxDuration: 2
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
  - type: report
    parameters:
      template: traditional-json
      reportDir: {report}
      reportFile: report.json
      displayReport: false
"""


def run_zap_target_spider(target: dict, exclusions: list[str]) -> dict:
    if not isinstance(target, dict) or not isinstance(target.get("url"), str):
        raise ValueError("Kayıtlı hedef eksik.")
    try:
        normalized = normalize_target(target["url"])
    except TargetRejected as exc:
        raise ValueError("Kayıtlı hedef güvenli değil.") from exc
    if normalized.path != "/":
        raise ValueError("Kayıtlı hedef yolu tam olarak / olmalı.")
    exclusions = validate_exclusions(exclusions)

    target_url, public_ips = _validated_target(target)
    binary, runtime = _trusted_runtime()
    lock_fd = _lock_scan()
    try:
        data_dir_raw = os.environ.get("SNIPER_DATA_DIR")
        if not data_dir_raw:
            raise ZapUnavailable("Sniper veri dizini kullanılamıyor.")
        data_dir = Path(data_dir_raw)
        if data_dir.is_symlink() or not data_dir.is_dir() or data_dir.stat().st_uid != os.getuid():
            raise ZapUnavailable("Sniper veri dizini kullanılamıyor.")
        with tempfile.TemporaryDirectory(prefix="sniper_zap_spider_", dir=data_dir) as temp:
            work = Path(temp)
            (work / "plan.yaml").write_text(_plan(target_url, work, exclusions), encoding="utf-8")
            name = "sniper-zap-spider-" + uuid.uuid4().hex[:18]
            command = [
                binary, "--user", "--wait", "--collect", "--pipe", "--unit=" + name,
                "-p", "PrivateTmp=yes", "-p", "ProtectSystem=strict",
                "-p", "ProtectHome=read-only", "-p", "ReadWritePaths=" + str(work),
                "-p", "NoNewPrivileges=yes", "-p", "RestrictSUIDSGID=yes",
                "-p", "LockPersonality=yes", "-p", "RestrictRealtime=yes",
                "-p", "MemoryMax=2G", "-p", "TasksMax=256",
                "-p", "CPUQuota=200%", "-p", "RuntimeMaxSec=240",
                "-p", "IPAddressDeny=any",
                "-p", "IPAddressAllow=" + " ".join(public_ips),
                "-E", "HOME=" + str(work),
                "-E", "JAVA_HOME=" + str(runtime / "java17"),
                str(runtime / "zap/zap.sh"), "-Xmx1024m", "-cmd", "-autorun", str(work / "plan.yaml"),
            ]
            started = time.monotonic()
            try:
                with (work / "zap.log").open("wb") as log:
                    process = subprocess.Popen(
                        command, stdin=subprocess.DEVNULL, stdout=log,
                        stderr=subprocess.STDOUT,
                        env={"PATH": "/usr/bin:/bin", "HOME": str(work), "LANG": "C.UTF-8",
                             "XDG_RUNTIME_DIR": os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")},
                    )
                    try:
                        exit_code = process.wait(timeout=RUN_TIMEOUT_SECONDS + 10)
                    except subprocess.TimeoutExpired as exc:
                        _stop_unit(name)
                        process.kill()
                        process.wait(timeout=5)
                        raise ZapExecutionError("ZAP örümceği zaman aşımına uğradı.") from exc
            except OSError as exc:
                raise ZapExecutionError("ZAP örümceği başlatılamadı.") from exc
            if exit_code:
                raise ZapExecutionError("ZAP örümceği başarısız oldu.")
            report = work / "report.json"
            try:
                info = report.lstat()
                if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_REPORT_BYTES:
                    raise ValueError("Geçersiz ZAP raporu.")
                data = json.loads(report.read_text(encoding="utf-8"))
                summary = parse_zap_traditional_json_summary(data)
            except (OSError, UnicodeError, ValueError) as exc:
                raise ZapExecutionError("ZAP raporu doğrulamadan geçemedi.") from exc
            summary["format"] = "zap-target-spider-v1"
            summary["profile"] = "same-origin-root-spider-v1"
            summary["elapsed_seconds"] = round(time.monotonic() - started, 3)
            return summary
    finally:
        os.close(lock_fd)
