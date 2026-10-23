"""Offline-candidate bounded ZAP spider restricted to explicitly selected same-origin paths."""
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
from urllib.parse import urlsplit

from scanner import TargetRejected, normalize_target, resolve_public_ips, _is_public_ip
from tool_report_zap import parse_zap_traditional_json_summary
from zap_passive_active import (
    MAX_REPORT_BYTES, ZapExecutionError, ZapUnavailable, _lock_scan, _stop_unit, _trusted_runtime,
)
from zap_target_spider import validate_exclusions

RUN_TIMEOUT_SECONDS = 240
MAX_SELECTED_PATHS = 16
_MAX_PATH_BYTES = 2048
_PATH_RE = re.compile(r"/[A-Za-z0-9._~-]+(?:/[A-Za-z0-9._~-]+)*", re.ASCII)


def validate_selected_paths(paths: object) -> list[str]:
    """Validate one to sixteen literal paths; only a sole '/' means whole origin."""
    if not isinstance(paths, list) or not 1 <= len(paths) <= MAX_SELECTED_PATHS:
        raise ValueError("Bir ile on altı arasında birebir yol seçin.")
    if sum(len(value.encode("utf-8")) for value in paths if isinstance(value, str)) > _MAX_PATH_BYTES:
        raise ValueError("Seçilen yollar azami boyutu aşıyor.")
    seen: set[str] = set()
    for path in paths:
        if path == "/":
            if len(paths) != 1:
                raise ValueError("Tüm kökeni kapsayan '/' yolu tek başına seçilmeli.")
        elif not isinstance(path, str) or _PATH_RE.fullmatch(path) is None:
            raise ValueError("Seçilen yollar birebir ASCII mutlak yollar olmalı.")
        if path != "/" and any(segment in {".", ".."} for segment in path[1:].split("/")):
            raise ValueError("Seçilen yollar tam nokta bölümleri içeremez.")
        if path in seen:
            raise ValueError("Seçilen yollar benzersiz olmalı.")
        seen.add(path)
    return list(paths)


def _path_prefix_regex(origin: str, path: str) -> str:
    escaped_origin = re.escape(origin)
    if path == "/":
        return f"^{escaped_origin}(?:/.*)?$"
    # Keep every discovered descendant within literal URL path segments. ZAP's
    # URL canonicalization is not assumed: reject encoded/backslash separators
    # exact dot segments, and semicolon path parameters at the include boundary.
    suffix = r"(?:/(?!\.{1,2}(?:/|$|\?))[A-Za-z0-9._~-]+)*(?:/)?(?:\?.*)?"
    return f"^{escaped_origin}{re.escape(path)}{suffix}$"


def _plan(target_url: str, selected_paths: list[str], report_dir: Path, exclusions: list[str]) -> str:
    """Build an explicit same-origin path-allow-list and bounded spider plan."""
    parsed = urlsplit(target_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc or parsed.path != "/" or parsed.query or parsed.fragment:
        raise ValueError("Örümcek hedefi kanonik bir genel köken kökü olmalı.")
    paths = validate_selected_paths(selected_paths)
    excluded = validate_exclusions(exclusions)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    urls = "".join("        - " + json.dumps(origin + path, ensure_ascii=True) + "\n" for path in paths)
    includes = "".join(
        "        - " + json.dumps(_path_prefix_regex(origin, path), ensure_ascii=True) + "\n"
        for path in paths
    )
    excluded_yaml = ""
    if excluded:
        entries = "".join(
            "        - " + json.dumps(
                f"^{re.escape(origin)}{re.escape(prefix)}(?:/.*|\\?.*)?$", ensure_ascii=True
            ) + "\n"
            for prefix in excluded
        )
        excluded_yaml = "      excludePaths:\n" + entries
    report = json.dumps(str(report_dir), ensure_ascii=True)
    return f"""env:
  contexts:
    - name: sniper-authorized-selected-paths
      urls:
{urls}      includePaths:
{includes}{excluded_yaml}  parameters:
    failOnError: true
    failOnWarning: false
    continueOnFailure: false
    progressToStdout: true
    maxDuration: 210
jobs:
  - type: spider
    parameters:
      context: sniper-authorized-selected-paths
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


def _validated_target(target: dict) -> tuple[str, list[str]]:
    if not isinstance(target, dict) or not isinstance(target.get("url"), str):
        raise ValueError("Kayıtlı hedef eksik.")
    try:
        normalized = normalize_target(target["url"])
        if normalized.url != target["url"] or normalized.path != "/":
            raise ValueError("Kayıtlı hedef kanonik bir köken kökü olmalı.")
        for key in ("scheme", "hostname", "port", "path"):
            if target.get(key) != getattr(normalized, key):
                raise ValueError("Kayıtlı hedef alanları URL'si ile eşleşmiyor.")
        addresses = resolve_public_ips(normalized.hostname, normalized.port)
    except TargetRejected as exc:
        raise ValueError("Kayıtlı hedef güvenli değil.") from exc
    if not addresses or len(addresses) > 16:
        raise ValueError("Kayıtlı hedefin DNS kaydı kullanılamıyor.")
    public_ips: list[str] = []
    for value in addresses:
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError("Kayıtlı hedefin DNS kaydı geçersiz.") from exc
        if not _is_public_ip(str(address)):
            raise ValueError("Kayıtlı hedef genel İnternet dışına çözümlendi.")
        public_ips.append(str(address))
    return normalized.url, sorted(set(public_ips))


def run_zap_selected_path_spider(target: dict, selected_paths: list[str], exclusions: list[str]) -> dict:
    """Run only a bounded spider; never starts active attack jobs."""
    paths = validate_selected_paths(selected_paths)
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
        with tempfile.TemporaryDirectory(prefix="sniper_zap_selected_spider_", dir=data_dir) as temp:
            work = Path(temp)
            (work / "plan.yaml").write_text(
                _plan(target_url, paths, work, exclusions), encoding="utf-8"
            )
            name = "sniper-zap-path-spider-" + uuid.uuid4().hex[:18]
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
                        command, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                        env={"PATH": "/usr/bin:/bin", "HOME": str(work), "LANG": "C.UTF-8",
                             "XDG_RUNTIME_DIR": os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")},
                    )
                    try:
                        exit_code = process.wait(timeout=RUN_TIMEOUT_SECONDS + 10)
                    except subprocess.TimeoutExpired as exc:
                        _stop_unit(name)
                        process.kill()
                        process.wait(timeout=5)
                        raise ZapExecutionError("Seçili yol ZAP örümceği zaman aşımına uğradı.") from exc
            except OSError as exc:
                raise ZapExecutionError("Seçili yol ZAP örümceği başlatılamadı.") from exc
            if exit_code:
                raise ZapExecutionError("Seçili yol ZAP örümceği başarısız oldu.")
            report = work / "report.json"
            try:
                info = report.lstat()
                if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_REPORT_BYTES:
                    raise ValueError("Geçersiz ZAP raporu.")
                data = json.loads(report.read_text(encoding="utf-8"))
                summary = parse_zap_traditional_json_summary(data)
            except (OSError, UnicodeError, ValueError) as exc:
                raise ZapExecutionError("Seçili yol ZAP raporu doğrulamadan geçemedi.") from exc
            summary["format"] = "zap-selected-path-spider-v1"
            summary["profile"] = "same-origin-selected-paths-v1"
            summary["selected_path_count"] = len(paths)
            summary["elapsed_seconds"] = round(time.monotonic() - started, 3)
            return summary
    finally:
        os.close(lock_fd)
