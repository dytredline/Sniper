"""Bounded, explicitly authorized ZAP active scan of one stored public URL.

The caller supplies a stored target after checking its active engagement. This
module revalidates the URL and DNS and limits the ZAP transient unit to those
public IPs. It never accepts credentials, arbitrary commands, or a scan plan.
"""

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
from urllib.parse import unquote_to_bytes, urljoin, urlsplit, urlunsplit

from scanner import TargetRejected, normalize_target, resolve_public_ips, _is_public_ip
from tool_report_zap import parse_zap_traditional_json_summary
from zap_actor_job_lease import ZapLeaseError, verify_actor_job_lease
from zap_passive_active import (
    MAX_REPORT_BYTES,
    ZapExecutionError,
    ZapUnavailable,
    _lock_scan,
    _stop_unit,
    _trusted_runtime,
)


RUN_TIMEOUT_SECONDS = 240
MAX_REDIRECT_HOPS = 5


class RedirectOriginError(ValueError):
    """Raised when a redirect target violates origin, port, path-scope, or DNS-pin confinement."""


def _canonical_scope_path(raw: str) -> str:
    if not isinstance(raw, str) or not raw.startswith("/") or raw.startswith("//"):
        raise RedirectOriginError("Yönlendirme yolu tek eğik çizgiyle başlayan mutlak bir yol olmalı.")
    try:
        raw.encode("ascii")
        if re.search(r"%2f|%5c", raw, flags=re.IGNORECASE):
            raise RedirectOriginError("Yönlendirme yolunda kodlanmış eğik çizgi yasak.")
        decoded = unquote_to_bytes(raw).decode("utf-8")
    except (UnicodeError, ValueError) as exc:
        raise RedirectOriginError("Geçersiz yönlendirme yolu kodlaması.") from exc
    if any(ord(c) < 0x20 or ord(c) == 0x7f for c in decoded):
        raise RedirectOriginError("Yönlendirme yolunda denetim karakterleri yasak.")
    if any(c in decoded for c in ("%", "\\", ";", "?", "#")) or "//" in decoded:
        raise RedirectOriginError("Yönlendirme yolunda belirsiz yol karakterleri yasak.")
    if any(part in (".", "..") for part in decoded.split("/")):
        raise RedirectOriginError("Yönlendirme yolunda nokta bölümleri yasak.")
    if decoded != raw:
        raise RedirectOriginError("Kanonik olmayan yönlendirme yolu.")
    return decoded


def _path_under(path: str, prefix: str) -> bool:
    return prefix == "/" or path == prefix or path.startswith(prefix.rstrip("/") + "/")


def validate_redirect_target(
    source_url: str,
    location: str,
    *,
    allowed_paths: list[str] | tuple[str, ...] | None = None,
    excluded_paths: list[str] | tuple[str, ...] | None = None,
    approved_ips: list[str] | tuple[str, ...] | None = None,
    resolved_ips: list[str] | tuple[str, ...] | None = None,
    allow_query: bool = True,
) -> str:
    """Validate that an HTTP redirect Location stays confined to the exact authorized origin, port, path scope, and pinned public IPs."""
    if not isinstance(source_url, str) or not source_url.strip():
        raise RedirectOriginError("Kanonik kaynak URL'si gerekli.")
    try:
        src_norm = normalize_target(source_url)
    except TargetRejected as exc:
        raise RedirectOriginError("Kaynak URL'si güvensiz veya geçersiz.") from exc
    if src_norm.url != source_url:
        raise RedirectOriginError("Kaynak URL'si kanonik olmalı.")
    src_parsed = urlsplit(src_norm.url)
    src_path = _canonical_scope_path(src_parsed.path or "/")

    if not isinstance(location, str) or not location or location != location.strip():
        raise RedirectOriginError("Yönlendirme Location değeri boş olmayan, kırpılmış bir metin olmalı.")
    try:
        location.encode("ascii")
    except UnicodeEncodeError as exc:
        raise RedirectOriginError("Yönlendirme Location değeri ASCII olmalı.") from exc
    if any(ord(c) < 0x20 or ord(c) == 0x7f for c in location):
        raise RedirectOriginError("Yönlendirme Location değerinde denetim karakterleri yasak.")
    if "\\" in location or location.startswith("//"):
        raise RedirectOriginError("Şemaya göreli veya ters eğik çizgili yönlendirme Location değeri yasak.")
    if re.search(r"%2f|%5c", location, flags=re.IGNORECASE):
        raise RedirectOriginError("Yönlendirme Location değerinde kodlanmış eğik çizgi yasak.")

    raw_loc = urlsplit(location)
    if raw_loc.fragment:
        raise RedirectOriginError("Yönlendirme Location değerinde parça (fragment) yasak.")
    if raw_loc.username is not None or raw_loc.password is not None:
        raise RedirectOriginError("Yönlendirme Location değerinde kullanıcı bilgisi yasak.")
    if raw_loc.scheme and raw_loc.scheme not in ("http", "https"):
        raise RedirectOriginError("HTTP(S) dışı yönlendirme şeması yasak.")
    raw_path_check = raw_loc.path or "/"
    if "//" in raw_path_check or ";" in raw_path_check or any(part in (".", "..") for part in raw_path_check.split("/")):
        raise RedirectOriginError("Yönlendirme Location değerinde nokta bölümleri veya yol parametreleri yasak.")

    resolved_url = urljoin(src_norm.url, location)
    dst_parsed = urlsplit(resolved_url)
    if dst_parsed.username is not None or dst_parsed.password is not None or dst_parsed.fragment:
        raise RedirectOriginError("Geçersiz yönlendirme hedefi bileşenleri.")
    dst_port = dst_parsed.port or (443 if dst_parsed.scheme == "https" else 80)
    if (
        dst_parsed.scheme != src_norm.scheme
        or dst_parsed.hostname != src_norm.hostname
        or dst_port != src_norm.port
        or dst_parsed.netloc != src_parsed.netloc
    ):
        raise RedirectOriginError("Kökenler veya portlar arası yönlendirme yasak.")

    dst_path = _canonical_scope_path(dst_parsed.path or "/")
    if dst_parsed.query and not allow_query:
        raise RedirectOriginError("Bu yönlendirme hedefi için sorgu dizelerine izin verilmiyor.")

    effective_allowed = (
        [_canonical_scope_path(p) for p in allowed_paths]
        if allowed_paths is not None
        else [src_path]
    )
    if not effective_allowed or not any(_path_under(dst_path, prefix) for prefix in effective_allowed):
        raise RedirectOriginError("Yönlendirme hedefi izinli yol kapsamının dışına çıkıyor.")

    if excluded_paths:
        effective_excluded = [_canonical_scope_path(p) for p in excluded_paths]
        if any(_path_under(dst_path, prefix) for prefix in effective_excluded):
            raise RedirectOriginError("Yönlendirme hedefi hariç tutulan bir yol önekine giriyor.")

    if approved_ips is not None:
        if not isinstance(approved_ips, (list, tuple)) or not (1 <= len(approved_ips) <= 16):
            raise RedirectOriginError("Geçersiz onaylı IP sabitleme kümesi.")
        pinned_set: set[str] = set()
        for raw_ip in approved_ips:
            try:
                canon_ip = str(ipaddress.ip_address(raw_ip))
            except ValueError as exc:
                raise RedirectOriginError("Geçersiz sabitlenmiş IP adresi.") from exc
            if canon_ip != raw_ip or not _is_public_ip(canon_ip):
                raise RedirectOriginError("Sabitlenmiş IP kanonik ve genel olmalı.")
            pinned_set.add(canon_ip)
        if resolved_ips is not None:
            if not isinstance(resolved_ips, (list, tuple)) or not resolved_ips:
                raise RedirectOriginError("Yönlendirme DNS çözümlemesi boş.")
            current_set: set[str] = set()
            for raw_ip in resolved_ips:
                try:
                    canon_ip = str(ipaddress.ip_address(raw_ip))
                except ValueError as exc:
                    raise RedirectOriginError("Geçersiz yönlendirme çözümlenmiş IP adresi.") from exc
                if canon_ip != raw_ip or not _is_public_ip(canon_ip):
                    raise RedirectOriginError("Yönlendirme genel olmayan bir IP adresine çözümlendi.")
                current_set.add(canon_ip)
            if not current_set.issubset(pinned_set):
                raise RedirectOriginError("Yönlendirme DNS çözümlemesi sabitlenmiş genel IP kümesinden farklı.")

    return urlunsplit((dst_parsed.scheme, dst_parsed.netloc, dst_path, dst_parsed.query, ""))


verify_redirect_origin = validate_redirect_target


def check_redirect_origin_guard(source_url: str, location: str, **kwargs) -> bool:
    try:
        validate_redirect_target(source_url, location, **kwargs)
        return True
    except (RedirectOriginError, ValueError):
        return False


def validate_redirect_chain(
    source_url: str,
    locations: list[str] | tuple[str, ...],
    *,
    max_hops: int = MAX_REDIRECT_HOPS,
    **kwargs,
) -> list[str]:
    if not isinstance(locations, (list, tuple)):
        raise RedirectOriginError("Yönlendirme konumları bir liste veya demet olmalı.")
    if type(max_hops) is not int or not (1 <= max_hops <= MAX_REDIRECT_HOPS):
        raise RedirectOriginError("Geçersiz max_hops sınırı.")
    if len(locations) > max_hops:
        raise RedirectOriginError("Yönlendirme zinciri izin verilen azami atlama sayısını aşıyor.")
    initial_parsed = urlsplit(source_url)
    initial_scope_path = _canonical_scope_path(initial_parsed.path or "/")
    chain_kwargs = dict(kwargs)
    if chain_kwargs.get("allowed_paths") is None:
        chain_kwargs["allowed_paths"] = [initial_scope_path]
    current = source_url
    validated_hops: list[str] = []
    for hop in locations:
        next_url = validate_redirect_target(current, hop, **chain_kwargs)
        validated_hops.append(next_url)
        current_parsed = urlsplit(next_url)
        current = urlunsplit((current_parsed.scheme, current_parsed.netloc, current_parsed.path, "", ""))
    return validated_hops


def full_origin_scope_authorized(target: dict, engagement: dict) -> bool:
    if not isinstance(target, dict) or not isinstance(engagement, dict):
        return False
    if engagement.get("target_id") != target.get("id") or engagement.get("status") != "active":
        return False
    if not str(engagement.get("authorization_ref") or "").strip():
        return False
    if str(engagement.get("out_of_scope") or "").strip():
        return False
    raw_url = target.get("url")
    if not isinstance(raw_url, str):
        return False
    try:
        normalized = normalize_target(raw_url)
    except TargetRejected:
        return False
    if normalized.url != raw_url or normalized.path != "/":
        return False
    for key in ("scheme", "hostname", "port", "path"):
        if target.get(key) != getattr(normalized, key):
            return False
    expected_note = "FULL_ORIGIN_ACTIVE_SCAN " + normalized.url[:-1]
    return str(engagement.get("scope_notes") or "").strip() == expected_note


def _enforce_actor_lease(
    target: dict,
    actor_lease: object | None,
    *,
    expected_actor: str | None = None,
    expected_job_id: str | None = None,
    store_path: Path | None = None,
) -> None:
    if actor_lease is None:
        return
    if not isinstance(target, dict) or not isinstance(target.get("url"), str):
        raise ZapLeaseError("Geçersiz ZAP aktör-iş kiralaması")
    resolved_actor = expected_actor
    if resolved_actor is None:
        if isinstance(target.get("actor_id"), str):
            resolved_actor = target["actor_id"]
        elif isinstance(target.get("requester_principal_id"), str):
            resolved_actor = target["requester_principal_id"]
        elif isinstance(actor_lease, dict) and isinstance(actor_lease.get("actor_id"), str):
            resolved_actor = actor_lease["actor_id"]
        else:
            resolved_actor = getattr(actor_lease, "actor_id", "")
    resolved_job_id = expected_job_id
    if resolved_job_id is None:
        if isinstance(target.get("job_id"), str):
            resolved_job_id = target["job_id"]
        elif isinstance(actor_lease, dict) and isinstance(actor_lease.get("job_id"), str):
            resolved_job_id = actor_lease["job_id"]
        else:
            resolved_job_id = getattr(actor_lease, "job_id", "")
    try:
        verify_actor_job_lease(
            actor_lease,
            expected_actor=str(resolved_actor or ""),
            expected_job_id=str(resolved_job_id or ""),
            expected_target=target["url"],
            store_path=store_path,
        )
    except Exception as exc:
        raise ZapLeaseError("Geçersiz ZAP aktör-iş kiralaması") from exc


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


def _plan(target_url: str, report_dir: Path) -> str:
    # JSON strings are valid YAML scalars. The context includes only this path
    # and query variants generated by ZAP's active rules; no other path.
    url = json.dumps(target_url, ensure_ascii=True)
    include = json.dumps("^" + re.escape(target_url) + r"(?:\?.*)?$", ensure_ascii=True)
    report = json.dumps(str(report_dir), ensure_ascii=True)
    return f"""env:
  contexts:
    - name: sniper-authorized-url
      urls:
        - {url}
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
  - type: requestor
    requests:
      - url: {url}
        method: GET
  - type: passiveScan-wait
    parameters:
      maxDuration: 1
  - type: activeScan
    parameters:
      context: sniper-authorized-url
      url: {url}
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


def run_zap_target_active(
    target: dict,
    actor_lease: object | None = None,
    *,
    engagement: dict | None = None,
    redirect_locations: list[str] | tuple[str, ...] | None = None,
    expected_actor: str | None = None,
    expected_job_id: str | None = None,
    store_path: Path | None = None,
) -> dict:
    if (
        isinstance(actor_lease, dict)
        and engagement is None
        and any(k in actor_lease for k in ("authorization_ref", "scope_notes", "out_of_scope", "test_window"))
        and "actor_id" not in actor_lease
        and "generation" not in actor_lease
    ):
        engagement = actor_lease
        actor_lease = None

    if engagement is not None and not full_origin_scope_authorized(target, engagement):
        raise ValueError("Aktif tarama açık bir tam köken kapsamı gerektirir.")

    _enforce_actor_lease(
        target,
        actor_lease,
        expected_actor=expected_actor,
        expected_job_id=expected_job_id,
        store_path=store_path,
    )
    target_url, public_ips = _validated_target(target)
    effective_redirects = redirect_locations
    if effective_redirects is None and isinstance(target, dict) and "redirect_locations" in target:
        effective_redirects = target["redirect_locations"]
    if effective_redirects is not None:
        validate_redirect_chain(target_url, effective_redirects, approved_ips=public_ips)

    binary, runtime = _trusted_runtime()
    lock_fd = _lock_scan()  # Shared with the loopback passive ZAP profile.
    try:
        data_dir_raw = os.environ.get("SNIPER_DATA_DIR")
        if not data_dir_raw:
            raise ZapUnavailable("Sniper veri dizini kullanılamıyor.")
        data_dir = Path(data_dir_raw)
        if data_dir.is_symlink() or not data_dir.is_dir() or data_dir.stat().st_uid != os.getuid():
            raise ZapUnavailable("Sniper veri dizini kullanılamıyor.")
        with tempfile.TemporaryDirectory(prefix="sniper_zap_active_", dir=data_dir) as temp:
            work = Path(temp)
            (work / "plan.yaml").write_text(_plan(target_url, work), encoding="utf-8")
            name = "sniper-zap-active-" + uuid.uuid4().hex[:18]
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
                        raise ZapExecutionError("ZAP aktif taraması zaman aşımına uğradı.") from exc
            except OSError as exc:
                raise ZapExecutionError("ZAP aktif taraması başlatılamadı.") from exc
            if exit_code:
                raise ZapExecutionError("ZAP aktif taraması başarısız oldu.")
            report = work / "report.json"
            try:
                info = report.lstat()
                if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_REPORT_BYTES:
                    raise ValueError("Geçersiz ZAP raporu.")
                data = json.loads(report.read_text(encoding="utf-8"))
                summary = parse_zap_traditional_json_summary(data)
            except (OSError, UnicodeError, ValueError) as exc:
                raise ZapExecutionError("ZAP raporu doğrulamadan geçemedi.") from exc
            if engagement is not None:
                summary["format"] = "zap-target-active-v2"
                summary["profile"] = "full-origin-active-v2"
            else:
                summary["format"] = "zap-target-active-v1"
                summary["profile"] = "single-url-active-v1"
            summary["elapsed_seconds"] = round(time.monotonic() - started, 3)
            return summary
    finally:
        os.close(lock_fd)


def run_zap_target_spider(
    target: dict,
    exclusions: list[str] | None = None,
    actor_lease: object | None = None,
    *,
    expected_actor: str | None = None,
    expected_job_id: str | None = None,
    store_path: Path | None = None,
) -> dict:
    _enforce_actor_lease(
        target,
        actor_lease,
        expected_actor=expected_actor,
        expected_job_id=expected_job_id,
        store_path=store_path,
    )
    from zap_target_spider import run_zap_target_spider as _run_spider

    return _run_spider(target, [] if exclusions is None else exclusions)
