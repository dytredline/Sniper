"""Verify a single loopback TLS peer with a pinned local trust anchor.

No DNS, public target, network scan, certificate persistence or raw certificate echo.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import socket
import ssl
import stat
import subprocess
from pathlib import Path

from tool_report_openssl_x509 import parse_openssl_x509_summary

_TARGET = re.compile(r"127\.0\.0\.1:([0-9]{1,5})\Z")
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_OPENSSL = Path("/usr/bin/openssl")
_MAX_CA_BYTES = 1_000_000
_MAX_DER_BYTES = 16_384


class OpenSSLUnavailable(RuntimeError):
    """A pinned local runtime or trust anchor is missing or invalid."""


class OpenSSLBusy(RuntimeError):
    """Another certificate check holds the local single-run lock."""


class OpenSSLExecutionError(RuntimeError):
    """A bounded TLS connection or certificate parsing step failed."""


def _regular_bytes(path: Path, *, limit: int, executable: bool = False) -> bytes:
    if path.is_symlink():
        raise OpenSSLUnavailable("Sabitlenmiş çalışma zamanı geçersiz")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            metadata = os.fstat(fd)
            if (not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_uid not in {0, os.getuid()}
                    or metadata.st_size <= 0
                    or metadata.st_size > limit):
                raise OpenSSLUnavailable("Sabitlenmiş çalışma zamanı geçersiz")
            if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                raise OpenSSLUnavailable("Sabitlenmiş çalışma zamanı yazılabilir durumda")
            if executable and not metadata.st_mode & stat.S_IXUSR:
                raise OpenSSLUnavailable("OpenSSL çalıştırılabilir değil")
            value = os.read(fd, limit + 1)
            if len(value) != metadata.st_size:
                raise OpenSSLUnavailable("Sabitlenmiş çalışma zamanı değişti")
            return value
        finally:
            os.close(fd)
    except (FileNotFoundError, NotADirectoryError, PermissionError, OSError) as exc:
        raise OpenSSLUnavailable("Sabitlenmiş çalışma zamanı kullanılamıyor") from exc


def _pinned_runtime() -> tuple[Path, bytes, Path]:
    data_text = os.environ.get("SNIPER_DATA_DIR")
    if not data_text:
        raise OpenSSLUnavailable("Sniper veri dizini yapılandırılmamış")
    data_dir = Path(data_text)
    try:
        data_metadata = data_dir.stat(follow_symlinks=False)
    except (FileNotFoundError, NotADirectoryError, PermissionError, OSError) as exc:
        raise OpenSSLUnavailable("Sniper veri dizini geçersiz") from exc
    if (not data_dir.is_absolute()
            or not stat.S_ISDIR(data_metadata.st_mode)
            or data_metadata.st_uid not in {0, os.getuid()}
            or data_metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
        raise OpenSSLUnavailable("Sniper veri dizini geçersiz")
    ca_path = data_dir / "openssl-trust-ca.pem"
    ca_sha = os.environ.get("SNIPER_OPENSSL_CA_SHA256", "")
    binary_sha = os.environ.get("SNIPER_OPENSSL_BINARY_SHA256", "")
    if not _HEX.fullmatch(ca_sha) or not _HEX.fullmatch(binary_sha):
        raise OpenSSLUnavailable("OpenSSL hash değerleri yapılandırılmamış")
    ca_bytes = _regular_bytes(ca_path, limit=_MAX_CA_BYTES)
    binary_bytes = _regular_bytes(_OPENSSL, limit=2_000_000, executable=True)
    if hashlib.sha256(ca_bytes).hexdigest() != ca_sha or hashlib.sha256(binary_bytes).hexdigest() != binary_sha:
        raise OpenSSLUnavailable("Sabitlenmiş OpenSSL çalışma zamanı hash değeri uyuşmuyor")
    return data_dir, ca_bytes, _OPENSSL


def _lock(data_dir: Path) -> int:
    path = data_dir / "openssl-x509-loopback.lock"
    fd = -1
    try:
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        meta = os.fstat(fd)
        if (not stat.S_ISREG(meta.st_mode)
                or meta.st_uid != os.getuid()
                or meta.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
            raise OpenSSLUnavailable("OpenSSL kilit dosyası güvenli değil")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise OpenSSLBusy("Başka bir sertifika denetimi sürüyor") from exc
        return fd
    except OpenSSLUnavailable:
        if fd >= 0:
            os.close(fd)
        raise
    except (OSError, OpenSSLBusy) as exc:
        try:
            if fd >= 0:
                os.close(fd)
        except OSError:
            pass
        raise OpenSSLBusy("Başka bir sertifika denetimi sürüyor") from exc


def verify_pinned_tls_peer(*, connect_host: str, identity: str, port: int,
                           format_name: str, public_fields: dict[str, object] | None = None) -> dict:
    """Make one bounded TLS connection and return only the approved aggregate fields."""
    if (type(connect_host) is not str or not connect_host
            or type(identity) is not str or not identity
            or type(port) is not int or not 1 <= port <= 65535
            or type(format_name) is not str or not re.fullmatch(r"[a-z0-9-]{1,80}", format_name)
            or public_fields is not None and type(public_fields) is not dict):
        raise ValueError("Geçersiz TLS doğrulama planı")
    extra = dict(public_fields or {})
    if set(extra) & {"format", "verification", "validity", "not_before_utc",
                     "not_after_utc", "days_until_expiry", "report_sha256"}:
        raise ValueError("Geçersiz TLS doğrulama planı")
    data_dir, ca_bytes, binary = _pinned_runtime()
    lock_fd = _lock(data_dir)
    try:
        try:
            trust = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            trust.minimum_version = ssl.TLSVersion.TLSv1_2
            trust.verify_mode = ssl.CERT_REQUIRED
            trust.check_hostname = True
            trust.options |= ssl.OP_NO_COMPRESSION
            trust.load_verify_locations(cadata=ca_bytes.decode("ascii"))
        except (ssl.SSLError, UnicodeError, ValueError) as exc:
            raise OpenSSLUnavailable("Sabitlenmiş CA paketi geçersiz") from exc
        try:
            with socket.create_connection((connect_host, port), timeout=3.0) as raw:
                raw.settimeout(3.0)
                with trust.wrap_socket(raw, server_hostname=identity) as peer:
                    der = peer.getpeercert(binary_form=True)
        except ssl.SSLCertVerificationError:
            return {"format": format_name, "verification": "rejected", **extra}
        except (ssl.SSLError, OSError, TimeoutError) as exc:
            raise OpenSSLExecutionError("TLS el sıkışması başarısız oldu") from exc
        if not isinstance(der, bytes) or not 1 <= len(der) <= _MAX_DER_BYTES:
            raise OpenSSLExecutionError("Yerel eş sertifikası geçersiz")
        try:
            result = subprocess.run(
                [str(binary), "x509", "-inform", "DER", "-noout", "-dates", "-fingerprint", "-sha256"],
                input=der, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=3.0, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise OpenSSLExecutionError("Sabitlenmiş OpenSSL x509 başarısız oldu") from exc
        if result.returncode or not 1 <= len(result.stdout) <= 4096 or len(result.stderr) > 4096:
            raise OpenSSLExecutionError("Sabitlenmiş OpenSSL x509 başarısız oldu")
        try:
            summary = parse_openssl_x509_summary(result.stdout.decode("ascii"))
        except (UnicodeError, ValueError) as exc:
            raise OpenSSLExecutionError("Sabitlenmiş OpenSSL x509 çıktısı geçersizdi") from exc
        # The saved-report parser's digest covers a fingerprint line. Discard it:
        # the active result digest is only over fields that this API already returns.
        summary.pop("report_sha256")
        summary["format"] = format_name
        summary["verification"] = "passed"
        summary.update(extra)
        digest_fields = {key: summary[key] for key in (
            "format", "verification", "validity", "not_before_utc",
            "not_after_utc", "days_until_expiry",
        )}
        digest_fields.update(extra)
        canonical = json.dumps(digest_fields, sort_keys=True, separators=(",", ":"),
                               ensure_ascii=False, allow_nan=False).encode("utf-8")
        summary["report_sha256"] = hashlib.sha256(canonical).hexdigest()
        return summary
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


def run_openssl_x509_loopback(target: str) -> dict:
    if not isinstance(target, str):
        raise ValueError("Geçersiz yerel TLS hedefi")
    match = _TARGET.fullmatch(target)
    if match is None:
        raise ValueError("Geçersiz yerel TLS hedefi")
    port = int(match.group(1))
    if port < 1 or port > 65535 or str(port) != match.group(1):
        raise ValueError("Geçersiz yerel TLS portu")
    return verify_pinned_tls_peer(
        connect_host="127.0.0.1",
        identity="127.0.0.1",
        port=port,
        format_name="openssl-x509-loopback-v1",
    )
