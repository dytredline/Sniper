from __future__ import annotations

import fcntl
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
from pathlib import Path
from typing import Any

from tool_report_testssl import MAX_RECORDS, parse_testssl_json_summary


_AUTHORIZED_PROFILES = frozenset({"protocols", "full"})
_HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")


def normalize_authorized_testssl_target(target: str) -> tuple[str, int, str]:
    """Return ``(host, port, canonical_target)`` for a direct authorized run."""
    if not isinstance(target, str):
        raise ValueError("target HOST:PORT biçiminde bir metin olmalı")
    value = target.strip()
    if not value or len(value) > 320 or any(ord(char) < 33 or ord(char) == 127 for char in value):
        raise ValueError("target HOST:PORT biçiminde olmalı")

    if value.startswith("["):
        close = value.find("]")
        if close < 0 or close + 1 >= len(value) or value[close + 1] != ":":
            raise ValueError("IPv6 hedefi [IP]:PORT biçiminde olmalı")
        host_text = value[1:close]
        port_text = value[close + 2:]
        try:
            address = ipaddress.ip_address(host_text)
        except ValueError as exc:
            raise ValueError("Geçersiz IP adresi") from exc
        if address.version != 6:
            raise ValueError("Köşeli parantez yalnız IPv6 hedefi için kullanılabilir")
        host = address.compressed
        canonical_host = f"[{host}]"
    else:
        if value.count(":") != 1:
            raise ValueError("target HOST:PORT; IPv6 için [IP]:PORT biçiminde olmalı")
        host_text, port_text = value.rsplit(":", 1)
        if not host_text:
            raise ValueError("Hedef host boş olamaz")
        try:
            address = ipaddress.ip_address(host_text)
        except ValueError:
            if re.fullmatch(r"[0-9.]+", host_text):
                raise ValueError("Geçersiz IPv4 adresi")
            hostname = host_text.rstrip(".")
            if not hostname:
                raise ValueError("Hedef host boş olamaz")
            try:
                host = hostname.encode("idna").decode("ascii").lower()
            except UnicodeError as exc:
                raise ValueError("Geçersiz hedef adı") from exc
            if len(host) > 253 or any(not _HOST_LABEL.fullmatch(label) for label in host.split(".")):
                raise ValueError("Geçersiz hedef adı")
            canonical_host = host
        else:
            if address.version != 4:
                raise ValueError("IPv6 hedefi [IP]:PORT biçiminde olmalı")
            host = address.compressed
            canonical_host = host

    if not port_text.isascii() or not port_text.isdigit():
        raise ValueError("PORT sayısal olmalı")
    port = int(port_text)
    if not 1 <= port <= 65535:
        raise ValueError("port [1, 65535] aralığında olmalı")
    return host, port, f"{canonical_host}:{port}"


def resolve_authorized_testssl_ip(host: str, port: int) -> str:
    """Resolve once and return one deterministic IP which testssl will be forced to use."""
    try:
        return ipaddress.ip_address(host).compressed
    except ValueError:
        pass
    try:
        answers = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
    except OSError as exc:
        raise RuntimeError("Hedef adı çözümlenemedi.") from exc
    addresses: dict[tuple[int, bytes], str] = {}
    for family, _socktype, _proto, _canonname, sockaddr in answers:
        if family not in (socket.AF_INET, socket.AF_INET6) or not sockaddr:
            continue
        try:
            address = ipaddress.ip_address(sockaddr[0])
        except ValueError:
            continue
        addresses[(address.version, address.packed)] = address.compressed
    if not addresses:
        raise RuntimeError("Hedef adı bir IP adresine çözümlenemedi.")
    return addresses[sorted(addresses)[0]]


def _trusted_testssl_binary() -> Path:
    binary = os.environ.get("SNIPER_TESTSSL_BINARY")
    if not binary:
        raise RuntimeError("testssl ikilisi yapılandırılmamış.")
    binary_path = Path(binary)
    if not binary_path.is_absolute():
        raise RuntimeError("testssl ikili yolu mutlak olmalı.")
    resolved_binary = binary_path.resolve()
    if not resolved_binary.is_relative_to(Path.home().resolve()):
        raise RuntimeError("testssl ikilisi $HOME altında çözümlenmeli.")
    if binary_path.is_symlink() or not binary_path.is_file():
        raise RuntimeError("testssl ikilisi normal bir dosya olmalı.")
    if not os.access(binary_path, os.X_OK):
        raise RuntimeError("testssl ikilisi çalıştırılabilir olmalı.")
    expected_sha256 = os.environ.get("SNIPER_TESTSSL_SHA256")
    if expected_sha256 is None:
        raise RuntimeError("testssl ikilisi SHA256 değeri yapılandırılmamış.")
    if len(expected_sha256) != 64 or not all(char in "0123456789abcdef" for char in expected_sha256):
        raise RuntimeError("testssl ikilisi SHA256 değeri 64 karakterlik küçük harfli onaltılık olmalı.")
    if hashlib.sha256(binary_path.read_bytes()).hexdigest() != expected_sha256:
        raise RuntimeError("testssl ikilisi hash değeri uyuşmuyor.")
    return binary_path


def run_testssl_authorized(target: str, *, profile: str) -> dict[str, Any]:
    """Run a fixed testssl profile against one once-resolved, IP-pinned authorized target."""
    if profile not in _AUTHORIZED_PROFILES:
        raise ValueError("profile protocols veya full olmalı")
    host, port, canonical_target = normalize_authorized_testssl_target(target)
    resolved_ip = resolve_authorized_testssl_ip(host, port)
    full = profile == "full"

    data_dir = os.environ.get("SNIPER_DATA_DIR")
    if not data_dir:
        raise RuntimeError("SNIPER_DATA_DIR ortam değişkeni tanımlı değil.")
    lock_path = Path(data_dir).resolve() / "testssl-protocols.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)

    lock_fd = None
    try:
        try:
            lock_fd = os.open(str(lock_path), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            lock_stat = os.fstat(lock_fd)
            if not stat.S_ISREG(lock_stat.st_mode):
                raise RuntimeError("Kilit dosyası normal bir dosya değil.")
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (OSError, RuntimeError) as exc:
            raise RuntimeError("Başka bir testssl taraması sürüyor.") from exc

        binary_path = _trusted_testssl_binary()
        with tempfile.TemporaryDirectory(prefix="sniper_testssl_authorized_") as tmpdir:
            report_path = Path(tmpdir) / "report.json"
            command = [
                str(binary_path),
                "--quiet",
                "--color", "0",
                "--warnings", "batch",
                "--nodns", "none",
                "--connect-timeout", "2",
                "--openssl-timeout", "2",
                "--ip", resolved_ip,
            ]
            if ipaddress.ip_address(resolved_ip).version == 6:
                command.append("-6")
            command.extend([
                "--full" if full else "--protocols",
                "--jsonfile", str(report_path),
                canonical_target,
            ])
            execution_env = os.environ.copy()
            # testssl.sh reads these switches from the environment before parsing
            # arguments. Force network side channels off even if the parent service
            # inherited permissive operator shell settings.
            execution_env["PHONE_OUT"] = "false"
            execution_env["DNS_VIA_PROXY"] = "false"
            started = time.monotonic()
            process = None
            try:
                process = subprocess.Popen(
                    command,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    stdin=subprocess.DEVNULL,
                    start_new_session=True,
                    env=execution_env,
                )
                try:
                    exit_code = process.wait(timeout=180 if full else 45)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(os.getpgid(process.pid), 9)
                    except ProcessLookupError:
                        pass
                    try:
                        process.wait(timeout=2)
                    except (subprocess.TimeoutExpired, ProcessLookupError):
                        pass
                    raise RuntimeError("testssl çalıştırması zaman aşımına uğradı.")
            except OSError as exc:
                raise RuntimeError("testssl çalıştırması başarısız oldu.") from exc
            elapsed = time.monotonic() - started

            if exit_code != 0 and not full:
                raise RuntimeError("testssl çalıştırması başarısız oldu.")
            if not report_path.exists():
                raise RuntimeError("testssl rapor dosyası üretilmedi.")
            if report_path.stat().st_size > 1_000_000:
                raise RuntimeError("testssl raporu 1 MB sınırını aşıyor.")
            try:
                report = json.loads(report_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise RuntimeError("testssl raporu geçerli JSON değil.") from exc
            if not isinstance(report, list):
                raise RuntimeError("testssl raporu bir JSON dizisi olmalı.")
            if len(report) > MAX_RECORDS:
                raise RuntimeError(f"Çok fazla kayıt (en fazla {MAX_RECORDS}).")
            if full and exit_code != 0 and not report:
                raise RuntimeError("testssl tam taraması sonuç döndürmedi.")
            try:
                result = parse_testssl_json_summary(report)
            except ValueError as exc:
                raise RuntimeError("testssl raporu doğrulamadan geçemedi.") from exc

            result["format"] = "testssl-authorized-v1"
            result["profile"] = f"authorized-{profile}-v1"
            result["target_sha256"] = hashlib.sha256(canonical_target.encode("utf-8")).hexdigest()
            result["resolved_ip_sha256"] = hashlib.sha256(resolved_ip.encode("ascii")).hexdigest()
            result["elapsed_seconds"] = round(elapsed, 3)
            if full:
                result["scan_complete"] = exit_code == 0
                result["scanner_exit_code"] = exit_code
            return result
    finally:
        if lock_fd is not None:
            os.close(lock_fd)
