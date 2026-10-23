"""Explicitly consented, bounded Nmap TCP service/version-light profile.

This profile can trigger Nmap's automatic version-category NSE behavior. It is
unavailable unless an operator provides an immutable, SHA-bound runtime bundle.
"""
from __future__ import annotations

import contextvars
import ctypes
import fcntl
import hashlib
import ipaddress
import json
import os
import re
import selectors
import signal
import stat
import subprocess
import tempfile
from functools import partial
import time
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

from scanner import TargetRejected, resolve_public_ips

PROFILE = "bounded-tcp-service-version-light-v1"
MAX_PORTS = 8
MAX_XML_BYTES = 60_000
MAX_STDERR_BYTES = 4096
MAX_BINARY_BYTES = 64 * 1024 * 1024
SUBPROCESS_TIMEOUT_SECONDS = 30
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_REQUIRED_FILES = {"nmap-services", "nmap-service-probes", "scripts/script.db"}

_WORKER_PROCESS_GROUP: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "nmap_worker_process_group", default=False)
_PR_SET_PDEATHSIG = 1
_LIBC = ctypes.CDLL(None, use_errno=True)


def _child_dies_with_runner(expected_parent: int) -> None:
    # Called only inside the dedicated, single-threaded worker runner before
    # exec. A parent-death signal closes the gap if the runner is SIGKILLed.
    if (_LIBC.prctl(_PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0) != 0
            or os.getppid() != expected_parent):
        os._exit(127)




def validate_service_ports(ports: object) -> list[int]:
    if not isinstance(ports, list) or not 1 <= len(ports) <= MAX_PORTS:
        raise ValueError("1 ile 8 arasında TCP portu seçin.")
    if any(type(port) is not int or not 1 <= port <= 65535 for port in ports):
        raise ValueError("TCP portları 1 ile 65535 arasında tamsayılar olmalı.")
    if len(set(ports)) != len(ports):
        raise ValueError("Yinelenen TCP portlarına izin verilmiyor.")
    return sorted(ports)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _strict_absolute_path(value: object) -> Path:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise RuntimeError("Nmap servis çalışma zamanı kullanılamıyor.")
    path = Path(value)
    if not path.is_absolute() or str(path) != value:
        raise RuntimeError("Nmap servis çalışma zamanı kullanılamıyor.")
    for current in (path, *path.parents):
        if current.is_symlink():
            raise RuntimeError("Nmap servis çalışma zamanı kullanılamıyor.")
    return path


def _require_immutable_data_view(data_dir: Path, file_paths: tuple[Path, ...]) -> None:
    """Reject data reachable through writable mounts before DNS or execution.

    Every path component must be on a read-only mount. File and data-root
    mode checks are performed by _validate_runtime_pin. A root-owned image
    directory may have mode 0755 while its mount is immutable. This check does
    not attest OCI origin: host-writable read-only binds require external proof.
    """
    readonly = getattr(os, "ST_RDONLY", None)
    if readonly is None:
        raise RuntimeError("Nmap servis çalışma zamanı kullanılamıyor.")
    files = set(file_paths)
    checked: set[Path] = set()
    try:
        for leaf in (data_dir, *file_paths):
            for path in (leaf, *leaf.parents):
                if path in checked:
                    continue
                mode = path.lstat().st_mode
                if ((not stat.S_ISREG(mode) if path in files else not stat.S_ISDIR(mode))
                        or not os.statvfs(path).f_flag & readonly):
                    raise RuntimeError("Nmap servis çalışma zamanı kullanılamıyor.")
                checked.add(path)
    except OSError as exc:
        raise RuntimeError("Nmap servis çalışma zamanı kullanılamıyor.") from exc


def _load_runtime_pin(runtime_pin: dict | None) -> dict:
    if runtime_pin is not None:
        return runtime_pin
    manifest = _strict_absolute_path(os.getenv("SNIPER_NMAP_SERVICE_RUNTIME_MANIFEST"))
    expected = os.getenv("SNIPER_NMAP_SERVICE_RUNTIME_MANIFEST_SHA256", "")
    if not _SHA256.fullmatch(expected):
        raise RuntimeError("Nmap servis çalışma zamanı kullanılamıyor.")
    # Hash and parse the same opened bytes. O_NOFOLLOW blocks a leaf-symlink
    # swap between path validation and open; no manifest read is trusted twice.
    try:
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
        fd = os.open(manifest, flags)
        with os.fdopen(fd, "rb") as handle:
            metadata = os.fstat(handle.fileno())
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o222
                    or metadata.st_size > 16384):
                raise RuntimeError("Nmap servis çalışma zamanı kullanılamıyor.")
            raw = handle.read(16385)
        if len(raw) > 16384 or hashlib.sha256(raw).hexdigest() != expected:
            raise RuntimeError("Nmap servis çalışma zamanı kullanılamıyor.")
        return json.loads(raw.decode("utf-8"))
    except (OSError, ValueError, UnicodeError) as exc:
        raise RuntimeError("Nmap servis çalışma zamanı kullanılamıyor.") from exc


def _validate_runtime_pin(runtime_pin: dict | None) -> tuple[Path, Path, str]:
    pin = _load_runtime_pin(runtime_pin)
    if not isinstance(pin, dict) or set(pin) != {"binary", "binary_sha256", "data_dir", "files"}:
        raise RuntimeError("Nmap servis çalışma zamanı kullanılamıyor.")
    binary = _strict_absolute_path(pin["binary"])
    data_dir = _strict_absolute_path(pin["data_dir"])
    expected_binary = pin["binary_sha256"]
    files = pin["files"]
    if (not _SHA256.fullmatch(expected_binary) if isinstance(expected_binary, str) else True):
        raise RuntimeError("Nmap servis çalışma zamanı kullanılamıyor.")
    if not isinstance(files, dict) or not _REQUIRED_FILES.issubset(files):
        raise RuntimeError("Nmap servis çalışma zamanı kullanılamıyor.")
    # A version-category NSE script and reviewed dependency must be explicitly pinned.
    if not any(name.startswith("scripts/") and name.endswith(".nse") for name in files):
        raise RuntimeError("Nmap servis çalışma zamanı kullanılamıyor.")
    if not any(name.startswith("nselib/") and name.endswith(".lua") for name in files):
        raise RuntimeError("Nmap servis çalışma zamanı kullanılamıyor.")
    if (not binary.is_file() or not data_dir.is_dir()
            or not binary.stat().st_mode & stat.S_IXUSR
            or binary.stat().st_mode & 0o222 or data_dir.stat().st_mode & 0o222
            or _sha256_file(binary) != expected_binary):
        raise RuntimeError("Nmap servis çalışma zamanı kullanılamıyor.")
    validated_files: dict[str, Path] = {}
    for relative, expected in files.items():
        if (not isinstance(relative, str) or not isinstance(expected, str)
                or not _SHA256.fullmatch(expected) or relative.startswith("/")
                or any(part in ("", ".", "..") for part in relative.split("/"))):
            raise RuntimeError("Nmap servis çalışma zamanı kullanılamıyor.")
        validated_files[relative] = _strict_absolute_path(str(data_dir / relative))
    _require_immutable_data_view(data_dir, tuple(validated_files.values()))
    for relative, file_path in validated_files.items():
        if (not file_path.is_file() or file_path.stat().st_mode & 0o222
                or _sha256_file(file_path) != files[relative]):
            raise RuntimeError("Nmap servis çalışma zamanı kullanılamıyor.")
    return binary, data_dir, expected_binary


def _sealed_verified_binary(binary: Path, expected_sha256: str) -> int:
    """Bind executable bytes to a sealed FD, never to a mutable pathname."""
    source_fd = -1
    executable_fd = -1
    try:
        required = ("memfd_create", "MFD_ALLOW_SEALING", "MFD_CLOEXEC")
        seals = ("F_ADD_SEALS", "F_GET_SEALS", "F_SEAL_WRITE",
                 "F_SEAL_GROW", "F_SEAL_SHRINK", "F_SEAL_SEAL")
        if any(not hasattr(os, name) for name in required) or any(
                not hasattr(fcntl, name) for name in seals):
            raise RuntimeError("Nmap servis çalışma zamanı kullanılamıyor.")
        source_fd = os.open(binary, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        metadata = os.fstat(source_fd)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o222
                or not metadata.st_mode & stat.S_IXUSR
                or not 0 < metadata.st_size <= MAX_BINARY_BYTES):
            raise RuntimeError("Nmap servis çalışma zamanı kullanılamıyor.")
        executable_fd = os.memfd_create(
            "sniper-nmap-verified", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        os.fchmod(executable_fd, 0o500)
        digest = hashlib.sha256()
        copied = 0
        while True:
            chunk = os.read(source_fd, 65536)
            if not chunk:
                break
            copied += len(chunk)
            if copied > MAX_BINARY_BYTES:
                raise RuntimeError("Nmap servis çalışma zamanı kullanılamıyor.")
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(executable_fd, view)
                if written <= 0:
                    raise RuntimeError("Nmap servis çalışma zamanı kullanılamıyor.")
                view = view[written:]
        if (copied != metadata.st_size or digest.hexdigest() != expected_sha256
                or os.fstat(source_fd).st_size != copied):
            raise RuntimeError("Nmap servis çalışma zamanı kullanılamıyor.")
        wanted = (fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW |
                  fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        fcntl.fcntl(executable_fd, fcntl.F_ADD_SEALS, wanted)
        if fcntl.fcntl(executable_fd, fcntl.F_GET_SEALS) & wanted != wanted:
            raise RuntimeError("Nmap servis çalışma zamanı kullanılamıyor.")
        os.lseek(executable_fd, 0, os.SEEK_SET)
        sealed = executable_fd
        executable_fd = -1
        return sealed
    except OSError as exc:
        raise RuntimeError("Nmap servis çalışma zamanı kullanılamıyor.") from exc
    finally:
        if source_fd >= 0:
            os.close(source_fd)
        if executable_fd >= 0:
            os.close(executable_fd)


def _parse_version_xml(raw: bytes, selected_ports: list[int]) -> tuple[int, int, list[int], int]:
    if not isinstance(raw, bytes) or len(raw) > MAX_XML_BYTES:
        raise RuntimeError("Nmap servis yanıtı kullanılamıyor.")
    try:
        text = raw.decode("utf-8", errors="strict")
        # Nmap 7.94 emits this inert declaration before the root. Strip only
        # that exact prolog line; ElementTree must never receive a DTD.
        nmap_prolog = ('<?xml version="1.0" encoding="UTF-8"?>\n'
                        '<!DOCTYPE nmaprun>\n')
        if text.startswith(nmap_prolog):
            text = ('<?xml version="1.0" encoding="UTF-8"?>\n'
                    + text[len(nmap_prolog):])
        if "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper():
            raise ValueError("XML DTD veya varlık tanımına izin verilmiyor")
        root = ET.fromstring(text)
    except (UnicodeError, ET.ParseError, ValueError) as exc:
        raise RuntimeError("Nmap servis yanıtı kullanılamıyor.") from exc
    if root.tag != "nmaprun":
        raise RuntimeError("Nmap servis yanıtı kullanılamıyor.")
    hosts = root.findall("host")
    if len(hosts) != 1:
        raise RuntimeError("Nmap servis yanıtı kullanılamıyor.")
    host = hosts[0]
    status_node = host.find("status")
    if status_node is None or status_node.get("state") not in {"up", "down"}:
        raise RuntimeError("Nmap servis yanıtı kullanılamıyor.")
    up_count = int(status_node.get("state") == "up")
    ports_node = host.find("ports")
    open_ports: list[int] = []
    fingerprinted = 0
    seen: set[int] = set()
    extra_states: set[str] = set()
    extra_count = 0
    for entry in [] if ports_node is None else list(ports_node):
        if entry.tag == "extraports":
            # Nmap groups closed/filtered selected ports instead of emitting
            # a <port> element for each one. These carry no open-port result.
            extra_state, raw_count = entry.get("state"), entry.get("count", "")
            if (extra_state not in {"closed", "filtered"} or extra_state in extra_states
                    or not raw_count.isdecimal() or int(raw_count) < 1
                    or any(child.tag != "extrareasons" for child in entry)):
                raise RuntimeError("Nmap servis yanıtı kullanılamıyor.")
            extra_states.add(extra_state)
            extra_count += int(raw_count)
            continue
        if entry.tag != "port" or entry.get("protocol") != "tcp":
            raise RuntimeError("Nmap servis yanıtı kullanılamıyor.")
        raw_id = entry.get("portid", "")
        if not raw_id.isdecimal():
            raise RuntimeError("Nmap servis yanıtı kullanılamıyor.")
        port = int(raw_id)
        if port not in selected_ports or port in seen:
            raise RuntimeError("Nmap servis yanıtı kullanılamıyor.")
        seen.add(port)
        state = entry.find("state")
        if state is None or state.get("state") not in {"open", "closed", "filtered"}:
            raise RuntimeError("Nmap servis yanıtı kullanılamıyor.")
        if state.get("state") == "open":
            if not up_count:
                raise RuntimeError("Nmap servis yanıtı kullanılamıyor.")
            service = entry.find("service")
            method = service.get("method") if service is not None else None
            if method not in (None, "table", "probed"):
                raise RuntimeError("Nmap servis yanıtı kullanılamıyor.")
            open_ports.append(port)
            fingerprinted += int(method == "probed")
    if len(seen) + extra_count > len(selected_ports):
        raise RuntimeError("Nmap servis yanıtı kullanılamıyor.")
    return 1, up_count, sorted(open_ports), fingerprinted


def _bounded_subprocess_output(args: list[str], env: dict[str, str], *, executable_fd: int) -> bytes:
    """Drain both pipes incrementally; never accumulate untrusted Nmap output."""
    process = None
    output = bytearray()
    error = bytearray()
    success = False
    try:
        if not args or args[0] != f"/proc/self/fd/{executable_fd}":
            raise RuntimeError("Nmap servis çalıştırması başarısız oldu.")
        worker_group = _WORKER_PROCESS_GROUP.get()
        process = subprocess.Popen(
            args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=env, cwd="/", close_fds=True, pass_fds=(executable_fd,),
            start_new_session=not worker_group,
            preexec_fn=(partial(_child_dies_with_runner, os.getpid())
                        if worker_group else None),
        )
        assert process.stdout is not None and process.stderr is not None
        deadline = time.monotonic() + SUBPROCESS_TIMEOUT_SECONDS
        with selectors.DefaultSelector() as selector:
            for stream, limit, sink in ((process.stdout, MAX_XML_BYTES, output),
                                        (process.stderr, MAX_STDERR_BYTES, error)):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, (limit, sink))
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RuntimeError("Nmap servis çalıştırması başarısız oldu.")
                for key, _ in selector.select(min(remaining, 0.25)):
                    limit, sink = key.data
                    chunk = os.read(key.fd, min(8192, limit - len(sink) + 1))
                    if not chunk:
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                        continue
                    if len(sink) + len(chunk) > limit:
                        raise RuntimeError("Nmap servis çalıştırması başarısız oldu.")
                    sink.extend(chunk)
        remaining = deadline - time.monotonic()
        if remaining <= 0 or process.wait(timeout=remaining) != 0:
            raise RuntimeError("Nmap servis çalıştırması başarısız oldu.")
        success = True
        return bytes(output)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("Nmap servis çalıştırması başarısız oldu.") from exc
    finally:
        if process is not None:
            if not success:
                # Outside the dedicated worker, Nmap owns a fresh session.
                # Inside it, Nmap shares the supervised runner group; the
                # worker parent finishes group cleanup before releasing work.
                try:
                    if worker_group:
                        process.kill()
                    else:
                        os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            process.wait()
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()


def run_bounded_tcp_service_fingerprint(
    target_id: str, engagement_id: str, hostname: str, port: int, ports: list[int],
    *, runtime_pin: dict | None = None,
) -> dict[str, Any]:
    selected_ports = validate_service_ports(ports)
    # Validate the declared bundle and copy executable bytes into a sealed FD
    # before DNS. The pathname is never used for execution afterward.
    binary, data_dir, expected_binary = _validate_runtime_pin(runtime_pin)
    executable_fd = _sealed_verified_binary(binary, expected_binary)
    try:
        try:
            addresses = resolve_public_ips(hostname, port)
        except (TargetRejected, OSError) as exc:
            raise RuntimeError("Nmap servis hedefi çözümlenemedi.") from exc
        if not addresses:
            raise RuntimeError("Nmap servis hedefi çözümlenemedi.")
        try:
            pinned_ip = str(ipaddress.ip_address(addresses[0]))
            if not ipaddress.ip_address(pinned_ip).is_global:
                raise ValueError("genel olmayan adres")
        except (ValueError, TypeError) as exc:
            raise RuntimeError("Nmap servis hedefi çözümlenemedi.") from exc
        args = [f"/proc/self/fd/{executable_fd}", "-sT", "-Pn", "-n", "--max-rate", "15",
                "--max-parallelism", "1", "--max-retries", "0", "--host-timeout", "25s",
                "-sV", "--version-light", "--datadir", str(data_dir),
                "-p", ",".join(map(str, selected_ports)), "-oX", "-"]
        if ":" in pinned_ip:
            args.append("-6")
        args.append(pinned_ip)
        with tempfile.TemporaryDirectory(prefix="sniper-nmap-service-") as temporary_home:
            env = {"PATH": "/usr/bin:/bin", "HOME": temporary_home,
                   "NMAPDIR": str(data_dir), "LC_ALL": "C"}
            raw_xml = _bounded_subprocess_output(args, env, executable_fd=executable_fd)
        host_count, up_count, open_ports, fingerprinted = _parse_version_xml(raw_xml, selected_ports)
        return {"target_id": target_id, "engagement_id": engagement_id, "profile": PROFILE,
                "host_count": host_count, "up_host_count": up_count,
                "open_port_count": len(open_ports), "open_ports": open_ports,
                "fingerprinted_open_port_count": fingerprinted,
                "report_sha256": hashlib.sha256(raw_xml).hexdigest()}
    finally:
        os.close(executable_fd)
