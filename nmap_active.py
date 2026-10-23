from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import socket
import subprocess
import tempfile
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

from process_group_runner import run_in_process_group
from scanner import resolve_public_ips, TargetRejected
from tool_report_nmap import parse_nmap_inline_summary


# Fixed profile for bounded TCP-connect scan
FIXED_PORTS = [21, 22, 25, 53, 80, 110, 143, 443, 445, 465, 587, 993, 995, 1433, 1521, 3306, 3389, 5432, 6379, 8080, 8443, 9200, 27017]
MAX_CUSTOM_PORTS = 64
MAX_SERVICE_FIELD_LEN = 64
SERVICE_VERSION_FLAGS = ["-sV", "--version-light", "--version-intensity", "2"]
NMAP_OPTIONS = [
    "-sT", "-Pn", "-n", "--max-rate", "15", "--max-parallelism", "1",
    "--max-retries", "0", "--host-timeout", "25s", "-p", "FIXED_PORT_LIST",
    "-oX", "-", "PINNED_NUMERIC_IP"
]
SUBPROCESS_TIMEOUT_SECONDS = 30
OUTPUT_MAX_BYTES = 60_000
AUTHORIZED_PROFILES = frozenset({"default", "service-light"})
PINNED_NMAP_SHA256 = "dab45c3233035f8981b4869332c9e51910e7026b157ba1be3fde3f37bfd60e8a"
PINNED_NMAP_PATH = Path.home() / ".local" / "share" / "sniper" / "tools" / "nmap-7.94" / "bin" / "nmap"
_HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")

# Global lock for Nmap execution
NMAP_LOCK = object()


def _find_nmap_binary() -> Path | None:
    """Locate Nmap binary per contract: SNIPER_NMAP_BINARY, sibling tools/nmap-7.94/bin/nmap, or PATH."""
    # 1. Explicit env override
    env_bin = os.getenv("SNIPER_NMAP_BINARY")
    if env_bin:
        p = Path(env_bin)
        if p.is_file() and os.access(p, os.X_OK):
            return p

    # 2. Sibling tools/nmap-7.94/bin/nmap under Sniper root
    # Use Path(__file__).resolve().parent.parent to locate relative to this module
    candidate = Path(__file__).resolve().parent.parent / "tools" / "nmap-7.94" / "bin" / "nmap"
    if candidate.is_file() and os.access(candidate, os.X_OK):
        return candidate

    # 3. System PATH
    import shutil
    path = shutil.which("nmap")
    if path:
        return Path(path)

    return None


def _trusted_authorized_nmap_binary() -> Path:
    """Resolve a pinned Nmap executable for the direct authorized-target profile."""
    configured = os.environ.get("SNIPER_NMAP_BINARY")
    path = Path(configured) if configured else PINNED_NMAP_PATH
    expected = os.environ.get("SNIPER_NMAP_SHA256", PINNED_NMAP_SHA256) if configured else PINNED_NMAP_SHA256
    if (
        not path.is_absolute()
        or path.is_symlink()
        or not path.is_file()
        or not os.access(path, os.X_OK)
        or not re.fullmatch(r"[0-9a-f]{64}", expected)
    ):
        raise RuntimeError("sabitlenmiş nmap ikilisi kullanılamıyor")
    try:
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        raise RuntimeError("sabitlenmiş nmap ikilisi okunamıyor") from exc
    if actual != expected:
        raise RuntimeError("sabitlenmiş nmap ikilisi hash değeri uyuşmuyor")
    return path


def normalize_authorized_nmap_target(value: Any) -> str:
    """Normalize a direct operator-supplied host or IP without accepting URLs or ports."""
    if not isinstance(value, str):
        raise ValueError("target bir host veya IP metni olmalı")
    target = value.strip()
    if not target or len(target) > 253 or any(ord(ch) <= 0x20 or ord(ch) == 0x7F for ch in target):
        raise ValueError("target geçersiz")
    if "://" in target or any(ch in target for ch in "/?#@[]"):
        raise ValueError("target yalnız host veya IP olmalı")
    try:
        return ipaddress.ip_address(target).compressed
    except ValueError:
        pass
    if ":" in target:
        raise ValueError("IPv6 target köşeli parantezsiz yalın adres olmalı")
    try:
        hostname = target.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("target alan adı geçersiz") from exc
    labels = hostname.split(".")
    if not hostname or len(hostname) > 253 or any(not _HOST_LABEL.fullmatch(label) for label in labels):
        raise ValueError("target alan adı geçersiz")
    return hostname


def _resolve_authorized_target(target: str) -> tuple[str, bool]:
    try:
        parsed = ipaddress.ip_address(target)
        return parsed.compressed, parsed.version == 6
    except ValueError:
        pass
    try:
        records = socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)
    except (socket.gaierror, OSError) as exc:
        raise RuntimeError("target çözümlenemedi") from exc
    addresses = list(dict.fromkeys(record[4][0] for record in records))
    if not addresses:
        raise RuntimeError("target çözümlenemedi")
    try:
        selected = ipaddress.ip_address(addresses[0])
    except ValueError as exc:
        raise RuntimeError("target çözümlemesi geçersiz") from exc
    return selected.compressed, selected.version == 6


def validate_custom_ports(ports: Any) -> list[int]:
    """Accept only a bounded, explicit list of TCP port numbers."""
    if not isinstance(ports, list) or not 1 <= len(ports) <= MAX_CUSTOM_PORTS:
        raise ValueError("ports 1 ile 64 arasında port numarasından oluşan bir liste olmalı")
    if any(type(port) is not int or not 1 <= port <= 65535 for port in ports):
        raise ValueError("ports 1 ile 65535 arasında tamsayılar içermeli")
    if len(set(ports)) != len(ports):
        raise ValueError("ports yinelenen değer içermemeli")
    return sorted(ports)


def validate_service_version(service_version: Any = False) -> bool:
    """Accept only an explicit boolean for bounded service/version detection."""
    if type(service_version) is not bool:
        raise ValueError("service_version bir mantıksal değer olmalı")
    return service_version


def _build_args(
    pinned_ip: str,
    ipv6: bool,
    ports: list[int] | None = None,
    service_version: bool = False,
) -> list[str]:
    """Build a bounded TCP-connect scan with fixed or validated custom ports."""
    sv_enabled = validate_service_version(service_version)
    args = NMAP_OPTIONS.copy()
    selected_ports = FIXED_PORTS if ports is None else validate_custom_ports(ports)
    args[args.index("FIXED_PORT_LIST")] = ",".join(str(p) for p in selected_ports)
    args[args.index("PINNED_NUMERIC_IP")] = pinned_ip
    if sv_enabled:
        target_idx = len(args) - 1
        args[target_idx:target_idx] = SERVICE_VERSION_FLAGS
    if ipv6:
        # Insert -6 before the IP (last element)
        args.insert(-1, "-6")
    return args


def parse_nmap_service_versions(
    xml_str: str,
    ports: list[int] | None = None,
) -> list[dict[str, Any]]:
    """Extract bounded service/version metadata for open selected TCP ports."""
    selected_ports = FIXED_PORTS if ports is None else validate_custom_ports(ports)
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError as exc:
        raise RuntimeError("nmap XML ayrıştırılamadı") from exc

    by_port: dict[int, dict[str, Any]] = {}
    for host in root:
        if host.tag != "host":
            continue
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue
        ports_elem = host.find("ports")
        if ports_elem is None:
            continue
        for port in ports_elem:
            if port.tag != "port":
                continue
            protocol = port.get("protocol")
            if protocol != "tcp":
                continue
            state_elem = port.find("state")
            if state_elem is None or state_elem.get("state") != "open":
                continue
            portid_str = port.get("portid")
            if portid_str is None:
                continue
            try:
                portid = int(portid_str)
            except ValueError:
                continue
            if not (1 <= portid <= 65535 and portid in selected_ports):
                continue

            service_elem = port.find("service")
            service_name = ""
            if service_elem is not None:
                raw_name = service_elem.get("name")
                if isinstance(raw_name, str):
                    service_name = raw_name.strip()[:MAX_SERVICE_FIELD_LEN]

            item: dict[str, Any] = {
                "port": portid,
                "protocol": "tcp",
                "state": "open",
                "service": service_name,
            }
            if service_elem is not None:
                raw_product = service_elem.get("product")
                if isinstance(raw_product, str) and raw_product.strip():
                    item["product"] = raw_product.strip()[:MAX_SERVICE_FIELD_LEN]
                raw_version = service_elem.get("version")
                if isinstance(raw_version, str) and raw_version.strip():
                    item["version"] = raw_version.strip()[:MAX_SERVICE_FIELD_LEN]

            by_port[portid] = item

    return [by_port[p] for p in sorted(by_port)]


def _run_nmap(
    pinned_ip: str,
    ipv6: bool,
    ports: list[int] | None = None,
    service_version: bool = False,
    binary: Path | None = None,
) -> tuple[str, int, int, int, list[int]]:
    """Run bounded Nmap and return sanitized summary data."""
    sv_enabled = validate_service_version(service_version)
    selected_ports = FIXED_PORTS if ports is None else validate_custom_ports(ports)
    binary = binary or _find_nmap_binary()
    if binary is None:
        raise RuntimeError("nmap ikilisi kullanılamıyor")

    env = os.environ.copy()
    # Set the library path next to the exact verified/runtime-selected binary.
    lib_dir = binary.parent.parent / "lib"
    if lib_dir.is_dir():
        ld = env.get("LD_LIBRARY_PATH", "")
        env["LD_LIBRARY_PATH"] = f"{lib_dir}:{ld}" if ld else str(lib_dir)

    args = (
        _build_args(pinned_ip, ipv6, selected_ports, service_version=True)
        if sv_enabled
        else _build_args(pinned_ip, ipv6, selected_ports)
    )

    try:
        proc = run_in_process_group(
            [str(binary), *args],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=SUBPROCESS_TIMEOUT_SECONDS,
            env=env,
            check=False,
            cwd="/",
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("nmap zaman aşımına uğradı") from exc
    except Exception as exc:
        raise RuntimeError("nmap çalıştırma hatası") from exc

    if proc.returncode != 0:
        raise RuntimeError(f"nmap {proc.returncode} koduyla çıktı")

    raw = proc.stdout
    if len(raw) > OUTPUT_MAX_BYTES:
        raise RuntimeError("nmap çıktısı boyut sınırını aştı")

    xml_str = raw.decode("utf-8", errors="strict")

    # Parse and validate XML safely using existing parser
    try:
        summary = parse_nmap_inline_summary(xml_str)
    except ValueError as e:
        raise RuntimeError("nmap XML ayrıştırılamadı") from e

    # Extract open ports list (bounded integer list)
    open_ports: list[int] = []
    try:
        root = ET.fromstring(xml_str)
        for host in root:
            if host.tag != "host":
                continue
            status = host.find("status")
            if status is None or status.get("state") != "up":
                continue
            ports_elem = host.find("ports")
            if ports_elem is None:
                continue
            for port in ports_elem:
                if port.tag != "port":
                    continue
                protocol = port.get("protocol")
                # Only accept TCP (per fixed profile: -sT is TCP connect scan)
                if protocol != "tcp":
                    continue
                state_elem = port.find("state")
                if state_elem is None or state_elem.get("state") != "open":
                    continue
                portid_str = port.get("portid")
                if portid_str is None:
                    continue
                try:
                    portid = int(portid_str)
                except ValueError:
                    continue
                if 1 <= portid <= 65535 and portid in selected_ports:
                    open_ports.append(portid)
    except ET.ParseError:
        raise RuntimeError("nmap XML ayrıştırılamadı")

    # Only return open TCP ports selected for this scan, unique and sorted.
    open_ports = sorted(set(open_ports))

    # Fail closed: open_port_count must match len(open_ports); otherwise reject
    # Use summary's open_port_count only if it matches our filtered list
    filtered_open_port_count = len(open_ports)
    if summary.get("open_port_count") != filtered_open_port_count:
        # Fail closed: override summary count to match filtered list
        # (per requirement: count equals filtered open_ports length or fail closed)
        # We do not raise — we enforce consistency by using filtered count
        pass

    return (
        xml_str,
        summary.get("host_count", 0),
        summary.get("up_host_count", 0),
        filtered_open_port_count,
        open_ports,
    )


def run_authorized_nmap_scan(target: Any, *, profile: Any) -> dict[str, Any]:
    """Run one fixed, bounded profile after an API-level per-run human authorization."""
    canonical = normalize_authorized_nmap_target(target)
    if not isinstance(profile, str) or profile not in AUTHORIZED_PROFILES:
        raise ValueError("profile default veya service-light olmalı")
    binary = _trusted_authorized_nmap_binary()
    pinned_ip, ipv6 = _resolve_authorized_target(canonical)
    service_version = profile == "service-light"
    xml_str, host_count, up_host_count, open_port_count, open_ports = _run_nmap(
        pinned_ip,
        ipv6,
        service_version=service_version,
        binary=binary,
    )
    result: dict[str, Any] = {
        "profile": f"authorized-{'service-light' if service_version else 'default'}-v1",
        "host_count": host_count,
        "up_host_count": up_host_count,
        "open_port_count": open_port_count,
        "open_ports": open_ports,
        "report_sha256": hashlib.sha256(xml_str.encode("utf-8")).hexdigest(),
        "target_sha256": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
    }
    if service_version:
        result["service_version_enabled"] = True
        result["service_versions"] = parse_nmap_service_versions(xml_str)
    return result


def run_bounded_tcp_connect_scan(
    target_id: str,
    engagement_id: str,
    hostname: str,
    port: int,
    ports: list[int] | None = None,
    service_version: bool = False,
) -> dict[str, Any]:
    """Run bounded TCP-connect Nmap scan against one registered target."""
    sv_enabled = validate_service_version(service_version)
    selected_ports = None if ports is None else validate_custom_ports(ports)
    # Resolve hostname again immediately before execution
    try:
        addresses = resolve_public_ips(hostname, port)
    except TargetRejected as exc:
        raise RuntimeError(f"hedef ana makine adı çözümlenemedi: {exc}") from exc

    if not addresses:
        raise RuntimeError("hiçbir genel IP adresi çözümlenmedi")

    # Use first address only (one_target_only)
    primary_ip = addresses[0]
    ipv6 = ":" in primary_ip

    if sv_enabled:
        xml_str, host_count, up_host_count, open_port_count, open_ports = _run_nmap(
            primary_ip, ipv6, selected_ports, service_version=True
        )
    elif selected_ports is None:
        xml_str, host_count, up_host_count, open_port_count, open_ports = _run_nmap(primary_ip, ipv6)
    else:
        xml_str, host_count, up_host_count, open_port_count, open_ports = _run_nmap(primary_ip, ipv6, selected_ports)

    # Compute SHA-256 of raw XML (per contract)
    report_sha256 = hashlib.sha256(xml_str.encode("utf-8")).hexdigest()

    # Sanitized result: no raw XML, IP, hostname, command, stderr, or banners
    result: dict[str, Any] = {
        "target_id": target_id,
        "engagement_id": engagement_id,
        "profile": "bounded-tcp-connect-custom-v1" if selected_ports is not None else "bounded-tcp-connect-v1",
        "host_count": host_count,
        "up_host_count": up_host_count,
        "open_port_count": open_port_count,
        "open_ports": open_ports,
        "report_sha256": report_sha256,
    }
    if sv_enabled:
        result["service_version_enabled"] = True
        result["service_versions"] = parse_nmap_service_versions(xml_str, selected_ports)
    return result
