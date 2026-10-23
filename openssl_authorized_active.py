"""Single-connection TLS verification for an operator-authorized HTTPS target.

The caller supplies the target for this run and separately declares authority.
This module normalizes one HTTPS origin, resolves it once to a pinned address,
then delegates one bounded TLS connection to the hash-pinned trust/runtime path.
"""
from __future__ import annotations

import ipaddress
from pathlib import Path
import re
import socket
import stat
import subprocess
from urllib.parse import urlsplit

from openssl_loopback_active import OpenSSLUnavailable, verify_pinned_tls_peer

CONSENT_VERSION = "authorized-tls-target-v1"
_GETENT = Path("/usr/bin/getent")
_DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_MAX_TARGET_BYTES = 512
_MAX_RESOLVER_OUTPUT = 32_768


def normalize_authorized_target(target: object) -> tuple[str, str, int]:
    if (type(target) is not str or not target or target != target.strip()
            or len(target.encode("utf-8")) > _MAX_TARGET_BYTES
            or any(ord(char) < 0x20 or ord(char) == 0x7f for char in target)
            or "\\" in target or "%" in target or "@" in target
            or "?" in target or "#" in target):
        raise ValueError("Geçersiz yetkili TLS hedefi")
    try:
        parsed = urlsplit(target)
        port = parsed.port or 443
        raw_host = parsed.hostname
    except ValueError as exc:
        raise ValueError("Geçersiz yetkili TLS hedefi") from exc
    if (parsed.scheme.lower() != "https" or parsed.username is not None or parsed.password is not None
            or parsed.path not in ("", "/") or parsed.query or parsed.fragment
            or not raw_host or not 1 <= port <= 65535):
        raise ValueError("Geçersiz yetkili TLS hedefi")
    raw_netloc = parsed.netloc
    if raw_netloc.startswith("["):
        closing = raw_netloc.find("]")
        port_suffix = raw_netloc[closing + 1:] if closing >= 0 else "!"
    else:
        if raw_netloc.count(":") > 1:
            raise ValueError("Geçersiz yetkili TLS hedefi")
        _host_part, separator, raw_port = raw_netloc.rpartition(":")
        port_suffix = f":{raw_port}" if separator else ""
    if port_suffix and (not re.fullmatch(r":[1-9][0-9]{0,4}", port_suffix)
                        or int(port_suffix[1:]) != port):
        raise ValueError("Geçersiz yetkili TLS hedefi")
    try:
        address = ipaddress.ip_address(raw_host)
    except ValueError:
        try:
            socket.inet_aton(raw_host)
        except OSError:
            pass
        else:
            raise ValueError("Geçersiz yetkili TLS hedefi")
        if raw_host.endswith("."):
            raise ValueError("Geçersiz yetkili TLS hedefi")
        try:
            host = raw_host.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise ValueError("Geçersiz yetkili TLS hedefi") from exc
        if (len(host) > 253 or len(host.split(".")) < 2
                or any(not _DNS_LABEL.fullmatch(label) for label in host.split("."))
                or all(label.isdigit() for label in host.split("."))):
            raise ValueError("Geçersiz yetkili TLS hedefi")
        display_host = host
    else:
        host = address.compressed
        display_host = f"[{host}]" if address.version == 6 else host
    return f"https://{display_host}:{port}", host, port


def _resolve_once(host: str) -> str:
    try:
        return ipaddress.ip_address(host).compressed
    except ValueError:
        pass
    try:
        metadata = _GETENT.stat(follow_symlinks=False)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0
                or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
                or not metadata.st_mode & stat.S_IXUSR):
            raise OSError("güvensiz çözümleyici")
        result = subprocess.run(
            [str(_GETENT), "ahosts", host],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
            timeout=2.0,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise OpenSSLUnavailable("Yetkili TLS hedefi çözümlenemedi") from exc
    if result.returncode or not result.stdout or len(result.stdout) > _MAX_RESOLVER_OUTPUT:
        raise OpenSSLUnavailable("Yetkili TLS hedefi çözümlenemedi")
    addresses: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
    try:
        for line in result.stdout.decode("ascii").splitlines():
            fields = line.split()
            if fields:
                addresses.add(ipaddress.ip_address(fields[0]))
    except (UnicodeError, ValueError) as exc:
        raise OpenSSLUnavailable("Yetkili TLS hedefi çözümlenemedi") from exc
    if not addresses or len(addresses) > 32:
        raise OpenSSLUnavailable("Yetkili TLS hedefi çözümlenemedi")
    # One deterministic address is pinned for the only connection. IPv4 first
    # avoids a second fallback connection while remaining deterministic.
    return sorted(addresses, key=lambda item: (item.version, item.packed))[0].compressed


def run_openssl_x509_authorized(target: object) -> dict[str, object]:
    normalized, identity, port = normalize_authorized_target(target)
    connected_ip = _resolve_once(identity)
    return verify_pinned_tls_peer(
        connect_host=connected_ip,
        identity=identity,
        port=port,
        format_name="openssl-x509-authorized-v1",
        public_fields={
            "normalized_target": normalized,
            "consent_version": CONSENT_VERSION,
        },
    )
