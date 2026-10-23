"""Run-scoped HTTP origins for explicitly authorized k6 and Schemathesis jobs.

This contract is deliberately separate from the persistent sandbox target
registry.  It accepts one exact origin for one invocation; callers must still
require ``confirm_authorized is True`` for every run.
"""
from __future__ import annotations

import hashlib
import ipaddress
from urllib.parse import urlsplit


CONSENT_VERSION = "authorized-target-v1"
TOOLS = frozenset({"k6", "schemathesis"})
_DNS_LABEL_CHARACTERS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-")


def _is_dns_name(host: str) -> bool:
    """Validate an ASCII DNS name with bounded, non-backtracking label checks."""
    if not 1 <= len(host) <= 253:
        return False
    labels = host.split(".")
    return all(
        1 <= len(label) <= 63
        and label[0] != "-"
        and label[-1] != "-"
        and all(character in _DNS_LABEL_CHARACTERS for character in label)
        for label in labels
    )


def parse_authorized_target(tool: str, target: object) -> dict[str, object]:
    """Return a canonical, one-run target descriptor without registry lookup."""
    if tool not in TOOLS:
        raise ValueError("Yetkili hedef yalnız k6 veya Schemathesis için kullanılabilir.")
    if not isinstance(target, str) or not 1 <= len(target) <= 300 or target != target.strip():
        raise ValueError("Geçersiz yetkili hedef.")
    if any(ch in target for ch in ("\\", "\r", "\n", "\t")):
        raise ValueError("Belirsiz yetkili hedef.")
    try:
        parts = urlsplit(target)
        port = parts.port or (443 if parts.scheme.lower() == "https" else 80)
    except ValueError as exc:
        raise ValueError("Geçersiz yetkili hedef portu.") from exc
    scheme = parts.scheme.lower()
    if (
        scheme not in {"http", "https"}
        or parts.username is not None
        or parts.password is not None
        or parts.path not in ("", "/")
        or parts.query
        or parts.fragment
        or not parts.hostname
        or not 1 <= port <= 65535
        or "%" in parts.netloc
    ):
        raise ValueError("Hedef yalnız http(s)://ana-makine[:port] kökeni olmalı.")

    host = parts.hostname.lower()
    if host.endswith(".") or any(ord(ch) > 127 for ch in host):
        raise ValueError("Belirsiz yetkili hedef adı.")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None:
        # The isolated tool namespace has one IPv4 relay listener.  A literal
        # remote address cannot be transparently remapped while preserving
        # HTTPS SNI; require a DNS name rather than silently changing identity.
        if str(address) != "127.0.0.1":
            raise ValueError("Uzak hedef için ham IP yerine DNS adı kullanın.")
        host = "127.0.0.1"
        kind = "loopback"
    else:
        if not _is_dns_name(host) or host.isdigit():
            raise ValueError("Geçersiz yetkili hedef adı.")
        kind = "loopback" if host == "localhost" else "hostname"

    normalized = f"{scheme}://{host}:{port}"
    target_id = "authorized:" + hashlib.sha256(normalized.encode("ascii")).hexdigest()[:20]
    return {
        "id": target_id,
        "kind": kind,
        "host": host,
        "port": port,
        "scheme": scheme,
        "critical": False,
        "normalized": normalized,
        "consent_version": CONSENT_VERSION,
    }
