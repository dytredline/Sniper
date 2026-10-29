"""Wave 5 — Programatik Konteyner/VM Başlatıcı (docker run / podman run) Denetleyicisi.

Python, TypeScript/JS, Go, Rust ve Shell kaynak kodlarında dinamik olarak oluşturulan
`docker run` / `podman run` komutlarındaki iki yüksek etkili izolasyon zafiyetini tespit eder:
- SNIPER-ORCH-PORT-01: Programatik konteyner/VM başlatıcısında (docker run) 0.0.0.0 arayüzüne
  açık veya loopback (127.0.0.1) kısıtı olmayan hassas port bağlaması (CWE-668).
- SNIPER-ORCH-MOUNT-02: Programatik konteyner/VM başlatıcısında konak kurulum/betik/paylaşım
  dizininin salt-okunur (:ro) olmadan yazılabilir (:rw) bağlanması (CWE-732).
"""

from __future__ import annotations

import re
from typing import Any

FORMAT_VERSION = "sniper-container-orchestrator-audit/1"

SENSITIVE_CONTAINER_PORTS: frozenset[str] = frozenset(
    {"8006", "3389", "5900", "5901", "10000", "2375", "9222"}
)

_LOOPBACK_HOSTS: frozenset[str] = frozenset(
    {"127.0.0.1", "localhost", "::1", "[::1]"}
)

_URL_SCHEMES: frozenset[str] = frozenset(
    {"http", "https", "ws", "wss", "tcp", "udp", "unix", "ssh", "rdp", "vnc"}
)

_ORCHESTRATOR_CONTEXT_RE = re.compile(
    r"(?:\b(?:docker|podman)\b|--cap-add|NET_ADMIN|/dev/kvm|--privileged|--publish|-p\b|-v\b|--volume)"
)

_PUBLISH_FLAG_RE = re.compile(
    r"(?:^|[\s'\"`,(\[=])(?:-p|--publish)(?:\s*=\s*|\s+|\s*,\s*\n?\s*(?:[frFR]{1,2})?['\"`])"
    r"(?P<spec>(?:[A-Za-z0-9_.*$-]+|\$\{[^}\n]+\}|\{[^}\n]+\}|\[::1\])"
    r"(?::(?:[A-Za-z0-9_.*$-]+|\$\{[^}\n]+\}|\{[^}\n]+\}))+(?:/(?:tcp|udp))?)"
)

_SENSITIVE_PORT_SPEC_RE = re.compile(
    r"(?<![A-Za-z0-9_.:/\-}$])"
    r"(?P<spec>(?:[A-Za-z0-9_.*$-]+|\$\{[^}\n]+\}|\{[^}\n]+\}|\[::1\])"
    r"(?::(?:[A-Za-z0-9_.*$-]+|\$\{[^}\n]+\}|\{[^}\n]+\}))*:"
    r"(?:8006|3389|5900|5901|10000|2375|9222)(?:/(?:tcp|udp))?)"
    r"(?![A-Za-z0-9_.:])"
)

_VOLUME_FLAG_RE = re.compile(
    r"(?:^|[\s'\"`,(\[=])(?:-v|--volume)(?:\s*=\s*|\s+|\s*,\s*\n?\s*(?:[frFR]{1,2})?['\"`])"
    r"(?P<mount>(?:[A-Za-z0-9_./~*$-]+|\$\{[^}\n]+\}|\{[^}\n]+\})"
    r":/(?:[A-Za-z0-9_./$-]+|\$\{[^}\n]+\}|\{[^}\n]+\})(?::[A-Za-z0-9_,]+)?)"
)

_SHARED_MOUNT_SPEC_RE = re.compile(
    r"(?<![A-Za-z0-9_.:/\-}$])"
    r"(?P<mount>(?:[A-Za-z0-9_./~*$-]+|\$\{[^}\n]+\}|\{[^}\n]+\})"
    r":/(?:shared|scripts|setup|install|oem|bootstrap|init|provision)(?:/[A-Za-z0-9_./$-]*)?"
    r"(?::[A-Za-z0-9_,]+)?)"
    r"(?![A-Za-z0-9_.:/])"
)

_SETUP_SCRIPT_MOUNT_KEYWORDS_RE = re.compile(
    r"(?:setup|script|shared|install|oem|bootstrap|init|provision)",
    re.IGNORECASE,
)


def _line_number(content: str, offset: int) -> int:
    return content.count("\n", 0, max(0, offset)) + 1


def _split_colon_outside_braces(spec: str) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    brace_depth = 0
    bracket_depth = 0
    for ch in spec:
        if ch == "{":
            brace_depth += 1
            current.append(ch)
        elif ch == "}":
            brace_depth = max(0, brace_depth - 1)
            current.append(ch)
        elif ch == "[":
            bracket_depth += 1
            current.append(ch)
        elif ch == "]":
            bracket_depth = max(0, bracket_depth - 1)
            current.append(ch)
        elif ch == ":" and brace_depth == 0 and bracket_depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(ch)
    parts.append("".join(current))
    return parts


def audit_programmatic_container_orchestration(
    raw_content: str,
    *,
    filename: str = "cli.py",
) -> dict[str, Any]:
    """Programatik docker/podman run çağrılarında 0.0.0.0 port bağlaması ve yazılabilir kurulum dizini bağlamalarını denetler."""
    content = str(raw_content or "")
    findings: list[dict[str, Any]] = []

    if not content or not _ORCHESTRATOR_CONTEXT_RE.search(content):
        return {
            "format": FORMAT_VERSION,
            "filename": filename,
            "finding_count": 0,
            "findings": findings,
        }

    # (a) SNIPER-ORCH-PORT-01
    port_candidates: list[tuple[int, str]] = []
    for m in _PUBLISH_FLAG_RE.finditer(content):
        port_candidates.append((m.start("spec"), m.group("spec")))
    for m in _SENSITIVE_PORT_SPEC_RE.finditer(content):
        port_candidates.append((m.start("spec"), m.group("spec")))

    seen_port_lines: set[int] = set()
    for spec_start, spec in port_candidates:
        before = content[max(0, spec_start - 16) : spec_start]
        if "://" in before or before.endswith("/"):
            continue
        if before.lower().endswith(("127.0.0.1:", "localhost:", "[::1]:", "::1:")):
            continue

        clean_spec = spec.split("/", 1)[0].strip()
        parts = _split_colon_outside_braces(clean_spec)
        if len(parts) < 2:
            continue

        first_part = parts[0].strip()
        if first_part.lower() in _URL_SCHEMES:
            continue
        if first_part.lower() in _LOOPBACK_HOSTS:
            continue

        container_port = parts[-1].strip()
        is_explicit_wildcard = len(parts) >= 3 and first_part in {"0.0.0.0", "*", "::", "[::]"}
        is_sensitive_port = container_port in SENSITIVE_CONTAINER_PORTS

        if not (is_explicit_wildcard or is_sensitive_port):
            continue

        line_no = _line_number(content, spec_start)
        if line_no in seen_port_lines:
            continue
        seen_port_lines.add(line_no)

        title = "Programatik konteyner/VM başlatıcısında (docker run) 0.0.0.0 arayüzüne açık hassas port bağlaması"
        remediation = (
            "Konteyner veya VM yönetim/masaüstü portlarını (`8006`, `3389`, `5900`, `10000` vb.) "
            "yalnızca geri döngü arayüzüne (`-p 127.0.0.1:<host_port>:<container_port>`) bağlayın."
        )
        findings.append(
            {
                "control_id": "SNIPER-ORCH-PORT-01",
                "rule_id": "SNIPER-ORCH-PORT-01",
                "cwe": "CWE-668",
                "reference": "CWE-668",
                "severity": "high",
                "category": "container",
                "title": title,
                "description": (
                    f"`{filename}` içinde konteyner/VM port eşlemesi (`{spec}`) `127.0.0.1:` (loopback) "
                    "öneki olmadan tanımlanmış; Docker/Podman varsayılan olarak portu `0.0.0.0` (tüm ağ "
                    "arayüzleri) üzerinden dış ağa açar."
                ),
                "remediation": remediation,
                "recommendation": remediation,
                "filename": filename,
                "file": filename,
                "line": line_no,
                "evidence": spec.strip(),
            }
        )

    # (b) SNIPER-ORCH-MOUNT-02
    mount_candidates: list[tuple[int, int, str]] = []
    for m in _VOLUME_FLAG_RE.finditer(content):
        mount_candidates.append((m.start("mount"), m.end("mount"), m.group("mount")))
    for m in _SHARED_MOUNT_SPEC_RE.finditer(content):
        mount_candidates.append((m.start("mount"), m.end("mount"), m.group("mount")))

    seen_mount_lines: set[int] = set()
    for mount_start, mount_end, mount_spec in mount_candidates:
        trailing = content[mount_end : mount_end + 8]
        if trailing.startswith(":ro"):
            continue

        parts = _split_colon_outside_braces(mount_spec)
        if len(parts) < 2:
            continue

        host_src = parts[0].strip()
        container_dst = parts[1].strip()
        mount_opts = parts[2].strip() if len(parts) >= 3 else ""

        opt_tokens = {tok.strip().lower() for tok in mount_opts.split(",") if tok.strip()}
        if "ro" in opt_tokens or "readonly" in opt_tokens:
            continue

        if not (
            _SETUP_SCRIPT_MOUNT_KEYWORDS_RE.search(host_src)
            or _SETUP_SCRIPT_MOUNT_KEYWORDS_RE.search(container_dst)
        ):
            continue

        line_no = _line_number(content, mount_start)
        if line_no in seen_mount_lines:
            continue
        seen_mount_lines.add(line_no)

        title = "Programatik konteyner/VM başlatıcısında konak kurulum/betik dizininin yazılabilir (:rw) bağlanması"
        remediation = (
            "Konak kurulum/betik dizinlerini konteyner veya VM içine bağlarken `:ro` (salt-okunur) "
            "bayrağını zorunlu kılın (`-v <host_path>:<container_path>:ro`)."
        )
        findings.append(
            {
                "control_id": "SNIPER-ORCH-MOUNT-02",
                "rule_id": "SNIPER-ORCH-MOUNT-02",
                "cwe": "CWE-732",
                "reference": "CWE-732",
                "severity": "high",
                "category": "container",
                "title": title,
                "description": (
                    f"`{filename}` içinde konak kurulum/betik/paylaşım dizini (`{mount_spec}`) `:ro` "
                    "(salt-okunur) kısıtı olmadan bağlanıyor; ayrıcalıklı (`NET_ADMIN`, `/dev/kvm`, "
                    "`--privileged`) konteyner/VM içinden konak betiklerinin değiştirilmesine yol açabilir."
                ),
                "remediation": remediation,
                "recommendation": remediation,
                "filename": filename,
                "file": filename,
                "line": line_no,
                "evidence": mount_spec.strip(),
            }
        )

    return {
        "format": FORMAT_VERSION,
        "filename": filename,
        "finding_count": len(findings),
        "findings": findings,
    }
