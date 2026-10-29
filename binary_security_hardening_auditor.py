"""Binary security hardening and native artifact static auditor.

Inspects ELF, PE, Mach-O, and WASM binaries (or readelf/objdump/nm text dumps)
for missing memory-mitigation flags (Stack Canary, NX, RELRO), unsafe dynamic
linker search paths (DT_RPATH / DT_RUNPATH hijacking), unbounded dangerous C
library imports, and hardcoded plaintext secrets in .rodata / .data sections.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any


AUDIT_FORMAT = "sniper-binary-security-hardening-audit/1"

_HEX_CLEAN_RE = re.compile(r"^[0-9a-fA-F\s]+$")
_PRINTABLE_BYTES_RE = re.compile(rb"[\x20-\x7e]{4,}")

_CANARY_MARKERS = (
    "__stack_chk_fail",
    "__stack_chk_guard",
    "__security_check_cookie",
    "__security_cookie",
)
_FORTIFY_RE = re.compile(r"\b__[a-z0-9_]+_chk\b")
_GNU_STACK_RWE_RE = re.compile(
    r"(?:GNU_STACK\b[^\n\r\x00]{0,80}\bRWE\b|\bRWE\b[^\n\r\x00]{0,40}\bGNU_STACK\b|\bEXECSTACK\b|NX\s*[:=]\s*disabled)",
    re.IGNORECASE,
)
_RELRO_ENABLE_MARKERS = (
    "BIND_NOW",
    "GNU_RELRO",
    "Full RELRO",
    "Partial RELRO",
    "FLAGS_1=NOW",
    "DT_BIND_NOW",
    "DYNAMICBASE",
    "HIGHENTROPYVA",
    "MH_PIE",
)
_RELRO_DISABLE_RE = re.compile(
    r"(?:No\s+RELRO|RELRO\s*[:=]\s*(?:no|none|disabled|false)|RELRO_DISABLED)",
    re.IGNORECASE,
)

_RPATH_DIRECTIVE_RE = re.compile(
    r"(?:Library\s++r(?:un)?path:\s*+\[([^\]]++)\]|"
    r"\((?:RPATH|RUNPATH)\)\s++[^\n\r\x00\[]*+\[([^\]]++)\]|"
    r"\b(?:DT_)?(?:RPATH|RUNPATH)\s*+(?:=|:|\s++)\s*+\[?([^\s\]\x00\"']++))",
    re.IGNORECASE,
)
_AT_RPATH_RE = re.compile(r"(@(?:rpath|loader_path|executable_path)/[^\s\x00\"':]+)")

_UNSAFE_LIBC_SYMS = (
    "gets",
    "strcpy",
    "strcat",
    "sprintf",
    "vsprintf",
    "mktemp",
    "system",
    "popen",
)
_UNSAFE_SYM_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9_./-])_?(gets|strcpy|strcat|sprintf|vsprintf|mktemp|system|popen)"
    r"(?:@[A-Za-z0-9_.-]+)?(?![A-Za-z0-9_./-])"
)

_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("openai_or_api_secret_key", re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b")),
    ("github_pat", re.compile(r"\bghp_[A-Za-z0-9]{20,}\b")),
    ("gitlab_pat", re.compile(r"\bglpat-[A-Za-z0-9_-]{16,}\b")),
    ("aws_access_key_id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("private_key_pem", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
)


def _coerce_bytes_and_text(raw_bytes_or_text: bytes | str) -> tuple[bytes, str]:
    if isinstance(raw_bytes_or_text, (bytes, bytearray, memoryview)):
        raw_bytes = bytes(raw_bytes_or_text)
        return raw_bytes, raw_bytes.decode("latin-1", errors="ignore")

    if not isinstance(raw_bytes_or_text, str):
        raw_bytes = bytes(str(raw_bytes_or_text), "latin-1", errors="ignore")
        return raw_bytes, raw_bytes.decode("latin-1", errors="ignore")

    stripped = raw_bytes_or_text.strip()
    compact = re.sub(r"\s+", "", stripped)
    if (
        len(compact) >= 8
        and len(compact) % 2 == 0
        and _HEX_CLEAN_RE.match(stripped)
        and compact[:8].lower() in ("7f454c46", "feedfacf", "cffaedfe", "feedface", "cefaedfe", "0061736d")
        or (len(compact) >= 8 and len(compact) % 2 == 0 and _HEX_CLEAN_RE.match(stripped) and compact[:4].lower() == "4d5a")
    ):
        try:
            decoded = bytes.fromhex(compact)
            return decoded, decoded.decode("latin-1", errors="ignore")
        except ValueError:
            pass

    raw_bytes = raw_bytes_or_text.encode("latin-1", errors="ignore")
    return raw_bytes, raw_bytes_or_text


def _detect_binary_format(raw_bytes: bytes, raw_text: str, filename: str) -> str:
    if raw_bytes.startswith(b"\x7fELF") or "\x7fELF" in raw_text or "ELF Header" in raw_text:
        return "ELF"
    if raw_bytes.startswith(b"MZ") or "PE32" in raw_text:
        return "PE"
    if (
        raw_bytes[:4] in (b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe")
        or "Mach-O" in raw_text
    ):
        return "Mach-O"
    if raw_bytes.startswith(b"\x00asm"):
        return "WASM"

    low_name = (filename or "").lower()
    if low_name.endswith((".dll", ".exe", ".sys")):
        return "PE"
    if low_name.endswith((".dylib", ".bundle")):
        return "Mach-O"
    if low_name.endswith(".wasm"):
        return "WASM"
    return "ELF"


def _extract_printable_strings(raw_bytes: bytes, raw_text: str) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for match in _PRINTABLE_BYTES_RE.finditer(raw_bytes):
        s = match.group(0).decode("ascii", errors="ignore").strip()
        if len(s) >= 4 and s not in seen:
            seen.add(s)
            found.append(s)
    for chunk in re.split(r"[\x00\r\n]+", raw_text):
        s = chunk.strip()
        if len(s) >= 4 and s not in seen:
            seen.add(s)
            found.append(s)
    return found


def _analyze_rpaths(printable_strings: list[str], raw_text: str) -> tuple[list[str], list[str]]:
    rpath_values: list[str] = []
    for text_item in [*printable_strings, raw_text]:
        for match in _RPATH_DIRECTIVE_RE.finditer(text_item):
            val = next((g for g in match.groups() if g is not None), "")
            if val and val not in rpath_values:
                rpath_values.append(val)
        for match in _AT_RPATH_RE.finditer(text_item):
            val = match.group(1)
            if val and val not in rpath_values:
                rpath_values.append(val)

    unsafe_reasons: list[str] = []
    for rpath in rpath_values:
        if "::" in rpath or rpath.startswith(":") or rpath.endswith(":"):
            unsafe_reasons.append(f"empty colon segment in '{rpath}' (implies current working directory)")
        segments = rpath.split(":")
        for seg in segments:
            s = seg.strip()
            if not s:
                continue
            if s in (".", "./") or s.startswith(("./", "../")):
                unsafe_reasons.append(f"relative directory segment '{s}' in '{rpath}'")
            elif s == "/tmp" or s.startswith("/tmp/") or s == "/var/tmp" or s.startswith("/var/tmp/") or s.startswith("/dev/shm"):
                unsafe_reasons.append(f"world-writable temporary path '{s}' in '{rpath}'")
            elif (
                "$ORIGIN/.." in s
                or "${ORIGIN}/.." in s
                or "@loader_path/.." in s
                or "@executable_path/.." in s
                or "@rpath/.." in s
            ):
                unsafe_reasons.append(f"writable relative parent traversal '{s}' in '{rpath}'")

    return rpath_values, unsafe_reasons


def _redact_secret(raw_secret: str) -> str:
    digest = hashlib.sha256(raw_secret.encode("utf-8")).hexdigest()[:12]
    prefix = raw_secret[:4] if not raw_secret.startswith("-----BEGIN") else "PEM_KEY"
    return f"{prefix}...<redacted:sha256:{digest}>"


def audit_binary_security_hardening(
    raw_bytes_or_text: bytes | str,
    *,
    filename: str = "libnative.so",
) -> dict[str, Any]:
    """Audit a compiled binary or symbol/header dump for memory hardening and embedded risks."""
    raw_bytes, raw_text = _coerce_bytes_and_text(raw_bytes_or_text)
    detected_format = _detect_binary_format(raw_bytes, raw_text, filename)
    printable_strings = _extract_printable_strings(raw_bytes, raw_text)
    joined_strings = "\n".join(printable_strings)
    combined_corpus = f"{joined_strings}\n{raw_text}"

    has_canary = any(marker in combined_corpus for marker in _CANARY_MARKERS)
    nx_enabled = not bool(_GNU_STACK_RWE_RE.search(combined_corpus))
    has_relro = any(marker in combined_corpus for marker in _RELRO_ENABLE_MARKERS) and not bool(
        _RELRO_DISABLE_RE.search(combined_corpus)
    )
    has_fortify = bool(_FORTIFY_RE.search(combined_corpus))

    findings: list[dict[str, Any]] = []

    # 1. SNIPER-BIN-HARDEN-01: Missing memory protection flags
    if detected_format in ("ELF", "PE", "Mach-O"):
        missing_flags: list[str] = []
        if not has_canary:
            missing_flags.append("Stack Canary (__stack_chk_fail / __security_check_cookie)")
        if not nx_enabled:
            missing_flags.append("NX / Non-Executable Stack (GNU_STACK RWE)")
        if not has_relro:
            missing_flags.append("RELRO / BIND_NOW")

        if missing_flags:
            findings.append(
                {
                    "id": "SNIPER-BIN-HARDEN-01",
                    "rule_id": "SNIPER-BIN-HARDEN-01",
                    "control_id": "SNIPER-BIN-HARDEN-01",
                    "cwe": "CWE-693",
                    "severity": "medium",
                    "category": "binary_security",
                    "title": "Derlenmiş ikili dosyada (Binary) eksik bellek koruma bayrakları (Stack Canary / NX / PIE / RELRO)",
                    "file": filename,
                    "location": filename,
                    "missing_mitigations": missing_flags,
                    "evidence": f"{filename} ({detected_format}): missing {', '.join(missing_flags)}",
                }
            )

    # 2. SNIPER-BIN-RPATH-02: Unsafe DT_RPATH / DT_RUNPATH
    rpath_values, unsafe_rpath_reasons = _analyze_rpaths(printable_strings, raw_text)
    if unsafe_rpath_reasons:
        findings.append(
            {
                "id": "SNIPER-BIN-RPATH-02",
                "rule_id": "SNIPER-BIN-RPATH-02",
                "control_id": "SNIPER-BIN-RPATH-02",
                "cwe": "CWE-426",
                "severity": "high",
                "category": "binary_security",
                "title": "İkili dosyada güvensiz DT_RPATH / DT_RUNPATH dinamik kütüphane arama yolu (RPATH Hijacking)",
                "file": filename,
                "location": filename,
                "rpath_values": rpath_values,
                "unsafe_reasons": unsafe_rpath_reasons,
                "evidence": f"{filename}: {'; '.join(unsafe_rpath_reasons)}",
            }
        )

    # 3. SNIPER-BIN-UNSAFE-SYM-03: Dangerous unbounded C library imports
    detected_unsafe_syms: list[str] = []
    for s in printable_strings:
        for m in _UNSAFE_SYM_TOKEN_RE.finditer(s):
            sym = m.group(1)
            if sym in _UNSAFE_LIBC_SYMS and sym not in detected_unsafe_syms:
                detected_unsafe_syms.append(sym)

    if detected_unsafe_syms:
        findings.append(
            {
                "id": "SNIPER-BIN-UNSAFE-SYM-03",
                "rule_id": "SNIPER-BIN-UNSAFE-SYM-03",
                "control_id": "SNIPER-BIN-UNSAFE-SYM-03",
                "cwe": "CWE-676",
                "severity": "high",
                "category": "binary_security",
                "title": "İkili sembol tablosunda sınır kontrolsüz tehlikeli C fonksiyonu ithali (gets / strcpy / sprintf / system)",
                "file": filename,
                "location": filename,
                "unsafe_symbols": detected_unsafe_syms,
                "evidence": f"{filename}: imported unfortified symbols {', '.join(detected_unsafe_syms)}",
            }
        )

    # 4. SNIPER-BIN-RODATA-SECRET-04: Embedded secrets in .rodata / .data
    redacted_secrets: list[str] = []
    secret_kinds: list[str] = []
    for s in printable_strings:
        for kind, pattern in _SECRET_PATTERNS:
            for m in pattern.finditer(s):
                redacted = _redact_secret(m.group(0))
                if redacted not in redacted_secrets:
                    redacted_secrets.append(redacted)
                if kind not in secret_kinds:
                    secret_kinds.append(kind)

    if redacted_secrets:
        findings.append(
            {
                "id": "SNIPER-BIN-RODATA-SECRET-04",
                "rule_id": "SNIPER-BIN-RODATA-SECRET-04",
                "control_id": "SNIPER-BIN-RODATA-SECRET-04",
                "cwe": "CWE-798",
                "severity": "critical",
                "category": "secrets",
                "title": "Derlenmiş ikili (.rodata / .data) bölümünde gömülü düz metin API anahtarı veya özel anahtar",
                "file": filename,
                "location": filename,
                "secret_types": secret_kinds,
                "redacted_matches": redacted_secrets,
                "evidence": f"{filename} (.rodata/.data): {', '.join(redacted_secrets)}",
            }
        )

    return {
        "format": AUDIT_FORMAT,
        "filename": filename,
        "binary_format": detected_format,
        "hardening_features": {
            "stack_canary": has_canary,
            "nx_enabled": nx_enabled,
            "relro": has_relro,
            "fortify_source": has_fortify,
        },
        "finding_count": len(findings),
        "findings": findings,
    }
