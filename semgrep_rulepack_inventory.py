"""Read-only, bounded inventory and language coverage validator for trusted local Semgrep rulepacks.

Validates that a local Semgrep rulepack is an absolute, non-symlink regular file
within size bounds, extracts rule count, declared languages, and SHA-256 without
executing YAML tags, and computes covered/uncovered file extensions. Never leaks
local filesystem paths.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from pathlib import Path

MAX_RULEPACK_BYTES = 524_288
MAX_RULES = 500
INVENTORY_FORMAT = "semgrep-rulepack-inventory-v1"
SCOPE_NOTICE = "bounded_trusted_rulepack_only"

ALLOWED_SEVERITIES = frozenset({
    "ERROR",
    "WARNING",
    "INFO",
    "INVENTORY",
    "EXPERIMENT",
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW",
})

LANGUAGE_EXTENSION_MAP: dict[str, tuple[str, ...]] = {
    "python": (".py",),
    "py": (".py",),
    "python2": (".py",),
    "python3": (".py",),
    "javascript": (".cjs", ".js", ".jsx", ".mjs"),
    "js": (".cjs", ".js", ".jsx", ".mjs"),
    "typescript": (".ts", ".tsx"),
    "ts": (".ts", ".tsx"),
    "jsx": (".js", ".jsx"),
    "tsx": (".ts", ".tsx"),
    "go": (".go",),
    "golang": (".go",),
    "rust": (".rs",),
    "rs": (".rs",),
    "java": (".java",),
    "kotlin": (".kt", ".kts"),
    "kt": (".kt", ".kts"),
    "ruby": (".rb",),
    "rb": (".rb",),
    "php": (".php",),
    "csharp": (".cs",),
    "c#": (".cs",),
    "cs": (".cs",),
    "c": (".c", ".h"),
    "cpp": (".c", ".cc", ".cpp", ".h", ".hpp"),
    "c++": (".c", ".cc", ".cpp", ".h", ".hpp"),
    "swift": (".swift",),
    "dart": (".dart",),
    "bash": (".sh",),
    "sh": (".sh",),
    "shell": (".sh",),
    "sql": (".sql",),
    "html": (".htm", ".html"),
    "yaml": (".yaml", ".yml"),
    "yml": (".yaml", ".yml"),
    "json": (".json",),
    "toml": (".toml",),
    "xml": (".xml",),
    "vue": (".vue",),
    "svelte": (".svelte",),
    "dockerfile": (".dockerfile",),
    "docker": (".dockerfile",),
    "terraform": (".hcl", ".tf", ".tfvars"),
    "hcl": (".hcl", ".tf", ".tfvars"),
    "tf": (".hcl", ".tf", ".tfvars"),
    "generic": (),
    "regex": (),
}

_LANG_RE = re.compile(r"^[a-z0-9_+#.-]{1,64}\Z")
_EXT_RE = re.compile(r"^\.[a-z0-9_+-]{1,32}\Z")
_YAML_TAG_TOKEN_RE = re.compile(r"(?:^|\s)![!a-zA-Z0-9_<]")


def _strip_yaml_comment(raw: str) -> str:
    in_single = False
    in_double = False
    escaped = False
    for idx, ch in enumerate(raw):
        if escaped:
            escaped = False
            continue
        if ch == "\\" and in_double:
            escaped = True
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double:
            if idx == 0 or raw[idx - 1].isspace():
                return raw[:idx].rstrip()
    return raw.rstrip()


def _reject_yaml_tag(fragment: str) -> None:
    cleaned = fragment.strip()
    if not cleaned:
        return
    if cleaned.startswith(("'", '"')) and len(cleaned) >= 2 and cleaned[-1] == cleaned[0]:
        return
    if cleaned.startswith("!") or "!!" in cleaned or "!<" in cleaned or _YAML_TAG_TOKEN_RE.search(cleaned):
        raise ValueError("Kural paketinde desteklenmeyen veya güvensiz YAML etiketi.")


def _unquote_scalar(value: str) -> str:
    cleaned = value.strip()
    _reject_yaml_tag(cleaned)
    if len(cleaned) >= 2 and cleaned[0] == cleaned[-1] and cleaned[0] in ("'", '"'):
        inner = cleaned[1:-1]
        if cleaned[0] in inner:
            raise ValueError("Skaler değerde desteklenmeyen iç içe tırnak.")
        return inner.strip()
    return cleaned


def _parse_flow_list(raw: str) -> list[str]:
    inner = raw[1:-1].strip()
    if not inner:
        return []
    items: list[str] = []
    for part in inner.split(","):
        token = part.strip()
        if not token:
            raise ValueError("Akış listesinde boş öğe.")
        _reject_yaml_tag(token)
        scalar = _unquote_scalar(token)
        if not scalar:
            raise ValueError("Akış listesinde boş öğe.")
        items.append(scalar)
    return items


def _validate_and_normalize_rules(raw_rules: list[dict[str, object]]) -> list[dict[str, object]]:
    if not isinstance(raw_rules, list) or not raw_rules:
        raise ValueError("Semgrep kural paketi hiç kural içermiyor.")
    if len(raw_rules) > MAX_RULES:
        raise ValueError(f"Semgrep kural paketi azami {MAX_RULES} kural sınırını aşıyor.")

    validated: list[dict[str, object]] = []
    for rule in raw_rules:
        if not isinstance(rule, dict):
            raise ValueError("Her Semgrep kuralı bir eşleme olmalı.")
        rule_id = rule.get("id")
        if not isinstance(rule_id, str) or not rule_id.strip():
            raise ValueError("Her Semgrep kuralının boş olmayan bir metin 'id' alanı olmalı.")
        _reject_yaml_tag(rule_id)

        severity = rule.get("severity")
        if not isinstance(severity, str) or not severity.strip():
            raise ValueError("Her Semgrep kuralının boş olmayan bir metin 'severity' alanı olmalı.")
        sev_upper = severity.strip().upper()
        if sev_upper not in ALLOWED_SEVERITIES:
            raise ValueError("Geçersiz Semgrep kural önemi.")

        languages = rule.get("languages")
        if not isinstance(languages, list) or not languages:
            raise ValueError("Her Semgrep kuralının boş olmayan bir 'languages' listesi olmalı.")
        norm_langs: list[str] = []
        for lang in languages:
            if not isinstance(lang, str) or not lang.strip():
                raise ValueError("Her kural dili boş olmayan bir metin olmalı.")
            _reject_yaml_tag(lang)
            cleaned_lang = lang.strip().lower()
            if not _LANG_RE.fullmatch(cleaned_lang):
                raise ValueError("Semgrep kural paketinde geçersiz dil tanımlayıcısı.")
            norm_langs.append(cleaned_lang)

        validated.append({
            "id": rule_id.strip(),
            "languages": norm_langs,
            "severity": sev_upper,
        })

    return validated


def _parse_json_rulepack(text: str) -> list[dict[str, object]]:
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError("Semgrep kural paketi geçerli JSON değil.") from exc
    if not isinstance(doc, dict):
        raise ValueError("Semgrep kural paketi kökü bir nesne olmalı.")
    raw_rules = doc.get("rules")
    if not isinstance(raw_rules, list) or not raw_rules:
        raise ValueError("Semgrep kural paketi hiç kural içermiyor.")
    return _validate_and_normalize_rules(raw_rules)


def _apply_yaml_rule_key(
    current_rule: dict[str, object],
    line_content: str,
) -> str | None:
    key, sep, raw_val = line_content.partition(":")
    if not sep:
        raise ValueError("Semgrep kural paketinde bozuk kural özniteliği.")
    key = key.strip()
    if not key:
        raise ValueError("Semgrep kural paketinde boş kural öznitelik anahtarı.")
    _reject_yaml_tag(key)
    val = _strip_yaml_comment(raw_val).strip()
    _reject_yaml_tag(val)

    if key in ("id", "severity", "languages") and key in current_rule:
        raise ValueError(f"Semgrep kuralında yinelenen '{key}'.")

    if key in ("id", "severity"):
        if not val or val in ("|", ">", "|-", ">-"):
            raise ValueError(f"Kural '{key}' satır içi bir skaler metin olmalı.")
        current_rule[key] = _unquote_scalar(val)
        return None

    if key == "languages":
        if not val:
            current_rule["languages"] = []
            return "languages"
        if val.startswith("[") and val.endswith("]"):
            current_rule["languages"] = _parse_flow_list(val)
            return None
        raise ValueError("Kural 'languages' alanı metinlerden oluşan bir liste olmalı.")

    return key


def _parse_yaml_rulepack(text: str) -> list[dict[str, object]]:
    lines = text.splitlines()
    in_rules = False
    rule_item_indent: int | None = None
    rule_key_indent: int | None = None
    active_subkey: str | None = None
    current_rule: dict[str, object] | None = None
    raw_rules: list[dict[str, object]] = []

    for raw_line in lines:
        if not raw_line.strip():
            continue
        leading_len = len(raw_line) - len(raw_line.lstrip())
        if "\t" in raw_line[:leading_len]:
            raise ValueError("YAML girintisinde sekme karakterine izin verilmiyor.")

        uncommented = _strip_yaml_comment(raw_line)
        stripped = uncommented.strip()
        if not stripped:
            continue

        if stripped.startswith("%"):
            raise ValueError("Kural paketinde YAML yönergelerine izin verilmiyor.")
        if stripped.startswith("---"):
            rest = stripped[3:].strip()
            _reject_yaml_tag(rest)
            if rest:
                raise ValueError("Desteklenmeyen YAML belge başlığı.")
            continue
        if stripped == "...":
            continue

        _reject_yaml_tag(stripped)
        indent = len(uncommented) - len(uncommented.lstrip(" "))

        if not in_rules:
            if indent == 0 and (stripped == "rules:" or stripped.startswith("rules:")):
                after = stripped[len("rules:"):].strip()
                _reject_yaml_tag(after)
                if not after:
                    in_rules = True
                    continue
                if after == "[]":
                    raise ValueError("Semgrep kural paketi hiç kural içermiyor.")
                if after.startswith("["):
                    try:
                        parsed_inline = json.loads(after)
                    except json.JSONDecodeError as exc:
                        raise ValueError("Bozuk satır içi kural listesi.") from exc
                    if not isinstance(parsed_inline, list):
                        raise ValueError("'rules' alanı bir liste olmalı.")
                    return _validate_and_normalize_rules(parsed_inline)
                raise ValueError("Üst düzey 'rules' için geçersiz değer.")
            raise ValueError("Semgrep kural paketi üst düzey 'rules:' ile başlamalı.")

        # Inside rules: block
        if rule_item_indent is None:
            if not (stripped == "-" or stripped.startswith("- ")):
                raise ValueError("'rules:' altında kural listesi öğesi bekleniyordu.")
            rule_item_indent = indent

        if indent < rule_item_indent:
            raise ValueError("Semgrep kural paketinde beklenmeyen girinti.")

        if indent == rule_item_indent:
            if not (stripped == "-" or stripped.startswith("- ")):
                raise ValueError("'rules:' içinde beklenmeyen liste dışı girdi.")
            if current_rule is not None:
                raw_rules.append(current_rule)
            current_rule = {}
            active_subkey = None
            if stripped == "-":
                rule_key_indent = None
            else:
                after_dash = stripped[1:]
                dash_spaces = len(after_dash) - len(after_dash.lstrip(" "))
                rule_key_indent = indent + 1 + dash_spaces
                active_subkey = _apply_yaml_rule_key(current_rule, after_dash.strip())
            continue

        # indent > rule_item_indent
        if current_rule is None:
            raise ValueError("Semgrep kural paketinde bozuk kural girintisi.")

        if rule_key_indent is None:
            if stripped.startswith("-"):
                raise ValueError("'-' sonrasında kural eşleme anahtarı bekleniyordu.")
            rule_key_indent = indent

        if indent == rule_key_indent and not stripped.startswith("-"):
            active_subkey = _apply_yaml_rule_key(current_rule, stripped)
            continue

        if active_subkey == "languages" and indent >= rule_key_indent:
            if stripped == "-" or stripped.startswith("- "):
                item_raw = stripped[1:].strip()
                _reject_yaml_tag(item_raw)
                scalar = _unquote_scalar(item_raw)
                if not scalar:
                    raise ValueError("Kural 'languages' alanında boş dil girdisi.")
                langs = current_rule.get("languages")
                if not isinstance(langs, list):
                    raise ValueError("Geçersiz 'languages' yapısı.")
                langs.append(scalar)
                continue
            raise ValueError("'languages' kuralı altında liste öğesi bekleniyordu.")

        if indent < rule_key_indent:
            raise ValueError("Semgrep kural paketinde tutarsız kural anahtarı girintisi.")

    if current_rule is not None:
        raw_rules.append(current_rule)

    if not in_rules or not raw_rules:
        raise ValueError("Semgrep kural paketi hiç kural içermiyor.")

    return _validate_and_normalize_rules(raw_rules)


def _read_and_verify_rulepack_bytes(rules_path: Path | str) -> bytes:
    if not isinstance(rules_path, (str, Path)):
        raise ValueError("Semgrep kural yolu bir metin veya Path olmalı.")
    if isinstance(rules_path, str) and not rules_path.strip():
        raise ValueError("Semgrep kural yolu boş olmamalı.")

    candidate = Path(rules_path)
    if not candidate.is_absolute():
        raise ValueError("Semgrep kural yolu mutlak olmalı.")
    if candidate.is_symlink() or any(parent.is_symlink() for parent in candidate.parents):
        raise ValueError("Semgrep kuralları sembolik bağ olmayan normal bir dosya olmalı.")

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(str(candidate), flags)
    except OSError as exc:
        raise ValueError("Semgrep kuralları mevcut, sembolik bağ olmayan normal bir dosya olmalı.") from exc

    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ValueError("Semgrep kuralları normal bir dosya olmalı.")
        if st.st_size <= 0:
            raise ValueError("Semgrep kural paketi boş.")
        if st.st_size > MAX_RULEPACK_BYTES:
            raise ValueError("Semgrep kural paketi 524288 bayt sınırını aşıyor.")

        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_RULEPACK_BYTES:
                raise ValueError("Semgrep kural paketi 524288 bayt sınırını aşıyor.")
            chunks.append(chunk)
        raw_bytes = b"".join(chunks)
    finally:
        os.close(fd)

    if not raw_bytes:
        raise ValueError("Semgrep kural paketi boş.")
    return raw_bytes


def _normalize_target_extensions(target_extensions: list[str]) -> list[str]:
    if not isinstance(target_extensions, (list, tuple, set)):
        raise ValueError("target_extensions uzantı metinlerinden oluşan bir liste olmalı.")
    normalized: list[str] = []
    seen: set[str] = set()
    for raw_ext in target_extensions:
        if not isinstance(raw_ext, str):
            raise ValueError("Her hedef uzantısı bir metin olmalı.")
        cleaned = raw_ext.strip().lower()
        if not cleaned:
            raise ValueError("Hedef uzantısı boş olmamalı.")
        if not cleaned.startswith("."):
            cleaned = "." + cleaned
        if not _EXT_RE.fullmatch(cleaned):
            raise ValueError("Geçersiz dosya uzantısı biçimi.")
        if cleaned not in seen:
            seen.add(cleaned)
            normalized.append(cleaned)
    return normalized


def summarize_trusted_semgrep_rulepack(
    rules_path: Path | str,
    *,
    target_extensions: list[str] | None = None,
) -> dict[str, object]:
    """Validate and summarize a local trusted Semgrep rulepack without leaking paths."""
    raw_bytes = _read_and_verify_rulepack_bytes(rules_path)
    rulepack_sha256 = hashlib.sha256(raw_bytes).hexdigest()

    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Semgrep kural paketi geçerli UTF-8 olmalı.") from exc

    stripped_text = text.lstrip()
    if not stripped_text:
        raise ValueError("Semgrep kural paketi boş.")

    if stripped_text.startswith(("{", "[")):
        rules = _parse_json_rulepack(text)
    else:
        rules = _parse_yaml_rulepack(text)

    languages = sorted({lang for rule in rules for lang in rule["languages"]})

    inventory: dict[str, object] = {
        "format": INVENTORY_FORMAT,
        "rule_count": len(rules),
        "languages": languages,
        "rulepack_sha256": rulepack_sha256,
        "scope_notice": SCOPE_NOTICE,
    }

    if target_extensions is not None:
        normalized_exts = _normalize_target_extensions(target_extensions)
        supported_exts: set[str] = set()
        for lang in languages:
            supported_exts.update(LANGUAGE_EXTENSION_MAP.get(lang, ()))
        inventory["covered_extensions"] = sorted(
            ext for ext in normalized_exts if ext in supported_exts
        )
        inventory["uncovered_extensions"] = sorted(
            ext for ext in normalized_exts if ext not in supported_exts
        )

    return inventory
