from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from process_group_runner import run_in_process_group
from project_tree import ProjectTree, ProjectTreeError
from safe_file_read import read_bytes_bounded
from tool_pins import PINS, configured_binary, open_pinned
from verified_exec import VerificationError
from project_analyzer import (
    MANIFEST_NAMES,
    SKIP_DIRS,
    SOURCE_EXTENSIONS,
    ProjectRejected,
    _iter_files,
    validate_project_path,
)

ALLOWED_RULEPACK_LANGUAGES = frozenset({
    "python", "javascript", "typescript", "go", "java", "ruby", "php", "rust",
    "c", "cpp", "csharp", "kotlin", "swift", "dart", "bash", "sh", "yaml",
    "json", "dockerfile", "terraform", "html", "sql",
})

ALLOWED_RULEPACK_CATEGORIES = frozenset({
    "security", "code-execution", "command-injection", "deserialization",
    "sql-injection", "xss", "ssrf", "path-traversal", "cryptography",
    "secrets", "configuration", "authentication", "authorization",
})

# Opengrep için Sniper'ın kendi yazdığı, lisans açısından temiz kural paketi.
BUILTIN_OPENGREP_RULES = Path(__file__).resolve().parent / "rules" / "opengrep" / "sniper-core.yaml"
MAX_REPORTED_FINDINGS = 200
MAX_RULEPACK_BYTES = 10_000_000


def active_engine() -> tuple[str, str | None, str | None]:
    """Kullanılacak motoru seçer: ``(araç, ikili yolu, kural yolu)``.

    Sıra: açık ``SNIPER_OPENGREP_BINARY`` → operatörün SHA-256 ile sabitlediği
    Semgrep (``SNIPER_SEMGREP_BINARY`` + ``SNIPER_SEMGREP_SHA256``) → Sniper araç
    dizinindeki sabitli Opengrep → (sabitlenmemiş) Semgrep. Sabitlenmemiş Semgrep
    seçilirse doğrulama aşamasında reddedilir; hiçbir şey yapılandırılmamışsa
    ikili yolu ``None`` döner.
    """
    opengrep_rules = os.environ.get("SNIPER_OPENGREP_RULES") or str(BUILTIN_OPENGREP_RULES)
    if os.environ.get("SNIPER_OPENGREP_BINARY"):
        return "opengrep", configured_binary("opengrep"), opengrep_rules
    semgrep_bin = os.environ.get("SNIPER_SEMGREP_BINARY") or None
    semgrep_rules = os.environ.get("SNIPER_SEMGREP_RULES") or None
    if semgrep_bin and os.environ.get("SNIPER_SEMGREP_SHA256"):
        return "semgrep", semgrep_bin, semgrep_rules
    default_opengrep = configured_binary("opengrep")
    if default_opengrep:
        return "opengrep", default_opengrep, opengrep_rules
    return "semgrep", semgrep_bin, semgrep_rules


def _rule_index(rules_document: Any) -> dict[str, dict[str, Any]]:
    """Kural paketindeki kimlik → (mesaj şablonu, CWE, kategori) eşlemesi."""
    index: dict[str, dict[str, Any]] = {}
    rules = rules_document.get("rules", []) if isinstance(rules_document, dict) else []
    for rule in rules:
        if not isinstance(rule, dict) or not isinstance(rule.get("id"), str):
            continue
        metadata = rule.get("metadata") if isinstance(rule.get("metadata"), dict) else {}
        cwe = metadata.get("cwe")
        if isinstance(cwe, list):
            cwe = cwe[0] if cwe else None
        message = rule.get("message")
        index[rule["id"]] = {
            "message": " ".join(message.split())[:400] if isinstance(message, str) else None,
            "cwe": str(cwe)[:120] if cwe else None,
            "category": str(metadata.get("category"))[:40] if isinstance(metadata.get("category"), str) else None,
        }
    return index


def _short_rule_id(check_id: str, known_ids: Any) -> str | None:
    """Yapılandırma yolundan türetilen ön eki atar; paket dışı kimlik için ``None``."""
    for rule_id in known_ids:
        if check_id == rule_id or check_id.endswith("." + rule_id):
            return rule_id
    return None


def _project_findings(report: dict[str, Any], input_dir: Path, rule_index: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """Rapordan sınırlı bir bulgu listesi çıkarır.

    Rapordan yalnız kural kimliği, proje içi göreli yol, satır ve önem alınır. Mesaj,
    CWE ve kategori güvenilir kural paketinin kendisinden gelir: raporun mesajı
    metavariable ile kaynak kod parçası taşıyabilir, bu yüzden kullanılmaz.
    """
    findings: list[dict[str, Any]] = []
    for result in report.get("results", [])[:MAX_REPORTED_FINDINGS]:
        if not isinstance(result, dict):
            continue
        rule_id = _short_rule_id(str(result.get("check_id", "")), rule_index)
        rule = rule_index.get(rule_id or "", {})
        extra = result.get("extra") if isinstance(result.get("extra"), dict) else {}
        raw_path = str(result.get("path", ""))
        try:
            candidate = Path(raw_path)
            if not candidate.is_absolute():
                candidate = input_dir / candidate
            rel = candidate.resolve().relative_to(input_dir.resolve()).as_posix()
        except (OSError, ValueError):
            rel = Path(raw_path).name
        start = result.get("start") if isinstance(result.get("start"), dict) else {}
        line = start.get("line")
        findings.append({
            "rule_id": rule_id,
            "severity": str(extra.get("severity", ""))[:16],
            "cwe": rule.get("cwe"),
            "category": rule.get("category"),
            "path": rel[:512],
            "line": line if isinstance(line, int) and not isinstance(line, bool) else None,
            "message": rule.get("message"),
        })
    return findings


_YAML_TAG_RE = re.compile(r"(?:^|\s)![!a-zA-Z0-9_<]")
_BLOCK_SCALAR_HEADERS = frozenset({"|", "|-", "|+", ">", ">-", ">+"})


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


def _check_no_yaml_tags(fragment: str) -> None:
    cleaned = fragment.strip()
    if not cleaned:
        return
    if len(cleaned) >= 2 and cleaned[0] == cleaned[-1] and cleaned[0] in ("'", '"'):
        return
    if cleaned.startswith("!") or "!!" in cleaned or "!<" in cleaned or _YAML_TAG_RE.search(cleaned):
        raise RuntimeError("Semgrep kuralları geçerli YAML değil.")


def _unquote_yaml_scalar(raw: str) -> str:
    cleaned = raw.strip()
    _check_no_yaml_tags(cleaned)
    if len(cleaned) >= 2 and cleaned[0] == cleaned[-1] and cleaned[0] in ("'", '"'):
        return cleaned[1:-1]
    return cleaned


def _split_top_level_commas(text: str) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    depth_bracket = 0
    depth_brace = 0
    in_single = False
    in_double = False
    for ch in text:
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif not in_single and not in_double:
            if ch == "[":
                depth_bracket += 1
            elif ch == "]":
                depth_bracket -= 1
            elif ch == "{":
                depth_brace += 1
            elif ch == "}":
                depth_brace -= 1
            elif ch == "," and depth_bracket == 0 and depth_brace == 0:
                parts.append("".join(current).strip())
                current = []
                continue
        current.append(ch)
    if depth_bracket != 0 or depth_brace != 0 or in_single or in_double:
        raise RuntimeError("Semgrep kuralları geçerli YAML değil.")
    tail = "".join(current).strip()
    if tail:
        parts.append(tail)
    return parts


def _parse_yaml_flow_list(raw: str) -> list[Any]:
    cleaned = raw.strip()
    if not (cleaned.startswith("[") and cleaned.endswith("]")):
        raise RuntimeError("Semgrep kuralları geçerli YAML değil.")
    inner = cleaned[1:-1].strip()
    if not inner:
        return []
    items: list[Any] = []
    for token in _split_top_level_commas(inner):
        if not token:
            raise RuntimeError("Semgrep kuralları geçerli YAML değil.")
        _check_no_yaml_tags(token)
        items.append(_unquote_yaml_scalar(token))
    return items


def _parse_yaml_flow_mapping(raw: str) -> dict[str, Any]:
    cleaned = raw.strip()
    if not (cleaned.startswith("{") and cleaned.endswith("}")):
        raise RuntimeError("Semgrep kuralları geçerli YAML değil.")
    inner = cleaned[1:-1].strip()
    if not inner:
        return {}
    mapping: dict[str, Any] = {}
    for pair in _split_top_level_commas(inner):
        key_raw, sep, val_raw = pair.partition(":")
        if not sep:
            raise RuntimeError("Semgrep kuralları geçerli YAML değil.")
        key = _unquote_yaml_scalar(key_raw.strip())
        val = val_raw.strip()
        if not key or not val:
            raise RuntimeError("Semgrep kuralları geçerli YAML değil.")
        _check_no_yaml_tags(val)
        if val.startswith("["):
            mapping[key] = _parse_yaml_flow_list(val)
        elif val.startswith("{"):
            mapping[key] = _parse_yaml_flow_mapping(val)
        else:
            mapping[key] = _unquote_yaml_scalar(val)
    return mapping


def _parse_yaml_value(raw_val: str) -> Any:
    val = raw_val.strip()
    _check_no_yaml_tags(val)
    if val.startswith("["):
        return _parse_yaml_flow_list(val)
    if val.startswith("{"):
        return _parse_yaml_flow_mapping(val)
    return _unquote_yaml_scalar(val)


def _parse_rulepack_fallback(raw_text: str) -> Any:
    stripped_all = raw_text.strip()
    if not stripped_all:
        return None
    if stripped_all.startswith("{"):
        try:
            return json.loads(stripped_all)
        except json.JSONDecodeError as exc:
            raise RuntimeError("Semgrep kuralları geçerli YAML değil.") from exc

    lines = raw_text.splitlines()
    in_rules = False
    rule_item_indent: int | None = None
    rule_key_indent: int | None = None
    block_scalar_indent: int | None = None
    active_subkey: str | None = None
    metadata_key_indent: int | None = None
    active_metadata_list_key: str | None = None
    current_rule: dict[str, Any] | None = None
    rules: list[dict[str, Any]] = []

    for raw_line in lines:
        if block_scalar_indent is not None:
            if not raw_line.strip():
                continue
            line_indent = len(raw_line) - len(raw_line.lstrip(" "))
            if line_indent > block_scalar_indent:
                continue
            block_scalar_indent = None

        if not raw_line.strip():
            continue
        leading = len(raw_line) - len(raw_line.lstrip())
        if "\t" in raw_line[:leading]:
            raise RuntimeError("Semgrep kuralları geçerli YAML değil.")

        uncommented = _strip_yaml_comment(raw_line)
        stripped = uncommented.strip()
        if not stripped:
            continue
        if stripped.startswith("%"):
            raise RuntimeError("Semgrep kuralları geçerli YAML değil.")
        if stripped.startswith("---"):
            rest = stripped[3:].strip()
            _check_no_yaml_tags(rest)
            if rest:
                raise RuntimeError("Semgrep kuralları geçerli YAML değil.")
            continue
        if stripped == "...":
            continue

        _check_no_yaml_tags(stripped)
        indent = len(uncommented) - len(uncommented.lstrip(" "))

        if not in_rules:
            if indent == 0 and (stripped == "rules:" or stripped.startswith("rules:")):
                after = stripped[len("rules:"):].strip()
                _check_no_yaml_tags(after)
                if not after:
                    in_rules = True
                    continue
                if after == "[]":
                    return {"rules": []}
                if after.startswith("["):
                    return {"rules": _parse_yaml_flow_list(after)}
                raise RuntimeError("Semgrep kurallarının yapısı geçersiz.")
            raise RuntimeError("Semgrep kurallarının yapısı geçersiz.")

        if rule_item_indent is None:
            if not (stripped == "-" or stripped.startswith("- ")):
                raise RuntimeError("Semgrep kurallarının yapısı geçersiz.")
            rule_item_indent = indent

        if indent < rule_item_indent:
            raise RuntimeError("Semgrep kurallarının yapısı geçersiz.")

        if indent == rule_item_indent:
            if not (stripped == "-" or stripped.startswith("- ")):
                raise RuntimeError("Semgrep kurallarının yapısı geçersiz.")
            if current_rule is not None:
                rules.append(current_rule)
            current_rule = {}
            active_subkey = None
            metadata_key_indent = None
            active_metadata_list_key = None
            if stripped == "-":
                rule_key_indent = None
            else:
                after_dash = stripped[1:]
                dash_spaces = len(after_dash) - len(after_dash.lstrip(" "))
                rule_key_indent = indent + 1 + dash_spaces
                k, sep, v_raw = after_dash.strip().partition(":")
                if not sep:
                    raise RuntimeError("Semgrep kuralları geçerli YAML değil.")
                k = k.strip()
                v = _strip_yaml_comment(v_raw).strip()
                _check_no_yaml_tags(v)
                if v in _BLOCK_SCALAR_HEADERS:
                    current_rule[k] = ""
                    block_scalar_indent = rule_key_indent
                elif not v:
                    current_rule[k] = {} if k == "metadata" else []
                    active_subkey = k
                else:
                    current_rule[k] = _parse_yaml_value(v)
            continue

        if current_rule is None:
            raise RuntimeError("Semgrep kurallarının yapısı geçersiz.")

        if rule_key_indent is None:
            if stripped.startswith("-"):
                raise RuntimeError("Semgrep kurallarının yapısı geçersiz.")
            rule_key_indent = indent

        if indent == rule_key_indent and not stripped.startswith("-"):
            active_subkey = None
            metadata_key_indent = None
            active_metadata_list_key = None
            k, sep, v_raw = stripped.partition(":")
            if not sep:
                raise RuntimeError("Semgrep kuralları geçerli YAML değil.")
            k = k.strip()
            v = _strip_yaml_comment(v_raw).strip()
            _check_no_yaml_tags(v)
            if k in ("id", "languages", "metadata") and k in current_rule:
                raise RuntimeError("Semgrep kurallarının yapısı geçersiz.")
            if v in _BLOCK_SCALAR_HEADERS:
                current_rule[k] = ""
                block_scalar_indent = rule_key_indent
            elif not v:
                current_rule[k] = {} if k == "metadata" else []
                active_subkey = k
            else:
                current_rule[k] = _parse_yaml_value(v)
            continue

        if active_subkey == "languages" and indent >= rule_key_indent:
            if stripped == "-" or stripped.startswith("- "):
                item_val = _unquote_yaml_scalar(stripped[1:].strip())
                current_rule.setdefault("languages", []).append(item_val)
                continue
            raise RuntimeError("Semgrep kurallarının yapısı geçersiz.")

        if active_subkey == "metadata" and indent > rule_key_indent:
            meta_obj = current_rule.get("metadata")
            if not isinstance(meta_obj, dict):
                raise RuntimeError("Semgrep kurallarının yapısı geçersiz.")
            if metadata_key_indent is None:
                if stripped.startswith("-"):
                    raise RuntimeError("Semgrep kurallarının yapısı geçersiz.")
                metadata_key_indent = indent
            if indent == metadata_key_indent and not stripped.startswith("-"):
                mk, sep, mv_raw = stripped.partition(":")
                if not sep:
                    raise RuntimeError("Semgrep kuralları geçerli YAML değil.")
                mk = mk.strip()
                mv = _strip_yaml_comment(mv_raw).strip()
                _check_no_yaml_tags(mv)
                if mv in _BLOCK_SCALAR_HEADERS:
                    meta_obj[mk] = ""
                    block_scalar_indent = metadata_key_indent
                    active_metadata_list_key = None
                elif not mv:
                    meta_obj[mk] = []
                    active_metadata_list_key = mk
                else:
                    meta_obj[mk] = _parse_yaml_value(mv)
                    active_metadata_list_key = None
                continue
            if active_metadata_list_key and indent >= metadata_key_indent and (stripped == "-" or stripped.startswith("- ")):
                meta_obj[active_metadata_list_key].append(_unquote_yaml_scalar(stripped[1:].strip()))
                continue
            raise RuntimeError("Semgrep kurallarının yapısı geçersiz.")

    if current_rule is not None:
        rules.append(current_rule)

    if not in_rules:
        raise RuntimeError("Semgrep kurallarının yapısı geçersiz.")
    return {"rules": rules}


def _load_rulepack_document(raw_text: str) -> Any:
    try:
        import yaml  # type: ignore[import-not-found]
    except ImportError:
        return _parse_rulepack_fallback(raw_text)
    try:
        return yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        raise RuntimeError("Semgrep kuralları geçerli YAML değil.") from exc


def _read_rulepack_bytes(rules_path: Path) -> bytes:
    raw_bytes = read_bytes_bounded(rules_path, MAX_RULEPACK_BYTES)
    if raw_bytes is None:
        raise RuntimeError("Semgrep kuralları normal ve sınırlı bir dosya olmalı.")
    return raw_bytes


def _extract_rulepack_coverage_metadata_from_bytes(raw_bytes: bytes) -> dict[str, Any]:
    rulepack_sha256 = hashlib.sha256(raw_bytes).hexdigest()
    try:
        raw_text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RuntimeError("Semgrep kuralları geçerli UTF-8 olmalı.") from exc

    # The host Semgrep profile uses YAML rules. Parse rule objects instead of
    # searching text: a message block may contain valid-looking YAML fragments.
    document = _load_rulepack_document(raw_text)
    if not isinstance(document, dict) or set(document) != {"rules"}:
        raise RuntimeError("Semgrep kurallarının yapısı geçersiz.")
    rules = document["rules"]
    if not isinstance(rules, list) or len(rules) > 10_000:
        raise RuntimeError("Semgrep kurallarının yapısı geçersiz.")

    languages: set[str] = set()
    categories: set[str] = set()
    seen_ids: set[str] = set()
    for rule in rules:
        if not isinstance(rule, dict):
            raise RuntimeError("Semgrep kurallarının yapısı geçersiz.")
        rule_id = rule.get("id")
        rule_languages = rule.get("languages")
        if (not isinstance(rule_id, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,256}", rule_id)
                or rule_id in seen_ids or not isinstance(rule_languages, list)
                or not rule_languages or any(
                    not isinstance(language, str) or language not in ALLOWED_RULEPACK_LANGUAGES
                    for language in rule_languages
                )):
            raise RuntimeError("Semgrep kurallarının yapısı geçersiz.")
        seen_ids.add(rule_id)
        languages.update(rule_languages)

        metadata = rule.get("metadata", {})
        if not isinstance(metadata, dict):
            raise RuntimeError("Semgrep kurallarının yapısı geçersiz.")
        explicit_category = metadata.get("category")
        if explicit_category is not None:
            declared = [explicit_category] if isinstance(explicit_category, str) else explicit_category
            if not isinstance(declared, list) or any(not isinstance(c, str) for c in declared):
                raise RuntimeError("Semgrep kurallarının yapısı geçersiz.")
            categories.update(c.casefold() for c in declared if c.casefold() in ALLOWED_RULEPACK_CATEGORIES)

        # The trusted pack also uses descriptive IDs without metadata.category.
        # Infer only from the parsed ID, never message or pattern text.
        id_tokens = set(re.findall(r"[a-z0-9]+", rule_id.casefold()))
        normalized_id = "-" + "-".join(re.findall(r"[a-z0-9]+", rule_id.casefold())) + "-"
        categories.update(category for category in ALLOWED_RULEPACK_CATEGORIES
                          if "-" + category + "-" in normalized_id)
        if "eval" in id_tokens or "exec" in id_tokens:
            categories.add("code-execution")
        if "subprocess" in id_tokens or "shell" in id_tokens or {"os", "system"} <= id_tokens:
            categories.add("command-injection")
        if "pickle" in id_tokens or {"yaml", "load"} <= id_tokens:
            categories.add("deserialization")

    return {
        "profile_id": "local-trusted-rules-v1",
        "rulepack_sha256": rulepack_sha256,
        "rule_count": len(rules),
        "languages": sorted(languages),
        "categories": sorted(c for c in categories if c in ALLOWED_RULEPACK_CATEGORIES),
        "remote_rules_fetched": False,
    }


def _extract_rulepack_coverage_metadata(rules_path: Path) -> dict[str, Any]:
    return _extract_rulepack_coverage_metadata_from_bytes(_read_rulepack_bytes(rules_path))


def _count_skipped_breakdown(src_root: Path | ProjectTree, secret_env_files: int) -> dict[str, int]:
    """Count non-staged entries without reopening a validated project pathname.

    When staging has yielded at least one project entry, callers pass a duplicate
    of that same descriptor-pinned tree.  The Path form remains for the public
    helper contract and opens its own no-follow tree.
    """
    excluded_directories = 0
    unsupported_or_binary_files = 0
    tree = src_root.duplicate() if isinstance(src_root, ProjectTree) else ProjectTree(src_root)
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    stack: list[int] = []
    try:
        with tree:
            stack.append(os.dup(tree.fileno()))
            seen = 0
            while stack:
                directory_fd = stack.pop()
                try:
                    with os.scandir(directory_fd) as entries:
                        ordered = sorted(entries, key=lambda entry: entry.name)
                    for entry in ordered:
                        seen += 1
                        if seen > 1_000_000:
                            raise ProjectTreeError("Semgrep kapsam sayımı girdi sınırını aşıyor.")
                        try:
                            info = entry.stat(follow_symlinks=False)
                        except OSError as exc:
                            raise ProjectTreeError("Semgrep kapsam girdisi değişti.") from exc
                        name = entry.name
                        normalized = name.casefold()
                        if stat.S_ISLNK(info.st_mode):
                            try:
                                points_to_directory = entry.is_dir(follow_symlinks=True)
                            except OSError:
                                points_to_directory = False
                            if points_to_directory:
                                excluded_directories += 1
                            else:
                                unsupported_or_binary_files += 1
                            continue
                        if stat.S_ISDIR(info.st_mode):
                            if normalized in SKIP_DIRS:
                                excluded_directories += 1
                                continue
                            child_fd: int | None = None
                            try:
                                child_fd = os.open(name, directory_flags, dir_fd=directory_fd)
                                opened = os.fstat(child_fd)
                            except OSError as exc:
                                if child_fd is not None:
                                    os.close(child_fd)
                                raise ProjectTreeError("Semgrep kapsam dizini değişti.") from exc
                            if not stat.S_ISDIR(opened.st_mode) or (
                                opened.st_dev,
                                opened.st_ino,
                            ) != (info.st_dev, info.st_ino):
                                os.close(child_fd)
                                raise ProjectTreeError("Semgrep kapsam dizini değişti.")
                            stack.append(child_fd)
                            continue
                        if not stat.S_ISREG(info.st_mode):
                            unsupported_or_binary_files += 1
                            continue
                        if normalized == ".env" or normalized.startswith(".env."):
                            continue
                        if Path(name).suffix.casefold() not in SOURCE_EXTENSIONS and normalized not in MANIFEST_NAMES:
                            unsupported_or_binary_files += 1
                finally:
                    os.close(directory_fd)
    finally:
        for directory_fd in stack:
            os.close(directory_fd)
    return {
        "secret_env_files": secret_env_files,
        "excluded_directories": excluded_directories,
        "unsupported_or_binary_files": unsupported_or_binary_files,
    }


def extract_semgrep_engine_error_count(report: dict[str, Any]) -> int:
    """Return bounded non-sensitive engine error count from a Semgrep JSON report (Task94)."""
    if not isinstance(report, dict):
        raise ValueError("report bir JSON nesnesi olmalı")
    errors = report.get("errors")
    if not isinstance(errors, list):
        raise ValueError("'errors' alanı bir dizi olmalı")
    return len(errors)


def summarize_semgrep_report_with_engine_errors(report: dict[str, Any]) -> dict[str, Any]:
    """Summarize saved Semgrep native JSON report including aggregate engine_error_count (Task94)."""
    from tool_report_semgrep import parse_semgrep_native_json_summary

    base = parse_semgrep_native_json_summary(report)
    return {
        "format": base["format"],
        "result_count": base["result_count"],
        "engine_error_count": extract_semgrep_engine_error_count(report),
        "severity_counts": base["severity_counts"],
        "report_sha256": base["report_sha256"],
    }


def is_semgrep_engagement_eligible(engagement: dict[str, Any] | None) -> bool:
    """Verify engagement eligibility for local Semgrep evidence linking even when scope_notes is empty (Task112)."""
    if not isinstance(engagement, dict):
        return False
    if engagement.get("status") != "active":
        return False
    eng_id = engagement.get("id")
    if not isinstance(eng_id, str) or not eng_id.strip():
        return False
    auth_ref = engagement.get("authorization_ref")
    if not isinstance(auth_ref, str) or not auth_ref.strip():
        return False
    approvals = engagement.get("special_approvals")
    if not isinstance(approvals, dict) or approvals.get("redacted_data_proof") is not True:
        return False
    return True


def prepare_semgrep_evidence_link_summary(summary: dict[str, Any]) -> dict[str, Any]:
    """Project a local Semgrep scan summary to the fixed 5-key aggregate accepted by Store.add_semgrep_tool_evidence."""
    if not isinstance(summary, dict):
        raise ValueError("Semgrep özeti bir sözlük olmalı.")
    required = ("format", "profile", "result_count", "severity_counts", "report_sha256")
    for key in required:
        if key not in summary:
            raise ValueError(f"Gerekli Semgrep özet alanı eksik: {key}")
    return {key: summary[key] for key in required}


def _custom_opengrep_rules() -> str | None:
    """Onaylı özel kurallardan derlenmiş Opengrep paketi (yoksa/güvensizse None)."""
    try:
        import taint_rules_dsl

        path = taint_rules_dsl.rules_dir() / "compiled" / "opengrep-custom.yaml"
    except Exception:
        return None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022 or info.st_size > 2_000_000:
            return None
        text = os.read(fd, info.st_size + 1).decode("utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    finally:
        os.close(fd)
    return text if text.strip() else None


def run_local_semgrep(project_path: str) -> dict[str, Any]:
    # Validate project path
    src_root = validate_project_path(project_path)

    # Acquire persistent lock in SNIPER_DATA_DIR
    data_dir = os.environ.get("SNIPER_DATA_DIR")
    if not data_dir:
        raise RuntimeError("SNIPER_DATA_DIR ortam değişkeni tanımlı değil.")
    lock_path = Path(data_dir).resolve() / "semgrep.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)

    lock_fd = None
    try:
        # Open with O_NOFOLLOW, O_CREAT, O_RDWR
        lock_fd = os.open(str(lock_path), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            st = os.fstat(lock_fd)
            if not stat.S_ISREG(st.st_mode):
                raise RuntimeError("Kilit dosyası normal bir dosya değil.")
        except OSError:
            os.close(lock_fd)
            raise RuntimeError("Kilit dosyası doğrulanamadı.")

        # Try to acquire exclusive non-blocking lock
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as e:
            if e.errno == 11:  # EAGAIN
                raise RuntimeError("Başka bir Semgrep taraması sürüyor.")
            raise RuntimeError("Başka bir Semgrep taraması sürüyor.")

    except Exception as e:
        if lock_fd is not None:
            os.close(lock_fd)
        raise RuntimeError("Başka bir Semgrep taraması sürüyor.")

    try:
        # Motor seçimi: sabitli Opengrep veya operatörün sabitlediği Semgrep.
        engine, engine_bin, semgrep_rules = active_engine()
        if not engine_bin:
            raise RuntimeError("Semgrep/Opengrep ikilisi yapılandırılmamış.")
        if not semgrep_rules:
            raise RuntimeError("Semgrep kuralları yapılandırılmamış.")
        rules_path = Path(semgrep_rules)
        if not rules_path.is_absolute():
            raise RuntimeError("Semgrep kural yolu mutlak olmalı.")
        rules_bytes = _read_rulepack_bytes(rules_path)
        try:
            rules_text = rules_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise RuntimeError("Semgrep kuralları geçerli UTF-8 olmalı.") from exc
        rulepack_meta = _extract_rulepack_coverage_metadata_from_bytes(rules_bytes)
        try:
            verified = open_pinned(engine, engine_bin)
        except VerificationError as exc:
            raise RuntimeError(str(exc)) from exc

        # Use system temp dir (PrivateTmp makes it service-private)
        with verified, tempfile.TemporaryDirectory(prefix="sniper_semgrep_") as tmpdir:
            snapshot_root = Path(tmpdir)
            input_dir = snapshot_root / "input"
            input_dir.mkdir(parents=True, exist_ok=True)
            rule_dir = snapshot_root / "rules"
            rule_dir.mkdir(mode=0o700)
            staged_rules_path = rule_dir / rules_path.name
            staged_rules_path.write_bytes(rules_bytes)

            staged_file_count = 0
            secret_env_files = 0
            project_snapshot: ProjectTree | None = None
            try:
                # Upstream iterator decodes through one pinned tree. Retain a
                # duplicate while calculating coverage so the project pathname
                # is never reopened after staging.
                try:
                    for path, text, kind, project_tree in _iter_files(src_root):
                        if project_snapshot is None:
                            project_snapshot = project_tree.duplicate()
                        if kind == "secret_file":
                            secret_env_files += 1
                            continue
                        rel = path.relative_to(src_root)
                        dest = input_dir / rel
                        dest.parent.mkdir(parents=True, exist_ok=True)
                        if text is not None:
                            dest.write_text(text, encoding="utf-8")
                            staged_file_count += 1
                except ProjectRejected as exc:
                    raise RuntimeError(str(exc)) from exc
                try:
                    skipped_counts = _count_skipped_breakdown(
                        project_snapshot if project_snapshot is not None else src_root,
                        secret_env_files,
                    )
                except ProjectTreeError as exc:
                    raise RuntimeError("Semgrep proje kapsamı tarama sırasında değişti.") from exc
            finally:
                if project_snapshot is not None:
                    project_snapshot.close()

            # Prepare output report file as sibling of input/
            report_file = snapshot_root / "report.json"

            # Build argument vector
            if engine == "opengrep":
                # Kural kimliklerine yerel yol ön eki eklenmesin diye kural dizininde
                # çalıştırılır ve yapılandırma dosya adıyla verilir.
                cmd = [
                    verified.argv0,
                    "scan",
                    str(input_dir),
                    "--config",
                    staged_rules_path.name,
                    "--json",
                    "--quiet",
                    "--disable-version-check",
                    "--no-git-ignore",
                    "--taint-intrafile",
                    "--jobs",
                    "2",
                    "--timeout",
                    "10",
                    "--output",
                    str(report_file),
                ]
                run_cwd: str | None = str(rule_dir)
                custom_text = _custom_opengrep_rules()
                if custom_text:
                    # İşletmecinin onaylı özel kuralları (taint_rules_dsl): sabitli paketle birlikte,
                    # kural kimlikleri yol öneki almasın diye ikisi de geçici kural dizininden verilir.
                    (rule_dir / "sniper-custom.yaml").write_text(custom_text, encoding="utf-8")
                    cmd[cmd.index("--json"):cmd.index("--json")] = ["--config", "sniper-custom.yaml"]
                    run_cwd = str(rule_dir)
            else:
                cmd = [
                    verified.argv0,
                    str(input_dir),
                    "--config",
                    str(staged_rules_path),
                    "--json",
                    "--quiet",
                    "--metrics",
                    "off",
                    "--disable-version-check",
                    "--no-git-ignore",
                    "--output",
                    str(report_file),
                ]
                run_cwd = None

            env = os.environ.copy()
            env["SEMGREP_SEND_METRICS"] = "off"
            # Set Semgrep HOME and XDG_CACHE_HOME inside scratch to avoid home writes
            env["HOME"] = str(snapshot_root / ".semgrep_home")
            env["XDG_CACHE_HOME"] = str(snapshot_root / ".semgrep_cache")
            (snapshot_root / ".semgrep_home").mkdir(exist_ok=True)
            (snapshot_root / ".semgrep_cache").mkdir(exist_ok=True)
            if engine == "opengrep":
                # Kural paketi UTF-8 (Türkçe iletiler); Opengrep yapılandırmayı yerel
                # ayarın kodlamasıyla okur, servis ortamında LANG olmayabilir.
                env["LC_ALL"] = "C.UTF-8"
                env["PYTHONUTF8"] = "1"

            # Run bounded runner
            try:
                popen_kwargs = verified.popen_kwargs(
                    env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if run_cwd is not None:
                    popen_kwargs["cwd"] = run_cwd
                proc = run_in_process_group(cmd, timeout=90, check=False, **popen_kwargs)
            except subprocess.TimeoutExpired:
                raise RuntimeError("Semgrep çalıştırması zaman aşımına uğradı.")
            except OSError:
                raise RuntimeError("Semgrep çalıştırması başarısız oldu.")

            if proc.returncode != 0:
                raise RuntimeError("Semgrep çalıştırması başarısız oldu.")

            # Enforce 2 MB report cap and existence
            if not report_file.is_file() or report_file.is_symlink():
                raise RuntimeError("Semgrep rapor dosyası üretmedi.")
            if report_file.stat().st_size > 2_000_000:
                raise RuntimeError("Semgrep raporu 2 MB sınırını aşıyor.")

            # Load and parse report
            try:
                raw = report_file.read_text(encoding="utf-8")
                report = json.loads(raw)
            except (json.JSONDecodeError, UnicodeDecodeError):
                raise RuntimeError("Semgrep raporu geçerli JSON değil.")

            # Validate required top-level fields
            if not isinstance(report, dict):
                raise RuntimeError("Semgrep raporu geçerli JSON değil.")
            if not isinstance(report.get("results"), list):
                raise RuntimeError("Semgrep raporu geçerli JSON değil.")
            if not isinstance(report.get("errors"), list):
                raise RuntimeError("Semgrep raporu geçerli JSON değil.")
            if report["errors"]:
                raise RuntimeError("Semgrep raporu hata içeriyor.")

            # Reuse existing parser
            from tool_report_semgrep import parse_semgrep_native_json_summary
            try:
                summary = parse_semgrep_native_json_summary(report)
            except ValueError as e:
                raise RuntimeError("Semgrep raporu geçerli JSON değil.") from e

            scanned_paths = report.get("paths", {}).get("scanned", []) if isinstance(report.get("paths"), dict) else []
            semgrep_scanned_count = len(scanned_paths) if isinstance(scanned_paths, list) else 0

            # Add profile and rulepack coverage summary
            summary["profile"] = "local-trusted-rules-v1"
            summary["engine"] = {
                "tool": engine,
                "version": PINS[engine].version,
                "binary_sha256": verified.sha256,
                "provenance": verified.provenance,
            }
            rule_index = _rule_index(_load_rulepack_document(rules_text))
            if engine == "opengrep" and custom_text:
                rule_index.update(_rule_index(_load_rulepack_document(custom_text)))
                summary["custom_rule_count"] = len(_rule_index(_load_rulepack_document(custom_text)))
            summary["findings"] = _project_findings(report, input_dir, rule_index)
            summary["findings_truncated"] = len(report["results"]) > MAX_REPORTED_FINDINGS
            summary["rulepack_coverage"] = {
                **rulepack_meta,
                "staged_file_count": staged_file_count,
                "semgrep_scanned_count": semgrep_scanned_count,
                "skipped_counts": skipped_counts,
            }

            return summary

    finally:
        if lock_fd is not None:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)
