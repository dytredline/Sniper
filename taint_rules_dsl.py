"""Kullanıcı (işletmeci) tanımlı taint kuralları: okunabilir YAML/JSON → sniper-taint-models-v1.

Kural dosyası yalnız veridir; kod çalıştırılmaz. Taranan proje kural getiremez: kurallar yalnız
işletmeci veri dizinine (``$SNIPER_DATA_DIR/custom-rules/``, 0700) onaylı API ile yazılır.

Biçim (``format: sniper-taint-rules-v1``)::

    format: sniper-taint-rules-v1
    name: sirket-veri-katmani          # [a-z0-9_-], en çok 64
    language: python                   # python | javascript
    description: Şirket içi sorgu yardımcıları
    sources:                           # (motor kancası gerekir; bkz. RAPOR)
      - calls: [sirket.http.girdi]     # çağrı sonucu kaynak
        label: request                 # request | pii | stored
    sinks:
      - kind: sql                      # taint_models.KNOWN_KINDS
        calls: [sirket.db.ham_sorgu, "*.raw_sql"]
        args: [0]
        keywords: [sorgu]
        cwe: CWE-89
        severity: high
    sanitizers:
      - calls: [sirket.db.kacis]
        kinds: [sql]
    propagators: [sirket.metin.birlestir]

Derleme çıktısı ``compiled/<dil>-custom.json`` (taint_models biçimi) ve isteğe bağlı
``compiled/opengrep-custom.yaml`` (Opengrep taint kuralları; JSON, YAML'ın alt kümesidir).
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any, Callable

import taint_models

RULES_FORMAT = "sniper-taint-rules-v1"
LANGUAGES = ("python", "javascript")
SOURCE_LABELS = frozenset({"request", "pii", "stored"})
SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})
MAX_RULE_BYTES = 64_000
MAX_RULES = 50
MAX_ENTRIES_PER_RULE = 500
MAX_NAMES_PER_ENTRY = 100
TRY_TIMEOUT_SECONDS = 30
MAX_TRY_CODE_BYTES = 200_000
_NAME_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}\Z")
_CWE_RE = re.compile(r"CWE-\d{1,5}\Z")
_DEFAULT_KIND_CWES: dict[str, str] = {
    "sql": "CWE-89", "nosql": "CWE-943", "nosql_expr": "CWE-943",
    "command": "CWE-78", "eval": "CWE-95", "code": "CWE-94", "ssti": "CWE-1336",
    "html": "CWE-79", "path": "CWE-22", "ssrf": "CWE-918",
    "deserialize": "CWE-502", "redirect": "CWE-601", "ldap": "CWE-90",
    "xpath": "CWE-643", "xxe": "CWE-611", "session": "CWE-501",
    "cookie": "CWE-614", "log": "CWE-117", "regex": "CWE-1333",
    "header": "CWE-113", "format": "CWE-134", "format_string": "CWE-134",
    "prototype": "CWE-1321", "mass_assign": "CWE-915",
    "memory": "CWE-120", "memory_len": "CWE-805", "memory_index": "CWE-129",
}
_TOP_KEYS = {"format", "name", "language", "description", "sources", "sinks", "sanitizers", "propagators"}

APP_DIR = Path(__file__).resolve().parent


class RuleError(ValueError):
    """Kural doğrulanamadı (Türkçe, kullanıcıya gösterilir)."""


# ---------------------------------------------------------------------------
# Ayrıştırma ve doğrulama
# ---------------------------------------------------------------------------


def parse_rule_text(text: str) -> dict[str, Any]:
    if not isinstance(text, str) or not text.strip():
        raise RuleError("Kural içeriği boş olamaz.")
    if len(text.encode("utf-8")) > MAX_RULE_BYTES:
        raise RuleError(f"Kural en çok {MAX_RULE_BYTES} bayt olabilir.")
    stripped = text.lstrip()
    try:
        if stripped.startswith("{"):
            data = json.loads(text)
        else:
            try:
                import yaml  # type: ignore[import-untyped]
            except ImportError as exc:  # pragma: no cover - sistem Python'unda PyYAML var
                raise RuleError("YAML desteği yok; kuralı JSON olarak verin.") from exc
            data = yaml.safe_load(text)
    except RuleError:
        raise
    except Exception as exc:  # yaml.YAMLError / json.JSONDecodeError
        raise RuleError(f"Kural ayrıştırılamadı: {type(exc).__name__}.") from exc
    if not isinstance(data, dict):
        raise RuleError("Kural bir nesne (eşleme) olmalı.")
    return data


def _name_segment(value: str, *, calls: bool) -> bool:
    if calls and value.endswith("()"):
        value = value[:-2]
    if not value or "(" in value or ")" in value:
        return False
    if not (value[0] in "_$" or value[0].isascii() and value[0].isalpha()):
        return False
    return all(character in "_$" or character.isalnum() for character in value[1:])


def _call_name(value: str) -> bool:
    if value.startswith("*."):
        value = value[2:]
    return bool(value) and all(_name_segment(segment, calls=True) for segment in value.split("."))


def _propagator_name(value: str) -> bool:
    if value.endswith(".*"):
        value = value[:-2]
    return bool(value) and all(_name_segment(segment, calls=False) for segment in value.split("."))


def _keyword_name(value: str) -> bool:
    return bool(value) and (value[0] == "_" or value[0].isascii() and value[0].isalpha()) \
        and all(character == "_" or character.isalnum() for character in value[1:])


def _string_list(value: Any, label: str, *, validator: Callable[[str], bool] | None = None,
                 limit: int = MAX_NAMES_PER_ENTRY) -> list[str]:
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list) or not value:
        raise RuleError(f"{label} boş olmayan bir metin listesi olmalı.")
    if len(value) > limit:
        raise RuleError(f"{label} en çok {limit} öğe içerebilir.")
    out: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip() or len(item) > 200:
            raise RuleError(f"{label} içinde geçersiz öğe.")
        item = item.strip()
        if validator is not None and not validator(item):
            raise RuleError(f"{label}: geçersiz çağrı adı {item!r} (ör. modul.fonksiyon veya *.metot).")
        out.append(item)
    return out


def _only_keys(entry: dict[str, Any], allowed: set[str], label: str) -> None:
    unknown = set(entry) - allowed
    if unknown:
        raise RuleError(f"{label}: bilinmeyen alan(lar): {', '.join(sorted(unknown))}.")


def validate_rule(data: dict[str, Any]) -> dict[str, Any]:
    """Kuralı doğrular ve normalize edilmiş biçimini döndürür."""
    _only_keys(data, _TOP_KEYS, "Kural")
    if data.get("format", RULES_FORMAT) != RULES_FORMAT:
        raise RuleError(f"format '{RULES_FORMAT}' olmalı.")
    name = data.get("name")
    if not isinstance(name, str) or not _NAME_RE.fullmatch(name):
        raise RuleError("name küçük harf, rakam, '-' veya '_' içermeli (en çok 64 karakter).")
    language = data.get("language")
    if language not in LANGUAGES:
        raise RuleError("language 'python' veya 'javascript' olmalı.")
    description = data.get("description", "")
    if not isinstance(description, str) or len(description) > 500:
        raise RuleError("description en çok 500 karakterlik bir metin olmalı.")
    rule: dict[str, Any] = {
        "format": RULES_FORMAT, "name": name, "language": language, "description": description.strip(),
        "sources": [], "sinks": [], "sanitizers": [], "propagators": [],
    }
    entries = 0
    for raw in data.get("sources") or []:
        if not isinstance(raw, dict):
            raise RuleError("sources öğeleri nesne olmalı.")
        _only_keys(raw, {"calls", "attributes", "label"}, "sources")
        label = raw.get("label", "request")
        if label not in SOURCE_LABELS:
            raise RuleError("sources.label 'request', 'pii' veya 'stored' olmalı.")
        item: dict[str, Any] = {"label": label}
        if raw.get("calls") is not None:
            item["calls"] = _string_list(raw["calls"], "sources.calls", validator=_call_name)
        if raw.get("attributes") is not None:
            item["attributes"] = _string_list(raw["attributes"], "sources.attributes", validator=_call_name)
        if "calls" not in item and "attributes" not in item:
            raise RuleError("sources öğesinde calls veya attributes gerekli.")
        rule["sources"].append(item)
        entries += 1
    allowed_kinds = getattr(taint_models, "VALID_KINDS", taint_models.KNOWN_KINDS)
    for raw in data.get("sinks") or []:
        if not isinstance(raw, dict):
            raise RuleError("sinks öğeleri nesne olmalı.")
        _only_keys(raw, {"kind", "calls", "args", "keywords", "receiver", "cwe", "severity", "message"}, "sinks")
        kind = raw.get("kind")
        if kind not in allowed_kinds:
            raise RuleError(f"sinks.kind şunlardan biri olmalı: {', '.join(sorted(allowed_kinds))}.")
        args = raw.get("args", [0] if not raw.get("receiver") and not raw.get("keywords") else [])
        if not isinstance(args, list) or not all(isinstance(i, int) and not isinstance(i, bool) and 0 <= i < 16 for i in args):
            raise RuleError("sinks.args 0-15 arası tamsayı listesi olmalı.")
        item = {"kind": kind, "calls": _string_list(raw.get("calls"), "sinks.calls", validator=_call_name), "args": args}
        if raw.get("keywords") is not None:
            item["keywords"] = _string_list(raw["keywords"], "sinks.keywords", validator=_keyword_name)
        if raw.get("receiver") is not None:
            if not isinstance(raw["receiver"], bool):
                raise RuleError("sinks.receiver true/false olmalı.")
            item["receiver"] = raw["receiver"]
        if raw.get("cwe") is not None:
            raw_cwe = raw["cwe"]
            if isinstance(raw_cwe, int) and not isinstance(raw_cwe, bool):
                cwe_str = f"CWE-{raw_cwe}"
            elif isinstance(raw_cwe, str):
                cwe_str = raw_cwe.strip().upper()
                if cwe_str.isdigit():
                    cwe_str = f"CWE-{cwe_str}"
            else:
                cwe_str = ""
            if not _CWE_RE.fullmatch(cwe_str):
                raise RuleError("sinks.cwe 'CWE-89' biçiminde olmalı.")
            item["cwe"] = cwe_str
        if raw.get("severity") is not None:
            if raw["severity"] not in SEVERITIES:
                raise RuleError("sinks.severity critical/high/medium/low/info olmalı.")
            item["severity"] = raw["severity"]
        if raw.get("message") is not None:
            if not isinstance(raw["message"], str) or len(raw["message"]) > 300:
                raise RuleError("sinks.message en çok 300 karakter olmalı.")
            item["message"] = raw["message"].strip()
        if not item["args"] and "keywords" not in item and not item.get("receiver"):
            raise RuleError("sinks öğesinde args, keywords veya receiver: true gerekli.")
        rule["sinks"].append(item)
        entries += 1
    for raw in data.get("sanitizers") or []:
        if not isinstance(raw, dict):
            raise RuleError("sanitizers öğeleri nesne olmalı.")
        _only_keys(raw, {"calls", "kinds"}, "sanitizers")
        kinds = _string_list(raw.get("kinds"), "sanitizers.kinds")
        unknown = set(kinds) - allowed_kinds
        if unknown:
            raise RuleError(f"sanitizers.kinds bilinmeyen tür: {', '.join(sorted(unknown))}.")
        rule["sanitizers"].append({"calls": _string_list(raw.get("calls"), "sanitizers.calls", validator=_call_name), "kinds": kinds})
        entries += 1
    propagators = data.get("propagators") or []
    if propagators:
        rule["propagators"] = _string_list(propagators, "propagators", validator=_propagator_name,
                                           limit=MAX_ENTRIES_PER_RULE)
        entries += len(rule["propagators"])
    if entries == 0:
        raise RuleError("Kural en az bir sources, sinks, sanitizers veya propagators kaydı içermeli.")
    if entries > MAX_ENTRIES_PER_RULE:
        raise RuleError(f"Bir kural en çok {MAX_ENTRIES_PER_RULE} kayıt içerebilir.")
    # Derlenen model, motorun yükleyicisi tarafından da kabul edilmeli.
    try:
        taint_models._merge(taint_models.LanguageModels(), compile_models([rule], language), name)
    except ValueError as exc:
        raise RuleError(f"Derlenen model reddedildi: {exc}") from exc
    return rule


def load_rule_text(text: str) -> dict[str, Any]:
    return validate_rule(parse_rule_text(text))


# ---------------------------------------------------------------------------
# Derleme
# ---------------------------------------------------------------------------


def compile_models(rules: list[dict[str, Any]], language: str) -> dict[str, Any]:
    """Doğrulanmış kuralları tek bir sniper-taint-models-v1 belgesinde birleştir."""
    sinks: list[dict[str, Any]] = []
    sanitizers: list[dict[str, Any]] = []
    propagators: list[str] = []
    sources: list[dict[str, Any]] = []
    names: list[str] = []
    for rule in rules:
        if rule["language"] != language:
            continue
        names.append(rule["name"])
        for sink in rule["sinks"]:
            entry: dict[str, Any] = {"kind": sink["kind"], "names": list(sink["calls"]), "args": list(sink["args"])}
            if sink.get("keywords"):
                entry["keywords"] = list(sink["keywords"])
            if sink.get("receiver"):
                entry["receiver"] = True
            sinks.append(entry)
        for sanitizer in rule["sanitizers"]:
            sanitizers.append({"names": list(sanitizer["calls"]), "kinds": list(sanitizer["kinds"])})
        propagators.extend(rule["propagators"])
        for source in rule["sources"]:
            sources.append({key: value for key, value in source.items()})
    return {
        "format": taint_models.MODEL_FORMAT,
        "language": language,
        "description": "İşletmeci tanımlı kurallar (taint_rules_dsl): " + ", ".join(names),
        "sinks": sinks,
        "sanitizers": sanitizers,
        "propagators": sorted(set(propagators)),
        # Motor kancası eklenene kadar yükleyici bu alanı yok sayar (ileri uyumlu).
        "sources": sources,
    }


_DEFAULT_OPENGREP_SOURCES = {
    "python": ["flask.request.$ATTR", "request.args", "request.form", "request.values", "request.json",
               "request.cookies", "request.headers", "request.data", "request.get_json()", "request.GET", "request.POST",
               "request.query_params", "request.path_params", "request.body()", "await request.body()",
               "await request.json()", "await request.form()"],
    "javascript": ["$REQ.query", "$REQ.body", "$REQ.params", "$REQ.headers", "$REQ.cookies",
                   "$REQ.json()", "$REQ.text()", "$REQ.formData()", "await $REQ.json()",
                   "await $REQ.text()", "await $REQ.formData()", "ctx.request.body", "ctx.query", "ctx.params"],
}
_SEVERITY_TO_OPENGREP = {"critical": "ERROR", "high": "ERROR", "medium": "WARNING", "low": "INFO", "info": "INFO"}


def _opengrep_call(name: str, arg_index: int | None, metavar: str = "$SINK") -> str:
    base = name.replace("()", "")
    if base.startswith("*."):
        base = "$OBJ." + base[2:]
    if arg_index is None:
        return f"{base}(...)"
    leading = ", ".join(["$_"] * arg_index)
    return f"{base}({leading + ', ' if leading else ''}{metavar}, ...)"


def compile_opengrep(rules: list[dict[str, Any]]) -> dict[str, Any]:
    """Opengrep (Semgrep uyumlu) taint kuralları; kaynaklar varsayılan + kural kaynakları."""
    out: list[dict[str, Any]] = []
    for rule in rules:
        language = rule["language"]
        source_patterns = [{"pattern": p} for p in _DEFAULT_OPENGREP_SOURCES[language]]
        for source in rule["sources"]:
            source_patterns += [{"pattern": _opengrep_call(c, None)} for c in source.get("calls", [])]
            source_patterns += [{"pattern": a.replace("*.", "$OBJ.")} for a in source.get("attributes", [])]
        sanitizer_patterns = [{"pattern": _opengrep_call(c, None)} for s in rule["sanitizers"] for c in s["calls"]]
        for index, sink in enumerate(rule["sinks"]):
            sink_patterns = []
            for call in sink["calls"]:
                for arg in sink["args"] or [None]:
                    if arg is None:
                        sink_patterns.append({"pattern": _opengrep_call(call, None)})
                    else:
                        sink_patterns.append({"patterns": [{"pattern": _opengrep_call(call, arg)}, {"focus-metavariable": "$SINK"}]})
            cwe_ref = sink.get("cwe") or _DEFAULT_KIND_CWES.get(sink["kind"])
            entry: dict[str, Any] = {
                "id": f"sniper-custom-{rule['name']}-{index + 1}",
                "mode": "taint",
                "languages": [language if language == "python" else "javascript"],
                "severity": _SEVERITY_TO_OPENGREP.get(sink.get("severity", "high"), "WARNING"),
                "message": sink.get("message") or f"{rule['description'] or rule['name']}: güvenilmeyen girdi '{sink['kind']}' hedefine ulaşıyor (özel kural).",
                "metadata": {"category": "security", "source": "sniper-custom-rule", "rule": rule["name"],
                             "sink_kind": sink["kind"], **({"cwe": [cwe_ref]} if cwe_ref else {})},
                "pattern-sources": source_patterns,
                "pattern-sinks": sink_patterns,
            }
            if sanitizer_patterns:
                entry["pattern-sanitizers"] = sanitizer_patterns
            out.append(entry)
    return {"rules": out}


def rule_sha256(rule: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(rule, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()


def summarize(rule: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": rule["name"], "language": rule["language"], "description": rule["description"],
        "counts": {key: len(rule[key]) for key in ("sources", "sinks", "sanitizers", "propagators")},
        "sink_kinds": sorted({s["kind"] for s in rule["sinks"]}),
        "sha256": rule_sha256(rule),
    }


# ---------------------------------------------------------------------------
# İşletmeci kural dizini
# ---------------------------------------------------------------------------


def rules_dir() -> Path:
    raw = os.environ.get("SNIPER_DATA_DIR", "")
    if not raw:
        raise RuleError("Sniper veri dizini yapılandırılmamış; özel kurallar saklanamıyor.")
    data_dir = Path(raw)
    if not data_dir.is_absolute() or data_dir.is_symlink() or not data_dir.is_dir():
        raise RuleError("Sniper veri dizini geçersiz.")
    directory = data_dir / "custom-rules"
    for path in (directory, directory / "compiled"):
        try:
            path.mkdir(mode=0o700, exist_ok=True)
        except OSError as exc:
            raise RuleError("Özel kural dizini oluşturulamadı.") from exc
        info = os.lstat(path)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise RuleError("Özel kural dizini güvensiz (sahip/izin); kurallar kullanılmadı.")
    return directory


def _atomic_write(path: Path, text: str) -> None:
    fd, tmp = tempfile.mkstemp(prefix=".kural-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _read_rule_file(path: Path) -> dict[str, Any] | None:
    from safe_file_read import read_text_bounded

    text = read_text_bounded(path, MAX_RULE_BYTES * 2)
    if text is None:
        return None
    try:
        stored = json.loads(text)
        rule = validate_rule(stored["rule"])
    except (ValueError, KeyError, TypeError, RecursionError):
        return None
    rule["_stored_at"] = stored.get("stored_at")
    return rule


def list_rules() -> list[dict[str, Any]]:
    directory = rules_dir()
    rules = []
    for path in sorted(directory.glob("*.json")):
        if not _NAME_RE.fullmatch(path.stem):
            continue
        rule = _read_rule_file(path)
        if rule is not None:
            rules.append(rule)
    return rules


def custom_model_paths() -> list[str]:
    """Derlenmiş özel modellerin yolları (taint_models yükleyici kancası için)."""
    try:
        compiled = rules_dir() / "compiled"
    except RuleError:
        return []
    return [str(p) for p in sorted(compiled.glob("*-custom.json")) if p.is_file() and not p.is_symlink()]


def _recompile(rules: list[dict[str, Any]]) -> dict[str, str]:
    compiled = rules_dir() / "compiled"
    written: dict[str, str] = {}
    for language in LANGUAGES:
        target = compiled / f"{language}-custom.json"
        clean = [{k: v for k, v in r.items() if not k.startswith("_")} for r in rules]
        if any(r["language"] == language for r in clean):
            _atomic_write(target, json.dumps(compile_models(clean, language), ensure_ascii=False, indent=1) + "\n")
            written[language] = str(target)
        elif target.exists():
            target.unlink()
    opengrep = compiled / "opengrep-custom.yaml"
    if rules:
        _atomic_write(opengrep, json.dumps(compile_opengrep([{k: v for k, v in r.items() if not k.startswith("_")} for r in rules]), ensure_ascii=False, indent=1) + "\n")
    elif opengrep.exists():
        opengrep.unlink()
    try:
        taint_models._load.cache_clear()
    except AttributeError:  # pragma: no cover
        pass
    return written


def save_rule(text: str) -> dict[str, Any]:
    rule = load_rule_text(text)
    directory = rules_dir()
    existing = [r for r in list_rules() if r["name"] != rule["name"]]
    if len(existing) >= MAX_RULES:
        raise RuleError(f"En çok {MAX_RULES} özel kural saklanabilir.")
    stored_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    _atomic_write(directory / f"{rule['name']}.json",
                  json.dumps({"stored_at": stored_at, "rule": rule}, ensure_ascii=False, indent=1) + "\n")
    _recompile([*existing, rule])
    return {**summarize(rule), "stored_at": stored_at}


def delete_rule(name: str) -> bool:
    if not isinstance(name, str) or not _NAME_RE.fullmatch(name):
        raise RuleError("Geçersiz kural adı.")
    directory = rules_dir()
    path = directory / f"{name}.json"
    if not path.is_file() or path.is_symlink():
        return False
    path.unlink()
    _recompile(list_rules())
    return True


def status() -> dict[str, Any]:
    """Kural listesi ve etkinlik durumu (dosya yolları yanıtta gösterilmez)."""
    try:
        rules = list_rules()
        paths = custom_model_paths()
    except RuleError as exc:
        return {"rules": [], "available": False, "message": str(exc)}
    configured = os.environ.get("SNIPER_TAINT_MODELS", "").split(os.pathsep)
    hooked = bool(getattr(taint_models, "CUSTOM_RULES_HOOK", False))
    active = hooked or (bool(paths) and all(p in configured for p in paths))
    return {
        "available": True,
        "active": active,
        "activation": ("Kurallar motor tarafından otomatik yükleniyor." if hooked else
                       "Kurallar derlendi; etkin olmaları için taint_models kancası veya SNIPER_TAINT_MODELS gerekir."),
        "limits": {"max_rules": MAX_RULES, "max_rule_bytes": MAX_RULE_BYTES, "max_entries": MAX_ENTRIES_PER_RULE},
        "rules": [{**summarize({k: v for k, v in r.items() if not k.startswith("_")}), "stored_at": r.get("_stored_at")} for r in rules],
    }


# ---------------------------------------------------------------------------
# Kuralı dene (ayrı süreçte, aday modelle)
# ---------------------------------------------------------------------------

_TRY_CHILD = r"""
import json, os, sys
request = json.loads(sys.stdin.read())
sys.path.insert(0, request["app"])
import taint_flow
analysis = taint_flow.analyze_source(request["code"], request["filename"])
flows = [] if analysis is None else [f.as_dict() for f in analysis.flows]
print(json.dumps({"analyzed": analysis is not None, "flows": flows}, ensure_ascii=False))
"""


def _run_trial(code: str, filename: str, model_paths: list[str]) -> dict[str, Any]:
    from process_group_runner import run_in_process_group

    # SNIPER_DATA_DIR verilmez: kayıtlı özel kurallar (ve taint önbelleği) denemeye karışmaz;
    # karşılaştırma yalnız "aday kuralla / kuralsız" farkını gösterir.
    env = {key: value for key, value in os.environ.items() if key not in {"SNIPER_TAINT_MODELS", "PYTHONPATH", "SNIPER_DATA_DIR"}}
    env["SNIPER_TAINT_MODELS"] = os.pathsep.join(model_paths)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    with tempfile.TemporaryDirectory(prefix="sniper-kural-dene-") as tmp:
        request = Path(tmp) / "istek.json"
        request.write_text(json.dumps({"app": str(APP_DIR), "code": code, "filename": filename}), encoding="utf-8")
        with request.open("rb") as stdin:
            completed = run_in_process_group(
                [sys.executable, "-c", _TRY_CHILD], timeout=TRY_TIMEOUT_SECONDS, stdin=stdin,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, cwd=tmp, env=env,
            )
    if completed.returncode != 0:
        raise RuleError("Deneme analizi başarısız oldu.")
    try:
        return json.loads(completed.stdout.decode("utf-8") or "{}")
    except (ValueError, UnicodeDecodeError) as exc:
        raise RuleError("Deneme analizinin çıktısı okunamadı.") from exc


def try_rule(text: str, code: str, filename: str = "") -> dict[str, Any]:
    """Aday kuralı kaydetmeden örnek koda karşı dene: kuralla ve kuralsız akışları karşılaştır."""
    rule = load_rule_text(text)
    if not isinstance(code, str) or not code.strip():
        raise RuleError("Denenecek örnek kod boş olamaz.")
    if len(code.encode("utf-8")) > MAX_TRY_CODE_BYTES:
        raise RuleError(f"Örnek kod en çok {MAX_TRY_CODE_BYTES} bayt olabilir.")
    default_name = "ornek.py" if rule["language"] == "python" else "ornek.js"
    if not isinstance(filename, str) or not re.fullmatch(r"[\w.-]{1,80}", filename or ""):
        filename = default_name
    if (rule["language"] == "python") != filename.endswith(".py"):
        filename = default_name
    clean = {k: v for k, v in rule.items() if not k.startswith("_")}
    with tempfile.TemporaryDirectory(prefix="sniper-kural-model-") as tmp:
        model_path = Path(tmp) / f"{rule['language']}-aday.json"
        model_path.write_text(json.dumps(compile_models([clean], rule["language"]), ensure_ascii=False), encoding="utf-8")
        os.chmod(model_path, 0o600)
        baseline = _run_trial(code, filename, [])
        candidate = _run_trial(code, filename, [str(model_path)])
    key = lambda f: (f.get("sink_kind"), f.get("sink_line"), f.get("source"), f.get("source_line"))
    before = {key(f) for f in baseline.get("flows", [])}
    new_flows = [f for f in candidate.get("flows", []) if key(f) not in before]
    after = {key(f) for f in candidate.get("flows", [])}
    removed = [f for f in baseline.get("flows", []) if key(f) not in after]
    return {
        "rule": summarize(clean),
        "analyzed": bool(candidate.get("analyzed")),
        "flows": candidate.get("flows", []),
        "new_flows": new_flows,
        "removed_flows": removed,
        "note": "",
    }
