"""Taint motoru için veri tabanlı hedef/arındırıcı/yayıcı modelleri.

Yerleşik modeller ``rules/taint/<dil>.json`` dosyalarındadır. İşletmeci, ek modelleri
``SNIPER_TAINT_MODELS`` ortam değişkeniyle verdiği JSON dosyasından ekleyebilir (aynı
biçim; birden çok dosya ``os.pathsep`` ile ayrılır). İşletmecinin onaylı API ile kaydettiği özel
kurallar (``taint_rules_dsl``; ``$SNIPER_DATA_DIR/custom-rules/compiled/*-custom.json``) dizin ve
dosya güvenlik denetimini geçerse kendiliğinden yüklenir (``CUSTOM_RULES_HOOK``). Taranan projenin kendi dosyaları
model olarak **okunmaz**: proje kendi açığını gizleyecek bir arındırıcı tanımlayamaz.

Model dosyası yalnız veri içerir; kod çalıştırılmaz.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import functools
import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Any

from safe_file_read import read_text_bounded

MODEL_DIR = Path(__file__).resolve().parent / "rules" / "taint"
MODEL_FORMAT = "sniper-taint-models-v1"
KNOWN_KINDS = frozenset({
    "log", "sql", "command", "eval", "html", "regex", "path", "ssrf", "deserialize", "redirect",
    "ldap", "xpath", "xxe", "session", "cookie",
})
EXTRA_KINDS = frozenset({
    "nosql", "nosql_expr", "ssti", "header", "format", "format_string",
    "prototype", "mass_assign", "code", "memory", "memory_len", "memory_index",
})
VALID_KINDS = KNOWN_KINDS | EXTRA_KINDS
MAX_MODEL_BYTES = 512_000
MAX_ENTRIES = 5_000
MAX_NAME_LENGTH = 200
SOURCE_LABELS = frozenset({"request", "pii", "stored"})
# Özel kurallar (taint_rules_dsl) yükleyiciye bağlı: models_for derlenmiş özel modelleri de okur.
CUSTOM_RULES_HOOK = True


@dataclass(frozen=True)
class SinkModel:
    kind: str
    names: frozenset[str]
    suffixes: frozenset[str]
    args: tuple[int, ...] = ()
    keywords: frozenset[str] = frozenset()
    receiver: bool = False
    receiver_calls: frozenset[str] = frozenset()
    safe_keyword_values: dict[str, frozenset[str]] = field(default_factory=dict)
    required_keyword_values: dict[str, frozenset[str]] = field(default_factory=dict)
    # JS (AST motoru) seçenekleri
    object_keys: frozenset[str] = frozenset()          # argüman nesne ise yalnız bu anahtarların değerleri
    last_arg: bool = False                              # son argüman (res.redirect(301, url))
    html_literal: bool = False                          # yalnız HTML parçası içeren ifadelerde hedef
    unless_object_key: tuple[int, frozenset[str]] | None = None      # bu indeksteki nesnede anahtar varsa hedef değil
    required_object_key: tuple[int, str, frozenset[str]] | None = None  # (indeks, anahtar, değerler) şart

    def matches(self, name: str) -> bool:
        if name in self.names:
            return True
        if "." in name and self.suffixes:
            return name.rsplit(".", 1)[-1] in self.suffixes
        return False


@dataclass
class LanguageModels:
    sinks: list[SinkModel] = field(default_factory=list)
    sanitizers: dict[str, frozenset[str]] = field(default_factory=dict)
    propagators: frozenset[str] = frozenset()
    # Kaynaklar: çağrı adı → etiket (dönüş değeri kaynak) ve nokta yolu öznitelik okuması → etiket.
    # "*.ad" kaydı son bileşene göre eşleşir.
    source_calls: dict[str, str] = field(default_factory=dict)
    source_attributes: dict[str, str] = field(default_factory=dict)
    # Alıcı türü izleme: çağrı adı (kurucu, fabrika, metot) → dönen nesnenin sınıfı (tanım yolu).
    returns: dict[str, str] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def class_of(self, name: str) -> str | None:
        """``requests.Session`` / ``psycopg2.connect`` gibi bir çağrının döndürdüğü sınıf (biliniyorsa)."""
        return self.returns.get(name) if name else None

    @staticmethod
    def _source_lookup(table: dict[str, str], name: str) -> str | None:
        if not name or not table:
            return None
        label = table.get(name)
        if label is None and "." in name:
            label = table.get("*." + name.rsplit(".", 1)[-1])
        return label

    def source_for(self, name: str) -> str | None:
        """Çağrı adı tanımlı bir kaynak mı? Etiketi (request/pii/stored) ya da None."""
        return self._source_lookup(self.source_calls, name)

    def attribute_source_for(self, dotted: str) -> str | None:
        """Nokta yolu öznitelik okuması (ör. ``sirket.istek.govde``) tanımlı bir kaynak mı?"""
        return self._source_lookup(self.source_attributes, dotted)

    def propagates(self, name: str) -> bool:
        """Ad yayıcı mı? ``modül.*`` biçimindeki kayıtlar modüldeki tüm çağrıları kapsar."""
        if not name:
            return False
        if name in self.propagators:
            return True
        # "modül.*" kayıtları önek kümesinde: adın her "a.b." öneki tek sözlük sorgusuyla denetlenir
        # (her çağrıda tüm yayıcıları taramak büyük projelerde sıcak noktaydı).
        cached = self.__dict__.get("_wildcard_cache")
        if cached is None or cached[0] is not self.propagators:
            cached = (self.propagators, frozenset(e[:-1] for e in self.propagators if e.endswith(".*")))
            self.__dict__["_wildcard_cache"] = cached
        prefixes = cached[1]
        if not prefixes:
            return False
        index = name.find(".")
        while index != -1:
            if name[: index + 1] in prefixes:
                return True
            index = name.find(".", index + 1)
        return False

    def sinks_for(self, name: str) -> list[SinkModel]:
        if not name:
            return []
        # Ad başına önbellek (19. tur hız); model listesi yüklemeden sonra değişirse (uzunluk) sıfırlanır.
        cache = self.__dict__.get("_sinks_for_cache")
        if cache is None or self.__dict__.get("_sinks_for_len") != len(self.sinks):
            cache = {}
            self.__dict__["_sinks_for_cache"] = cache
            self.__dict__["_sinks_for_len"] = len(self.sinks)
        hit = cache.get(name)
        if hit is None:
            hit = cache[name] = tuple(model for model in self.sinks if model.matches(name))
        return list(hit)

    def sanitizer_kinds(self, name: str) -> frozenset[str] | None:
        return self.sanitizers.get(name)


def _names(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) and 0 < len(item) <= MAX_NAME_LENGTH for item in value):
        raise ValueError(f"{label} metin listesi olmalı")
    return value


def _kinds(value: Any) -> frozenset[str]:
    kinds = frozenset(_names(value, "kinds"))
    unknown = kinds - VALID_KINDS
    if unknown:
        raise ValueError(f"bilinmeyen hedef türü: {', '.join(sorted(unknown))}")
    return kinds


def _keyword_values(value: Any) -> dict[str, frozenset[str]]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError("anahtar sözcük değerleri nesne olmalı")
    return {str(key): frozenset(_names(items, str(key))) for key, items in value.items()}


def _object_key_option(value: Any, *, required: bool) -> Any:
    if value is None:
        return None
    if not isinstance(value, dict) or not isinstance(value.get("index"), int) or isinstance(value.get("index"), bool):
        raise ValueError("nesne anahtarı seçeneği {index, ...} olmalı")
    index = int(value["index"])
    if not -4 <= index < 16:
        raise ValueError("nesne anahtarı indeksi -4..15 olmalı")
    if required:
        key = value.get("key")
        if not isinstance(key, str) or not key:
            raise ValueError("required_object_key.key metin olmalı")
        return (index, key, frozenset(_names(value.get("values"), "values")))
    return (index, frozenset(_names(value.get("keys"), "keys")))


def _merge(target: LanguageModels, data: Any, origin: str) -> None:
    if not isinstance(data, dict) or data.get("format") != MODEL_FORMAT:
        raise ValueError(f"biçim '{MODEL_FORMAT}' olmalı")
    entries = 0
    for raw in data.get("sinks", []) or []:
        entries += 1
        if not isinstance(raw, dict):
            raise ValueError("sink kaydı nesne olmalı")
        kind = raw.get("kind")
        if kind not in VALID_KINDS:
            raise ValueError(f"bilinmeyen hedef türü: {kind!r}")
        names = _names(raw.get("names"), "names")
        args = raw.get("args", [])
        if not isinstance(args, list) or not all(isinstance(i, int) and not isinstance(i, bool) and 0 <= i < 16 for i in args):
            raise ValueError("args 0-15 arası tamsayı listesi olmalı")
        target.sinks.append(SinkModel(
            kind=kind,
            names=frozenset(n for n in names if not n.startswith("*.")),
            suffixes=frozenset(n[2:] for n in names if n.startswith("*.")),
            args=tuple(args),
            keywords=frozenset(_names(raw.get("keywords", []), "keywords")),
            receiver=bool(raw.get("receiver", False)),
            receiver_calls=frozenset(_names(raw.get("receiver_calls", []), "receiver_calls")),
            safe_keyword_values=_keyword_values(raw.get("safe_keyword_values")),
            required_keyword_values=_keyword_values(raw.get("required_keyword_values")),
            object_keys=frozenset(_names(raw.get("object_keys", []), "object_keys")),
            last_arg=bool(raw.get("last_arg", False)),
            html_literal=bool(raw.get("html_literal", False)),
            unless_object_key=_object_key_option(raw.get("unless_object_key"), required=False),
            required_object_key=_object_key_option(raw.get("required_object_key"), required=True),
        ))
    for raw in data.get("sanitizers", []) or []:
        entries += 1
        if not isinstance(raw, dict):
            raise ValueError("sanitizer kaydı nesne olmalı")
        kinds = _kinds(raw.get("kinds"))
        for name in _names(raw.get("names"), "names"):
            target.sanitizers[name] = target.sanitizers.get(name, frozenset()) | kinds
    for raw in data.get("sources", []) or []:
        entries += 1
        if not isinstance(raw, dict):
            raise ValueError("source kaydı nesne olmalı")
        label = raw.get("label", "request")
        if label not in SOURCE_LABELS:
            raise ValueError(f"bilinmeyen kaynak etiketi: {label!r}")
        calls = _names(raw.get("names", raw.get("calls", [])) or [], "names")
        attributes = _names(raw.get("attributes", []) or [], "attributes")
        if not calls and not attributes:
            raise ValueError("source kaydında names veya attributes gerekli")
        for name in calls:
            target.source_calls[name.removesuffix("()")] = label
        for name in attributes:
            target.source_attributes[name] = label
    returns = data.get("returns") or {}
    if not isinstance(returns, dict) or not all(
            isinstance(k, str) and isinstance(v, str) and 0 < len(k) <= MAX_NAME_LENGTH and 0 < len(v) <= MAX_NAME_LENGTH
            for k, v in returns.items()):
        raise ValueError("returns ad → sınıf metin eşlemesi olmalı")
    entries += len(returns)
    target.returns.update(returns)
    propagators = _names(data.get("propagators", []) or [], "propagators")
    entries += len(propagators)
    target.propagators = target.propagators | frozenset(propagators)
    if entries > MAX_ENTRIES:
        raise ValueError(f"en fazla {MAX_ENTRIES} kayıt")


def _load_file(target: LanguageModels, path: Path, language: str) -> None:
    text = read_text_bounded(path, MAX_MODEL_BYTES)
    if text is None:
        raise ValueError("okunamadı (normal dosya değil veya boyut sınırı aşıldı)")
    data = json.loads(text)
    if isinstance(data, dict) and data.get("language") not in (None, language):
        return
    _merge(target, data, str(path))


def _custom_model_paths() -> list[str]:
    """İşletmeci özel kurallarının derlenmiş model dosyaları (güvenlik denetiminden geçenler).

    Dizin yoksa oluşturulmaz (tarama yan etkisiz kalır); varsa ``taint_rules_dsl.rules_dir``
    sahip/izin denetimi uygulanır. Dosyalar da sahibi biz ve grup/diğerlerine yazılamaz olmalı."""
    raw = os.environ.get("SNIPER_DATA_DIR", "")
    if not raw or not (Path(raw) / "custom-rules" / "compiled").is_dir():
        return []
    try:
        import taint_rules_dsl  # döngüsel içe aktarma: yalnız gerektiğinde
        paths = taint_rules_dsl.custom_model_paths()
    except Exception:  # özel kural katmanı bozuksa yerleşik modellerle devam
        return []
    safe = []
    for item in paths:
        try:
            info = os.lstat(item)
        except OSError:
            continue
        if stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o022:
            safe.append(item)
    return safe


def _model_stamp(paths: list[str]) -> tuple[tuple[Any, ...], ...]:
    """Ek model icerigi icin sinirli, hashlenebilir cache anahtari."""
    stamps: list[tuple[Any, ...]] = []
    for item in paths:
        path = Path(item).expanduser()
        text = read_text_bounded(path, MAX_MODEL_BYTES)
        if text is not None:
            stamps.append((str(path), hashlib.sha256(text.encode("utf-8")).hexdigest()))
            continue
        try:
            info = os.lstat(path)
            stamps.append((str(path), info.st_dev, info.st_ino, info.st_size,
                           info.st_mtime_ns, info.st_ctime_ns, "unreadable"))
        except OSError:
            stamps.append((str(path), "missing"))
    return tuple(stamps)


def _merge_models(models: LanguageModels, candidate: LanguageModels) -> None:
    models.sinks.extend(candidate.sinks)
    for name, kinds in candidate.sanitizers.items():
        models.sanitizers[name] = models.sanitizers.get(name, frozenset()) | kinds
    models.propagators = models.propagators | candidate.propagators
    models.source_calls.update(candidate.source_calls)
    models.source_attributes.update(candidate.source_attributes)
    models.returns.update(candidate.returns)


@functools.lru_cache(maxsize=8)
def _load(language: str, extra: str, custom: tuple[str, ...] = (),
          stamp: tuple[tuple[Any, ...], ...] = ()) -> LanguageModels:
    models = LanguageModels()
    # Elle yazılmış <dil>.json ve otomatik üretilmiş <dil>-*.json (ör. python-stdlib.json, typeshed'den).
    builtins = [MODEL_DIR / f"{language}.json", *sorted(MODEL_DIR.glob(f"{language}-*.json"))]
    for builtin in builtins:
        try:
            _load_file(models, builtin, language)
        except (OSError, ValueError, RecursionError) as exc:
            models.errors.append(f"{builtin.name}: {exc}")
    for item in [*[part for part in extra.split(os.pathsep) if part.strip()], *custom]:
        path = Path(item).expanduser()
        candidate = LanguageModels()
        try:
            _load_file(candidate, path, language)
        except (OSError, ValueError, RecursionError) as exc:
            # Geçersiz ek model sessizce yarım uygulanmaz: tamamı atlanır.
            models.errors.append(f"{path.name}: {exc}")
            continue
        _merge_models(models, candidate)
    return models


def models_for(language: str) -> LanguageModels:
    extra = os.environ.get("SNIPER_TAINT_MODELS", "")
    extra_paths = [part for part in extra.split(os.pathsep) if part.strip()]
    configured = set(extra_paths)
    # SNIPER_TAINT_MODELS ile zaten verilmiş özel model iki kez yüklenmez.
    custom = [path for path in _custom_model_paths() if path not in configured]
    return _load(language, extra, tuple(custom), _model_stamp([*extra_paths, *custom]))


def model_status() -> dict[str, Any]:
    """Readiness/rapor için: yüklü model sayıları ve hatalar (dosya içeriği yazılmaz)."""
    status: dict[str, Any] = {}
    for language in ("python", "javascript"):
        models = models_for(language)
        status[language] = {
            "sinks": len(models.sinks),
            "sanitizers": len(models.sanitizers),
            "propagators": len(models.propagators),
            "sources": len(models.source_calls) + len(models.source_attributes),
            "errors": list(models.errors),
        }
    return status
