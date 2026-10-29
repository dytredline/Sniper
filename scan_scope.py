"""Proje taramalarının kapsam seçenekleri: varsayılan olarak atlanan dizin ve dosyaları isteğe bağlı dahil etme.

Varsayılan kapsam önceki davranışla aynıdır. Bir istek ``scope`` nesnesi gönderirse :func:`scan_scope` ile
istek boyunca etkinleşir; ``project_analyzer.SKIP_DIRS`` bu bağlamı okuduğu için bütün yerel denetçiler
(taint, Joern, Semgrep dahil) aynı dizin kapsamını kullanır.
"""
from __future__ import annotations

import contextlib
import contextvars
from dataclasses import dataclass, field
import json
import os
import re
from pathlib import Path
from collections.abc import Set
from typing import Any, Iterator


def _env_limit(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        return max(minimum, min(maximum, int(os.environ.get(name, default))))
    except ValueError:
        return default


# Her zaman atlanır: sürüm denetimi, IDE ve önbellek dizinleri (kaynak kod içermez).
ALWAYS_SKIP_DIRS = frozenset({".git", ".hg", ".svn", ".idea", ".vscode", "__pycache__", ".dart_tool", ".gradle"})

# İsteğe bağlı dahil edilebilen dizin grupları (varsayılan: atlanır).
OPTIONAL_DIR_GROUPS: dict[str, frozenset[str]] = {
    "tests": frozenset({"tests", "test", "__tests__", "fixtures", "testdata"}),
    "vendor": frozenset({"vendor", "bower_components", "jspm_packages", "pods"}),
    "packages": frozenset({"node_modules", "venv", ".venv"}),
    "build": frozenset({"build", "dist", ".next", ".nuxt", "coverage", "deriveddata"}),
}
DIR_GROUP_LABELS = {
    "tests": "test",
    "vendor": "vendor / üçüncü taraf",
    "packages": "paket (node_modules, venv)",
    "build": "derleme çıktısı (build, dist)",
}
DEFAULT_SKIP_DIRS = ALWAYS_SKIP_DIRS.union(*OPTIONAL_DIR_GROUPS.values())

MB = 1_000_000
DEFAULT_MAX_FILES = _env_limit("SNIPER_PROJECT_MAX_FILES", 10_000, 100, 500_000)
DEFAULT_MAX_FILE_BYTES = _env_limit("SNIPER_PROJECT_MAX_FILE_BYTES", 1 * MB, 100_000, 200 * MB)
DEFAULT_MAX_TOTAL_BYTES = _env_limit("SNIPER_PROJECT_MAX_BYTES", 150 * MB, 1 * MB, 10_000 * MB)

# Seçeneklerle yükseltilebilen üst sınırlar.
HARD_MAX_FILES = _env_limit("SNIPER_HARD_MAX_FILES", 50_000, 10_000, 500_000)
HARD_MAX_FILE_BYTES = _env_limit("SNIPER_HARD_MAX_FILE_BYTES", 20 * MB, 1 * MB, 200 * MB)
HARD_MAX_TOTAL_BYTES = _env_limit("SNIPER_HARD_MAX_TOTAL_BYTES", 1_000 * MB, 100 * MB, 10_000 * MB)

_ALLOWED_KEYS = {"preset", "include_dirs", "include_generated", "include_non_utf8", "max_file_mb", "max_total_mb", "max_files",
                 "skipped_only", "changed_only", "base_ref"}

# git başvurusu (dal, etiket, HEAD~N, commit) ya da proje analizi kimliği (prj_…). Aralık (..), seçenek (-) yok.
_BASE_REF_RE = re.compile(r"(?!-)(?!.*\.\.)[A-Za-z0-9._/~^@{}+-]{1,200}\Z")

# Üretilmiş/küçültülmüş paketler: kaynak analizi için gürültü (bağımlılık taraması ayrı yapılır).
GENERATED_SUFFIXES = (".min.js", ".min.mjs", ".min.cjs", ".bundle.js", ".chunk.js")


class ScopeError(ValueError):
    """Geçersiz kapsam seçeneği."""


@dataclass(frozen=True)
class ScanScope:
    include_dirs: frozenset[str] = field(default_factory=frozenset)
    include_generated: bool = False
    include_non_utf8: bool = False
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES
    max_files: int = DEFAULT_MAX_FILES
    # Yalnız varsayılan kapsamın atlayacağı dosyalar taranır (önceki normal taramada incelenenler yeniden taranmaz).
    skipped_only: bool = False
    # Yalnız değişenler: base_ref'e göre değişen/eklenen dosyaların bulguları raporlanır (changed_scan.py).
    changed_only: bool = False
    base_ref: str = ""
    # İç kullanım (API'den gelmez): raporlanacak dosyalar (proje köküne göre posix yollar); None = hepsi.
    only_paths: frozenset[str] | None = None
    # İç kullanım: dosyalar arası taint bağlamına alınacak kaynak dosyalar; None = tüm proje.
    context_paths: frozenset[str] | None = None

    @property
    def is_default(self) -> bool:
        return self == DEFAULT_SCOPE

    @property
    def skip_dirs(self) -> frozenset[str]:
        if not self.include_dirs:
            return DEFAULT_SKIP_DIRS
        included = frozenset().union(*(OPTIONAL_DIR_GROUPS[name] for name in self.include_dirs))
        return DEFAULT_SKIP_DIRS - included

    def public(self) -> dict[str, Any]:
        return {
            "include_dirs": sorted(self.include_dirs),
            "include_generated": self.include_generated,
            "include_non_utf8": self.include_non_utf8,
            "max_file_mb": self.max_file_bytes // MB,
            "max_total_mb": self.max_total_bytes // MB,
            "max_files": self.max_files,
            "skipped_only": self.skipped_only,
            "changed_only": self.changed_only,
            "base_ref": self.base_ref,
        }


DEFAULT_SCOPE = ScanScope()
FULL_SCOPE = ScanScope(
    include_dirs=frozenset(OPTIONAL_DIR_GROUPS),
    include_generated=True,
    include_non_utf8=True,
    max_file_bytes=HARD_MAX_FILE_BYTES,
    max_total_bytes=HARD_MAX_TOTAL_BYTES,
    max_files=HARD_MAX_FILES,
)

SKIPPED_ONLY_SCOPE = ScanScope(
    include_dirs=FULL_SCOPE.include_dirs,
    include_generated=True,
    include_non_utf8=True,
    max_file_bytes=HARD_MAX_FILE_BYTES,
    max_total_bytes=HARD_MAX_TOTAL_BYTES,
    max_files=HARD_MAX_FILES,
    skipped_only=True,
)

_SCOPE: contextvars.ContextVar[ScanScope] = contextvars.ContextVar("sniper_scan_scope", default=DEFAULT_SCOPE)


def _bool(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise ScopeError(f"scope.{name} true/false olmalıdır.")
    return value


def _int(value: Any, name: str, minimum: int, maximum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
        raise ScopeError(f"scope.{name} {minimum} ile {maximum} arasında bir tam sayı olmalıdır.")
    return value


def parse_scope(raw: Any) -> ScanScope:
    """API/CLI kapsam nesnesini doğrula. ``None`` varsayılan kapsamdır; ``{"preset": "all"}`` her şeyi dahil eder."""
    if raw is None:
        return DEFAULT_SCOPE
    if not isinstance(raw, dict):
        raise ScopeError("scope bir JSON nesnesi olmalıdır.")
    unknown = set(raw) - _ALLOWED_KEYS
    if unknown:
        raise ScopeError("Bilinmeyen kapsam seçeneği: " + ", ".join(sorted(map(str, unknown))))
    preset = raw.get("preset", "default")
    if preset not in {"default", "all", "skipped"}:
        raise ScopeError("scope.preset 'default', 'all' veya 'skipped' olmalıdır.")
    base = {"default": DEFAULT_SCOPE, "all": FULL_SCOPE, "skipped": SKIPPED_ONLY_SCOPE}[preset]
    include_dirs = base.include_dirs
    if "include_dirs" in raw:
        value = raw["include_dirs"]
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            raise ScopeError("scope.include_dirs bir metin listesi olmalıdır.")
        bad = sorted(set(value) - set(OPTIONAL_DIR_GROUPS))
        if bad:
            raise ScopeError("Bilinmeyen dizin grubu: " + ", ".join(bad) + " (geçerli: " + ", ".join(OPTIONAL_DIR_GROUPS) + ")")
        include_dirs = frozenset(value)
    return ScanScope(
        include_dirs=include_dirs,
        include_generated=_bool(raw["include_generated"], "include_generated") if "include_generated" in raw else base.include_generated,
        include_non_utf8=_bool(raw["include_non_utf8"], "include_non_utf8") if "include_non_utf8" in raw else base.include_non_utf8,
        max_file_bytes=_int(raw["max_file_mb"], "max_file_mb", 1, HARD_MAX_FILE_BYTES // MB) * MB if "max_file_mb" in raw else base.max_file_bytes,
        max_total_bytes=_int(raw["max_total_mb"], "max_total_mb", 1, HARD_MAX_TOTAL_BYTES // MB) * MB if "max_total_mb" in raw else base.max_total_bytes,
        max_files=_int(raw["max_files"], "max_files", 100, HARD_MAX_FILES) if "max_files" in raw else base.max_files,
        skipped_only=_bool(raw["skipped_only"], "skipped_only") if "skipped_only" in raw else base.skipped_only,
        changed_only=_bool(raw["changed_only"], "changed_only") if "changed_only" in raw else False,
        base_ref=_base_ref(raw.get("base_ref", ""), bool(raw.get("changed_only"))),
    )


def _base_ref(value: Any, required: bool) -> str:
    if value in ("", None):
        if required:
            raise ScopeError("scope.base_ref gerekli (ör. HEAD~1, origin/main ya da prj_… analiz kimliği).")
        return ""
    if not isinstance(value, str) or not _BASE_REF_RE.fullmatch(value):
        raise ScopeError("scope.base_ref geçersiz: dal/etiket/commit/HEAD~N ya da analiz kimliği olmalı (aralık ve '-' ile başlayan değer yok).")
    return value


def current() -> ScanScope:
    return _SCOPE.get()


@contextlib.contextmanager
def scan_scope(scope: ScanScope) -> Iterator[ScanScope]:
    token = _SCOPE.set(scope)
    try:
        yield scope
    finally:
        _SCOPE.reset(token)


def default_skips_path(rel_parts: tuple[str, ...], size: int, max_file_bytes: int = DEFAULT_MAX_FILE_BYTES) -> bool:
    """Varsayılan kapsam bu dosyayı yapısal olarak atlar mıydı (isteğe bağlı dizin grubu, üretilmiş, büyük)?

    ``rel_parts`` proje köküne göre yol parçalarıdır (son parça dosya adı). Kodlama ve bütçe atlamaları içeriğe ve
    tüm projeye bağlı olduğundan burada değil, dosya yürüyüşünde ayrıca değerlendirilir."""
    if any(part.casefold() in DEFAULT_SKIP_DIRS for part in rel_parts[:-1]):
        return True
    name = rel_parts[-1].casefold() if rel_parts else ""
    return name.endswith(GENERATED_SUFFIXES) or size > max_file_bytes


def dir_group(name: str) -> str | None:
    """Atlanan dizin adının ait olduğu isteğe bağlı grup (yoksa ``None``)."""
    lowered = name.casefold()
    for group, names in OPTIONAL_DIR_GROUPS.items():
        if lowered in names:
            return group
    return None


class ScopedSkipDirs(Set):
    """``SKIP_DIRS`` görünümü: ``in``, yineleme, uzunluk ve küme işlemleri etkin kapsamın atlanan
    dizinlerini kullanır (içerik her erişimde :func:`current` kapsamından okunur).

    Bilerek ``frozenset`` alt sınıfı değildir: CPython ``frozenset(x)`` ve ``|`` işlemlerinde küme alt
    sınıflarının iç verisini doğrudan kopyalar ve ``__iter__``'ı atlar."""

    __slots__ = ()

    @classmethod
    def _from_iterable(cls, iterable):
        return frozenset(iterable)

    def __contains__(self, item: object) -> bool:
        return item in current().skip_dirs

    def __iter__(self):
        return iter(current().skip_dirs)

    def __len__(self) -> int:
        return len(current().skip_dirs)

    def __hash__(self) -> int:
        return hash(current().skip_dirs)

    def __repr__(self) -> str:
        return f"ScopedSkipDirs({sorted(current().skip_dirs)!r})"


# ---------------------------------------------------------------------------
# Kalıcı varsayılan kapsam ($SNIPER_DATA_DIR/scan-scope.json)
# ---------------------------------------------------------------------------
FILE_NAME = "scan-scope.json"


def _settings_path(environ: dict[str, str] | None = None) -> Path | None:
    text = (os.environ if environ is None else environ).get("SNIPER_DATA_DIR", "")
    path = Path(text)
    if not text or not path.is_absolute() or path.is_symlink() or not path.is_dir():
        return None
    return path / FILE_NAME


def load_default(environ: dict[str, str] | None = None) -> ScanScope:
    """Kaydedilmiş varsayılan kapsam; dosya yoksa ya da bozuksa önceki davranış (``DEFAULT_SCOPE``)."""
    path = _settings_path(environ)
    if path is None:
        return DEFAULT_SCOPE
    try:
        if path.is_symlink():
            return DEFAULT_SCOPE
        raw = json.loads(path.read_text(encoding="utf-8"))
        return parse_scope(raw.get("scope") if isinstance(raw, dict) else None)
    except (OSError, ValueError):
        return DEFAULT_SCOPE


def save_default(scope: ScanScope, environ: dict[str, str] | None = None) -> ScanScope:
    """Varsayılan kapsamı atomik olarak (0600) kaydet; varsayılana dönüşte dosya içeriği boş kapsam olur."""
    path = _settings_path(environ)
    if path is None:
        raise ScopeError("Sniper veri dizini yapılandırılmamış.")
    data = json.dumps({"format": 1, "scope": scope.public()}, ensure_ascii=False, sort_keys=True).encode("utf-8")
    tmp = path.with_name(f".{FILE_NAME}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)
    return scope


def describe() -> dict[str, Any]:
    """Arayüz için seçenek açıklamaları."""
    return {
        "dir_groups": {name: {"label": DIR_GROUP_LABELS[name], "dirs": sorted(dirs)} for name, dirs in OPTIONAL_DIR_GROUPS.items()},
        "always_skipped": sorted(ALWAYS_SKIP_DIRS),
        "defaults": DEFAULT_SCOPE.public(),
        "maximums": FULL_SCOPE.public(),
    }
