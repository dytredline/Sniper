"""Yerel (çevrimdışı) OSV veritabanıyla çok ekosistemli bağımlılık eşlemesi (18. tur).

Neden: ``osv_active`` yalnız npm kilit dosyasını sabitlenmiş OSV-Scanner ikilisiyle sayar (bulgu döndürmez);
diğer ekosistemler (PyPI, Go, Maven, RubyGems, crates.io, Packagist, NuGet, Pub, Hex) çevrimdışı hiç
denetlenmiyordu. Bu modül:

* ``osv_db_refresh`` ile indirilmiş, manifesti yerel denetim anahtarıyla (HMAC) imzalı ya da npm için
  systemd pinine uyan arşivleri kullanır; arşivin SHA-256'sı manifestle eşleşmezse o ekosistem atlanır.
* Paket adı → kayıt dizinini (``package-index.json.gz``; güncelleme sırasında üretilir, SHA-256'sı imzalı
  manifesttedir) okur, yalnız ilgili kayıtları arşivden açar. Dizin yoksa (eski nesil) bellekte kurar.
* Sürümü OSV aralık semantiğine göre değerlendirir: SEMVER (npm, Go, crates.io, Pub, Hex), ECOSYSTEM
  (PEP 440, Maven ComparableVersion, RubyGems, NuGet, Composer) ve açık ``versions`` listeleri. GIT
  aralıkları kullanılmaz (sürüm bilgisi yok).
* Takma adlarla (PYSEC/GHSA/GO/CVE) aynı açığı tek bulguya indirir; Go'da sembol bilgisi taşıyan GO-
  kaydını temsilci seçer (VEX/erişilebilirlik ``ecosystem_specific.imports`` sembollerini kullanır).

Ağ yok, ikili çalıştırma yok, veri dizinine yazma yok; yalnız okunur.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import functools
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import threading
from typing import Any, Callable, Iterable
import zipfile

import audit_integrity
import osv_db_refresh

STALE_AFTER = timedelta(days=7)
MAX_INDEX_BYTES = 64 * 1024 * 1024
MAX_RECORD_BYTES = osv_db_refresh.MAX_MEMBER_BYTES
MAX_COMPONENTS = 20_000

# Envanterdeki ekosistem adları → OSV ekosistem adları.
OSV_ECOSYSTEM = {
    "pypi": "PyPI", "python": "PyPI", "pip": "PyPI",
    "npm": "npm", "node": "npm", "javascript": "npm",
    "golang": "Go", "go": "Go",
    "cargo": "crates.io", "crates.io": "crates.io", "rust": "crates.io",
    "maven": "Maven", "gradle": "Maven", "java": "Maven",
    "rubygems": "RubyGems", "gem": "RubyGems", "ruby": "RubyGems",
    "packagist": "Packagist", "composer": "Packagist", "php": "Packagist",
    "nuget": "NuGet", "dotnet": "NuGet",
    "pub": "Pub", "dart": "Pub",
    "hex": "Hex", "elixir": "Hex", "erlang": "Hex",
    "swift": "SwiftURL", "swiftpm": "SwiftURL", "swifturl": "SwiftURL",
    "github-actions": "GitHub Actions", "actions": "GitHub Actions", "github actions": "GitHub Actions",
}
SEMVER_ECOSYSTEMS = frozenset({"npm", "Go", "crates.io", "Pub", "Hex", "SwiftURL", "GitHub Actions"})


class OfflineDBError(Exception):
    """Kullanıcıya gösterilebilir, yol/sır içermeyen hata."""


def osv_ecosystem(name: str) -> str | None:
    return OSV_ECOSYSTEM.get(str(name or "").casefold())


# ---------------------------------------------------------------------------------------------
# Sürüm karşılaştırma
# ---------------------------------------------------------------------------------------------

def _cmp(a: Any, b: Any) -> int:
    return (a > b) - (a < b)


_SEMVER_RE = re.compile(r"^v?=?\s*(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$")


def _semver_key(version: str) -> tuple | None:
    match = _SEMVER_RE.match(version.strip().replace("+incompatible", ""))
    if not match:
        return None
    nums = tuple(int(match.group(i) or 0) for i in (1, 2, 3, 4))
    pre = match.group(5)
    if not pre:
        return nums + ((1,),)  # yayın sürümü ön sürümlerden büyüktür
    parts: list[tuple] = []
    for ident in pre.split("."):
        parts.append((0, int(ident), "") if ident.isdigit() else (1, 0, ident))
    return nums + ((0, tuple(parts)),)


def compare_semver(a: str, b: str) -> int:
    ka, kb = _semver_key(a), _semver_key(b)
    if ka is None or kb is None:
        return compare_generic(a, b)
    head = _cmp(ka[:4], kb[:4])
    if head:
        return head
    pa, pb = ka[4], kb[4]
    if pa[0] != pb[0]:
        return _cmp(pa[0], pb[0])
    if pa[0] == 1:
        return 0
    # Ön sürüm tanımlayıcıları: sayısal < alfasayısal; daha uzun liste (eşit önekte) büyüktür.
    return _cmp(pa[1], pb[1])


def _generic_key(version: str) -> list[tuple[int, Any]]:
    return [(1, int(t)) if t.isdigit() else (0, t) for t in re.findall(r"\d+|[a-z]+", version.lower())]


def compare_generic(a: str, b: str) -> int:
    return _cmp(_generic_key(a), _generic_key(b))


try:  # PEP 440 (sistemde packaging varsa)
    from packaging.version import InvalidVersion, Version as _PEP440Version
except Exception:  # pragma: no cover - packaging yoksa genel karşılaştırma
    _PEP440Version = None
    InvalidVersion = ValueError


def compare_pypi(a: str, b: str) -> int:
    if _PEP440Version is not None:
        try:
            return _cmp(_PEP440Version(a), _PEP440Version(b))
        except InvalidVersion:
            pass
    return compare_generic(a, b)


_MAVEN_QUALIFIERS = {"alpha": 0, "a": 0, "beta": 1, "b": 1, "milestone": 2, "m": 2, "rc": 3, "cr": 3,
                     "snapshot": 4, "": 5, "ga": 5, "final": 5, "release": 5, "sp": 6}
_MAVEN_RELEASE = (1, 5, "")


def _maven_key(version: str) -> list[tuple]:
    """Maven ComparableVersion'a yakın: sayılar, nitelendiriciler (alpha<beta<milestone<rc<snapshot<yayın<sp),
    sondaki ve nitelendiriciden önceki sıfırlar atılır (1.0.0-alpha == 1.0-alpha, 2.0.0.RELEASE == 2)."""
    tokens = re.findall(r"\d+|[a-z]+", version.lower())
    numbers: list[tuple] = []
    rest: list[tuple] = []
    seen_qualifier = False
    for token in tokens:
        if token.isdigit() and not seen_qualifier:
            numbers.append((2, int(token), ""))
            continue
        seen_qualifier = True
        if token.isdigit():
            rest.append((2, int(token), ""))
        else:
            rank = _MAVEN_QUALIFIERS.get(token)
            rest.append((1, rank, "") if rank is not None else (1, 7, token))
    while numbers and numbers[-1] == (2, 0, ""):
        numbers.pop()
    items = numbers + rest
    while items and items[-1] in ((2, 0, ""), _MAVEN_RELEASE):
        items.pop()
    return items


def compare_maven(a: str, b: str) -> int:
    ka, kb = _maven_key(a), _maven_key(b)
    for index in range(max(len(ka), len(kb))):
        x = ka[index] if index < len(ka) else _MAVEN_RELEASE
        y = kb[index] if index < len(kb) else _MAVEN_RELEASE
        if x != y:
            return _cmp(x, y)
    return 0


def _ruby_key(version: str) -> list[Any]:
    text = version.strip().lower().replace("-", ".pre.")
    segments: list[Any] = [int(t) if t.isdigit() else t for t in re.findall(r"\d+|[a-z]+", text)]
    # Gem::Version#canonical_segments: ön sürüm öncesindeki ve sondaki sıfırlar atılır.
    first_str = next((i for i, s in enumerate(segments) if isinstance(s, str)), len(segments))
    head, tail = segments[:first_str], segments[first_str:]
    while head and head[-1] == 0:
        head.pop()
    while tail and tail[-1] == 0:
        tail.pop()
    return head + tail


def compare_rubygems(a: str, b: str) -> int:
    ka, kb = _ruby_key(a), _ruby_key(b)
    for index in range(max(len(ka), len(kb))):
        x = ka[index] if index < len(ka) else 0
        y = kb[index] if index < len(kb) else 0
        if x == y:
            continue
        if isinstance(x, str) and isinstance(y, str):
            return _cmp(x, y)
        if isinstance(x, str):
            return -1  # harfli bölüm (ön sürüm) sayıdan küçüktür
        if isinstance(y, str):
            return 1
        return _cmp(x, y)
    return 0


def compare_nuget(a: str, b: str) -> int:
    def key(value: str) -> tuple | None:
        match = re.match(r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+.*)?$", value.strip())
        if not match:
            return None
        nums = tuple(int(match.group(i) or 0) for i in (1, 2, 3, 4))
        pre = match.group(5)
        if not pre:
            return nums + ((1, ()),)
        return nums + ((0, tuple((0, int(p), "") if p.isdigit() else (1, 0, p.lower()) for p in pre.split("."))),)
    ka, kb = key(a), key(b)
    if ka is None or kb is None:
        return compare_generic(a, b)
    return _cmp(ka, kb)


_COMPOSER_STABILITY = {"dev": 0, "alpha": 1, "a": 1, "beta": 2, "b": 2, "rc": 3, "": 4, "stable": 4,
                       "patch": 5, "pl": 5, "p": 5}


def compare_packagist(a: str, b: str) -> int:
    def key(value: str) -> tuple | None:
        text = value.strip().lower()
        if text.startswith("dev-") or text.endswith("-dev") and not re.match(r"^v?\d", text):
            return None
        match = re.match(r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?[._-]?([a-z]*)\.?(\d*)$", text)
        if not match:
            return None
        nums = tuple(int(match.group(i) or 0) for i in (1, 2, 3, 4))
        stability = _COMPOSER_STABILITY.get(match.group(5) or "")
        if stability is None:
            return None
        return nums + (stability, int(match.group(6) or 0))
    ka, kb = key(a), key(b)
    if ka is None or kb is None:
        return compare_generic(a, b)
    return _cmp(ka, kb)


ECOSYSTEM_COMPARATORS: dict[str, Callable[[str, str], int]] = {
    "PyPI": compare_pypi, "Maven": compare_maven, "RubyGems": compare_rubygems, "NuGet": compare_nuget,
    "Packagist": compare_packagist, "npm": compare_semver, "Go": compare_semver, "crates.io": compare_semver,
    "Pub": compare_semver, "Hex": compare_semver, "SwiftURL": compare_semver, "GitHub Actions": compare_semver,
}


def comparator(ecosystem: str, range_type: str) -> Callable[[str, str], int] | None:
    if range_type == "GIT":
        return None
    if range_type == "SEMVER":
        return compare_semver
    return ECOSYSTEM_COMPARATORS.get(ecosystem, compare_generic)


_RUBY_PLATFORM = re.compile(r"^(.+?)-(?:x86_64|x86|x64|aarch64|arm64|arm|universal|java|jruby|mingw\w*|mswin\w*|"
                            r"darwin|linux|i386|i686|powerpc\w*|ppc64le|s390x|wasm\w*)(?:[-.].*)?$")


def normalize_version(ecosystem: str, version: str) -> str:
    value = str(version or "").strip()
    if ecosystem == "Go":
        value = value.removeprefix("v").replace("+incompatible", "")
    elif ecosystem == "RubyGems":
        # Gemfile.lock platform sürümleri (nokogiri 1.19.0-x86_64-linux-gnu): platform eki ön sürüm değildir.
        match = _RUBY_PLATFORM.match(value)
        if match:
            value = match.group(1)
    return value


def concrete_version(ecosystem: str, version: str) -> bool:
    """Aralık ya da yer tutucu değil, tek bir sürüm mü? (``^1.2``, ``${spring.version}``, boş → hayır)"""
    value = str(version or "").strip()
    if not value or any(ch in value for ch in "^~<>=*$|, {}()[]") or value.lower() in {"latest", "x"}:
        return False
    return bool(re.match(r"^v?\d", value))


def _event_version(event: dict[str, Any]) -> tuple[str, str] | None:
    for kind in ("introduced", "fixed", "last_affected", "limit"):
        value = event.get(kind)
        if isinstance(value, str) and value:
            return kind, value
    return None


def range_affects(version: str, events: Iterable[dict[str, Any]], cmp: Callable[[str, str], int]) -> bool:
    """OSV aralık değerlendirmesi (şema belgesindeki algoritma; olaylar sürüme göre sıralanır)."""
    parsed = [ev for ev in (_event_version(e) for e in events if isinstance(e, dict)) if ev]
    if not parsed:
        return False

    def order(x: tuple[str, str], y: tuple[str, str]) -> int:
        if x[1] == "0" and x[0] == "introduced":
            return -1 if not (y[1] == "0" and y[0] == "introduced") else 0
        if y[1] == "0" and y[0] == "introduced":
            return 1
        return cmp(x[1], y[1])

    affected = False
    for kind, value in sorted(parsed, key=functools.cmp_to_key(order)):
        if kind == "introduced":
            if value == "0" or cmp(version, value) >= 0:
                affected = True
        elif kind == "fixed":
            if cmp(version, value) >= 0:
                affected = False
        elif kind == "last_affected":
            if cmp(version, value) > 0:
                affected = False
        elif kind == "limit":
            if cmp(version, value) >= 0:
                affected = False
    return affected


def _versions_equal(ecosystem: str, a: str, b: str) -> bool:
    if a == b:
        return True
    if ecosystem == "PyPI" and _PEP440Version is not None:
        try:
            return _PEP440Version(a) == _PEP440Version(b)
        except InvalidVersion:
            return False
    if ecosystem == "Go":
        return normalize_version("Go", a) == normalize_version("Go", b)
    return False


def affected_entry_matches(ecosystem: str, version: str, entry: dict[str, Any]) -> bool:
    versions = entry.get("versions")
    if isinstance(versions, list) and any(isinstance(v, str) and _versions_equal(ecosystem, version, v) for v in versions):
        return True
    for range_item in entry.get("ranges") or []:
        if not isinstance(range_item, dict):
            continue
        cmp = comparator(ecosystem, str(range_item.get("type") or ""))
        if cmp is None:
            continue
        try:
            if range_affects(version, range_item.get("events") or [], cmp):
                return True
        except (TypeError, ValueError):
            continue
    return False


# ---------------------------------------------------------------------------------------------
# Önem
# ---------------------------------------------------------------------------------------------

# ---------------------------------------------------------------------------------------------
# Kötü amaçlı paketler (20. tur): OpenSSF malicious-packages kayıtları (MAL-…) açık değil, ele geçirilmiş/zararlı
# paket bildirir. Ayrı bir sınıf olarak kritik raporlanır (CWE-506); çoğu "introduced: 0" ile tüm sürümleri kapsar.
# ---------------------------------------------------------------------------------------------

MALICIOUS_PREFIX = "MAL-"
MALICIOUS_CWE = "CWE-506"


_MALWARE_SUMMARY = re.compile(
    r"^\s*(?:embedded\s+)?(?:malware|malicious\s+(?:code|package)|typosquat(?:ting)?(?:\s+package)?|credential\s+stealer|crypto(?:currency)?\s+stealer|protestware)\s+in\b|\bembedded\s+malware\b",
    re.I,
)


def is_malicious_record(record: dict[str, Any]) -> bool:
    """OpenSSF MAL- kaydı ya da GitHub "malware" danışması (CWE-506 / "Malware in …" özeti; ör. ua-parser-js 0.7.29,
    event-stream, ctx). Yalnız "malicious code execution" gibi açık anlatımları yakalamamak için özet kalıbı dardır."""
    ids = [record.get("id"), *(record.get("aliases") or [])]
    if any(isinstance(i, str) and i.startswith(MALICIOUS_PREFIX) for i in ids):
        return True
    database_specific = record.get("database_specific")
    cwes = database_specific.get("cwe_ids") if isinstance(database_specific, dict) else None
    if isinstance(cwes, list) and MALICIOUS_CWE in cwes:
        return True
    return bool(_MALWARE_SUMMARY.search(str(record.get("summary") or "")))


_SEVERITY_WORDS = {"critical": "critical", "high": "high", "moderate": "medium", "medium": "medium", "low": "low"}


def record_severity(record: dict[str, Any]) -> str:
    db_specific = record.get("database_specific")
    word = str((db_specific or {}).get("severity") or "").casefold() if isinstance(db_specific, dict) else ""
    if word in _SEVERITY_WORDS:
        return _SEVERITY_WORDS[word]
    best: float | None = None
    for item in record.get("severity") or []:
        if not isinstance(item, dict):
            continue
        vector = str(item.get("score") or "")
        score: float | None = None
        try:
            if vector.startswith("CVSS:3"):
                from risk import calculate_cvss31
                _vec, score = calculate_cvss31("CVSS:3.1/" + vector.split("/", 1)[1])
            elif vector.startswith("CVSS:4.0"):
                from cvss40 import compute_cvss40
                score = compute_cvss40(vector)["score"]
        except (ValueError, KeyError, IndexError, TypeError):
            score = None
        if score is not None and (best is None or score > best):
            best = score
    if best is None:
        return "unknown"
    if best >= 9.0:
        return "critical"
    if best >= 7.0:
        return "high"
    if best >= 4.0:
        return "medium"
    if best > 0:
        return "low"
    return "info"


# ---------------------------------------------------------------------------------------------
# Güvenilir veritabanı ve dizin
# ---------------------------------------------------------------------------------------------

_DIGESTS: dict[str, tuple[tuple[int, int, int, int, int], str]] = {}
_INDEXES: dict[str, dict[str, list[str]]] = {}
_LOCK = threading.Lock()


def _sha256_file(path: Path) -> str:
    """Kimliği (dev, ino, boyut, mtime, ctime) değişmeyen dosya için önbellekli SHA-256."""
    with path.open("rb") as stream:
        info = os.fstat(stream.fileno())
        identity = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        with _LOCK:
            cached = _DIGESTS.get(str(path))
        if cached and cached[0] == identity:
            return cached[1]
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    with _LOCK:
        if len(_DIGESTS) > 64:
            _DIGESTS.clear()
        _DIGESTS[str(path)] = (identity, digest)
    return digest


def _manifest_trusted(ecosystem: str, path: Path, manifest: dict[str, Any]) -> bool:
    if audit_integrity.verify_document_mac(audit_integrity.load_key(create=False),
                                           osv_db_refresh.MANIFEST_MAC_LABEL, manifest):
        return True
    # npm manifesti systemd'de SHA-256 ile de sabitlenebilir (osv_active ile aynı güven yolu).
    pin = os.environ.get("SNIPER_OSV_DB_MANIFEST_SHA256", "")
    if ecosystem == "npm" and re.fullmatch(r"[0-9a-f]{64}", pin or ""):
        try:
            return hashlib.sha256(path.read_bytes()).hexdigest() == pin
        except OSError:
            return False
    return False


def _inside(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


class TrustedDB:
    def __init__(self, ecosystem: str, root: Path, manifest: dict[str, Any], archive: Path, stale: bool):
        self.ecosystem = ecosystem
        self.root = root
        self.manifest = manifest
        self.archive = archive
        self.stale = stale
        self.sha256 = str(manifest["sha256"])
        self.retrieved_utc = str(manifest.get("retrieved_utc") or "")

    def index(self) -> dict[str, list[str]]:
        with _LOCK:
            cached = _INDEXES.get(self.sha256)
        if cached is not None:
            return cached
        index = self._read_index() if self.manifest.get("package_index_sha256") else None
        if index is None:
            index = build_index_from_archive(self.archive, self.ecosystem)
        with _LOCK:
            if len(_INDEXES) > 16:
                _INDEXES.clear()
            _INDEXES[self.sha256] = index
        return index

    def _read_index(self) -> dict[str, list[str]] | None:
        path = self.archive.parent / osv_db_refresh.INDEX_FILENAME
        try:
            if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_INDEX_BYTES:
                return None
            raw = path.read_bytes()
        except OSError:
            return None
        if hashlib.sha256(raw).hexdigest() != self.manifest.get("package_index_sha256"):
            raise OfflineDBError(f"{self.ecosystem}: paket dizini imzalı manifestle uyuşmuyor.")
        try:
            document = json.loads(gzip.decompress(raw).decode("utf-8"))
        except (OSError, ValueError, UnicodeDecodeError, EOFError):
            raise OfflineDBError(f"{self.ecosystem}: paket dizini okunamadı.") from None
        packages = document.get("packages") if isinstance(document, dict) else None
        if (not isinstance(packages, dict) or document.get("format") != osv_db_refresh.INDEX_FORMAT
                or document.get("db_sha256") != self.sha256):
            raise OfflineDBError(f"{self.ecosystem}: paket dizini biçimi geçersiz.")
        return packages

    def open(self) -> zipfile.ZipFile:
        """Arşivi bir kez aç (npm arşivinin merkezi dizini ~230 bin girdi: bileşen başına açmak çok yavaş)."""
        return zipfile.ZipFile(self.archive)

    @staticmethod
    def records(archive: zipfile.ZipFile, members: Iterable[str]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for name in members:
            try:
                info = archive.getinfo(name)
            except KeyError:
                continue
            if info.file_size > MAX_RECORD_BYTES:
                continue
            try:
                record = json.loads(archive.read(info).decode("utf-8"))
            except (ValueError, UnicodeDecodeError, zipfile.BadZipFile, OSError):
                continue
            if isinstance(record, dict) and not record.get("withdrawn"):
                out.append(record)
        return out


def build_index_from_archive(archive_path: Path, ecosystem: str) -> dict[str, list[str]]:
    """Eski nesillerde dizin yoksa: arşivi bir kez okuyup bellekte ad → kayıt dizini kur."""
    index: dict[str, list[str]] = {}
    with zipfile.ZipFile(archive_path) as archive:
        for info in archive.infolist():
            if info.file_size > MAX_RECORD_BYTES or not info.filename.endswith(".json"):
                continue
            try:
                record = json.loads(archive.read(info).decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                continue
            osv_db_refresh.add_to_index(index, ecosystem, info.filename, record)
    return index


def load_db(ecosystem: str, *, root: Path | None = None, now: datetime | None = None) -> TrustedDB:
    """İmzalı (ya da npm için sabitli) manifeste ve arşiv özetine güvenilen etkin nesil."""
    root = (root or osv_db_refresh.default_root()).expanduser()
    path = osv_db_refresh.manifest_path(root, ecosystem)
    try:
        manifest = osv_db_refresh.read_manifest(path)
    except osv_db_refresh.OSVRefreshError as exc:
        raise OfflineDBError(f"{ecosystem}: {exc}") from None
    if manifest is None:
        raise OfflineDBError(f"{ecosystem}: çevrimdışı veritabanı yok.")
    if not _manifest_trusted(ecosystem, path, manifest):
        raise OfflineDBError(f"{ecosystem}: manifest imzası doğrulanamadı.")
    try:
        archive = Path(str(manifest["scanner_cache_path"]))
        expected = str(manifest["sha256"])
        size = manifest["bytes"]
        retrieved = datetime.fromisoformat(str(manifest["retrieved_utc"]))
    except (KeyError, TypeError, ValueError):
        raise OfflineDBError(f"{ecosystem}: manifest alanları geçersiz.") from None
    if (manifest.get("ecosystem") != ecosystem or manifest.get("network") != "none"
            or manifest.get("zip_test") != "PASS" or retrieved.tzinfo is None
            or not re.fullmatch(r"[0-9a-f]{64}", expected) or type(size) is not int or size <= 0):
        raise OfflineDBError(f"{ecosystem}: manifest güvenilir değil.")
    generations = (root / "generations").resolve()
    if (not archive.is_absolute() or archive.parts[-3:] != ("osv-scalibr", ecosystem, "all.zip")
            or not _inside(archive.resolve(), generations)):
        raise OfflineDBError(f"{ecosystem}: arşiv yolu beklenen nesil dizininde değil.")
    try:
        if any(part.is_symlink() for part in (archive, *archive.parents) if _inside(part, root)):
            raise OfflineDBError(f"{ecosystem}: arşiv yolunda sembolik bağ var.")
        info = archive.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_size != size or _sha256_file(archive) != expected:
            raise OfflineDBError(f"{ecosystem}: arşiv SHA-256 değeri manifestle uyuşmuyor.")
    except OSError:
        raise OfflineDBError(f"{ecosystem}: arşiv okunamadı.") from None
    current = now or datetime.now(timezone.utc)
    return TrustedDB(ecosystem, root, manifest, archive, stale=current - retrieved > STALE_AFTER)


def database_status(*, root: Path | None = None, now: datetime | None = None) -> list[dict[str, Any]]:
    """Arayüz ve sağlık panosu için ekosistem başına veritabanı durumu (güven denetimiyle)."""
    root = (root or osv_db_refresh.default_root()).expanduser()
    out: list[dict[str, Any]] = []
    for ecosystem in osv_db_refresh.known_ecosystems(root):
        item: dict[str, Any] = {"ecosystem": ecosystem}
        try:
            db = load_db(ecosystem, root=root, now=now)
        except OfflineDBError as exc:
            item.update({"status": "missing" if "yok" in str(exc) else "untrusted", "detail": str(exc)})
        else:
            manifest = db.manifest
            item.update({
                "status": "stale" if db.stale else "ok",
                "retrieved_utc": db.retrieved_utc,
                "bytes": manifest.get("bytes"),
                "records": manifest.get("zip_members"),
                "generation": manifest.get("generation"),
                "indexed": bool(manifest.get("package_index_sha256")),
            })
        out.append(item)
    return out


# ---------------------------------------------------------------------------------------------
# Eşleme
# ---------------------------------------------------------------------------------------------

def _alias_groups(records: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    parent: dict[str, str] = {}

    def find(x: str) -> str:
        while parent.setdefault(x, x) != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for record in records:
        ids = [str(record.get("id"))] + [a for a in record.get("aliases") or [] if isinstance(a, str)]
        for other in ids[1:]:
            parent[find(other)] = find(ids[0])
        find(ids[0])
    groups: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        groups.setdefault(find(str(record.get("id"))), []).append(record)
    return list(groups.values())


def _representative(group: list[dict[str, Any]], package_name: str) -> dict[str, Any]:
    def has_symbols(record: dict[str, Any]) -> bool:
        for item in record.get("affected") or []:
            if isinstance(item, dict) and ((item.get("ecosystem_specific") or {}).get("imports")):
                return True
        return False

    def rank(record: dict[str, Any]) -> tuple:
        rid = str(record.get("id"))
        return (not has_symbols(record), not rid.startswith("GHSA-"), record_severity(record) == "unknown", rid)

    return sorted(group, key=rank)[0]


def _merge_group(group: list[dict[str, Any]], package_name: str, ecosystem: str) -> dict[str, Any]:
    malicious = any(is_malicious_record(r) for r in group)
    mal_records = sorted((r for r in group if str(r.get("id") or "").startswith(MALICIOUS_PREFIX)),
                         key=lambda r: str(r.get("id")))
    # Kötü amaçlı grupta temsilci MAL- kaydıdır (kimlik önekinden ayırt edilir; GHSA "malware" kaydı takma ad olur).
    chosen = mal_records[0] if mal_records else _representative(group, package_name)
    severities = [record_severity(r) for r in group]
    order = ["critical", "high", "medium", "low", "info", "unknown"]
    severity = "critical" if malicious else (min(severities, key=order.index) if severities else "unknown")
    aliases = sorted({a for r in group for a in [r.get("id"), *(r.get("aliases") or [])] if isinstance(a, str)}
                     - {chosen.get("id")})
    references: list[Any] = []
    seen_urls: set[str] = set()
    for record in [chosen] + [r for r in group if r is not chosen]:
        for ref in record.get("references") or []:
            url = ref.get("url") if isinstance(ref, dict) else None
            if isinstance(url, str) and url not in seen_urls:
                seen_urls.add(url)
                references.append(ref)
    summary = next((str(r.get("summary")) for r in [chosen, *group] if r.get("summary")), "")
    details = next((str(r.get("details")) for r in [chosen, *group] if r.get("details")), "")
    affected = [item for r in group for item in r.get("affected") or []
                if isinstance(item, dict) and osv_db_refresh.package_key(
                    ecosystem, str((item.get("package") or {}).get("name") or "")) == osv_db_refresh.package_key(ecosystem, package_name)]
    return {
        "id": chosen.get("id"),
        "aliases": aliases,
        "summary": summary[:500],
        "details": details[:8000],
        "references": references[:50],
        "database_specific": ({"severity": severity, "malicious": True, "cwe_ids": [MALICIOUS_CWE]}
                              if malicious else {"severity": severity}),
        "affected": affected[:20],
    }


def match_components(components: list[dict[str, str]], *, root: Path | None = None,
                     now: datetime | None = None) -> dict[str, Any]:
    """Envanter bileşenlerini yerel OSV ile eşle; OSV-Scanner JSON biçimine yakın belge + kapsam döndür."""
    if len(components) > MAX_COMPONENTS:
        raise OfflineDBError("Bileşen sayısı güvenli sınırı aşıyor.")
    by_eco: dict[str, list[dict[str, str]]] = {}
    skipped = {"unsupported_ecosystem": 0, "no_concrete_version": 0}
    for component in components:
        ecosystem = osv_ecosystem(component.get("ecosystem", ""))
        if ecosystem is None:
            skipped["unsupported_ecosystem"] += 1
            continue
        if not concrete_version(ecosystem, component.get("version", "")):
            skipped["no_concrete_version"] += 1
            continue
        by_eco.setdefault(ecosystem, []).append(component)
    packages_out: list[dict[str, Any]] = []
    coverage: list[dict[str, Any]] = []
    warnings: list[str] = []
    retrieved: list[str] = []
    for ecosystem in sorted(by_eco):
        items = by_eco[ecosystem]
        entry: dict[str, Any] = {"ecosystem": ecosystem, "components": len(items)}
        try:
            db = load_db(ecosystem, root=root, now=now)
            index = db.index()
        except OfflineDBError as exc:
            entry.update({"status": "unavailable", "detail": str(exc)})
            warnings.append(f"{exc} {len(items)} bileşen denetlenmedi.")
            coverage.append(entry)
            continue
        if db.stale:
            warnings.append(f"{ecosystem}: çevrimdışı veritabanı 7 günden eski; yeni açıklar eksik olabilir.")
        retrieved.append(db.retrieved_utc)
        affected_packages = 0
        vuln_total = 0
        try:
            archive = db.open()
        except (OSError, zipfile.BadZipFile):
            entry.update({"status": "unavailable", "detail": f"{ecosystem}: arşiv açılamadı."})
            warnings.append(f"{ecosystem}: arşiv açılamadı; {len(items)} bileşen denetlenmedi.")
            coverage.append(entry)
            continue
        with archive:
            affected_packages, vuln_total = _match_ecosystem(ecosystem, items, index, archive, packages_out)
        entry.update({"status": "stale" if db.stale else "ok", "db_retrieved_utc": db.retrieved_utc,
                      "db_sha256": db.sha256, "affected_packages": affected_packages, "vulnerabilities": vuln_total})
        coverage.append(entry)
    return {
        "document": {"results": [{"source": {"path": "sniper-offline-inventory", "type": "inventory"},
                                  "packages": packages_out}]},
        "coverage": coverage,
        "skipped": skipped,
        "warnings": warnings,
        "oldest_db_retrieved_utc": min(retrieved) if retrieved else "",
    }


def _match_ecosystem(ecosystem: str, items: list[dict[str, str]], index: dict[str, list[str]],
                     archive: zipfile.ZipFile, packages_out: list[dict[str, Any]]) -> tuple[int, int]:
    affected_packages = 0
    vuln_total = 0
    cache: dict[str, list[dict[str, Any]]] = {}
    seen: set[tuple[str, str]] = set()
    for component in items:
        name = component["name"]
        version = normalize_version(ecosystem, component["version"])
        key = osv_db_refresh.package_key(ecosystem, name)
        if (key, version) in seen:  # aynı paket/sürüm (ör. Ruby platform kopyaları) tek kez raporlanır
            continue
        seen.add((key, version))
        members = index.get(key) or []
        if not members:
            continue
        if key not in cache:  # aynı paketin birden çok sürümü (npm) kayıtları bir kez okur
            cache[key] = TrustedDB.records(archive, members)
        matched: list[dict[str, Any]] = []
        for record in cache[key]:
            for item in record.get("affected") or []:
                if not isinstance(item, dict):
                    continue
                package = item.get("package") or {}
                if osv_db_refresh.base_ecosystem(str(package.get("ecosystem") or "")) != ecosystem:
                    continue
                if osv_db_refresh.package_key(ecosystem, str(package.get("name") or "")) != osv_db_refresh.package_key(ecosystem, name):
                    continue
                if affected_entry_matches(ecosystem, version, item):
                    matched.append(record)
                    break
        if not matched:
            continue
        vulnerabilities = [_merge_group(group, name, ecosystem) for group in _alias_groups(matched)]
        # kötü amaçlı kayıt önce gelir (paket başına ilk satır en acil eylemi gösterir)
        vulnerabilities.sort(key=lambda v: (not (v.get("database_specific") or {}).get("malicious"), str(v.get("id"))))
        affected_packages += 1
        vuln_total += len(vulnerabilities)
        packages_out.append({
            "package": {"name": name, "version": version if ecosystem == "RubyGems" else component["version"],
                        "ecosystem": ecosystem,
                        "manifest": component.get("manifest", "")},
            "vulnerabilities": vulnerabilities,
        })
    return affected_packages, vuln_total


_MALWARE_CACHE: dict[str, dict[str, list[str]]] = {}


def _malware_members(db: "TrustedDB", archive: zipfile.ZipFile, index: dict[str, list[str]]) -> dict[str, list[str]]:
    """MAL- dışındaki "malware" danışmaları (GHSA CWE-506 vb.): paket → üye listesi. Veritabanı özeti başına bir kez
    hesaplanır (MAL- olmayan kayıtlar bir kez okunur) ve bellekte tutulur."""
    with _LOCK:
        cached = _MALWARE_CACHE.get(db.sha256)
    if cached is not None:
        return cached
    disk = _malware_disk_cache_load(db.sha256)
    if disk is not None:
        with _LOCK:
            _MALWARE_CACHE[db.sha256] = disk
        return disk
    out: dict[str, list[str]] = {}
    for key, members in index.items():
        for member in members:
            if Path(member).name.startswith(MALICIOUS_PREFIX):
                continue
            for record in TrustedDB.records(archive, [member]):
                if is_malicious_record(record):
                    out.setdefault(key, []).append(member)
    with _LOCK:
        if len(_MALWARE_CACHE) > 32:
            _MALWARE_CACHE.clear()
        _MALWARE_CACHE[db.sha256] = out
    _malware_disk_cache_store(db.sha256, out)
    return out


def _malware_cache_dir() -> Path | None:
    """Önbellek dizini: veri dizini varsa ``<veri>/cache``; yoksa (CLI / CI çalıştırması, 23. tur)
    ``SNIPER_CACHE_HOME`` ya da ``$XDG_CACHE_HOME/sniper`` ya da ``~/.cache/sniper``. ``SNIPER_CACHE_HOME=""`` yedeği
    kapatır (testler). Sembolik bağ olan dizin kullanılmaz."""
    base = os.environ.get("SNIPER_DATA_DIR", "").strip()
    if base:
        return Path(base) / "cache"
    if "SNIPER_CACHE_HOME" in os.environ:
        override = os.environ["SNIPER_CACHE_HOME"].strip()
        return Path(override) if override else None
    xdg = os.environ.get("XDG_CACHE_HOME", "").strip()
    root = Path(xdg) if xdg and os.path.isabs(xdg) else Path.home() / ".cache"
    return root / "sniper"


def _malware_cache_path(sha256: str) -> Path | None:
    """20. tur: malware dizini disk önbelleği (iş kuyruğunun her alt sürecinde ve CI çalıştırmalarında arşivi yeniden
    taramamak için). Anahtar doğrulanmış arşivin SHA-256'sıdır; arşiv değişince yeni dosya kullanılır."""
    directory = _malware_cache_dir()
    if directory is None or not re.fullmatch(r"[0-9a-f]{64}", sha256 or ""):
        return None
    return directory / f"osv-malware-{sha256[:32]}.json"


def _malware_disk_cache_load(sha256: str) -> dict[str, list[str]] | None:
    path = _malware_cache_path(sha256)
    if path is None or not path.is_file() or path.is_symlink():
        return None
    try:
        info = path.stat()
    except OSError:
        return None
    if info.st_uid != os.getuid() or info.st_mode & 0o022:
        return None  # başkasının yazabildiği önbellek kötü amaçlı paket tespitini susturmak için kullanılamaz
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or data.get("sha256") != sha256 or not isinstance(data.get("members"), dict):
        return None
    members = data["members"]
    if not all(isinstance(k, str) and isinstance(v, list) and all(isinstance(m, str) for m in v) for k, v in members.items()):
        return None
    return members


def _malware_disk_cache_store(sha256: str, members: dict[str, list[str]]) -> None:
    path = _malware_cache_path(sha256)
    if path is None:
        return
    try:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if path.parent.is_symlink():
            return  # bağ üzerinden başka bir yere yazma
        if path.parent.stat().st_uid == os.getuid() and path.parent.stat().st_mode & 0o077:
            os.chmod(path.parent, 0o700)  # yalnız sahibi okuyabilsin
        tmp = path.with_name(path.name + f".{os.getpid()}.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump({"sha256": sha256, "members": members}, handle, separators=(",", ":"))
        os.replace(tmp, path)
    except OSError:
        pass  # önbellek yazılamazsa yalnız hız kaybı


def malicious_components(components: list[dict[str, str]], *, root: Path | None = None,
                         now: datetime | None = None) -> dict[str, Any]:
    """Yalnız kötü amaçlı paket (MAL-) eşleşmesi: dizinde MAL- üyesi olan paketlerin kayıtları okunur (hızlı yol;
    proje analizi bunu kullanır). Dönen: {"matches": [...], "checked_ecosystems": [...], "warnings": [...]}.
    Veritabanı yoksa ya da güvenilmezse ilgili ekosistem atlanır ve uyarı döner; ağ yok."""
    by_eco: dict[str, list[dict[str, str]]] = {}
    for component in components[:MAX_COMPONENTS]:
        ecosystem = osv_ecosystem(component.get("ecosystem", ""))
        if ecosystem is None or not concrete_version(ecosystem, component.get("version", "")):
            continue
        by_eco.setdefault(ecosystem, []).append(component)
    matches: list[dict[str, Any]] = []
    checked: list[str] = []
    warnings: list[str] = []
    for ecosystem in sorted(by_eco):
        try:
            db = load_db(ecosystem, root=root, now=now)
            index = db.index()
        except OfflineDBError as exc:
            warnings.append(str(exc))
            continue
        # Arşivi açmak pahalı (npm merkezi dizini ~230 bin girdi): yalnız malware dizini önbellekte yoksa ya da aday
        # varsa açılır.
        archive: zipfile.ZipFile | None = None
        with _LOCK:
            malware = _MALWARE_CACHE.get(db.sha256)
        try:
            if malware is None:
                archive = db.open()
                malware = _malware_members(db, archive, index)
            candidates = []
            for component in by_eco[ecosystem]:
                key = osv_db_refresh.package_key(ecosystem, component["name"])
                members = [m for m in index.get(key) or [] if Path(m).name.startswith(MALICIOUS_PREFIX)]
                members += [m for m in malware.get(key, ()) if m not in members]
                if members:
                    candidates.append((component, key, members))
            checked.append(ecosystem)
            if not candidates:
                if archive is not None:
                    archive.close()
                continue
            if archive is None:
                archive = db.open()
        except (OSError, zipfile.BadZipFile):
            if archive is not None:
                archive.close()
            warnings.append(f"{ecosystem}: arşiv açılamadı.")
            continue
        seen: set[tuple[str, str, str]] = set()
        with archive:
            for component, key, members in candidates:
                version = normalize_version(ecosystem, component["version"])
                for record in TrustedDB.records(archive, members):
                    for item in record.get("affected") or []:
                        if not isinstance(item, dict):
                            continue
                        package = item.get("package") or {}
                        if osv_db_refresh.package_key(ecosystem, str(package.get("name") or "")) != key:
                            continue
                        if affected_entry_matches(ecosystem, version, item):
                            ident = (key, version, str(record.get("id")))
                            fixed = sorted({str(e["fixed"]) for r in item.get("ranges") or [] if isinstance(r, dict)
                                            for e in r.get("events") or [] if isinstance(e, dict) and e.get("fixed")})
                            if ident not in seen:
                                seen.add(ident)
                                matches.append({
                                    "fixed": fixed[:3],
                                    "ecosystem": ecosystem, "name": component["name"],
                                    "version": component["version"], "manifest": component.get("manifest", ""),
                                    "id": str(record.get("id")),
                                    "aliases": sorted(a for a in record.get("aliases") or [] if isinstance(a, str)),
                                    "summary": str(record.get("summary") or "")[:300],
                                })
                            break
    matches.sort(key=lambda m: (m["ecosystem"], m["name"], m["version"], m["id"]))
    return {"matches": matches, "checked_ecosystems": checked, "warnings": warnings}


def scan_project(project_path: str, *, allowed_roots: tuple[Path, ...] | None = None,
                 root: Path | None = None, now: datetime | None = None) -> dict[str, Any]:
    """Proje envanterini yerel OSV ile eşle ve ``Store.import_dependency_findings`` biçiminde rapor üret."""
    from dependency_security import discover_inventory, parse_osv

    inventory_warnings: list[str] = []
    project_root, components, _skipped = discover_inventory(project_path, allowed_roots=allowed_roots, lenient=True,
                                                            warnings=inventory_warnings)
    result = match_components(components, root=root, now=now)
    result["warnings"] = inventory_warnings[:50] + result["warnings"]
    findings = parse_osv(result["document"], str(project_root))
    canonical = json.dumps(result["document"], ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    ecosystems = ",".join(c["ecosystem"] for c in result["coverage"] if c.get("status") in ("ok", "stale"))
    timestamp = result["oldest_db_retrieved_utc"] or (now or datetime.now(timezone.utc)).isoformat()
    return {
        "source": "osv",
        "source_path": f"osv-offline:{ecosystems or '-'}",
        "source_timestamp": timestamp,
        "document_hash": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        "project_path": str(project_root),
        "findings": findings,
        "coverage": result["coverage"],
        "skipped": result["skipped"],
        "warnings": result["warnings"],
        "component_count": len(components),
    }
