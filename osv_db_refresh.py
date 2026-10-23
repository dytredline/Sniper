"""OSV çevrimdışı zafiyet veritabanının elle tetiklenen, doğrulamalı güncellemesi.

Kaynak yalnız resmi OSV deposudur: https://osv-vulnerabilities.storage.googleapis.com/<ekosistem>/all.zip
(HTTPS, sistem CA'larıyla sertifika ve ana bilgisayar adı doğrulaması, yönlendirme yok).

Güvenlik önlemleri:
* İndirme bayt ve süre sınırlı; Content-Length ve (varsa) GCS ``x-goog-hash: md5`` doğrulanır.
* Zip: girdi sayısı, girdi başına ve toplam açılmış boyut, sıkıştırma oranı sınırı; şifreli girdi,
  dizin, alt yol, ``..``, mutlak yol, yinelenen ad ve desteklenmeyen sıkıştırma reddedilir.
  Arşiv diske açılmaz; her girdi bellekte sınırlı okunur, CRC zipfile tarafından denetlenir.
* Her girdi OSV şemasının asgari alanlarına göre denetlenir (id = dosya adı, modified, affected...).
* Yeni nesil ayrı bir dizine yazılır; manifest (sha256, bayt, zaman, kaynak URL, md5 sonucu) geçici
  dosyadan ``os.replace`` ile atomik değişir. Önceki nesil bir kez saklanır, daha eskiler silinir.
* Yerel denetim anahtarı (audit_integrity) kullanılabiliyorsa manifest HMAC ile imzalanır; böylece
  osv_active, systemd'deki manifest SHA-256 pini eskidiğinde de yeniden başlatma gerekmeden yeni
  manifeste güvenebilir.

Bu modül tarama yapmaz; yalnız veri dosyası indirir.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import fcntl
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import ssl
import stat
import time
from typing import Any, Callable
import urllib.error
import urllib.parse
import urllib.request
import zipfile

import audit_integrity

SOURCE_BASE = "https://osv-vulnerabilities.storage.googleapis.com"
SOURCE_HOST = "osv-vulnerabilities.storage.googleapis.com"
MANIFEST_MAC_LABEL = "osv-offline-manifest-v1"
NPM_SCHEMA = "SNIPER_OSV_NPM_OFFLINE_DB_V2"
GENERIC_SCHEMA = "SNIPER_OSV_OFFLINE_DB_V2"

DEFAULT_MAX_DOWNLOAD_BYTES = 1_000_000_000
DEFAULT_DEADLINE_SECONDS = 1_800
SOCKET_TIMEOUT_SECONDS = 60
MAX_MEMBERS = 1_000_000
MAX_MEMBER_BYTES = 32 * 1024 * 1024
MAX_TOTAL_UNCOMPRESSED = 8 * 1024 * 1024 * 1024
MAX_RATIO = 200
MAX_MANIFEST_BYTES = 65_536
_CHUNK = 1024 * 1024

# 18. tur: çok ekosistemli çevrimdışı tarama. Varsayılan liste ve ekosisteme göre indirme sınırı (bayt).
DEFAULT_ECOSYSTEMS = ("npm", "PyPI", "Go", "Maven", "RubyGems", "crates.io", "Packagist", "NuGet", "Pub", "Hex")
ECOSYSTEM_MAX_BYTES = {
    "npm": 1_000_000_000, "PyPI": 400_000_000, "Go": 200_000_000, "Maven": 200_000_000, "RubyGems": 100_000_000,
    "crates.io": 100_000_000, "Packagist": 200_000_000, "NuGet": 100_000_000, "Pub": 20_000_000, "Hex": 50_000_000,
}
CONFIG_FILENAME = "ecosystems.json"
INDEX_FILENAME = "package-index.json.gz"
INDEX_FORMAT = "sniper-osv-index/1"

_ECOSYSTEM_RE = re.compile(r"[A-Za-z][A-Za-z0-9.:_ -]{0,63}\Z")
_MEMBER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:+-]{0,250}\.json\Z")
_GENERATION_RE = re.compile(r"\d{8}T\d{6}Z-[0-9a-f]{12}\Z")


class OSVRefreshError(Exception):
    """Türkçe, kullanıcıya gösterilebilir güncelleme hatası (iç yol/sır içermez)."""


class OSVRefreshBusy(OSVRefreshError):
    pass


def default_root() -> Path:
    raw = os.environ.get("SNIPER_OSV_DB_ROOT", "").strip()
    return Path(raw).expanduser() if raw else Path.home() / ".local" / "state" / "sniper" / "osv-db"


def validate_ecosystem(ecosystem: str) -> str:
    if not isinstance(ecosystem, str) or not _ECOSYSTEM_RE.fullmatch(ecosystem) or ".." in ecosystem:
        raise OSVRefreshError("Geçersiz OSV ekosistem adı.")
    return ecosystem


def source_url(ecosystem: str) -> str:
    return f"{SOURCE_BASE}/{urllib.parse.quote(validate_ecosystem(ecosystem), safe='')}/all.zip"


def _slug(ecosystem: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", ecosystem.lower()).strip("-") or "eco"


def manifest_path(root: Path, ecosystem: str) -> Path:
    if ecosystem == "npm":
        return root / "NPM-OFFLINE-DB-MANIFEST-v2.json"
    return root / f"{_slug(ecosystem).upper()}-OFFLINE-DB-MANIFEST-v2.json"


def base_ecosystem(ecosystem: str) -> str:
    """``Debian:11`` → ``Debian``; OSV ekosistem adının sürüm/dağıtım eki atılır."""
    return str(ecosystem or "").split(":", 1)[0]


def package_key(ecosystem: str, name: str) -> str:
    """Dizin anahtarı: PyPI için PEP 503, diğerlerinde küçük harf (NuGet/Packagist/Maven büyük-küçük duyarsız)."""
    text = str(name or "").strip()
    if base_ecosystem(ecosystem) == "PyPI":
        return re.sub(r"[-_.]+", "-", text).lower()
    return text.lower()


def add_to_index(index: dict[str, list[str]], ecosystem: str, member: str, record: Any) -> None:
    """Kaydı, etkilediği (bu ekosistemdeki) her paket adının altına ekle."""
    if not isinstance(record, dict) or record.get("withdrawn"):
        return
    wanted = base_ecosystem(ecosystem)
    names: set[str] = set()
    for item in record.get("affected") or []:
        if not isinstance(item, dict):
            continue
        package = item.get("package") or {}
        if not isinstance(package, dict) or base_ecosystem(str(package.get("ecosystem") or "")) != wanted:
            continue
        name = package.get("name")
        if isinstance(name, str) and name:
            names.add(package_key(wanted, name))
    for key in names:
        bucket = index.setdefault(key, [])
        if member not in bucket:
            bucket.append(member)


def configured_ecosystems(root: Path | None = None, environ: dict[str, str] | None = None) -> list[str]:
    """Zamanlayıcının güncelleyeceği ekosistemler: SNIPER_OSV_ECOSYSTEMS (virgülle) > <kök>/ecosystems.json
    (``{"ecosystems": [...]}``) > varsayılan liste. Geçersiz adlar atlanır."""
    env = os.environ if environ is None else environ
    raw = str(env.get("SNIPER_OSV_ECOSYSTEMS", "") or "").strip()
    names: list[str] = []
    if raw:
        names = [part.strip() for part in raw.split(",") if part.strip()]
    else:
        config = (root or default_root()).expanduser() / CONFIG_FILENAME
        try:
            if config.is_file() and not config.is_symlink() and config.stat().st_size <= MAX_MANIFEST_BYTES:
                document = json.loads(config.read_text(encoding="utf-8"))
                value = document.get("ecosystems") if isinstance(document, dict) else None
                if isinstance(value, list):
                    names = [str(v) for v in value if isinstance(v, str)]
        except (OSError, ValueError, UnicodeDecodeError):
            names = []
    if not names:
        names = list(DEFAULT_ECOSYSTEMS)
    out: list[str] = []
    for name in names:
        try:
            valid = validate_ecosystem(name)
        except OSVRefreshError:
            continue
        if valid not in out:
            out.append(valid)
    return out


def known_ecosystems(root: Path | None = None) -> list[str]:
    """Yapılandırılmış ekosistemler + kökte manifesti bulunanlar (durum ekranı için)."""
    root = (root or default_root()).expanduser()
    names = configured_ecosystems(root)
    try:
        for child in sorted(root.glob("*-OFFLINE-DB-MANIFEST-v2.json")):
            manifest = read_manifest(child)
            eco = str((manifest or {}).get("ecosystem") or "")
            if eco and eco not in names:
                try:
                    names.append(validate_ecosystem(eco))
                except OSVRefreshError:
                    pass
    except (OSError, OSVRefreshError):
        pass
    return names


def _ensure_private_dir(path: Path) -> None:
    missing: list[Path] = []
    current = path
    while not current.exists() and current != current.parent:
        missing.append(current)
        current = current.parent
    for component in reversed(missing):
        try:
            component.mkdir(mode=0o700)
        except FileExistsError:
            pass
    info = os.lstat(path)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022:
        raise OSVRefreshError("OSV veri dizini güvensiz (sembolik bağ, başka sahip ya da grup/diğer yazabilir).")


# --- İndirme ------------------------------------------------------------------------------------

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401 - urllib arayüzü
        raise OSVRefreshError("OSV kaynağı yönlendirme döndürdü; yönlendirme izlenmez.")


def _opener() -> urllib.request.OpenerDirector:
    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    return urllib.request.build_opener(urllib.request.HTTPSHandler(context=context), _NoRedirect())


def _goog_md5(headers: Any) -> str | None:
    values = headers.get_all("x-goog-hash") if hasattr(headers, "get_all") else None
    for value in values or []:
        for part in str(value).split(","):
            name, _, encoded = part.strip().partition("=")
            if name == "md5" and encoded:
                try:
                    return base64.b64decode(encoded, validate=True).hex()
                except ValueError:
                    raise OSVRefreshError("OSV kaynağı geçersiz md5 başlığı döndürdü.") from None
    return None


def download(url: str, destination: Path, *, max_bytes: int = DEFAULT_MAX_DOWNLOAD_BYTES,
             deadline_seconds: float = DEFAULT_DEADLINE_SECONDS,
             opener: Callable[..., Any] | None = None) -> dict[str, Any]:
    """`url`'yi `destination`'a (O_EXCL, 0600) indir; sha256/md5/bayt ve başlık bilgisini döndür."""
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname != SOURCE_HOST or parsed.port not in (None, 443):
        raise OSVRefreshError("Yalnız resmi OSV deposundan HTTPS ile indirme yapılır.")
    started = time.monotonic()
    request = urllib.request.Request(url, headers={"User-Agent": "sniper-osv-refresh/1"})
    open_url = opener or _opener().open
    try:
        response = open_url(request, timeout=SOCKET_TIMEOUT_SECONDS)
    except OSVRefreshError:
        raise
    except urllib.error.HTTPError as exc:
        raise OSVRefreshError(f"OSV kaynağı HTTP {exc.code} döndürdü.") from None
    except (urllib.error.URLError, OSError, ssl.SSLError) as exc:
        reason = getattr(exc, "reason", exc)
        raise OSVRefreshError(f"OSV kaynağına bağlanılamadı ({type(reason).__name__}).") from None
    sha256 = hashlib.sha256()
    # MD5 yalnız GCS'nin bildirdiği aktarım özetiyle karşılaştırma (bozulma tespiti) içindir; güven
    # çapası SHA-256'dır ve manifestte o kaydedilir.
    md5 = hashlib.new("md5", usedforsecurity=False)
    total = 0
    try:
        status = getattr(response, "status", 200)
        if status != 200:
            raise OSVRefreshError(f"OSV kaynağı HTTP {status} döndürdü.")
        headers = response.headers
        length_header = headers.get("Content-Length")
        expected_length = None
        if length_header is not None:
            if not str(length_header).isdigit():
                raise OSVRefreshError("OSV kaynağı geçersiz Content-Length döndürdü.")
            expected_length = int(length_header)
            if expected_length > max_bytes:
                raise OSVRefreshError("OSV arşivi izin verilen indirme boyutunu aşıyor.")
        expected_md5 = _goog_md5(headers)
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(fd, "wb") as stream:
            while True:
                if time.monotonic() - started > deadline_seconds:
                    raise OSVRefreshError("OSV indirmesi süre sınırını aştı.")
                chunk = response.read(_CHUNK)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise OSVRefreshError("OSV arşivi izin verilen indirme boyutunu aşıyor.")
                sha256.update(chunk)
                md5.update(chunk)
                stream.write(chunk)
            stream.flush()
            os.fsync(stream.fileno())
        if expected_length is not None and total != expected_length:
            raise OSVRefreshError("OSV indirmesi eksik (Content-Length uyuşmuyor).")
        if expected_md5 is not None and md5.hexdigest() != expected_md5:
            raise OSVRefreshError("OSV arşivinin md5 değeri kaynağın bildirdiğiyle uyuşmuyor.")
        return {
            "sha256": sha256.hexdigest(),
            "bytes": total,
            "md5_verified": expected_md5 is not None,
            "last_modified": str(headers.get("Last-Modified") or ""),
        }
    except BaseException:
        try:
            os.unlink(destination)
        except OSError:
            pass
        raise
    finally:
        try:
            response.close()
        except Exception:
            pass


# --- Zip ve şema doğrulaması --------------------------------------------------------------------

def _check_record(name: str, record: Any) -> None:
    stem = name[:-5]
    if not isinstance(record, dict):
        raise OSVRefreshError(f"OSV kaydı bir nesne değil: {name[:80]}")
    if record.get("id") != stem:
        raise OSVRefreshError(f"OSV kaydının id alanı dosya adıyla uyuşmuyor: {name[:80]}")
    if not isinstance(record.get("modified"), str) or not record["modified"]:
        raise OSVRefreshError(f"OSV kaydında modified alanı yok: {name[:80]}")
    for list_field in ("aliases", "related", "upstream"):
        value = record.get(list_field)
        if value is not None and (not isinstance(value, list) or not all(isinstance(v, str) for v in value)):
            raise OSVRefreshError(f"OSV kaydında {list_field} alanı geçersiz: {name[:80]}")
    affected = record.get("affected")
    if affected is not None:
        if not isinstance(affected, list) or not all(isinstance(item, dict) for item in affected):
            raise OSVRefreshError(f"OSV kaydında affected alanı geçersiz: {name[:80]}")
        for item in affected:
            package = item.get("package")
            if package is not None and (not isinstance(package, dict) or not isinstance(package.get("name", ""), str)):
                raise OSVRefreshError(f"OSV kaydında package alanı geçersiz: {name[:80]}")
            for list_field in ("ranges", "versions"):
                value = item.get(list_field)
                if value is not None and not isinstance(value, list):
                    raise OSVRefreshError(f"OSV kaydında {list_field} alanı geçersiz: {name[:80]}")


def validate_archive(path: Path, ecosystem: str, *, max_members: int = MAX_MEMBERS,
                     max_member_bytes: int = MAX_MEMBER_BYTES,
                     max_total_uncompressed: int = MAX_TOTAL_UNCOMPRESSED,
                     index: dict[str, list[str]] | None = None) -> dict[str, Any]:
    try:
        archive = zipfile.ZipFile(path)
    except (zipfile.BadZipFile, OSError, ValueError):
        raise OSVRefreshError("OSV arşivi geçerli bir zip değil.") from None
    with archive:
        infos = archive.infolist()
        if not infos:
            raise OSVRefreshError("OSV arşivi boş.")
        if len(infos) > max_members:
            raise OSVRefreshError("OSV arşivinde izin verilenden fazla girdi var.")
        seen: set[str] = set()
        declared_total = 0
        for info in infos:
            name = info.filename
            if (info.is_dir() or "/" in name or "\\" in name or name.startswith(".") or ".." in name
                    or not _MEMBER_RE.fullmatch(name)):
                raise OSVRefreshError(f"OSV arşivinde güvensiz ya da beklenmeyen girdi adı: {name[:80]!r}")
            if name in seen:
                raise OSVRefreshError(f"OSV arşivinde yinelenen girdi: {name[:80]}")
            seen.add(name)
            if info.flag_bits & 0x1:
                raise OSVRefreshError("OSV arşivinde şifreli girdi var.")
            if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                raise OSVRefreshError("OSV arşivinde desteklenmeyen sıkıştırma yöntemi var.")
            if info.file_size > max_member_bytes:
                raise OSVRefreshError(f"OSV arşivinde çok büyük girdi: {name[:80]}")
            if info.file_size > 1_048_576 and info.file_size > MAX_RATIO * max(info.compress_size, 1):
                raise OSVRefreshError(f"OSV arşivinde olağandışı sıkıştırma oranı (zip bombası şüphesi): {name[:80]}")
            declared_total += info.file_size
            if declared_total > max_total_uncompressed:
                raise OSVRefreshError("OSV arşivinin açılmış toplam boyutu sınırı aşıyor.")
        actual_total = 0
        ecosystem_mismatch = 0
        for info in infos:
            try:
                with archive.open(info) as member:
                    data = member.read(max_member_bytes + 1)
            except (zipfile.BadZipFile, OSError, EOFError, RuntimeError, ValueError):
                raise OSVRefreshError(f"OSV arşiv girdisi bozuk (CRC/sıkıştırma): {info.filename[:80]}") from None
            if len(data) != info.file_size or len(data) > max_member_bytes:
                raise OSVRefreshError(f"OSV arşiv girdisinin boyutu bildirilenle uyuşmuyor: {info.filename[:80]}")
            actual_total += len(data)
            try:
                record = json.loads(data.decode("utf-8"))
            except (UnicodeDecodeError, ValueError):
                raise OSVRefreshError(f"OSV kaydı geçerli JSON değil: {info.filename[:80]}") from None
            _check_record(info.filename, record)
            if index is not None:
                add_to_index(index, ecosystem, info.filename, record)
            affected = record.get("affected") or []
            ecosystems = {str((item.get("package") or {}).get("ecosystem", "")) for item in affected}
            if ecosystems and not any(eco.split(":", 1)[0] == ecosystem.split(":", 1)[0] for eco in ecosystems):
                ecosystem_mismatch += 1
    return {
        "zip_members": len(infos),
        "uncompressed_bytes": actual_total,
        "records_without_ecosystem_match": ecosystem_mismatch,
        "zip_test": "PASS",
        "schema_check": "PASS",
    }


# --- Manifest ve nesiller -----------------------------------------------------------------------

def read_manifest(path: Path) -> dict[str, Any] | None:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        return None
    except OSError:
        raise OSVRefreshError("Mevcut OSV manifesti okunamadı.") from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_MANIFEST_BYTES:
            raise OSVRefreshError("Mevcut OSV manifesti güvensiz.")
        raw = os.read(fd, MAX_MANIFEST_BYTES + 1)
    finally:
        os.close(fd)
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise OSVRefreshError("Mevcut OSV manifesti geçersiz JSON.") from None
    return data if isinstance(data, dict) else None


def _write_manifest(path: Path, manifest: dict[str, Any]) -> None:
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(manifest, stream, ensure_ascii=False, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    dir_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def _prune_generations(eco_dir: Path, keep: set[str]) -> list[str]:
    removed: list[str] = []
    for child in sorted(eco_dir.iterdir()):
        if child.name in keep or not _GENERATION_RE.fullmatch(child.name):
            continue
        if child.is_symlink() or not child.is_dir():
            continue
        shutil.rmtree(child)
        removed.append(child.name)
    return removed


def _write_index(path: Path, ecosystem: str, db_sha256: str, index: dict[str, list[str]]) -> dict[str, Any]:
    """Paket adı → kayıt dosyası dizini (gzip, belirlenimci); özeti imzalı manifeste girer."""
    document = {"format": INDEX_FORMAT, "ecosystem": ecosystem, "db_sha256": db_sha256,
                "packages": {key: sorted(index[key]) for key in sorted(index)}}
    raw = gzip.compress(json.dumps(document, ensure_ascii=False, sort_keys=True,
                                   separators=(",", ":")).encode("utf-8"), mtime=0)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(path, 0o400)
    return {"package_index_format": INDEX_FORMAT, "package_index_sha256": hashlib.sha256(raw).hexdigest(),
            "package_index_bytes": len(raw), "package_index_packages": len(index)}


def refresh(ecosystem: str = "npm", *, root: Path | None = None, max_bytes: int | None = None,
            deadline_seconds: float = DEFAULT_DEADLINE_SECONDS, opener: Callable[..., Any] | None = None,
            now: datetime | None = None) -> dict[str, Any]:
    """Tek ekosistemi indir, doğrula ve etkin nesli atomik olarak değiştir."""
    ecosystem = validate_ecosystem(ecosystem)
    if max_bytes is None:
        max_bytes = ECOSYSTEM_MAX_BYTES.get(ecosystem, 300_000_000)
    root = (root or default_root()).expanduser()
    _ensure_private_dir(root)
    eco_dir = root / "generations" / _slug(ecosystem)
    _ensure_private_dir(eco_dir)
    lock_path = root / f".refresh-{_slug(ecosystem)}.lock"
    lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise OSVRefreshBusy("Bu ekosistem için başka bir OSV güncellemesi sürüyor.") from None
        url = source_url(ecosystem)
        incoming = eco_dir / f".incoming-{os.getpid()}-{int(time.time())}.zip"
        retrieved = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        download_info = download(url, incoming, max_bytes=max_bytes, deadline_seconds=deadline_seconds,
                                 opener=opener)
        try:
            package_index: dict[str, list[str]] = {}
            archive_info = validate_archive(incoming, ecosystem, index=package_index)
            generation = f"{retrieved.strftime('%Y%m%dT%H%M%SZ')}-{download_info['sha256'][:12]}"
            target = eco_dir / generation / "db-cache" / "osv-scalibr" / ecosystem / "all.zip"
            if target.parent.exists():
                raise OSVRefreshError("Aynı nesil zaten var; güncelleme tekrarlanmadı.")
            for component in (eco_dir / generation, eco_dir / generation / "db-cache",
                              eco_dir / generation / "db-cache" / "osv-scalibr", target.parent):
                component.mkdir(mode=0o700)
            os.replace(incoming, target)
            os.chmod(target, 0o400)
            index_info = _write_index(target.parent / INDEX_FILENAME, ecosystem, download_info["sha256"], package_index)
        except BaseException:
            try:
                os.unlink(incoming)
            except OSError:
                pass
            raise
        manifest_file = manifest_path(root, ecosystem)
        previous = read_manifest(manifest_file)
        previous_generation = str(previous.get("generation") or "") if previous else ""
        manifest: dict[str, Any] = {
            "schema": NPM_SCHEMA if ecosystem == "npm" else GENERIC_SCHEMA,
            "ecosystem": ecosystem,
            "source_url": url,
            "retrieved_utc": retrieved.isoformat(),
            "source_last_modified": download_info["last_modified"],
            "sha256": download_info["sha256"],
            "bytes": download_info["bytes"],
            "md5_verified": download_info["md5_verified"],
            "scanner_cache_path": str(target),
            "network": "none",
            "generation": generation,
            "previous_generation": previous_generation,
            "refresh_tool": "sniper-osv-refresh-v1",
            **archive_info,
            **index_info,
        }
        key_state = audit_integrity.load_key(create=False)
        manifest["key_id"] = key_state.key_id
        manifest["mac"] = (audit_integrity.document_mac(key_state.key, MANIFEST_MAC_LABEL, manifest)
                           if key_state.usable and key_state.key else None)
        _write_manifest(manifest_file, manifest)
        removed = _prune_generations(eco_dir, {generation, previous_generation})
        manifest_sha = hashlib.sha256(manifest_file.read_bytes()).hexdigest()
        return {
            "status": "updated",
            "ecosystem": ecosystem,
            "manifest_path": str(manifest_file),
            "manifest_sha256": manifest_sha,
            "manifest_signed": manifest["mac"] is not None,
            "key_status": key_state.status,
            "generation": generation,
            "previous_generation": previous_generation,
            "removed_generations": removed,
            "sha256": manifest["sha256"],
            "bytes": manifest["bytes"],
            "md5_verified": manifest["md5_verified"],
            "zip_members": archive_info["zip_members"],
            "retrieved_utc": manifest["retrieved_utc"],
        }
    finally:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(lock_fd)


def status(ecosystem: str = "npm", *, root: Path | None = None, now: datetime | None = None) -> dict[str, Any]:
    ecosystem = validate_ecosystem(ecosystem)
    root = (root or default_root()).expanduser()
    path = manifest_path(root, ecosystem)
    manifest = read_manifest(path)
    if manifest is None:
        return {"status": "missing", "ecosystem": ecosystem, "manifest_path": str(path)}
    try:
        retrieved = datetime.fromisoformat(str(manifest.get("retrieved_utc")))
        age_hours = round(((now or datetime.now(timezone.utc)) - retrieved).total_seconds() / 3600, 1)
    except (TypeError, ValueError):
        age_hours = None
    key_state = audit_integrity.load_key(create=False)
    return {
        "status": "present",
        "ecosystem": ecosystem,
        "manifest_path": str(path),
        "generation": manifest.get("generation"),
        "retrieved_utc": manifest.get("retrieved_utc"),
        "age_hours": age_hours,
        "sha256": manifest.get("sha256"),
        "bytes": manifest.get("bytes"),
        "zip_members": manifest.get("zip_members"),
        "signature_valid": audit_integrity.verify_document_mac(key_state, MANIFEST_MAC_LABEL, manifest),
    }
