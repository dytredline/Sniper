"""Konteyner imajı / rootfs işletim sistemi paket açığı taraması (18. tur; Docker daemon gerekmez, ağ yok).

Girdiler (yerel yol, proje analizindeki izin verilen kökler kuralıyla):
* ``docker save`` tar dosyası (``manifest.json`` + katmanlar),
* OCI imaj düzeni: dizin ya da tar (``oci-layout`` + ``index.json`` + ``blobs/sha256``),
* açılmış rootfs dizini ya da tek katmanlı rootfs tar'ı (ör. ``docker export``).

Güvenlik: katmanlar diske HİÇ açılmaz; tar akışı bellekte okunur ve yalnız ilgili dosyalar (os-release, paket
veritabanları, dil paketi meta verileri) sınırlı boyutta tutulur. ``..``/mutlak adlar, aygıt dosyaları ve FIFO'lar
yok sayılır; sembolik bağlar yalnız sanal kök içinde çözülür (kökten yukarı çıkılamaz). Whiteout'lar (``.wh.ad``,
``.wh..wh..opq``) OCI kurallarıyla uygulanır. Katman, girdi, bayt ve dosya sayısı bütçeleri vardır.

Paket veritabanları: dpkg ``status`` (+ distroless ``status.d``), apk ``installed``, rpm ``rpmdb.sqlite``.
Eski BerkeleyDB/NDB rpmdb ayrıştırılmaz; algılandığında envanter kontrolü fail-closed ``na`` olur ve
yapılandırılmış neden/açık uyarı döner. OS sürümü ``/etc/os-release``'ten; açıklar resmi OSV
çevrimdışı veritabanından (``osv_db_refresh`` ile indirilen, sürüm uzantılı ekosistemler: ``Debian:12``,
``Ubuntu:24.04:LTS``, ``Alpine:v3.19`` …) eşlenir. Dil paketleri (PyPI/npm/Maven) bileşen olarak çıkarılır;
eşleştirmeleri çok ekosistemli OSV eşleyicisine (``set_language_matcher``) bırakılır.
"""
from __future__ import annotations

import collections
import datetime as dt
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shlex
import sqlite3
import stat
import struct
import subprocess
import tarfile
import tempfile
import threading
import time
from typing import Any, Callable, Iterable
import zipfile

import os_versions
import osv_db_refresh
from project_tree import ProjectFile, ProjectTree, ProjectTreeError

FORMAT = "sniper-container-scan/1"
CATEGORY = "container_os"
CWE = "CWE-1395"  # Açıklı üçüncü taraf bileşene bağımlılık

MAX_LAYERS = 128
MAX_MEMBERS = 2_000_000
MAX_INTERESTING_BYTES = 48 * 1024 * 1024  # tek ilgili dosya (paket veritabanı) üst sınırı
MAX_JAR_BYTES = 64 * 1024 * 1024
MAX_RETAINED_BYTES = 768 * 1024 * 1024
# 22. tur güvenlik: katman tar akışında bildirilen düzenli dosya boyutlarının toplam üst sınırı. Atlanan üyeler de
# akıştan okunarak (açılarak) geçildiği için sınırsız bir sıkıştırma bombası sunucu iş parçacığını saatlerce meşgul
# edebiliyordu; gerçek imajlar bunun çok altındadır.
MAX_DECLARED_BYTES = 32 * 1024 * 1024 * 1024
MAX_SYMLINKS = 400_000
MAX_ROOTFS_ENTRIES = 600_000
MAX_LANGUAGE_COMPONENTS = 20_000
MAX_FINDINGS = 5_000
MAX_RPM_ROWS = 100_000
MAX_RPM_HEADER_BYTES = 16 * 1024 * 1024
MAX_OCI_DESCRIPTORS = 4_096
MAX_OCI_INDEX_DEPTH = 8
SYMLINK_HOPS = 40

_INDEX_CACHE_DIR = "index-cache"
_INDEX_SCHEMA = 2


class ContainerScanError(ValueError):
    """Kullanıcıya gösterilebilir Türkçe hata (iç yol/sır içermez)."""


# ---------------------------------------------------------------------------
# İlgili dosyalar
# ---------------------------------------------------------------------------
OS_RELEASE = ("etc/os-release", "usr/lib/os-release")
DPKG_STATUS = "var/lib/dpkg/status"
DPKG_STATUS_D = "var/lib/dpkg/status.d/"
APK_INSTALLED = ("lib/apk/db/installed", "usr/lib/apk/db/installed")
RPM_SQLITE = ("var/lib/rpm/rpmdb.sqlite", "usr/lib/sysimage/rpm/rpmdb.sqlite")
RPM_LEGACY = ("var/lib/rpm/Packages", "usr/lib/sysimage/rpm/Packages",
              "var/lib/rpm/Packages.db", "usr/lib/sysimage/rpm/Packages.db")
_PY_META_RE = re.compile(r"(?:^|/)(?:site|dist)-packages/[^/]+\.(?:dist-info/METADATA|egg-info/PKG-INFO|egg-info)\Z")
_NPM_PKG_RE = re.compile(r"(?:^|/)node_modules/(?:@[^/]+/)?[^/@][^/]*/package\.json\Z")
_JAR_RE = re.compile(r"\.(?:jar|war|ear)\Z", re.IGNORECASE)


def _interesting(path: str) -> str | None:
    """İlgili dosya türü ya da ``None``."""
    if path in OS_RELEASE:
        return "os-release"
    if path == DPKG_STATUS:
        return "dpkg"
    if path.startswith(DPKG_STATUS_D) and "/" not in path[len(DPKG_STATUS_D):] and not path.endswith(".md5sums"):
        return "dpkg-d"
    if path in APK_INSTALLED:
        return "apk"
    if path in RPM_SQLITE:
        return "rpm-sqlite"
    if path in RPM_LEGACY:
        return "rpm-legacy"
    if _PY_META_RE.search(path):
        return "pypi"
    if _NPM_PKG_RE.search(path):
        return "npm"
    if _JAR_RE.search(path):
        return "jar"
    return None


def _normalize_member(name: str) -> str | None:
    """Tar üye adı → kökten göreli POSIX yol; ``..`` ya da boş ad ``None``."""
    text = name.replace("\\", "/")
    while text.startswith("./"):
        text = text[2:]
    text = text.lstrip("/")
    parts = [part for part in text.split("/") if part not in ("", ".")]
    if not parts or any(part == ".." for part in parts):
        return None
    return "/".join(parts)


# ---------------------------------------------------------------------------
# Sanal dosya sistemi (katmanların birleşimi)
# ---------------------------------------------------------------------------
class VirtualFS:
    def __init__(self) -> None:
        self.files: dict[str, bytes] = {}
        self.kinds: dict[str, str] = {}
        self.links: dict[str, str] = {}
        self.retained = 0
        self.members = 0
        self.bytes_read = 0
        self.warnings: list[str] = []
        self.skipped: collections.Counter[str] = collections.Counter()

    # -- whiteout ---------------------------------------------------------
    def _remove_tree(self, path: str, include_self: bool) -> None:
        prefix = path + "/"
        for store in (self.files, self.links):
            for key in [k for k in store if k.startswith(prefix) or (include_self and k == path)]:
                if store is self.files:
                    self.retained -= len(self.files[key])
                    self.kinds.pop(key, None)
                del store[key]

    def _remove_exact(self, path: str) -> None:
        if path in self.files:
            self.retained -= len(self.files.pop(path))
            self.kinds.pop(path, None)
        self.links.pop(path, None)

    def apply_member(self, path: str, member: tarfile.TarInfo, read: Callable[[int], bytes | None]) -> None:
        base = path.rsplit("/", 1)[-1]
        parent = path.rsplit("/", 1)[0] if "/" in path else ""
        if base == ".wh..wh..opq":
            self._remove_tree(parent, include_self=False)
            return
        if base.startswith(".wh."):
            target = (parent + "/" if parent else "") + base[4:]
            self._remove_tree(target, include_self=True)
            return
        if member.isdir():
            # Overlayfs dizinleri alttaki dizin içeriğiyle birleşir; ancak aynı
            # yoldaki eski dosya/sembolik bağ yeni dizinin altında görünmez.
            self._remove_exact(path)
            return
        # Dosya, bağ veya özel girdi aynı yoldaki alt dizinin bütün alt ağacını
        # gölgeler. Yalnız tam yolu kaldırmak eski paket meta verisini canlı bırakırdı.
        self._remove_tree(path, include_self=True)
        if member.issym():
            if len(self.links) >= MAX_SYMLINKS:
                self.skipped["symlink_budget"] += 1
                return
            self.links[path] = member.linkname
            return
        if member.islnk():
            target = _normalize_member(member.linkname)
            if target and target in self.files:
                kind = _interesting(path)
                if kind:
                    self._store(path, kind, self.files[target])
            return
        if not member.isreg():
            self.skipped["special"] += 1  # aygıt, FIFO vb.
            return
        kind = _interesting(path)
        if not kind:
            return
        limit = MAX_JAR_BYTES if kind == "jar" else MAX_INTERESTING_BYTES
        if member.size > limit:
            self.skipped["large_metadata"] += 1
            return
        if self.retained + member.size > MAX_RETAINED_BYTES:
            self.skipped["retained_budget"] += 1
            return
        data = read(member.size)
        if data is not None:
            self._store(path, kind, data)

    def _store(self, path: str, kind: str, data: bytes) -> None:
        self.files[path] = data
        self.kinds[path] = kind
        self.retained += len(data)

    # -- çözümleme --------------------------------------------------------
    def resolve(self, path: str) -> str | None:
        """Sembolik bağları sanal kök içinde çözerek gerçek yol (kökten yukarı çıkılamaz)."""
        parts = path.split("/")
        resolved: list[str] = []
        hops = 0
        index = 0
        while index < len(parts):
            part = parts[index]
            index += 1
            if part in ("", "."):
                continue
            if part == "..":
                if resolved:
                    resolved.pop()
                continue
            candidate = "/".join(resolved + [part])
            target = self.links.get(candidate)
            if target is None:
                resolved.append(part)
                continue
            hops += 1
            if hops > SYMLINK_HOPS:
                return None
            remaining = parts[index:]
            if target.startswith("/"):
                resolved = []
            parts = [p for p in target.split("/")] + remaining
            index = 0
        return "/".join(resolved)

    def read(self, path: str) -> bytes | None:
        if path in self.files:
            return self.files[path]
        real = self.resolve(path)
        return self.files.get(real) if real else None


# ---------------------------------------------------------------------------
# Girdi biçimleri
# ---------------------------------------------------------------------------
def _open_layer_stream(fileobj: Any) -> tarfile.TarFile:
    head = fileobj.read(4)
    if head == b"\x28\xb5\x2f\xfd":
        decoder = _find_zstd_decoder()
        if decoder is None:
            raise ContainerScanError("zstd katman çözücüsü hazır değil; sabit /usr/bin/zstd bulunamadı.")
        stream: io.RawIOBase = _ZstdReader(_Prefixed(head, fileobj), decoder)
        mode = "r|"
    else:
        stream = _Prefixed(head, fileobj)
        mode = "r|*"
    try:
        archive = tarfile.open(fileobj=stream, mode=mode)
    except BaseException:
        # ``tarfile.open`` can reject a corrupt stream before returning an owner for
        # it.  Close our decoder here so its process/feed thread cannot outlive the
        # failed image operation.
        stream.close()
        raise
    # TarFile dışarıdan verilen fileobj'yi varsayılan olarak kapatmaz. Akışı bizim kurduğumuz bu
    # durumda kapatması gerekir; zstd alt süreci ve besleme iş parçacığı böylece her hata yolunda temizlenir.
    archive._extfileobj = False  # type: ignore[attr-defined]
    return archive


class _Prefixed(io.RawIOBase):
    """Okunmuş baş baytlarını akışın önüne geri ekler (sıkıştırma türü tespiti için)."""

    def __init__(self, head: bytes, rest: Any) -> None:
        self._head = head
        self._rest = rest

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: Any) -> int:
        size = len(buffer)
        if self._head:
            chunk, self._head = self._head[:size], self._head[size:]
        else:
            chunk = self._rest.read(size)
        buffer[: len(chunk)] = chunk
        return len(chunk)


_ZSTD_DECODER = Path("/usr/bin/zstd")


def _find_zstd_decoder() -> str | None:
    """Yalnız sabit sistem decoder'ini kabul et; PATH ve proje dosyalarına güvenme."""
    try:
        info = _ZSTD_DECODER.stat()
    except OSError:
        return None
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or not os.access(_ZSTD_DECODER, os.X_OK):
        return None
    return str(_ZSTD_DECODER)


def zstd_readiness() -> dict[str, Any]:
    """OCI zstd katman desteğinin salt okunur hazırlık sözleşmesi."""
    decoder = _find_zstd_decoder()
    return {"available": decoder is not None, "decoder": "zstd-cli-stream-v1" if decoder else None,
            "path": decoder, "reason": None if decoder else "Sabit /usr/bin/zstd decoder'i yok veya güvenli değil."}


class _ZstdReader(io.RawIOBase):
    """Sabit zstd CLI'a sınırlı boru; katman diske açılmaz ve tarfile akış halinde tüketir."""

    def __init__(self, source: Any, decoder: str) -> None:
        super().__init__()
        self._source = source
        self._process = subprocess.Popen([decoder, "-d", "-q", "-c", "--"], stdin=subprocess.PIPE,
                                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, shell=False,
                                         close_fds=True, bufsize=0)
        self._pump_error: BaseException | None = None
        self._thread = threading.Thread(target=self._pump, name="sniper-zstd-feed", daemon=True)
        self._thread.start()

    def _pump(self) -> None:
        try:
            assert self._process.stdin is not None
            while True:
                chunk = self._source.read(64 * 1024)
                if not chunk:
                    break
                self._process.stdin.write(chunk)
        except Exception as exc:
            self._pump_error = exc
        finally:
            if self._process.stdin is not None:
                try:
                    self._process.stdin.close()
                except OSError:
                    pass

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: Any) -> int:
        if self.closed or self._process.stdout is None:
            return 0
        if len(buffer) == 0:
            return 0  # RawIO sözleşmesi: sıfır uzunluklu okuma akış sonu değildir ve süreç durumunu değiştirmez.
        chunk = self._process.stdout.read(len(buffer))
        if chunk:
            buffer[:len(chunk)] = chunk
            return len(chunk)
        self._thread.join(timeout=2)
        try:
            code = self._process.wait(timeout=2)
        except subprocess.TimeoutExpired as exc:
            self._process.kill()
            raise OSError("zstd decoder zaman aşımı") from exc
        if code != 0 or self._pump_error is not None:
            raise OSError("zstd katmanı açılamadı")
        return 0

    def close(self) -> None:
        if not self.closed:
            if self._process.stdout is not None:
                self._process.stdout.close()
            if self._process.poll() is None:
                self._process.terminate()
                try:
                    self._process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    self._process.kill()
                    self._process.wait(timeout=1)
            self._thread.join(timeout=1)
        super().close()


def _apply_layer(vfs: VirtualFS, layer: tarfile.TarFile) -> None:
    for position, member in enumerate(layer):
        if position % 512 == 0:
            layer.members = []  # akış kipinde TarFile her girdiyi listede biriktirir: bellek sınırlı kalsın
        vfs.members += 1
        if vfs.members > MAX_MEMBERS:
            raise ContainerScanError("İmajdaki dosya sayısı tarama bütçesini aştı.")
        path = _normalize_member(member.name)
        if path is None:
            vfs.skipped["unsafe_name"] += 1
            continue
        if member.isreg():
            vfs.bytes_read += member.size
            if vfs.bytes_read > MAX_DECLARED_BYTES:
                raise ContainerScanError("İmajın açılmış toplam boyutu tarama bütçesini aştı (sıkıştırma bombası olabilir).")

        def read(size: int, member: tarfile.TarInfo = member) -> bytes | None:
            handle = layer.extractfile(member)
            if handle is None:
                return None
            data = handle.read(size + 1)
            return data[:size] if len(data) <= size else None

        vfs.apply_member(path, member, read)


def _platform_arch() -> str:
    machine = platform.machine().lower()
    return {
        "x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64",
        "armv6l": "arm", "armv7l": "arm", "armv8l": "arm",
    }.get(machine, machine)


def _platform_variant() -> str | None:
    machine = platform.machine().lower()
    return {"armv6l": "v6", "armv7l": "v7", "armv8l": "v8"}.get(machine)


def _open_regular_nofollow(path: Path, *, max_bytes: int | None = None) -> Any:
    """Open one local regular file without following any pathname component."""
    absolute = Path(os.path.abspath(os.fspath(path)))
    parts = absolute.parts
    if len(parts) < 2:
        raise OSError("regular file path required")
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    file_flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
    directory_fd = os.open(parts[0], directory_flags)
    try:
        for part in parts[1:-1]:
            child_fd = os.open(part, directory_flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = child_fd
        fd = os.open(parts[-1], file_flags, dir_fd=directory_fd)
    finally:
        os.close(directory_fd)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or (max_bytes is not None and info.st_size > max_bytes):
            raise OSError("regular file size/type check failed")
        return os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise


def _read_regular_nofollow(path: Path, max_bytes: int) -> bytes:
    with _open_regular_nofollow(path, max_bytes=max_bytes) as handle:
        before = os.fstat(handle.fileno())
        data = handle.read(max_bytes + 1)
        after = os.fstat(handle.fileno())
    if len(data) > max_bytes:
        raise OSError("regular file grew beyond read budget")
    if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
            or len(data) != before.st_size):
        raise OSError("regular file changed while it was read")
    return data


class _Source:
    """Arşiv (tar) ya da dizin içinden dosya okuma soyutlaması."""

    def __init__(self, path: Path) -> None:
        self.path = Path(os.path.abspath(os.fspath(path)))
        self.tar: tarfile.TarFile | None = None
        self._archive_stream: Any | None = None
        self._archive_identity: tuple[int, int, int, int, int] | None = None
        self.tree: ProjectTree | None = None
        self.index: dict[str, tarfile.TarInfo] = {}
        self.records: dict[str, ProjectFile] = {}
        self.plain_rootfs = False
        self.rootfs_directory = False
        try:
            self._archive_stream = _open_regular_nofollow(self.path)
            info = os.fstat(self._archive_stream.fileno())
            self._archive_identity = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        except OSError:
            try:
                self.tree = ProjectTree(str(self.path)).open()
                walker = self.tree.walk(max_entries=MAX_ROOTFS_ENTRIES + MAX_OCI_DESCRIPTORS,
                                        reject_unsafe=False)
                first = next(walker)
                root_names = {record.name for record in first.files}
                layout = "oci-layout" in root_names or "manifest.json" in root_names
                if not layout:
                    walker.close()
                    self.rootfs_directory = True
                    return
                for entry in (first,):
                    for record in entry.files:
                        self.records[record.path.as_posix()] = record
                for entry in walker:
                    for record in entry.files:
                        self.records[record.path.as_posix()] = record
            except (ProjectTreeError, StopIteration) as exc:
                if self.tree is not None:
                    self.tree.close()
                    self.tree = None
                raise ContainerScanError("İmaj yolu okunamadı veya güvenli bir dosya/dizin değil.") from exc
            return
        try:
            self.tar = tarfile.open(fileobj=self._archive_stream, mode="r:*")
        except (tarfile.TarError, OSError) as exc:
            self._archive_stream.close()
            self._archive_stream = None
            raise ContainerScanError("İmaj dosyası tar arşivi olarak okunamadı.") from exc
        try:
            count = 0
            for member in self.tar:
                count += 1
                if count > 50_000:  # imaj arşivleri az girdilidir; bu kadar çoksa düz rootfs tar'ıdır
                    self.plain_rootfs = True
                    self.index.clear()
                    break
                name = _normalize_member(member.name)
                if name and member.isreg():
                    self.index[name] = member
        except (tarfile.TarError, OSError) as exc:
            self.close()
            raise ContainerScanError("İmaj dosyası tar arşivi olarak okunamadı.") from exc

    def exists(self, name: str) -> bool:
        if self.tar is not None:
            return name in self.index
        return name in self.records

    def open(self, name: str) -> Any:
        if self.tar is not None:
            member = self.index.get(name)
            handle = self.tar.extractfile(member) if member else None
            if handle is None:
                raise ContainerScanError("İmaj arşivinde beklenen girdi yok.")
            return handle
        record = self.records.get(name)
        if self.tree is None or record is None:
            raise ContainerScanError("İmaj düzeninde beklenen dosya okunamadı.")
        try:
            fd, _expected = self.tree._open_file(record)  # type: ignore[attr-defined]
        except ProjectTreeError as exc:
            raise ContainerScanError("İmaj düzeninde beklenen dosya okunamadı.") from exc
        return os.fdopen(fd, "rb")

    def read_json(self, name: str, limit: int = 8 * 1024 * 1024) -> Any:
        with self.open(name) as handle:
            data = handle.read(limit + 1)
        if len(data) > limit:
            raise ContainerScanError("İmaj meta verisi çok büyük.")
        try:
            return json.loads(data)
        except (ValueError, RecursionError) as exc:
            raise ContainerScanError("İmaj meta verisi geçerli JSON değil.") from exc

    def read_descriptor_json(self, descriptor: dict[str, Any], limit: int = 8 * 1024 * 1024) -> Any:
        name, expected_digest, expected_size = _oci_descriptor_ref(descriptor)
        with self.open(name) as handle:
            data = handle.read(limit + 1)
        if len(data) > limit:
            raise ContainerScanError("İmaj meta verisi çok büyük.")
        _verify_oci_blob(data, expected_digest, expected_size)
        try:
            return json.loads(data)
        except (ValueError, RecursionError) as exc:
            raise ContainerScanError("İmaj meta verisi geçerli JSON değil.") from exc

    def close(self) -> None:
        if self.tar is not None:
            self.tar.close()
            self.tar = None
        if self._archive_stream is not None:
            info = os.fstat(self._archive_stream.fileno())
            current = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
            self._archive_stream.close()
            self._archive_stream = None
            if self._archive_identity is not None and current != self._archive_identity:
                self._archive_identity = None
                raise ContainerScanError("İmaj arşivi tarama sırasında değişti.")
            self._archive_identity = None
        if self.tree is not None:
            self.tree.close()
            self.tree = None

    def reopen_archive(self) -> Any:
        """Return a stream pinned to the archive inode opened by ``__init__``."""
        if self._archive_stream is None:
            raise ContainerScanError("İmaj arşivi doğrulanmış tanımlayıcıdan yeniden açılamadı.")
        try:
            fd = os.dup(self._archive_stream.fileno())
            handle = os.fdopen(fd, "rb")
            handle.seek(0)
            return handle
        except OSError as exc:
            try:
                os.close(fd)
            except (OSError, UnboundLocalError):
                pass
            raise ContainerScanError("İmaj arşivi doğrulanmış tanımlayıcıdan yeniden açılamadı.") from exc


_DIGEST_RE = re.compile(r"sha256:([0-9a-f]{64})\Z")
_OCI_MANIFEST_MEDIA_TYPES = {
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
}
_OCI_INDEX_MEDIA_TYPES = {
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
}
_OCI_IMAGE_MEDIA_TYPES = _OCI_MANIFEST_MEDIA_TYPES | _OCI_INDEX_MEDIA_TYPES
_OCI_ARTIFACT_MEDIA_TYPES = {
    "application/vnd.oci.artifact.manifest.v1+json",
}


def _blob_name(digest: Any) -> str:
    match = _DIGEST_RE.fullmatch(str(digest or ""))
    if not match:
        raise ContainerScanError("OCI içerik özeti geçersiz.")
    return f"blobs/sha256/{match.group(1)}"


def _oci_descriptor_ref(descriptor: dict[str, Any]) -> tuple[str, str, int | None]:
    name = _blob_name(descriptor.get("digest"))
    expected_digest = name.rsplit("/", 1)[-1]
    size = descriptor.get("size")
    if size is not None and (isinstance(size, bool) or not isinstance(size, int) or size < 0):
        raise ContainerScanError("OCI descriptor boyutu geçersiz.")
    return name, expected_digest, size


def _verify_oci_blob(data: bytes, expected_digest: str, expected_size: int | None) -> None:
    if hashlib.sha256(data).hexdigest() != expected_digest:
        raise ContainerScanError("OCI blob içerik özeti descriptor ile uyuşmuyor.")
    if expected_size is not None and len(data) != expected_size:
        raise ContainerScanError("OCI blob boyutu descriptor ile uyuşmuyor.")


class _VerifiedOciBlob:
    """Hash and count a layer's compressed blob without retaining it in memory."""

    def __init__(self, raw: Any, descriptor: dict[str, Any]) -> None:
        _name, self.expected_digest, self.expected_size = _oci_descriptor_ref(descriptor)
        self.raw = raw
        self.digest = hashlib.sha256()
        self.size = 0
        self.done = False

    def read(self, size: int = -1) -> bytes:
        data = self.raw.read(size)
        if data:
            self.digest.update(data)
            self.size += len(data)
        else:
            self.done = True
        return data

    def finish(self) -> None:
        while not self.done:
            self.read(1024 * 1024)
        if self.digest.hexdigest() != self.expected_digest:
            raise ContainerScanError("OCI blob içerik özeti descriptor ile uyuşmuyor.")
        if self.expected_size is not None and self.size != self.expected_size:
            raise ContainerScanError("OCI blob boyutu descriptor ile uyuşmuyor.")


def _read_oci_descriptor_json(source: Any, descriptor: dict[str, Any]) -> Any:
    """Keep lightweight test sources compatible while production sources verify content identity."""
    reader = getattr(source, "read_descriptor_json", None)
    if callable(reader):
        return reader(descriptor)
    return source.read_json(_blob_name(descriptor.get("digest")))


def _select_oci_descriptor(candidates: Any) -> dict[str, Any]:
    """Choose the local Linux platform from an OCI descriptor list, with a stable first-item fallback."""
    if not isinstance(candidates, list):
        raise ContainerScanError("OCI descriptor listesi geçersiz.")
    if len(candidates) > MAX_OCI_DESCRIPTORS:
        raise ContainerScanError("OCI descriptor listesi güvenlik sınırını aştı.")
    options = [item for item in candidates if isinstance(item, dict)]
    if not options:
        raise ContainerScanError("OCI descriptor listesinde geçerli imaj yok.")
    # Buildx/provenance-enabled archives may put an attestation manifest before the
    # runnable image.  Such descriptors commonly advertise unknown/unknown and the
    # Docker reference-type annotation.  Keep unknown platforms as a last resort for
    # older platform-less image layouts, but never prefer a declared artifact.
    def is_artifact(item: dict[str, Any]) -> bool:
        annotations = item.get("annotations")
        reference_type = (annotations.get("vnd.docker.reference.type")
                          if isinstance(annotations, dict) else None)
        media_type = str(item.get("mediaType") or "").casefold()
        return media_type in _OCI_ARTIFACT_MEDIA_TYPES or bool(item.get("artifactType")) or \
            str(reference_type or "").casefold() in {
            "attestation-manifest", "signature-manifest", "sbom-manifest",
        }

    images = [item for item in options
              if not is_artifact(item)
              and str(item.get("mediaType") or "").casefold() in (_OCI_IMAGE_MEDIA_TYPES | {""})]
    if not images:
        raise ContainerScanError("OCI descriptor listesinde taranabilir imaj yok.")
    known_platform = [item for item in images
                      if not (isinstance(item.get("platform"), dict)
                              and item["platform"].get("os") == "unknown"
                              and item["platform"].get("architecture") == "unknown")]
    fallback = known_platform or images
    wanted = _platform_arch()
    architecture_matches = [
        item for item in fallback if isinstance(item.get("platform"), dict)
        and item["platform"].get("os") == "linux"
        and item["platform"].get("architecture") == wanted
    ]
    variant = _platform_variant()
    if variant:
        exact = next((item for item in architecture_matches
                      if item["platform"].get("variant") == variant), None)
        unspecified = next((item for item in architecture_matches
                            if not item["platform"].get("variant")), None)
        return exact or unspecified or fallback[0]
    return architecture_matches[0] if architecture_matches else fallback[0]


def _oci_layers(source: _Source) -> tuple[list[tuple[str, dict[str, Any] | None]], dict[str, Any]]:
    index = source.read_json("index.json")
    manifests = index.get("manifests") if isinstance(index, dict) else None
    if not isinstance(manifests, list) or not manifests:
        raise ContainerScanError("OCI index.json içinde imaj yok.")
    meta: dict[str, Any] = {"format": "oci"}
    descriptor = _select_oci_descriptor(manifests)
    tags = [str(m["annotations"].get("org.opencontainers.image.ref.name") or "")
            for m in manifests if isinstance(m, dict) and isinstance(m.get("annotations"), dict)]
    meta["tags"] = [t for t in tags if t][:10]
    if isinstance(descriptor.get("platform"), dict):
        meta["platform"] = descriptor["platform"]
    seen: set[str] = set()
    for _depth in range(MAX_OCI_INDEX_DEPTH):
        blob_name = _blob_name(descriptor.get("digest"))
        if blob_name in seen:
            raise ContainerScanError("OCI descriptor dizininde döngü bulundu.")
        seen.add(blob_name)
        manifest = _read_oci_descriptor_json(source, descriptor)
        if isinstance(manifest, dict) and isinstance(manifest.get("manifests"), list):  # çok platformlu dizin
            if str(descriptor.get("mediaType") or "").casefold() in _OCI_MANIFEST_MEDIA_TYPES:
                raise ContainerScanError("OCI descriptor medya türü içerikle uyuşmuyor.")
            descriptor = _select_oci_descriptor(manifest["manifests"])
            if isinstance(descriptor.get("platform"), dict):
                meta["platform"] = descriptor["platform"]
            continue
        layers = manifest.get("layers") if isinstance(manifest, dict) else None
        if not isinstance(layers, list):
            raise ContainerScanError("OCI manifestinde katman listesi yok.")
        if str(descriptor.get("mediaType") or "").casefold() in _OCI_INDEX_MEDIA_TYPES:
            raise ContainerScanError("OCI descriptor medya türü içerikle uyuşmuyor.")
        names: list[tuple[str, dict[str, Any] | None]] = []
        for layer in layers:
            if not isinstance(layer, dict):
                raise ContainerScanError("OCI katman descriptor'ı geçersiz.")
            media = str(layer.get("mediaType") or "")
            if "zstd" in media and _find_zstd_decoder() is None:
                raise ContainerScanError("zstd katman çözücüsü hazır değil; sabit /usr/bin/zstd bulunamadı.")
            names.append((_blob_name(layer.get("digest")), layer))
        return names, meta
    raise ContainerScanError("OCI dizin derinliği çok fazla.")


def _docker_layers(source: _Source) -> tuple[list[tuple[str, dict[str, Any] | None]], dict[str, Any]]:
    manifest = source.read_json("manifest.json")
    if not isinstance(manifest, list) or not manifest or not isinstance(manifest[0], dict):
        raise ContainerScanError("docker save manifest.json biçimi tanınmadı.")
    image = manifest[0]
    layers = image.get("Layers")
    if not isinstance(layers, list):
        raise ContainerScanError("docker save manifest.json içinde katman listesi yok.")
    names = []
    for layer in layers:
        name = _normalize_member(str(layer))
        if not name:
            raise ContainerScanError("docker save katman adı geçersiz.")
        names.append((name, None))
    meta = {"format": "docker-save", "tags": [str(t) for t in (image.get("RepoTags") or [])][:10]}
    if len(manifest) > 1:
        meta["note"] = "Arşivde birden çok imaj var; yalnız ilki tarandı."
    return names, meta


def _walk_rootfs(source: _Source, vfs: VirtualFS) -> None:
    """Walk a rootfs from its pinned root descriptor; never reopen the user pathname."""
    if source.tree is None:
        raise ContainerScanError("Rootfs dizini güvenli biçimde açılamadı.")
    root_dev = os.fstat(source.tree.fileno()).st_dev
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    stack: list[tuple[str, int]] = [("", os.dup(source.tree.fileno()))]
    regulars: dict[str, ProjectFile] = {}
    entries = 0

    def retain(path: str, kind: str, record: ProjectFile) -> None:
        limit = MAX_JAR_BYTES if kind == "jar" else MAX_INTERESTING_BYTES
        if record.size > limit or vfs.retained + record.size > MAX_RETAINED_BYTES:
            vfs.skipped["large_metadata"] += 1
            return
        try:
            data = source.tree.read_bytes(record, limit, allow_empty=True)
        except ProjectTreeError as exc:
            raise ContainerScanError("Rootfs girdisi yürüyüşten sonra değişti.") from exc
        vfs.bytes_read += len(data)
        vfs._store(path, kind, data)

    try:
        while stack:
            rel, directory_fd = stack.pop()
            try:
                try:
                    with os.scandir(directory_fd) as iterator:
                        children = sorted(iterator, key=lambda entry: entry.name)
                except OSError as exc:
                    raise ContainerScanError("Rootfs dizini tarama sırasında değişti veya okunamadı.") from exc
                for entry in children:
                    entries += 1
                    if entries > MAX_ROOTFS_ENTRIES:
                        vfs.warnings.append("Rootfs girdi bütçesi aşıldı; tarama kısmi.")
                        vfs.members = entries
                        return
                    if (not isinstance(entry.name, str) or entry.name in ("", ".", "..")
                            or "/" in entry.name or "\x00" in entry.name):
                        vfs.skipped["unsafe_name"] += 1
                        continue
                    path = f"{rel}/{entry.name}" if rel else entry.name
                    if not rel and entry.name in ("proc", "sys", "dev", "run"):
                        continue
                    try:
                        info = entry.stat(follow_symlinks=False)
                    except OSError as exc:
                        raise ContainerScanError("Rootfs girdisi tarama sırasında değişti.") from exc
                    if stat.S_ISLNK(info.st_mode):
                        if len(vfs.links) >= MAX_SYMLINKS:
                            vfs.skipped["symlink_budget"] += 1
                            continue
                        try:
                            vfs.links[path] = os.readlink(entry.name, dir_fd=directory_fd)
                        except OSError as exc:
                            raise ContainerScanError("Rootfs sembolik bağı tarama sırasında değişti.") from exc
                        continue
                    if stat.S_ISDIR(info.st_mode):
                        if info.st_dev != root_dev:
                            continue
                        child_fd: int | None = None
                        try:
                            child_fd = os.open(entry.name, directory_flags, dir_fd=directory_fd)
                            opened_info = os.fstat(child_fd)
                        except OSError as exc:
                            if child_fd is not None:
                                os.close(child_fd)
                            raise ContainerScanError("Rootfs alt dizini tarama sırasında değişti.") from exc
                        if (not stat.S_ISDIR(opened_info.st_mode)
                                or (opened_info.st_dev, opened_info.st_ino) != (info.st_dev, info.st_ino)):
                            os.close(child_fd)
                            raise ContainerScanError("Rootfs alt dizini yürüyüşten sonra değişti.")
                        stack.append((path, child_fd))
                        continue
                    if not stat.S_ISREG(info.st_mode) or info.st_dev != root_dev:
                        continue
                    record = ProjectFile(PurePosixPath(path), info.st_size, info.st_dev, info.st_ino,
                                         info.st_mtime_ns, info.st_ctime_ns)
                    regulars[path] = record
                    kind = _interesting(path)
                    if kind:
                        retain(path, kind, record)
            finally:
                os.close(directory_fd)
    finally:
        for _rel, directory_fd in stack:
            os.close(directory_fd)

    # Interesting symlink names (commonly /etc/os-release) inherit verified target bytes.
    for path in sorted(vfs.links):
        if path in vfs.files:
            continue
        kind = _interesting(path)
        target = vfs.resolve(path) if kind else None
        record = regulars.get(target or "")
        if kind and record is not None:
            retain(path, kind, record)
        elif kind:
            vfs.skipped["unreadable_symlink"] += 1
    vfs.members = entries


def load_image(path: Path | _Source) -> tuple[VirtualFS, dict[str, Any]]:
    """İmaj/rootfs'i sanal dosya sistemine yükler. Dönüş: (vfs, imaj meta verisi)."""
    vfs = VirtualFS()
    source = path if isinstance(path, _Source) else _Source(path)
    try:
        if source.rootfs_directory:
            _walk_rootfs(source, vfs)
            return vfs, {"format": "rootfs-dir", "layers": 0, "tags": []}
        if not source.plain_rootfs and source.exists("oci-layout") and source.exists("index.json"):
            layers, meta = _oci_layers(source)
        elif not source.plain_rootfs and source.exists("manifest.json"):
            layers, meta = _docker_layers(source)
        elif source.tar is not None:  # tek katmanlı rootfs tar'ı (docker export)
            handle = source.reopen_archive()
            with handle:
                try:
                    layer = _open_layer_stream(handle)
                except (tarfile.TarError, OSError) as exc:
                    raise ContainerScanError("Rootfs arşivi okunamadı.") from exc
                with layer:
                    _apply_layer(vfs, layer)
            return vfs, {"format": "rootfs-tar", "layers": 1, "tags": []}
        else:
            raise ContainerScanError("Dizin bir OCI düzeni ya da rootfs olarak tanınmadı.")
        if len(layers) > MAX_LAYERS:
            raise ContainerScanError("İmajdaki katman sayısı bütçeyi aştı.")
        for name, descriptor in layers:
            if not source.exists(name):
                raise ContainerScanError("İmaj katmanı arşivde bulunamadı.")
            with source.open(name) as handle:
                blob = _VerifiedOciBlob(handle, descriptor) if descriptor is not None else handle
                try:
                    layer = _open_layer_stream(blob)
                except (tarfile.TarError, OSError) as exc:
                    raise ContainerScanError("İmaj katmanı tar olarak okunamadı.") from exc
                with layer:
                    _apply_layer(vfs, layer)
                if descriptor is not None:
                    blob.finish()
        meta["layers"] = len(layers)
        return vfs, meta
    finally:
        source.close()


# ---------------------------------------------------------------------------
# OS ve paket veritabanları
# ---------------------------------------------------------------------------
def parse_os_release(data: bytes | None) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in (data or b"").decode("utf-8", "replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key.strip()] = value[:200]
    return values


def os_ecosystem(release: dict[str, str]) -> tuple[str | None, str | None]:
    """os-release → (OSV ekosistemi, paket türü) ya da (None, açıklama)."""
    os_id = release.get("ID", "").lower()
    version = release.get("VERSION_ID", "")
    if os_id == "debian":
        major = version.split(".", 1)[0]
        if major.isdigit():
            return f"Debian:{major}", "deb"
        return None, "Debian sürümü (VERSION_ID) yok: testing/sid desteklenmez."
    if os_id == "ubuntu":
        if re.fullmatch(r"\d{2}\.\d{2}", version):
            lts = "LTS" in release.get("VERSION", "") or (version.endswith(".04") and int(version[:2]) % 2 == 0)
            return f"Ubuntu:{version}{':LTS' if lts else ''}", "deb"
        return None, "Ubuntu sürümü tanınmadı."
    if os_id == "alpine":
        match = re.match(r"(\d+)\.(\d+)", version)
        if match:
            return f"Alpine:v{match.group(1)}.{match.group(2)}", "apk"
        return None, "Alpine sürümü tanınmadı (edge desteklenmez)."
    if os_id == "wolfi":
        return "Wolfi", "apk"
    if os_id == "chainguard":
        return "Chainguard", "apk"
    if os_id == "almalinux":
        major = version.split(".", 1)[0]
        return (f"AlmaLinux:{major}", "rpm") if major.isdigit() else (None, "AlmaLinux sürümü tanınmadı.")
    if os_id == "rocky":
        major = version.split(".", 1)[0]
        return (f"Rocky Linux:{major}", "rpm") if major.isdigit() else (None, "Rocky Linux sürümü tanınmadı.")
    if os_id in ("rhel", "redhat", "redhatenterpriseserver"):
        major = version.split(".", 1)[0]
        return (f"Red Hat Enterprise Linux:{major}", "rpm") if major.isdigit() \
            else (None, "Red Hat Enterprise Linux sürümü tanınmadı.")
    if os_id in ("amzn", "amazon"):
        generation = version.split(".", 1)[0]
        return (f"Amazon Linux:{generation}", "rpm") if generation in ("2", "2023") \
            else (None, "Amazon Linux sürümü tanınmadı (yalnız 2 ve 2023).")
    if os_id in ("sles", "sled"):
        match = re.match(r"(\d+)(?:\.(\d+))?", version)
        return (f"SUSE Linux Enterprise Server:{match.group(1)}" + (f".{match.group(2)}" if match.group(2) else ""),
                "rpm") if match else (None, "SUSE Linux Enterprise Server sürümü tanınmadı.")
    if os_id in ("opensuse-leap", "opensuse"):
        match = re.match(r"(\d+)(?:\.(\d+))?", version)
        return (f"openSUSE Leap:{match.group(1)}" + (f".{match.group(2)}" if match.group(2) else ""), "rpm") \
            if match else (None, "openSUSE Leap sürümü tanınmadı.")
    if os_id:
        return None, f"'{os_id[:40]}' dağıtımı için OSV eşlemesi bu sürümde yok."
    return None, "os-release bulunamadı."


def _stanzas(text: str) -> Iterable[tuple[int, dict[str, str]]]:
    fields: dict[str, str] = {}
    start = 0
    last = None
    for number, raw in enumerate(text.splitlines(), 1):
        if not raw.strip():
            if fields:
                yield start, fields
            fields, last = {}, None
            continue
        if raw[0] in " \t":
            if last:
                fields[last] = fields[last] + "\n" + raw.strip()
            continue
        if ":" not in raw:
            continue
        key, value = raw.split(":", 1)
        if not fields:
            start = number
        last = key.strip()
        fields[last] = value.strip()
    if fields:
        yield start, fields


_SOURCE_RE = re.compile(r"([A-Za-z0-9][A-Za-z0-9.+-]*)(?:\s*\(([^)]+)\))?")


def parse_dpkg(data: bytes, db_path: str) -> list[dict[str, Any]]:
    packages = []
    for line, fields in _stanzas(data.decode("utf-8", "replace")):
        name, version = fields.get("Package"), fields.get("Version")
        status = fields.get("Status", "install ok installed").split()
        if not name or not version or (len(status) >= 3 and status[2] != "installed"):
            continue
        source_name, source_version = name, version
        match = _SOURCE_RE.match(fields.get("Source", ""))
        if match:
            source_name = match.group(1)
            source_version = (match.group(2) or version).strip()
        packages.append({"type": "deb", "name": name, "version": version, "source": source_name,
                         "source_version": source_version, "arch": fields.get("Architecture", ""),
                         "db": db_path, "line": line})
    return packages


def parse_apk(data: bytes, db_path: str) -> list[dict[str, Any]]:
    packages = []
    for line, fields in _stanzas(data.decode("utf-8", "replace")):
        name, version = fields.get("P"), fields.get("V")
        if not name or not version:
            continue
        packages.append({"type": "apk", "name": name, "version": version, "source": fields.get("o") or name,
                         "source_version": version, "arch": fields.get("A", ""), "db": db_path, "line": line})
    return packages


_RPM_TAGS = {1000: "name", 1001: "version", 1002: "release", 1003: "epoch", 1022: "arch", 1044: "sourcerpm"}


def _rpm_header(blob: bytes) -> dict[str, Any]:
    if len(blob) < 8:
        raise ValueError("kısa rpm başlığı")
    # rpmdb.sqlite stores exported rpm Headers.  Real exports carry the canonical
    # 8-byte magic/version/reserved prefix; retain the older prefixless form for
    # databases produced by earlier rpm tooling and existing offline fixtures.
    index_start = 8
    if blob.startswith(b"\x8e\xad\xe8"):
        if len(blob) < 16 or blob[3] != 1 or blob[4:8] != b"\x00\x00\x00\x00":
            raise ValueError("bozuk rpm başlığı")
        count, data_len = struct.unpack(">II", blob[8:16])
        index_start = 16
    else:
        count, data_len = struct.unpack(">II", blob[:8])
    if count > 100_000 or index_start + count * 16 + data_len > len(blob):
        raise ValueError("bozuk rpm başlığı")
    data_start = index_start + count * 16
    values: dict[str, Any] = {}
    for position in range(count):
        entry_start = index_start + position * 16
        tag, kind, offset, num = struct.unpack(">IIII", blob[entry_start: entry_start + 16])
        key = _RPM_TAGS.get(tag)
        if not key or offset >= data_len:
            continue
        start = data_start + offset
        if kind in (6, 8, 9):  # STRING, STRING_ARRAY, I18NSTRING
            end = blob.find(b"\x00", start, data_start + data_len)
            if end < 0:
                continue  # RPM string etiketleri NUL sonlandırmalıdır; kalan veri etiket değeri sayılamaz.
            values[key] = blob[start:end].decode("utf-8", "replace")
        elif kind == 4 and num >= 1 and start + 4 <= data_start + data_len:
            values[key] = struct.unpack(">I", blob[start:start + 4])[0]
    return values


def parse_rpm_sqlite(data: bytes, db_path: str) -> list[dict[str, Any]]:
    packages: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="sniper-rpmdb-") as tmp:
        target = Path(tmp) / "rpmdb.sqlite"
        target.write_bytes(data)
        os.chmod(target, 0o400)
        try:
            connection = sqlite3.connect(f"file:{target}?mode=ro&immutable=1", uri=True)
        except sqlite3.Error as exc:
            raise ContainerScanError("rpmdb.sqlite açılamadı.") from exc
        try:
            connection.execute("PRAGMA trusted_schema=OFF")
            schema = connection.execute(
                "SELECT type, sql FROM sqlite_schema WHERE name = 'Packages' COLLATE BINARY").fetchone()
            if not schema or schema[0] != "table" or not isinstance(schema[1], str) or \
                    not re.match(r"\s*CREATE\s+TABLE\b", schema[1], re.I):
                raise ContainerScanError("rpmdb.sqlite içindeki Packages nesnesi gerçek bir tablo olmalı.")
            cursor = connection.execute(
                "SELECT hnum, blob FROM Packages LIMIT ?", (MAX_RPM_ROWS + 1,))
            for position, row in enumerate(cursor):
                if position >= MAX_RPM_ROWS:
                    raise ContainerScanError("rpmdb.sqlite paket satırı güvenlik sınırını aştı.")
                hnum, blob = row
                # SQLite dinamik türlere izin verir. Tek bozuk satır tüm geçerli envanteri düşürmemeli ve
                # kullanıcı denetimli hnum hata metnine taşınmamalıdır.
                if isinstance(hnum, bool) or not isinstance(hnum, int) or \
                        not isinstance(blob, bytes) or len(blob) > MAX_RPM_HEADER_BYTES:
                    continue
                try:
                    header = _rpm_header(blob)
                except (ValueError, struct.error):
                    continue
                name, version = header.get("name"), header.get("version")
                if not name or not version or name == "gpg-pubkey":
                    continue
                release = header.get("release", "")
                epoch = header.get("epoch")
                full = (f"{epoch}:" if epoch else "") + version + (f"-{release}" if release else "")
                source = str(header.get("sourcerpm") or "")
                source_name = re.sub(r"-[^-]+-[^-]+\.src\.rpm\Z", "", source) \
                    if source.endswith(".src.rpm") else name
                packages.append({"type": "rpm", "name": name, "version": full, "source": source_name or name,
                                 "source_version": full, "arch": header.get("arch", ""), "db": db_path,
                                 "line": hnum})
        except sqlite3.Error as exc:
            raise ContainerScanError("rpmdb.sqlite içinde Packages tablosu okunamadı.") from exc
        finally:
            connection.close()
    return packages


_BERKELEY_RPMDB_HASH_MAGIC = 0x00061561


def detect_legacy_rpmdb(data: bytes, db_path: str) -> str:
    """Eski RPM veritabanını ayrıştırmadan, yalnız raporlama için sınıflandırır.

    RPM'in BerkeleyDB ``Packages`` dosyası bir DB_HASH metadata sayfasıdır. Magic, sürüm ve sayfa
    boyutu her iki bayt sırasında da doğrulanır; tek başına dosya adı BerkeleyDB kanıtı sayılmaz.
    RPM NDB için bu çalışma alanında doğrulanabilir bir magic/okuyucu yoktur; canonical ``Packages.db``
    yolu bu nedenle destek iddiası içermeyen ``ndb_candidate`` olarak raporlanır.
    """
    if len(data) >= 512:
        for byte_order in ("little", "big"):
            magic = int.from_bytes(data[12:16], byte_order)
            version = int.from_bytes(data[16:20], byte_order)
            page_size = int.from_bytes(data[20:24], byte_order)
            if magic == _BERKELEY_RPMDB_HASH_MAGIC and 1 <= version <= 20 and \
                    512 <= page_size <= 64 * 1024 and page_size & (page_size - 1) == 0 and \
                    len(data) >= page_size:
                return "berkeleydb"
    if PurePosixPath(db_path).name == "Packages.db":
        return "ndb_candidate"
    return "unknown"


# ---------------------------------------------------------------------------
# Dil paketleri (bileşen çıkarımı; eşleştirme çok ekosistemli OSV eşleyicisine bırakılır)
# ---------------------------------------------------------------------------
def _py_component(path: str, data: bytes) -> dict[str, Any] | None:
    name = version = ""
    for raw in data[:65536].decode("utf-8", "replace").splitlines():
        if not raw.strip():
            break
        if raw.startswith("Name:") and not name:
            name = raw.split(":", 1)[1].strip()
        elif raw.startswith("Version:") and not version:
            version = raw.split(":", 1)[1].strip()
    if not name or not version:
        return None
    return {"ecosystem": "PyPI", "name": name, "version": version, "path": path,
            "purl": f"pkg:pypi/{re.sub(r'[-_.]+', '-', name).lower()}@{version}"}


def _npm_component(path: str, data: bytes) -> dict[str, Any] | None:
    try:
        document = json.loads(data[: 2 * 1024 * 1024])
    except ValueError:
        return None
    if not isinstance(document, dict):
        return None
    name, version = document.get("name"), document.get("version")
    if not isinstance(name, str) or not isinstance(version, str) or not name or not version:
        return None
    return {"ecosystem": "npm", "name": name[:214], "version": version[:64], "path": path,
            "purl": f"pkg:npm/{name.replace('@', '%40')}@{version}"}


def _jar_components(path: str, data: bytes, depth: int = 0) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, ValueError):
        return out
    with archive:
        for info in archive.infolist()[:20_000]:
            name = info.filename
            if name.startswith("META-INF/maven/") and name.endswith("/pom.properties") and info.file_size < 65536:
                props: dict[str, str] = {}
                for raw in archive.read(info).decode("utf-8", "replace").splitlines():
                    if "=" in raw and not raw.startswith("#"):
                        key, value = raw.split("=", 1)
                        props[key.strip()] = value.strip()
                group, artifact, version = props.get("groupId"), props.get("artifactId"), props.get("version")
                if group and artifact and version:
                    out.append({"ecosystem": "Maven", "name": f"{group}:{artifact}", "version": version,
                                "path": path, "purl": f"pkg:maven/{group}/{artifact}@{version}"})
            elif depth == 0 and _JAR_RE.search(name) and info.file_size <= MAX_JAR_BYTES // 4:
                out.extend(_jar_components(f"{path}!/{name}", archive.read(info), depth + 1))  # fat jar / war
    return out


def language_components(vfs: VirtualFS) -> list[dict[str, Any]]:
    components: list[dict[str, Any]] = []
    for path, kind in sorted(vfs.kinds.items()):
        if len(components) >= MAX_LANGUAGE_COMPONENTS:
            break
        data = vfs.files[path]
        if kind == "pypi":
            item = _py_component(path, data)
            if item:
                components.append(item)
        elif kind == "npm":
            item = _npm_component(path, data)
            if item:
                components.append(item)
        elif kind == "jar":
            components.extend(_jar_components(path, data))
    unique: dict[tuple[str, str, str], dict[str, Any]] = {}
    for item in components:
        unique.setdefault((item["ecosystem"], item["name"], item["version"]), item)
    return list(unique.values())


def offline_osv_language_matcher(components: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Varsayılan dil paketi eşleyicisi (18. tur birleştirme): çevrimdışı çok ekosistemli OSV (osv_offline) ile
    PyPI/npm/Maven bileşenlerini eşler; bulgular bu modülün bulgu biçimindedir (kategori ``container_lang``)."""
    import dependency_security
    import osv_offline

    paths = {(c["ecosystem"].casefold(), c["name"], c["version"]): c.get("path", "") for c in components}
    result = osv_offline.match_components([{k: c[k] for k in ("ecosystem", "name", "version")} for c in components])
    out: list[dict[str, Any]] = []
    for item in dependency_security.parse_osv(result["document"], "container-image"):
        name, version, vuln_id = item["package_name"], item["installed_version"], item["vulnerability_id"]
        ecosystem = next((e for (e, n, v) in paths if n == name and v == version), "")
        fix = item.get("fixed_version") or None
        if item.get("malicious"):
            # 20. tur: kötü amaçlı paket (OpenSSF MAL-) — kritik, yükseltme değil kaldırma
            out.append({
                "category": "container_lang",
                "severity": "critical",
                "title": f"{dependency_security.MALICIOUS_TITLE}: {name} {version} ({vuln_id})",
                "file": paths.get((ecosystem, name, version), ""),
                "line": 0,
                "reference": vuln_id,
                "cwe": dependency_security.MALICIOUS_CWE,
                "evidence": f"{ecosystem or 'paket'}: {name} {version}",
                "recommendation": dependency_security.MALICIOUS_RECOMMENDATION,
                "package": {"type": ecosystem, "source": name, "installed_version": version, "binaries": [name]},
                "vulnerability": {"id": vuln_id, "aliases": item.get("aliases") or [], "summary": item.get("title", ""),
                                  "severity_source": "osv-malicious"},
                "fixed_version": None,
                "fix_state": "not_fixed",
                "label": vuln_id,
                "malicious": True,
            })
            continue
        out.append({
            "category": "container_lang",
            "severity": item.get("severity") or "medium",
            "title": f"Açıklı dil paketi: {name} {version} ({vuln_id})",
            "file": paths.get((ecosystem, name, version), ""),
            "line": 0,
            "reference": vuln_id,
            "cwe": CWE,
            "evidence": f"{ecosystem or 'paket'}: {name} {version}",
            "recommendation": (f"{name} paketini {fix} ya da üstüne yükseltip imajı yeniden derleyin." if fix else
                               f"{name} için düzeltilmiş sürüm yok; paketi kaldırmayı ya da telafi edici kontrolü "
                               "değerlendirin."),
            "package": {"type": ecosystem, "source": name, "installed_version": version, "binaries": [name]},
            "vulnerability": {"id": vuln_id, "aliases": item.get("aliases") or [], "summary": item.get("title", ""),
                              "severity_source": "osv"},
            "fixed_version": fix,
            "fix_state": "fixed" if fix else "not_fixed",
            "label": vuln_id,
        })
    return out


_LANGUAGE_MATCHER: Callable[[list[dict[str, Any]]], list[dict[str, Any]]] | None = offline_osv_language_matcher


def set_language_matcher(matcher: Callable[[list[dict[str, Any]]], list[dict[str, Any]]] | None) -> None:
    """Dil paketleri için çok ekosistemli OSV eşleyicisi. Sözleşme: bileşen listesi (ecosystem, name, version,
    path, purl) → bulgu listesi (bu modülün bulgu alanlarıyla uyumlu; category ``components`` önerilir)."""
    global _LANGUAGE_MATCHER
    _LANGUAGE_MATCHER = matcher


# ---------------------------------------------------------------------------
# OSV dizini ve eşleştirme
# ---------------------------------------------------------------------------
_UBUNTU_PRIORITY = {"negligible": "info", "untriaged": "medium", "low": "low", "medium": "medium",
                    "high": "high", "critical": "critical"}
_DEBIAN_URGENCY = {"unimportant": "info", "end-of-life": "info", "low": "low", "low*": "low", "low**": "low",
                   "medium": "medium", "medium*": "medium", "medium**": "medium", "high": "high", "high*": "high",
                   "high**": "high"}


def _cvss_severity(vectors: list[str]) -> str | None:
    import risk

    best = None
    for vector in vectors:
        text = vector.strip()
        if text.startswith("CVSS:3.0/"):
            text = "CVSS:3.1/" + text[len("CVSS:3.0/"):]
        if not text.startswith("CVSS:3.1/"):
            continue
        try:
            _normalized, score = risk.calculate_cvss31(text)
        except ValueError:
            continue
        if score is None:
            continue
        level = "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low" if score > 0 else "info"
        order = ["info", "low", "medium", "high", "critical"]
        if best is None or order.index(level) > order.index(best):
            best = level
    return best


def _slim(record: dict[str, Any], affected: dict[str, Any]) -> dict[str, Any]:
    specific = affected.get("ecosystem_specific") if isinstance(affected.get("ecosystem_specific"), dict) else {}
    vectors = [str(s.get("score") or "") for s in (record.get("severity") or []) + (affected.get("severity") or [])
               if isinstance(s, dict) and str(s.get("type") or "").startswith("CVSS_V3")]
    severity, source = None, "default"
    priority = str(specific.get("ubuntu_priority") or "").lower()
    urgency = str(specific.get("urgency") or "").lower()
    if priority in _UBUNTU_PRIORITY:
        severity, source = _UBUNTU_PRIORITY[priority], "ubuntu_priority"
    elif urgency in _DEBIAN_URGENCY:
        severity, source = _DEBIAN_URGENCY[urgency], "urgency"
    if severity is None:
        cvss = _cvss_severity(vectors)
        if cvss:
            severity, source = cvss, "cvss_v3"
    ranges = []
    for item in affected.get("ranges") or []:
        if isinstance(item, dict) and item.get("type") == "ECOSYSTEM":
            events = [e for e in item.get("events") or [] if isinstance(e, dict)]
            ranges.append(events)
    aliases = [str(a) for a in (record.get("aliases") or []) + (record.get("related") or []) if isinstance(a, str)]
    return {
        "id": str(record.get("id") or ""),
        "aliases": sorted({a for a in aliases if a.startswith("CVE-")})[:5],
        "summary": str(record.get("summary") or "")[:300],
        "severity": severity or "medium",
        "severity_source": source,
        "ranges": ranges,
        "versions": [str(v) for v in (affected.get("versions") or [])][:2000],
    }


def _db_path(root: Path, ecosystem: str) -> tuple[Path, dict[str, Any]]:
    manifest_file = osv_db_refresh.manifest_path(root, ecosystem)
    manifest = osv_db_refresh.read_manifest(manifest_file)
    if not manifest or manifest.get("ecosystem") != ecosystem:
        raise FileNotFoundError(ecosystem)
    path = Path(str(manifest.get("scanner_cache_path") or ""))
    expected_root = (root / "generations").resolve()
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise FileNotFoundError(ecosystem) from exc
    if expected_root not in resolved.parents:
        raise ContainerScanError("OSV manifesti veri dizini dışını gösteriyor.")
    return resolved, manifest


def archive_ecosystem(ecosystem: str) -> str:
    """İndirilecek OSV arşivi: sürüm uzantılı arşivi olan ailelerde aynısı; AlmaLinux/Rocky, Wolfi/Chainguard ve
    LTS olmayan Ubuntu sürümlerinde yalnız taban arşiv vardır (kayıtlar sürüm uzantılı ekosistem adı taşır)."""
    family = ecosystem.split(":", 1)[0]
    if family in ("AlmaLinux", "Rocky Linux") or (family == "Ubuntu" and not ecosystem.endswith(":LTS")):
        return family
    return ecosystem


def load_index(ecosystem: str, *, root: Path | None = None) -> tuple[dict[str, list[dict[str, Any]]], dict[str, Any]]:
    """Ekosistemin OSV dizini: kaynak paket adı → açık listesi. Önce sürüm uzantılı, yoksa taban arşiv kullanılır
    (kayıtlar her durumda tam ekosistem adıyla süzülür). Arşiv SHA-256'sı manifestle doğrulanır; dizin
    ``index-cache`` altında arşiv özetine bağlı önbelleklenir."""
    root = (root or osv_db_refresh.default_root()).expanduser()
    try:
        archive, manifest = _db_path(root, ecosystem)
    except FileNotFoundError:
        family = ecosystem.split(":", 1)[0]
        if family == ecosystem:
            raise
        archive, manifest = _db_path(root, family)
    sha = str(manifest.get("sha256") or "")
    cache_dir = root / _INDEX_CACHE_DIR
    cache_file = cache_dir / f"{re.sub(r'[^a-z0-9]+', '-', ecosystem.lower())}-{sha[:16]}.json.gz"
    info = {"ecosystem": ecosystem, "archive": manifest.get("ecosystem"), "retrieved_utc": manifest.get("retrieved_utc"),
            "sha256": sha, "generation": manifest.get("generation")}
    if cache_file.is_file() and not cache_file.is_symlink():
        try:
            with gzip.open(cache_file, "rt", encoding="utf-8") as handle:
                cached = json.load(handle)
            if cached.get("schema") == _INDEX_SCHEMA and cached.get("sha256") == sha:
                return cached["index"], {**info, "cached": True, "records": cached.get("records")}
        except (OSError, ValueError, KeyError):
            pass
    digest = hashlib.sha256()
    with open(archive, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    if digest.hexdigest() != sha:
        raise ContainerScanError(f"{ecosystem} OSV arşivi manifestteki SHA-256 ile uyuşmuyor; yeniden indirin.")
    index: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)
    records = 0
    with zipfile.ZipFile(archive) as bundle:
        for member in bundle.infolist():
            if member.file_size > osv_db_refresh.MAX_MEMBER_BYTES:
                continue
            try:
                record = json.loads(bundle.read(member))
            except ValueError:
                continue
            records += 1
            for affected in record.get("affected") or []:
                package = affected.get("package") if isinstance(affected, dict) else None
                if not isinstance(package, dict) or package.get("ecosystem") != ecosystem:
                    continue
                name = str(package.get("name") or "")
                if name and not str(record.get("id") or "").startswith(_NON_SECURITY_PREFIXES):
                    index[name].append(_slim(record, affected))
    index = dict(index)
    try:
        cache_dir.mkdir(mode=0o700, exist_ok=True)
        tmp_file = cache_file.with_suffix(".tmp")
        fd = os.open(tmp_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as raw, gzip.open(raw, "wt", encoding="utf-8") as handle:
            json.dump({"schema": _INDEX_SCHEMA, "sha256": sha, "records": records, "index": index}, handle)
        os.replace(tmp_file, cache_file)
    except OSError:
        pass  # önbellek yazılamazsa tarama yine çalışır
    return index, {**info, "cached": False, "records": records}


def _affected(version: str, vuln: dict[str, Any], compare: Callable[[str, str], int]) -> tuple[bool, str | None]:
    """(etkileniyor mu, düzeltme sürümü). OSV ECOSYSTEM aralıkları + açık ``versions`` listesi."""
    fixed_versions: list[str] = []
    affected = False
    for events in vuln.get("ranges") or []:
        state = False
        ordered = []
        for event in events:
            for key in ("introduced", "fixed", "last_affected", "limit"):
                if key in event:
                    ordered.append((key, str(event[key])))
        for key, value in ordered:
            if key == "fixed":
                fixed_versions.append(value)
            try:
                if key == "introduced":
                    if value == "0" or compare(version, value) >= 0:
                        state = True
                elif key == "fixed" and state and compare(version, value) >= 0:
                    state = False
                elif key == "last_affected" and state and compare(version, value) > 0:
                    state = False
                elif key == "limit" and state and compare(version, value) >= 0:
                    state = False
            except ValueError:
                continue
        affected = affected or state
    if not affected and version in (vuln.get("versions") or []):
        affected = True
    fix = None
    for candidate in fixed_versions:
        try:
            if compare(candidate, version) > 0 and (fix is None or compare(candidate, fix) < 0):
                fix = candidate
        except ValueError:
            continue
    return affected, fix


_SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
# RHEL türevi hata düzeltme / iyileştirme duyuruları güvenlik açığı değildir.
_NON_SECURITY_PREFIXES = ("ALBA-", "ALEA-", "RLBA-", "RLEA-", "RHBA-", "RHEA-")


def match_packages(packages: list[dict[str, Any]], index: dict[str, list[dict[str, Any]]], package_type: str,
                   *, ignore_unfixed: bool = False) -> list[dict[str, Any]]:
    """Kurulu paketler × OSV dizini → (kaynak paket, açık) başına bir bulgu."""
    compare = os_versions.comparator_for(package_type)
    by_source: dict[tuple[str, str], list[dict[str, Any]]] = collections.defaultdict(list)
    for package in packages:
        by_source[(package["source"], package["source_version"])].append(package)
    findings: list[dict[str, Any]] = []
    for (source, source_version), binaries in sorted(by_source.items()):
        candidates = list(index.get(source, []))
        if package_type == "rpm":  # AlmaLinux/Rocky kayıtları ikili ad da kullanabilir
            for binary in binaries:
                if binary["name"] != source:
                    candidates.extend(index.get(binary["name"], []))
        seen: set[str] = set()
        group: list[tuple[dict[str, Any], str | None]] = []
        for vuln in candidates:
            if vuln["id"] in seen:
                continue
            affected, fix = _affected(source_version, vuln, compare)
            if not affected:
                continue
            seen.add(vuln["id"])
            if ignore_unfixed and not fix:
                continue
            group.append((vuln, fix))
        # Dağıtım duyuruları (USN/DSA/DLA…) CVE kayıtlarını yineler: CVE'lerinin hepsi aynı pakette ayrı kayıtla
        # zaten raporlanıyorsa duyuru ayrıca bulgu olmaz (CVE'siz duyuru, ör. gerileme düzeltmesi, kalır).
        cve_ids = {cve for vuln, _fix in group if not vuln["id"].startswith(_ADVISORY_PREFIXES)
                   for cve in [vuln["id"].split("-", 1)[-1] if vuln["id"].startswith("UBUNTU-CVE-") else vuln["id"]] + vuln["aliases"]
                   if cve.startswith("CVE-")}
        for vuln, fix in group:
            if vuln["id"].startswith(_ADVISORY_PREFIXES) and vuln["aliases"] and set(vuln["aliases"]) <= cve_ids:
                continue
            findings.append(_finding(source, source_version, binaries, vuln, fix))
            if len(findings) >= MAX_FINDINGS:
                return findings
    return findings


_ADVISORY_PREFIXES = ("USN-", "DSA-", "DLA-", "DTSA-", "ALSA-", "RLSA-")


def _finding(source: str, version: str, binaries: list[dict[str, Any]], vuln: dict[str, Any],
             fix: str | None) -> dict[str, Any]:
    first = binaries[0]
    names = sorted({b["name"] for b in binaries})
    cves = ", ".join(vuln["aliases"][:3])
    label = vuln["id"] + (f" / {cves}" if cves and cves not in vuln["id"] else "")
    if fix:
        recommendation = f"{source} paketini {fix} ya da üstüne yükseltin (temel imajı güncelleyip yeniden derleyin)."
    else:
        recommendation = (f"{source} için dağıtım henüz düzeltme yayımlamadı; paketi kaldırmayı, daha küçük bir temel "
                          "imajı ya da telafi edici kontrolü değerlendirin.")
    return {
        "category": CATEGORY,
        "severity": vuln["severity"],
        "title": f"Açıklı işletim sistemi paketi: {source} ({vuln['id']})",
        "file": first["db"],
        "line": int(first.get("line") or 0),
        "reference": vuln["id"],
        "cwe": CWE,
        "evidence": "Paketler: " + ", ".join(names[:12]) + (" …" if len(names) > 12 else ""),
        "recommendation": recommendation,
        "package": {"type": first["type"], "source": source, "installed_version": version, "binaries": names[:50]},
        "vulnerability": {"id": vuln["id"], "aliases": vuln["aliases"], "summary": vuln["summary"],
                          "severity_source": vuln["severity_source"]},
        "fixed_version": fix,
        "fix_state": "fixed" if fix else "not_fixed",
        "label": label,
    }


# ---------------------------------------------------------------------------
# Ana giriş
# ---------------------------------------------------------------------------
def _allowed_input_path(value: str, allowed_roots: tuple[Path, ...] | None = None) -> Path:
    import project_analyzer

    if not isinstance(value, str) or not value.strip() or len(value) > 1024:
        raise ContainerScanError("Geçerli bir yerel imaj dosyası ya da rootfs dizini girin.")
    expanded = os.path.expandvars(os.path.expanduser(value.strip()))
    if "\x00" in expanded:
        raise ContainerScanError("İmaj yolu bulunamadı veya okunamıyor.")
    candidate = Path(os.path.normpath(os.path.abspath(expanded)))
    roots = allowed_roots if allowed_roots is not None else project_analyzer._allowed_roots()
    normalized_roots = [Path(os.path.normpath(os.path.abspath(os.fspath(root)))) for root in roots]
    if not any(candidate != root and str(candidate).startswith(str(root) + os.sep) for root in normalized_roots):
        raise ContainerScanError("İmaj yalnızca kullanıcı dizini veya bağlı yerel disk içinde olabilir.")
    return candidate


def validate_image_path(value: str, allowed_roots: tuple[Path, ...] | None = None) -> Path:
    """Validate containment and type through a no-follow descriptor, without returning that descriptor."""
    candidate = _allowed_input_path(value, allowed_roots)
    try:
        with _open_regular_nofollow(candidate):
            return candidate
    except OSError:
        try:
            with ProjectTree(str(candidate)):
                return candidate
        except ProjectTreeError as exc:
            raise ContainerScanError("İmaj yolu bulunamadı veya güvenli bir dosya/dizin değil.") from exc


def _dockerfile_instructions(text: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    pending: list[str] = []
    for raw in text.splitlines():
        stripped = raw.strip()
        if not pending and (not stripped or stripped.startswith("#")):
            continue
        if stripped.endswith("\\"):
            pending.append(stripped[:-1])
            continue
        pending.append(stripped)
        logical = " ".join(pending)
        pending = []
        match = re.match(r"([A-Za-z]+)\s+(.*)$", logical)
        if match:
            out.append((match.group(1).upper(), match.group(2).strip()))
    return out


_PACKAGE_MANAGERS = {"apt", "apt-get", "aptitude", "apk", "dnf", "dnf5", "tdnf", "yum", "microdnf", "pacman", "pkg", "rpm-ostree", "zypper", "eopkg"}
_PACKAGE_ACTIONS = {
    "apt": {"install": True, "reinstall": True, "remove": False, "purge": False, "autoremove": False},
    "apt-get": {"install": True, "reinstall": True, "remove": False, "purge": False, "autoremove": False},
    "aptitude": {"install": True, "reinstall": True, "remove": False, "purge": False},
    "apk": {"add": True, "fix": True, "upgrade": True, "del": False},
    "dnf": {"install": True, "reinstall": True, "upgrade": True, "update": True, "distro-sync": True, "remove": False, "erase": False},
    "dnf5": {"install": True, "reinstall": True, "upgrade": True, "update": True, "distro-sync": True, "remove": False, "erase": False},
    "tdnf": {"install": True, "reinstall": True, "upgrade": True, "update": True, "remove": False, "erase": False},
    "yum": {"install": True, "reinstall": True, "upgrade": True, "update": True, "distro-sync": True, "remove": False, "erase": False},
    "microdnf": {"install": True, "reinstall": True, "upgrade": True, "update": True, "remove": False, "erase": False},
    "pacman": {"-s": True, "--sync": True, "-r": False, "--remove": False},
    "pkg": {"install": True, "delete": False, "remove": False},
    "rpm-ostree": {"install": True, "uninstall": False},
    "zypper": {"install": True, "in": True, "update": True, "up": True, "remove": False, "rm": False},
    "eopkg": {"install": True, "upgrade": True, "up": True, "remove": False},
}
_RPM_PACKAGE_MANAGERS = {"dnf", "dnf5", "tdnf", "yum", "microdnf", "rpm-ostree", "zypper"}
_DEBIAN_PACKAGE_MANAGERS = {"apt", "apt-get", "aptitude"}
_APK_PACKAGE_MANAGERS = {"apk"}
_DEBIAN_ARCHES = {
    "all", "alpha", "amd64", "arc", "arm", "arm64", "armel", "armhf", "hppa", "hurd-amd64",
    "hurd-i386", "i386", "ia64", "kfreebsd-amd64", "kfreebsd-i386", "loong64", "m68k", "mips",
    "mips64", "mips64el", "mipsel", "powerpc", "ppc64", "ppc64el", "riscv64", "s390", "s390x",
    "sh4", "sparc", "sparc64", "x32",
}
_RPM_ARCHES = {
    "aarch64", "alpha", "armhfp", "armv5tel", "armv6hl", "armv7hl", "i386", "i486", "i586", "i686",
    "ia64", "loongarch64", "mips", "mips64", "mips64el", "mipsel", "noarch", "ppc", "ppc64",
    "ppc64le", "riscv64", "s390", "s390x", "sparc", "sparc64", "x86_64",
}
_RPM_VERSION_PART = re.compile(r"^(?:[0-9]+:)?(?=[A-Za-z0-9~^+_.]*[0-9])[A-Za-z0-9~^+_.]+$")
_RPM_RELEASE_PART = re.compile(r"^(?=[A-Za-z0-9~^+_.]*[0-9])[A-Za-z0-9~^+_.]+$")
_APK_PACKAGE_SPEC = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9+_.-]*)"
    r"(?:@(?P<tag>[A-Za-z0-9][A-Za-z0-9+_.-]*))?"
    r"(?:(?P<operator><=|>=|~=|=|<|>|~)(?P<version>[A-Za-z0-9][A-Za-z0-9+_.:~-]*))?$"
)


def _rpm_package_identity(spec: str) -> str:
    """Açık mimarili RPM ``name-[epoch:]version-release.arch`` belirtimini paket adına indirger."""
    if "." not in spec:
        return spec
    base, arch = spec.rsplit(".", 1)
    if not base or arch.casefold() not in _RPM_ARCHES:
        return spec
    parts = base.rsplit("-", 2)
    if len(parts) == 3 and parts[0] and _RPM_VERSION_PART.fullmatch(parts[1]) \
            and _RPM_RELEASE_PART.fullmatch(parts[2]):
        return parts[0]
    return base


def _debian_package_identity(spec: str) -> str:
    """APT ``name:architecture/release`` belirtimini doğrulanmış bölümlerle paket adına indirger."""
    if "/" in spec:
        candidate, release = spec.rsplit("/", 1)
        if candidate and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9+_.~-]*", release):
            spec = candidate
    if ":" not in spec:
        return spec
    name, architecture = spec.rsplit(":", 1)
    return name if name and architecture.casefold() in _DEBIAN_ARCHES else spec


def _apk_package_identity(spec: str) -> str:
    """APK ``name[@repository][constraint]`` belirtimini kurulu paket adına indirger."""
    match = _APK_PACKAGE_SPEC.fullmatch(spec)
    return match.group("name") if match else spec


def _package_manager_index(tokens: list[str]) -> int | None:
    """Yalnız gerçek komut konumundaki paket yöneticisini kabul et; sıradan argümanları sayma."""
    wrapper_seen = False
    wrapper_argument = False
    for index, token in enumerate(tokens):
        if wrapper_argument:
            wrapper_argument = False
            continue
        executable = token.rsplit("/", 1)[-1]
        if executable in _PACKAGE_MANAGERS:
            return index
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", token):
            continue
        if index == 0 and token.startswith(("--mount=", "--network=", "--security=")):
            continue
        if executable in {"env", "command", "exec"} and not wrapper_seen:
            wrapper_seen = True
            continue
        if wrapper_seen:
            if executable in {"env", "command", "exec"}:
                continue
            if token in {"-i", "--ignore-environment", "--"}:
                continue
            if token in {"-u", "--unset", "-C", "--chdir"}:
                wrapper_argument = True
                continue
            if re.fullmatch(r"(?:--unset|--chdir)=.+|-[uC].+", token):
                continue
        return None
    return None


def _shell_command_prefix(command: str) -> str:
    """POSIX kabuk yorumunu kaldır; sözcük içindeki/alıntılanmış ``#`` işaretini koru."""
    single = double = escaped = False
    word_start = True
    for index, char in enumerate(command):
        if escaped:
            escaped = False
            word_start = False
            continue
        if char == "\\" and not single:
            escaped = True
            word_start = False
            continue
        if char == "'" and not double:
            single = not single
            word_start = False
            continue
        if char == '"' and not single:
            double = not double
            word_start = False
            continue
        if not single and not double and char == "#" and word_start:
            return command[:index]
        if not single and not double and char.isspace():
            word_start = True
        else:
            word_start = False
    return command


def _safe_docker_variable_value(value: str) -> bool:
    """Accept an empty value or a bounded list of shell-safe literal tokens."""
    if value == "":
        return True
    tokens = value.split()
    return 1 <= len(tokens) <= 32 and all(
        re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9+_.:@/-]{0,299}", token)
        for token in tokens
    )


def _expand_shell_variables(command: str, variables: dict[str, str]) -> str:
    """Expand bounded Docker ENV/ARG names and literal ``-``/``:-`` defaults."""
    out: list[str] = []
    single = double = escaped = False
    index = 0
    while index < len(command):
        char = command[index]
        if escaped:
            out.append(char)
            escaped = False
            index += 1
            continue
        if char == "\\" and not single:
            out.append(char)
            escaped = True
            index += 1
            continue
        if char == "'" and not double:
            single = not single
            out.append(char)
            index += 1
            continue
        if char == '"' and not single:
            double = not double
            out.append(char)
            index += 1
            continue
        if char == "$" and not single:
            braced = re.match(
                r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?:(:-|-)([^{}]*))?\}", command[index:],
            )
            if braced:
                raw, name, operator, fallback = braced.group(0), *braced.groups()
                fallback_is_literal = fallback == "" or bool(
                    re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9+_.:@/-]{0,299}", fallback or "")
                )
                if name in variables and not (operator == ":-" and variables[name] == ""):
                    out.append(variables[name])
                elif operator is not None and fallback_is_literal:
                    out.append(fallback or "")
                else:
                    out.append(raw)
                index += len(raw)
                continue
            plain = re.match(r"\$([A-Za-z_][A-Za-z0-9_]*)", command[index:])
            if plain:
                raw, name = plain.group(0), plain.group(1)
                out.append(variables.get(name, raw))
                index += len(raw)
                continue
        out.append(char)
        index += 1
    return "".join(out)


def _docker_env_updates(args: str, current: dict[str, str]) -> dict[str, str | None]:
    """Parse only bounded single-token Docker ENV values used for package identity."""
    try:
        tokens = shlex.split(args, posix=True)
    except ValueError:
        return {}
    pairs: list[tuple[str, str]] = []
    if tokens and all("=" in token for token in tokens):
        pairs = [tuple(token.split("=", 1)) for token in tokens]
    elif len(tokens) == 2:
        pairs = [(tokens[0], tokens[1])]
    updates: dict[str, str | None] = {}
    visible = dict(current)
    for name, raw_value in pairs:
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            continue
        value = _expand_shell_variables(raw_value, visible)
        if _safe_docker_variable_value(value):
            updates[name] = value
            visible[name] = value
        else:
            # The assignment still overwrites the older Docker ENV value.
            # Keep the new unknown value out of shell/package parsing and clear
            # stale literal provenance.
            updates[name] = None
            visible.pop(name, None)
    return updates


def _docker_arg_update(args: str, visible: dict[str, str]) -> tuple[str, str | None] | None:
    """Parse one bounded Docker ARG declaration and its literal default."""
    try:
        tokens = shlex.split(args, posix=True)
    except ValueError:
        return None
    normalized = tokens[0] if len(tokens) == 1 else ""
    match = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*)(?:=(.*))?", normalized)
    if not match:
        return None
    name, raw_default = match.groups()
    if raw_default is None:
        return name, visible.get(name)
    value = _expand_shell_variables(raw_default, visible)
    if _safe_docker_variable_value(value):
        return name, value
    return name, None


def _package_token_groups(command: str, variables: dict[str, str] | None = None) -> list[list[str]]:
    stripped = command.strip()
    token_groups: list[list[str]] = []
    if stripped.startswith("["):
        try:
            exec_form = json.loads(stripped)
        except ValueError:
            exec_form = None
        if isinstance(exec_form, list) and exec_form and all(isinstance(item, str) for item in exec_form):
            executable = exec_form[0].rsplit("/", 1)[-1]
            if executable in ("sh", "bash", "dash", "ash", "ksh", "zsh") and len(exec_form) >= 3 \
                    and exec_form[1] in ("-c", "-ec", "-xc", "-exc"):
                shell_command = _expand_shell_variables(exec_form[2], variables or {})
                for segment in re.split(r"(?:&&|\|\||;|\n)", shell_command):
                    try:
                        token_groups.append(shlex.split(_shell_command_prefix(segment), posix=True))
                    except ValueError:
                        continue
            else:
                token_groups.append(exec_form)
    else:
        shell_command = _expand_shell_variables(command, variables or {})
        for segment in re.split(r"(?:&&|\|\||;|\n)", shell_command):
            try:
                token_groups.append(shlex.split(_shell_command_prefix(segment), posix=True))
            except ValueError:
                continue
    return token_groups


def _package_changes(command: str, variables: dict[str, str] | None = None) -> list[tuple[bool, str]]:
    changes: list[tuple[bool, str]] = []
    token_groups = _package_token_groups(command, variables)
    for tokens in token_groups:
        manager_index = _package_manager_index(tokens)
        if manager_index is None:
            continue
        manager = tokens[manager_index].rsplit("/", 1)[-1]
        actions = _PACKAGE_ACTIONS[manager]
        action_index = next((i for i in range(manager_index + 1, len(tokens))
                             if tokens[i].casefold() in actions), None)
        if action_index is None:
            continue
        installing = actions[tokens[action_index].casefold()]
        for token in tokens[action_index + 1:]:
            if token.startswith("-") or token in ("\\",) or "=" in token and token.split("=", 1)[0].isupper():
                continue
            if token.startswith(("$", "http://", "https://")) or any(mark in token for mark in ("*", "?", "[")):
                continue
            name = token.strip() if manager in _APK_PACKAGE_MANAGERS else token.split("=", 1)[0].strip()
            if manager in _APK_PACKAGE_MANAGERS:
                name = _apk_package_identity(name)
            elif manager in _RPM_PACKAGE_MANAGERS:
                name = _rpm_package_identity(name)
            elif manager in _DEBIAN_PACKAGE_MANAGERS:
                name = _debian_package_identity(name)
            if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9+_.:@-]*", name):
                changes.append((installing, name))
    return changes


def _apk_virtual_events(command: str, variables: dict[str, str] | None = None) -> list[tuple[bool, str, set[str]]]:
    """Return ordered add/delete events for explicit Alpine virtual package groups."""
    events: list[tuple[bool, str, set[str]]] = []
    for tokens in _package_token_groups(command, variables):
        manager_index = _package_manager_index(tokens)
        if manager_index is None or tokens[manager_index].rsplit("/", 1)[-1] != "apk":
            continue
        actions = _PACKAGE_ACTIONS["apk"]
        action_index = next((index for index in range(manager_index + 1, len(tokens))
                             if tokens[index].casefold() in actions), None)
        if action_index is None:
            continue
        action = tokens[action_index].casefold()
        if action == "del":
            for token in tokens[action_index + 1:]:
                if token.startswith(".") and re.fullmatch(r"\.[A-Za-z0-9][A-Za-z0-9_.-]*", token):
                    events.append((False, token, set()))
            continue
        if action != "add":
            continue
        group = ""
        member_tokens: list[str] = []
        index = action_index + 1
        while index < len(tokens):
            token = tokens[index]
            if token in ("--virtual", "-t") and index + 1 < len(tokens):
                group = tokens[index + 1]
                index += 2
                continue
            if token.startswith("--virtual="):
                group = token.split("=", 1)[1]
                index += 1
                continue
            if not token.startswith("-"):
                member_tokens.append(token)
            index += 1
        if not re.fullmatch(r"\.[A-Za-z0-9][A-Za-z0-9_.-]*", group):
            continue
        members = {_apk_package_identity(token) for token in member_tokens}
        members = {name for name in members if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9+_.:@-]*", name)}
        events.append((True, group, members))
    return events


def _installed_packages(command: str) -> set[str]:
    packages: set[str] = set()
    for installing, name in _package_changes(command):
        if installing:
            packages.add(name)
        else:
            packages.discard(name)
    return packages


def _full_root_copy_source(args: str) -> str | None:
    """``COPY --from=<stage> / /`` için kaynak aşama; dar kopyalar paket mirası sayılmaz."""
    json_start = args.find("[")
    if json_start >= 0:
        try:
            prefix = shlex.split(args[:json_start], posix=True)
            json_paths = json.loads(args[json_start:])
        except (ValueError, json.JSONDecodeError):
            return None
        if not isinstance(json_paths, list) or not all(isinstance(path, str) for path in json_paths):
            return None
        tokens = prefix + json_paths
    else:
        try:
            tokens = shlex.split(args, posix=True)
        except ValueError:
            return None
    source_stage: str | None = None
    paths: list[str] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if not paths and token.startswith("--from="):
            source_stage = token.split("=", 1)[1]
        elif not paths and token == "--from" and index + 1 < len(tokens):
            index += 1
            source_stage = tokens[index]
        elif not paths and token.startswith("--"):
            pass  # --chown/--chmod/--link gibi diğer COPY bayrakları kök kopya kararını değiştirmez
        else:
            paths.append(token)
        index += 1
    def root_path(path: str) -> bool:
        # Docker ``/``, ``/.`` ve ``/./`` yazımlarını aynı kök olarak yorumlar. ``..`` içeren ya da göreli
        # yolları kök mirası saymamak, dar bir COPY için paket aşaması ilişkisi kurmayı önler.
        return path.startswith("/") and all(part in ("", ".") for part in path.split("/"))

    if source_stage and len(paths) == 2 and root_path(paths[0]) and root_path(paths[1]):
        return source_stage
    return None


def link_final_stage_packages(dockerfile: str, packages: list[dict[str, Any]]) -> dict[str, Any]:
    """Çok aşamalı Dockerfile'ın son aşamasındaki kurulumları imaj envanteriyle ilişkilendirir."""
    stages: list[dict[str, Any]] = []
    aliases: dict[str, dict[str, Any]] = {}
    global_args: dict[str, str] = {}
    current: dict[str, Any] | None = None
    for instruction, args in _dockerfile_instructions(dockerfile):
        if instruction == "ARG" and not stages:
            # Only ARG declarations before the first FROM are in scope for FROM.
            # Build-time overrides are unknown offline, so use a bounded literal default only.
            update = _docker_arg_update(args, global_args)
            if update is not None and (update[0] in global_args or len(global_args) < 100):
                name, value = update
                if value is None:
                    global_args.pop(name, None)
                else:
                    global_args[name] = value
        elif instruction == "FROM":
            match = re.match(r"(?:--\S+\s+)*([^\s]+)(?:\s+AS\s+([^\s]+))?", args, re.I)
            if not match:
                continue
            base, alias = match.group(1), (match.group(2) or "")
            variable = re.fullmatch(r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))", base)
            if variable:
                base = global_args.get(variable.group(1) or variable.group(2), base)
            inherited = aliases.get(base.casefold())
            current = {
                "base": base,
                "alias": alias,
                "packages": set(inherited["packages"]) if inherited else set(),
                "direct": set(inherited.get("direct", ())) if inherited else set(),
                "virtuals": {name: set(members) for name, members in inherited.get("virtuals", {}).items()}
                if inherited else {},
                "env": dict(inherited["env"]) if inherited else {},
                "args": dict(inherited["args"]) if inherited else {},
            }
            stages.append(current)
            aliases[str(len(stages) - 1)] = current  # COPY --from=0 biçimi
            if alias:
                aliases[alias.casefold()] = current
        elif instruction == "ARG" and current is not None:
            visible = {**global_args, **current["args"]}
            update = _docker_arg_update(args, visible)
            if update is not None and (update[0] in current["args"] or len(current["args"]) < 100):
                name, value = update
                if value is None:
                    current["args"].pop(name, None)
                else:
                    current["args"][name] = value
        elif instruction == "ENV" and current is not None:
            visible = {**current["args"], **current["env"]}
            for name, value in _docker_env_updates(args, visible).items():
                if value is None:
                    current["env"].pop(name, None)
                else:
                    current["env"][name] = value
        elif instruction == "RUN" and current is not None:
            visible = {**current["args"], **current["env"]}
            # Bir RUN içindeki ``&&``/``;`` parçalarını sırayla uygula. Bütün RUN için sanal üyeleri
            # önceden birleştirmek, aynı satırdaki ayrı ``apk add curl`` komutunun açık kurulumunu kaybederdi.
            for tokens in _package_token_groups(args, visible):
                segment = shlex.join(tokens)
                virtual_events = _apk_virtual_events(segment)
                virtual_additions = set().union(
                    *(members for adding, _group, members in virtual_events if adding)
                ) if any(adding for adding, _group, _members in virtual_events) else set()
                for installing, name in _package_changes(segment):
                    if installing:
                        current["packages"].add(name)
                        if name not in virtual_additions:
                            current["direct"].add(name)
                    else:
                        current["packages"].discard(name)
                        current["direct"].discard(name)
                for adding, group, members in virtual_events:
                    if adding:
                        current["virtuals"].setdefault(group, set()).update(members)
                    else:
                        removed = current["virtuals"].pop(group, set())
                        still_virtual = set().union(*current["virtuals"].values()) if current["virtuals"] else set()
                        for member in removed - current["direct"] - still_virtual:
                            current["packages"].discard(member)
        elif instruction == "COPY" and current is not None:
            source_stage = _full_root_copy_source(args)
            inherited = aliases.get(source_stage.casefold()) if source_stage else None
            if inherited is not None and inherited is not current:
                current["packages"].update(inherited["packages"])
                current["direct"].update(inherited.get("direct", ()))
                current["virtuals"].update(
                    {name: set(members) for name, members in inherited.get("virtuals", {}).items()}
                )
    if not stages:
        return {"format": "sniper-dockerfile-package-link/1", "final_stage": None, "base": None,
                "declared_packages": [], "matched_packages": [], "unmatched_packages": []}
    final = stages[-1]
    declared = sorted(final["packages"], key=str.casefold)
    inventory = {str(item.get("name") or "").casefold() for item in packages} | \
                {str(item.get("source") or "").casefold() for item in packages}
    matched = sorted((name for name in declared if name.casefold() in inventory), key=str.casefold)
    return {"format": "sniper-dockerfile-package-link/1",
            "final_stage": final["alias"] or str(len(stages) - 1), "base": final["base"],
            "declared_packages": declared, "matched_packages": matched,
            "unmatched_packages": sorted(set(declared) - set(matched), key=str.casefold)}


def _read_dockerfile(value: str, allowed_roots: tuple[Path, ...] | None) -> tuple[Path, str]:
    path = _allowed_input_path(value, allowed_roots)
    try:
        data = _read_regular_nofollow(path, 1_000_000)
        return path, data.decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ContainerScanError("Dockerfile düzenli, en çok 1 MB ve geçerli UTF-8 olmalı.") from exc


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def scan_image(path_value: str, *, osv_root: Path | None = None, ignore_unfixed: bool = False,
               allowed_roots: tuple[Path, ...] | None = None, dockerfile_path: str | None = None) -> dict[str, Any]:
    """İmajı tarar; sonuç proje analizi biçimindedir (``audit_kind: container``), bulgu takibi ve portföye girer."""
    started = time.monotonic()
    image_path = _allowed_input_path(path_value, allowed_roots)
    vfs, meta = load_image(_Source(image_path))
    release = parse_os_release(vfs.read(OS_RELEASE[0]) or vfs.read(OS_RELEASE[1]))
    ecosystem, package_type_or_note = os_ecosystem(release)
    warnings = list(vfs.warnings)
    if meta.get("note"):
        warnings.append(meta["note"])

    packages: list[dict[str, Any]] = []
    covered: list[str] = []
    covered_by_type: dict[str, list[str]] = {"deb": [], "apk": [], "rpm": []}
    unsupported_rpmdb: list[dict[str, str]] = []
    dpkg_data = vfs.read(DPKG_STATUS)
    if dpkg_data is not None:
        packages += parse_dpkg(dpkg_data, DPKG_STATUS)
        covered.append(DPKG_STATUS)
        covered_by_type["deb"].append(DPKG_STATUS)
    for path in sorted(p for p, kind in vfs.kinds.items() if kind == "dpkg-d"):
        packages += parse_dpkg(vfs.files[path], path)
        covered.append(path)
        covered_by_type["deb"].append(path)
    for path in APK_INSTALLED:
        data = vfs.read(path)
        if data is not None:
            packages += parse_apk(data, path)
            covered.append(path)
            covered_by_type["apk"].append(path)
            break
    for path in RPM_SQLITE:
        data = vfs.read(path)
        if data is not None:
            packages += parse_rpm_sqlite(data, path)
            covered.append(path)
            covered_by_type["rpm"].append(path)
            break
    else:
        for path in RPM_LEGACY:
            data = vfs.read(path)
            if data is None:
                continue
            backend = detect_legacy_rpmdb(data, path)
            unsupported_rpmdb.append({"path": path, "backend": backend})
            if backend == "berkeleydb":
                warnings.append(f"Desteklenmeyen BerkeleyDB RPM paket veritabanı bulundu: {path}; "
                                "RPM paketleri taranmadı.")
            elif backend == "ndb_candidate":
                warnings.append(f"Desteklenmeyen olası NDB RPM paket veritabanı bulundu: {path}; "
                                "RPM paketleri taranmadı.")
            else:
                warnings.append(f"Desteklenmeyen veya tanınmayan eski RPM paket veritabanı bulundu: {path}; "
                                "RPM paketleri taranmadı.")
    build_context = None
    if dockerfile_path:
        build_path, dockerfile = _read_dockerfile(dockerfile_path, allowed_roots)
        build_context = link_final_stage_packages(dockerfile, packages)
        build_context["dockerfile"] = build_path.name

    findings: list[dict[str, Any]] = []
    osv_info: dict[str, Any] | None = None
    expected_package_type = package_type_or_note if ecosystem else None
    if expected_package_type in covered_by_type and covered_by_type[expected_package_type]:
        inventory_status = "available"
        inventory_reason = None
    elif expected_package_type == "rpm" and unsupported_rpmdb:
        inventory_status = "unsupported"
        inventory_reason = "legacy_rpmdb_unsupported"
    elif expected_package_type in covered_by_type:
        inventory_status = "missing"
        inventory_reason = "package_database_missing"
    else:
        inventory_status = "unknown_os"
        inventory_reason = "os_ecosystem_unknown"
    package_inventory = {
        "status": inventory_status,
        "package_type": expected_package_type if expected_package_type in covered_by_type else None,
        "covered_files": list(covered_by_type.get(str(expected_package_type), [])),
        "unsupported_files": unsupported_rpmdb,
        "reason": inventory_reason,
    }
    if ecosystem:
        package_type = package_type_or_note
        relevant = [p for p in packages if p["type"] == package_type]
        if not relevant:
            warnings.append("İşletim sistemi paket veritabanı bulunamadı ya da boş.")
        try:
            index, osv_info = load_index(ecosystem, root=osv_root)
            findings = match_packages(relevant, index, package_type, ignore_unfixed=ignore_unfixed)
        except (FileNotFoundError, osv_db_refresh.OSVRefreshError):
            warnings.append(f"{ecosystem} için çevrimdışı OSV veritabanı yok: "
                            f"python3 scripts/osv_refresh.py --ecosystem '{archive_ecosystem(ecosystem)}' ile indirin.")
            osv_info = {"ecosystem": ecosystem, "status": "missing"}
    else:
        warnings.append(str(package_type_or_note))

    components = language_components(vfs)
    language_findings: list[dict[str, Any]] = []
    language_matching = "unavailable"
    if components and _LANGUAGE_MATCHER is not None:
        try:
            language_findings = list(_LANGUAGE_MATCHER(components))[:MAX_FINDINGS]
            language_matching = "matched"
        except Exception:  # noqa: BLE001 - eşleyici hatası OS taramasını etkilemez
            language_matching = "failed"
    elif not components:
        language_matching = "none"
    findings += language_findings

    weights = {"critical": 24, "high": 14, "medium": 7, "low": 3, "info": 0}
    by_category: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)
    for item in findings:
        by_category[item["category"]].append(item)
    penalty = sum(max(weights[i["severity"]] for i in items) + min(6, max(0, len(items) - 1))
                  for items in by_category.values())
    score = max(0, 100 - min(100, penalty))
    grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "E"
    findings.sort(key=lambda f: (_SEVERITY_ORDER[::-1].index(f["severity"]), f["file"], f["title"]))
    counts = collections.Counter(f["severity"] for f in findings)
    tags = meta.get("tags") or []
    name = tags[0] if tags else image_path.name
    fixable = sum(1 for f in findings if f.get("fix_state") == "fixed")
    return {
        "created_at": _utc_now(),
        "audit_kind": "container",
        "project_path": str(image_path),
        "project_name": name[:200],
        "score": score,
        "grade": grade,
        "file_count": len(packages),
        "bytes_scanned": int(vfs.bytes_read),
        "findings": findings,
        "finding_counts": {s: counts.get(s, 0) for s in _SEVERITY_ORDER[::-1]},
        "languages": {},
        "manifests": [],
        "checks": [
            {"id": "os_packages", "label": "İşletim sistemi paket açıkları",
             "status": "review" if any(f["category"] == CATEGORY for f in findings) else
                       ("pass" if inventory_status == "available" and osv_info and osv_info.get("sha256") else "na")},
            {"id": "components", "label": "Dil paketleri (PyPI/npm/Maven)",
             "status": "review" if language_findings else ("na" if language_matching != "matched" else "pass")},
        ],
        "skipped_files": dict(vfs.skipped),
        "warnings": warnings,
        "container": {
            "format": FORMAT,
            "image": {"format": meta.get("format"), "layers": meta.get("layers", 0), "tags": tags,
                      "platform": meta.get("platform")},
            "zstd_readiness": zstd_readiness(),
            "os": {"id": release.get("ID", ""), "version": release.get("VERSION_ID", ""),
                   "pretty_name": release.get("PRETTY_NAME", "")[:120], "ecosystem": ecosystem},
            "package_count": len(packages),
            "package_types": dict(collections.Counter(p["type"] for p in packages)),
            "covered_files": covered,
            "package_inventory": package_inventory,
            "osv": osv_info,
            "ignore_unfixed": bool(ignore_unfixed),
            "fixable_findings": fixable,
            "language_components": len(components),
            "language_matching": language_matching,
            "seconds": round(time.monotonic() - started, 2),
            "members": vfs.members,
            "build_context": build_context,
        },
        # SBOM ve dil eşleştirmesi için kompakt bileşen listeleri (özet JSON'unda saklanır)
        "components": [{"type": p["type"], "name": p["name"], "version": p["version"], "source": p["source"],
                        "arch": p["arch"]} for p in packages][:50_000],
        "language_packages": components[:MAX_LANGUAGE_COMPONENTS],
    }


# ---------------------------------------------------------------------------
# CycloneDX
# ---------------------------------------------------------------------------
def _os_purl(component: dict[str, Any], os_id: str, os_version: str) -> str:
    distro = f"{os_id}-{os_version}" if os_id and os_version else os_id
    namespace = {"deb": os_id or "debian", "apk": os_id or "alpine", "rpm": os_id or "rpm"}[component["type"]]
    qualifiers = []
    if component.get("arch"):
        qualifiers.append(f"arch={component['arch']}")
    if distro:
        qualifiers.append(f"distro={distro}")
    if component.get("source") and component["source"] != component["name"]:
        qualifiers.append(f"upstream={component['source']}")
    return f"pkg:{component['type']}/{namespace}/{component['name']}@{component['version']}" + (
        "?" + "&".join(qualifiers) if qualifiers else "")


def cyclonedx_sbom(result: dict[str, Any]) -> dict[str, Any]:
    container = result.get("container") or {}
    os_info = container.get("os") or {}
    components = []
    for item in result.get("components") or []:
        purl = _os_purl(item, str(os_info.get("id") or ""), str(os_info.get("version") or ""))
        components.append({"type": "library", "bom-ref": purl, "name": item["name"], "version": item["version"],
                           "purl": purl})
    for item in result.get("language_packages") or []:
        components.append({"type": "library", "bom-ref": item["purl"], "name": item["name"],
                           "version": item["version"], "purl": item["purl"],
                           "properties": [{"name": "sniper:path", "value": item.get("path", "")}]})
    serial = hashlib.sha256(json.dumps([result.get("project_path"), result.get("created_at")]).encode()).hexdigest()
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{serial[:8]}-{serial[8:12]}-{serial[12:16]}-{serial[16:20]}-{serial[20:32]}",
        "version": 1,
        "metadata": {
            "timestamp": result.get("created_at"),
            "tools": [{"vendor": "Sniper", "name": "container_scan", "version": FORMAT}],
            "component": {"type": "container", "name": result.get("project_name"),
                          "properties": [{"name": "sniper:os", "value": str(os_info.get("pretty_name") or "")},
                                         {"name": "sniper:osv-ecosystem", "value": str(os_info.get("ecosystem") or "")}]},
        },
        "components": components,
    }
