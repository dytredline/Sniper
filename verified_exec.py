"""SHA-256 ile doğrulanmış ikiliyi, doğrulanan aynı dosya tanıtıcısından çalıştırma.

Yol tabanlı "önce hashle, sonra yolu çalıştır" deseni yarış durumuna açıktır:
hash hesaplandıktan sonra yol başka bir dosyaya (yeniden adlandırma, sembolik bağ)
çevrilebilir. Bu modül ikiliyi bir kez ``O_NOFOLLOW`` ile açar, ``fstat`` ile normal
dosya olduğunu doğrular, SHA-256'yı bu tanıtıcıdan hesaplar ve aracı
``/proc/self/fd/N`` üzerinden — yani hashlenen inode'un kendisinden — çalıştırır.
Tanıtıcı çocuk sürece ``pass_fds`` ile aktarılır; ``#!`` betiklerinde yorumlayıcı da
aynı yolu açabildiği için betikler de çalışır.

Sınır: Aynı kullanıcı kimliğine sahip bir saldırgan dosyanın içeriğini yerinde
değiştirebilir; bu yüzden grup/diğerleri tarafından yazılabilen veya başka bir
kullanıcıya ait ikililer reddedilir.
"""

from __future__ import annotations

import hashlib
import os
import stat
import threading
from typing import Any, Mapping

_CHUNK = 1 << 20
_DIGEST_CACHE: dict[tuple[int, int, int, int, int], str] = {}
_DIGEST_CACHE_LOCK = threading.Lock()
_DIGEST_CACHE_MAX = 64


class VerificationError(RuntimeError):
    """İkili açılamadı, güvenli değil veya sabitlenmiş SHA-256 ile uyuşmuyor."""

    def __init__(self, message: str, reason: str) -> None:
        super().__init__(message)
        self.reason = reason


def _fd_sha256(fd: int, info: os.stat_result) -> str:
    key = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    with _DIGEST_CACHE_LOCK:
        cached = _DIGEST_CACHE.get(key)
    if cached is not None:
        return cached
    digest = hashlib.sha256()
    offset = 0
    while True:
        chunk = os.pread(fd, _CHUNK, offset)
        if not chunk:
            break
        digest.update(chunk)
        offset += len(chunk)
    value = digest.hexdigest()
    with _DIGEST_CACHE_LOCK:
        if len(_DIGEST_CACHE) >= _DIGEST_CACHE_MAX:
            _DIGEST_CACHE.clear()
        _DIGEST_CACHE[key] = value
    return value


def _visible_root_uid(map_path: str = "/proc/self/uid_map", overflow_path: str = "/proc/sys/kernel/overflowuid") -> int | None:
    """Ana makine root'unun (UID 0) bu sürecin kullanıcı ad alanındaki görünen kimliği.

    systemd kullanıcı servisleri (PrivateTmp/ProtectSystem/ProtectHome) yalnız kendi UID'sini eşleyen bir ad
    alanında çalışır; orada root'a ait dosyalar çekirdeğin overflow kimliğiyle (65534) görünür. Root eşlenmişse
    (normal süreç) ``None`` döner: ek bir kimlik kabul edilmez. Eşleme okunamazsa da ``None`` (sıkı davranış).
    """
    try:
        with open(map_path, encoding="ascii") as handle:
            for line in handle:
                inside, outside, count = (int(part) for part in line.split())
                if outside <= 0 < outside + count:
                    return None
        with open(overflow_path, encoding="ascii") as handle:
            return int(handle.read().strip())
    except (OSError, ValueError):
        return None


def _namespaced_root_owned(path: str, info: os.stat_result) -> bool:
    """Kullanıcı ad alanında overflow sahipli görünen ikiliyi root'a ait say, yalnız şu koşullarla:

    * ana makine root'u bu ad alanında eşlenmemiş ve dosya sahibi tam olarak overflow kimliği;
    * bu süreç dosyaya yazamıyor (grup/diğer yazma bitleri ayrıca reddedildi);
    * üst dizin bize ait değil, grup/diğerleri tarafından yazılamıyor ve bu süreç oraya yazamıyor
      (dosya değiştirilemez ya da yerine başkası konamaz).

    Kalan sınır: ad alanı içinden eşlenmemiş başka bir ana makine kullanıcısı da overflow görünür; bu yüzden
    içerik ayrıca SHA-256 sabitlemesiyle doğrulanır ve yalnız ad alanı dışında (root eşliyken) tam sahiplik
    denetimi uygulanabilir.
    """
    overflow = _visible_root_uid()
    if overflow is None or info.st_uid != overflow or overflow == os.getuid():
        return False
    parent = os.path.dirname(path) or "/"
    try:
        parent_info = os.stat(parent, follow_symlinks=False)
    except OSError:
        return False
    if not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_uid not in (0, overflow):
        return False
    if parent_info.st_mode & 0o022:
        return False
    return not os.access(path, os.W_OK, follow_symlinks=False) and not os.access(parent, os.W_OK)


def _open_checked(path: str | os.PathLike[str] | None, label: str) -> tuple[int, os.stat_result]:
    raw = os.fspath(path) if path is not None else ""
    if not raw:
        raise VerificationError(f"{label} ikilisi yapılandırılmamış.", "binary_unconfigured")
    if not os.path.isabs(raw):
        raise VerificationError(f"{label} ikili yolu mutlak olmalı.", "binary_path_not_absolute")
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(raw, flags)
    except OSError as exc:
        raise VerificationError(
            f"{label} ikilisi açılamadı (yok, sembolik bağ veya erişilemiyor).", "binary_unavailable"
        ) from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise VerificationError(f"{label} ikilisi normal bir dosya değil.", "binary_not_regular")
        if not info.st_mode & 0o111:
            raise VerificationError(f"{label} ikilisi çalıştırılabilir değil.", "binary_not_executable")
        if info.st_mode & 0o022:
            raise VerificationError(
                f"{label} ikilisi grup veya diğer kullanıcılar tarafından yazılabilir; reddedildi.",
                "binary_writable_by_others",
            )
        if info.st_uid not in (0, os.getuid()) and not _namespaced_root_owned(raw, info):
            raise VerificationError(f"{label} ikilisi başka bir kullanıcıya ait; reddedildi.", "binary_foreign_owner")
    except BaseException:
        os.close(fd)
        raise
    return fd, info


def file_sha256(path: str | os.PathLike[str] | None, label: str = "Araç") -> str:
    """İkiliyi güvenli açıp SHA-256 döndürür (çalıştırmaz). Hata: ``VerificationError``."""
    fd, info = _open_checked(path, label)
    try:
        return _fd_sha256(fd, info)
    finally:
        os.close(fd)


class VerifiedExecutable:
    """Doğrulanmış ikilinin açık tanıtıcısı; ``with`` bloğu sonunda kapanır."""

    def __init__(self, fd: int, sha256: str, path: str, provenance: str) -> None:
        self.fd = fd
        self.sha256 = sha256
        self.path = path
        self.provenance = provenance

    @property
    def argv0(self) -> str:
        return f"/proc/self/fd/{self.fd}"

    def popen_kwargs(self, **kwargs: Any) -> dict[str, Any]:
        """``pass_fds``'e tanıtıcıyı ekler; ``close_fds`` kapatılamaz."""
        if kwargs.get("close_fds") is False:
            raise ValueError("close_fds=False doğrulanmış çalıştırmayla kullanılamaz")
        kwargs["pass_fds"] = tuple(sorted({*kwargs.get("pass_fds", ()), self.fd}))
        return kwargs

    def close(self) -> None:
        if self.fd >= 0:
            try:
                os.close(self.fd)
            finally:
                self.fd = -1

    def __enter__(self) -> "VerifiedExecutable":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def open_verified_executable(
    path: str | os.PathLike[str] | None,
    accepted: Mapping[str, str],
    *,
    label: str,
) -> VerifiedExecutable:
    """İkiliyi açar, SHA-256'sını ``accepted`` (sha256 → köken) ile karşılaştırır.

    Uyuşmazsa veya hiç sabitleme yoksa araç çalıştırılmaz; ``VerificationError``.
    """
    fd, info = _open_checked(path, label)
    try:
        if not accepted:
            raise VerificationError(
                f"{label} için sabitlenmiş SHA-256 yok; doğrulanmamış ikili çalıştırılmaz.", "pin_missing"
            )
        digest = _fd_sha256(fd, info)
        provenance = accepted.get(digest)
        if provenance is None:
            raise VerificationError(
                f"{label} ikilisinin SHA-256 değeri sabitlenmiş değerlerle uyuşmuyor; çalıştırılmadı.",
                "binary_digest_mismatch",
            )
    except BaseException:
        os.close(fd)
        raise
    return VerifiedExecutable(fd, digest, os.fspath(path), provenance)  # type: ignore[arg-type]
