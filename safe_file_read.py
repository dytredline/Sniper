"""Sınırlı ve TOCTOU'ya dayanıklı yerel dosya okuma yardımcısı.

Denetçiler proje ağacında ``stat()`` ardından ``read_text()`` çağırdığında iki
çağrı arasında dosya FIFO'ya / aygıta çevrilebilir (open süresiz bekler) ya da
büyüyebilir (sınır aşılır). Bu yardımcı dosyayı tek bir tanımlayıcı üzerinden
doğrular ve okur:

* ``O_NOFOLLOW``: son bileşen sembolik bağlantıysa açılmaz.
* ``O_NONBLOCK``: FIFO'ya yazan yoksa ``open`` beklemez.
* ``fstat``: açılan tanımlayıcı gerçekten normal dosya mı, boyutu sınırda mı.
* En fazla ``max_bytes + 1`` bayt okunur; sınır aşılırsa ``None`` döner.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

_CHUNK_BYTES = 65536


def _open_regular_candidate(path: str | os.PathLike[str]) -> int:
    """Open a file without following any pathname component.

    ``O_NOFOLLOW`` on a full pathname protects only the leaf.  Walk directory
    components relative to an already-open descriptor so an intermediate
    symlink replacement cannot redirect the read outside the selected tree.
    """
    raw = os.fspath(path)
    if not isinstance(raw, str) or not raw or "\x00" in raw:
        raise ValueError("invalid path")
    absolute = raw.startswith("/")
    parts = [part for part in raw.split("/") if part not in ("", ".")]
    if not parts:
        raise ValueError("file path required")
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    file_flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
    directory_fd = os.open("/" if absolute else ".", directory_flags)
    try:
        for component in parts[:-1]:
            next_fd = os.open(component, directory_flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        return os.open(parts[-1], file_flags, dir_fd=directory_fd)
    finally:
        os.close(directory_fd)


def read_bytes_bounded(path: str | os.PathLike[str], max_bytes: int, *, allow_empty: bool = False) -> bytes | None:
    """Normal dosyanın içeriğini en fazla ``max_bytes`` bayt olarak döndürür.

    Boş (``allow_empty`` kapalıyken), sınırı aşan, normal olmayan, sembolik
    bağlantı olan ya da okunamayan dosyalar için ``None`` döner; istisna atmaz.
    """
    if max_bytes < 0:
        return None
    try:
        fd = _open_regular_candidate(path)
    except (OSError, ValueError, TypeError):
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            return None
        size = info.st_size
        if size > max_bytes or (size == 0 and not allow_empty):
            return None
        chunks: list[bytes] = []
        total = 0
        limit = max_bytes + 1
        while total < limit:
            chunk = os.read(fd, min(_CHUNK_BYTES, limit - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        if total > max_bytes:
            return None
        if total == 0 and not allow_empty:
            return None
        return b"".join(chunks)
    except OSError:
        return None
    finally:
        os.close(fd)


def read_text_bounded(
    path: str | os.PathLike[str] | Path,
    max_bytes: int,
    *,
    errors: str = "replace",
    allow_empty: bool = False,
) -> str | None:
    """``read_bytes_bounded`` sonucunu UTF-8 olarak çözer (varsayılan errors=replace)."""
    data = read_bytes_bounded(path, max_bytes, allow_empty=allow_empty)
    if data is None:
        return None
    return data.decode("utf-8", errors=errors)
