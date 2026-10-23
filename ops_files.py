"""İşletim ayarları için küçük, kilitli JSON dosya deposu ($SNIPER_DATA_DIR altında).

Zamanlanmış taramalar ve bildirimler ana süreçte ve iş kuyruğunun alt süreçlerinde (job_worker) yazılabilir;
bu yüzden her okuma-değiştirme-yazma ``fcntl.flock`` ile ayrı bir kilit dosyası üzerinden yapılır. Yazım atomiktir
(geçici dosya + ``os.replace``), dosyalar 0600 oluşturulur ve sembolik bağ izlenmez.
"""
from __future__ import annotations

import contextlib
import fcntl
import json
import os
from pathlib import Path
from typing import Any, Callable, Iterator


class OpsStoreError(ValueError):
    """Veri dizini yapılandırılmamış ya da dosya okunamıyor/yazılamıyor."""


def data_dir(environ: dict[str, str] | None = None) -> Path:
    text = (os.environ if environ is None else environ).get("SNIPER_DATA_DIR", "")
    path = Path(text)
    if not text or not path.is_absolute() or path.is_symlink() or not path.is_dir():
        raise OpsStoreError("Sniper veri dizini yapılandırılmamış.")
    return path


@contextlib.contextmanager
def _locked(path: Path) -> Iterator[None]:
    lock_path = path.with_name(path.name + ".lock")
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def _read(path: Path, default: Callable[[], Any]) -> Any:
    if path.is_symlink():
        raise OpsStoreError(f"{path.name} sembolik bağ olamaz.")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return default()
    except OSError as exc:
        raise OpsStoreError(f"{path.name} okunamadı.") from exc
    try:
        with os.fdopen(fd, "rb") as handle:
            raw = handle.read(4_000_001)
    except OSError as exc:
        raise OpsStoreError(f"{path.name} okunamadı.") from exc
    if len(raw) > 4_000_000:
        raise OpsStoreError(f"{path.name} çok büyük.")
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return default()  # bozuk dosya: varsayılanla devam (bir sonraki yazım düzeltir)


def write_private(path: Path, data: bytes) -> None:
    """Atomik ve 0600 yazım (sır dosyaları dahil)."""
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{os.urandom(4).hex()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)


def read_json(name: str, default: Callable[[], Any], environ: dict[str, str] | None = None) -> Any:
    path = data_dir(environ) / name
    with _locked(path):
        return _read(path, default)


def update_json(name: str, default: Callable[[], Any], change: Callable[[Any], Any],
                environ: dict[str, str] | None = None) -> Any:
    """Kilit altında oku, ``change(veri)`` ile değiştir (yerinde ya da yeni değer döndürerek), yaz; sonucu döndür."""
    path = data_dir(environ) / name
    with _locked(path):
        current = _read(path, default)
        result = change(current)
        value = current if result is None else result
        write_private(path, json.dumps(value, ensure_ascii=False, indent=1, sort_keys=True).encode("utf-8"))
        return value
