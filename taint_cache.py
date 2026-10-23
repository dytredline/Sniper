"""Taint analizi sonuçları için güvenli disk önbelleği (yalnız JSON; pickle YOK).

Değişmemiş bir projenin ikinci taraması, dosyalar arası analizi yeniden yapmadan önbellekten döner.

* Konum: ``$SNIPER_DATA_DIR/taint-cache`` (dizin 0700, dosyalar 0600; sahip denetimi). Veri dizini
  yoksa ya da güvensizse önbellek kapalıdır (analiz yine yapılır).
* Anahtar: önbellek biçimi + tüm analiz motorlarının parmak izi ve tüm model dosyalarının
  (yerleşik, SNIPER_TAINT_MODELS ve işletmeci özel kuralları) içerik özeti + motor
  ayarları + projedeki her dosyanın (göreli yol, içerik SHA-256) listesi. Kök dizin anahtarda değildir.
* Bozuk, sınırı aşan, biçimi tutmayan ya da anahtarı eşleşmeyen dosya sessizce yok sayılır.
* Sınırlı LRU: en çok ``MAX_ENTRIES`` dosya ve ``MAX_TOTAL_BYTES``; isabet dosyanın mtime'ını tazeler.
* ``SNIPER_TAINT_CACHE=0`` önbelleği kapatır.

Önbellek yalnız serileştirilebilir sözlükler saklar; nesneleri çağıran (taint_flow) kurar.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import time
from typing import Any

from engine_identity import engine_digest
from safe_file_read import read_text_bounded

CACHE_FORMAT = "sniper-taint-cache-v1"
MAX_ENTRY_BYTES = 64_000_000
MAX_ENTRIES = 64
MAX_TOTAL_BYTES = 512_000_000
APP_DIR = Path(__file__).resolve().parent


def enabled() -> bool:
    return os.environ.get("SNIPER_TAINT_CACHE", "1").strip().lower() not in {"0", "false", "no", "off"}


def cache_dir(create: bool = True) -> Path | None:
    """Güvenli önbellek dizini ya da None (yapılandırılmamış/güvensiz)."""
    raw = os.environ.get("SNIPER_DATA_DIR", "")
    if not raw or not enabled():
        return None
    data_dir = Path(raw)
    try:
        if not data_dir.is_absolute() or data_dir.is_symlink() or not data_dir.is_dir():
            return None
        directory = data_dir / "taint-cache"
        if create:
            directory.mkdir(mode=0o700, exist_ok=True)
        info = os.lstat(directory)
    except OSError:
        return None
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        return None
    return directory


def _model_files() -> list[Path]:
    import taint_models

    paths = sorted((APP_DIR / "rules" / "taint").glob("*.json"))
    extra = [Path(p).expanduser() for p in os.environ.get("SNIPER_TAINT_MODELS", "").split(os.pathsep) if p.strip()]
    custom = [Path(p) for p in taint_models._custom_model_paths()]
    return [*paths, *extra, *custom]


def engine_fingerprint() -> str:
    """Tum motor kodu ve modeller degisince degisen tam icerik ozeti."""
    digest = hashlib.sha256(CACHE_FORMAT.encode())
    digest.update(engine_digest(APP_DIR).encode("ascii") + b"\0")
    for path in sorted(set(_model_files()), key=lambda item: str(item)):
        digest.update(str(path).encode("utf-8", "surrogatepass") + b"\0")
        try:
            digest.update(path.read_bytes())
        except OSError:
            digest.update(b"<yok>")
        digest.update(b"\0")
    return digest.hexdigest()


def project_key(language: str, files: dict[str, str], settings: dict[str, Any]) -> str:
    digest = hashlib.sha256()
    digest.update(json.dumps({"format": CACHE_FORMAT, "language": language, "engine": engine_fingerprint(),
                              "settings": settings}, sort_keys=True).encode())
    for relpath in sorted(files):
        digest.update(relpath.encode("utf-8", "surrogatepass") + b"\0")
        digest.update(hashlib.sha256(files[relpath].encode("utf-8", "surrogatepass")).digest())
    return digest.hexdigest()


def load(key: str) -> dict[str, Any] | None:
    """Anahtarın kaydı (``payload``) ya da None. Her hata sessizce None."""
    directory = cache_dir(create=False)
    if directory is None:
        return None
    path = directory / f"{key}.json"
    text = read_text_bounded(path, MAX_ENTRY_BYTES)
    if text is None:
        return None
    try:
        info = os.lstat(path)
        if info.st_uid != os.geteuid() or info.st_mode & 0o077:
            return None
        document = json.loads(text)
    except (OSError, ValueError, RecursionError):
        return None
    if not isinstance(document, dict) or document.get("format") != CACHE_FORMAT or document.get("key") != key:
        return None
    payload = document.get("payload")
    if not isinstance(payload, dict):
        return None
    try:
        os.utime(path)  # LRU: son kullanım
    except OSError:
        pass
    return payload


def store(key: str, payload: dict[str, Any]) -> bool:
    directory = cache_dir(create=True)
    if directory is None:
        return False
    text = json.dumps({"format": CACHE_FORMAT, "key": key, "payload": payload}, ensure_ascii=False, separators=(",", ":"))
    if len(text.encode("utf-8", "surrogatepass")) > MAX_ENTRY_BYTES:
        return False
    try:
        fd, tmp = tempfile.mkstemp(prefix=".kayit-", suffix=".tmp", dir=directory)
    except OSError:
        return False
    try:
        with os.fdopen(fd, "w", encoding="utf-8", errors="surrogatepass") as handle:
            os.fchmod(handle.fileno(), 0o600)
            handle.write(text)
        os.replace(tmp, directory / f"{key}.json")
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        return False
    _prune(directory)
    return True


def _prune(directory: Path) -> None:
    """En eski kullanılanlardan başlayarak sınırların üstünü sil (yalnız bu önbelleğin dosyaları)."""
    entries = []
    for path in directory.glob(".kayit-*.tmp"):
        try:  # yarıda kalmış yazımlar (süreç öldürüldüyse) bir saat sonra temizlenir
            if os.lstat(path).st_mtime < time.time() - 3600:
                path.unlink()
        except OSError:
            pass
    for path in directory.glob("*.json"):
        try:
            info = os.lstat(path)
        except OSError:
            continue
        if stat.S_ISREG(info.st_mode) and len(path.stem) == 64:
            entries.append((info.st_mtime_ns, info.st_size, path))
    entries.sort(reverse=True)
    total = 0
    for index, (_, size, path) in enumerate(entries):
        total += size
        if index >= MAX_ENTRIES or total > MAX_TOTAL_BYTES:
            try:
                path.unlink()
            except OSError:
                pass
