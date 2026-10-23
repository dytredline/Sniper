#!/usr/bin/env python3
"""Joern PHP ön ucu (php2cpg) için en küçük PHP yorumlayıcısını resmî kaynaktan kur (root gerekmez).

php2cpg, PHP kodunu ayrıştırmak için paketlediği php-parser.phar'ı bir ``php`` yorumlayıcısıyla
çalıştırır. php.net Linux ikilisi dağıtmadığından önceden edinilip onaylanmış resmî kaynak arşivi
zorunlu ``--archive`` parametresiyle verilir, SHA-256 değeri ``joern_active.PHP_SOURCE_SHA256`` ile
doğrulanır ve yalnız CLI + tokenizer + ctype + phar (php-parser.phar için) ile derlenir
(ağ, veritabanı, XML eklentisi yok). Sonuç ``<araç dizini>/php/<sürüm>/bin/php`` olarak salt okunur
kurulur; ``provenance.json`` kaynak ve ikili SHA-256 değerlerini mimari onay bekliyor durumuyla kaydeder.
Derleme runtime'ı etkinleştirmez: ``joern_active`` ayrıca kod içindeki onaylı ikili SHA-256 kaydını ister.

Bu betik ağdan arşiv indirmez.

Kullanım:
    python3 scripts/joern_install_php.py --archive php-8.3.36.tar.xz [--jobs 8]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import joern_active  # noqa: E402

SOURCE_URL = f"https://www.php.net/distributions/php-{joern_active.PHP_VERSION}.tar.xz"
CONFIGURE = ["--disable-all", "--enable-cli", "--disable-cgi", "--disable-phpdbg", "--enable-tokenizer",
             "--enable-ctype", "--enable-phar", "--without-pear", "--without-sqlite3", "--without-pdo-sqlite", "--disable-opcache"]
MAX_ARCHIVE_BYTES = 40_000_000


def _pending_provenance(binary: bytes) -> dict[str, str]:
    return {
        "tool": "php",
        "version": joern_active.PHP_VERSION,
        "source": SOURCE_URL,
        "source_sha256": joern_active.PHP_SOURCE_SHA256,
        "configure": " ".join(CONFIGURE),
        "binary_sha256": hashlib.sha256(binary).hexdigest(),
        "activation": "pending_architecture_binary_approval",
    }


def _copy_verified_archive(source: Path, destination: Path) -> Path:
    """Arşivi no-follow FD'den özel kopyaya al; özeti ve okuma süresince kimliği sabitle."""
    source_fd = -1
    destination_fd = -1
    try:
        source_fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        before = os.fstat(source_fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_ARCHIVE_BYTES:
            raise SystemExit("PHP kaynak arşivi düzenli bir yerel dosya olmalı.")
        destination_fd = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o400,
        )
        digest = hashlib.sha256()
        copied = 0
        while True:
            block = os.read(source_fd, 1 << 20)
            if not block:
                break
            copied += len(block)
            if copied > MAX_ARCHIVE_BYTES:
                raise SystemExit("PHP kaynak arşivi boyut sınırını aşıyor.")
            digest.update(block)
            view = memoryview(block)
            while view:
                written = os.write(destination_fd, view)
                view = view[written:]
        os.fsync(destination_fd)
        after = os.fstat(source_fd)
    except OSError as exc:
        raise SystemExit("PHP kaynak arşivi düzenli bir yerel dosya olmalı.") from exc
    finally:
        if destination_fd >= 0:
            os.close(destination_fd)
        if source_fd >= 0:
            os.close(source_fd)
    identity = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    if identity(before) != identity(after) or copied != before.st_size:
        raise SystemExit("PHP kaynak arşivi doğrulama sırasında değişti.")
    if digest.hexdigest() != joern_active.PHP_SOURCE_SHA256:
        raise SystemExit("PHP kaynak arşivinin SHA-256 değeri resmî değerle eşleşmiyor.")
    os.chmod(destination, 0o400)
    return destination


def _prepare_install_directories(target: Path) -> Path:
    """Kurulum zincirindeki kullanıcıya ait dizinleri oluştur ve group/world write bitlerini kapat."""
    for directory in (target.parent, target, target / "bin"):
        try:
            directory.mkdir(parents=True, exist_ok=True, mode=0o755)
            info = os.lstat(directory)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
                raise OSError("untrusted install directory")
            os.chmod(directory, 0o755)
            info = os.lstat(directory)
            if info.st_mode & 0o022:
                raise OSError("writable install directory")
        except OSError as exc:
            raise SystemExit("PHP kurulum dizini güvenli biçimde hazırlanamadı.") from exc
    return target / "bin"


def _write_new_file(path: Path, data: bytes, mode: int) -> None:
    fd = -1
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.fsync(fd)
        os.fchmod(fd, mode)
    except OSError as exc:
        raise SystemExit(f"PHP kurulum dosyası güvenli biçimde yazılamadı: {path.name}") from exc
    finally:
        if fd >= 0:
            os.close(fd)


def _safe_extract(archive: Path, destination: Path) -> Path:
    with tarfile.open(archive, "r:xz") as tar:
        for member in tar.getmembers():
            name = Path(member.name)
            if name.is_absolute() or ".." in name.parts or not (member.isfile() or member.isdir() or member.issym()):
                raise SystemExit(f"Güvensiz arşiv girdisi: {member.name}")
            if member.issym() and (Path(member.linkname).is_absolute() or ".." in Path(member.linkname).parts):
                raise SystemExit(f"Dışarıyı gösteren bağ: {member.name}")
        tar.extractall(destination, filter="data")
    roots = [p for p in destination.iterdir() if p.is_dir()]
    if len(roots) != 1:
        raise SystemExit("Beklenmeyen arşiv yapısı.")
    return roots[0]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--archive", type=Path, required=True,
                        help="Önceden edinilmiş ve onaylanmış php-<sürüm>.tar.xz (ağdan indirilmez)")
    parser.add_argument("--jobs", type=int, default=4)
    args = parser.parse_args(argv)
    target = joern_active.php_home()
    if (target / "bin" / "php").exists():
        try:
            joern_active.verified_php()
        except joern_active.JoernUnavailable as exc:
            raise SystemExit(f"Mevcut PHP kurulumu doğrulanamadı: {exc}") from exc
        print(f"Zaten kurulu ve doğrulandı: {target}")
        return 0
    with tempfile.TemporaryDirectory(prefix="sniper-php-") as tmp:
        work = Path(tmp)
        archive = _copy_verified_archive(args.archive, work / f"php-{joern_active.PHP_VERSION}.tar.xz")
        source = _safe_extract(archive, work / "src")
        env = {"PATH": "/usr/bin:/bin", "HOME": str(work), "LANG": "C"}
        subprocess.run(["./configure", f"--prefix={target}", *CONFIGURE], cwd=source, env=env, check=True,
                       stdout=subprocess.DEVNULL)
        subprocess.run(["make", f"-j{max(1, args.jobs)}"], cwd=source, env=env, check=True, stdout=subprocess.DEVNULL)
        built = source / "sapi" / "cli" / "php"
        binary = built.read_bytes()
        if len(binary) > joern_active.MAX_PHP_BYTES:
            raise SystemExit("Derlenen PHP ikilisi boyut sınırını aşıyor.")
        binary_dir = _prepare_install_directories(target)
        _write_new_file(binary_dir / "php", binary, 0o555)
        provenance = _pending_provenance(binary)
        _write_new_file(
            target / "provenance.json",
            (json.dumps(provenance, indent=1) + "\n").encode("utf-8"),
            0o444,
        )
    print(f"Derlendi, mimari onay bekliyor: {target / 'bin' / 'php'}")
    print(f"Onay adayı PHP ikili SHA-256: {provenance['binary_sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
