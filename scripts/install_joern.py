#!/usr/bin/env python3
"""Joern derin analiz modu için JDK 25 LTS ve Joern'ü doğrulayarak kur (root gerekmez).

Arşivler önceden indirilmiş olmalıdır (resmî kaynaklar):

* Eclipse Temurin 25 (aarch64/x64) — https://github.com/adoptium/temurin25-binaries/releases
* Joern ``joern-cli-linux-<mimari>.zip`` + ``.sha512`` — https://github.com/joernio/joern/releases

Doğrulama: JDK arşivi Adoptium API'sinin yayımladığı SHA-256 ile, Joern zip'i GitHub
varlık özeti (SHA-256) ve resmî ``.sha512`` dosyasıyla karşılaştırılır. Açma sırasında
yol aşımı, mutlak yol ve kurulum dışını gösteren bağlar reddedilir; kurulumdan sonra
tüm dosyalar salt okunur yapılır ve Joern için dosya başına SHA-256 içeren
``SNIPER-INSTALL-MANIFEST.json`` üretilir. Çıktıdaki ``java_sha256`` ve ``manifest_sha256``
değerleri ``tool_pins.PINS["joern-jdk"]`` ve ``joern_active.JOERN_MANIFEST_SHA256`` içine
sabitlenir (veya ``SNIPER_JOERN_JDK_SHA256`` / ``SNIPER_JOERN_MANIFEST_SHA256``).

Kullanım:
  python3 scripts/install_joern.py --jdk-archive OpenJDK25U-...tar.gz \\
      --joern-archive joern-cli-linux-arm64.zip --joern-sha512 joern-cli-linux-arm64.zip.sha512
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import shutil
import stat
import sys
import tarfile
import zipfile

APP_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(APP_ROOT))

from joern_active import JOERN_VERSION, MANIFEST_NAME  # noqa: E402
from tool_pins import SNIPER_TOOLS_DIR  # noqa: E402

JDK_VERSION = "25.0.4.1+1"
# Adoptium Temurin 25 sürüm varlığının yayımlanan SHA-256 değeri.
JDK_ARCHIVES = {
    "aarch64": ("OpenJDK25U-jdk_aarch64_linux_hotspot_25.0.4.1_1.tar.gz",
                "69df11a02cfa3ef7d7ca645e03edce6778ec090e100f6ae2b42097865730ac52"),
}
# GitHub sürüm varlık özeti (api.github.com/repos/joernio/joern/releases, v4.0.647).
JOERN_ARCHIVES = {
    "aarch64": ("joern-cli-linux-arm64.zip",
                "1ac7d162d87cab4cdc2cf24d139fa95006d87d22df6b4b28c750cbb227861cab"),
}
MAX_MEMBERS = 50_000
MAX_EXTRACTED_BYTES = 6_000_000_000


def machine() -> str:
    raw = platform.machine().lower()
    return {"arm64": "aarch64", "amd64": "x86_64"}.get(raw, raw)


def file_digest(path: Path, algorithm: str) -> str:
    digest = hashlib.new(algorithm)
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def make_read_only(root: Path) -> None:
    for current, directories, files in os.walk(root, topdown=False):
        for name in files:
            path = Path(current) / name
            if path.is_symlink():
                continue
            mode = path.stat().st_mode
            os.chmod(path, 0o555 if mode & 0o111 else 0o444)
        for name in directories:
            path = Path(current) / name
            if not path.is_symlink():
                os.chmod(path, 0o555)
    os.chmod(root, 0o555)


def remove_tree(path: Path) -> None:
    """Salt okunur kurulumu (önceki sürüm/yarım kurulum) silebilmek için önce yazılabilir yap."""
    if not path.exists() and not path.is_symlink():
        return
    for current, directories, _files in os.walk(path):
        os.chmod(current, 0o700)
        for name in directories:
            child = Path(current) / name
            if not child.is_symlink():
                os.chmod(child, 0o700)
    shutil.rmtree(path)


def _safe_target(base: Path, member: str) -> Path:
    path = PurePosixPath(member)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise ValueError(f"güvensiz arşiv yolu: {member!r}")
    return base.joinpath(*path.parts)


def install_jdk(archive: Path, destination: Path) -> Path:
    name, expected = JDK_ARCHIVES[machine()]
    if archive.name != name or file_digest(archive, "sha256") != expected:
        raise SystemExit("JDK arşivi beklenen resmî sürümle (SHA-256) eşleşmiyor.")
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(destination.parent, 0o700)
    staging = destination.with_name(destination.name + ".partial")
    remove_tree(staging)
    staging.mkdir(parents=True, mode=0o700)
    with tarfile.open(archive) as tar:
        members = tar.getmembers()
        if len(members) > MAX_MEMBERS:
            raise SystemExit("JDK arşivinde çok fazla girdi var.")
        # Python 3.12 "data" süzgeci: mutlak yol, '..', aygıt dosyası ve dışarıyı gösteren bağları reddeder.
        for member in members:
            tar.extract(member, staging, filter=tarfile.data_filter)
    tops = [p for p in staging.iterdir()]
    if len(tops) != 1 or not tops[0].is_dir():
        raise SystemExit("JDK arşivi beklenmeyen yapıda.")
    remove_tree(destination)
    tops[0].rename(destination)
    staging.rmdir()
    make_read_only(destination)
    return destination / "bin" / "java"


def install_joern(archive: Path, sha512_file: Path, destination: Path) -> tuple[Path, str]:
    name, expected_sha256 = JOERN_ARCHIVES[machine()]
    if archive.name != name or file_digest(archive, "sha256") != expected_sha256:
        raise SystemExit("Joern arşivi GitHub varlık özetiyle (SHA-256) eşleşmiyor.")
    published = sha512_file.read_text(encoding="ascii").split()[0].strip().lower()
    if file_digest(archive, "sha512") != published:
        raise SystemExit("Joern arşivi resmî .sha512 dosyasıyla eşleşmiyor.")
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(destination.parent, 0o700)
    staging = destination.with_name(destination.name + ".partial")
    remove_tree(staging)
    staging.mkdir(parents=True, mode=0o700)
    total = 0
    with zipfile.ZipFile(archive) as bundle:
        infos = bundle.infolist()
        if len(infos) > MAX_MEMBERS:
            raise SystemExit("Joern arşivinde çok fazla girdi var.")
        for info in infos:
            target = _safe_target(staging, info.filename)
            mode = info.external_attr >> 16
            if stat.S_ISLNK(mode):
                link = bundle.read(info).decode("utf-8")
                resolved = (target.parent / link).resolve()
                if staging.resolve() not in resolved.parents:
                    raise SystemExit(f"Joern arşivinde kurulum dışını gösteren bağ: {info.filename}")
                target.parent.mkdir(parents=True, exist_ok=True)
                os.symlink(link, target)
                continue
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            total += info.file_size
            if total > MAX_EXTRACTED_BYTES:
                raise SystemExit("Joern arşivinin açılmış boyutu sınırı aşıyor.")
            target.parent.mkdir(parents=True, exist_ok=True)
            with bundle.open(info) as source, open(target, "xb") as sink:
                shutil.copyfileobj(source, sink, 1 << 20)
            if mode & 0o111:
                os.chmod(target, 0o755)
    home = staging / "joern-cli"
    if not (home / "lib").is_dir():
        raise SystemExit("Joern arşivi beklenmeyen yapıda (joern-cli/lib yok).")
    files: dict[str, str] = {}
    for current, _dirs, names in os.walk(home):
        for file_name in names:
            path = Path(current) / file_name
            if path.is_symlink() or not path.is_file():
                continue
            files[path.relative_to(home).as_posix()] = file_digest(path, "sha256")
    manifest = {
        "format": "sniper-joern-install-v1",
        "version": JOERN_VERSION,
        "archive": name,
        "archive_sha256": expected_sha256,
        "archive_sha512": published,
        "files": dict(sorted(files.items())),
    }
    raw = json.dumps(manifest, indent=1, sort_keys=True).encode("utf-8")
    (home / MANIFEST_NAME).write_bytes(raw)
    remove_tree(destination)
    staging.rename(destination)
    make_read_only(destination)
    return destination / "joern-cli", hashlib.sha256(raw).hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Joern + JDK 25 LTS doğrulamalı kurulum")
    parser.add_argument("--jdk-archive", type=Path, required=True)
    parser.add_argument("--joern-archive", type=Path, required=True)
    parser.add_argument("--joern-sha512", type=Path, required=True)
    parser.add_argument("--tools-dir", type=Path, default=SNIPER_TOOLS_DIR)
    args = parser.parse_args(argv)
    if machine() not in JDK_ARCHIVES:
        raise SystemExit(f"Desteklenmeyen mimari: {machine()}")
    tools = args.tools_dir
    tools.mkdir(parents=True, exist_ok=True, mode=0o700)
    java = install_jdk(args.jdk_archive, tools / "jdk" / JDK_VERSION)
    home, manifest_sha256 = install_joern(args.joern_archive, args.joern_sha512, tools / "joern" / JOERN_VERSION)
    print(json.dumps({
        "jdk": str(java.parent.parent),
        "java_sha256": file_digest(java, "sha256"),
        "joern_home": str(home),
        "manifest_sha256": manifest_sha256,
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
