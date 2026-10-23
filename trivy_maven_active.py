from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
from contextlib import contextmanager
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from project_analyzer import validate_project_path
from tool_report_trivy import parse_trivy_native_json_summary
from trivy_vuln_active import (
    TrivyVulnBusy,
    TrivyVulnExecutionError,
    TrivyVulnInvalidInput,
    TrivyVulnUnavailable,
    _streaming_sha256,
)

_MAX_POM_BYTES = 1_000_000
_MAX_REPORT_BYTES = 2_000_000
_MAVEN_NS = "http://maven.apache.org/POM/4.0.0"


@contextmanager
def _verified_binary(path: Path):
    """Execute a SHA-pinned sealed copy, so pathname or inode swaps cannot change it."""
    expected = os.environ.get("SNIPER_TRIVY_BINARY_SHA256", "")
    if re.fullmatch(r"[0-9a-f]{64}", expected) is None:
        raise TrivyVulnUnavailable("Trivy ikilisi SHA256 değeri yapılandırılmamış.")
    source_fd = None
    snapshot_fd = None
    try:
        if not hasattr(os, "memfd_create") or not hasattr(os, "MFD_ALLOW_SEALING"):
            raise TrivyVulnUnavailable("Doğrulanmış Trivy çalıştırması kullanılamıyor.")
        source_fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        before = os.fstat(source_fd)
        if (not stat.S_ISREG(before.st_mode) or not (before.st_mode & 0o111)
                or not 0 < before.st_size <= 256_000_000):
            raise TrivyVulnUnavailable("Trivy ikilisi kullanılamıyor.")
        snapshot_fd = os.memfd_create("sniper-trivy-maven", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        os.fchmod(snapshot_fd, 0o500)
        copied = 0
        while copied < before.st_size:
            chunk = os.read(source_fd, min(1_048_576, before.st_size - copied))
            if not chunk:
                break
            view = memoryview(chunk)
            while view:
                written = os.write(snapshot_fd, view)
                view = view[written:]
            copied += len(chunk)
        after = os.fstat(source_fd)
        if copied != before.st_size or (
            before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns
        ) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns
        ):
            raise TrivyVulnUnavailable("Trivy ikilisi doğrulama sırasında değişti.")
        seals = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
        fcntl.fcntl(snapshot_fd, fcntl.F_ADD_SEALS, seals)
        if fcntl.fcntl(snapshot_fd, fcntl.F_GET_SEALS) & seals != seals:
            raise TrivyVulnUnavailable("Doğrulanmış Trivy çalıştırması kullanılamıyor.")
        digest = hashlib.sha256()
        for offset in range(0, copied, 1_048_576):
            chunk = os.pread(snapshot_fd, min(1_048_576, copied - offset), offset)
            if not chunk:
                raise TrivyVulnUnavailable("Doğrulanmış Trivy çalıştırılabiliri eksik.")
            digest.update(chunk)
        if digest.hexdigest() != expected:
            raise TrivyVulnUnavailable("Trivy ikilisi SHA256 değeri uyuşmuyor.")
        yield f"/proc/self/fd/{snapshot_fd}", snapshot_fd
    except OSError as exc:
        raise TrivyVulnUnavailable("Doğrulanmış Trivy çalıştırması kullanılamıyor.") from exc
    finally:
        if source_fd is not None:
            os.close(source_fd)
        if snapshot_fd is not None:
            os.close(snapshot_fd)


def _read_root_pom(root: Path) -> bytes:
    """Open every directory component and the root pom by fd without following links."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    directory_fd = None
    pom_fd = None
    try:
        directory_fd = os.open("/", flags)
        for component in root.parts[1:]:
            next_fd = os.open(component, flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        pom_fd = os.open("pom.xml", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory_fd)
        info = os.fstat(pom_fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > _MAX_POM_BYTES:
            raise TrivyVulnInvalidInput("Kök pom.xml 1.000.000 baytın altında normal bir dosya olmalı.")
        chunks = bytearray()
        while len(chunks) <= _MAX_POM_BYTES:
            block = os.read(pom_fd, min(65536, _MAX_POM_BYTES + 1 - len(chunks)))
            if not block:
                break
            chunks.extend(block)
        if len(chunks) != info.st_size or len(chunks) > _MAX_POM_BYTES:
            raise TrivyVulnInvalidInput("Kök pom.xml okuma sırasında değişti veya boyut sınırını aştı.")
        final = os.fstat(pom_fd)
        if (final.st_dev, final.st_ino, final.st_size, final.st_mtime_ns) != (
            info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns
        ):
            raise TrivyVulnInvalidInput("Kök pom.xml okuma sırasında değişti.")
        return bytes(chunks)
    except OSError as exc:
        raise TrivyVulnInvalidInput("Kök pom.xml eksik, bağlantılı veya okunamıyor.") from exc
    finally:
        if pom_fd is not None:
            os.close(pom_fd)
        if directory_fd is not None:
            os.close(directory_fd)


def _validate_pom(data: bytes) -> None:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise TrivyVulnInvalidInput("Kök pom.xml UTF-8 XML olmalı.") from exc
    if not data or "\x00" in text or "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper():
        raise TrivyVulnInvalidInput("Kök pom.xml desteklenmeyen XML bildirimleri veya varlıklar içeriyor.")
    try:
        root = ET.fromstring(data)
    except (ET.ParseError, ValueError) as exc:
        raise TrivyVulnInvalidInput("Kök pom.xml geçerli XML içermeli.") from exc
    if root.tag not in ("project", f"{{{_MAVEN_NS}}}project"):
        raise TrivyVulnInvalidInput("Kök pom.xml bir Maven proje belgesi olmalı.")
    namespace = f"{{{_MAVEN_NS}}}" if root.tag.startswith("{") else ""
    model_version = root.find(f"{namespace}modelVersion")
    if model_version is None or (model_version.text or "").strip() != "4.0.0":
        raise TrivyVulnInvalidInput("Kök pom.xml Maven modelVersion 4.0.0 bildirmeli.")


def _validate_runtime() -> tuple[Path, Path]:
    binary = os.environ.get("SNIPER_TRIVY_BINARY")
    if not binary:
        raise TrivyVulnUnavailable("Trivy ikilisi yapılandırılmamış.")
    binary_path = Path(binary)
    if not binary_path.is_absolute() or binary_path.is_symlink() or not binary_path.is_file() or not os.access(binary_path, os.X_OK):
        raise TrivyVulnUnavailable("Trivy ikilisi çalıştırılabilir, normal ve yerel bir dosya olmalı.")

    raw_cache = os.environ.get("SNIPER_TRIVY_VULN_CACHE_DIR")
    if not raw_cache:
        raise TrivyVulnUnavailable("Trivy zafiyet önbellek dizini yapılandırılmamış.")
    cache_path = Path(raw_cache)
    if not cache_path.is_absolute() or cache_path.is_symlink() or not cache_path.is_dir():
        raise TrivyVulnUnavailable("Trivy zafiyet önbelleği mutlak ve gerçek bir dizin olmalı.")
    if (cache_path / "db").is_symlink() or not (cache_path / "db").is_dir():
        raise TrivyVulnUnavailable("Trivy zafiyet veritabanı dizini kullanılamıyor.")
    cache_path = cache_path.resolve()
    metadata_path = cache_path / "db" / "metadata.json"
    db_path = cache_path / "db" / "trivy.db"
    for path in (metadata_path, db_path):
        if path.is_symlink() or not path.is_file():
            raise TrivyVulnUnavailable("Trivy zafiyet veritabanı kullanılamıyor.")
    expected_sha = os.environ.get("SNIPER_TRIVY_VULN_DB_SHA256", "")
    if re.fullmatch(r"[0-9a-f]{64}", expected_sha) is None:
        raise TrivyVulnUnavailable("Trivy zafiyet veritabanı SHA256 değeri yapılandırılmamış.")
    if _streaming_sha256(db_path) != expected_sha:
        raise TrivyVulnUnavailable("Trivy zafiyet veritabanı SHA256 değeri uyuşmuyor.")
    return binary_path, cache_path


def _load_report(report_path: Path) -> dict[str, Any]:
    fd = None
    try:
        fd = os.open(report_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > _MAX_REPORT_BYTES:
            raise TrivyVulnExecutionError("Trivy raporu kullanılamıyor veya çok büyük.")
        data = bytearray()
        while len(data) <= _MAX_REPORT_BYTES:
            block = os.read(fd, min(65536, _MAX_REPORT_BYTES + 1 - len(data)))
            if not block:
                break
            data.extend(block)
        final = os.fstat(fd)
        if (len(data) != info.st_size or len(data) > _MAX_REPORT_BYTES
                or (final.st_dev, final.st_ino, final.st_size, final.st_mtime_ns, final.st_ctime_ns)
                != (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)):
            raise TrivyVulnExecutionError("Trivy raporu değişti veya boyut sınırını aştı.")
        report = json.loads(data.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TrivyVulnExecutionError("Trivy raporu eksik veya geçersiz JSON.") from exc
    finally:
        if fd is not None:
            os.close(fd)
    if not isinstance(report, dict):
        raise TrivyVulnExecutionError("Trivy raporu bir JSON nesnesi olmalı.")
    results = report.get("Results")
    if (not isinstance(results, list) or len(results) != 1 or not isinstance(results[0], dict)
            or results[0].get("Target") != "pom.xml" or results[0].get("Type") != "pom"
            or results[0].get("Class") != "lang-pkgs"
            or any(key in results[0] for key in ("Misconfigurations", "Secrets", "Licenses"))):
        raise TrivyVulnExecutionError("Trivy raporu yalnız kök Maven pom sonucunu içermiyordu.")
    return report


def run_local_trivy_maven_vulnerability(project_path: str) -> dict[str, Any]:
    """Scan only a home-contained root pom.xml with pinned offline Trivy DB."""
    src_root = validate_project_path(project_path, allowed_roots=(Path.home().resolve(),))
    data_dir = os.environ.get("SNIPER_DATA_DIR")
    if not data_dir:
        raise TrivyVulnUnavailable("Trivy zafiyet tarayıcısı kullanılamıyor.")
    lock_path = Path(data_dir).resolve() / "trivy.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_fd = None
    try:
        try:
            lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            if not stat.S_ISREG(os.fstat(lock_fd).st_mode):
                raise TrivyVulnUnavailable("Trivy kilidi kullanılamıyor.")
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise TrivyVulnBusy("Başka bir Trivy taraması sürüyor.") from exc
        except OSError as exc:
            raise TrivyVulnUnavailable("Trivy kilidi kullanılamıyor.") from exc

        binary_path, cache_path = _validate_runtime()
        content = _read_root_pom(src_root)
        _validate_pom(content)
        with _verified_binary(binary_path) as binary, tempfile.TemporaryDirectory(prefix="sniper_trivy_maven_") as temp:
            scratch = Path(temp)
            staged = scratch / "input"
            staged.mkdir()
            (staged / "pom.xml").write_bytes(content)
            report_path = scratch / "report.json"
            argv = [
                binary[0], "fs", "--scanners", "vuln", "--offline-scan",
                "--skip-db-update", "--skip-java-db-update", "--skip-check-update",
                "--skip-version-check", "--config=", "--ignorefile=", "--format", "json",
                "--output", str(report_path), "--cache-dir", str(cache_path), "--timeout", "60s",
                str(staged),
            ]
            env = os.environ.copy()
            env["HOME"] = str(scratch)
            env["XDG_CACHE_HOME"] = str(scratch / "cache")
            try:
                process = subprocess.run(argv, env=env, stdout=subprocess.DEVNULL,
                                         stderr=subprocess.DEVNULL, timeout=90, check=False,
                                         pass_fds=(binary[1],))
            except subprocess.TimeoutExpired as exc:
                raise TrivyVulnExecutionError("Trivy çalıştırması zaman aşımına uğradı.") from exc
            except OSError as exc:
                raise TrivyVulnExecutionError("Trivy çalıştırılamadı.") from exc
            if process.returncode != 0:
                raise TrivyVulnExecutionError("Trivy çalıştırılamadı.")
            report = _load_report(report_path)
            try:
                summary = parse_trivy_native_json_summary(report)
            except ValueError as exc:
                raise TrivyVulnExecutionError("Trivy raporu geçersiz.") from exc
            summary["profile"] = "local-maven-pom-v1"
            return summary
    finally:
        if lock_fd is not None:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)
