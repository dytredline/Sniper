from __future__ import annotations

import fcntl
import hashlib
import json
import os
import stat
import subprocess
import tempfile
import tomllib
from pathlib import Path
from typing import Any

from trivy_vuln_active import (
    TrivyVulnBusy,
    TrivyVulnExecutionError,
    TrivyVulnInvalidInput,
    TrivyVulnUnavailable,
)
from tool_report_trivy import parse_trivy_native_json_summary

MAX_LOCK_BYTES = 5_000_000
MAX_REPORT_BYTES = 2_000_000
PROFILE = "local-cargo-lock-v1"
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC


def _read_root_lockfile(project_path: str) -> bytes:
    """Read only the root Cargo.lock through descriptors anchored in the service home.

    No resolved project pathname is reopened: replacing any parent with a symlink
    while this function runs cannot redirect the already-open directory fd.
    """
    home = Path.home().resolve(strict=True)
    raw = Path(project_path)
    if not raw.is_absolute() or ".." in raw.parts or not raw.is_relative_to(home):
        raise TrivyVulnInvalidInput("project_path hizmet kullanıcısının ev dizini içinde olmalı")
    relative = raw.relative_to(home)
    directory_fd = None
    file_fd = None
    try:
        directory_fd = os.open(home, _DIR_FLAGS)
        if not stat.S_ISDIR(os.fstat(directory_fd).st_mode):
            raise TrivyVulnInvalidInput("project_path bir dizin olmalı")
        for part in relative.parts:
            if part in ("", ".", ".."):
                raise TrivyVulnInvalidInput("project_path geçersiz bir bileşen içeriyor")
            next_fd = os.open(part, _DIR_FLAGS, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
            if not stat.S_ISDIR(os.fstat(directory_fd).st_mode):
                raise TrivyVulnInvalidInput("project_path bir dizin olmalı")
        file_fd = os.open("Cargo.lock", _FILE_FLAGS, dir_fd=directory_fd)
        before = os.fstat(file_fd)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= MAX_LOCK_BYTES:
            raise TrivyVulnInvalidInput("Kök Cargo.lock en fazla 5 MB büyüklüğünde normal bir dosya olmalı")
        chunks = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(file_fd, min(65536, remaining))
            if not chunk:
                raise TrivyVulnInvalidInput("Cargo.lock okuma sırasında değişti")
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(file_fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise TrivyVulnInvalidInput("Cargo.lock okuma sırasında değişti")
        return b"".join(chunks)
    except OSError as exc:
        raise TrivyVulnInvalidInput("Kök Cargo.lock kullanılamıyor veya güvensiz") from exc
    finally:
        if file_fd is not None:
            os.close(file_fd)
        if directory_fd is not None:
            os.close(directory_fd)


def _validate_cargo_lock(raw: bytes) -> None:
    try:
        lock = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise TrivyVulnInvalidInput("Cargo.lock geçerli UTF-8 TOML olmalı") from exc
    if type(lock.get("version")) is not int or lock["version"] not in (3, 4):
        raise TrivyVulnInvalidInput("Cargo.lock biçim sürümü 3 veya 4 olmalı")
    packages = lock.get("package")
    if not isinstance(packages, list) or not packages:
        raise TrivyVulnInvalidInput("Cargo.lock paket içermeli")
    for package in packages:
        if not isinstance(package, dict) or not isinstance(package.get("name"), str) or not package["name"] or not isinstance(package.get("version"), str) or not package["version"]:
            raise TrivyVulnInvalidInput("Cargo.lock geçersiz bir paket girdisi içeriyor")


def _checked_cache() -> Path:
    configured = os.environ.get("SNIPER_TRIVY_VULN_CACHE_DIR")
    expected = os.environ.get("SNIPER_TRIVY_VULN_DB_SHA256")
    if not configured or not expected or len(expected) != 64 or any(c not in "0123456789abcdef" for c in expected):
        raise TrivyVulnUnavailable("Sabitlenmiş Trivy zafiyet veritabanı kullanılamıyor")
    cache = Path(configured)
    if not cache.is_absolute() or cache.is_symlink() or not cache.is_dir() or (cache / "db").is_symlink():
        raise TrivyVulnUnavailable("Trivy önbellek dizini kullanılamıyor")
    for name in ("metadata.json", "trivy.db"):
        item = cache / "db" / name
        if item.is_symlink() or not item.is_file():
            raise TrivyVulnUnavailable("Trivy zafiyet veritabanı kullanılamıyor")
    db = cache / "db" / "trivy.db"
    digest = hashlib.sha256()
    try:
        with db.open("rb") as stream:
            for chunk in iter(lambda: stream.read(65536), b""):
                digest.update(chunk)
    except OSError as exc:
        raise TrivyVulnUnavailable("Trivy zafiyet veritabanı kullanılamıyor") from exc
    if digest.hexdigest() != expected:
        raise TrivyVulnUnavailable("Sabitlenmiş Trivy zafiyet veritabanı eşleşmiyor")
    return cache.resolve(strict=True)


def _open_trivy_binary() -> int:
    configured = os.environ.get("SNIPER_TRIVY_BINARY")
    if not configured or not Path(configured).is_absolute():
        raise TrivyVulnUnavailable("Trivy çalıştırılabiliri kullanılamıyor")
    try:
        fd = os.open(configured, _FILE_FLAGS)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or not info.st_mode & 0o111:
            os.close(fd)
            raise TrivyVulnUnavailable("Trivy çalıştırılabiliri güvensiz")
        expected = os.environ.get("SNIPER_TRIVY_BINARY_SHA256")
        if expected:
            if len(expected) != 64 or any(c not in "0123456789abcdef" for c in expected):
                os.close(fd)
                raise TrivyVulnUnavailable("Trivy çalıştırılabilir özeti geçersiz")
            digest = hashlib.sha256()
            while True:
                data = os.read(fd, 65536)
                if not data:
                    break
                digest.update(data)
            if digest.hexdigest() != expected:
                os.close(fd)
                raise TrivyVulnUnavailable("Trivy çalıştırılabilir özeti eşleşmiyor")
            os.lseek(fd, 0, os.SEEK_SET)
        return fd
    except OSError as exc:
        raise TrivyVulnUnavailable("Trivy çalıştırılabiliri kullanılamıyor") from exc


def _open_scan_lock() -> int:
    configured = os.environ.get("SNIPER_DATA_DIR")
    if not configured:
        raise TrivyVulnUnavailable("Trivy tarama kilidi kullanılamıyor")
    lock = Path(configured).resolve() / "trivy.lock"
    lock.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            os.close(fd)
            raise TrivyVulnUnavailable("Trivy tarama kilidi güvensiz")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            os.close(fd)
            raise TrivyVulnBusy("Başka bir Trivy taraması sürüyor") from exc
        return fd
    except OSError as exc:
        raise TrivyVulnUnavailable("Trivy tarama kilidi kullanılamıyor") from exc


def _read_cargo_report(report_file: Path) -> dict[str, Any]:
    fd = None
    try:
        fd = os.open(report_file, _FILE_FLAGS)
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= MAX_REPORT_BYTES:
            raise TrivyVulnExecutionError("Trivy raporu eksik veya çok büyük")
        chunks = []
        remaining = before.st_size
        while remaining:
            data = os.read(fd, min(65536, remaining))
            if not data:
                raise TrivyVulnExecutionError("Trivy raporu okuma sırasında değişti")
            chunks.append(data)
            remaining -= len(data)
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise TrivyVulnExecutionError("Trivy raporu okuma sırasında değişti")
        report = json.loads(b"".join(chunks).decode("utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise TrivyVulnExecutionError("Trivy raporu kullanılamıyor veya geçersiz") from exc
    finally:
        if fd is not None:
            os.close(fd)
    if not isinstance(report, dict) or report.get("SchemaVersion") != 2 or not isinstance(report.get("Results"), list) or len(report["Results"]) != 1:
        raise TrivyVulnExecutionError("Trivy Cargo sonucu eksik veya belirsiz")
    result = report["Results"][0]
    if not isinstance(result, dict) or result.get("Target") != "Cargo.lock" or result.get("Type") != "cargo" or result.get("Class") != "lang-pkgs":
        raise TrivyVulnExecutionError("Trivy Cargo sonucu güvenilmez")
    try:
        summary = parse_trivy_native_json_summary(report)
    except ValueError as exc:
        raise TrivyVulnExecutionError("Trivy Cargo sonucu geçersiz") from exc
    summary["profile"] = PROFILE
    return summary


def run_local_trivy_cargo_lock_vulnerability(project_path: str) -> dict[str, Any]:
    data = _read_root_lockfile(project_path)
    _validate_cargo_lock(data)
    lock_fd = _open_scan_lock()
    binary_fd = None
    try:
        binary_fd = _open_trivy_binary()
        cache = _checked_cache()
        with tempfile.TemporaryDirectory(prefix="sniper_trivy_cargo_") as tmp:
            scratch = Path(tmp)
            input_dir = scratch / "input"
            input_dir.mkdir()
            (input_dir / "Cargo.lock").write_bytes(data)
            report_file = scratch / "report.json"
            cmd = [
                f"/proc/self/fd/{binary_fd}", "fs", "--scanners", "vuln",
                "--offline-scan", "--skip-db-update", "--skip-java-db-update",
                "--skip-check-update", "--skip-version-check", "--config=",
                "--ignorefile=", "--format", "json", "--output", str(report_file),
                "--cache-dir", str(cache), "--timeout", "60s", str(input_dir),
            ]
            env = os.environ.copy()
            env["HOME"] = str(scratch)
            env["XDG_CACHE_HOME"] = str(scratch / "cache")
            try:
                process = subprocess.run(cmd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=90, check=False, pass_fds=(binary_fd,))
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise TrivyVulnExecutionError("Trivy çalıştırılamadı") from exc
            if process.returncode != 0:
                raise TrivyVulnExecutionError("Trivy çalıştırılamadı")
            return _read_cargo_report(report_file)
    finally:
        if binary_fd is not None:
            os.close(binary_fd)
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)
