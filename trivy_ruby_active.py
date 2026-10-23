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

_MAX_LOCK_BYTES = 5 * 1024 * 1024
_MAX_REPORT_BYTES = 2_000_000
_PACKAGE_RE = re.compile(r"    [A-Za-z0-9][A-Za-z0-9_.-]* \([0-9][A-Za-z0-9_.+\-]*\)\Z")
_DEPENDENCY_RE = re.compile(r"  [A-Za-z0-9][A-Za-z0-9_.-]*(?:!?| \([^()\r\n]+\))\Z")
_ALLOWED_SECTIONS = frozenset({"GEM", "GIT", "PATH", "PLATFORMS", "DEPENDENCIES", "RUBY VERSION", "BUNDLED WITH", "CHECKSUMS"})


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
        snapshot_fd = os.memfd_create("sniper-trivy-ruby", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
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


def _read_root_lock(root: Path) -> bytes:
    """Open every directory component and the root Gemfile.lock by fd without following links."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    directory_fd = None
    file_fd = None
    try:
        directory_fd = os.open("/", flags)
        for component in root.parts[1:]:
            next_fd = os.open(component, flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        file_fd = os.open("Gemfile.lock", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory_fd)
        info = os.fstat(file_fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > _MAX_LOCK_BYTES:
            raise TrivyVulnInvalidInput("Kök Gemfile.lock en fazla 5 MiB (5.242.880 bayt) büyüklüğünde normal bir dosya olmalı.")
        chunks = bytearray()
        while len(chunks) <= _MAX_LOCK_BYTES:
            block = os.read(file_fd, min(65536, _MAX_LOCK_BYTES + 1 - len(chunks)))
            if not block:
                break
            chunks.extend(block)
        if len(chunks) != info.st_size or len(chunks) > _MAX_LOCK_BYTES:
            raise TrivyVulnInvalidInput("Kök Gemfile.lock okuma sırasında değişti veya boyut sınırını aştı.")
        final = os.fstat(file_fd)
        if (final.st_dev, final.st_ino, final.st_size, final.st_mtime_ns) != (
            info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns
        ):
            raise TrivyVulnInvalidInput("Kök Gemfile.lock okuma sırasında değişti.")
        return bytes(chunks)
    except OSError as exc:
        raise TrivyVulnInvalidInput("Kök Gemfile.lock eksik, bağlantılı veya okunamıyor.") from exc
    finally:
        if file_fd is not None:
            os.close(file_fd)
        if directory_fd is not None:
            os.close(directory_fd)


def _validate_lockfile(data: bytes) -> None:
    """Bounded, conservative Bundler lockfile preflight; Trivy must also recognize it."""
    if not data or len(data) > _MAX_LOCK_BYTES:
        raise TrivyVulnInvalidInput("Kök Gemfile.lock boş veya çok büyük.")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise TrivyVulnInvalidInput("Kök Gemfile.lock UTF-8 olmalı.") from exc
    if "\x00" in text or "\r" in text.replace("\r\n", ""):
        raise TrivyVulnInvalidInput("Kök Gemfile.lock geçersiz metin içeriyor.")
    lines = text.splitlines()
    sections: dict[str, list[str]] = {}
    current = None
    for line in lines:
        if line and not line.startswith((" ", "\t")):
            if not re.fullmatch(r"[A-Z][A-Z ]*", line) or line in sections or line not in _ALLOWED_SECTIONS:
                raise TrivyVulnInvalidInput("Kök Gemfile.lock bölüm yapısı geçersiz.")
            sections[line] = []
            current = line
        elif current is None:
            if line.strip():
                raise TrivyVulnInvalidInput("Kök Gemfile.lock bölüm yapısı geçersiz.")
        elif line.strip():
            if "\t" in line:
                raise TrivyVulnInvalidInput("Kök Gemfile.lock Bundler girintisini kullanmalı.")
            sections[current].append(line)
    gem = sections.get("GEM")
    platforms = sections.get("PLATFORMS")
    dependencies = sections.get("DEPENDENCIES")
    if gem is None or platforms is None or dependencies is None:
        raise TrivyVulnInvalidInput("Kök Gemfile.lock GEM, PLATFORMS ve DEPENDENCIES bölümlerini gerektirir.")
    if "  specs:" not in gem or gem.count("  specs:") != 1:
        raise TrivyVulnInvalidInput("Kök Gemfile.lock tek bir GEM specs listesi gerektirir.")
    before_specs, after_specs = gem[:gem.index("  specs:")], gem[gem.index("  specs:") + 1:]
    if any(not line.startswith("  remote: ") for line in before_specs):
        raise TrivyVulnInvalidInput("Kök Gemfile.lock desteklenmeyen GEM meta verisi içeriyor.")
    packages = [line for line in after_specs if line.startswith("    ") and not line.startswith("      ")]
    if not packages or any(_PACKAGE_RE.fullmatch(line) is None for line in packages):
        raise TrivyVulnInvalidInput("Kök Gemfile.lock geçerli bir GEM paket listesi içermiyor.")
    if any(not (line.startswith("      ") or line in packages) for line in after_specs):
        raise TrivyVulnInvalidInput("Kök Gemfile.lock GEM spec girintisi geçersiz.")
    if not platforms or any(re.fullmatch(r"  [A-Za-z0-9_.+\-]+", line) is None for line in platforms):
        raise TrivyVulnInvalidInput("Kök Gemfile.lock geçerli bir PLATFORMS listesi içermiyor.")
    if not dependencies or any(_DEPENDENCY_RE.fullmatch(line) is None for line in dependencies):
        raise TrivyVulnInvalidInput("Kök Gemfile.lock geçerli bir DEPENDENCIES listesi içermiyor.")


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
            or results[0].get("Target") != "Gemfile.lock" or results[0].get("Type") != "bundler"
            or results[0].get("Class") != "lang-pkgs"
            or any(key in results[0] for key in ("Misconfigurations", "Secrets", "Licenses"))):
        raise TrivyVulnExecutionError("Trivy raporu yalnız kök Bundler kilit dosyası sonucunu içermiyordu.")
    return report


def run_local_trivy_ruby_vulnerability(project_path: str) -> dict[str, Any]:
    """Scan only a home-contained root Gemfile.lock with pinned offline Trivy DB."""
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
        content = _read_root_lock(src_root)
        _validate_lockfile(content)
        with _verified_binary(binary_path) as binary, tempfile.TemporaryDirectory(prefix="sniper_trivy_ruby_") as temp:
            scratch = Path(temp)
            staged = scratch / "input"
            staged.mkdir()
            (staged / "Gemfile.lock").write_bytes(content)
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
            summary["profile"] = "local-ruby-gemfile-lock-v1"
            return summary
    finally:
        if lock_fd is not None:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)
