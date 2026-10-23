from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import signal
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
)

_MAX_LOCK_BYTES = 5_000_000
_MAX_REPORT_BYTES = 2_000_000
_MAX_BINARY_BYTES = 256_000_000
_SELECTOR = re.compile(r"(?:@[A-Za-z0-9_.-]+/)?[A-Za-z0-9_.-]+@[~^]?[0-9][A-Za-z0-9.+*-]*\Z")
_VERSION = re.compile(r"[0-9][A-Za-z0-9.+-]*\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_REGISTRY_URL = re.compile(r'https://(?:registry\.yarnpkg\.com|registry\.npmjs\.org)/[^\s"]+\Z')
_DEPENDENCY = re.compile(r'    (?:@[A-Za-z0-9_.-]+/)?[A-Za-z0-9_.-]+ "[~^]?[0-9][A-Za-z0-9.+*-]*"\Z')


@contextmanager
def _scan_lock():
    data_dir = os.environ.get("SNIPER_DATA_DIR")
    if not data_dir:
        raise TrivyVulnUnavailable("Trivy zafiyet tarayıcısı kullanılamıyor.")
    path = Path(data_dir).resolve() / "trivy.lock"
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    except OSError as exc:
        raise TrivyVulnUnavailable("Trivy tarama kilidi kullanılamıyor.") from exc
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise TrivyVulnUnavailable("Trivy tarama kilidi kullanılamıyor.")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise TrivyVulnBusy("Başka bir Trivy taraması sürüyor.") from exc
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def _runtime() -> tuple[Path, Path]:
    binary_value = os.environ.get("SNIPER_TRIVY_BINARY")
    if not binary_value:
        raise TrivyVulnUnavailable("Trivy ikilisi yapılandırılmamış.")
    binary = Path(binary_value)
    if (not binary.is_absolute() or binary.is_symlink() or not binary.is_file()
            or not os.access(binary, os.X_OK)):
        raise TrivyVulnUnavailable("Trivy ikilisi çalıştırılabilir normal bir dosya olmalı.")
    cache_value = os.environ.get("SNIPER_TRIVY_VULN_CACHE_DIR")
    if not cache_value:
        raise TrivyVulnUnavailable("Trivy zafiyet veritabanı yapılandırılmamış.")
    cache = Path(cache_value)
    if not cache.is_absolute() or cache.is_symlink() or not cache.is_dir():
        raise TrivyVulnUnavailable("Trivy zafiyet veritabanı kullanılamıyor.")
    db_dir = cache / "db"
    if db_dir.is_symlink() or not db_dir.is_dir():
        raise TrivyVulnUnavailable("Trivy zafiyet veritabanı kullanılamıyor.")
    db = db_dir / "trivy.db"
    metadata = db_dir / "metadata.json"
    for path in (db, metadata):
        if path.is_symlink() or not path.is_file():
            raise TrivyVulnUnavailable("Trivy zafiyet veritabanı kullanılamıyor.")
    expected = os.environ.get("SNIPER_TRIVY_VULN_DB_SHA256", "")
    if _SHA.fullmatch(expected) is None:
        raise TrivyVulnUnavailable("Trivy veritabanı SHA256 değeri yapılandırılmamış.")
    digest = hashlib.sha256()
    try:
        with db.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1_048_576), b""):
                digest.update(chunk)
    except OSError as exc:
        raise TrivyVulnUnavailable("Trivy zafiyet veritabanı kullanılamıyor.") from exc
    if digest.hexdigest() != expected:
        raise TrivyVulnUnavailable("Trivy veritabanı SHA256 değeri uyuşmuyor.")
    return binary, cache.resolve()


@contextmanager
def _verified_binary(path: Path):
    """Run a sealed SHA-pinned executable snapshot, independent of source path swaps."""
    expected = os.environ.get("SNIPER_TRIVY_BINARY_SHA256", "")
    if _SHA.fullmatch(expected) is None:
        raise TrivyVulnUnavailable("Trivy ikilisi SHA256 değeri yapılandırılmamış.")
    source_fd = None
    snapshot_fd = None
    try:
        if not hasattr(os, "memfd_create") or not hasattr(os, "MFD_ALLOW_SEALING"):
            raise TrivyVulnUnavailable("Doğrulanmış Trivy çalıştırması kullanılamıyor.")
        source_fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        before = os.fstat(source_fd)
        if (not stat.S_ISREG(before.st_mode) or not (before.st_mode & 0o111)
                or not 0 < before.st_size <= _MAX_BINARY_BYTES):
            raise TrivyVulnUnavailable("Trivy ikilisi kullanılamıyor.")
        snapshot_fd = os.memfd_create("sniper-trivy-yarn", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        os.fchmod(snapshot_fd, 0o500)
        copied = 0
        digest = hashlib.sha256()
        while copied < before.st_size:
            chunk = os.read(source_fd, min(1_048_576, before.st_size - copied))
            if not chunk:
                break
            view = memoryview(chunk)
            while view:
                written = os.write(snapshot_fd, view)
                view = view[written:]
            digest.update(chunk)
            copied += len(chunk)
        after = os.fstat(source_fd)
        identity = lambda st: (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
        if copied != before.st_size or identity(before) != identity(after):
            raise TrivyVulnUnavailable("Trivy ikilisi doğrulama sırasında değişti.")
        if digest.hexdigest() != expected:
            raise TrivyVulnUnavailable("Trivy ikilisi SHA256 değeri uyuşmuyor.")
        seals = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
        fcntl.fcntl(snapshot_fd, fcntl.F_ADD_SEALS, seals)
        if fcntl.fcntl(snapshot_fd, fcntl.F_GET_SEALS) & seals != seals:
            raise TrivyVulnUnavailable("Doğrulanmış Trivy çalıştırması kullanılamıyor.")
        yield f"/proc/self/fd/{snapshot_fd}", snapshot_fd
    except OSError as exc:
        raise TrivyVulnUnavailable("Doğrulanmış Trivy çalıştırması kullanılamıyor.") from exc
    finally:
        if source_fd is not None:
            os.close(source_fd)
        if snapshot_fd is not None:
            os.close(snapshot_fd)


def _read_root_lock(root: Path) -> bytes:
    """Traverse every directory by descriptor; never follow parent or leaf symlinks."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    directory_fd = None
    file_fd = None
    try:
        directory_fd = os.open("/", flags)
        for component in root.parts[1:]:
            next_fd = os.open(component, flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        file_fd = os.open("yarn.lock", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory_fd)
        initial = os.fstat(file_fd)
        if not stat.S_ISREG(initial.st_mode) or not 0 < initial.st_size <= _MAX_LOCK_BYTES:
            raise TrivyVulnInvalidInput("Kök yarn.lock en fazla 5.000.000 bayt büyüklüğünde, boş olmayan normal bir dosya olmalı.")
        data = bytearray()
        while len(data) <= _MAX_LOCK_BYTES:
            chunk = os.read(file_fd, min(65_536, _MAX_LOCK_BYTES + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        final = os.fstat(file_fd)
        identity = lambda st: (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
        if len(data) != initial.st_size or len(data) > _MAX_LOCK_BYTES or identity(initial) != identity(final):
            raise TrivyVulnInvalidInput("Kök yarn.lock okuma sırasında değişti veya boyut sınırını aştı.")
        return bytes(data)
    except OSError as exc:
        raise TrivyVulnInvalidInput("Kök yarn.lock eksik, bağlantılı veya okunamıyor.") from exc
    finally:
        if file_fd is not None:
            os.close(file_fd)
        if directory_fd is not None:
            os.close(directory_fd)


def _validate_yarn_classic_lock(data: bytes) -> None:
    """Conservative Yarn classic v1 registry-package subset; engine recognition is mandatory."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise TrivyVulnInvalidInput("Kök yarn.lock UTF-8 olmalı.") from exc
    if "\x00" in text or "\r" in text.replace("\r\n", ""):
        raise TrivyVulnInvalidInput("Kök yarn.lock geçersiz metin içeriyor.")
    lines = text.splitlines()
    banner = "# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY."
    if lines and lines[0] == banner:
        lines = lines[1:]
    if not lines or lines[0] != "# yarn lockfile v1":
        raise TrivyVulnInvalidInput("Yalnız Yarn classic v1 kilit dosyaları desteklenir.")
    current = None
    have_version = False
    package_count = 0
    nested = False
    for line in lines[1:]:
        if not line or line.startswith("#"):
            if current is not None and not have_version:
                raise TrivyVulnInvalidInput("Kök yarn.lock dosyasında sürümsüz bir paket var.")
            current = None
            nested = False
            continue
        if not line.startswith(" "):
            if current is not None and not have_version:
                raise TrivyVulnInvalidInput("Kök yarn.lock dosyasında sürümsüz bir paket var.")
            if not line.endswith(":"):
                raise TrivyVulnInvalidInput("Kök yarn.lock geçersiz bir paket anahtarı içeriyor.")
            selectors = [piece.strip().strip('"') for piece in line[:-1].split(",")]
            if not selectors or any(_SELECTOR.fullmatch(piece) is None for piece in selectors):
                raise TrivyVulnInvalidInput("Kök yarn.lock desteklenmeyen bir paket seçicisi içeriyor.")
            package_count += 1
            current = line
            have_version = False
            nested = False
            continue
        if current is None:
            raise TrivyVulnInvalidInput("Kök yarn.lock girdi yapısı geçersiz.")
        if line.startswith("    "):
            if not nested or _DEPENDENCY.fullmatch(line) is None:
                raise TrivyVulnInvalidInput("Kök yarn.lock desteklenmeyen bir bağımlılık içeriyor.")
            continue
        if not line.startswith("  ") or line.startswith("   "):
            raise TrivyVulnInvalidInput("Kök yarn.lock girintisi geçersiz.")
        nested = False
        if line.startswith('  version "'):
            if have_version or not line.endswith('"') or _VERSION.fullmatch(line[len('  version "'): -1]) is None:
                raise TrivyVulnInvalidInput("Kök yarn.lock geçersiz bir paket sürümü içeriyor.")
            have_version = True
        elif line.startswith('  resolved "'):
            if not line.endswith('"') or _REGISTRY_URL.fullmatch(line[len('  resolved "'): -1]) is None:
                raise TrivyVulnInvalidInput("Kök yarn.lock desteklenmeyen bir paket kaynağı içeriyor.")
        elif line.startswith("  integrity "):
            if len(line) > 1024 or not re.fullmatch(r"  integrity (?:sha512|sha1)-[A-Za-z0-9+/=]+", line):
                raise TrivyVulnInvalidInput("Kök yarn.lock geçersiz bir bütünlük değeri içeriyor.")
        elif line in ("  dependencies:", "  optionalDependencies:"):
            nested = True
        else:
            raise TrivyVulnInvalidInput("Kök yarn.lock desteklenmeyen alanlar içeriyor.")
    if current is not None and not have_version:
        raise TrivyVulnInvalidInput("Kök yarn.lock dosyasında sürümsüz bir paket var.")
    if package_count == 0:
        raise TrivyVulnInvalidInput("Kök yarn.lock desteklenen bir paket içermiyor.")


def _read_report(path: Path) -> dict[str, Any]:
    fd = None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= _MAX_REPORT_BYTES:
            raise TrivyVulnExecutionError("Trivy raporu kullanılamıyor veya çok büyük.")
        data = bytearray()
        while len(data) <= _MAX_REPORT_BYTES:
            chunk = os.read(fd, min(65_536, _MAX_REPORT_BYTES + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(fd)
        identity = lambda st: (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
        if len(data) != before.st_size or len(data) > _MAX_REPORT_BYTES or identity(before) != identity(after):
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
            or results[0].get("Target") != "yarn.lock" or results[0].get("Type") != "yarn"
            or results[0].get("Class") != "lang-pkgs"
            or any(key in results[0] for key in ("Misconfigurations", "Secrets", "Licenses"))):
        raise TrivyVulnExecutionError("Trivy raporu yalnız kök Yarn kilit dosyasını tanımadı.")
    return report


def _run_engine(argv: list[str], env: dict[str, str], binary_fd: int) -> None:
    try:
        with subprocess.Popen(
            argv, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            pass_fds=(binary_fd,), start_new_session=True,
        ) as process:
            try:
                process.communicate(timeout=90)
            except subprocess.TimeoutExpired as exc:
                os.killpg(process.pid, signal.SIGKILL)
                process.communicate()
                raise TrivyVulnExecutionError("Trivy çalıştırması zaman aşımına uğradı.") from exc
            if process.returncode != 0:
                raise TrivyVulnExecutionError("Trivy çalıştırılamadı.")
    except OSError as exc:
        raise TrivyVulnExecutionError("Trivy çalıştırılamadı.") from exc


def run_local_trivy_yarn_vulnerability(project_path: str) -> dict[str, Any]:
    """Explicitly consented local Yarn classic v1 lockfile vulnerability scan."""
    root = validate_project_path(project_path, allowed_roots=(Path.home().resolve(),))
    with _scan_lock():
        binary_path, cache_path = _runtime()
        content = _read_root_lock(root)
        _validate_yarn_classic_lock(content)
        with _verified_binary(binary_path) as (binary, binary_fd):
            with tempfile.TemporaryDirectory(prefix="sniper_trivy_yarn_") as temp:
                scratch = Path(temp)
                input_dir = scratch / "input"
                input_dir.mkdir()
                (input_dir / "yarn.lock").write_bytes(content)
                report_path = scratch / "report.json"
                argv = [
                    binary, "fs", "--scanners", "vuln", "--offline-scan",
                    "--skip-db-update", "--skip-java-db-update", "--skip-check-update",
                    "--skip-version-check", "--config=", "--ignorefile=", "--format", "json",
                    "--output", str(report_path), "--cache-dir", str(cache_path), "--timeout", "60s",
                    str(input_dir),
                ]
                env = {
                    "PATH": "/usr/local/bin:/usr/bin:/bin",
                    "LANG": "C.UTF-8",
                    "LC_ALL": "C.UTF-8",
                    "HOME": str(scratch),
                    "XDG_CACHE_HOME": str(scratch / "cache"),
                }
                _run_engine(argv, env, binary_fd)
                report = _read_report(report_path)
                try:
                    summary = parse_trivy_native_json_summary(report)
                except ValueError as exc:
                    raise TrivyVulnExecutionError("Trivy raporu geçersiz.") from exc
                summary["profile"] = "local-yarn-lock-v1"
                return summary
