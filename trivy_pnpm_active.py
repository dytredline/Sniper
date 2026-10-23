"""Bounded, explicit-consent pnpm v9 lockfile vulnerability profile.

The supported subset is a single importer with registry-resolved packages.  A
missing pnpm result is an execution failure, never an all-clear result.
"""
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

from trivy_vuln_active import (
    TrivyVulnBusy, TrivyVulnExecutionError, TrivyVulnInvalidInput,
    TrivyVulnUnavailable,
)
from tool_report_trivy import parse_trivy_native_json_summary

_LOCKFILE = "pnpm-lock.yaml"
_MAX_LOCK_BYTES = 5_000_000
_MAX_REPORT_BYTES = 2_000_000
_MAX_BINARY_BYTES = 256_000_000
_ALLOWED_TOP = {"lockfileVersion", "settings", "importers", "packages", "snapshots"}
_MAPPING = re.compile(r"^( *)([^:\s][^:]*?):(?: +(.+))?$", re.ASCII)
_KEY = re.compile(r"^[A-Za-z0-9@./_+()^~-]+$")
_SCALAR = re.compile(r"^[A-Za-z0-9@./_+()^~=+-]+$")
_VERSION = re.compile(r"^(?:@[^/]+/)?[^/@\s]+@[0-9][A-Za-z0-9.+_-]*(?:\([^)]*\))?$")
_FORBIDDEN_VALUE = re.compile(r"(?:workspace:|file:|link:|git\+|git:|https?://|npm:|patch:)", re.I)


def _validate_v9_lockfile(raw: bytes) -> None:
    try:
        source = raw.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise TrivyVulnInvalidInput("pnpm kilit dosyası UTF-8 olmalı") from exc
    if not source or "\r" in source or "\t" in source or "\x00" in source:
        raise TrivyVulnInvalidInput("pnpm kilit dosyası desteklenmeyen sözdizimi içeriyor")
    root_keys: set[str] = set()
    sections: dict[str, set[str]] = {"importers": set(), "packages": set(), "snapshots": set()}
    seen: dict[tuple[str, ...], set[str]] = {}
    parents: list[tuple[int, tuple[str, ...], bool]] = []
    current_top = ""
    for line in source.splitlines():
        if not line.strip():
            continue
        if any(token in line for token in ("&", "*", "!", "|", ">", "[", "]", "{", "}")) and not line.rstrip().endswith(": {}"):
            raise TrivyVulnInvalidInput("pnpm kilit dosyası desteklenmeyen YAML özellikleri içeriyor")
        match = _MAPPING.fullmatch(line)
        if not match:
            raise TrivyVulnInvalidInput("pnpm kilit dosyası desteklenmeyen sözdizimi içeriyor")
        indent = len(match.group(1))
        key, value = match.group(2), match.group(3)
        if indent % 2 or indent > 12 or not _KEY.fullmatch(key):
            raise TrivyVulnInvalidInput("pnpm kilit dosyası desteklenmeyen sözdizimi içeriyor")
        if value is not None and value != "{}" and not _SCALAR.fullmatch(value):
            raise TrivyVulnInvalidInput("pnpm kilit dosyası desteklenmeyen bir skaler içeriyor")
        if _FORBIDDEN_VALUE.search(key) or (value and _FORBIDDEN_VALUE.search(value)):
            raise TrivyVulnInvalidInput("pnpm kilit dosyası desteklenmeyen bir bağımlılık kaynağı kullanıyor")
        while parents and parents[-1][0] >= indent:
            parents.pop()
        if indent and (not parents or parents[-1][0] != indent - 2 or not parents[-1][2]):
            raise TrivyVulnInvalidInput("pnpm kilit dosyasının iç içe yapısı geçersiz")
        context = parents[-1][1] if parents else ()
        if key in seen.setdefault(context, set()):
            raise TrivyVulnInvalidInput("pnpm kilit dosyası yinelenen anahtarlar içeriyor")
        seen[context].add(key)
        path = context + (key,)
        if indent == 0:
            if key not in _ALLOWED_TOP:
                raise TrivyVulnInvalidInput("pnpm kilit dosyası desteklenmeyen bir üst düzey bölüm içeriyor")
            root_keys.add(key)
            current_top = key
            if key == "lockfileVersion":
                if value != "9.0":
                    raise TrivyVulnInvalidInput("pnpm kilit dosyası sürüm 9.0 olmalı")
            elif value is not None:
                raise TrivyVulnInvalidInput("pnpm bölümü bir eşleme olmalı")
        elif indent == 2 and current_top in sections:
            sections[current_top].add(key)
            if current_top == "importers" and key != ".":
                raise TrivyVulnInvalidInput("pnpm çalışma alanları desteklenmiyor")
            if current_top in ("packages", "snapshots") and not _VERSION.fullmatch(key):
                raise TrivyVulnInvalidInput("pnpm paket tanımlayıcısı desteklenmiyor")
            if value is not None and value != "{}":
                raise TrivyVulnInvalidInput("pnpm paket girdisi bir eşleme olmalı")
        if value is None:
            parents.append((indent, path, True))
        else:
            parents.append((indent, path, False))
    if root_keys != _ALLOWED_TOP or sections["importers"] != {"."} or not sections["packages"] or not sections["snapshots"]:
        raise TrivyVulnInvalidInput("pnpm kilit dosyası eksik")
    if sections["packages"] != sections["snapshots"]:
        raise TrivyVulnInvalidInput("pnpm paket ve anlık görüntü kapsamı farklı")


def _open_lockfile_beneath_home(project_path: str) -> bytes:
    if not isinstance(project_path, str) or not project_path.strip() or len(project_path) > 1024:
        raise TrivyVulnInvalidInput("Yerel bir proje yolu gerekli")
    raw_path = Path(os.path.abspath(os.path.expanduser(project_path.strip())))
    home = Path.home().absolute()
    try:
        components = raw_path.relative_to(home).parts
    except ValueError as exc:
        raise TrivyVulnInvalidInput("Proje, hizmet kullanıcısının ev dizini altında olmalı") from exc
    if not components or any(component in ("", ".", "..") for component in components):
        raise TrivyVulnInvalidInput("Ev dizini altında bir proje dizini gerekli")
    fds: list[int] = []
    try:
        base_fd = os.open(home, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        fds.append(base_fd)
        for component in components:
            fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fds[-1])
            fds.append(fd)
        lock_fd = os.open(_LOCKFILE, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fds[-1])
        fds.append(lock_fd)
        st_before = os.fstat(lock_fd)
        if not stat.S_ISREG(st_before.st_mode) or st_before.st_size > _MAX_LOCK_BYTES:
            raise TrivyVulnInvalidInput("pnpm kilit dosyası en fazla 5.000.000 bayt büyüklüğünde normal bir dosya olmalı")
        chunks: list[bytes] = []
        remaining = st_before.st_size
        while remaining:
            chunk = os.read(lock_fd, min(65536, remaining))
            if not chunk:
                raise TrivyVulnInvalidInput("pnpm kilit dosyası okuma sırasında değişti")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(lock_fd, 1):
            raise TrivyVulnInvalidInput("pnpm kilit dosyası okuma sırasında büyüdü")
        st_after = os.fstat(lock_fd)
        if (st_before.st_dev, st_before.st_ino, st_before.st_size, st_before.st_mtime_ns) != (st_after.st_dev, st_after.st_ino, st_after.st_size, st_after.st_mtime_ns):
            raise TrivyVulnInvalidInput("pnpm kilit dosyası okuma sırasında değişti")
        raw = b"".join(chunks)
        _validate_v9_lockfile(raw)
        return raw
    except OSError as exc:
        raise TrivyVulnInvalidInput("pnpm projesi veya kök kilit dosyası kullanılamıyor") from exc
    finally:
        for fd in reversed(fds):
            os.close(fd)


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


@contextmanager
def _verified_binary(path: Path):
    """Run a sealed SHA-pinned executable snapshot, independent of source path swaps."""
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
                or not 0 < before.st_size <= _MAX_BINARY_BYTES):
            raise TrivyVulnUnavailable("Trivy ikilisi kullanılamıyor.")
        snapshot_fd = os.memfd_create("sniper-trivy-pnpm", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
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


def _runtime() -> tuple[Path, Path]:
    configured_binary = os.environ.get("SNIPER_TRIVY_BINARY", "")
    expected_binary_hash = os.environ.get("SNIPER_TRIVY_BINARY_SHA256", "")
    configured_cache = os.environ.get("SNIPER_TRIVY_VULN_CACHE_DIR", "")
    expected_hash = os.environ.get("SNIPER_TRIVY_VULN_DB_SHA256", "")
    if (not configured_binary or not configured_cache
            or not re.fullmatch(r"[0-9a-f]{64}", expected_binary_hash)
            or not re.fullmatch(r"[0-9a-f]{64}", expected_hash)):
        raise TrivyVulnUnavailable("Sabitlenmiş Trivy çalışma zamanı kullanılamıyor")
    binary = Path(configured_binary)
    cache = Path(configured_cache)
    if not binary.is_absolute() or binary.is_symlink() or not binary.is_file() or not os.access(binary, os.X_OK):
        raise TrivyVulnUnavailable("Sabitlenmiş Trivy ikilisi kullanılamıyor")
    if not cache.is_absolute() or cache.is_symlink() or not cache.is_dir() or (cache / "db").is_symlink():
        raise TrivyVulnUnavailable("Sabitlenmiş Trivy önbelleği kullanılamıyor")
    for path in (cache / "db" / "metadata.json", cache / "db" / "trivy.db"):
        if path.is_symlink() or not path.is_file():
            raise TrivyVulnUnavailable("Sabitlenmiş Trivy veritabanı kullanılamıyor")
    try:
        actual_hash = _file_sha256(cache / "db" / "trivy.db")
    except OSError as exc:
        raise TrivyVulnUnavailable("Sabitlenmiş Trivy veritabanı kullanılamıyor") from exc
    if actual_hash != expected_hash:
        raise TrivyVulnUnavailable("Sabitlenmiş Trivy veritabanı özeti uyuşmuyor")
    return binary, cache


def run_local_trivy_pnpm_vulnerability(project_path: str) -> dict[str, Any]:
    data_dir = os.environ.get("SNIPER_DATA_DIR", "")
    if not data_dir:
        raise TrivyVulnUnavailable("Trivy tarama kilidi kullanılamıyor")
    lock_path = Path(data_dir).resolve() / "trivy.lock"
    if not lock_path.parent.is_dir():
        raise TrivyVulnUnavailable("Trivy tarama kilidi dizini kullanılamıyor")
    try:
        lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    except OSError as exc:
        raise TrivyVulnUnavailable("Trivy tarama kilidi kullanılamıyor") from exc
    try:
        if not stat.S_ISREG(os.fstat(lock_fd).st_mode):
            raise TrivyVulnUnavailable("Trivy tarama kilidi geçersiz")
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise TrivyVulnBusy("Başka bir Trivy taraması sürüyor") from exc
        raw = _open_lockfile_beneath_home(project_path)
        binary, cache = _runtime()
        with _verified_binary(binary) as (sealed_binary, binary_fd):
            with tempfile.TemporaryDirectory(prefix="sniper_trivy_pnpm_") as temporary:
                scratch = Path(temporary)
                input_dir = scratch / "input"
                input_dir.mkdir()
                (input_dir / _LOCKFILE).write_bytes(raw)
                report_path = scratch / "report.json"
                command = [sealed_binary, "fs", "--scanners", "vuln", "--offline-scan", "--skip-db-update", "--skip-java-db-update", "--skip-check-update", "--skip-version-check", "--config=", "--ignorefile=", "--format", "json", "--output", str(report_path), "--cache-dir", str(cache), "--timeout", "60s", str(input_dir)]
                environment = {"HOME": str(scratch), "XDG_CACHE_HOME": str(scratch / "cache"), "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
                try:
                    process = subprocess.Popen(command, env=environment, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, pass_fds=(binary_fd,), start_new_session=True)
                    try:
                        result = process.wait(timeout=90)
                    except subprocess.TimeoutExpired as exc:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait(timeout=5)
                        raise TrivyVulnExecutionError("Trivy çalıştırması zaman aşımına uğradı") from exc
                except OSError as exc:
                    raise TrivyVulnExecutionError("Trivy çalıştırılamadı") from exc
                if result != 0 or report_path.is_symlink() or not report_path.is_file() or report_path.stat().st_size > _MAX_REPORT_BYTES:
                    raise TrivyVulnExecutionError("Trivy raporu kullanılamıyor")
                try:
                    report = json.loads(report_path.read_text(encoding="utf-8"))
                except (ValueError, UnicodeError) as exc:
                    raise TrivyVulnExecutionError("Trivy raporu geçersiz") from exc
                if not isinstance(report, dict) or type(report.get("SchemaVersion")) is not int or report["SchemaVersion"] != 2:
                    raise TrivyVulnExecutionError("Trivy rapor şeması geçersiz")
                results = report.get("Results")
                if not isinstance(results, list) or len(results) != 1 or not isinstance(results[0], dict) or results[0].get("Type") != "pnpm" or results[0].get("Target") != _LOCKFILE or results[0].get("Class") != "lang-pkgs":
                    raise TrivyVulnExecutionError("Trivy pnpm kilit dosyasını tanımadı")
                if not isinstance(results[0].get("Packages"), list) or not results[0]["Packages"]:
                    raise TrivyVulnExecutionError("Trivy pnpm paketlerini belirlemedi")
                try:
                    summary = parse_trivy_native_json_summary(report)
                except ValueError as exc:
                    raise TrivyVulnExecutionError("Trivy raporu geçersiz") from exc
                summary["profile"] = "local-pnpm-lock-v9-v1"
                return summary
    finally:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(lock_fd)
