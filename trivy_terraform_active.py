"""Run bounded, offline Trivy Dockerfile and Terraform config checks."""

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

from project_analyzer import validate_project_path
from tool_report_trivy import parse_trivy_native_json_summary


EXPECTED_TRIVY_SHA256 = "869e310e208f0f2e3e90e4f842cc6adaa2b2c046fecbaade481e6b23fcc8f2a9"
MAX_DOCKERFILE_BYTES = 1_000_000
MAX_TERRAFORM_FILE_BYTES = 1_000_000
MAX_TERRAFORM_BATCH_FILES = 8
MAX_TERRAFORM_BATCH_BYTES = 8_000_000
MAX_REPORT_BYTES = 2_000_000
MAX_TRIVY_BINARY_BYTES = 256_000_000
_TERRAFORM_BATCH_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,123}\.tf\Z")


class TrivyConfigUnavailable(RuntimeError):
    pass


class TrivyConfigBusy(RuntimeError):
    pass


class TrivyConfigExecutionError(RuntimeError):
    pass


class _VerifiedBinary:
    """Own a sealed, digest-verified executable snapshot until the child exits."""

    def __init__(self, fd: int):
        self.fd = fd

    def __str__(self) -> str:
        return f"/proc/self/fd/{self.fd}"

    def close(self) -> None:
        os.close(self.fd)


def _trusted_binary() -> _VerifiedBinary:
    configured = os.environ.get("SNIPER_TRIVY_BINARY", "")
    path = Path(configured)
    if not path.is_absolute():
        raise TrivyConfigUnavailable("Trivy ikilisi kullanılamıyor.")
    source_fd = None
    snapshot_fd = None
    try:
        if not hasattr(os, "memfd_create") or not hasattr(os, "MFD_ALLOW_SEALING"):
            raise TrivyConfigUnavailable("Doğrulanmış Trivy çalıştırması kullanılamıyor.")
        source_fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        source_before = os.fstat(source_fd)
        if (
            not stat.S_ISREG(source_before.st_mode)
            or not (source_before.st_mode & 0o111)
            or not 0 < source_before.st_size <= MAX_TRIVY_BINARY_BYTES
        ):
            raise TrivyConfigUnavailable("Trivy ikilisi kullanılamıyor.")
        snapshot_fd = os.memfd_create("sniper-verified-trivy", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        os.fchmod(snapshot_fd, 0o500)
        copied = 0
        while copied < source_before.st_size:
            chunk = os.read(source_fd, min(1_048_576, source_before.st_size - copied))
            if not chunk:
                break
            view = memoryview(chunk)
            while view:
                written = os.write(snapshot_fd, view)
                view = view[written:]
            copied += len(chunk)
        source_after = os.fstat(source_fd)
        if copied != source_before.st_size or (
            source_before.st_dev,
            source_before.st_ino,
            source_before.st_size,
            source_before.st_mtime_ns,
            source_before.st_ctime_ns,
        ) != (
            source_after.st_dev,
            source_after.st_ino,
            source_after.st_size,
            source_after.st_mtime_ns,
            source_after.st_ctime_ns,
        ):
            raise TrivyConfigUnavailable("Trivy ikilisi doğrulama sırasında değişti.")
        seals = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
        fcntl.fcntl(snapshot_fd, fcntl.F_ADD_SEALS, seals)
        if fcntl.fcntl(snapshot_fd, fcntl.F_GET_SEALS) & seals != seals:
            raise TrivyConfigUnavailable("Doğrulanmış Trivy çalıştırması kullanılamıyor.")
        digest = hashlib.sha256()
        offset = 0
        while offset < copied:
            chunk = os.pread(snapshot_fd, min(1_048_576, copied - offset), offset)
            if not chunk:
                raise TrivyConfigUnavailable("Doğrulanmış Trivy çalıştırılabiliri eksik.")
            digest.update(chunk)
            offset += len(chunk)
        if digest.hexdigest() != EXPECTED_TRIVY_SHA256:
            raise TrivyConfigUnavailable("Trivy ikilisi hash değeri uyuşmuyor.")
        verified = _VerifiedBinary(snapshot_fd)
        snapshot_fd = None
        return verified
    except OSError as exc:
        raise TrivyConfigUnavailable("Doğrulanmış Trivy çalıştırması kullanılamıyor.") from exc
    finally:
        if source_fd is not None:
            os.close(source_fd)
        if snapshot_fd is not None:
            os.close(snapshot_fd)


def _read_bounded_report(report: Path) -> str:
    """Validate and read one report inode; never reopen its pathname after checks."""
    try:
        fd = os.open(report, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError as exc:
        raise TrivyConfigExecutionError("Trivy yapılandırma raporu kullanılamıyor.") from exc
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= MAX_REPORT_BYTES:
            raise TrivyConfigExecutionError("Trivy yapılandırma raporunun boyutu veya türü geçersiz.")
        data = bytearray()
        while len(data) <= MAX_REPORT_BYTES:
            try:
                chunk = os.read(fd, min(65536, MAX_REPORT_BYTES + 1 - len(data)))
            except OSError as exc:
                raise TrivyConfigExecutionError("Trivy yapılandırma raporu okunamadı.") from exc
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(fd)
        if len(data) != before.st_size or (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise TrivyConfigExecutionError("Trivy yapılandırma raporu okuma sırasında değişti.")
        try:
            return data.decode("utf-8")
        except UnicodeError as exc:
            raise TrivyConfigExecutionError("Trivy yapılandırma raporu UTF-8 değil.") from exc
    finally:
        os.close(fd)


@contextmanager
def _open_project_dir_fd(project_root: Path, allowed_root: Path | None = None):
    """Hold a project directory reached through no-follow directory descriptors.

    `validate_project_path` checks the user-visible pathname, but its return
    value cannot safely be reopened by name after another process renames a
    parent directory. Open the allowed root and every child directory without
    following symlinks, then use this descriptor for every selected file.
    """
    root = allowed_root if allowed_root is not None else Path.home().resolve()
    try:
        if not project_root.is_absolute() or not root.is_absolute():
            raise ValueError("project_path mutlak olmalı")
        relative = project_root.relative_to(root)
        if not relative.parts or any(part in ("", ".", "..") for part in relative.parts):
            raise ValueError("project_path izin verilen kök içinde olmalı")
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        directory_fd = os.open("/", flags)
        try:
            for component in (*root.parts[1:], *relative.parts):
                next_fd = os.open(component, flags, dir_fd=directory_fd)
                os.close(directory_fd)
                directory_fd = next_fd
            yield directory_fd
        finally:
            os.close(directory_fd)
    except OSError as exc:
        raise ValueError("project_path değişti veya sembolik bağ içeriyor") from exc


def _read_dockerfile(project_root: Path, project_fd: int | None = None) -> bytes:
    if project_fd is None:
        with _open_project_dir_fd(project_root) as opened_fd:
            return _read_dockerfile(project_root, opened_fd)
    try:
        fd = os.open("Dockerfile", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=project_fd)
    except OSError as exc:
        raise ValueError("project_path normal bir Dockerfile içermeli.") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_DOCKERFILE_BYTES:
            raise ValueError("Dockerfile en fazla 1 MB büyüklüğünde normal bir dosya olmalı.")
        data = bytearray()
        while len(data) <= MAX_DOCKERFILE_BYTES:
            chunk = os.read(fd, min(65536, MAX_DOCKERFILE_BYTES + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        if len(data) > MAX_DOCKERFILE_BYTES or len(data) != info.st_size:
            raise ValueError("Dockerfile değişti veya boyut sınırını aştı.")
        after = os.fstat(fd)
        if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (
            info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns
        ):
            raise ValueError("Dockerfile hazırlama sırasında değişti.")
        return bytes(data)
    finally:
        os.close(fd)

def _read_terraform_file(project_root: Path, terraform_file: str, project_fd: int | None = None) -> bytes:
    if not isinstance(terraform_file, str) or not terraform_file.strip():
        raise ValueError("terraform_file boş olmayan bir metin olmalı")
    if "/" in terraform_file or "\\" in terraform_file:
        raise ValueError("terraform_file yol ayırıcı içermemeli")
    if ".." in terraform_file:
        raise ValueError("terraform_file '..' içermemeli")
    if terraform_file.startswith("."):
        raise ValueError("terraform_file gizli dosya olmamalı")
    if not terraform_file.endswith(".tf"):
        raise ValueError("terraform_file .tf uzantılı olmalı")
    if project_fd is None:
        with _open_project_dir_fd(project_root) as opened_fd:
            return _read_terraform_file(project_root, terraform_file, opened_fd)
    try:
        fd = os.open(terraform_file, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=project_fd)
    except OSError as exc:
        raise ValueError("terraform_file, project_path altında normal bir dosya olmalı") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size == 0 or info.st_size > MAX_TERRAFORM_FILE_BYTES:
            raise ValueError("terraform_file en fazla 1 MB büyüklüğünde, boş olmayan normal bir dosya olmalı")
        data = bytearray()
        while len(data) <= MAX_TERRAFORM_FILE_BYTES:
            chunk = os.read(fd, min(65536, MAX_TERRAFORM_FILE_BYTES + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        if len(data) > MAX_TERRAFORM_FILE_BYTES or len(data) != info.st_size:
            raise ValueError("terraform_file değişti veya boyut sınırını aştı")
        after = os.fstat(fd)
        if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (
            info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns
        ):
            raise ValueError("terraform_file hazırlama sırasında değişti")
        return bytes(data)
    finally:
        os.close(fd)



def _scan_lock() -> int:
    data_dir = os.environ.get("SNIPER_DATA_DIR")
    if not data_dir:
        raise TrivyConfigUnavailable("Trivy veri dizini kullanılamıyor.")
    fd = None
    try:
        fd = os.open(Path(data_dir) / "trivy-config.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            raise OSError("geçersiz kilit dosyası")
    except OSError as exc:
        if fd is not None:
            os.close(fd)
        raise TrivyConfigUnavailable("Trivy kilidi kullanılamıyor.") from exc
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        os.close(fd)
        raise TrivyConfigBusy("Bir Trivy yapılandırma taraması zaten sürüyor.") from exc
    return fd


def run_local_trivy_dockerfile(project_path: str) -> dict:
    allowed_root = Path.home().resolve()
    project_root = validate_project_path(project_path, allowed_roots=(allowed_root,))
    with _open_project_dir_fd(project_root, allowed_root) as project_fd:
        dockerfile = _read_dockerfile(project_root, project_fd)
    lock = _scan_lock()
    binary = None
    try:
        binary = _trusted_binary()
        with tempfile.TemporaryDirectory(prefix="sniper_trivy_config_") as directory:
            scratch = Path(directory)
            staged = scratch / "input"
            staged.mkdir()
            (staged / "Dockerfile").write_bytes(dockerfile)
            report = scratch / "report.json"
            environment = {
                "HOME": str(scratch),
                "XDG_CACHE_HOME": str(scratch / "cache"),
                "TMPDIR": str(scratch),
                "PATH": "/usr/bin:/bin",
                "LANG": "C.UTF-8",
            }
            command = [
                str(binary), "config", "--misconfig-scanners", "dockerfile",
                "--skip-check-update", "--skip-version-check", "--config=", "--ignorefile=",
                "--format", "json", "--output", str(report), "--cache-dir", str(scratch / "cache"),
                "--timeout", "30s", str(staged),
            ]
            try:
                process = subprocess.Popen(
                    command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, env=environment, start_new_session=True,
                    pass_fds=(binary.fd,),
                )
                try:
                    exit_code = process.wait(timeout=40)
                except subprocess.TimeoutExpired as exc:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait(timeout=3)
                    raise TrivyConfigExecutionError("Trivy yapılandırma taraması zaman aşımına uğradı.") from exc
            except OSError as exc:
                raise TrivyConfigExecutionError("Trivy yapılandırma taraması başarısız oldu.") from exc
            if exit_code != 0:
                raise TrivyConfigExecutionError("Trivy yapılandırma taraması başarısız oldu.")
            try:
                document = json.loads(_read_bounded_report(report))
                if not isinstance(document, dict):
                    raise ValueError("geçersiz rapor")
                rows = document.get("Results", [])
                if not isinstance(rows, list) or len(rows) != 1:
                    raise ValueError("beklenmeyen sonuç sayısı")
                for row in rows:
                    if not isinstance(row, dict) or row.get("Target") != "Dockerfile":
                        raise ValueError("beklenmeyen hedef")
                    if row.get("Class") != "config" or row.get("Type") != "dockerfile":
                        raise ValueError("beklenmeyen tarayıcı")
                    if any(row.get(key) for key in ("Vulnerabilities", "Secrets", "Licenses")):
                        raise ValueError("beklenmeyen bulgu türü")
                    findings = row.get("Misconfigurations", [])
                    counters = row.get("MisconfSummary")
                    if not isinstance(counters, dict):
                        raise ValueError("yanlış yapılandırma özeti eksik")
                    count = counters.get("Failures")
                    if not isinstance(findings, list) or type(count) is not int or count != len(findings):
                        raise ValueError("yanlış yapılandırma sayıları tutarsız")
                summary = parse_trivy_native_json_summary(document)
            except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
                raise TrivyConfigExecutionError("Trivy yapılandırma raporu doğrulamadan geçemedi.") from exc
            summary["profile"] = "local-dockerfile-config-v1"
            return summary
    finally:
        try:
            if binary is not None:
                binary.close()
        finally:
            os.close(lock)

def run_local_trivy_terraform(project_path: str, terraform_file: str) -> dict:
    allowed_root = Path.home().resolve()
    project_root = validate_project_path(project_path, allowed_roots=(allowed_root,))
    with _open_project_dir_fd(project_root, allowed_root) as project_fd:
        terraform_data = _read_terraform_file(project_root, terraform_file, project_fd)
    lock = _scan_lock()
    binary = None
    try:
        binary = _trusted_binary()
        with tempfile.TemporaryDirectory(prefix="sniper_trivy_terraform_") as directory:
            scratch = Path(directory)
            staged = scratch / "input"
            staged.mkdir()
            (staged / terraform_file).write_bytes(terraform_data)
            report = scratch / "report.json"
            environment = {
                "HOME": str(scratch),
                "XDG_CACHE_HOME": str(scratch / "cache"),
                "TMPDIR": str(scratch),
                "PATH": "/usr/bin:/bin",
                "LANG": "C.UTF-8",
            }
            command = [
                str(binary), "config", "--misconfig-scanners", "terraform",
                "--skip-check-update", "--skip-version-check", "--config=", "--ignorefile=",
                "--format", "json", "--output", str(report), "--cache-dir", str(scratch / "cache"),
                "--timeout", "30s", str(staged),
            ]
            try:
                process = subprocess.Popen(
                    command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, env=environment, start_new_session=True,
                    pass_fds=(binary.fd,),
                )
                try:
                    exit_code = process.wait(timeout=40)
                except subprocess.TimeoutExpired as exc:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait(timeout=3)
                    raise TrivyConfigExecutionError("Trivy yapılandırma taraması zaman aşımına uğradı.") from exc
            except OSError as exc:
                raise TrivyConfigExecutionError("Trivy yapılandırma taraması başarısız oldu.") from exc
            if exit_code != 0:
                raise TrivyConfigExecutionError("Trivy yapılandırma taraması başarısız oldu.")
            try:
                document = json.loads(_read_bounded_report(report))
                if not isinstance(document, dict):
                    raise ValueError("geçersiz rapor")
                rows = document.get("Results", [])
                if not isinstance(rows, list):
                    raise ValueError("Results bir JSON dizisi olmalı")
                target_found = False
                root_row_found = False
                for row in rows:
                    if not isinstance(row, dict):
                        raise ValueError("Her Result bir nesne olmalı")
                    target = row.get("Target")
                    if not isinstance(target, str):
                        raise ValueError("Target bir metin olmalı")
                    if target == ".":
                        if root_row_found:
                            raise ValueError("Yinelenen kök satır")
                        root_row_found = True
                        if row.get("Class") != "config" or row.get("Type") != "terraform":
                            raise ValueError("Beklenmeyen '.' hedef satırı")
                        root_summary = row.get("MisconfSummary")
                        if not isinstance(root_summary, dict):
                            raise ValueError("MisconfSummary bir sözlük olmalı")
                        failures = root_summary.get("Failures")
                        if type(failures) is not int or failures != 0:
                            raise ValueError("'.' satırında beklenmeyen bulgular")
                        if "Misconfigurations" in row:
                            misconfigs = row["Misconfigurations"]
                            if misconfigs is None:
                                row["Misconfigurations"] = []
                            elif not isinstance(misconfigs, list) or misconfigs:
                                raise ValueError("Beklenmeyen kök yanlış yapılandırmaları")
                        if any(row.get(key) for key in ("Vulnerabilities", "Secrets", "Licenses")):
                            raise ValueError("'.' satırında beklenmeyen bulgu türü")
                    elif target == terraform_file:
                        if row.get("Class") != "config" or row.get("Type") != "terraform":
                            raise ValueError("Beklenmeyen hedef satırı")
                        if target_found:
                            raise ValueError("Yinelenen hedef satırı")
                        target_found = True
                        if any(row.get(key) for key in ("Vulnerabilities", "Secrets", "Licenses")):
                            raise ValueError("Hedef satırında beklenmeyen bulgu türü")
                    else:
                        raise ValueError(f"Beklenmeyen hedef: {target}")
                if not root_row_found:
                    raise ValueError("Beklenen kök satır eksik")
                summary = parse_trivy_native_json_summary(document)
                if not target_found and summary["finding_counts"]["misconfigurations"] != 0:
                    raise ValueError(f"Beklenen hedef satırı eksik: {terraform_file}")
            except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
                raise TrivyConfigExecutionError("Trivy yapılandırma raporu doğrulamadan geçemedi.") from exc
            summary["profile"] = "local-terraform-config-v1"
            return summary
    finally:
        try:
            if binary is not None:
                binary.close()
        finally:
            os.close(lock)


def run_local_trivy_terraform_batch(project_path: str, terraform_files: list[str]) -> dict:
    """Scan explicitly selected root-level Terraform files in one local Trivy context."""
    if not isinstance(terraform_files, list) or not 1 <= len(terraform_files) <= MAX_TERRAFORM_BATCH_FILES:
        raise ValueError("terraform_files 1 ile 8 arasında kök düzey .tf dosyası içermeli")
    if any(
        not isinstance(name, str)
        or not _TERRAFORM_BATCH_NAME.fullmatch(name)
        or ".." in name
        for name in terraform_files
    ):
        raise ValueError("terraform_files yalnız kök düzey .tf dosya adları içermeli")
    if len(set(terraform_files)) != len(terraform_files):
        raise ValueError("terraform_files birbirinden farklı olmalı")

    allowed_root = Path.home().resolve()
    project_root = validate_project_path(project_path, allowed_roots=(allowed_root,))
    staged_files: list[tuple[str, bytes]] = []
    total_bytes = 0
    with _open_project_dir_fd(project_root, allowed_root) as project_fd:
        for name in terraform_files:
            source = _read_terraform_file(project_root, name, project_fd)
            total_bytes += len(source)
            if total_bytes > MAX_TERRAFORM_BATCH_BYTES:
                raise ValueError("Hazırlanan toplam Terraform boyutu 8 MB'ı aştı")
            staged_files.append((name, source))

    lock = _scan_lock()
    binary = None
    try:
        binary = _trusted_binary()
        with tempfile.TemporaryDirectory(prefix="sniper_trivy_terraform_batch_") as directory:
            scratch = Path(directory)
            staged_dir = scratch / "input"
            staged_dir.mkdir()
            for name, source in staged_files:
                (staged_dir / name).write_bytes(source)
            report = scratch / "report.json"
            environment = {
                "HOME": str(scratch),
                "XDG_CACHE_HOME": str(scratch / "cache"),
                "TMPDIR": str(scratch),
                "PATH": "/usr/bin:/bin",
                "LANG": "C.UTF-8",
            }
            command = [
                str(binary), "config", "--misconfig-scanners", "terraform",
                "--skip-check-update", "--skip-version-check", "--config=", "--ignorefile=",
                "--format", "json", "--output", str(report), "--cache-dir", str(scratch / "cache"),
                "--timeout", "30s", str(staged_dir),
            ]
            try:
                process = subprocess.Popen(
                    command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, env=environment, start_new_session=True,
                    pass_fds=(binary.fd,),
                )
                try:
                    exit_code = process.wait(timeout=40)
                except subprocess.TimeoutExpired as exc:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait(timeout=3)
                    raise TrivyConfigExecutionError("Trivy Terraform toplu taraması zaman aşımına uğradı.") from exc
            except OSError as exc:
                raise TrivyConfigExecutionError("Trivy Terraform toplu taraması başarısız oldu.") from exc
            if exit_code != 0:
                raise TrivyConfigExecutionError("Trivy Terraform toplu taraması başarısız oldu.")
            try:
                document = json.loads(_read_bounded_report(report))
                if not isinstance(document, dict):
                    raise ValueError("geçersiz rapor")
                if type(document.get("SchemaVersion")) is not int or document["SchemaVersion"] != 2:
                    raise ValueError("geçersiz rapor şeması")
                rows = document.get("Results")
                if not isinstance(rows, list) or not 1 <= len(rows) <= len(terraform_files) + 1:
                    raise ValueError("beklenmeyen sonuç sayısı")
                expected_targets = set(terraform_files) | {"."}
                observed_targets: set[str] = set()
                for row in rows:
                    if not isinstance(row, dict):
                        raise ValueError("geçersiz sonuç satırı")
                    target = row.get("Target")
                    if not isinstance(target, str) or target not in expected_targets or target in observed_targets:
                        raise ValueError("beklenmeyen veya yinelenen sonuç hedefi")
                    observed_targets.add(target)
                    if row.get("Class") != "config" or row.get("Type") != "terraform":
                        raise ValueError("beklenmeyen tarayıcı")
                    if any(key in row for key in ("Vulnerabilities", "Secrets", "Licenses")):
                        raise ValueError("beklenmeyen bulgu türü")
                    counters = row.get("MisconfSummary")
                    if not isinstance(counters, dict):
                        raise ValueError("yanlış yapılandırma özeti eksik")
                    failures = counters.get("Failures")
                    successes = counters.get("Successes")
                    if type(failures) is not int or failures < 0:
                        raise ValueError("geçersiz başarısızlık sayısı")
                    if type(successes) is not int or successes < 0:
                        raise ValueError("geçersiz başarı sayısı")
                    findings = row.get("Misconfigurations", [])
                    if target == "." and findings is None:
                        findings = []
                        row["Misconfigurations"] = []
                    if not isinstance(findings, list) or failures != len(findings):
                        raise ValueError("yanlış yapılandırma sayıları tutarsız")
                    if target == "." and failures:
                        raise ValueError("beklenmeyen kök bulgular")
                # Trivy 0.75.0 omits selected clean .tf target rows when another
                # staged file has findings. The root row is always required;
                # every emitted file target must belong to the staged set.
                if "." not in observed_targets:
                    raise ValueError("kök sonuç hedefi eksik")
                summary = parse_trivy_native_json_summary(document)
            except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
                raise TrivyConfigExecutionError("Trivy Terraform toplu raporu doğrulamadan geçemedi.") from exc
            summary["profile"] = "local-terraform-config-batch-v1"
            return summary
    finally:
        try:
            if binary is not None:
                binary.close()
        finally:
            os.close(lock)
