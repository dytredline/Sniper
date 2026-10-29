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
from pathlib import Path

from project_analyzer import validate_project_path
from project_tree import ProjectTree, ProjectTreeError
from tool_report_trivy import parse_trivy_native_json_summary


EXPECTED_TRIVY_SHA256 = "869e310e208f0f2e3e90e4f842cc6adaa2b2c046fecbaade481e6b23fcc8f2a9"
MAX_DOCKERFILE_BYTES = 1_000_000
MAX_TERRAFORM_FILE_BYTES = 1_000_000
MAX_REPORT_BYTES = 2_000_000


class TrivyConfigUnavailable(RuntimeError):
    pass


class TrivyConfigBusy(RuntimeError):
    pass


class TrivyConfigExecutionError(RuntimeError):
    pass


def expected_trivy_sha256() -> str:
    configured = os.environ.get("SNIPER_TRIVY_BINARY_SHA256", "").strip()
    return configured if re.fullmatch(r"[0-9a-f]{64}", configured) else EXPECTED_TRIVY_SHA256


def _open_trusted_binary() -> tuple[Path, int]:
    """Open and verify the exact executable inode inherited by a child."""
    configured = os.environ.get("SNIPER_TRIVY_BINARY", "")
    path = Path(configured)
    if not path.is_absolute():
        raise TrivyConfigUnavailable("Trivy ikilisi kullanılamıyor.")
    binary_fd: int | None = None
    try:
        binary_fd = os.open(
            path,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
        )
        info = os.fstat(binary_fd)
        if not stat.S_ISREG(info.st_mode) or not info.st_mode & 0o111:
            raise OSError("geçersiz Trivy ikilisi")
        with os.fdopen(os.dup(binary_fd), "rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        os.lseek(binary_fd, 0, os.SEEK_SET)
    except OSError as exc:
        if binary_fd is not None:
            os.close(binary_fd)
        raise TrivyConfigUnavailable("Trivy ikilisi okunamıyor.") from exc
    if digest != expected_trivy_sha256():
        os.close(binary_fd)
        raise TrivyConfigUnavailable("Trivy ikilisi hash değeri uyuşmuyor.")
    return path, binary_fd


def _trusted_binary() -> Path:
    """Compatibility/readiness probe; execution keeps its descriptor open."""
    path, binary_fd = _open_trusted_binary()
    os.close(binary_fd)
    return path


def _read_dockerfile(project_root: Path) -> bytes:
    try:
        with ProjectTree(project_root) as tree:
            walker = tree.walk(reject_unsafe=False)
            source = None
            try:
                for entry in walker:
                    for item in entry.files:
                        posix_p = item.path.as_posix()
                        if posix_p == "Dockerfile":
                            source = item
                            break
                        if source is None and posix_p in ("docker/Dockerfile", "build/Dockerfile"):
                            source = item
                    if source is not None and source.path.as_posix() == "Dockerfile":
                        break
            finally:
                walker.close()
            if source is None:
                raise ValueError("project_path normal bir Dockerfile içermeli.")
            if source.size > MAX_DOCKERFILE_BYTES:
                raise ValueError("Dockerfile en fazla 1 MB büyüklüğünde normal bir dosya olmalı.")
            return tree.read_bytes(source, MAX_DOCKERFILE_BYTES, allow_empty=True)
    except ProjectTreeError as exc:
        raise ValueError("Dockerfile değişti veya boyut sınırını aştı.") from exc

def _read_terraform_file(project_root: Path, terraform_file: str) -> bytes:
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
    try:
        with ProjectTree(project_root) as tree:
            walker = tree.walk(reject_unsafe=False)
            try:
                entry = next(walker)
            finally:
                walker.close()
            source = next((item for item in entry.files if item.path.as_posix() == terraform_file), None)
            if source is None:
                raise ValueError("terraform_file, project_path altında normal bir dosya olmalı")
            if source.size == 0 or source.size > MAX_TERRAFORM_FILE_BYTES:
                raise ValueError("terraform_file en fazla 1 MB büyüklüğünde, boş olmayan normal bir dosya olmalı")
            return tree.read_bytes(source, MAX_TERRAFORM_FILE_BYTES)
    except ProjectTreeError as exc:
        raise ValueError("terraform_file değişti veya boyut sınırını aştı") from exc



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
    project_root = validate_project_path(project_path, allowed_roots=(Path.home().resolve(),))
    dockerfile = _read_dockerfile(project_root)
    _binary, binary_fd = _open_trusted_binary()
    try:
        lock = _scan_lock()
    except BaseException:
        os.close(binary_fd)
        raise
    try:
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
                f"/proc/self/fd/{binary_fd}", "config", "--misconfig-scanners", "dockerfile",
                "--skip-check-update", "--skip-version-check", "--config=", "--ignorefile=",
                "--format", "json", "--output", str(report), "--cache-dir", str(scratch / "cache"),
                "--timeout", "30s", str(staged),
            ]
            try:
                process = subprocess.Popen(
                    command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, env=environment, start_new_session=True,
                    pass_fds=(binary_fd,),
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
            if exit_code != 0 or report.is_symlink() or not report.is_file():
                raise TrivyConfigExecutionError("Trivy yapılandırma taraması başarısız oldu.")
            if report.stat().st_size > MAX_REPORT_BYTES:
                raise TrivyConfigExecutionError("Trivy yapılandırma raporu boyut sınırını aştı.")
            try:
                document = json.loads(report.read_text(encoding="utf-8"))
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
        os.close(lock)
        os.close(binary_fd)

def run_local_trivy_terraform(project_path: str, terraform_file: str) -> dict:
    project_root = validate_project_path(project_path, allowed_roots=(Path.home().resolve(),))
    terraform_data = _read_terraform_file(project_root, terraform_file)
    _binary, binary_fd = _open_trusted_binary()
    try:
        lock = _scan_lock()
    except BaseException:
        os.close(binary_fd)
        raise
    try:
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
                f"/proc/self/fd/{binary_fd}", "config", "--misconfig-scanners", "terraform",
                "--skip-check-update", "--skip-version-check", "--config=", "--ignorefile=",
                "--format", "json", "--output", str(report), "--cache-dir", str(scratch / "cache"),
                "--timeout", "30s", str(staged),
            ]
            try:
                process = subprocess.Popen(
                    command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, env=environment, start_new_session=True,
                    pass_fds=(binary_fd,),
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
            if exit_code != 0 or report.is_symlink() or not report.is_file():
                raise TrivyConfigExecutionError("Trivy yapılandırma taraması başarısız oldu.")
            if report.stat().st_size > MAX_REPORT_BYTES:
                raise TrivyConfigExecutionError("Trivy yapılandırma raporu boyut sınırını aştı.")
            try:
                document = json.loads(report.read_text(encoding="utf-8"))
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
        os.close(lock)
        os.close(binary_fd)


def _discover_all_dockerfiles(project_root: Path, max_files: int = 200) -> list[tuple[str, bytes]]:
    skip = {".git", "node_modules", "vendor", "__pycache__", ".cache", "dist", "build", ".next", ".turbo", "target"}
    discovered: list[tuple[str, bytes]] = []
    try:
        with ProjectTree(project_root) as tree:
            for item in tree.iter_files(skip_dirs=skip, reject_unsafe=False):
                name_low = item.name.casefold()
                if not (
                    name_low == "dockerfile"
                    or name_low.startswith("dockerfile.")
                    or name_low.endswith(".dockerfile")
                ):
                    continue
                if item.size == 0 or item.size > MAX_DOCKERFILE_BYTES:
                    continue
                rel_posix = item.path.as_posix()
                raw = tree.read_bytes(item, MAX_DOCKERFILE_BYTES, allow_empty=True)
                discovered.append((rel_posix, raw))
                if len(discovered) >= max_files:
                    break
    except ProjectTreeError as exc:
        raise ValueError("Dockerfile ağacı okuma sırasında değişti.") from exc
    return discovered


def run_local_trivy_dockerfile_all(project_path: str) -> dict:
    """Discover and scan ALL root and nested Dockerfile* files across the project."""
    project_root = validate_project_path(project_path, allowed_roots=(Path.home().resolve(),))
    dockerfiles = _discover_all_dockerfiles(project_root)
    if not dockerfiles:
        return {
            "format": "trivy-native-json",
            "profile": "local-dockerfile-config-all-v1",
            "_engine_status": "skipped",
            "dockerfiles_scanned_count": 0,
            "dockerfiles_scanned": [],
            "finding_counts": {"vulnerabilities": 0, "misconfigurations": 0, "secrets": 0, "licenses": 0},
        }
    _binary, binary_fd = _open_trusted_binary()
    try:
        lock = _scan_lock()
    except BaseException:
        os.close(binary_fd)
        raise
    try:
        with tempfile.TemporaryDirectory(prefix="sniper_trivy_df_all_") as directory:
            scratch = Path(directory)
            staged = scratch / "input"
            staged.mkdir()
            staged_paths: list[str] = []
            for rel_posix, raw_bytes in dockerfiles:
                dest = staged / rel_posix
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(raw_bytes)
                staged_paths.append(rel_posix)
            report = scratch / "report.json"
            environment = {
                "HOME": str(scratch),
                "XDG_CACHE_HOME": str(scratch / "cache"),
                "TMPDIR": str(scratch),
                "PATH": "/usr/bin:/bin",
                "LANG": "C.UTF-8",
            }
            command = [
                f"/proc/self/fd/{binary_fd}", "config", "--misconfig-scanners", "dockerfile",
                "--skip-check-update", "--skip-version-check", "--config=", "--ignorefile=",
                "--format", "json", "--output", str(report), "--cache-dir", str(scratch / "cache"),
                "--timeout", "60s", str(staged),
            ]
            try:
                process = subprocess.Popen(
                    command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, env=environment, start_new_session=True,
                    pass_fds=(binary_fd,),
                )
                try:
                    exit_code = process.wait(timeout=75)
                except subprocess.TimeoutExpired as exc:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait(timeout=3)
                    raise TrivyConfigExecutionError("Trivy çoklu Dockerfile taraması zaman aşımına uğradı.") from exc
            except OSError as exc:
                raise TrivyConfigExecutionError("Trivy çoklu Dockerfile taraması başarısız oldu.") from exc
            max_rep = int(os.environ.get("SNIPER_TRIVY_MAX_REPORT_BYTES", str(MAX_REPORT_BYTES * 5)) or str(MAX_REPORT_BYTES * 5))
            if exit_code != 0 or report.is_symlink() or not report.is_file() or report.stat().st_size > max_rep:
                raise TrivyConfigExecutionError("Trivy çoklu Dockerfile raporu üretilemedi veya sınırı aştı.")
            document = json.loads(report.read_text(encoding="utf-8"))
            summary = parse_trivy_native_json_summary(document)
            summary["profile"] = "local-dockerfile-config-all-v1"
            summary["dockerfiles_scanned_count"] = len(staged_paths)
            summary["dockerfiles_scanned"] = staged_paths
            return summary
    finally:
        os.close(lock)
        os.close(binary_fd)

