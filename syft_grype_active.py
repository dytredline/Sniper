"""Pinned, local-only Syft SBOM generation followed by offline Grype analysis."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
import threading
from pathlib import Path
from typing import Any

from process_group_runner import run_in_process_group
from project_analyzer import ProjectRejected, validate_project_path
from project_tree import ProjectTree, ProjectTreeError


class SyftGrypeUnavailable(RuntimeError):
    pass


class SyftGrypeBusy(RuntimeError):
    pass


class SyftGrypeExecutionError(RuntimeError):
    pass


SYFT_VERSION = "1.55.0"
GRYPE_VERSION = "0.121.0"
SYFT_SHA256 = "4f8068b25551a42991a292a42078519fdc739a97a6f6310e1dcf1367a258c1c2"
GRYPE_SHA256 = "e81fd2b6669c5a9ab7fee756e63e769cc40163310c11e546420b4d93e2118543"
GRYPE_DB_SHA256 = "bd2a260cf746a39229f01a3eb0da8453ba0ef5e51e88a1abe735c6e257774494"
_RUNTIME_ROOT = Path.home() / ".local" / "state" / "sniper-tool-runtimes"
_DEFAULT_SYFT = _RUNTIME_ROOT / f"syft-{SYFT_VERSION}" / "syft"
_DEFAULT_GRYPE = _RUNTIME_ROOT / f"grype-{GRYPE_VERSION}" / "grype"
_DEFAULT_DB_ROOT = _RUNTIME_ROOT / "grype-db-20261029"
_DEFAULT_DB = _DEFAULT_DB_ROOT / "6" / "vulnerability.db"
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_DB_SCHEMA = re.compile(r"v6\.[0-9]+\.[0-9]+\Z")
_DB_BUILT = re.compile(r"20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
_MAX_REPORT_BYTES = 12_000_000
_MAX_FILES = 5_000
_MAX_FILE_BYTES = 10_000_000
_MAX_TOTAL_BYTES = 100_000_000
_MAX_FINDINGS = 200
_DB_DIGEST_CACHE_LOCK = threading.Lock()
_DB_DIGEST_CACHE: tuple[tuple[int, int, int, int, int], str] | None = None
_EXCLUDED_DIRECTORIES = {
    ".git", ".hg", ".svn", "node_modules", "vendor", "dist", "build", "target",
    "__pycache__", ".cache", ".venv", "venv", ".tox", ".mypy_cache", ".pytest_cache",
}
_MANIFEST_NAMES = {
    "requirements.txt", "pyproject.toml", "poetry.lock", "pipfile", "pipfile.lock",
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock",
    "bun.lockb", "pubspec.yaml", "pubspec.lock", "cargo.toml", "cargo.lock", "go.mod",
    "go.sum", "gemfile", "gemfile.lock", "composer.json", "composer.lock", "pom.xml",
    "build.gradle", "build.gradle.kts", "gradle.lockfile", "packages.lock.json",
    "package.resolved", "paket.lock", "mix.exs", "mix.lock", "conan.lock",
    "conanfile.txt", "conanfile.py", "vcpkg.json", "vcpkg-lock.json",
    ".terraform.lock.hcl", "renovate.json",
}
_MANIFEST_SUFFIXES = (".csproj", ".fsproj", ".vbproj", ".deps.json")


def _sha256_fd(fd: int) -> str:
    digest = hashlib.sha256()
    with os.fdopen(os.dup(fd), "rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _open_binary(path_env: str, sha_env: str, default_path: Path, default_sha: str) -> tuple[Path, int]:
    raw_path = os.environ.get(path_env, "").strip()
    path = Path(raw_path) if raw_path else default_path
    expected = os.environ.get(sha_env, "").strip() or default_sha
    if not path.is_absolute() or not _HEX64.fullmatch(expected):
        raise SyftGrypeUnavailable("Sabitlenmiş çalışma zamanı kullanılamıyor.")
    try:
        if path.is_symlink() or path.resolve(strict=True) != path:
            raise OSError("unsafe path")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o022 or not os.access(path, os.X_OK)):
            raise OSError("unsafe binary")
        if _sha256_fd(fd) != expected:
            raise OSError("digest mismatch")
        return path, fd
    except OSError as exc:
        if "fd" in locals():
            os.close(fd)
        raise SyftGrypeUnavailable("Sabitlenmiş çalışma zamanı kullanılamıyor.") from exc


def _trusted_database() -> tuple[Path, str, str]:
    global _DB_DIGEST_CACHE
    root = Path(os.environ.get("SNIPER_GRYPE_DB_ROOT", "").strip() or _DEFAULT_DB_ROOT)
    path = Path(os.environ.get("SNIPER_GRYPE_DB_PATH", "").strip() or _DEFAULT_DB)
    expected = os.environ.get("SNIPER_GRYPE_DB_SHA256", "").strip() or GRYPE_DB_SHA256
    schema = os.environ.get("SNIPER_GRYPE_DB_SCHEMA", "").strip() or "v6.1.10"
    built = os.environ.get("SNIPER_GRYPE_DB_BUILT", "").strip() or "2026-10-29T06:23:34Z"
    if (not root.is_absolute() or not path.is_absolute() or not _HEX64.fullmatch(expected)
            or not _DB_SCHEMA.fullmatch(schema) or not _DB_BUILT.fullmatch(built)):
        raise SyftGrypeUnavailable("Sabitlenmiş Grype veritabanı kullanılamıyor.")
    try:
        if root.is_symlink() or root.resolve(strict=True) != root or not root.is_dir():
            raise OSError("unsafe root")
        if path.is_symlink() or path.resolve(strict=True) != path or root not in path.parents:
            raise OSError("unsafe database path")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or info.st_mode & 0o022 or not 1 <= info.st_size <= 5_000_000_000):
                raise OSError("unsafe database")
            key = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
            with _DB_DIGEST_CACHE_LOCK:
                if _DB_DIGEST_CACHE is not None and _DB_DIGEST_CACHE[0] == key:
                    actual = _DB_DIGEST_CACHE[1]
                else:
                    actual = _sha256_fd(fd)
                    _DB_DIGEST_CACHE = (key, actual)
            after = path.stat(follow_symlinks=False)
            if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) != key:
                raise OSError("database changed during verification")
        finally:
            os.close(fd)
        if actual != expected:
            raise OSError("database digest mismatch")
    except OSError as exc:
        raise SyftGrypeUnavailable("Sabitlenmiş Grype veritabanı kullanılamıyor.") from exc
    return root, schema, built


def readiness() -> dict[str, object]:
    syft_fd = grype_fd = None
    try:
        _syft, syft_fd = _open_binary(
            "SNIPER_SYFT_BINARY", "SNIPER_SYFT_BINARY_SHA256", _DEFAULT_SYFT, SYFT_SHA256)
        _grype, grype_fd = _open_binary(
            "SNIPER_GRYPE_BINARY", "SNIPER_GRYPE_BINARY_SHA256", _DEFAULT_GRYPE, GRYPE_SHA256)
        _root, schema, built = _trusted_database()
        return {"state": "ready", "database": {"schema": schema, "built": built}}
    finally:
        if syft_fd is not None:
            os.close(syft_fd)
        if grype_fd is not None:
            os.close(grype_fd)


def _is_manifest(relative: Path) -> bool:
    name = relative.name.casefold()
    if name in _MANIFEST_NAMES or name.endswith(_MANIFEST_SUFFIXES):
        return True
    parts = tuple(part.casefold() for part in relative.parts)
    return (len(parts) >= 3 and parts[0] == ".github" and parts[1] == "workflows"
            and relative.suffix.casefold() in {".yml", ".yaml"}) or (
                len(parts) >= 2 and parts[0] == ".github" and name == "dependabot.yml")


def _snapshot_manifests(source: Path, destination: Path) -> tuple[int, int]:
    files = 0
    total = 0
    try:
        with ProjectTree(source) as tree:
            for observed in tree.iter_files(
                skip_dirs=_EXCLUDED_DIRECTORIES,
                max_entries=100_000,
                max_depth=40,
                reject_unsafe=False,
            ):
                relative = Path(observed.path.as_posix())
                if not _is_manifest(relative):
                    continue
                if not 0 <= observed.size <= _MAX_FILE_BYTES:
                    raise ProjectRejected("Bağımlılık manifesti boyut sınırını aşıyor.")
                files += 1
                total += observed.size
                if files > _MAX_FILES or total > _MAX_TOTAL_BYTES:
                    raise ProjectRejected("Bağımlılık manifesti kapsamı güvenli sınırı aşıyor.")
                data = tree.read_bytes(observed, _MAX_FILE_BYTES, allow_empty=True)
                output = destination / relative
                output.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
                descriptor = os.open(
                    output,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600,
                )
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(data)
    except ProjectTreeError as exc:
        raise ProjectRejected("Proje dosyaları güvenli biçimde okunamadı.") from exc
    return files, total


def _private_data_dir() -> Path:
    raw = os.environ.get("SNIPER_DATA_DIR", "").strip()
    if not raw:
        raise SyftGrypeUnavailable("Özel çalışma dizini kullanılamıyor.")
    path = Path(raw)
    try:
        if (not path.is_absolute() or path.is_symlink() or path.resolve(strict=True) != path
                or not path.is_dir() or path.stat().st_uid != os.getuid()
                or path.stat().st_mode & 0o077):
            raise OSError("unsafe data dir")
    except OSError as exc:
        raise SyftGrypeUnavailable("Özel çalışma dizini kullanılamıyor.") from exc
    return path


def _open_lock(data_dir: Path) -> int:
    try:
        fd = os.open(data_dir / "syft-grype.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise OSError("unsafe lock")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return fd
    except BlockingIOError as exc:
        if "fd" in locals():
            os.close(fd)
        raise SyftGrypeBusy("Başka bir SBOM analizi sürüyor.") from exc
    except OSError as exc:
        if "fd" in locals():
            os.close(fd)
        raise SyftGrypeUnavailable("SBOM analiz kilidi kullanılamıyor.") from exc


def _read_json_report(path: Path) -> tuple[dict[str, Any], str]:
    try:
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_size < 2
                or info.st_size > _MAX_REPORT_BYTES):
            raise OSError("invalid report")
        raw = path.read_bytes()
        doc = json.loads(raw.decode("utf-8"))
        if not isinstance(doc, dict):
            raise ValueError("object required")
        return doc, hashlib.sha256(raw).hexdigest()
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise SyftGrypeExecutionError("Araç raporu doğrulanamadı.") from exc


def _safe_text(value: object, *, maximum: int = 200, fallback: str = "unknown") -> str:
    if not isinstance(value, str):
        return fallback
    text = value.strip()
    if not text or len(text) > maximum or any(ord(char) < 32 for char in text):
        return fallback
    return text


def _summarize(sbom: dict[str, Any], grype: dict[str, Any], sbom_sha: str,
               report_sha: str, schema: str, built: str, manifest_count: int) -> dict[str, Any]:
    artifacts = sbom.get("artifacts")
    relationships = sbom.get("artifactRelationships")
    matches = grype.get("matches")
    ignored = grype.get("ignoredMatches", [])
    if (not isinstance(artifacts, list) or len(artifacts) > 100_000
            or not isinstance(relationships, list) or len(relationships) > 250_000
            or not isinstance(matches, list) or len(matches) > 100_000
            or not isinstance(ignored, list) or len(ignored) > 100_000):
        raise SyftGrypeExecutionError("Araç raporu sınırları aşıyor.")
    severity_counts = {key: 0 for key in ("critical", "high", "medium", "low", "negligible", "unknown")}
    fix_state_counts = {key: 0 for key in ("fixed", "not-fixed", "wont-fix", "unknown")}
    findings: list[dict[str, Any]] = []
    matched_packages: set[tuple[str, str, str]] = set()
    for match in matches:
        if not isinstance(match, dict):
            raise SyftGrypeExecutionError("Grype eşleşmesi doğrulanamadı.")
        vulnerability = match.get("vulnerability")
        artifact = match.get("artifact")
        if not isinstance(vulnerability, dict) or not isinstance(artifact, dict):
            raise SyftGrypeExecutionError("Grype eşleşmesi doğrulanamadı.")
        severity = _safe_text(vulnerability.get("severity"), maximum=20).casefold()
        if severity not in severity_counts:
            severity = "unknown"
        severity_counts[severity] += 1
        fix = vulnerability.get("fix") if isinstance(vulnerability.get("fix"), dict) else {}
        fix_state = _safe_text(fix.get("state"), maximum=20).casefold()
        if fix_state not in fix_state_counts:
            fix_state = "unknown"
        fix_state_counts[fix_state] += 1
        package = _safe_text(artifact.get("name"))
        version = _safe_text(artifact.get("version"))
        package_type = _safe_text(artifact.get("type"), maximum=80)
        matched_packages.add((package, version, package_type))
        versions = fix.get("versions")
        fixed_versions = [] if not isinstance(versions, list) else [
            _safe_text(item, maximum=100) for item in versions[:20]
            if _safe_text(item, maximum=100) != "unknown"
        ]
        if len(findings) < _MAX_FINDINGS:
            findings.append({
                "vulnerability_id": _safe_text(vulnerability.get("id")),
                "severity": severity,
                "package": package,
                "version": version,
                "type": package_type,
                "fix_state": fix_state,
                "fixed_versions": fixed_versions,
            })
    return {
        "format": "syft-json+grype-json-summary",
        "profile": "local-sbom-vulnerability-v1",
        "syft_version": SYFT_VERSION,
        "grype_version": GRYPE_VERSION,
        "manifest_count": manifest_count,
        "package_count": len(artifacts),
        "relationship_count": len(relationships),
        "vulnerability_count": len(matches),
        "ignored_vulnerability_count": len(ignored),
        "matched_package_count": len(matched_packages),
        "severity_counts": severity_counts,
        "fix_state_counts": fix_state_counts,
        "findings": findings,
        "findings_truncated": len(matches) > len(findings),
        "database": {"schema": schema, "built": built},
        "sbom_sha256": sbom_sha,
        "report_sha256": report_sha,
    }


def run_local_syft_grype(project_path: str) -> dict[str, Any]:
    source = validate_project_path(project_path, allowed_roots=(Path.home().resolve(),))
    data_dir = _private_data_dir()
    lock_fd = _open_lock(data_dir)
    syft_fd = grype_fd = None
    try:
        _syft, syft_fd = _open_binary(
            "SNIPER_SYFT_BINARY", "SNIPER_SYFT_BINARY_SHA256", _DEFAULT_SYFT, SYFT_SHA256)
        _grype, grype_fd = _open_binary(
            "SNIPER_GRYPE_BINARY", "SNIPER_GRYPE_BINARY_SHA256", _DEFAULT_GRYPE, GRYPE_SHA256)
        db_root, db_schema, db_built = _trusted_database()
        with tempfile.TemporaryDirectory(prefix="syft-grype-", dir=data_dir) as raw_work:
            work = Path(raw_work)
            staged = work / "input"
            staged.mkdir(mode=0o700)
            manifest_count, _bytes = _snapshot_manifests(source, staged)
            sbom_path = work / "sbom.json"
            report_path = work / "grype.json"
            environment = {
                "HOME": str(work), "XDG_CACHE_HOME": str(work / "cache"),
                "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
                "HTTP_PROXY": "", "HTTPS_PROXY": "", "ALL_PROXY": "",
                "http_proxy": "", "https_proxy": "", "all_proxy": "", "NO_PROXY": "*", "no_proxy": "*",
                "SYFT_CHECK_FOR_APP_UPDATE": "false", "SYFT_LOG_QUIET": "true",
            }
            syft_command = [
                f"/proc/self/fd/{syft_fd}", "scan", f"dir:{staged}",
                "--source-name", "local-project", "--quiet", "--output", f"syft-json={sbom_path}",
            ]
            try:
                syft_result = run_in_process_group(
                    syft_command, env=environment, stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    timeout=120, check=False, pass_fds=(syft_fd,), cwd=str(work))
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise SyftGrypeExecutionError("Syft çalıştırması tamamlanamadı.") from exc
            if syft_result.returncode != 0:
                raise SyftGrypeExecutionError("Syft çalıştırması tamamlanamadı.")
            sbom, sbom_sha = _read_json_report(sbom_path)

            grype_environment = dict(environment)
            grype_environment.update({
                "GRYPE_DB_CACHE_DIR": str(db_root),
                "GRYPE_DB_AUTO_UPDATE": "false",
                "GRYPE_DB_VALIDATE_AGE": "false",
                "GRYPE_CHECK_FOR_APP_UPDATE": "false",
            })
            grype_command = [
                f"/proc/self/fd/{grype_fd}", f"sbom:{sbom_path}",
                "--output", "json", "--file", str(report_path), "--name", "local-project", "--quiet",
            ]
            try:
                grype_result = run_in_process_group(
                    grype_command, env=grype_environment, stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    timeout=180, check=False, pass_fds=(grype_fd,), cwd=str(work))
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise SyftGrypeExecutionError("Grype çalıştırması tamamlanamadı.") from exc
            if grype_result.returncode not in (0,):
                raise SyftGrypeExecutionError("Grype çalıştırması tamamlanamadı.")
            grype, report_sha = _read_json_report(report_path)
            return _summarize(
                sbom, grype, sbom_sha, report_sha, db_schema, db_built, manifest_count)
    finally:
        if syft_fd is not None:
            os.close(syft_fd)
        if grype_fd is not None:
            os.close(grype_fd)
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)
