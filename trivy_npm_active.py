from __future__ import annotations

import fcntl
import hashlib
import json
import os
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from project_analyzer import validate_project_path, ProjectRejected
from project_tree import ProjectTreeError
from trivy_config_active import _open_trusted_binary


from trivy_vuln_active import (
    TrivyVulnUnavailable, TrivyVulnBusy, TrivyVulnExecutionError, TrivyVulnInvalidInput,
    _read_root_project_file,
)


def _streaming_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def run_local_trivy_npm_vulnerability(project_path: str) -> dict[str, Any]:
    # Validate project path — restrict to home-only (no external mounts)
    src_root = validate_project_path(project_path, allowed_roots=(Path.home().resolve(),))

    # Acquire persistent lock in SNIPER_DATA_DIR
    data_dir = os.environ.get("SNIPER_DATA_DIR")
    if not data_dir:
        raise TrivyVulnUnavailable("Trivy zafiyet tarayıcısı kullanılamıyor.")
    lock_path = Path(data_dir).resolve() / "trivy.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)

    lock_fd = None
    binary_fd: int | None = None
    try:
        # Open with O_NOFOLLOW, O_CREAT, O_RDWR
        lock_fd = os.open(str(lock_path), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            st = os.fstat(lock_fd)
            if not stat.S_ISREG(st.st_mode):
                raise TrivyVulnUnavailable("Trivy zafiyet tarayıcısı kullanılamıyor.")
        except OSError:
            if lock_fd is not None:
                os.close(lock_fd)
                lock_fd = None
            raise TrivyVulnUnavailable("Trivy zafiyet tarayıcısı kullanılamıyor.")

        # Try to acquire exclusive non-blocking lock
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as e:
            if lock_fd is not None:
                os.close(lock_fd)
                lock_fd = None
            if e.errno == 11:  # EAGAIN
                raise TrivyVulnBusy("Başka bir Trivy taraması sürüyor.")
            raise TrivyVulnBusy("Başka bir Trivy taraması sürüyor.")

    except Exception as e:
        if lock_fd is not None:
            os.close(lock_fd)
            lock_fd = None
        raise TrivyVulnBusy("Başka bir Trivy taraması sürüyor.")

    try:
        try:
            _trivy_path, binary_fd = _open_trusted_binary()
        except RuntimeError as exc:
            raise TrivyVulnUnavailable(str(exc)) from exc

        # Validate cache dir and DB
        cache_dir = os.environ.get("SNIPER_TRIVY_VULN_CACHE_DIR")
        if not cache_dir:
            raise TrivyVulnUnavailable("Trivy zafiyet önbellek dizini yapılandırılmamış.")
        raw_cache_path = Path(cache_dir)
        # Check raw path is absolute and not a symlink BEFORE resolving
        if not raw_cache_path.is_absolute():
            raise TrivyVulnUnavailable("Trivy önbellek dizini yolu mutlak olmalı.")
        if raw_cache_path.is_symlink():
            raise TrivyVulnUnavailable("Trivy önbellek dizini normal bir dizin olmalı.")
        cache_abs = raw_cache_path.resolve()
        if not cache_abs.is_dir():
            raise TrivyVulnUnavailable("Trivy önbellek dizini mevcut olmalı.")

        # Check intermediate db directory (unresolved)
        db_dir = Path(cache_dir) / "db"
        if db_dir.is_symlink():
            raise TrivyVulnUnavailable("Trivy veritabanı dizini normal bir dizin olmalı.")
        if not db_dir.is_dir():
            raise TrivyVulnUnavailable("Trivy veritabanı dizini mevcut olmalı.")

        metadata_path = cache_abs / "db" / "metadata.json"
        trivy_db_path = cache_abs / "db" / "trivy.db"

        for p in (metadata_path, trivy_db_path):
            if p.is_symlink():
                raise TrivyVulnUnavailable("Trivy veritabanı dosyası normal bir dosya olmalı.")
            if not p.is_file():
                raise TrivyVulnUnavailable("Trivy veritabanı dosyası mevcut olmalı.")

        # Validate DB SHA256
        expected_sha = os.environ.get("SNIPER_TRIVY_VULN_DB_SHA256")
        if not expected_sha:
            raise TrivyVulnUnavailable("Trivy veritabanı SHA256 değeri yapılandırılmamış.")
        if len(expected_sha) != 64 or not all(c in "0123456789abcdef" for c in expected_sha.lower()):
            raise TrivyVulnUnavailable("Trivy veritabanı SHA256 değeri 64 karakterlik küçük harfli onaltılık metin olmalı.")

        actual_sha = _streaming_sha256(trivy_db_path)
        if actual_sha.lower() != expected_sha.lower():
            raise TrivyVulnUnavailable("Trivy veritabanı SHA256 değeri uyuşmuyor.")

        # Use system temp dir (PrivateTmp makes it service-private)
        with tempfile.TemporaryDirectory(prefix="sniper_trivy_npm_") as tmpdir:
            snapshot_root = Path(tmpdir)
            input_dir = snapshot_root / "input"
            input_dir.mkdir(parents=True, exist_ok=True)

            try:
                data = _read_root_project_file(
                    src_root,
                    "package-lock.json",
                    5_000_000,
                    allow_empty=True,
                )
            except ProjectTreeError as exc:
                raise TrivyVulnInvalidInput(
                    "Kök düzeydeki package-lock.json en fazla 5.000.000 baytlık normal bir dosya olmalı."
                ) from exc
            try:
                lock_data = json.loads(data)
            except (ValueError, UnicodeDecodeError) as exc:
                raise TrivyVulnInvalidInput("package-lock.json geçerli JSON içermeli") from exc
            if (
                not isinstance(lock_data, dict)
                or type(lock_data.get("lockfileVersion")) is not int
                or lock_data["lockfileVersion"] not in (1, 2, 3)
            ):
                raise TrivyVulnInvalidInput("package-lock.json npm kilit dosyası sürüm 1, 2 veya 3 olmalı")
            if not isinstance(lock_data.get("packages"), dict) and not isinstance(lock_data.get("dependencies"), dict):
                raise TrivyVulnInvalidInput("package-lock.json packages veya dependencies içermeli")
            (input_dir / "package-lock.json").write_bytes(data)

            # Prepare output report file
            report_file = snapshot_root / "report.json"

            # Build argument vector per spec — use VALIDATED cache dir
            cmd = [
                f"/proc/self/fd/{binary_fd}",
                "fs",
                "--scanners", "vuln",
                "--offline-scan",
                "--skip-db-update",
                "--skip-java-db-update",
                "--skip-check-update",
                "--skip-version-check",
                "--config=",
                "--ignorefile=",
                "--format", "json",
                "--output", str(report_file),
                "--cache-dir", str(cache_abs),
                "--timeout", "60s",
                str(input_dir),
            ]

            env = os.environ.copy()
            # Force private cache and HOME inside scratch
            env["HOME"] = str(snapshot_root)
            env["XDG_CACHE_HOME"] = str(snapshot_root / "cache")

            # Run bounded runner
            try:
                proc = subprocess.run(
                    cmd,
                    env=env,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=90,
                    check=False,
                    pass_fds=(binary_fd,),
                )
            except subprocess.TimeoutExpired:
                raise TrivyVulnExecutionError("Trivy çalıştırması zaman aşımına uğradı.")
            except OSError:
                raise TrivyVulnExecutionError("Trivy çalıştırılamadı.")

            # Fail closed if subprocess returned non-zero
            if proc.returncode != 0:
                raise TrivyVulnExecutionError("Trivy çalıştırılamadı.")

            # Enforce 2 MB report cap and existence
            if not report_file.is_file() or report_file.is_symlink():
                raise TrivyVulnExecutionError("Trivy rapor dosyası üretmedi.")
            if report_file.stat().st_size > 2_000_000:
                raise TrivyVulnExecutionError("Trivy raporu 2 MB sınırını aşıyor.")

            # Load and parse report
            try:
                raw = report_file.read_text(encoding="utf-8")
                report = json.loads(raw)
            except (json.JSONDecodeError, UnicodeDecodeError):
                raise TrivyVulnExecutionError("Trivy raporu geçerli JSON değil.")

            # Reuse existing parser
            from tool_report_trivy import parse_trivy_native_json_summary
            try:
                summary = parse_trivy_native_json_summary(report)
            except ValueError as e:
                raise TrivyVulnExecutionError("Trivy raporu geçerli JSON değil.") from e

            # Add profile label
            summary["profile"] = "local-npm-package-lock-v1"

            # Compute dynamic SHA256 of canonical JSON report
            canonical = json.dumps(report, sort_keys=True, separators=(",", ":"))
            summary["report_sha256"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

            return summary

    finally:
        if binary_fd is not None:
            os.close(binary_fd)
        if lock_fd is not None:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)
                lock_fd = None
