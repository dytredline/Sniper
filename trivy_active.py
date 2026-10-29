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

from process_group_runner import run_in_process_group
from project_analyzer import validate_project_path, ProjectRejected
from trivy_config_active import _open_trusted_binary


def run_local_trivy_secret(project_path: str) -> dict[str, Any]:
    # Validate project path — restrict to home-only (no external mounts)
    src_root = validate_project_path(project_path, allowed_roots=(Path.home().resolve(),))

    # Acquire persistent lock in SNIPER_DATA_DIR
    data_dir = os.environ.get("SNIPER_DATA_DIR")
    if not data_dir:
        raise RuntimeError("SNIPER_DATA_DIR ortam değişkeni tanımlı değil.")
    lock_path = Path(data_dir).resolve() / "trivy.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)

    lock_fd = None
    try:
        # Open with O_NOFOLLOW, O_CREAT, O_RDWR
        lock_fd = os.open(str(lock_path), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            st = os.fstat(lock_fd)
            if not stat.S_ISREG(st.st_mode):
                raise RuntimeError("Kilit dosyası normal bir dosya değil.")
        except OSError:
            os.close(lock_fd)
            raise RuntimeError("Kilit dosyası doğrulanamadı.")

        # Try to acquire exclusive non-blocking lock
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as e:
            if e.errno == 11:  # EAGAIN
                raise RuntimeError("Başka bir Trivy taraması sürüyor.")
            raise RuntimeError("Başka bir Trivy taraması sürüyor.")

    except Exception as e:
        if lock_fd is not None:
            os.close(lock_fd)
        raise RuntimeError("Başka bir Trivy taraması sürüyor.")

    binary_fd: int | None = None
    try:
        _trivy_path, binary_fd = _open_trusted_binary()

        # Use system temp dir (PrivateTmp makes it service-private)
        with tempfile.TemporaryDirectory(prefix="sniper_trivy_") as tmpdir:
            snapshot_root = Path(tmpdir)
            input_dir = snapshot_root / "input"
            input_dir.mkdir(parents=True, exist_ok=True)

            # Enforce bounded scan: total bytes <= 25_000_000, per-file <= 1_000_000, MAX_FILES (overridable via env)
            MAX_TOTAL_BYTES = int(os.environ.get("SNIPER_SECRET_SCAN_MAX_TOTAL_BYTES", "25000000"))
            MAX_FILE_BYTES = int(os.environ.get("SNIPER_SECRET_SCAN_MAX_FILE_BYTES", "1000000"))
            total_bytes = 0

            # Local bounded file walker: copy all regular files (including .txt, .md, .pem, .key, .env, source/manifest)
            # Exclude .git, common cache/dependency dirs, symlinks, trivy.yaml, trivy-secret.yaml, .trivyignore
            # Never follow symlinks; enforce per-file and total size limits; fail closed on errors
            EXCLUDE_DIRS = {".git", "node_modules", "vendor", "__pycache__", ".cache", "dist", "build"}
            if os.environ.get("SNIPER_TRIVY_SKIP_SNAPSHOTS", "0") == "1":
                EXCLUDE_DIRS = EXCLUDE_DIRS | {".next", ".turbo", "target", "coverage", "__snapshots__", "compiled"}
            EXCLUDE_BASENAMES = {"trivy.yaml", "trivy-secret.yaml", ".trivyignore"}
            MAX_FILES = int(os.environ.get("SNIPER_SECRET_SCAN_MAX_FILES", "2000"))
            skip_oversized = os.environ.get("SNIPER_SECRET_SCAN_SKIP_OVERSIZED", "0") == "1"
            file_count = 0

            def _is_excluded_dir(p: Path) -> bool:
                return any(part in EXCLUDE_DIRS for part in p.relative_to(src_root).parts)

            def _walk_local(root: Path):
                """Yield (Path, bytes) for regular files, respecting exclusions and limits."""
                try:
                    entries = list(root.iterdir())
                except OSError as e:
                    raise RuntimeError("Dizin gezintisi başarısız oldu") from e
                for entry in entries:
                    try:
                        st = os.lstat(entry)
                    except OSError as e:
                        raise RuntimeError("Dosya bilgisi alınamadı") from e
                    if stat.S_ISLNK(st.st_mode):
                        continue
                    if stat.S_ISDIR(st.st_mode):
                        if _is_excluded_dir(entry):
                            continue
                        yield from _walk_local(entry)
                        continue
                    if not stat.S_ISREG(st.st_mode):
                        continue
                    if entry.name in EXCLUDE_BASENAMES:
                        continue
                    yield entry, st

            for path, st in _walk_local(src_root):
                file_bytes = st.st_size
                if file_bytes > MAX_FILE_BYTES:
                    if skip_oversized:
                        continue
                    raise ValueError("Dosya 1.000.000 baytı aşıyor")
                file_count += 1
                if file_count > MAX_FILES:
                    raise ValueError("Hazırlanan dosya sayısı 2000 sınırını aşıyor")
                total_bytes += file_bytes
                if total_bytes > MAX_TOTAL_BYTES:
                    raise ValueError(f"Hazırlanan toplam bayt ({total_bytes}) 25.000.000 sınırını aşıyor")

                rel = path.relative_to(src_root)
                dest = input_dir / rel
                dest.parent.mkdir(parents=True, exist_ok=True)

                # Copy raw bytes with O_NOFOLLOW and fstat validation
                try:
                    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                except OSError as e:
                    raise RuntimeError("Dosya okunamadı") from e
                try:
                    st2 = os.fstat(fd)
                    if not stat.S_ISREG(st2.st_mode):
                        raise RuntimeError(f"Dosya lstat sonrasında değişti: {path}")
                    if st2.st_size != file_bytes:
                        raise RuntimeError(f"Dosya boyutu lstat sonrasında değişti: {path}")
                    data = bytearray()
                    remaining = file_bytes
                    while remaining > 0:
                        chunk = os.read(fd, min(65536, remaining))
                        if not chunk:
                            break
                        data.extend(chunk)
                        remaining -= len(chunk)
                    if len(data) != file_bytes:
                        raise RuntimeError(f"{path} kısmen okundu: {file_bytes} bekleniyordu, {len(data)} okundu")
                    dest.write_bytes(bytes(data))
                finally:
                    os.close(fd)

            # Reject if total staged bytes exceed limit (double-check)
            if total_bytes > MAX_TOTAL_BYTES:
                raise ValueError(f"Hazırlanan toplam bayt ({total_bytes}) 25.000.000 sınırını aşıyor")

            # Prepare output report file as sibling of input/
            report_file = snapshot_root / "report.json"
            trivy_timeout = int(os.environ.get("SNIPER_TRIVY_TIMEOUT", "45") or "45")
            max_report_bytes = int(os.environ.get("SNIPER_TRIVY_MAX_REPORT_BYTES", "2000000") or "2000000")
            cli_timeout_s = max(30, trivy_timeout - 15) if trivy_timeout > 45 else 30

            # Build argument vector per spec
            cmd = [
                f"/proc/self/fd/{binary_fd}",
                "fs",
                "--scanners", "secret",
                "--offline-scan",
                "--skip-db-update",
                "--skip-java-db-update",
                "--skip-check-update",
                "--skip-version-check",
                "--config=",
                "--secret-config=",
                "--ignorefile=",
                "--format", "json",
                "--output", str(report_file),
                "--cache-dir", str(snapshot_root / "cache"),
                "--timeout", f"{cli_timeout_s}s",
                str(input_dir),
            ]

            env = os.environ.copy()
            # Force private cache and HOME inside scratch
            env["HOME"] = str(snapshot_root)
            env["XDG_CACHE_HOME"] = str(snapshot_root / "cache")

            # Run bounded runner
            try:
                proc = run_in_process_group(
                    cmd,
                    env=env,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=trivy_timeout,
                    check=False,
                    pass_fds=(binary_fd,),
                )
            except subprocess.TimeoutExpired:
                raise RuntimeError("Trivy çalıştırması zaman aşımına uğradı.")
            except OSError:
                raise RuntimeError("Trivy çalıştırılamadı.")

            # Fail closed if subprocess returned non-zero
            if proc.returncode != 0:
                raise RuntimeError("Trivy çalıştırılamadı.")

            # Enforce 2 MB report cap (or SNIPER_TRIVY_MAX_REPORT_BYTES override) and existence
            if not report_file.is_file() or report_file.is_symlink():
                raise RuntimeError("Trivy rapor dosyası üretmedi.")
            if report_file.stat().st_size > max_report_bytes:
                raise RuntimeError("Trivy raporu 2 MB sınırını aşıyor.")

            # Load and parse report
            try:
                raw = report_file.read_text(encoding="utf-8")
                report = json.loads(raw)
            except (json.JSONDecodeError, UnicodeDecodeError):
                raise RuntimeError("Trivy raporu geçerli JSON değil.")

            # Reuse existing parser
            from tool_report_trivy import parse_trivy_native_json_summary
            try:
                summary = parse_trivy_native_json_summary(report)
            except ValueError as e:
                raise RuntimeError("Trivy raporu geçerli JSON değil.") from e

            # Add profile label
            summary["profile"] = "local-secret-v1"

            # Compute dynamic SHA256 of canonical JSON report
            canonical = json.dumps(report, sort_keys=True, separators=(",", ":"))
            summary["report_sha256"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

            return summary

    finally:
        if binary_fd is not None:
            os.close(binary_fd)
        if lock_fd is not None:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)
