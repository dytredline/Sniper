from __future__ import annotations

import fcntl
import hashlib
import json
import os
import stat
import subprocess
import tempfile
import selectors
import time
from pathlib import Path
from typing import Any

from process_group_runner import kill_process_group
from tool_pins import open_pinned
from verified_exec import VerificationError
from project_analyzer import validate_project_path, ProjectRejected


def run_local_trufflehog_filesystem(project_path: str) -> dict[str, Any]:
    # Validate project path — restrict to home-only (no external mounts)
    src_root = validate_project_path(project_path, allowed_roots=(Path.home().resolve(),))

    # Acquire persistent lock in SNIPER_DATA_DIR
    data_dir = os.environ.get("SNIPER_DATA_DIR")
    if not data_dir:
        raise RuntimeError("SNIPER_DATA_DIR ortam değişkeni tanımlı değil.")
    lock_path = Path(data_dir).resolve() / "trufflehog.lock"
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
                raise RuntimeError("Başka bir TruffleHog taraması sürüyor.")
            raise RuntimeError("Başka bir TruffleHog taraması sürüyor.")

    except Exception as e:
        if lock_fd is not None:
            os.close(lock_fd)
        raise RuntimeError("Başka bir TruffleHog taraması sürüyor.")

    try:
        # İkili SHA-256 sabitlemesine göre doğrulanır ve doğrulanan tanıtıcıdan çalıştırılır.
        try:
            verified = open_pinned("trufflehog")
        except VerificationError as exc:
            raise RuntimeError(str(exc)) from exc

        # Use system temp dir (PrivateTmp makes it service-private)
        with verified, tempfile.TemporaryDirectory(prefix="sniper_trufflehog_") as tmpdir:
            snapshot_root = Path(tmpdir)
            input_dir = snapshot_root / "input"
            input_dir.mkdir(parents=True, exist_ok=True)

            # Enforce bounded scan: total bytes <= 25_000_000, per-file <= 1_000_000, MAX_FILES (overridable via env)
            MAX_TOTAL_BYTES = int(os.environ.get("SNIPER_SECRET_SCAN_MAX_TOTAL_BYTES", "25000000"))
            MAX_FILE_BYTES = int(os.environ.get("SNIPER_SECRET_SCAN_MAX_FILE_BYTES", "1000000"))
            total_bytes = 0

            # Local bounded file walker: copy all regular files (including .txt, .md, .pem, .key, .env, source/manifest)
            # Exclude .git, common cache/dependency dirs, symlinks, .trivyignore (not TruffleHog-specific)
            # Never follow symlinks; enforce per-file and total size limits; fail closed on errors
            EXCLUDE_DIRS = {".git", "node_modules", "vendor", "__pycache__", ".cache", "dist", "build"}
            EXCLUDE_BASENAMES: set[str] = set()  # TruffleHog doesn’t use config files by default here
            MAX_FILES = int(os.environ.get("SNIPER_SECRET_SCAN_MAX_FILES", "2000"))
            skip_oversized = os.environ.get("SNIPER_SECRET_SCAN_SKIP_OVERSIZED", "0") == "1"
            file_count = 0

            def _is_excluded_dir(p: Path) -> bool:
                return any(part in EXCLUDE_DIRS for part in p.relative_to(src_root).parts)

            def _walk_local(root: Path):
                """Yield (Path, os.stat_result) for regular files, respecting exclusions and limits."""
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

            # Build argument vector per spec
            cmd = [
                verified.argv0,
                "--no-update",
                "--no-verification",
                "--results=unverified",
                "--json",
                "--concurrency=1",
                "filesystem",
                str(input_dir),
            ]

            env = os.environ.copy()
            env["HOME"] = str(snapshot_root)

            # Run bounded subprocess: nonblocking read, deadline, 64KiB chunks, 2MB cap
            try:
                proc = subprocess.Popen(
                    cmd,
                    **verified.popen_kwargs(
                        env=env,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.DEVNULL,
                        stdin=subprocess.DEVNULL,
                        start_new_session=True,
                    ),
                )
            except OSError as e:
                raise RuntimeError("TruffleHog çalıştırması başarısız oldu.") from e

            stdout_buffer = bytearray()
            deadline = time.monotonic() + 45.0
            try:
                if proc.stdout is None:
                    raise RuntimeError("TruffleHog stdout borusu kullanılamıyor.")
                sel = selectors.DefaultSelector()
                sel.register(proc.stdout, selectors.EVENT_READ)
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        kill_process_group(proc)
                        proc.wait()
                        raise RuntimeError("TruffleHog çalıştırması zaman aşımına uğradı.")
                    ready = sel.select(timeout=min(remaining, 1.0))
                    if ready:
                        chunk = os.read(proc.stdout.fileno(), 65536)
                        if not chunk:
                            break
                        stdout_buffer.extend(chunk)
                        if len(stdout_buffer) > 2_000_000:
                            kill_process_group(proc)
                            proc.wait()
                            raise RuntimeError("TruffleHog stdout çıktısı 2 MB sınırını aşıyor.")
                    else:
                        # Timeout waiting for data — re-check exit
                        if proc.poll() is not None:
                            break

                # Final wait with remaining deadline
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    kill_process_group(proc)
                    proc.wait()
                    raise RuntimeError("TruffleHog çalıştırması zaman aşımına uğradı.")
                exit_code = proc.wait(timeout=max(0.0, remaining))
            except subprocess.TimeoutExpired:
                kill_process_group(proc)
                proc.wait()
                raise RuntimeError("TruffleHog çalıştırması zaman aşımına uğradı.")
            except OSError:
                kill_process_group(proc)
                proc.wait()
                raise RuntimeError("TruffleHog çalıştırması başarısız oldu.")
            finally:
                sel.close()
                if proc.stdout and not proc.stdout.closed:
                    proc.stdout.close()

            # Fail closed on nonzero exit
            if exit_code != 0:
                raise RuntimeError("TruffleHog çalıştırması başarısız oldu.")

            # Parse stdout as UTF-8 JSONL (strict), reject blank interior lines, long lines, bad JSON, non-objects, >500 records
            try:
                raw_stdout = stdout_buffer.decode("utf-8", errors="strict")
            except UnicodeDecodeError as e:
                raise RuntimeError("TruffleHog çıktısı geçersiz UTF-8 içeriyor.") from e

            if not raw_stdout.strip():
                records: list[dict[str, Any]] = []
            else:
                lines = raw_stdout.splitlines()
                if len(lines) > 500:
                    raise RuntimeError("TruffleHog çıktısı 500 kaydı aşıyor.")
                records = []
                for i, line in enumerate(lines, start=1):
                    if not line.strip():
                        raise RuntimeError(f"TruffleHog çıktısının {i}. satırı boş.")
                    line_bytes = line.encode("utf-8")
                    if len(line_bytes) > 64_000:
                        raise RuntimeError(f"TruffleHog {i}. satırı 64.000 baytı aşıyor.")
                    try:
                        obj = json.loads(line)
                    except json.JSONDecodeError:
                        raise RuntimeError(f"TruffleHog çıktısının {i}. satırı geçerli JSON değil.")
                    if not isinstance(obj, dict):
                        raise RuntimeError(f"TruffleHog çıktısının {i}. satırı bir JSON nesnesi değil.")
                    records.append(obj)
                if len(records) > 500:
                    raise RuntimeError("TruffleHog çıktısı 500 kaydı aşıyor.")

            # Reuse existing parser
            from tool_report_trufflehog import parse_trufflehog_json_summary
            try:
                summary = parse_trufflehog_json_summary(records)
            except ValueError as e:
                raise RuntimeError("TruffleHog çıktısı geçerli bir JSON özeti değil.") from e

            # Add profile label
            summary["profile"] = "local-filesystem-no-verification-v1"

            # Compute dynamic SHA256 of canonical JSON report (records only)
            canonical = json.dumps(records, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            summary["report_sha256"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

            return summary

    finally:
        if lock_fd is not None:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)
