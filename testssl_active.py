from __future__ import annotations

import fcntl
import hashlib
import json
import os
import stat
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from tool_report_testssl import parse_testssl_json_summary, MAX_RECORDS, SEVERITY_KEYS


def run_testssl_loopback(target_ip: str, target_port: int, *, full: bool = False) -> dict[str, Any]:
    """
    Run testssl.sh against a loopback TLS service.
    Requires:
      - target_ip == '127.0.0.1'
      - target_port in [1, 65535]
    Uses configured SNIPER_TESTSSL_BINARY and SNIPER_TESTSSL_SHA256.
    Returns aggregate summary without leaking raw data.
    """
    if type(full) is not bool:
        raise ValueError("full bir mantıksal değer olmalı")

    # Validate target (loopback only — IPv4 only per contract)
    if target_ip != "127.0.0.1":
        raise ValueError("target loopback 127.0.0.1 olmalı")

    if not (1 <= target_port <= 65535):
        raise ValueError("port [1, 65535] aralığında bir tamsayı olmalı")

    # Acquire lock in SNIPER_DATA_DIR
    data_dir = os.environ.get("SNIPER_DATA_DIR")
    if not data_dir:
        raise RuntimeError("SNIPER_DATA_DIR ortam değişkeni tanımlı değil.")
    lock_path = Path(data_dir).resolve() / "testssl-protocols.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)

    lock_fd = None
    try:
        lock_fd = os.open(str(lock_path), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            st = os.fstat(lock_fd)
            if not stat.S_ISREG(st.st_mode):
                raise RuntimeError("Kilit dosyası normal bir dosya değil.")
        except OSError:
            os.close(lock_fd)
            raise RuntimeError("Kilit dosyası doğrulanamadı.")

        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as e:
            if e.errno == 11:  # EAGAIN
                raise RuntimeError("Başka bir testssl taraması sürüyor.")
            raise RuntimeError("Başka bir testssl taraması sürüyor.")

    except Exception as e:
        if lock_fd is not None:
            os.close(lock_fd)
        raise RuntimeError("Başka bir testssl taraması sürüyor.")

    try:
        # Validate binary
        binary = os.environ.get("SNIPER_TESTSSL_BINARY")
        if not binary:
            raise RuntimeError("testssl ikilisi yapılandırılmamış.")
        binary_path = Path(binary)
        if not binary_path.is_absolute():
            raise RuntimeError("testssl ikili yolu mutlak olmalı.")
        resolved = binary_path.resolve()
        home = Path.home().resolve()
        if not str(resolved).startswith(str(home) + os.sep) and resolved != home:
            raise RuntimeError("testssl ikilisi $HOME altında çözümlenmeli.")
        if binary_path.is_symlink() or not binary_path.is_file():
            raise RuntimeError("testssl ikilisi normal bir dosya olmalı.")
        if not os.access(binary_path, os.X_OK):
            raise RuntimeError("testssl ikilisi çalıştırılabilir olmalı.")

        # Validate hash — mandatory per contract
        expected_sha256 = os.environ.get("SNIPER_TESTSSL_SHA256")
        if expected_sha256 is None:
            raise RuntimeError("testssl ikilisi SHA256 değeri yapılandırılmamış.")
        if len(expected_sha256) != 64 or not all(c in "0123456789abcdef" for c in expected_sha256):
            raise RuntimeError("testssl ikilisi SHA256 değeri 64 karakterlik küçük harfli onaltılık olmalı.")
        actual = hashlib.sha256(binary_path.read_bytes()).hexdigest()
        if actual != expected_sha256:
            raise RuntimeError("testssl ikilisi hash değeri uyuşmuyor.")

        # Create private temporary directory
        with tempfile.TemporaryDirectory(prefix="sniper_testssl_") as tmpdir:
            tmpdir_path = Path(tmpdir)
            json_path = tmpdir_path / "report.json"

            # Build command — ensure --jsonfile comes BEFORE target
            cmd = [
                str(binary_path),
                "--quiet",
                "--color", "0",
                "--warnings", "batch",
                "--nodns", "none",
                "--connect-timeout", "2",
                "--openssl-timeout", "2",
                "--full" if full else "--protocols",
                "--jsonfile", str(json_path),
                f"{target_ip}:{target_port}"
            ]

            # Run bounded subprocess in new process group
            start = time.monotonic()
            proc = None
            try:
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    stdin=subprocess.DEVNULL,
                    start_new_session=True,
                )
                try:
                    exit_code = proc.wait(timeout=180 if full else 45)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(os.getpgid(proc.pid), 9)  # SIGKILL
                    except ProcessLookupError:
                        pass
                    # Wait for the direct child to avoid zombies
                    try:
                        proc.wait(timeout=2)
                    except (subprocess.TimeoutExpired, ProcessLookupError):
                        pass
                    raise RuntimeError("testssl çalıştırması zaman aşımına uğradı.")
            except OSError:
                raise RuntimeError("testssl çalıştırması başarısız oldu.")

            elapsed = time.monotonic() - start

            if exit_code != 0 and not full:
                raise RuntimeError("testssl çalıştırması başarısız oldu.")

            # Validate output
            if not json_path.exists():
                raise RuntimeError("testssl rapor dosyası üretilmedi.")
            if json_path.stat().st_size > 1_000_000:
                raise RuntimeError("testssl raporu 1 MB sınırını aşıyor.")

            data = json_path.read_bytes()
            try:
                report = json.loads(data.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                raise RuntimeError("testssl raporu geçerli JSON değil.")

            if not isinstance(report, list):
                raise RuntimeError("testssl raporu bir JSON dizisi olmalı.")
            if len(report) > MAX_RECORDS:
                raise RuntimeError(f"Çok fazla kayıt (en fazla {MAX_RECORDS}).")
            if full and exit_code != 0 and not report:
                raise RuntimeError("testssl tam taraması sonuç döndürmedi.")

            # Run parser — catch ValueError and convert to RuntimeError for generic HTTP502
            try:
                result = parse_testssl_json_summary(report)
            except ValueError as ve:
                raise RuntimeError("testssl raporu doğrulamadan geçemedi.") from ve

            # Enrich with runtime
            result["format"] = "testssl-loopback-full-v1" if full else "testssl-loopback-v1"
            if full:
                # testssl.sh sums individual check return codes. A nonzero code can
                # coexist with a useful validated report; label it as partial.
                result["scan_complete"] = exit_code == 0
                result["scanner_exit_code"] = exit_code
            result["elapsed_seconds"] = round(elapsed, 3)
            return result

    finally:
        if lock_fd is not None:
            os.close(lock_fd)
