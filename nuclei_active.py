"""Run one pinned Nuclei template against an explicitly selected loopback service."""

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
import time
from pathlib import Path

from tool_report_nuclei import MAX_FINDINGS, parse_nuclei_jsonl_summary


TEMPLATE = Path(__file__).resolve().parent / "templates/nuclei/local-powered-by.yaml"
TEMPLATE_SHA256 = "a7c444042e0322e314ceb900d0a5cfae6f72bc6c40e80f7626a36ecdf0d466e0"
TARGET_PATTERN = re.compile(r"127\.0\.0\.1:([1-9][0-9]{0,4})\Z")
MAX_REPORT_BYTES = 1_000_000


class NucleiUnavailable(RuntimeError):
    pass


class NucleiBusy(RuntimeError):
    pass


class NucleiExecutionError(RuntimeError):
    pass


def _trusted_binary() -> Path:
    configured = os.environ.get("SNIPER_NUCLEI_BINARY", "")
    digest = os.environ.get("SNIPER_NUCLEI_SHA256", "")
    path = Path(configured)
    if not path.is_absolute() or path.is_symlink() or not path.is_file() or not os.access(path, os.X_OK):
        raise NucleiUnavailable("Nuclei ikilisi kullanılamıyor.")
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise NucleiUnavailable("Nuclei ikilisi hash değeri kullanılamıyor.")
    try:
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        raise NucleiUnavailable("Nuclei ikilisi okunamıyor.") from exc
    if actual != digest:
        raise NucleiUnavailable("Nuclei ikilisi hash değeri uyuşmuyor.")
    return path


def _trusted_template() -> Path:
    if TEMPLATE.is_symlink() or not TEMPLATE.is_file():
        raise NucleiUnavailable("Nuclei şablonu kullanılamıyor.")
    try:
        actual = hashlib.sha256(TEMPLATE.read_bytes()).hexdigest()
    except OSError as exc:
        raise NucleiUnavailable("Nuclei şablonu okunamıyor.") from exc
    if actual != TEMPLATE_SHA256:
        raise NucleiUnavailable("Nuclei şablonu hash değeri uyuşmuyor.")
    return TEMPLATE


def _lock_scan() -> int:
    data_dir = os.environ.get("SNIPER_DATA_DIR")
    if not data_dir:
        raise NucleiUnavailable("Nuclei veri dizini kullanılamıyor.")
    path = Path(data_dir) / "nuclei-loopback.lock"
    fd = None
    try:
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            raise OSError("geçersiz kilit")
    except OSError as exc:
        if fd is not None:
            os.close(fd)
        raise NucleiUnavailable("Nuclei kilidi kullanılamıyor.") from exc
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        os.close(fd)
        raise NucleiBusy("Bir Nuclei taraması zaten sürüyor.") from exc
    return fd


def run_nuclei_loopback(target: str) -> dict:
    match = TARGET_PATTERN.fullmatch(target)
    if match is None or int(match.group(1)) > 65535:
        raise ValueError("target 1..65535 aralığında portla 127.0.0.1:<port> olmalı")
    binary = _trusted_binary()
    template = _trusted_template()
    fd = _lock_scan()
    try:
        with tempfile.TemporaryDirectory(prefix="sniper_nuclei_") as temp:
            report = Path(temp) / "report.jsonl"
            environment = {
                "HOME": temp,
                "TMPDIR": temp,
                "PATH": "/usr/bin:/bin",
                "LANG": "C.UTF-8",
                "NO_PROXY": "127.0.0.1,localhost",
                "no_proxy": "127.0.0.1,localhost",
            }
            command = [
                str(binary), "-u", f"http://{target}", "-t", str(template),
                "-jsonl", "-silent", "-nc", "-or", "-ot", "-duc", "-ni", "-dr",
                "-no-stdin", "-pt", "http", "-c", "1", "-rl", "1", "-timeout", "2",
                "-retries", "0",
            ]
            started = time.monotonic()
            try:
                with report.open("wb") as output:
                    process = subprocess.Popen(
                        command,
                        stdin=subprocess.DEVNULL,
                        stdout=output,
                        stderr=subprocess.DEVNULL,
                        env=environment,
                        start_new_session=True,
                    )
                    try:
                        exit_code = process.wait(timeout=30)
                    except subprocess.TimeoutExpired as exc:
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        process.wait(timeout=3)
                        raise NucleiExecutionError("Nuclei çalıştırması zaman aşımına uğradı.") from exc
            except OSError as exc:
                raise NucleiExecutionError("Nuclei çalıştırması başarısız oldu.") from exc
            if exit_code:
                raise NucleiExecutionError("Nuclei çalıştırması başarısız oldu.")
            if report.stat().st_size > MAX_REPORT_BYTES:
                raise NucleiExecutionError("Nuclei çıktısı boyut sınırını aştı.")
            try:
                lines = [line for line in report.read_text(encoding="utf-8").splitlines() if line.strip()]
                if len(lines) > MAX_FINDINGS:
                    raise ValueError("çok fazla kayıt")
                records = [json.loads(line) for line in lines]
                if any(row.get("template-id") != "sniper-local-powered-by-v1" for row in records):
                    raise ValueError("beklenmeyen şablon")
                summary = parse_nuclei_jsonl_summary(records)
            except (UnicodeError, json.JSONDecodeError, ValueError, AttributeError) as exc:
                raise NucleiExecutionError("Nuclei çıktısı doğrulamadan geçemedi.") from exc
            summary["format"] = "nuclei-loopback-v1"
            summary["profile"] = "local-powered-by-v1"
            summary["elapsed_seconds"] = round(time.monotonic() - started, 3)
            return summary
    finally:
        os.close(fd)
