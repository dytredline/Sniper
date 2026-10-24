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


def _open_trusted_binary() -> tuple[Path, int]:
    """Open and verify the exact executable inode that the child will inherit."""
    configured = os.environ.get("SNIPER_NUCLEI_BINARY", "")
    digest = os.environ.get("SNIPER_NUCLEI_SHA256", "")
    path = Path(configured)
    if not path.is_absolute() or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise NucleiUnavailable("Nuclei ikilisi kullanılamıyor.")
    binary_fd: int | None = None
    try:
        binary_fd = os.open(
            path,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
        )
        info = os.fstat(binary_fd)
        if not stat.S_ISREG(info.st_mode) or not info.st_mode & 0o111:
            raise OSError("geçersiz Nuclei ikilisi")
        with os.fdopen(os.dup(binary_fd), "rb") as stream:
            actual = hashlib.file_digest(stream, "sha256").hexdigest()
        os.lseek(binary_fd, 0, os.SEEK_SET)
    except OSError as exc:
        if binary_fd is not None:
            os.close(binary_fd)
        raise NucleiUnavailable("Nuclei ikilisi okunamıyor.") from exc
    if actual != digest:
        os.close(binary_fd)
        raise NucleiUnavailable("Nuclei ikilisi hash değeri uyuşmuyor.")
    return path, binary_fd


def _trusted_binary() -> Path:
    """Compatibility readiness probe; execution uses the still-open descriptor."""
    path, binary_fd = _open_trusted_binary()
    os.close(binary_fd)
    return path


def _open_trusted_template() -> tuple[Path, int]:
    """Open and verify the exact template inode that the child will inherit."""
    template_fd: int | None = None
    try:
        template_fd = os.open(
            TEMPLATE,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
        )
        info = os.fstat(template_fd)
        if not stat.S_ISREG(info.st_mode):
            raise OSError("geçersiz Nuclei şablonu")
        with os.fdopen(os.dup(template_fd), "rb") as stream:
            actual = hashlib.file_digest(stream, "sha256").hexdigest()
        os.lseek(template_fd, 0, os.SEEK_SET)
    except OSError as exc:
        if template_fd is not None:
            os.close(template_fd)
        raise NucleiUnavailable("Nuclei şablonu okunamıyor.") from exc
    if actual != TEMPLATE_SHA256:
        os.close(template_fd)
        raise NucleiUnavailable("Nuclei şablonu hash değeri uyuşmuyor.")
    return TEMPLATE, template_fd


def _trusted_template() -> Path:
    """Compatibility readiness probe; execution uses the still-open descriptor."""
    path, template_fd = _open_trusted_template()
    os.close(template_fd)
    return path


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
    if match is None:
        raise ValueError("target 1..65535 aralığında portla 127.0.0.1:<port> olmalı")
    port = int(match.group(1))
    if port > 65535:
        raise ValueError("target 1..65535 aralığında portla 127.0.0.1:<port> olmalı")
    loopback_url = "http://127.0.0.1:" + str(port)
    _binary, binary_fd = _open_trusted_binary()
    template_fd: int | None = None
    try:
        _template, template_fd = _open_trusted_template()
        fd = _lock_scan()
        try:
            with tempfile.TemporaryDirectory(prefix="sniper_nuclei_") as temp:
                report = Path(temp) / "report.jsonl"
                # Nuclei filters -t inputs by filename extension.  A bare
                # /proc/self/fd/<n> is therefore ignored even though its
                # contents are valid YAML.  Keep the verified descriptor as
                # the source, but give the child a private .yaml pathname.
                template_link = Path(temp) / "local-powered-by.yaml"
                template_link.symlink_to(f"/proc/self/fd/{template_fd}")
                environment = {
                    "HOME": temp,
                    "TMPDIR": temp,
                    "PATH": "/usr/bin:/bin",
                    "LANG": "C.UTF-8",
                    "NO_PROXY": "127.0.0.1,localhost",
                    "no_proxy": "127.0.0.1,localhost",
                }
                command = [
                    f"/proc/self/fd/{binary_fd}", "-u", loopback_url,
                    "-t", str(template_link),
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
                            pass_fds=(binary_fd, template_fd),
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
    finally:
        if template_fd is not None:
            os.close(template_fd)
        os.close(binary_fd)
