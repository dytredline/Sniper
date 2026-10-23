"""Bounded, offline Gitleaks scan of a local Git repository's commit history.

The source worktree is never passed to Gitleaks. Only regular Git metadata is
copied into an empty, private repository; source config, hooks, and alternates
are excluded. No raw report is returned or retained.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import stat
import subprocess
import time
from typing import Any

from project_analyzer import ProjectRejected, validate_project_path
from tool_report_gitleaks import parse_gitleaks_json_summary
from tool_pins import open_pinned
from verified_exec import VerificationError
from trufflehog_git_active import (
    GitHistoryInvalid,
    GitHistoryExecution,
    _required_git_dir,
    _stage,
)

MAX_PROCESS_OUTPUT_BYTES = 2_000_000
MAX_REPORT_BYTES = 2_000_000
PROCESS_TIMEOUT_SECONDS = 45.0


class GitleaksGitInvalid(ValueError):
    pass


class GitleaksGitUnavailable(RuntimeError):
    pass


class GitleaksGitBusy(RuntimeError):
    pass


class GitleaksGitExecution(RuntimeError):
    pass


def _executable(raw: str | None, label: str) -> Path:
    if not raw:
        raise GitleaksGitUnavailable(f"{label} yapılandırılmamış.")
    path = Path(raw)
    try:
        st = os.lstat(path)
    except OSError as exc:
        raise GitleaksGitUnavailable(f"{label} kullanılamıyor.") from exc
    if not path.is_absolute() or not stat.S_ISREG(st.st_mode) or not os.access(path, os.X_OK):
        raise GitleaksGitUnavailable(f"{label} kullanılamıyor.")
    return path


def _locked_data_dir() -> tuple[int, Path]:
    configured = os.environ.get("SNIPER_DATA_DIR")
    if not configured:
        raise GitleaksGitUnavailable("Gitleaks veri dizini yapılandırılmamış.")
    data_dir = Path(configured).resolve()
    if not data_dir.is_dir():
        raise GitleaksGitUnavailable("Gitleaks veri dizini kullanılamıyor.")
    fd: int | None = None
    try:
        fd = os.open(data_dir / "gitleaks.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise GitleaksGitUnavailable("Gitleaks kilidi kullanılamıyor.")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise GitleaksGitBusy("Başka bir Gitleaks taraması sürüyor.") from exc
        return fd, data_dir
    except (OSError, GitleaksGitUnavailable, GitleaksGitBusy) as exc:
        if fd is not None:
            os.close(fd)
        if isinstance(exc, OSError):
            raise GitleaksGitUnavailable("Gitleaks kilidi kullanılamıyor.") from exc
        raise


def _run_bounded(command: list[str], env: dict[str, str], cwd: Path, pass_fds: tuple[int, ...] = ()) -> int:
    try:
        process = subprocess.Popen(
            command, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=True,
            pass_fds=pass_fds,
        )
    except OSError as exc:
        raise GitleaksGitExecution("Gitleaks Git geçmişi çalıştırması başarısız oldu.") from exc
    selector = selectors.DefaultSelector()
    received = 0
    completed = False
    deadline = time.monotonic() + PROCESS_TIMEOUT_SECONDS
    try:
        assert process.stdout is not None
        selector.register(process.stdout, selectors.EVENT_READ)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise GitleaksGitExecution("Gitleaks Git geçmişi çalıştırması zaman aşımına uğradı.")
            ready = selector.select(min(remaining, 0.5))
            if not ready:
                continue
            chunk = os.read(process.stdout.fileno(), 65_536)
            if not chunk:
                break
            received += len(chunk)
            if received > MAX_PROCESS_OUTPUT_BYTES:
                raise GitleaksGitExecution("Gitleaks Git geçmişi çıktısı sınırı aştı.")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise GitleaksGitExecution("Gitleaks Git geçmişi çalıştırması zaman aşımına uğradı.")
        status = process.wait(timeout=remaining)
        completed = True
        return status
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GitleaksGitExecution("Gitleaks Git geçmişi çalıştırması başarısız oldu veya zaman aşımına uğradı.") from exc
    finally:
        selector.close()
        if process.stdout is not None:
            process.stdout.close()
        if not completed:
            # The parent may have exited while a child still holds stdout.
            # Kill the entire process group before reaping the parent.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()


def _read_report(path: Path) -> list[dict[str, Any]]:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_REPORT_BYTES:
                raise GitleaksGitExecution("Gitleaks Git geçmişi raporu kullanılamıyor veya çok büyük.")
            raw = bytearray()
            while len(raw) <= MAX_REPORT_BYTES:
                chunk = os.read(fd, min(65_536, MAX_REPORT_BYTES + 1 - len(raw)))
                if not chunk:
                    break
                raw.extend(chunk)
            if len(raw) > MAX_REPORT_BYTES:
                raise GitleaksGitExecution("Gitleaks Git geçmişi raporu çok büyük.")
        finally:
            os.close(fd)
        report = json.loads(raw.decode("utf-8", errors="strict"))
        if not isinstance(report, list):
            raise ValueError("liste değil")
        return report
    except (OSError, UnicodeError, ValueError) as exc:
        raise GitleaksGitExecution("Gitleaks Git geçmişi raporu geçersiz.") from exc


def run_local_gitleaks_git_history(project_path: str) -> dict[str, Any]:
    """Scan committed local history and return only parser-compatible counts.

    The API caller must separately enforce explicit opt-in. This function also
    rejects paths outside HOME, Git links, alternates and unsafe metadata.
    """
    try:
        root = validate_project_path(project_path, allowed_roots=(Path.home().resolve(),))
        git_dir = _required_git_dir(root)
    except (ProjectRejected, GitHistoryInvalid, ValueError) as exc:
        raise GitleaksGitInvalid("HOME altında normal bir yerel Git deposu gerekli.") from exc
    try:
        gitleaks = open_pinned("gitleaks")
    except VerificationError as exc:
        raise GitleaksGitUnavailable(str(exc)) from exc
    try:
        git = _executable("/usr/bin/git", "Git binary")
        lock_fd, _ = _locked_data_dir()
    except BaseException:
        gitleaks.close()
        raise
    try:
        try:
            staged, temporary, env = _stage(root, git_dir, git)
        except GitHistoryInvalid as exc:
            raise GitleaksGitInvalid("Güvensiz yerel Git meta verisi.") from exc
        except GitHistoryExecution as exc:
            raise GitleaksGitExecution("Güvenli Git geçmişi hazırlığı başarısız oldu.") from exc
        with temporary:
            env = {
                **env,
                "GIT_TERMINAL_PROMPT": "0",
                "GIT_LFS_SKIP_SMUDGE": "1",
                "GIT_OPTIONAL_LOCKS": "0",
            }
            report_path = Path(temporary.name) / "report.json"
            command = [
                gitleaks.argv0, "git", str(staged),
                "--report-format", "json", "--report-path", str(report_path),
                "--no-banner", "--redact=100", "--timeout", "20",
                "--max-target-megabytes", "1",
            ]
            status = _run_bounded(command, env, staged, (gitleaks.fd,))
            if status not in (0, 1):
                raise GitleaksGitExecution("Gitleaks Git geçmişi çalıştırması başarısız oldu.")
            report = _read_report(report_path)
            try:
                summary = parse_gitleaks_json_summary(report)
            except ValueError as exc:
                raise GitleaksGitExecution("Gitleaks Git geçmişi raporu geçersiz.") from exc
            count = summary["total_findings"]
            if (status == 0 and count) or (status == 1 and not count):
                raise GitleaksGitExecution("Gitleaks Git geçmişi çıkış kodu ile rapor uyuşmuyor.")
            canonical = json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            return {
                "format": summary["format"],
                "profile": "git-history-local-v1",
                "total_findings": count,
                "rules_triggered": summary["rules_triggered"],
                "files_affected": summary["files_affected"],
                "report_sha256": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
            }
    finally:
        gitleaks.close()
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)
