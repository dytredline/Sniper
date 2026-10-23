"""Bounded, offline TruffleHog scan of a local Git repository's commit history."""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import tempfile
import time
from typing import Any

from project_analyzer import validate_project_path
from tool_report_trufflehog import parse_trufflehog_json_summary
from tool_pins import open_pinned
from verified_exec import VerificationError, VerifiedExecutable


class GitHistoryInvalid(ValueError):
    pass


class GitHistoryUnavailable(RuntimeError):
    pass


class GitHistoryBusy(RuntimeError):
    pass


class GitHistoryExecution(RuntimeError):
    pass


MAX_FILES = 5_000
MAX_ENTRIES = 10_000
MAX_TOTAL_BYTES = 100_000_000
MAX_FILE_BYTES = 25_000_000
MAX_OUTPUT_BYTES = 2_000_000
MAX_RECORDS = 500
MAX_LINE_BYTES = 64_000
TIMEOUT_SECONDS = 90.0


def _regular_executable(path: Path) -> bool:
    try:
        st = os.lstat(path)
    except OSError:
        return False
    return path.is_absolute() and stat.S_ISREG(st.st_mode) and os.access(path, os.X_OK)


def _safe_child_env(root: Path, template: Path) -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": str(root),
        "XDG_CONFIG_HOME": str(root / "xdg"),
        "GIT_ALLOW_PROTOCOL": "file",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TEMPLATE_DIR": str(template),
    }


def _required_git_dir(root: Path) -> Path:
    git_dir = root / ".git"
    try:
        st = os.lstat(git_dir)
        if not stat.S_ISDIR(st.st_mode):
            raise GitHistoryInvalid("Normal bir yerel .git dizini gerekli.")
        for rel in ("HEAD", "index"):
            f = git_dir / rel
            if not stat.S_ISREG(os.lstat(f).st_mode):
                raise GitHistoryInvalid("Gerekli Git meta verisi normal bir dosya değil.")
        for rel in ("objects", "refs"):
            d = git_dir / rel
            if not stat.S_ISDIR(os.lstat(d).st_mode):
                raise GitHistoryInvalid("Gerekli Git meta verisi bir dizin değil.")
        if os.path.lexists(git_dir / "commondir") or os.path.lexists(git_dir / "objects/info/alternates"):
            raise GitHistoryInvalid("Harici Git meta verisi desteklenmiyor.")
        packed = git_dir / "packed-refs"
        if os.path.lexists(packed) and not stat.S_ISREG(os.lstat(packed).st_mode):
            raise GitHistoryInvalid("Paketlenmiş Git başvuruları normal dosya olmalı.")
    except (OSError, ValueError) as exc:
        if isinstance(exc, GitHistoryInvalid):
            raise
        raise GitHistoryInvalid("Normal bir yerel Git çalışma ağacı gerekli.") from exc
    return git_dir


def _check_head(git_dir: Path) -> None:
    try:
        fd = os.open(git_dir / "HEAD", os.O_RDONLY | os.O_NOFOLLOW)
        try:
            raw = os.read(fd, 257)
        finally:
            os.close(fd)
    except OSError as exc:
        raise GitHistoryInvalid("Git HEAD güvenli biçimde okunamadı.") from exc
    line = raw.rstrip(b"\n")
    if len(raw) > 256 or raw.count(b"\n") > 1 or not (
        re.fullmatch(rb"[0-9a-fA-F]{40}(?:\n)?", raw)
        or re.fullmatch(rb"[0-9a-fA-F]{64}(?:\n)?", raw)
        or (
            re.fullmatch(rb"ref: refs/[A-Za-z0-9._/-]+(?:\n)?", raw)
            and b".." not in line and b"//" not in line and not line.endswith(b"/")
        )
    ):
        raise GitHistoryInvalid("Güvensiz Git HEAD meta verisi.")


def _copy_regular(src: Path, dest: Path, budget: dict[str, int]) -> None:
    try:
        before = os.lstat(src)
        if not stat.S_ISREG(before.st_mode):
            raise GitHistoryInvalid("Git meta verisi normal olmayan bir girdi içeriyor.")
        if before.st_size > MAX_FILE_BYTES or budget["bytes"] + before.st_size > MAX_TOTAL_BYTES:
            raise GitHistoryInvalid("Git meta verisi bayt sınırını aşıyor.")
        if budget["files"] >= MAX_FILES:
            raise GitHistoryInvalid("Git meta verisi dosya sınırını aşıyor.")
        source_fd = os.open(src, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            opened = os.fstat(source_fd)
            if (opened.st_dev, opened.st_ino, opened.st_size) != (before.st_dev, before.st_ino, before.st_size) or not stat.S_ISREG(opened.st_mode):
                raise GitHistoryInvalid("Git meta verisi hazırlama sırasında değişti.")
            dest.parent.mkdir(parents=True, exist_ok=True)
            target_fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
            try:
                remaining = before.st_size
                while remaining:
                    chunk = os.read(source_fd, min(65_536, remaining))
                    if not chunk:
                        raise GitHistoryInvalid("Git meta verisi hazırlama sırasında değişti.")
                    view = memoryview(chunk)
                    while view:
                        written = os.write(target_fd, view)
                        if written <= 0:
                            raise GitHistoryInvalid("Git meta verisi güvenli biçimde hazırlanamadı.")
                        view = view[written:]
                    remaining -= len(chunk)
                if os.read(source_fd, 1):
                    raise GitHistoryInvalid("Git meta verisi hazırlama sırasında değişti.")
            finally:
                os.close(target_fd)
            after = os.fstat(source_fd)
            if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) != (
                opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns
            ):
                raise GitHistoryInvalid("Git meta verisi hazırlama sırasında değişti.")
        finally:
            os.close(source_fd)
    except OSError as exc:
        raise GitHistoryInvalid("Git meta verisi güvenli biçimde hazırlanamadı.") from exc
    budget["files"] += 1
    budget["bytes"] += before.st_size


def _copy_tree(src: Path, dest: Path, budget: dict[str, int], depth: int = 0) -> None:
    if depth > 32:
        raise GitHistoryInvalid("Git meta verisi çok derin iç içe.")
    try:
        directory_fd = os.open(src, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            # Resolve each child below an open directory handle, not a mutable path.
            pinned = Path(f"/proc/self/fd/{directory_fd}")
            with os.scandir(directory_fd) as entries:
                for entry in entries:
                    budget["entries"] += 1
                    if budget["entries"] > MAX_ENTRIES:
                        raise GitHistoryInvalid("Git meta verisi çok fazla girdi içeriyor.")
                    st = entry.stat(follow_symlinks=False)
                    target = dest / entry.name
                    source = pinned / entry.name
                    if stat.S_ISDIR(st.st_mode):
                        target.mkdir(mode=0o700, parents=True, exist_ok=True)
                        _copy_tree(source, target, budget, depth + 1)
                    elif stat.S_ISREG(st.st_mode):
                        _copy_regular(source, target, budget)
                    else:
                        raise GitHistoryInvalid("Git meta verisi güvensiz bir girdi içeriyor.")
        finally:
            os.close(directory_fd)
    except OSError as exc:
        raise GitHistoryInvalid("Git meta verisi listelenemedi.") from exc


def _stage(root: Path, git_dir: Path, git_bin: Path) -> tuple[Path, tempfile.TemporaryDirectory[str], dict[str, str]]:
    temporary = tempfile.TemporaryDirectory(prefix="sniper_git_history_")
    git_fd: int | None = None
    try:
        before_dir = os.lstat(git_dir)
        git_fd = os.open(git_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        opened_dir = os.fstat(git_fd)
        if (opened_dir.st_dev, opened_dir.st_ino) != (before_dir.st_dev, before_dir.st_ino):
            raise GitHistoryInvalid("Git dizini hazırlama sırasında değişti.")
        pinned_git = Path(f"/proc/self/fd/{git_fd}")
        if os.path.lexists(pinned_git / "commondir") or os.path.lexists(pinned_git / "objects/info/alternates"):
            raise GitHistoryInvalid("Harici Git meta verisi desteklenmiyor.")
        _check_head(pinned_git)
        parent = Path(temporary.name)
        staged_root = parent / "repository"
        template = parent / "empty_template"
        template.mkdir(mode=0o700)
        env = _safe_child_env(parent, template)
        try:
            init = subprocess.run(
                [str(git_bin), "init", "--quiet", f"--template={template}", str(staged_root)],
                env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, timeout=10, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise GitHistoryExecution("Güvenli Git hazırlığı başarısız oldu.") from exc
        if init.returncode:
            raise GitHistoryExecution("Güvenli Git hazırlığı başarısız oldu.")
        dest_git = staged_root / ".git"
        budget = {"entries": 0, "files": 0, "bytes": 0}
        _copy_regular(pinned_git / "HEAD", dest_git / "HEAD", budget)
        _copy_regular(pinned_git / "index", dest_git / "index", budget)
        packed = pinned_git / "packed-refs"
        if os.path.lexists(packed):
            _copy_regular(packed, dest_git / "packed-refs", budget)
        for name in ("refs", "objects"):
            _copy_tree(pinned_git / name, dest_git / name, budget)
        if os.path.lexists(dest_git / "objects/info/alternates") or os.path.lexists(dest_git / "commondir"):
            raise GitHistoryInvalid("Harici Git meta verisi desteklenmiyor.")
        os.close(git_fd)
        git_fd = None
        return staged_root, temporary, env
    except BaseException:
        if git_fd is not None:
            os.close(git_fd)
        temporary.cleanup()
        raise


def _kill_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait()


def _bounded_stdout(command: list[str], env: dict[str, str], cwd: Path, pass_fds: tuple[int, ...] = ()) -> bytes:
    try:
        process = subprocess.Popen(
            command, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=True,
            pass_fds=pass_fds,
        )
    except OSError as exc:
        raise GitHistoryExecution("TruffleHog başlatılamadı.") from exc
    output = bytearray()
    selector = selectors.DefaultSelector()
    deadline = time.monotonic() + TIMEOUT_SECONDS
    try:
        assert process.stdout is not None
        selector.register(process.stdout, selectors.EVENT_READ)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise GitHistoryExecution("TruffleHog çalıştırması zaman aşımına uğradı.")
            ready = selector.select(min(remaining, 1.0))
            if not ready:
                continue
            chunk = os.read(process.stdout.fileno(), 65_536)
            if not chunk:
                break
            output.extend(chunk)
            if len(output) > MAX_OUTPUT_BYTES:
                raise GitHistoryExecution("TruffleHog çıktısı sınırı aştı.")
        remaining = deadline - time.monotonic()
        if remaining <= 0 or process.wait(timeout=remaining) != 0:
            raise GitHistoryExecution("TruffleHog çalıştırması başarısız oldu veya zaman aşımına uğradı.")
        return bytes(output)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GitHistoryExecution("TruffleHog çalıştırması başarısız oldu veya zaman aşımına uğradı.") from exc
    finally:
        selector.close()
        if process.stdout is not None:
            process.stdout.close()
        _kill_group(process)


def _summarize(raw: bytes) -> dict[str, Any]:
    try:
        text = raw.decode("utf-8", errors="strict")
        lines = text.splitlines() if text.strip() else []
        if len(lines) > MAX_RECORDS:
            raise ValueError("Çok fazla kayıt")
        records: list[dict[str, Any]] = []
        for line in lines:
            if not line.strip() or len(line.encode("utf-8")) > MAX_LINE_BYTES:
                raise ValueError("Geçersiz JSONL satırı")
            record = json.loads(line)
            if not isinstance(record, dict):
                raise ValueError("Geçersiz JSONL kaydı")
            records.append(record)
        result = parse_trufflehog_json_summary(records)
    except (UnicodeDecodeError, ValueError, TypeError) as exc:
        raise GitHistoryExecution("TruffleHog raporu geçersizdi.") from exc
    result["profile"] = "local-git-history-no-verification-v1"
    canonical = json.dumps(records, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    result["report_sha256"] = hashlib.sha256(canonical.encode()).hexdigest()
    return result


def run_local_trufflehog_git_history(project_path: str) -> dict[str, Any]:
    root = validate_project_path(project_path, allowed_roots=(Path.home().resolve(),))
    git_dir = _required_git_dir(root)
    _check_head(git_dir)
    binary_value = os.environ.get("SNIPER_TRUFFLEHOG_BINARY")
    if not binary_value or not _regular_executable(Path(binary_value)):
        raise GitHistoryUnavailable("TruffleHog ikilisi kullanılamıyor.")
    try:
        trufflehog = open_pinned("trufflehog", binary_value)
    except VerificationError as exc:
        raise GitHistoryUnavailable(str(exc)) from exc
    with trufflehog:
        return _run_verified(root, git_dir, trufflehog)


def _run_verified(root: Path, git_dir: Path, trufflehog: VerifiedExecutable) -> dict[str, Any]:
    git_bin = Path("/usr/bin/git")
    if not _regular_executable(git_bin):
        raise GitHistoryUnavailable("Git ikilisi kullanılamıyor.")
    data_dir = os.environ.get("SNIPER_DATA_DIR")
    if not data_dir:
        raise GitHistoryUnavailable("Sniper veri dizini kullanılamıyor.")
    lock_path = Path(data_dir).resolve() / "trufflehog.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        if not stat.S_ISREG(os.fstat(lock_fd).st_mode):
            os.close(lock_fd)
            raise GitHistoryUnavailable("TruffleHog kilidi kullanılamıyor.")
    except OSError as exc:
        raise GitHistoryUnavailable("TruffleHog kilidi kullanılamıyor.") from exc
    try:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise GitHistoryBusy("TruffleHog meşgul.") from exc
        staged_root, temporary, env = _stage(root, git_dir, git_bin)
        try:
            argv = [
                trufflehog.argv0, "git", staged_root.as_uri(),
                "--no-update", "--no-verification", "--results=unverified",
                "--json", "--concurrency=1",
            ]
            return _summarize(_bounded_stdout(argv, env, staged_root, (trufflehog.fd,)))
        finally:
            temporary.cleanup()
    finally:
        os.close(lock_fd)
