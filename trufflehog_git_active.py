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
from project_tree import ProjectTree, ProjectTreeError
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


_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC


def _entry_stat(directory_fd: int, name: str) -> os.stat_result | None:
    try:
        return os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise GitHistoryInvalid("Git meta verisi güvenli biçimde incelenemedi.") from exc


def _open_directory_at(directory_fd: int, name: str, expected: os.stat_result | None = None) -> int:
    try:
        child_fd = os.open(name, _DIR_FLAGS, dir_fd=directory_fd)
        opened = os.fstat(child_fd)
        if not stat.S_ISDIR(opened.st_mode) or (
            expected is not None
            and (
                opened.st_dev,
                opened.st_ino,
                opened.st_mtime_ns,
                opened.st_ctime_ns,
            ) != (
                expected.st_dev,
                expected.st_ino,
                expected.st_mtime_ns,
                expected.st_ctime_ns,
            )
        ):
            os.close(child_fd)
            raise GitHistoryInvalid("Git dizini hazırlama sırasında değişti.")
        return child_fd
    except GitHistoryInvalid:
        raise
    except OSError as exc:
        raise GitHistoryInvalid("Git meta verisi güvenli biçimde açılamadı.") from exc


def _relative_entry_stat(directory_fd: int, parts: tuple[str, ...]) -> os.stat_result | None:
    current_fd = os.dup(directory_fd)
    try:
        for part in parts[:-1]:
            expected = _entry_stat(current_fd, part)
            if expected is None:
                return None
            if not stat.S_ISDIR(expected.st_mode):
                raise GitHistoryInvalid("Git meta verisi güvensiz bir girdi içeriyor.")
            next_fd = _open_directory_at(current_fd, part, expected)
            os.close(current_fd)
            current_fd = next_fd
        return _entry_stat(current_fd, parts[-1])
    finally:
        os.close(current_fd)


def _required_git_tree(root: Path) -> ProjectTree:
    tree = ProjectTree(root / ".git")
    try:
        tree.open()
        root_fd = tree.fileno()
        for name in ("HEAD", "index"):
            info = _entry_stat(root_fd, name)
            if info is None or not stat.S_ISREG(info.st_mode):
                raise GitHistoryInvalid("Gerekli Git meta verisi normal bir dosya değil.")
        for name in ("objects", "refs"):
            info = _entry_stat(root_fd, name)
            if info is None or not stat.S_ISDIR(info.st_mode):
                raise GitHistoryInvalid("Gerekli Git meta verisi bir dizin değil.")
        if _entry_stat(root_fd, "commondir") is not None or _relative_entry_stat(
            root_fd, ("objects", "info", "alternates")
        ) is not None:
            raise GitHistoryInvalid("Harici Git meta verisi desteklenmiyor.")
        packed = _entry_stat(root_fd, "packed-refs")
        if packed is not None and not stat.S_ISREG(packed.st_mode):
            raise GitHistoryInvalid("Paketlenmiş Git başvuruları normal dosya olmalı.")
        return tree
    except (ProjectTreeError, GitHistoryInvalid) as exc:
        tree.close()
        if isinstance(exc, GitHistoryInvalid):
            raise
        raise GitHistoryInvalid("Normal bir yerel Git çalışma ağacı gerekli.") from exc


def _required_git_dir(root: Path) -> ProjectTree:
    """Compatibility entry point shared with the Gitleaks history runner.

    The historical name is retained, but the returned object is now an open,
    descriptor-pinned view rather than a pathname that could be reopened.
    """
    return _required_git_tree(root)


def _check_head(git_tree: ProjectTree) -> None:
    try:
        raw = git_tree.read_bytes("HEAD", 257, allow_empty=True)
    except ProjectTreeError as exc:
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


def _copy_regular_at(
    source_parent_fd: int,
    name: str,
    dest: Path,
    budget: dict[str, int],
    expected: os.stat_result | None = None,
) -> None:
    try:
        before = expected or os.stat(name, dir_fd=source_parent_fd, follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode):
            raise GitHistoryInvalid("Git meta verisi normal olmayan bir girdi içeriyor.")
        if before.st_size > MAX_FILE_BYTES or budget["bytes"] + before.st_size > MAX_TOTAL_BYTES:
            raise GitHistoryInvalid("Git meta verisi bayt sınırını aşıyor.")
        if budget["files"] >= MAX_FILES:
            raise GitHistoryInvalid("Git meta verisi dosya sınırını aşıyor.")
        source_fd = os.open(name, _FILE_FLAGS, dir_fd=source_parent_fd)
        try:
            opened = os.fstat(source_fd)
            if (
                opened.st_dev,
                opened.st_ino,
                opened.st_size,
                opened.st_mtime_ns,
                opened.st_ctime_ns,
            ) != (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            ) or not stat.S_ISREG(opened.st_mode):
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


def _copy_tree_at(
    source_parent_fd: int,
    name: str,
    dest: Path,
    budget: dict[str, int],
    depth: int = 0,
    logical_prefix: str = "",
) -> None:
    if depth > 32:
        raise GitHistoryInvalid("Git meta verisi çok derin iç içe.")
    try:
        before = os.stat(name, dir_fd=source_parent_fd, follow_symlinks=False)
        if not stat.S_ISDIR(before.st_mode):
            raise GitHistoryInvalid("Git meta verisi güvensiz bir girdi içeriyor.")
        directory_fd = _open_directory_at(source_parent_fd, name, before)
        try:
            with os.scandir(directory_fd) as entries:
                for entry in entries:
                    if entry.name in ("", ".", "..") or "/" in entry.name or "\x00" in entry.name:
                        raise GitHistoryInvalid("Git meta verisi geçersiz bir girdi içeriyor.")
                    budget["entries"] += 1
                    if budget["entries"] > MAX_ENTRIES:
                        raise GitHistoryInvalid("Git meta verisi çok fazla girdi içeriyor.")
                    st = entry.stat(follow_symlinks=False)
                    target = dest / entry.name
                    logical = f"{logical_prefix}/{entry.name}" if logical_prefix else entry.name
                    if logical == "objects/info/alternates":
                        raise GitHistoryInvalid("Harici Git meta verisi desteklenmiyor.")
                    if stat.S_ISDIR(st.st_mode):
                        target.mkdir(mode=0o700, parents=True, exist_ok=True)
                        _copy_tree_at(directory_fd, entry.name, target, budget, depth + 1, logical)
                    elif stat.S_ISREG(st.st_mode):
                        _copy_regular_at(directory_fd, entry.name, target, budget, st)
                    else:
                        raise GitHistoryInvalid("Git meta verisi güvensiz bir girdi içeriyor.")
            after = os.fstat(directory_fd)
            if (after.st_dev, after.st_ino, after.st_mtime_ns, after.st_ctime_ns) != (
                before.st_dev, before.st_ino, before.st_mtime_ns, before.st_ctime_ns
            ):
                raise GitHistoryInvalid("Git dizini hazırlama sırasında değişti.")
        finally:
            os.close(directory_fd)
    except OSError as exc:
        raise GitHistoryInvalid("Git meta verisi listelenemedi.") from exc


def _stage_pinned(
    git_tree: ProjectTree,
    git_bin: Path,
) -> tuple[Path, tempfile.TemporaryDirectory[str], dict[str, str]]:
    temporary = tempfile.TemporaryDirectory(prefix="sniper_git_history_")
    source_tree: ProjectTree | None = None
    try:
        source_tree = git_tree.duplicate()
        root_fd = source_tree.fileno()
        before_dir = os.fstat(root_fd)
        if _entry_stat(root_fd, "commondir") is not None or _relative_entry_stat(
            root_fd, ("objects", "info", "alternates")
        ) is not None:
            raise GitHistoryInvalid("Harici Git meta verisi desteklenmiyor.")
        _check_head(source_tree)
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
        _copy_regular_at(root_fd, "HEAD", dest_git / "HEAD", budget)
        _copy_regular_at(root_fd, "index", dest_git / "index", budget)
        packed = _entry_stat(root_fd, "packed-refs")
        if packed is not None:
            _copy_regular_at(root_fd, "packed-refs", dest_git / "packed-refs", budget, packed)
        for name in ("refs", "objects"):
            _copy_tree_at(root_fd, name, dest_git / name, budget, logical_prefix=name)
        if os.path.lexists(dest_git / "objects/info/alternates") or os.path.lexists(dest_git / "commondir"):
            raise GitHistoryInvalid("Harici Git meta verisi desteklenmiyor.")
        after_dir = os.fstat(root_fd)
        if (after_dir.st_dev, after_dir.st_ino, after_dir.st_mtime_ns, after_dir.st_ctime_ns) != (
            before_dir.st_dev, before_dir.st_ino, before_dir.st_mtime_ns, before_dir.st_ctime_ns
        ):
            raise GitHistoryInvalid("Git dizini hazırlama sırasında değişti.")
        source_tree.close()
        source_tree = None
        return staged_root, temporary, env
    except BaseException:
        if source_tree is not None:
            source_tree.close()
        temporary.cleanup()
        raise


def _stage(
    git_tree_or_root: ProjectTree | Path,
    git_tree_or_bin: ProjectTree | Path,
    git_bin: Path | None = None,
) -> tuple[Path, tempfile.TemporaryDirectory[str], dict[str, str]]:
    """Stage pinned metadata; accept the former three-argument Gitleaks call.

    In compatibility form ``(root, git_tree, git_bin)``, ``root`` is ignored
    and the transferred tree handle is always closed here.
    """
    if git_bin is None:
        if not isinstance(git_tree_or_root, ProjectTree):
            raise GitHistoryInvalid("Git meta verisi sabit bir dizin tanımlayıcısı gerektiriyor.")
        return _stage_pinned(git_tree_or_root, Path(git_tree_or_bin))
    if not isinstance(git_tree_or_bin, ProjectTree):
        raise GitHistoryInvalid("Git meta verisi sabit bir dizin tanımlayıcısı gerektiriyor.")
    try:
        return _stage_pinned(git_tree_or_bin, git_bin)
    finally:
        git_tree_or_bin.close()


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
    git_tree = _required_git_tree(root)
    try:
        _check_head(git_tree)
        binary_value = os.environ.get("SNIPER_TRUFFLEHOG_BINARY")
        if not binary_value or not _regular_executable(Path(binary_value)):
            raise GitHistoryUnavailable("TruffleHog ikilisi kullanılamıyor.")
        try:
            trufflehog = open_pinned("trufflehog", binary_value)
        except VerificationError as exc:
            raise GitHistoryUnavailable(str(exc)) from exc
        with trufflehog:
            return _run_verified(git_tree, trufflehog)
    finally:
        git_tree.close()


def _run_verified(git_tree: ProjectTree, trufflehog: VerifiedExecutable) -> dict[str, Any]:
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
        staged_root, temporary, env = _stage(git_tree, git_bin)
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
