"""Bounded, offline execution for Sniper-generated optional fuzz harnesses.

The optional engines are never downloaded or inferred from ``PATH``.  An operator
must supply exact local runtime/support paths and SHA-256 pins.  Target and support
bytes are copied into a private snapshot, while the process runs in Sniper's
networkless bubblewrap/seccomp sandbox with wall-clock, CPU, input, run and output
limits.  Missing configuration is a first-class ``runtime_missing/not_run`` result.
"""

from __future__ import annotations

from contextlib import ExitStack
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import resource
import shutil
import stat
import subprocess
import tempfile
import threading
from typing import Any

import process_group_runner
import sandbox_seccomp
import tool_sandbox
from verified_exec import VerificationError, VerifiedExecutable, open_verified_executable


FORMAT = "sniper-fuzz-runtime-execution/1"
MAX_SUPPORT_FILES = 4096
MAX_SUPPORT_BYTES = 64 * 1024 * 1024
MAX_SOURCE_BYTES = 2 * 1024 * 1024
MAX_HARNESS_BYTES = 512 * 1024
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_LOCK = threading.Lock()


class FuzzRuntimeError(ValueError):
    """The requested runtime execution failed closed before engine execution."""


class _RuntimeUnavailable(RuntimeError):
    pass


def _bounds(
    max_runs: object, seed: object, max_input_bytes: object,
    timeout_seconds: object, max_output_bytes: object,
) -> dict[str, int]:
    values = {
        "max_runs": (max_runs, 1, 10_000),
        "seed": (seed, 0, 2_147_483_647),
        "max_input_bytes": (max_input_bytes, 1, 1_048_576),
        "timeout_seconds": (timeout_seconds, 1, 30),
        "max_output_bytes": (max_output_bytes, 1024, 262_144),
    }
    result: dict[str, int] = {}
    for name, (value, minimum, maximum) in values.items():
        if type(value) is not int or not minimum <= value <= maximum:
            raise FuzzRuntimeError(f"{name} {minimum}..{maximum} aralığında tam sayı olmalı.")
        result[name] = value
    return result


def _engine(harness: dict[str, Any]) -> str:
    language = harness.get("language")
    engine = harness.get("fuzz_engine")
    if language == "python" and engine == "atheris":
        return "atheris"
    if language in {"javascript", "typescript"} and engine == "fast-check":
        return "fast-check"
    if language == "java" and harness.get("runtime_requirement") == "jazzer":
        return "jazzer"
    raise FuzzRuntimeError("Yalnız Atheris, fast-check ve Jazzer runtime yürütmesi desteklenir.")


def _missing(engine: str, bounds: dict[str, int]) -> dict[str, Any]:
    return {
        "format": FORMAT,
        "engine": engine,
        "readiness": "runtime_missing",
        "execution": "not_run",
        "reason": "runtime_configuration_incomplete",
        "bounds": bounds,
        "runtime_sha256": None,
        "support_sha256": None,
        "diagnostic": "",
        "output_truncated": False,
    }


def _pin(value: object, label: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise FuzzRuntimeError(f"{label} SHA-256 sabitlemesi 64 küçük onaltılık karakter olmalı.")
    return value


def _safe_project_target(root_value: object, relative_value: object, expected_sha: object) -> tuple[Path, bytes]:
    if not isinstance(root_value, (str, os.PathLike)):
        raise FuzzRuntimeError("project_root mutlak yerel dizin olmalı.")
    root_raw = os.fspath(root_value)
    if not os.path.isabs(root_raw):
        raise FuzzRuntimeError("project_root mutlak yerel dizin olmalı.")
    try:
        root = Path(root_raw).resolve(strict=True)
        root_info = os.stat(root, follow_symlinks=False)
    except OSError as exc:
        raise FuzzRuntimeError("project_root okunamadı.") from exc
    if not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != os.getuid():
        raise FuzzRuntimeError("project_root kullanıcıya ait normal dizin olmalı.")
    if not isinstance(relative_value, str) or not relative_value or "\\" in relative_value or "\x00" in relative_value:
        raise FuzzRuntimeError("Fuzz hedefi güvenli göreli POSIX yolu olmalı.")
    relative = PurePosixPath(relative_value)
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise FuzzRuntimeError("Fuzz hedefi güvenli göreli POSIX yolu olmalı.")
    current = root
    try:
        for part in relative.parts:
            current = current / part
            if stat.S_ISLNK(os.lstat(current).st_mode):
                raise FuzzRuntimeError("Fuzz hedef yolu sembolik bağ içeremez.")
        target = current.resolve(strict=True)
        fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
    except FuzzRuntimeError:
        raise
    except OSError as exc:
        raise FuzzRuntimeError("Fuzz hedef kaynağı açılamadı.") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or not 1 <= info.st_size <= MAX_SOURCE_BYTES:
            raise FuzzRuntimeError("Fuzz hedefi sınırlı, kullanıcıya ait normal dosya olmalı.")
        raw = os.pread(fd, info.st_size, 0)
    finally:
        os.close(fd)
    if len(raw) != info.st_size or b"\x00" in raw:
        raise FuzzRuntimeError("Fuzz hedefi kararlı UTF-8 kaynak olmalı.")
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise FuzzRuntimeError("Fuzz hedefi kararlı UTF-8 kaynak olmalı.") from exc
    if not isinstance(expected_sha, str) or hashlib.sha256(raw).hexdigest() != expected_sha:
        raise FuzzRuntimeError("Fuzz hedefi sentezlenen kaynak SHA-256 değeriyle eşleşmiyor.")
    return target, raw


def _safe_harness(harness: dict[str, Any]) -> tuple[str, bytes]:
    filename = harness.get("harness_filename")
    code = harness.get("harness_code")
    digest = harness.get("harness_sha256")
    if not isinstance(filename, str) or PurePosixPath(filename).name != filename or len(filename) > 160:
        raise FuzzRuntimeError("Harness dosya adı güvenli değil.")
    if not isinstance(code, str):
        raise FuzzRuntimeError("Harness kaynak kodu eksik.")
    raw = code.encode("utf-8")
    if not 1 <= len(raw) <= MAX_HARNESS_BYTES or hashlib.sha256(raw).hexdigest() != digest:
        raise FuzzRuntimeError("Harness SHA-256 veya boyut doğrulaması başarısız.")
    return filename, raw


def _regular_bytes(path_value: object, *, label: str) -> tuple[Path, bytes, str]:
    if not isinstance(path_value, (str, os.PathLike)):
        raise FuzzRuntimeError(f"{label} mutlak yol olmalı.")
    raw_path = os.fspath(path_value)
    if not os.path.isabs(raw_path):
        raise FuzzRuntimeError(f"{label} mutlak yol olmalı.")
    try:
        fd = os.open(raw_path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
    except OSError as exc:
        raise FuzzRuntimeError(f"{label} açılamadı veya sembolik bağ.") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid not in {0, os.getuid()} or info.st_mode & 0o022:
            raise FuzzRuntimeError(f"{label} güvenli normal dosya olmalı.")
        if not 1 <= info.st_size <= MAX_SUPPORT_BYTES:
            raise FuzzRuntimeError(f"{label} boyut sınırını aşıyor.")
        data = os.pread(fd, info.st_size, 0)
    finally:
        os.close(fd)
    if len(data) != info.st_size:
        raise FuzzRuntimeError(f"{label} kararlı okunamadı.")
    return Path(raw_path).resolve(), data, hashlib.sha256(data).hexdigest()


def _snapshot_tree(source_value: object, destination: Path, *, expected_sha: str, label: str) -> str:
    if not isinstance(source_value, (str, os.PathLike)):
        raise FuzzRuntimeError(f"{label} mutlak dizin yolu olmalı.")
    raw_path = os.fspath(source_value)
    if not os.path.isabs(raw_path):
        raise FuzzRuntimeError(f"{label} mutlak dizin yolu olmalı.")
    source = Path(raw_path)
    try:
        info = os.lstat(source)
    except OSError as exc:
        raise FuzzRuntimeError(f"{label} okunamadı.") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or info.st_uid not in {0, os.getuid()} \
            or info.st_mode & 0o022:
        raise FuzzRuntimeError(f"{label} güvenli normal dizin olmalı.")
    records: list[tuple[str, str, int]] = []
    total = 0
    for directory, dirs, files in os.walk(source, topdown=True, followlinks=False):
        base = Path(directory)
        kept: list[str] = []
        for name in sorted(dirs):
            item = base / name
            child = os.lstat(item)
            if stat.S_ISLNK(child.st_mode) or not stat.S_ISDIR(child.st_mode) \
                    or child.st_uid not in {0, os.getuid()} or child.st_mode & 0o022:
                raise FuzzRuntimeError(f"{label} sembolik/özel/yazılabilir dizin içeremez.")
            kept.append(name)
        dirs[:] = kept
        for name in sorted(files):
            item = base / name
            child = os.lstat(item)
            if stat.S_ISLNK(child.st_mode) or not stat.S_ISREG(child.st_mode) \
                    or child.st_uid not in {0, os.getuid()} or child.st_mode & 0o022:
                raise FuzzRuntimeError(f"{label} sembolik/özel/yazılabilir dosya içeremez.")
            if child.st_size > MAX_SUPPORT_BYTES:
                raise FuzzRuntimeError(f"{label} dosya boyut sınırını aşıyor.")
            data = item.read_bytes()
            total += len(data)
            if len(records) >= MAX_SUPPORT_FILES or total > MAX_SUPPORT_BYTES:
                raise FuzzRuntimeError(f"{label} dosya veya toplam boyut sınırını aşıyor.")
            relative = item.relative_to(source).as_posix()
            digest = hashlib.sha256(data).hexdigest()
            records.append((relative, digest, stat.S_IMODE(child.st_mode)))
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            target.write_bytes(data)
            target.chmod(0o500 if child.st_mode & 0o111 else 0o400)
    actual = hashlib.sha256(repr(records).encode("utf-8")).hexdigest()
    if actual != expected_sha:
        raise FuzzRuntimeError(f"{label} SHA-256 sabitlemesi eşleşmiyor.")
    return actual


def support_tree_sha256(path: str | os.PathLike[str]) -> str:
    """Return the canonical digest accepted for an operator-supplied module tree."""
    source = Path(path)
    records: list[tuple[str, str, int]] = []
    total = 0
    try:
        info = os.lstat(source)
    except OSError as exc:
        raise FuzzRuntimeError("Modül dizini okunamadı.") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or info.st_uid not in {0, os.getuid()} \
            or info.st_mode & 0o022:
        raise FuzzRuntimeError("Modül dizini güvenli normal dizin olmalı.")
    for directory, dirs, files in os.walk(source, topdown=True, followlinks=False):
        base = Path(directory)
        dirs[:] = sorted(dirs)
        for name in dirs:
            child = os.lstat(base / name)
            if stat.S_ISLNK(child.st_mode) or not stat.S_ISDIR(child.st_mode) \
                    or child.st_uid not in {0, os.getuid()} or child.st_mode & 0o022:
                raise FuzzRuntimeError("Modül dizini sembolik/özel/yazılabilir girdi içeremez.")
        for name in sorted(files):
            item = base / name
            child = os.lstat(item)
            if stat.S_ISLNK(child.st_mode) or not stat.S_ISREG(child.st_mode) \
                    or child.st_uid not in {0, os.getuid()} or child.st_mode & 0o022:
                raise FuzzRuntimeError("Modül dizini sembolik/özel/yazılabilir girdi içeremez.")
            data = item.read_bytes()
            total += len(data)
            if len(records) >= MAX_SUPPORT_FILES or total > MAX_SUPPORT_BYTES:
                raise FuzzRuntimeError("Modül dizini dosya veya toplam boyut sınırını aşıyor.")
            records.append((item.relative_to(source).as_posix(), hashlib.sha256(data).hexdigest(),
                            stat.S_IMODE(child.st_mode)))
    return hashlib.sha256(repr(records).encode("utf-8")).hexdigest()


def _open_runtime(stack: ExitStack, path: object, pin: object, label: str) -> VerifiedExecutable:
    digest = _pin(pin, label)
    try:
        return stack.enter_context(open_verified_executable(path, {digest: "operator-supplied"}, label=label))
    except VerificationError as exc:
        raise FuzzRuntimeError(f"{label} SHA-256/yol doğrulaması başarısız ({exc.reason}).") from exc


def _safe_runtime_root(root_value: object, executable: VerifiedExecutable, mount: str) -> tuple[list[str], str]:
    path = Path(executable.path).resolve()
    if path == Path("/usr") or Path("/usr") in path.parents:
        return ["--ro-bind", executable.argv0, path.as_posix()], path.as_posix()
    if not isinstance(root_value, (str, os.PathLike)) or not os.path.isabs(os.fspath(root_value)):
        raise FuzzRuntimeError("/usr dışı runtime için mutlak runtime_root zorunlu.")
    root = Path(os.fspath(root_value))
    try:
        info = os.lstat(root)
        resolved = root.resolve(strict=True)
        relative = path.relative_to(resolved)
    except (OSError, ValueError) as exc:
        raise FuzzRuntimeError("runtime_root runtime ikilisini içeren güvenli dizin olmalı.") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or info.st_uid not in {0, os.getuid()} \
            or info.st_mode & 0o022:
        raise FuzzRuntimeError("runtime_root güvenli normal dizin olmalı.")
    mapped = f"{mount}/{relative.as_posix()}"
    return ["--ro-bind", str(resolved), mount, "--ro-bind", executable.argv0, mapped], mapped


def _limit(pid: int, *, timeout: int, output_bytes: int) -> None:
    try:
        resource.prlimit(pid, resource.RLIMIT_CPU, (timeout + 2, timeout + 2))
        resource.prlimit(pid, resource.RLIMIT_CORE, (0, 0))
        resource.prlimit(pid, resource.RLIMIT_FSIZE, (output_bytes, output_bytes))
        resource.prlimit(pid, resource.RLIMIT_NOFILE, (64, 64))
    except (ValueError, OSError, AttributeError):
        pass


def _data_fd(data: bytes) -> int:
    read_fd, write_fd = os.pipe()
    try:
        os.write(write_fd, data)
    finally:
        os.close(write_fd)
    return read_fd


def _run_stage(
    work: Path, name: str, binds: list[str], command: list[str], pass_fds: tuple[int, ...],
    *, timeout: int, output_bytes: int,
) -> tuple[int, str, bool, bool]:
    bwrap = None
    seccomp_fd = -1
    stdout_fd = stderr_fd = -1
    timed_out = False
    try:
        bwrap = tool_sandbox.open_bwrap()
        seccomp_fd = _data_fd(sandbox_seccomp.build_filter())
        stdout_path = work / f"{name}.stdout"
        stderr_path = work / f"{name}.stderr"
        stdout_fd = os.open(stdout_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        stderr_fd = os.open(stderr_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        argv = tool_sandbox.bwrap_argv(bwrap.fd, binds, seccomp_fd=seccomp_fd) + command
        try:
            with subprocess.Popen(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=stdout_fd,
                stderr=stderr_fd,
                pass_fds=tuple(sorted({bwrap.fd, seccomp_fd, *pass_fds})),
                close_fds=True,
                start_new_session=True,
                env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
            ) as process:
                _limit(process.pid, timeout=timeout, output_bytes=output_bytes)
                try:
                    code = process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    timed_out = True
                    process_group_runner.kill_process_group(process)
                    process.wait(timeout=2)
                    code = -9
        except OSError as exc:
            raise _RuntimeUnavailable("Fuzz runtime yalıtımda başlatılamadı.") from exc
        os.close(stdout_fd)
        os.close(stderr_fd)
        stdout_fd = stderr_fd = -1
        stderr_raw = stderr_path.read_bytes()
        stdout_raw = stdout_path.read_bytes()
        combined = stderr_raw + (b"\n" if stderr_raw and stdout_raw else b"") + stdout_raw
        # RLIMIT_FSIZE can stop a writer exactly at the cap; equality is therefore
        # conservatively reported as truncated rather than as complete output.
        truncated = len(combined) >= output_bytes
        diagnostic = combined[:output_bytes].decode("utf-8", "replace")
        if "bwrap:" in diagnostic or "Creating new namespace failed" in diagnostic or "RTM_NEWADDR" in diagnostic:
            raise _RuntimeUnavailable("Fuzz runtime yalıtımı kullanılamıyor.")
        return int(code), diagnostic, truncated, timed_out
    except (tool_sandbox.SandboxUnavailable, sandbox_seccomp.SeccompUnsupported, OSError) as exc:
        raise _RuntimeUnavailable("Fuzz runtime yalıtımı kullanılamıyor.") from exc
    finally:
        for fd in (stdout_fd, stderr_fd, seccomp_fd):
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass
        if bwrap is not None:
            bwrap.close()


def execute(
    harness: dict[str, Any],
    *,
    project_root: object,
    confirm_local: object,
    runtime_path: object = None,
    runtime_sha256: object = None,
    support_path: object = None,
    support_sha256: object = None,
    compiler_path: object = None,
    compiler_sha256: object = None,
    runtime_root: object = None,
    max_runs: object = 1,
    seed: object = 1,
    max_input_bytes: object = 4096,
    timeout_seconds: object = 5,
    max_output_bytes: object = 65_536,
) -> dict[str, Any]:
    """Execute one generated optional-engine harness under fixed local bounds."""
    if confirm_local is not True:
        raise FuzzRuntimeError("Fuzz runtime yürütmesi için confirm_local tam olarak true olmalı.")
    bounds = _bounds(max_runs, seed, max_input_bytes, timeout_seconds, max_output_bytes)
    engine = _engine(harness)
    required = [runtime_path, runtime_sha256, support_path, support_sha256]
    if engine == "jazzer":
        required += [compiler_path, compiler_sha256]
    if any(value is None or value == "" for value in required):
        return _missing(engine, bounds)

    target_path, target_raw = _safe_project_target(
        project_root, harness.get("target_file"), harness.get("source_sha256")
    )
    harness_name, harness_raw = _safe_harness(harness)
    support_pin = _pin(support_sha256, f"{engine} desteği")

    if not _LOCK.acquire(blocking=False):
        raise FuzzRuntimeError("Başka bir fuzz runtime yürütmesi sürüyor.")
    work: Path | None = None
    try:
        work = Path(tempfile.mkdtemp(prefix="sniper-fuzz-runtime-"))
        os.chmod(work, 0o700)
        project = work / "project"
        project.mkdir(mode=0o700)
        relative = PurePosixPath(str(harness["target_file"]))
        copied_target = project.joinpath(*relative.parts)
        copied_target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        copied_target.write_bytes(target_raw)
        copied_target.chmod(0o400)
        copied_harness = project / harness_name
        copied_harness.write_bytes(harness_raw)
        copied_harness.chmod(0o400)

        support_actual = ""
        if engine == "jazzer":
            support_source, support_raw, support_actual = _regular_bytes(support_path, label="Jazzer JAR")
            if support_source.suffix.casefold() != ".jar" or support_actual != support_pin:
                raise FuzzRuntimeError("Jazzer JAR SHA-256 sabitlemesi eşleşmiyor.")
            (project / "jazzer.jar").write_bytes(support_raw)
            (project / "jazzer.jar").chmod(0o400)
        elif engine == "atheris":
            source = Path(os.fspath(support_path))
            modules = project / "modules"
            modules.mkdir(mode=0o700)
            if source.is_dir():
                if source.name != "atheris":
                    raise FuzzRuntimeError("Atheris modül dizininin adı atheris olmalı.")
                target_module = modules / "atheris"
                target_module.mkdir(mode=0o700)
                support_actual = _snapshot_tree(
                    source, target_module, expected_sha=support_pin, label="Atheris modülü"
                )
            else:
                source_path, module_raw, support_actual = _regular_bytes(source, label="Atheris modülü")
                if not source_path.name.startswith("atheris") or support_actual != support_pin:
                    raise FuzzRuntimeError("Atheris modül SHA-256 sabitlemesi eşleşmiyor.")
                (modules / source_path.name).write_bytes(module_raw)
                (modules / source_path.name).chmod(0o400)
        else:
            source = Path(os.fspath(support_path))
            if source.name != "node_modules" or not (source / "fast-check").is_dir():
                raise FuzzRuntimeError("fast-check desteği tam node_modules dizini olmalı.")
            node_modules = project / "node_modules"
            node_modules.mkdir(mode=0o700)
            support_actual = _snapshot_tree(
                source, node_modules, expected_sha=support_pin, label="fast-check node_modules"
            )

        with ExitStack() as stack:
            runtime = _open_runtime(stack, runtime_path, runtime_sha256, f"{engine} runtime")
            runtime_binds, runtime_cmd = _safe_runtime_root(runtime_root, runtime, "/runtime")
            compiler = None
            compiler_binds: list[str] = []
            compiler_cmd = ""
            if engine == "jazzer":
                compiler = _open_runtime(stack, compiler_path, compiler_sha256, "Javac")
                compiler_binds, compiler_cmd = _safe_runtime_root(runtime_root, compiler, "/runtime")
                if runtime_binds[:3] == compiler_binds[:3] and runtime_binds[:1] == ["--ro-bind"]:
                    # One custom JDK root, two independently pinned executable overlays.
                    compiler_binds = compiler_binds[3:]
            common_binds = [
                "--ro-bind", str(project), "/work",
                *runtime_binds,
                *compiler_binds,
            ]
            pass_fds = tuple(item.fd for item in (runtime, compiler) if item is not None)
            if engine == "atheris":
                binds = [
                    *common_binds,
                    "--setenv", "PYTHONPATH", "/work/modules",
                    "--setenv", "PYTHONNOUSERSITE", "1",
                    "--setenv", "PYTHONDONTWRITEBYTECODE", "1",
                ]
                command = [
                    runtime_cmd, f"/work/{harness_name}", f"-runs={bounds['max_runs']}",
                    f"-seed={bounds['seed']}", f"-max_len={bounds['max_input_bytes']}",
                    f"-max_total_time={bounds['timeout_seconds']}",
                ]
                stages = [("fuzz", binds, command)]
            elif engine == "fast-check":
                binds = [
                    *common_binds,
                    "--setenv", "SNIPER_FUZZ_RUNS", str(bounds["max_runs"]),
                    "--setenv", "SNIPER_FUZZ_SEED", str(bounds["seed"]),
                    "--setenv", "SNIPER_FUZZ_MAX_INPUT_BYTES", str(bounds["max_input_bytes"]),
                    "--setenv", "NODE_NO_WARNINGS", "1",
                ]
                stages = [("fuzz", binds, [runtime_cmd, f"/work/{harness_name}"])]
            else:
                classes = work / "classes"
                classes.mkdir(mode=0o700)
                java_binds = [*common_binds, "--bind", str(classes), "/out"]
                target_inside = f"/work/{relative.as_posix()}"
                stages = [
                    ("compile", java_binds, [compiler_cmd, "-d", "/out", target_inside, f"/work/{harness_name}"]),
                    (
                        "fuzz", java_binds,
                        [
                            runtime_cmd, "-jar", "/work/jazzer.jar", "--cp=/out",
                            f"--target_class={harness['harness_class']}", f"-runs={bounds['max_runs']}",
                            f"-seed={bounds['seed']}", f"-max_len={bounds['max_input_bytes']}",
                            f"-max_total_time={bounds['timeout_seconds']}",
                        ],
                    ),
                ]

            diagnostics: list[str] = []
            truncated = False
            last_code = 0
            execution = "completed"
            reason = "bounded_run_completed"
            for stage_name, binds, command in stages:
                try:
                    code, diagnostic, was_truncated, timed_out = _run_stage(
                        work,
                        stage_name,
                        binds,
                        command,
                        pass_fds,
                        timeout=bounds["timeout_seconds"],
                        output_bytes=bounds["max_output_bytes"],
                    )
                except _RuntimeUnavailable:
                    return {
                        "format": FORMAT,
                        "engine": engine,
                        "readiness": "sandbox_unavailable",
                        "execution": "not_run",
                        "reason": "sandbox_unavailable",
                        "bounds": bounds,
                        "runtime_sha256": runtime.sha256,
                        "support_sha256": support_actual,
                        "diagnostic": "",
                        "output_truncated": False,
                    }
                diagnostics.append(diagnostic)
                truncated = truncated or was_truncated
                last_code = code
                if timed_out:
                    execution, reason = "timed_out", "wall_clock_limit_exceeded"
                    break
                if code != 0:
                    execution = "failed"
                    reason = "compile_failed" if stage_name == "compile" else "engine_nonzero_exit"
                    break

            diagnostic = "\n".join(item for item in diagnostics if item)
            if len(diagnostic.encode("utf-8")) > bounds["max_output_bytes"]:
                diagnostic = diagnostic.encode("utf-8")[:bounds["max_output_bytes"]].decode("utf-8", "replace")
                truncated = True
            return {
                "format": FORMAT,
                "engine": engine,
                "readiness": "ready",
                "execution": execution,
                "reason": reason,
                "exit_code": last_code,
                "bounds": bounds,
                "runtime_sha256": runtime.sha256,
                "support_sha256": support_actual,
                "target_sha256": hashlib.sha256(target_raw).hexdigest(),
                "harness_sha256": hashlib.sha256(harness_raw).hexdigest(),
                "diagnostic": diagnostic,
                "output_truncated": truncated,
                "network": "isolated",
                "process_group_cleanup": True,
            }
    finally:
        if work is not None:
            shutil.rmtree(work, ignore_errors=True)
        _LOCK.release()


BUILTIN_DETERMINISTIC_FUZZ_FORMAT = "sniper-builtin-deterministic-fuzz-proof/1"
BUILTIN_DETERMINISTIC_ENGINE = "sniper-deterministic-mutator-v1"

_BOUNDARY_CORPUS: tuple[str, ...] = (
    "",
    "\x00",
    "\x00\x00\x00\x00",
    "%s%n%x%d",
    "%s%s%s%s%n%n",
    "../../etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "/../../../../etc/shadow",
    "'; DROP TABLE users; --",
    '" OR 1=1 --',
    "; id; uname -a #",
    "$(id)",
    "`id`",
    '{"unclosed": [1, 2,',
    '{"__proto__": {"admin": true}, "count": -1}',
    '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>',
    "<script>alert(1)</script><unclosed>",
    "\xff\xfe\xfd\x80\x81",
    "\xf0\x9f\x92\xa9" * 8,
    "0",
    "-1",
    "2147483647",
    "-2147483648",
    "99999999999999999999999999999999999999",
    "NaN",
    "Infinity",
    "-Infinity",
    "\r\n\r\n",
    "A" * 256,
    "A" * 4096,
)


def _extract_source_literals(target_source: str) -> list[str]:
    literals: list[str] = []
    seen: set[str] = set()

    def _add(val: str) -> None:
        if val not in seen and len(literals) < 32:
            seen.add(val)
            literals.append(val)

    # Priority 1: string literals around comparisons or prefix/suffix checks
    comp_patterns = (
        r"""(?:==|!=|===|!==|\bin\b)\s*['"]([^'"]{1,128})['"]""",
        r"""['"]([^'"]{1,128})['"]\s*(?:==|!=|===|!==)""",
        r"""\.(?:startswith|endswith|startsWith|endsWith|includes|find|index|split)\s*\(\s*['"]([^'"]{1,128})['"]""",
    )
    for pat in comp_patterns:
        for match in re.finditer(pat, target_source):
            _add(match.group(1))

    # Priority 2: any general short string literals in the source
    for match in re.finditer(r"""['"]([^'"\n]{1,64})['"]""", target_source):
        _add(match.group(1))

    # Add pairwise/augmented combinations of extracted literals (e.g. magic prefix + trigger suffix)
    base_literals = list(literals)
    for lit in base_literals[:8]:
        _add(lit + "\x00")
        _add(lit + "0")
        _add(lit + "-1")
        _add(lit + "../../")
        _add(lit + "%s%n")
        _add(lit + "A" * 32)
        for other in base_literals[:8]:
            if lit != other:
                _add(lit + other)
                _add(f"{lit}:{other}")
                _add(f"{lit}/{other}")
    return literals


def _resolve_target_symbol(target_source: str, target_symbol: str, language: str) -> str:
    if isinstance(target_symbol, str) and target_symbol.strip():
        return target_symbol.strip()
    lang = (language or "python").strip().lower()
    if lang == "python":
        matches = [m.group(1) for m in re.finditer(r"^\s*def\s+([A-Za-z_]\w*)\s*\(", target_source, re.MULTILINE)]
        for name in matches:
            if not name.startswith("_"):
                return name
        if matches:
            return matches[0]
    else:
        patterns = (
            r"\bfunction\s+([A-Za-z_$]\w*)\s*\(",
            r"\b(?:const|let|var)\s+([A-Za-z_$]\w*)\s*=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$]\w*)\s*=>",
        )
        for pat in patterns:
            m = re.search(pat, target_source)
            if m:
                return m.group(1)
    return "__main__"


def _generate_deterministic_corpus(target_source: str, *, max_runs: int, seed: int) -> list[str]:
    corpus: list[str] = []
    seen: set[str] = set()

    def _push(item: str) -> None:
        if len(corpus) < max_runs and item not in seen:
            seen.add(item)
            corpus.append(item)

    extracted = _extract_source_literals(target_source)
    for item in extracted:
        _push(item)
    for item in _BOUNDARY_CORPUS:
        _push(item)

    base_pool = list(corpus) if corpus else [""]
    counter = 0
    while len(corpus) < max_runs:
        digest = hashlib.sha256(f"{seed}:{counter}".encode("utf-8")).digest()
        counter += 1
        base = base_pool[digest[0] % len(base_pool)]
        op = digest[1] % 6
        if op == 0:
            raw_bytes = bytearray(base.encode("utf-8", errors="surrogateescape"))
            if raw_bytes:
                idx = digest[2] % len(raw_bytes)
                raw_bytes[idx] ^= (digest[3] or 1)
                mutated = raw_bytes.decode("utf-8", errors="replace")
            else:
                mutated = digest[:8].decode("latin1")
        elif op == 1:
            other = base_pool[digest[2] % len(base_pool)]
            split_a = digest[3] % (len(base) + 1)
            split_b = digest[4] % (len(other) + 1)
            mutated = base[:split_a] + other[split_b:]
        elif op == 2:
            repeat = 2 + (digest[2] % 16)
            mutated = (base or _BOUNDARY_CORPUS[digest[3] % len(_BOUNDARY_CORPUS)]) * repeat
        elif op == 3:
            token = _BOUNDARY_CORPUS[digest[2] % len(_BOUNDARY_CORPUS)]
            pos = digest[3] % (len(base) + 1)
            mutated = base[:pos] + token + base[pos:]
        elif op == 4:
            mutated = f'{{"{base[:32]}": "{digest[2:6].hex()}", "value": {digest[6] - 128}}}'
        else:
            mutated = digest[: 1 + (digest[2] % 31)].decode("latin1")

        if len(corpus) < max_runs:
            if mutated not in seen:
                seen.add(mutated)
                corpus.append(mutated)
            elif counter > max_runs * 4:
                corpus.append(f"{mutated}#{counter}")
    return corpus[:max_runs]


def execute_builtin_deterministic_fuzzer(
    target_source: str,
    *,
    target_symbol: str = "",
    language: str = "python",
    max_runs: int = 64,
    seed: int = 1337,
    timeout_seconds: int = 5,
) -> dict[str, Any]:
    """Execute a built-in deterministic SHA-256 mutation fuzzer in an isolated subprocess."""
    import json
    import sys

    if not isinstance(target_source, str) or not target_source.strip():
        raise FuzzRuntimeError("target_source boş olmayan metin olmalı.")
    lang = (language or "python").strip().lower()
    if lang not in {"python", "javascript", "typescript", "js", "ts"}:
        raise FuzzRuntimeError(f"Desteklenmeyen dil: {language}")
    norm_lang = "python" if lang == "python" else "javascript"
    max_runs = max(1, min(int(max_runs), 10_000))
    seed = int(seed)
    timeout_seconds = max(1, min(int(timeout_seconds), 30))

    resolved_symbol = _resolve_target_symbol(target_source, target_symbol, norm_lang)
    corpus = _generate_deterministic_corpus(target_source, max_runs=max_runs, seed=seed)

    work = Path(tempfile.mkdtemp(prefix="sniper-det-fuzz-"))
    os.chmod(work, 0o700)
    try:
        corpus_path = work / "corpus.json"
        corpus_path.write_text(json.dumps(corpus, ensure_ascii=True), encoding="utf-8")

        if norm_lang == "python":
            target_path = work / "target_mod.py"
            target_path.write_text(target_source, encoding="utf-8")
            driver_path = work / "driver.py"
            driver_code = (
                "import hashlib, json, sys\n"
                "corpus = json.loads(open(sys.argv[1], 'r', encoding='utf-8').read())\n"
                "symbol = sys.argv[2]\n"
                "source = open(sys.argv[3], 'r', encoding='utf-8').read()\n"
                "ns = {'__name__': '__fuzz_target__'}\n"
                "compiled = compile(source, sys.argv[3], 'exec')\n"
                "exec(compiled, ns)\n"
                "fn = ns.get(symbol) if symbol != '__main__' else None\n"
                "runs = 0\n"
                "for item in corpus:\n"
                "    runs += 1\n"
                "    try:\n"
                "        if callable(fn):\n"
                "            try:\n"
                "                fn(item)\n"
                "            except TypeError as exc:\n"
                "                msg = str(exc)\n"
                "                if 'bytes' in msg or 'buffer' in msg:\n"
                "                    fn(item.encode('utf-8', errors='surrogateescape'))\n"
                "                else:\n"
                "                    raise\n"
                "        else:\n"
                "            local_ns = dict(ns)\n"
                "            local_ns.update({'data': item, 'payload': item, 'inp': item, 'raw': item})\n"
                "            exec(compiled, local_ns)\n"
                "    except BaseException as exc:\n"
                "        raw_bytes = item.encode('utf-8', errors='surrogateescape')\n"
                "        print(json.dumps({\n"
                "            'runs_executed': runs,\n"
                "            'crash_reproduced': True,\n"
                "            'crashing_input_sha256': hashlib.sha256(raw_bytes).hexdigest(),\n"
                "            'exception_type': type(exc).__name__,\n"
                "        }))\n"
                "        sys.exit(0)\n"
                "print(json.dumps({\n"
                "    'runs_executed': runs,\n"
                "    'crash_reproduced': False,\n"
                "    'crashing_input_sha256': None,\n"
                "    'exception_type': None,\n"
                "}))\n"
            )
            driver_path.write_text(driver_code, encoding="utf-8")
            cmd = [sys.executable, "-I", str(driver_path), str(corpus_path), resolved_symbol, str(target_path)]
        else:
            target_path = work / "target_mod.js"
            target_path.write_text(target_source, encoding="utf-8")
            driver_path = work / "driver.js"
            driver_code = (
                "const fs = require('fs');\n"
                "const crypto = require('crypto');\n"
                "const vm = require('vm');\n"
                "const corpus = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));\n"
                "const symbol = process.argv[3];\n"
                "const source = fs.readFileSync(process.argv[4], 'utf8');\n"
                "const sandbox = { Buffer, JSON, Math, parseInt, parseFloat, Error, TypeError, RangeError, SyntaxError, exports: {}, module: { exports: {} } };\n"
                "vm.createContext(sandbox);\n"
                "vm.runInContext(source, sandbox, { timeout: 1000 });\n"
                "const fn = sandbox[symbol] || (sandbox.module && sandbox.module.exports && sandbox.module.exports[symbol]) || (typeof sandbox.module.exports === 'function' ? sandbox.module.exports : null);\n"
                "let runs = 0;\n"
                "for (const item of corpus) {\n"
                "  runs += 1;\n"
                "  try {\n"
                "    if (typeof fn === 'function') {\n"
                "      fn(item);\n"
                "    } else {\n"
                "      sandbox.data = item; sandbox.payload = item; sandbox.input = item;\n"
                "      vm.runInContext(source, sandbox, { timeout: 500 });\n"
                "    }\n"
                "  } catch (err) {\n"
                "    const sha = crypto.createHash('sha256').update(Buffer.from(item, 'utf8')).digest('hex');\n"
                "    console.log(JSON.stringify({\n"
                "      runs_executed: runs,\n"
                "      crash_reproduced: true,\n"
                "      crashing_input_sha256: sha,\n"
                "      exception_type: (err && err.name) ? String(err.name) : 'Error'\n"
                "    }));\n"
                "    process.exit(0);\n"
                "  }\n"
                "}\n"
                "console.log(JSON.stringify({\n"
                "  runs_executed: runs,\n"
                "  crash_reproduced: false,\n"
                "  crashing_input_sha256: null,\n"
                "  exception_type: null\n"
                "}));\n"
            )
            driver_path.write_text(driver_code, encoding="utf-8")
            node_bin = shutil.which("node") or "/usr/bin/node"
            cmd = [node_bin, str(driver_path), str(corpus_path), resolved_symbol, str(target_path)]

        runs_executed = 0
        crash_reproduced = False
        crashing_input_sha256: str | None = None
        exception_type: str | None = None

        try:
            proc = subprocess.run(
                cmd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout_seconds,
                cwd=str(work),
                env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1"},
                check=False,
            )
            stdout_text = proc.stdout.decode("utf-8", errors="replace").strip()
            lines = [line.strip() for line in stdout_text.splitlines() if line.strip().startswith("{")]
            if lines:
                payload = json.loads(lines[-1])
                runs_executed = int(payload.get("runs_executed") or 0)
                crash_reproduced = bool(payload.get("crash_reproduced"))
                crashing_input_sha256 = payload.get("crashing_input_sha256")
                exception_type = payload.get("exception_type")
            elif proc.returncode != 0:
                runs_executed = 1
                crash_reproduced = True
                first_bytes = corpus[0].encode("utf-8", errors="surrogateescape")
                crashing_input_sha256 = hashlib.sha256(first_bytes).hexdigest()
                exception_type = f"SubprocessExit_{proc.returncode}"
        except subprocess.TimeoutExpired:
            runs_executed = max(1, len(corpus))
            crash_reproduced = True
            first_bytes = corpus[0].encode("utf-8", errors="surrogateescape")
            crashing_input_sha256 = hashlib.sha256(first_bytes).hexdigest()
            exception_type = "TimeoutExpired"

        return {
            "format": BUILTIN_DETERMINISTIC_FUZZ_FORMAT,
            "engine": BUILTIN_DETERMINISTIC_ENGINE,
            "language": language,
            "target_symbol": resolved_symbol,
            "runs_executed": runs_executed,
            "seed": seed,
            "crash_reproduced": crash_reproduced,
            "crashing_input_sha256": crashing_input_sha256,
            "exception_type": exception_type,
            "status": "crash_reproduced" if crash_reproduced else "completed_no_crash",
        }
    finally:
        shutil.rmtree(work, ignore_errors=True)

