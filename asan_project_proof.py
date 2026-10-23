"""Önceden derlenmiş, sabit kaynak veya compile-database ASan ELF için ağsız çalışma zamanı kanıtı."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import tempfile
import threading
from typing import Any

import process_group_runner
import sandbox_seccomp
import taint_autofix
import tool_sandbox

FORMAT = "sniper-asan-project-proof/1"
SOURCE_FORMAT = "sniper-asan-source-proof/1"
COMPILE_DATABASE_FORMAT = "sniper-asan-compile-database-proof/1"
MAX_BINARY_BYTES = 64 * 1024 * 1024
MAX_SOURCE_BYTES = 2 * 1024 * 1024
MAX_COMPILE_DATABASE_BYTES = 2 * 1024 * 1024
MAX_COMPILE_DATABASE_ENTRIES = 4096
MAX_SNAPSHOT_FILES = 2048
MAX_SNAPSHOT_DIRECTORIES = 4096
MAX_SNAPSHOT_BYTES = 32 * 1024 * 1024
MAX_DIAGNOSTIC_BYTES = 512_000
RUN_TIMEOUT = 7
COMPILE_TIMEOUT = 20
_LOCK = threading.Lock()

_CWE_CLASS = {
    "CWE-416": "heap-use-after-free",
    "CWE-415": "double-free",
    "CWE-787": "buffer-overflow",
    "CWE-120": "buffer-overflow",
    "CWE-121": "buffer-overflow",
    "CWE-122": "buffer-overflow",
    "CWE-125": "buffer-overflow",
    "CWE-126": "buffer-overflow",
    "CWE-127": "buffer-overflow",
}
_KIND_CLASS = {
    "uaf": "heap-use-after-free",
    "double_free": "double-free",
    "overflow": "buffer-overflow",
    "overread": "buffer-overflow",
    "underread": "buffer-overflow",
}
_SNAPSHOT_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".inc"}
_SNAPSHOT_HEADER_SUFFIXES = {".h", ".hh", ".hpp", ".hxx", ".inc"}
_SAFE_VALUE_FLAG = re.compile(
    r"(?:-std=(?:c(?:89|90|99|11|17|18|2x)|gnu(?:89|90|99|11|17|18|2x)|"
    r"c\+\+(?:11|14|17|20|23|2b)|gnu\+\+(?:11|14|17|20|23|2b))|"
    r"-O(?:0|1|2|3|g|s)|-g(?:0|1|2|3)?|"
    r"-D[A-Za-z_][A-Za-z0-9_]*(?:=[A-Za-z0-9_.,:+/\-]{0,128})?|"
    r"-U[A-Za-z_][A-Za-z0-9_]*)\Z"
)
_SAFE_EXACT_FLAGS = {
    "-Wall", "-Wextra", "-Wpedantic", "-pedantic", "-pedantic-errors", "-pthread",
    "-fcommon", "-fno-common", "-fno-strict-aliasing", "-fwrapv", "-funsigned-char",
    "-fsigned-char",
}


class AsanProjectProofError(ValueError):
    pass


class AsanProjectProofUnavailable(AsanProjectProofError):
    pass


def _finding(store, audit_id: object, finding_index: object) -> tuple[dict[str, Any], Path, str]:
    if not isinstance(audit_id, str) or not audit_id.startswith("prj_") \
            or type(finding_index) is not int or finding_index < 0:
        raise AsanProjectProofError("Geçersiz proje analizi veya bulgu sırası.")
    audit = store.get_project_audit(audit_id)
    findings = audit.get("findings") if isinstance(audit, dict) else None
    if not isinstance(findings, list) or finding_index >= len(findings):
        raise AsanProjectProofError("Proje analizi veya bulgu bulunamadı.")
    finding = findings[finding_index]
    memory = finding.get("memory_safety") if isinstance(finding, dict) else None
    kind = memory.get("kind") if isinstance(memory, dict) else None
    reference = str(finding.get("reference") or finding.get("cwe") or "")
    match = re.search(r"CWE-\d+", reference)
    expected = _KIND_CLASS.get(kind) or _CWE_CLASS.get(match.group(0) if match else "")
    if expected is None:
        raise AsanProjectProofError("Bu profil yalnız desteklenen C/C++ bellek güvenliği bulgularını doğrular.")
    try:
        root = taint_autofix.project_root(audit)
    except taint_autofix.AutofixError as exc:
        raise AsanProjectProofError(str(exc)) from exc
    return finding, root, expected


def _open_binary(root: Path, relative: object) -> tuple[int, os.stat_result, str]:
    if not isinstance(relative, str) or not relative or len(relative) > 1024 or "\\" in relative or "\x00" in relative:
        raise AsanProjectProofError("İkili yolu proje köküne göreli olmalı.")
    pure = PurePosixPath(relative)
    if pure.is_absolute() or not pure.parts or any(part in {"", ".", ".."} for part in pure.parts):
        raise AsanProjectProofError("İkili yolu proje köküne göreli olmalı.")
    current = root
    try:
        for part in pure.parts:
            current = current / part
            if stat.S_ISLNK(os.lstat(current).st_mode):
                raise AsanProjectProofError("İkili yolu sembolik bağ içeremez.")
        resolved = current.resolve(strict=True)
        if root not in resolved.parents:
            raise AsanProjectProofError("İkili proje kökü içinde olmalı.")
        fd = os.open(resolved, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
        info = os.fstat(fd)
    except AsanProjectProofError:
        raise
    except OSError as exc:
        raise AsanProjectProofError("İkili açılamadı.") from exc
    try:
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022 \
                or not info.st_mode & 0o111 or not 1 <= info.st_size <= MAX_BINARY_BYTES:
            raise AsanProjectProofError("İkili normal, kullanıcıya ait, özel ve çalıştırılabilir bir dosya olmalı.")
        data = os.pread(fd, info.st_size, 0)
        if len(data) != info.st_size or not data.startswith(b"\x7fELF"):
            raise AsanProjectProofError("Yalnız ELF ikilisi çalıştırılabilir.")
        if b"__asan_init" not in data and b"libasan.so" not in data:
            raise AsanProjectProofError("İkili AddressSanitizer ile derlenmiş görünmüyor.")
        return fd, info, hashlib.sha256(data).hexdigest()
    except BaseException:
        os.close(fd)
        raise


def _data_fd(data: bytes) -> int:
    read_fd, write_fd = os.pipe()
    try:
        os.write(write_fd, data)
    finally:
        os.close(write_fd)
    return read_fd


def _limit(pid: int, *, cpu_seconds: int = RUN_TIMEOUT + 2) -> None:
    try:
        import resource

        resource.prlimit(pid, resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds))
        resource.prlimit(pid, resource.RLIMIT_CORE, (0, 0))
        resource.prlimit(pid, resource.RLIMIT_FSIZE, (1_048_576, 1_048_576))
        resource.prlimit(pid, resource.RLIMIT_NOFILE, (64, 64))
        # RLIMIT_NPROC, Linux'ta süreçlerden çok aynı gerçek UID'nin iş parçacıklarını sayar. Mevcut hizmet
        # yükünün üstüne küçük bir pay bırak; sabit düşük değer bwrap'ın ad alanını kurmasını da engellerdi.
        tasks = 0
        for entry in os.scandir("/proc"):
            if not entry.name.isdigit():
                continue
            try:
                if entry.stat(follow_symlinks=False).st_uid == os.getuid():
                    tasks += sum(1 for _ in os.scandir(f"/proc/{entry.name}/task"))
            except OSError:
                continue
        if tasks:
            limit = tasks + 128
            resource.prlimit(pid, resource.RLIMIT_NPROC, (limit, limit))
    except (ImportError, ValueError, OSError, AttributeError):
        pass


def _observed_class(diagnostic: str) -> str:
    if "heap-use-after-free" in diagnostic:
        return "heap-use-after-free"
    if "attempting double-free" in diagnostic or "double-free" in diagnostic:
        return "double-free"
    match = re.search(r"(?:heap|stack|global)-buffer-overflow", diagnostic)
    if match:
        return match.group(0)
    if "AddressSanitizer" in diagnostic:
        return "address-sanitizer-error"
    return ""


def _matches(expected: str, observed: str) -> bool:
    return observed.endswith("buffer-overflow") if expected == "buffer-overflow" else observed == expected


def _execute(binary_fd: int) -> tuple[int, str]:
    bwrap = None
    try:
        bwrap = tool_sandbox.open_bwrap()
        seccomp_fd = _data_fd(sandbox_seccomp.build_filter())
    except (tool_sandbox.SandboxUnavailable, sandbox_seccomp.SeccompUnsupported, OSError) as exc:
        if bwrap is not None:
            bwrap.close()
        raise AsanProjectProofUnavailable("ASan ikili yalıtımı kullanılamıyor.") from exc
    work: Path | None = None
    try:
        work = Path(tempfile.mkdtemp(prefix="sniper-asan-proof-"))
        os.chmod(work, 0o700)
    except OSError as exc:
        os.close(seccomp_fd)
        bwrap.close()
        if work is not None:
            shutil.rmtree(work, ignore_errors=True)
        raise AsanProjectProofUnavailable("ASan ikili çalışma dizini hazırlanamadı.") from exc
    output_fd = error_fd = -1
    try:
        output_fd = os.open(work / "stdout", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        error_fd = os.open(work / "stderr", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        binds = ["--dir", "/proof", "--perms", "0555", "--ro-bind-data", str(binary_fd), "/proof/program"]
        argv = tool_sandbox.bwrap_argv(bwrap.fd, binds, seccomp_fd=seccomp_fd) + [
            "--setenv", "ASAN_OPTIONS",
            "abort_on_error=1:halt_on_error=1:detect_leaks=0:symbolize=0:allocator_may_return_null=1",
            "/proof/program",
        ]
        try:
            with subprocess.Popen(
                argv, stdin=subprocess.DEVNULL, stdout=output_fd, stderr=error_fd,
                pass_fds=(bwrap.fd, binary_fd, seccomp_fd), close_fds=True,
                start_new_session=True, env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
            ) as process:
                _limit(process.pid)
                try:
                    code = process.wait(timeout=RUN_TIMEOUT)
                except subprocess.TimeoutExpired as exc:
                    process_group_runner.kill_process_group(process)
                    process.wait(timeout=2)
                    raise AsanProjectProofUnavailable("ASan ikilisi süre sınırını aştı.") from exc
        except OSError as exc:
            raise AsanProjectProofUnavailable("ASan ikilisi yalıtımda başlatılamadı.") from exc
        os.close(output_fd)
        os.close(error_fd)
        output_fd = error_fd = -1
        diagnostic = ((work / "stderr").read_bytes() + b"\n" + (work / "stdout").read_bytes())[
            :MAX_DIAGNOSTIC_BYTES
        ].decode("utf-8", "replace")
        if not diagnostic.strip() and code != 0:
            return int(code), ""
        if ("bwrap:" in diagnostic or "Creating new namespace failed" in diagnostic) and "AddressSanitizer" not in diagnostic:
            raise AsanProjectProofUnavailable("ASan ikili yalıtımı çalıştırılamadı.")
        return int(code), diagnostic
    finally:
        for fd in (output_fd, error_fd, seccomp_fd):
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass
        bwrap.close()
        shutil.rmtree(work, ignore_errors=True)


def _open_source(root: Path, finding: dict[str, Any], relative: object) -> tuple[int, str, str]:
    finding_file = str(finding.get("file") or "")
    if not isinstance(relative, str) or relative != finding_file or len(relative) > 1024 \
            or "\\" in relative or "\x00" in relative:
        raise AsanProjectProofError("Kaynak yolu bulgunun proje içi dosyasıyla tam eşleşmeli.")
    pure = PurePosixPath(relative)
    suffix = pure.suffix.lower()
    language = "c" if suffix == ".c" else ("cpp" if suffix in {".cc", ".cpp", ".cxx"} else "")
    if not language or pure.is_absolute() or not pure.parts or any(part in {"", ".", ".."} for part in pure.parts):
        raise AsanProjectProofError("Sabit ASan kaynak profili yalnız proje içindeki C/C++ kaynak dosyasını kabul eder.")
    current = root
    try:
        for part in pure.parts:
            current = current / part
            if stat.S_ISLNK(os.lstat(current).st_mode):
                raise AsanProjectProofError("Kaynak yolu sembolik bağ içeremez.")
        resolved = current.resolve(strict=True)
        if root not in resolved.parents:
            raise AsanProjectProofError("Kaynak proje kökü içinde olmalı.")
        fd = os.open(resolved, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
        info = os.fstat(fd)
    except AsanProjectProofError:
        raise
    except OSError as exc:
        raise AsanProjectProofError("Kaynak dosya açılamadı.") from exc
    try:
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or not 1 <= info.st_size <= MAX_SOURCE_BYTES:
            raise AsanProjectProofError("Kaynak normal, kullanıcıya ait ve en çok 2 MiB olmalı.")
        raw = os.pread(fd, info.st_size, 0)
        if len(raw) != info.st_size or b"\x00" in raw:
            raise AsanProjectProofError("Kaynak dosya eksik veya metin değil.")
        try:
            raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise AsanProjectProofError("Kaynak UTF-8 olmalı.") from exc
        return fd, language, hashlib.sha256(raw).hexdigest()
    except BaseException:
        os.close(fd)
        raise


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _project_path(root: Path, base: Path, value: object, *, want_directory: bool = False) -> tuple[Path, str]:
    """Resolve one lexical in-project path without accepting symlink traversal."""
    if not isinstance(value, str) or not value or len(value) > 2048 or "\x00" in value or "\\" in value:
        raise AsanProjectProofError("Derleme veritabanı yalnız proje içi POSIX yollarını kullanmalı.")
    supplied = Path(value)
    if any(part in {"", ".", ".."} for part in PurePosixPath(value).parts):
        raise AsanProjectProofError("Derleme veritabanı yolu üst dizin veya belirsiz bileşen içeremez.")
    candidate = supplied if supplied.is_absolute() else base / supplied
    try:
        lexical = candidate.relative_to(root)
    except ValueError as exc:
        raise AsanProjectProofError("Derleme veritabanı yolu proje kökü içinde olmalı.") from exc
    current = root
    try:
        for part in lexical.parts:
            current = current / part
            if stat.S_ISLNK(os.lstat(current).st_mode):
                raise AsanProjectProofError("Derleme veritabanı yolu sembolik bağ içeremez.")
        resolved = current.resolve(strict=True)
        info = os.stat(resolved, follow_symlinks=False)
    except AsanProjectProofError:
        raise
    except OSError as exc:
        raise AsanProjectProofError("Derleme veritabanı proje yolu okunamadı.") from exc
    if resolved != root and root not in resolved.parents:
        raise AsanProjectProofError("Derleme veritabanı yolu proje kökü içinde olmalı.")
    valid_type = stat.S_ISDIR(info.st_mode) if want_directory else stat.S_ISREG(info.st_mode)
    if not valid_type or info.st_uid != os.getuid():
        raise AsanProjectProofError("Derleme veritabanı yolu kullanıcıya ait normal türde olmalı.")
    return resolved, resolved.relative_to(root).as_posix()


def _load_compile_database(root: Path, relative: object) -> tuple[list[dict[str, Any]], str]:
    path, _rel = _project_path(root, root, relative)
    fd = -1
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            raise AsanProjectProofError("compile_commands.json kullanıcıya ait normal dosya olmalı.")
        if not 1 <= info.st_size <= MAX_COMPILE_DATABASE_BYTES:
            raise AsanProjectProofError("compile_commands.json boyut sınırını aşıyor.")
        raw = os.pread(fd, info.st_size, 0)
        if len(raw) != info.st_size:
            raise AsanProjectProofError("compile_commands.json kararlı biçimde okunamadı.")
        document = json.loads(raw)
    except AsanProjectProofError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AsanProjectProofError("compile_commands.json geçerli UTF-8 JSON olmalı.") from exc
    finally:
        if fd >= 0:
            os.close(fd)
    if not isinstance(document, list) or not 1 <= len(document) <= MAX_COMPILE_DATABASE_ENTRIES \
            or any(not isinstance(entry, dict) for entry in document):
        raise AsanProjectProofError("compile_commands.json sınırlı bir girdi listesi olmalı.")
    return document, hashlib.sha256(raw).hexdigest()


def _select_compile_entry(
    root: Path, finding: dict[str, Any], document: list[dict[str, Any]], entry_index: object,
) -> tuple[Path, str, list[str], str, str]:
    if type(entry_index) is not int or not 0 <= entry_index < len(document):
        raise AsanProjectProofError("entry_index geçerli bir derleme veritabanı sırası olmalı.")
    entry = document[entry_index]
    if "command" in entry or not isinstance(entry.get("arguments"), list) \
            or not 2 <= len(entry["arguments"]) <= 128 \
            or any(not isinstance(arg, str) or not arg or len(arg) > 4096 or "\x00" in arg
                   for arg in entry["arguments"]):
        raise AsanProjectProofError("Yalnız shell içermeyen sınırlı arguments derleme girdisi kabul edilir.")
    directory, _directory_rel = _project_path(root, root, entry.get("directory"), want_directory=True)
    source, source_rel = _project_path(root, directory, entry.get("file"))
    finding_file = str(finding.get("file") or "")
    finding_source, finding_rel = _project_path(root, root, finding_file)
    if source != finding_source or source_rel != finding_rel:
        raise AsanProjectProofError("Derleme girdisi bulgunun kaynak dosyasıyla tam eşleşmeli.")
    suffix = source.suffix.lower()
    language = "c" if suffix == ".c" else ("cpp" if suffix in {".cc", ".cpp", ".cxx"} else "")
    if not language:
        raise AsanProjectProofError("Derleme veritabanı kanıtı yalnız C/C++ bulgu kaynağını kabul eder.")

    trusted = _compilers(language)
    driver = Path(entry["arguments"][0])
    candidates = []
    for compiler, digest in trusted:
        if driver.is_absolute():
            try:
                matches = driver.resolve(strict=True) == compiler
            except OSError:
                matches = False
        else:
            driver_name = driver.name
            if language == "c":
                gcc_alias = re.fullmatch(r"(?:cc|gcc)(?:-[0-9]+)?", driver_name)
                clang_alias = re.fullmatch(r"clang(?:-[0-9]+)?", driver_name)
            else:
                gcc_alias = re.fullmatch(r"(?:c\+\+|g\+\+)(?:-[0-9]+)?", driver_name)
                clang_alias = re.fullmatch(r"clang\+\+(?:-[0-9]+)?", driver_name)
            matches = bool(gcc_alias and ("gcc" in compiler.name or "g++" in compiler.name)) \
                or bool(clang_alias and "clang" in compiler.name)
        if matches:
            candidates.append((compiler, digest))
    if len(candidates) != 1:
        raise AsanProjectProofError("Derleme girdisi yalnız doğrulanmış GCC/Clang sürücüsünü kullanmalı.")
    compiler, compiler_sha = candidates[0]

    safe: list[str] = []
    source_seen = False
    compile_only_seen = False
    args = entry["arguments"][1:]
    index = 0
    while index < len(args):
        token = args[index]
        if token == "-c":
            if compile_only_seen:
                raise AsanProjectProofError("Derleme girdisi yinelenen -c seçeneği içeremez.")
            compile_only_seen = True
            index += 1
            continue
        if token == "-o":
            if index + 1 >= len(args):
                raise AsanProjectProofError("Derleme girdisinin -o seçeneği eksik.")
            index += 2
            continue
        if token.startswith("-o") and len(token) > 2:
            index += 1
            continue
        if token in {"-I", "-iquote", "-isystem", "-include"}:
            if index + 1 >= len(args):
                raise AsanProjectProofError("Derleme girdisinin proje yolu seçeneği eksik.")
            target, rel = _project_path(root, directory, args[index + 1], want_directory=token != "-include")
            if token == "-include" and target.suffix.lower() not in _SNAPSHOT_SUFFIXES:
                raise AsanProjectProofError("Zorunlu include yalnız C/C++ kaynak veya başlık dosyası olmalı.")
            safe.extend((token, "/project" + ("/" + rel if rel else "")))
            index += 2
            continue
        include_match = re.fullmatch(r"(-I|-iquote|-isystem)(.+)", token)
        if include_match:
            _target, rel = _project_path(root, directory, include_match.group(2), want_directory=True)
            safe.extend((include_match.group(1), "/project" + ("/" + rel if rel else "")))
            index += 1
            continue
        if token in _SAFE_EXACT_FLAGS or _SAFE_VALUE_FLAG.fullmatch(token):
            safe.append(token)
            index += 1
            continue
        if token.startswith("-"):
            raise AsanProjectProofError("Derleme girdisi izinli profil dışında seçenek içeriyor.")
        positional, _rel = _project_path(root, directory, token)
        if positional != source or source_seen:
            raise AsanProjectProofError("Derleme girdisi yalnız bulgunun tek çeviri birimini içermeli.")
        source_seen = True
        index += 1
    if not source_seen or not compile_only_seen:
        raise AsanProjectProofError("Derleme girdisi tek kaynaklı -c profili olmalı.")
    canonical = {
        "compiler_sha256": compiler_sha,
        "source_relpath": source_rel,
        "language": language,
        "safe_arguments": safe,
    }
    entry_sha = hashlib.sha256(
        json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return compiler, compiler_sha, safe, source_rel, entry_sha


def _snapshot_project(root: Path, destination: Path) -> tuple[str, int, dict[str, str]]:
    """Copy only bounded C/C++ source/header bytes; never follow project symlinks."""
    records: list[tuple[str, str]] = []
    digests: dict[str, str] = {}
    total = 0
    directory_count = 0
    for directory, dirs, files in os.walk(root, topdown=True, followlinks=False):
        directory_count += 1
        if directory_count > MAX_SNAPSHOT_DIRECTORIES:
            raise AsanProjectProofError("Proje snapshot dizin sınırını aşıyor.")
        base = Path(directory)
        kept_dirs = []
        for name in sorted(dirs):
            candidate = base / name
            try:
                if not stat.S_ISLNK(os.lstat(candidate).st_mode):
                    kept_dirs.append(name)
            except OSError:
                continue
        dirs[:] = kept_dirs
        for name in sorted(files):
            source = base / name
            if source.suffix.lower() not in _SNAPSHOT_SUFFIXES:
                continue
            try:
                link_info = os.lstat(source)
                if not stat.S_ISREG(link_info.st_mode):
                    raise AsanProjectProofError("Proje snapshot'ı sembolik veya özel kaynak içeremez.")
                fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
                try:
                    info = os.fstat(fd)
                    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() \
                            or not 0 <= info.st_size <= MAX_SOURCE_BYTES:
                        raise AsanProjectProofError(
                            "Proje snapshot'ı yalnız sınırlı kullanıcı kaynaklarını kabul eder."
                        )
                    if info.st_size == 0:
                        if source.suffix.lower() in _SNAPSHOT_HEADER_SUFFIXES:
                            continue
                        raise AsanProjectProofError("Proje snapshot çeviri birimi boş olamaz.")
                    raw = os.pread(fd, info.st_size, 0)
                finally:
                    os.close(fd)
            except AsanProjectProofError:
                raise
            except OSError as exc:
                raise AsanProjectProofError("Proje snapshot kaynağı güvenli biçimde okunamadı.") from exc
            if len(raw) != info.st_size or b"\x00" in raw:
                raise AsanProjectProofError("Proje snapshot kaynağı eksik veya metin değil.")
            try:
                raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise AsanProjectProofError("Proje snapshot kaynakları UTF-8 olmalı.") from exc
            rel = source.relative_to(root).as_posix()
            total += len(raw)
            if len(records) >= MAX_SNAPSHOT_FILES or total > MAX_SNAPSHOT_BYTES:
                raise AsanProjectProofError("Proje snapshot dosya veya bayt sınırını aşıyor.")
            target = destination / rel
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            target.write_bytes(raw)
            target.chmod(0o400)
            digest = hashlib.sha256(raw).hexdigest()
            records.append((rel, digest))
            digests[rel] = digest
    snapshot_sha = hashlib.sha256(repr(records).encode("utf-8")).hexdigest()
    return snapshot_sha, len(records), digests


def _compilers(language: str) -> list[tuple[Path, str]]:
    configured = os.environ.get("SNIPER_CLANG_BINARY")
    candidates = ([configured] if configured else
                  (["/usr/bin/gcc", "/usr/bin/clang"] if language == "c" else ["/usr/bin/g++", "/usr/bin/clang++"]))
    names = re.compile(r"(?:clang|gcc|clang\+\+|g\+\+)(?:-[0-9]+)?\Z")
    result = []
    for candidate in candidates:
        if not candidate:
            continue
        path = Path(candidate)
        if not path.is_absolute() or not names.fullmatch(path.name):
            continue
        try:
            resolved = path.resolve(strict=True)
            info = resolved.stat()
        except OSError:
            continue
        if Path("/usr") not in resolved.parents or not stat.S_ISREG(info.st_mode) or info.st_uid != 0 \
                or info.st_mode & 0o022 or not os.access(resolved, os.X_OK):
            continue
        digest = _file_sha256(resolved)
        expected = os.environ.get("SNIPER_CLANG_ASAN_SHA256", "").strip().lower()
        if expected and (not re.fullmatch(r"[0-9a-f]{64}", expected) or expected != digest):
            raise AsanProjectProofUnavailable("Derleyici SHA-256 sabitlemesi eşleşmedi.")
        result.append((resolved, digest))
    if not result:
        raise AsanProjectProofUnavailable("Güvenilir sistem C/C++ derleyicisi bulunamadı.")
    return result


def _compile_source(source_fds: list[int], language: str, compiler: Path) -> tuple[int, str]:
    bwrap = None
    try:
        bwrap = tool_sandbox.open_bwrap()
        seccomp_fd = _data_fd(sandbox_seccomp.build_filter())
    except (tool_sandbox.SandboxUnavailable, sandbox_seccomp.SeccompUnsupported, OSError) as exc:
        if bwrap is not None:
            bwrap.close()
        raise AsanProjectProofUnavailable("ASan kaynak derleme yalıtımı kullanılamıyor.") from exc
    work: Path | None = None
    try:
        work = Path(tempfile.mkdtemp(prefix="sniper-asan-build-"))
        os.chmod(work, 0o700)
        out_dir = work / "out"
        out_dir.mkdir(mode=0o700)
    except OSError as exc:
        os.close(seccomp_fd)
        bwrap.close()
        if work is not None:
            shutil.rmtree(work, ignore_errors=True)
        raise AsanProjectProofUnavailable("ASan kaynak derleme dizini hazırlanamadı.") from exc
    stdout_fd = stderr_fd = binary_fd = -1
    try:
        stdout_fd = os.open(work / "stdout", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        stderr_fd = os.open(work / "stderr", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        suffix, standard, profile = (("c", "c11", "c11-asan-fixed-v1") if language == "c"
                                     else ("cpp", "c++17", "cpp17-asan-fixed-v1"))
        if len(source_fds) > 1:
            profile = profile.replace("-v1", "-multifile-v1")
        diagnostics = (["-fno-caret-diagnostics"] if compiler.name.startswith("clang")
                       else ["-fno-diagnostics-show-caret", "-fdiagnostics-color=never"])
        binds = ["--dir", "/proof"]
        source_names = []
        for index, source_fd in enumerate(source_fds):
            name = f"/proof/source{index}.{suffix}"
            binds += ["--perms", "0444", "--ro-bind-data", str(source_fd), name]
            source_names.append(name)
        binds += ["--bind", str(out_dir), "/out"]
        command = [str(compiler), "-x", "c" if language == "c" else "c++", f"-std={standard}", "-O0", "-g0",
                   "-fsanitize=address", "-fno-omit-frame-pointer", *diagnostics,
                   *source_names, "-o", "/out/program"]
        argv = tool_sandbox.bwrap_argv(bwrap.fd, binds, seccomp_fd=seccomp_fd) + command
        try:
            with subprocess.Popen(
                argv, stdin=subprocess.DEVNULL, stdout=stdout_fd, stderr=stderr_fd,
                pass_fds=(bwrap.fd, *source_fds, seccomp_fd), close_fds=True, start_new_session=True,
                env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
            ) as process:
                _limit(process.pid, cpu_seconds=COMPILE_TIMEOUT + 2)
                try:
                    code = process.wait(timeout=COMPILE_TIMEOUT)
                except subprocess.TimeoutExpired as exc:
                    process_group_runner.kill_process_group(process)
                    process.wait(timeout=2)
                    raise AsanProjectProofUnavailable("ASan kaynak derlemesi süre sınırını aştı.") from exc
        except OSError as exc:
            raise AsanProjectProofUnavailable("ASan kaynak derlemesi yalıtımda başlatılamadı.") from exc
        os.close(stdout_fd)
        os.close(stderr_fd)
        stdout_fd = stderr_fd = -1
        if code != 0:
            diagnostic = (work / "stderr").read_text("utf-8", "replace")[:4000]
            if "bwrap:" in diagnostic or "Creating new namespace failed" in diagnostic:
                raise AsanProjectProofUnavailable("ASan kaynak derleme yalıtımı çalıştırılamadı.")
            raise AsanProjectProofError("Kaynak sabit ASan profiliyle derlenemedi; proje derleme betikleri çalıştırılmadı.")
        binary = out_dir / "program"
        binary_fd = os.open(binary, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
        info = os.fstat(binary_fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or not 1 <= info.st_size <= MAX_BINARY_BYTES:
            raise AsanProjectProofUnavailable("Derlenen ASan ikilisi geçersiz.")
        raw = os.pread(binary_fd, info.st_size, 0)
        if len(raw) != info.st_size or not raw.startswith(b"\x7fELF") \
                or (b"__asan_init" not in raw and b"libasan.so" not in raw):
            raise AsanProjectProofUnavailable("Derlenen ikilide ASan çalışma zamanı bulunamadı.")
        digest = hashlib.sha256(raw).hexdigest()
        kept_fd, binary_fd = binary_fd, -1
        return kept_fd, profile
    finally:
        for fd in (stdout_fd, stderr_fd, binary_fd, seccomp_fd):
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass
        bwrap.close()
        shutil.rmtree(work, ignore_errors=True)


def _compile_snapshot_entry(
    root: Path, compiler: Path, safe_arguments: list[str], source_relpath: str,
) -> tuple[int, str, int, str]:
    """Compile one selected translation unit from a bounded private project snapshot."""
    bwrap = None
    try:
        bwrap = tool_sandbox.open_bwrap()
        seccomp_fd = _data_fd(sandbox_seccomp.build_filter())
    except (tool_sandbox.SandboxUnavailable, sandbox_seccomp.SeccompUnsupported, OSError) as exc:
        if bwrap is not None:
            bwrap.close()
        raise AsanProjectProofUnavailable("ASan compile-database yalıtımı kullanılamıyor.") from exc
    work: Path | None = None
    try:
        work = Path(tempfile.mkdtemp(prefix="sniper-asan-compile-db-"))
        os.chmod(work, 0o700)
        snapshot = work / "project"
        output = work / "out"
        snapshot.mkdir(mode=0o700)
        output.mkdir(mode=0o700)
        snapshot_sha, snapshot_file_count, source_digests = _snapshot_project(root, snapshot)
        if source_relpath not in source_digests:
            raise AsanProjectProofError("Bulgu kaynağı sınırlı proje snapshot'ına alınamadı.")
    except AsanProjectProofError:
        os.close(seccomp_fd)
        bwrap.close()
        if work is not None:
            shutil.rmtree(work, ignore_errors=True)
        raise
    except OSError as exc:
        os.close(seccomp_fd)
        bwrap.close()
        if work is not None:
            shutil.rmtree(work, ignore_errors=True)
        raise AsanProjectProofUnavailable("ASan compile-database çalışma alanı hazırlanamadı.") from exc
    stdout_fd = stderr_fd = binary_fd = -1
    try:
        stdout_fd = os.open(work / "stdout", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        stderr_fd = os.open(work / "stderr", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        binds = ["--ro-bind", str(snapshot), "/project", "--bind", str(output), "/out"]
        command = [str(compiler), *safe_arguments, "-fsanitize=address", "-fno-omit-frame-pointer",
                   f"/project/{source_relpath}", "-o", "/out/program"]
        argv = tool_sandbox.bwrap_argv(bwrap.fd, binds, seccomp_fd=seccomp_fd) + command
        try:
            with subprocess.Popen(
                argv, stdin=subprocess.DEVNULL, stdout=stdout_fd, stderr=stderr_fd,
                pass_fds=(bwrap.fd, seccomp_fd), close_fds=True, start_new_session=True,
                env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
            ) as process:
                _limit(process.pid, cpu_seconds=COMPILE_TIMEOUT + 2)
                try:
                    code = process.wait(timeout=COMPILE_TIMEOUT)
                except subprocess.TimeoutExpired as exc:
                    process_group_runner.kill_process_group(process)
                    process.wait(timeout=2)
                    raise AsanProjectProofUnavailable("ASan compile-database derlemesi süre sınırını aştı.") from exc
        except OSError as exc:
            raise AsanProjectProofUnavailable("ASan compile-database girdisi yalıtımda başlatılamadı.") from exc
        os.close(stdout_fd)
        os.close(stderr_fd)
        stdout_fd = stderr_fd = -1
        if code != 0:
            diagnostic = (work / "stderr").read_text("utf-8", "replace")[:4000]
            if "bwrap:" in diagnostic or "Creating new namespace failed" in diagnostic:
                raise AsanProjectProofUnavailable("ASan compile-database yalıtımı çalıştırılamadı.")
            raise AsanProjectProofError(
                "Seçilen compile_commands girdisi güvenli ASan profiliyle derlenemedi; build betiği çalıştırılmadı."
            )
        binary = output / "program"
        binary_fd = os.open(binary, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
        info = os.fstat(binary_fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or not 1 <= info.st_size <= MAX_BINARY_BYTES:
            raise AsanProjectProofUnavailable("Compile-database ile derlenen ASan ikilisi geçersiz.")
        raw = os.pread(binary_fd, info.st_size, 0)
        if len(raw) != info.st_size or not raw.startswith(b"\x7fELF") \
                or (b"__asan_init" not in raw and b"libasan.so" not in raw):
            raise AsanProjectProofUnavailable("Compile-database ikilisinde ASan çalışma zamanı bulunamadı.")
        kept_fd, binary_fd = binary_fd, -1
        return kept_fd, snapshot_sha, snapshot_file_count, source_digests[source_relpath]
    finally:
        for fd in (stdout_fd, stderr_fd, binary_fd, seccomp_fd):
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass
        bwrap.close()
        shutil.rmtree(work, ignore_errors=True)


def run(store, audit_id: object, finding_index: object, *, binary_relpath: object,
        confirm_local: object) -> dict[str, Any]:
    if confirm_local is not True:
        raise AsanProjectProofError("ASan proje kanıtı için confirm_local tam olarak true olmalı.")
    finding, root, expected = _finding(store, audit_id, finding_index)
    if not _LOCK.acquire(blocking=False):
        raise AsanProjectProofUnavailable("Başka bir ASan proje kanıtı çalışıyor.")
    binary_fd = -1
    try:
        binary_fd, _info, binary_sha = _open_binary(root, binary_relpath)
        code, diagnostic = _execute(binary_fd)
    finally:
        if binary_fd >= 0:
            os.close(binary_fd)
        _LOCK.release()
    observed = _observed_class(diagnostic)
    asan_error = bool(observed)
    evidence = {
        "format": FORMAT, "expected_error_class": expected, "observed_error_class": observed,
        "verdict": "confirmed" if _matches(expected, observed) else "not_reproduced",
        "asan_error": asan_error, "exit_code": code, "binary_sha256": binary_sha,
        "network_available": False, "argument_count": 0, "stdin_available": False, "timed_out": False,
    }
    digest = hashlib.sha256(
        repr(sorted(evidence.items())).encode("utf-8")
    ).hexdigest()
    proof = {
        **evidence, "audit_id": str(audit_id), "finding_index": int(finding_index),
        "finding_reference": str(finding.get("reference") or "")[:80], "evidence_sha256": digest,
    }
    return store.add_project_asan_runtime_proof(str(audit_id), int(finding_index), proof)


def run_source(store, audit_id: object, finding_index: object, *, source_relpath: object,
               confirm_local: object, companion_relpaths: object = None) -> dict[str, Any]:
    """Bulgu kaynağını ve en çok üç açık eşlikçi C/C++ kaynağını sabit profille derle."""
    if confirm_local is not True:
        raise AsanProjectProofError("ASan kaynak kanıtı için confirm_local tam olarak true olmalı.")
    finding, root, expected = _finding(store, audit_id, finding_index)
    if companion_relpaths is None:
        companions: list[str] = []
    elif not isinstance(companion_relpaths, list) or len(companion_relpaths) > 3 \
            or any(not isinstance(item, str) for item in companion_relpaths) \
            or len(set(companion_relpaths)) != len(companion_relpaths) \
            or source_relpath in companion_relpaths:
        raise AsanProjectProofError("companion_relpaths en çok üç benzersiz kaynak yolu içermeli.")
    else:
        companions = companion_relpaths
    # Yapısal istek doğrulaması kilitten önce tamamlanır. Aksi halde duplicate/excess gibi bir 400 yanıtı
    # süreç ömrü boyunca kilidi elde tutar ve sonraki bütün geçerli kanıtları 503'e dönüştürür.
    if not _LOCK.acquire(blocking=False):
        raise AsanProjectProofUnavailable("Başka bir ASan proje kanıtı çalışıyor.")
    source_fds: list[int] = []
    binary_fd = -1
    try:
        source_fd, language, source_sha = _open_source(root, finding, source_relpath)
        source_fds.append(source_fd)
        source_parts = [(str(source_relpath), source_sha)]
        for relative in companions:
            fd, companion_language, digest = _open_source(root, {"file": relative}, relative)
            if companion_language != language:
                os.close(fd)
                raise AsanProjectProofError("Tüm ASan kaynakları aynı C/C++ dil profilinde olmalı.")
            source_fds.append(fd); source_parts.append((relative, digest))
        if companions:
            source_sha = hashlib.sha256(repr(sorted(source_parts)).encode("utf-8")).hexdigest()
        last_compile_error: AsanProjectProofError | None = None
        for compiler, compiler_sha in _compilers(language):
            try:
                binary_fd, build_profile = _compile_source(source_fds, language, compiler)
                break
            except AsanProjectProofError as exc:
                last_compile_error = exc
        else:
            raise last_compile_error or AsanProjectProofUnavailable("Kaynak için çalışan ASan derleyicisi bulunamadı.")
        info = os.fstat(binary_fd)
        binary_raw = os.pread(binary_fd, info.st_size, 0)
        binary_sha = hashlib.sha256(binary_raw).hexdigest()
        code, diagnostic = _execute(binary_fd)
    finally:
        for fd in (*source_fds, binary_fd):
            if fd >= 0:
                os.close(fd)
        _LOCK.release()
    observed = _observed_class(diagnostic)
    evidence = {
        "format": SOURCE_FORMAT, "expected_error_class": expected, "observed_error_class": observed,
        "verdict": "confirmed" if _matches(expected, observed) else "not_reproduced",
        "asan_error": bool(observed), "exit_code": code, "binary_sha256": binary_sha,
        "source_sha256": source_sha, "compiler_sha256": compiler_sha, "source_language": language,
        "build_profile": build_profile, "network_available": False, "argument_count": 0,
        "stdin_available": False, "timed_out": False, "project_build_scripts_executed": False,
    }
    digest = hashlib.sha256(repr(sorted(evidence.items())).encode("utf-8")).hexdigest()
    proof = {**evidence, "audit_id": str(audit_id), "finding_index": int(finding_index),
             "finding_reference": str(finding.get("reference") or "")[:80], "evidence_sha256": digest}
    return store.add_project_asan_source_proof(str(audit_id), int(finding_index), proof)


def run_compile_database(
    store, audit_id: object, finding_index: object, *, compile_commands_relpath: object,
    entry_index: object, confirm_local: object,
) -> dict[str, Any]:
    """Rebuild one finding translation unit from a shell-free compile database entry."""
    if confirm_local is not True:
        raise AsanProjectProofError("ASan compile-database kanıtı için confirm_local tam olarak true olmalı.")
    finding, root, expected = _finding(store, audit_id, finding_index)
    document, database_sha = _load_compile_database(root, compile_commands_relpath)
    compiler, compiler_sha, safe_arguments, source_relpath, entry_sha = _select_compile_entry(
        root, finding, document, entry_index,
    )
    if not _LOCK.acquire(blocking=False):
        raise AsanProjectProofUnavailable("Başka bir ASan proje kanıtı çalışıyor.")
    binary_fd = -1
    try:
        binary_fd, snapshot_sha, snapshot_file_count, source_sha = _compile_snapshot_entry(
            root, compiler, safe_arguments, source_relpath,
        )
        info = os.fstat(binary_fd)
        binary_sha = hashlib.sha256(os.pread(binary_fd, info.st_size, 0)).hexdigest()
        code, diagnostic = _execute(binary_fd)
    finally:
        if binary_fd >= 0:
            os.close(binary_fd)
        _LOCK.release()
    observed = _observed_class(diagnostic)
    evidence = {
        "format": COMPILE_DATABASE_FORMAT,
        "expected_error_class": expected,
        "observed_error_class": observed,
        "verdict": "confirmed" if _matches(expected, observed) else "not_reproduced",
        "asan_error": bool(observed),
        "exit_code": code,
        "binary_sha256": binary_sha,
        "source_sha256": source_sha,
        "compiler_sha256": compiler_sha,
        "compile_database_sha256": database_sha,
        "compile_entry_sha256": entry_sha,
        "snapshot_sha256": snapshot_sha,
        "snapshot_file_count": snapshot_file_count,
        "source_language": "c" if Path(source_relpath).suffix.lower() == ".c" else "cpp",
        "build_profile": "compile-database-single-tu-v1",
        "snapshot_scope": "bounded_c_cpp_sources_headers_only",
        "network_available": False,
        "argument_count": 0,
        "stdin_available": False,
        "timed_out": False,
        "project_build_scripts_executed": False,
    }
    digest = hashlib.sha256(
        json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    proof = {
        **evidence,
        "audit_id": str(audit_id),
        "finding_index": int(finding_index),
        "finding_reference": str(finding.get("reference") or "")[:80],
        "evidence_sha256": digest,
    }
    return store.add_project_asan_compile_database_proof(str(audit_id), int(finding_index), proof)
