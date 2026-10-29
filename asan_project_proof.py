"""Önceden derlenmiş, sabit kaynak veya compile-database ASan ELF için ağsız çalışma zamanı kanıtı."""

from __future__ import annotations

import ast
import hashlib
import importlib.util
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
import fuzz_runtime

FORMAT = "sniper-asan-project-proof/1"
SOURCE_FORMAT = "sniper-asan-source-proof/1"
COMPILE_DATABASE_FORMAT = "sniper-asan-compile-database-proof/1"
MAX_HARNESS_SOURCE_BYTES = 512 * 1024
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
    "CWE-562": "heap-use-after-free",
    "CWE-415": "double-free",
    "CWE-787": "buffer-overflow",
    "CWE-119": "buffer-overflow",
    "CWE-120": "buffer-overflow",
    "CWE-121": "buffer-overflow",
    "CWE-122": "buffer-overflow",
    "CWE-124": "buffer-overflow",
    "CWE-125": "buffer-overflow",
    "CWE-126": "buffer-overflow",
    "CWE-127": "buffer-overflow",
    "CWE-129": "buffer-overflow",
    "CWE-130": "buffer-overflow",
    "CWE-131": "buffer-overflow",
    "CWE-193": "buffer-overflow",
    "CWE-788": "buffer-overflow",
    "CWE-805": "buffer-overflow",
    "CWE-806": "buffer-overflow",
    "CWE-590": "bad-free",
    "CWE-761": "bad-free",
    "CWE-762": "alloc-dealloc-mismatch",
    "CWE-680": "allocation-size-too-big",
}
_KIND_CLASS = {
    "uaf": "heap-use-after-free",
    "double_free": "double-free",
    "overflow": "buffer-overflow",
    "overflow_taint": "buffer-overflow",
    "off_by_one": "buffer-overflow",
    "underwrite": "buffer-overflow",
    "overread": "buffer-overflow",
    "underread": "buffer-overflow",
    "memory": "buffer-overflow",
    "memory_len": "buffer-overflow",
    "memory_index": "buffer-overflow",
    "free_nonheap": "bad-free",
    "free_offset": "bad-free",
    "mismatch_free": "alloc-dealloc-mismatch",
    "alloc_overflow": "allocation-size-too-big",
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

MAX_PYTHON_FUZZ_SOURCE_BYTES = 512_000
MAX_JS_FUZZ_SOURCE_BYTES = 512_000
_PYTHON_FUZZ_TARGET_RE = re.compile(r"^(?:parse|decode|normalize)(?:_|$)")
_JS_FUZZ_SUFFIXES = {".js", ".mjs", ".ts", ".mts"}
_JS_EXPORTED_FUNCTION_RE = re.compile(
    r"^[ \t]*export[ \t]+function[ \t]+"
    r"((?:parse|decode|normalize)[A-Za-z0-9_]*)[ \t]*\(([^()\n]*)\)",
    re.MULTILINE,
)
_GO_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_GO_PACKAGE = re.compile(r"(?m)^[ \t]*package[ \t]+([A-Za-z_][A-Za-z0-9_]*)[ \t]*$")
_GO_BYTE_OR_STRING_FUNCTION = re.compile(
    r"(?m)^[ \t]*func[ \t]+([A-Za-z_][A-Za-z0-9_]*)[ \t]*"
    r"\([ \t]*(?:[A-Za-z_][A-Za-z0-9_]*[ \t]+)?(\[\]byte|string)[ \t]*\)"
)
_GO_KEYWORDS = {
    "break", "default", "func", "interface", "select", "case", "defer", "go", "map", "struct",
    "chan", "else", "goto", "package", "switch", "const", "fallthrough", "if", "range", "type",
    "continue", "for", "import", "return", "var",
}
_JAVA_IDENTIFIER = r"[A-Za-z_$][A-Za-z0-9_$]*"
_JAVA_PACKAGE_RE = re.compile(rf"\bpackage\s+({_JAVA_IDENTIFIER}(?:\.{_JAVA_IDENTIFIER})*)\s*;")
_JAVA_CLASS_RE = re.compile(
    rf"\b(?P<mods>(?:(?:public|protected|private|abstract|final|sealed|non-sealed|static|strictfp)\s+)*)"
    rf"class\s+(?P<name>{_JAVA_IDENTIFIER})\b[^{{}};]*\{{"
)
_JAVA_METHOD_RE = re.compile(
    rf"(?P<mods>(?:(?:public|protected|private|static|final|synchronized|native|abstract|strictfp)\s+)*)"
    rf"(?P<returns>{_JAVA_IDENTIFIER}(?:\.{_JAVA_IDENTIFIER})*(?:\s*<[^{{}}();]*>)?(?:\s*\[\s*\])?)\s+"
    rf"(?P<name>{_JAVA_IDENTIFIER})\s*\((?P<params>[^(){{}};]*)\)"
    rf"(?:\s+throws\s+[^{{}};]+)?\s*\{{"
)
_JAVA_SYMBOL_RE = re.compile(
    rf"(?:(?P<class>{_JAVA_IDENTIFIER}(?:\.{_JAVA_IDENTIFIER})*)#)?"
    rf"(?P<method>{_JAVA_IDENTIFIER})(?:\((?P<signature>byte\s*\[\s*\]|(?:java\.lang\.)?String)\))?\Z"
)
_JAVA_TARGET_METHOD_RE = re.compile(
    r"(?:parse|decode|normalize|normalise|canonicalize|canonicalise)[A-Za-z0-9_$]*\Z", re.IGNORECASE,
)


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
    flow = finding.get("taint_flow") if isinstance(finding, dict) else None
    kind = (memory.get("kind") if isinstance(memory, dict) else None) or (
        flow.get("sink_kind") if isinstance(flow, dict) else None
    )
    reference = str(finding.get("reference") or finding.get("cwe") or finding.get("cwe_id") or "").strip()
    match = re.search(r"CWE-(\d+)", reference, re.IGNORECASE)
    cwe_key = f"CWE-{match.group(1)}" if match else (f"CWE-{reference}" if reference.isdigit() else "")
    expected = _KIND_CLASS.get(kind) or _CWE_CLASS.get(cwe_key)
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
    if "stack-use-after-return" in diagnostic:
        return "stack-use-after-return"
    if "stack-use-after-scope" in diagnostic:
        return "stack-use-after-scope"
    if "attempting double-free" in diagnostic or "double-free" in diagnostic:
        return "double-free"
    if "attempting free on address which was not malloc()-ed" in diagnostic or "bad-free" in diagnostic:
        return "bad-free"
    if "alloc-dealloc-mismatch" in diagnostic:
        return "alloc-dealloc-mismatch"
    if "allocation-size-too-big" in diagnostic or "exceeds maximum supported size" in diagnostic:
        return "allocation-size-too-big"
    if "negative-size-param" in diagnostic:
        return "negative-size-param"
    match = re.search(r"(?:heap|stack|global|dynamic-stack)-buffer-(?:overflow|underflow)", diagnostic)
    if match:
        return match.group(0)
    if "AddressSanitizer" in diagnostic:
        return "address-sanitizer-error"
    return ""


def _matches(expected: str, observed: str) -> bool:
    if expected == "buffer-overflow":
        return observed.endswith(("buffer-overflow", "buffer-underflow")) or observed == "negative-size-param"
    if expected == "heap-use-after-free":
        return observed in {"heap-use-after-free", "stack-use-after-return", "stack-use-after-scope"}
    return observed == expected


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


def _strip_go_comments_and_literals(source: str) -> str:
    """Preserve Go token positions while removing comment/string decoys."""
    if not isinstance(source, str) or not source or "\x00" in source \
            or len(source.encode("utf-8")) > MAX_HARNESS_SOURCE_BYTES:
        raise ValueError("Go fuzz harness için sınırlı ve geçerli kaynak metni gerekli.")
    source = source.replace("\r\n", "\n")
    output: list[str] = []
    state = "code"
    escaped = False
    index = 0
    while index < len(source):
        char = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if state == "code":
            if char == "/" and following == "/":
                output.extend((" ", " "))
                state = "line_comment"
                index += 2
                continue
            if char == "/" and following == "*":
                output.extend((" ", " "))
                state = "block_comment"
                index += 2
                continue
            if char == '"':
                output.append(" ")
                state = "string"
                escaped = False
            elif char == "'":
                output.append(" ")
                state = "rune"
                escaped = False
            elif char == "`":
                output.append(" ")
                state = "raw_string"
            else:
                output.append(char)
        elif state == "line_comment":
            output.append("\n" if char == "\n" else " ")
            if char == "\n":
                state = "code"
        elif state == "block_comment":
            if char == "*" and following == "/":
                output.extend((" ", " "))
                state = "code"
                index += 2
                continue
            output.append("\n" if char == "\n" else " ")
        elif state in {"string", "rune"}:
            output.append("\n" if char == "\n" else " ")
            if char == "\n":
                raise ValueError("Go kaynak metninde kapanmamış literal var.")
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif (state == "string" and char == '"') or (state == "rune" and char == "'"):
                state = "code"
        else:
            output.append("\n" if char == "\n" else " ")
            if char == "`":
                state = "code"
        index += 1
    if state not in {"code", "line_comment"}:
        raise ValueError("Go kaynak metninde kapanmamış yorum veya literal var.")
    return "".join(output)


def _go_fuzz_harness(
    finding: dict[str, Any], file_path: str, source_snippet: str, cwe: str,
) -> dict[str, Any]:
    pure_path = PurePosixPath(file_path)
    if not file_path or len(file_path) > 1024 or "\\" in file_path or "\x00" in file_path \
            or pure_path.is_absolute() or not pure_path.parts \
            or any(part in {"", ".", ".."} for part in pure_path.parts):
        raise ValueError("Go fuzz hedef dosyası proje köküne göreli olmalı.")
    cleaned = _strip_go_comments_and_literals(source_snippet)
    packages = _GO_PACKAGE.findall(cleaned)
    if len(packages) != 1 or packages[0] == "_" or packages[0] in _GO_KEYWORDS:
        raise ValueError("Go fuzz harness için tek ve geçerli package bildirimi gerekli.")
    candidates = [
        (name, input_type)
        for name, input_type in _GO_BYTE_OR_STRING_FUNCTION.findall(cleaned)
        if name != "_" and name not in _GO_KEYWORDS
    ]
    requested_values = [finding[key] for key in ("function", "symbol", "function_name") if key in finding]
    if len(set(map(str, requested_values))) > 1:
        raise ValueError("Go fuzz bulgusunda çelişkili hedef fonksiyon adları var.")
    requested = requested_values[0] if requested_values else None
    if requested_values and (
        not isinstance(requested, str)
        or not _GO_IDENTIFIER.fullmatch(requested)
        or requested == "_"
        or requested in _GO_KEYWORDS
    ):
        raise ValueError("Go fuzz hedef fonksiyonu geçerli bir tanımlayıcı olmalı.")
    matching = [(name, input_type) for name, input_type in candidates if requested is None or name == requested]
    if len(matching) != 1:
        raise ValueError("Go fuzz hedefi tek bir top-level []byte veya string fonksiyona çözülmeli.")
    target, input_type = matching[0]
    fuzz_name = f"Fuzz{target}" if target[0].isupper() else f"FuzzSniper{target[0].upper()}{target[1:]}"
    if re.search(rf"(?m)^[ \t]*func[ \t]+{re.escape(fuzz_name)}[ \t]*\(", cleaned):
        raise ValueError("Üretilecek Go fuzz hedefi kaynakta zaten tanımlı.")
    if input_type == "[]byte":
        seeds = "\tf.Add([]byte{})\n\tf.Add([]byte{0})\n"
        parameter = "data []byte"
        argument = "data"
    else:
        seeds = '\tf.Add("")\n\tf.Add("\\x00")\n'
        parameter = "value string"
        argument = "value"
    harness_code = (
        f"package {packages[0]}\n\n"
        'import "testing"\n\n'
        f"func {fuzz_name}(f *testing.F) {{\n"
        f"{seeds}"
        f"\tf.Fuzz(func(t *testing.T, {parameter}) {{\n"
        f"\t\t{target}({argument})\n"
        "\t})\n"
        "}\n"
    )
    stem = re.sub(r"[^A-Za-z0-9_]", "_", Path(file_path).stem)[:80] or "target"
    return {
        "format": "sniper-sanitizer-fuzz-harness/1",
        "language": "go",
        "target_file": file_path,
        "target_function": target,
        "input_type": input_type,
        "cwe": cwe,
        "compile_command": "go test -run=^$ ./...",
        "fuzz_command": f"go test -run=^$ -fuzz=^{fuzz_name}$ -fuzztime=60s ./...",
        "harness_filename": f"{stem}_sniper_fuzz_test.go",
        "harness_code": harness_code,
        "network_required": False,
    }


def _safe_python_fuzz_path(file_path: str) -> PurePosixPath:
    if not file_path or "\x00" in file_path or "\\" in file_path or len(file_path) > 240:
        raise AsanProjectProofError("Python fuzz hedefi güvenli göreli bir .py yolu olmalı.")
    target = PurePosixPath(file_path)
    if target.is_absolute() or target.suffix.casefold() != ".py" or ".." in target.parts:
        raise AsanProjectProofError("Python fuzz hedefi güvenli göreli bir .py yolu olmalı.")
    return target


def _python_fuzz_target(source_snippet: str) -> tuple[str, str]:
    if not isinstance(source_snippet, str) or not source_snippet.strip():
        raise AsanProjectProofError("Python fuzz hedef çözümü için kaynak gerekli.")
    if len(source_snippet.encode("utf-8")) > MAX_PYTHON_FUZZ_SOURCE_BYTES:
        raise AsanProjectProofError("Python fuzz hedef kaynağı 512 KB sınırını aşıyor.")
    try:
        tree = ast.parse(source_snippet, filename="<sniper-python-fuzz-target>")
    except SyntaxError as exc:
        raise AsanProjectProofError("Python fuzz hedef kaynağı ayrıştırılamadı.") from exc

    candidates: list[tuple[str, str]] = []
    for node in tree.body:
        if not isinstance(node, ast.FunctionDef) or not _PYTHON_FUZZ_TARGET_RE.match(node.name):
            continue
        positional = [*node.args.posonlyargs, *node.args.args]
        if (
            len(positional) != 1
            or node.args.vararg is not None
            or node.args.kwarg is not None
            or node.args.kwonlyargs
            or node.args.defaults
        ):
            continue
        annotation = positional[0].annotation
        if isinstance(annotation, ast.Name) and annotation.id in {"bytes", "str"}:
            candidates.append((node.name, annotation.id))

    if len(candidates) != 1:
        raise AsanProjectProofError(
            "Python fuzz kaynağı tam olarak bir üst düzey parse/decode/normalize bytes veya str hedefi içermeli."
        )
    return candidates[0]


def _python_atheris_harness(target_path: PurePosixPath, target_name: str, input_kind: str) -> str:
    target_literal = repr(target_path.as_posix())
    name_literal = repr(target_name)
    input_literal = repr(input_kind)
    return (
        "from __future__ import annotations\n\n"
        "import importlib.util\n"
        "from pathlib import Path\n"
        "import sys\n\n"
        f"_TARGET_RELATIVE_PATH = {target_literal}\n"
        f"_TARGET_SYMBOL = {name_literal}\n"
        f"_TARGET_INPUT = {input_literal}\n"
        "_TARGET = None\n\n"
        "def _load_target():\n"
        "    root = Path(__file__).resolve().parent\n"
        "    target_path = (root / _TARGET_RELATIVE_PATH).resolve()\n"
        "    try:\n"
        "        target_path.relative_to(root)\n"
        "    except ValueError as exc:\n"
        "        raise SystemExit('Python fuzz target escaped the harness root.') from exc\n"
        "    if not target_path.is_file():\n"
        "        raise SystemExit('Python fuzz target file is unavailable.')\n"
        "    spec = importlib.util.spec_from_file_location('_sniper_python_fuzz_target', target_path)\n"
        "    if spec is None or spec.loader is None:\n"
        "        raise SystemExit('Python fuzz target module could not be loaded.')\n"
        "    module = importlib.util.module_from_spec(spec)\n"
        "    sys.modules[spec.name] = module\n"
        "    spec.loader.exec_module(module)\n"
        "    target = getattr(module, _TARGET_SYMBOL, None)\n"
        "    if not callable(target):\n"
        "        raise SystemExit('Python fuzz target symbol is not callable.')\n"
        "    return target\n\n"
        "def TestOneInput(data: bytes) -> None:\n"
        "    if _TARGET is None:\n"
        "        raise RuntimeError('Python fuzz target is not initialized.')\n"
        "    payload = data if _TARGET_INPUT == 'bytes' else data.decode('utf-8', errors='surrogateescape')\n"
        "    try:\n"
        "        _TARGET(payload)\n"
        "    except (ValueError, UnicodeError):\n"
        "        return\n\n"
        "def _atheris_runtime():\n"
        "    try:\n"
        "        import atheris\n"
        "    except ModuleNotFoundError as exc:\n"
        "        if exc.name != 'atheris':\n"
        "            raise\n"
        "        print('Atheris runtime unavailable; install the declared requirement before fuzzing.', file=sys.stderr)\n"
        "        return None\n"
        "    return atheris\n\n"
        "def main() -> int:\n"
        "    global _TARGET\n"
        "    if sys.argv[1:] == ['--check-target']:\n"
        "        _TARGET = _load_target()\n"
        "        TestOneInput(b'')\n"
        "        print(f'SNIPER_PY_FUZZ_TARGET_OK {_TARGET_SYMBOL} {_TARGET_INPUT}')\n"
        "        return 0\n"
        "    atheris = _atheris_runtime()\n"
        "    if atheris is None:\n"
        "        return 2\n"
        "    if sys.argv[1:] == ['--check-runtime']:\n"
        "        print('SNIPER_PY_FUZZ_RUNTIME_OK atheris')\n"
        "        return 0\n"
        "    with atheris.instrument_imports():\n"
        "        _TARGET = _load_target()\n"
        "    atheris.Setup(sys.argv, TestOneInput)\n"
        "    atheris.Fuzz()\n"
        "    return 0\n\n"
        "if __name__ == '__main__':\n"
        "    raise SystemExit(main())\n"
    )


def _mask_java_noncode(source: str) -> str:
    """Mask Java comments, strings, chars and text blocks while preserving offsets/newlines."""
    out = list(source)
    i = 0
    state = "code"
    while i < len(source):
        if state == "code":
            if source.startswith("//", i):
                out[i:i + 2] = "  "
                i += 2
                state = "line"
                continue
            if source.startswith("/*", i):
                out[i:i + 2] = "  "
                i += 2
                state = "block"
                continue
            if source.startswith('"""', i):
                out[i:i + 3] = "   "
                i += 3
                state = "text"
                continue
            if source[i] in {'"', "'"}:
                out[i] = " "
                state = "string" if source[i] == '"' else "char"
                i += 1
                continue
            i += 1
            continue
        if state == "line":
            if source[i] == "\n":
                state = "code"
            else:
                out[i] = " "
            i += 1
            continue
        if state == "block":
            if source.startswith("*/", i):
                out[i:i + 2] = "  "
                i += 2
                state = "code"
            else:
                if source[i] != "\n":
                    out[i] = " "
                i += 1
            continue
        if state == "text":
            if source.startswith('"""', i):
                out[i:i + 3] = "   "
                i += 3
                state = "code"
            else:
                if source[i] != "\n":
                    out[i] = " "
                i += 1
            continue
        quote = '"' if state == "string" else "'"
        if source[i] == "\\" and i + 1 < len(source):
            out[i] = " "
            if source[i + 1] != "\n":
                out[i + 1] = " "
            i += 2
        elif source[i] == quote:
            out[i] = " "
            i += 1
            state = "code"
        else:
            if source[i] != "\n":
                out[i] = " "
            i += 1
    if state not in {"code", "line"}:
        raise AsanProjectProofError("Java kaynak parçasında sonlanmamış yorum veya dize var.")
    return "".join(out)


def _matching_java_brace(source: str, opening: int) -> int | None:
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return index
    return None


def _java_param_signature(params: str) -> str | None:
    value = re.sub(r"\bfinal\s+", "", params).strip()
    if re.fullmatch(rf"byte\s*\[\s*\]\s+{_JAVA_IDENTIFIER}", value):
        return "byte[]"
    if re.fullmatch(rf"(?:java\.lang\.)?String\s+{_JAVA_IDENTIFIER}", value):
        return "String"
    return None


def _java_target(finding: dict[str, Any], source: str) -> tuple[str, str, str, str]:
    if not source.strip():
        raise AsanProjectProofError("Java Jazzer harness için tam yerel kaynak içeriği gerekli.")
    if len(source.encode("utf-8", "ignore")) > MAX_SOURCE_BYTES:
        raise AsanProjectProofError("Java kaynak içeriği boyut sınırını aşıyor.")
    masked = _mask_java_noncode(source)
    packages = _JAVA_PACKAGE_RE.findall(masked)
    if len(packages) > 1:
        raise AsanProjectProofError("Java paket bildirimi belirsiz.")
    package = packages[0] if packages else ""
    file_path = str(finding.get("file") or "")
    pure_path = PurePosixPath(file_path.replace("\\", "/"))
    if not file_path or pure_path.is_absolute() or ".." in pure_path.parts or pure_path.suffix.lower() != ".java":
        raise AsanProjectProofError("Java hedef dosyası göreli ve .java uzantılı olmalı.")
    class_name = pure_path.stem
    if not re.fullmatch(_JAVA_IDENTIFIER, class_name):
        raise AsanProjectProofError("Java hedef sınıfı dosya adından güvenli çözülemedi.")
    if package:
        expected = tuple([*package.split("."), class_name + ".java"])
        parts = pure_path.parts
        if len(parts) < len(expected) or tuple(parts[-len(expected):]) != expected:
            raise AsanProjectProofError("Java paket bildirimi hedef dosya yolu ile eşleşmiyor.")

    classes = [match for match in _JAVA_CLASS_RE.finditer(masked) if match.group("name") == class_name]
    if len(classes) != 1:
        raise AsanProjectProofError("Java hedef sınıf bildirimi tekil değil veya bulunamadı.")
    class_match = classes[0]
    if "public" not in class_match.group("mods").split():
        raise AsanProjectProofError("Java hedef sınıf public olmalı.")
    opening = class_match.end() - 1
    closing = _matching_java_brace(masked, opening)
    if closing is None:
        raise AsanProjectProofError("Java hedef sınıf gövdesi sonlanmıyor.")
    body = masked[opening + 1:closing]
    depths = [0] * (len(body) + 1)
    depth = 0
    for index, char in enumerate(body):
        depths[index] = depth
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
    depths[len(body)] = depth

    methods: list[dict[str, Any]] = []
    for match in _JAVA_METHOD_RE.finditer(body):
        if depths[match.start()] != 0:
            continue
        methods.append({
            "name": match.group("name"),
            "signature": _java_param_signature(match.group("params")),
            "modifiers": frozenset(match.group("mods").split()),
        })
        if len(methods) > 4096:
            raise AsanProjectProofError("Java hedef sınıf yöntem sayısı sınırını aşıyor.")

    raw_symbol = finding.get("symbol") or finding.get("function") or finding.get("method") or ""
    symbol = str(raw_symbol).strip()
    target_name = ""
    requested_signature: str | None = None
    if symbol:
        parsed = _JAVA_SYMBOL_RE.fullmatch(symbol)
        if parsed is None:
            raise AsanProjectProofError("Java hedef symbol biçimi geçersiz; Sınıf#metot(byte[]|String) bekleniyor.")
        symbol_class = parsed.group("class") or ""
        fqcn = f"{package}.{class_name}" if package else class_name
        if symbol_class and symbol_class not in {class_name, fqcn}:
            raise AsanProjectProofError("Java symbol sınıfı hedef dosya sınıfıyla eşleşmiyor.")
        target_name = parsed.group("method")
        raw_signature = parsed.group("signature")
        requested_signature = "byte[]" if raw_signature and re.sub(r"\s+", "", raw_signature) == "byte[]" \
            else ("String" if raw_signature else None)
        named = [method for method in methods if method["name"] == target_name]
        if not named:
            raise AsanProjectProofError(f"Java hedef metodu bulunamadı: {target_name}")
        if requested_signature is None and len(named) != 1:
            raise AsanProjectProofError(f"Java hedef metot overload nedeniyle belirsiz: {target_name}")
        candidates = [
            method for method in named
            if requested_signature is None or method["signature"] == requested_signature
        ]
    else:
        candidates = [
            method for method in methods
            if method["signature"] and _JAVA_TARGET_METHOD_RE.fullmatch(method["name"])
        ]
        if len(candidates) != 1:
            raise AsanProjectProofError("Java parser/decoder/normalizer hedefi tekil çözülemedi.")
        target_name = candidates[0]["name"]

    if len(candidates) != 1 or candidates[0]["signature"] not in {"byte[]", "String"}:
        raise AsanProjectProofError(f"Java hedef imzası byte[] veya String olarak tekil çözülemedi: {target_name}")
    selected = candidates[0]
    if not {"public", "static"}.issubset(selected["modifiers"]):
        raise AsanProjectProofError(f"Java hedef metodu public static olmalı: {target_name}")
    if not _JAVA_TARGET_METHOD_RE.fullmatch(target_name):
        raise AsanProjectProofError("Java hedefi parser/decoder/normalizer metodu değil.")
    return package, class_name, target_name, str(selected["signature"])


def _java_fuzz_harness(finding: dict[str, Any], source_snippet: str, cwe: str) -> dict[str, Any]:
    package, class_name, method, signature = _java_target(finding, source_snippet)
    harness_name = "SniperJazzerHarness"
    fq_harness = f"{package}.{harness_name}" if package else harness_name
    package_line = f"package {package};\n\n" if package else ""
    if signature == "String":
        import_line = "import java.nio.charset.StandardCharsets;\n\n"
        body = (
            "        String input = new String(data, StandardCharsets.UTF_8);\n"
            f"        {class_name}.{method}(input);\n"
        )
    else:
        import_line = ""
        body = f"        {class_name}.{method}(data);\n"
    harness_code = (
        package_line
        + import_line
        + f"public final class {harness_name} {{\n"
        + f"    private {harness_name}() {{}}\n\n"
        + "    public static void fuzzerTestOneInput(byte[] data) throws Throwable {\n"
        + body
        + "    }\n"
        + "}\n"
    )
    compile_command = (
        f'javac -cp "$SNIPER_JVM_CLASSPATH" -d sniper-jazzer-classes {harness_name}.java && '
        f'jazzer --cp="sniper-jazzer-classes:$SNIPER_JVM_CLASSPATH" --target_class={fq_harness}'
    )
    runtime_available = shutil.which("jazzer") is not None
    harness_sha256 = hashlib.sha256(harness_code.encode("utf-8")).hexdigest()
    return {
        "format": "sniper-sanitizer-fuzz-harness/1",
        "language": "java",
        "target_file": str(finding.get("file") or "target.java"),
        "target_class": f"{package}.{class_name}" if package else class_name,
        "target_method": method,
        "target_signature": signature,
        "harness_class": fq_harness,
        "source_sha256": hashlib.sha256(source_snippet.encode("utf-8")).hexdigest(),
        "cwe": cwe,
        "compile_command": compile_command,
        "runtime_requirement": "jazzer",
        "fuzz_engine": "jazzer",
        "runtime_available": runtime_available,
        "readiness": "ready" if runtime_available else "runtime_missing",
        "harness_filename": f"{harness_name}.java",
        "harness_code": harness_code,
        "harness_sha256": harness_sha256,
        "runtime_execution_supported": True,
        "execution": "not_run",
        "limitations": [
            "Jazzer çalıştırılmadı; komut için yerel Jazzer ve proje sınıf yolu gerekir.",
            "Yalnız tekil public static byte[] veya String parser/decoder/normalizer hedefi desteklenir.",
        ],
    }


def _safe_js_fuzz_path(file_path: str) -> PurePosixPath:
    if not file_path or "\x00" in file_path or "\\" in file_path or len(file_path) > 240:
        raise AsanProjectProofError("JavaScript fuzz hedefi güvenli göreli bir kaynak yolu olmalı.")
    target = PurePosixPath(file_path)
    if target.is_absolute() or target.suffix.casefold() not in _JS_FUZZ_SUFFIXES or ".." in target.parts:
        raise AsanProjectProofError("JavaScript fuzz hedefi güvenli göreli bir kaynak yolu olmalı.")
    return target


def _mask_js_comments_and_literals(source: str) -> str:
    """Preserve offsets/newlines while hiding comment, string, and template decoys."""
    out = list(source)
    index = 0
    state = "code"
    while index < len(source):
        char = source[index]
        nxt = source[index + 1] if index + 1 < len(source) else ""
        if state == "code":
            if char == "/" and nxt == "/":
                out[index] = out[index + 1] = " "
                index += 2
                state = "line_comment"
                continue
            if char == "/" and nxt == "*":
                out[index] = out[index + 1] = " "
                index += 2
                state = "block_comment"
                continue
            if char in {"'", '"', "`"}:
                out[index] = " "
                state = {"'": "single", '"': "double", "`": "template"}[char]
                index += 1
                continue
            index += 1
            continue
        if state == "line_comment":
            if char == "\n":
                state = "code"
            else:
                out[index] = " "
            index += 1
            continue
        if state == "block_comment":
            if char == "*" and nxt == "/":
                out[index] = out[index + 1] = " "
                index += 2
                state = "code"
                continue
            if char != "\n":
                out[index] = " "
            index += 1
            continue
        delimiter = {"single": "'", "double": '"', "template": "`"}[state]
        if char == "\\" and index + 1 < len(source):
            out[index] = " "
            if source[index + 1] != "\n":
                out[index + 1] = " "
            index += 2
            continue
        if char == delimiter:
            out[index] = " "
            state = "code"
        elif char != "\n":
            out[index] = " "
        index += 1
    return "".join(out)


def _js_parameter_kind(source: str, function_start: int, parameter: str) -> tuple[str, str] | None:
    typed = re.fullmatch(
        r"([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(Buffer|Uint8Array|string)",
        parameter.strip(),
    )
    if typed is not None:
        return typed.group(1), typed.group(2).casefold()

    plain = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*)", parameter.strip())
    if plain is None:
        return None
    prefix = source[:function_start]
    doc = re.search(r"/\*\*([\s\S]*?)\*/\s*$", prefix)
    if doc is None:
        return None
    param_name = re.escape(plain.group(1))
    annotation = re.search(
        rf"@param\s+\{{\s*(Buffer|Uint8Array|string)\s*\}}\s+{param_name}\b",
        doc.group(1),
    )
    if annotation is None:
        return None
    return plain.group(1), annotation.group(1).casefold()


def _js_fuzz_target(source_snippet: str) -> tuple[str, str]:
    if not isinstance(source_snippet, str) or not source_snippet.strip():
        raise AsanProjectProofError("JavaScript fuzz hedef çözümü için kaynak gerekli.")
    if len(source_snippet.encode("utf-8")) > MAX_JS_FUZZ_SOURCE_BYTES:
        raise AsanProjectProofError("JavaScript fuzz hedef kaynağı 512 KB sınırını aşıyor.")
    masked = _mask_js_comments_and_literals(source_snippet)
    candidates: list[tuple[str, str]] = []
    for match in _JS_EXPORTED_FUNCTION_RE.finditer(masked):
        prefix = masked[:match.start()]
        if prefix.count("{") != prefix.count("}"):
            continue
        resolved = _js_parameter_kind(source_snippet, match.start(), match.group(2))
        if resolved is not None:
            candidates.append((match.group(1), resolved[1]))
    if len(candidates) != 1:
        raise AsanProjectProofError(
            "JavaScript fuzz kaynağı tam olarak bir doğrudan export edilen parse/decode/normalize Buffer, "
            "Uint8Array veya string hedefi içermeli."
        )
    return candidates[0]


def _node_package_available(package_name: str) -> bool:
    node = shutil.which("node")
    if node is None:
        return False
    try:
        result = subprocess.run(
            [node, "-e", f"require.resolve({package_name!r})"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def _js_fast_check_harness(target_path: PurePosixPath, target_name: str, input_kind: str) -> str:
    return (
        "import { dirname, isAbsolute, relative, resolve } from 'node:path';\n"
        "import { fileURLToPath, pathToFileURL } from 'node:url';\n\n"
        f"const TARGET_RELATIVE_PATH = {json.dumps(target_path.as_posix())};\n"
        f"const TARGET_SYMBOL = {json.dumps(target_name)};\n"
        f"const TARGET_INPUT = {json.dumps(input_kind)};\n\n"
        "async function loadTarget() {\n"
        "  const root = dirname(fileURLToPath(import.meta.url));\n"
        "  const targetPath = resolve(root, TARGET_RELATIVE_PATH);\n"
        "  const rel = relative(root, targetPath);\n"
        "  if (!rel || rel.startsWith('..') || isAbsolute(rel)) {\n"
        "    throw new Error('JavaScript fuzz target escaped the harness root.');\n"
        "  }\n"
        "  const targetModule = await import(pathToFileURL(targetPath).href);\n"
        "  const target = targetModule[TARGET_SYMBOL];\n"
        "  if (typeof target !== 'function') {\n"
        "    throw new Error('JavaScript fuzz target symbol is not callable.');\n"
        "  }\n"
        "  return target;\n"
        "}\n\n"
        "function coerceInput(value) {\n"
        "  if (TARGET_INPUT === 'buffer') return Buffer.from(value);\n"
        "  if (TARGET_INPUT === 'uint8array') return new Uint8Array(value);\n"
        "  return value;\n"
        "}\n\n"
        "function exercise(target, value) {\n"
        "  try {\n"
        "    target(coerceInput(value));\n"
        "  } catch (error) {\n"
        "    if (error instanceof SyntaxError || error instanceof URIError) return true;\n"
        "    throw error;\n"
        "  }\n"
        "  return true;\n"
        "}\n\n"
        "async function loadFastCheck() {\n"
        "  try {\n"
        "    const loaded = await import('fast-check');\n"
        "    return loaded.default ?? loaded;\n"
        "  } catch (error) {\n"
        "    if (error?.code !== 'ERR_MODULE_NOT_FOUND' || !String(error.message).includes('fast-check')) throw error;\n"
        "    console.error('fast-check runtime unavailable; install the declared requirement before fuzzing.');\n"
        "    return null;\n"
        "  }\n"
        "}\n\n"
        "async function main() {\n"
        "  const args = process.argv.slice(2);\n"
        "  if (args.length === 1 && args[0] === '--check-target') {\n"
        "    const target = await loadTarget();\n"
        "    const sample = TARGET_INPUT === 'string' ? '' : new Uint8Array();\n"
        "    exercise(target, sample);\n"
        "    console.log(`SNIPER_JS_FUZZ_TARGET_OK ${TARGET_SYMBOL} ${TARGET_INPUT}`);\n"
        "    return 0;\n"
        "  }\n"
        "  const fc = await loadFastCheck();\n"
        "  if (fc === null) return 2;\n"
        "  if (args.length === 1 && args[0] === '--check-runtime') {\n"
        "    console.log('SNIPER_JS_FUZZ_RUNTIME_OK fast-check');\n"
        "    return 0;\n"
        "  }\n"
        "  const target = await loadTarget();\n"
        "  const readBound = (name, fallback, minimum, maximum) => {\n"
        "    const raw = process.env[name];\n"
        "    if (raw === undefined) return fallback;\n"
        "    if (!/^[0-9]+$/.test(raw)) throw new Error(`${name} must be a bounded integer`);\n"
        "    const value = Number(raw);\n"
        "    if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {\n"
        "      throw new Error(`${name} is outside the accepted bounds`);\n"
        "    }\n"
        "    return value;\n"
        "  };\n"
        "  const numRuns = readBound('SNIPER_FUZZ_RUNS', 1000, 1, 10000);\n"
        "  const seed = readBound('SNIPER_FUZZ_SEED', 1, 0, 2147483647);\n"
        "  const maxLength = readBound('SNIPER_FUZZ_MAX_INPUT_BYTES', 4096, 1, 1048576);\n"
        "  const arbitrary = TARGET_INPUT === 'string'\n"
        "    ? fc.string({ maxLength })\n"
        "    : fc.uint8Array({ maxLength });\n"
        "  fc.assert(fc.property(arbitrary, (value) => exercise(target, value)), { numRuns, seed });\n"
        "  return 0;\n"
        "}\n\n"
        "main().then((code) => { process.exitCode = code; }).catch((error) => {\n"
        "  console.error(error?.stack ?? String(error));\n"
        "  process.exitCode = 1;\n"
        "});\n"
    )


def synthesize_sanitizer_fuzz_harness(
    finding: dict[str, Any],
    *,
    source_snippet: str = "",
) -> dict[str, Any]:
    """Synthesize a bounded C/C++, Rust, Go, Python, JVM, or JS/TS fuzz harness."""
    if not isinstance(finding, dict):
        raise ValueError("Fuzz harness bulgusu nesne olmalı.")
    file_path = str(finding.get("file") or "target.c")
    cwe = str(finding.get("reference") or finding.get("cwe") or "CWE-787")
    suffix = PurePosixPath(file_path.replace("\\", "/")).suffix.casefold()

    if suffix == ".go":
        return _go_fuzz_harness(finding, file_path, source_snippet, cwe)

    if suffix == ".py":
        target_path = _safe_python_fuzz_path(file_path)
        target_name, input_kind = _python_fuzz_target(source_snippet)
        harness_filename = f"fuzz_{target_name}.py"
        harness_code = _python_atheris_harness(target_path, target_name, input_kind)
        source_sha256 = hashlib.sha256(source_snippet.encode("utf-8")).hexdigest()
        harness_sha256 = hashlib.sha256(harness_code.encode("utf-8")).hexdigest()
        runtime_available = importlib.util.find_spec("atheris") is not None
        return {
            "format": "sniper-sanitizer-fuzz-harness/1",
            "language": "python",
            "target_file": target_path.as_posix(),
            "target_symbol": target_name,
            "target_input": input_kind,
            "source_sha256": source_sha256,
            "cwe": cwe,
            "fuzz_engine": "atheris",
            "runtime_requirement": "atheris",
            "runtime_available": runtime_available,
            "readiness": "ready" if runtime_available else "runtime_missing",
            "execution": "not_run",
            "compile_command": f"python -m py_compile {harness_filename}",
            "target_check_command": f"python {harness_filename} --check-target",
            "runtime_check_command": f"python {harness_filename} --check-runtime",
            "run_command": f"python {harness_filename} -max_total_time=60",
            "harness_filename": harness_filename,
            "harness_code": harness_code,
            "harness_sha256": harness_sha256,
            "runtime_execution_supported": True,
        }

    if suffix == ".java":
        return _java_fuzz_harness(finding, source_snippet, cwe)

    if suffix in _JS_FUZZ_SUFFIXES:
        target_path = _safe_js_fuzz_path(file_path)
        target_name, input_kind = _js_fuzz_target(source_snippet)
        harness_filename = f"fuzz_{target_name}.mjs"
        language = "typescript" if suffix in {".ts", ".mts"} else "javascript"
        runtime_available = _node_package_available("fast-check")
        harness_code = _js_fast_check_harness(target_path, target_name, input_kind)
        source_sha256 = hashlib.sha256(source_snippet.encode("utf-8")).hexdigest()
        harness_sha256 = hashlib.sha256(harness_code.encode("utf-8")).hexdigest()
        return {
            "format": "sniper-sanitizer-fuzz-harness/1",
            "language": language,
            "target_file": target_path.as_posix(),
            "target_symbol": target_name,
            "target_input": input_kind,
            "source_sha256": source_sha256,
            "cwe": cwe,
            "fuzz_engine": "fast-check",
            "runtime_requirement": "fast-check",
            "node_available": shutil.which("node") is not None,
            "runtime_available": runtime_available,
            "readiness": "ready" if runtime_available else "runtime_missing",
            "execution": "not_run",
            "compile_command": f"node --check {harness_filename}",
            "target_check_command": f"node {harness_filename} --check-target",
            "runtime_check_command": f"node {harness_filename} --check-runtime",
            "run_command": f"node {harness_filename}",
            "harness_filename": harness_filename,
            "harness_code": harness_code,
            "harness_sha256": harness_sha256,
            "runtime_execution_supported": True,
        }

    is_rust = suffix == ".rs"

    if is_rust:
        harness_code = (
            "#![no_main]\n"
            "use libfuzzer_sys::fuzz_target;\n"
            "fuzz_target!(|data: &[u8]| {\n"
            "    if data.len() >= 16 {\n"
            "        // Sniper synthesized bounds/overflow sanitizer harness\n"
            "    }\n"
            "});\n"
        )
        compile_command = "cargo +nightly fuzz run sniper_target -- -max_total_time=60 && cargo +nightly miri test"
    else:
        harness_code = (
            "#include <stdint.h>\n"
            "#include <stddef.h>\n"
            'extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n'
            "    if (size < 4) return 0;\n"
            "    return 0;\n"
            "}\n"
        )
        compile_command = "clang -g -O1 -fsanitize=fuzzer,address,undefined harness.cc -o sniper_fuzz_harness"

    return {
        "format": "sniper-sanitizer-fuzz-harness/1",
        "language": "rust" if is_rust else "c_cpp",
        "target_file": file_path,
        "cwe": cwe,
        "compile_command": compile_command,
        "harness_filename": "fuzz_target.rs" if is_rust else "fuzz_harness.cc",
        "harness_code": harness_code,
    }


def execute_sanitizer_fuzz_runtime(
    finding: dict[str, Any],
    *,
    source_snippet: str,
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
    """Run one synthesized Atheris, Jazzer or fast-check harness offline.

    Optional runtimes are never fetched and never selected from ``PATH``.  The
    operator supplies exact paths plus SHA-256 pins; incomplete configuration is
    reported as ``runtime_missing/not_run`` rather than being mistaken for proof.
    """
    harness = synthesize_sanitizer_fuzz_harness(finding, source_snippet=source_snippet)
    try:
        return fuzz_runtime.execute(
            harness,
            project_root=project_root,
            confirm_local=confirm_local,
            runtime_path=runtime_path,
            runtime_sha256=runtime_sha256,
            support_path=support_path,
            support_sha256=support_sha256,
            compiler_path=compiler_path,
            compiler_sha256=compiler_sha256,
            runtime_root=runtime_root,
            max_runs=max_runs,
            seed=seed,
            max_input_bytes=max_input_bytes,
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
        )
    except fuzz_runtime.FuzzRuntimeError as exc:
        raise AsanProjectProofError(str(exc)) from exc

def _safe_rel_fuzz_member(raw_path: str) -> PurePosixPath:
    norm = str(raw_path or "target.py").replace("\\", "/").lstrip("/")
    p = PurePosixPath(norm)
    parts = [part for part in p.parts if part not in {"", ".", ".."}]
    return PurePosixPath(*parts) if parts else PurePosixPath("target.py")


def execute_bounded_fuzz_harness(
    harness_bundle: dict[str, Any],
    *,
    target_source: str = "",
    timeout_sec: int = 5,
    seeds: list[bytes | str] | None = None,
) -> dict[str, Any]:
    """Execute a synthesized fuzz harness in an isolated temp directory with bounded timeout."""
    import sys

    if not isinstance(harness_bundle, dict) or harness_bundle.get("format") != "sniper-sanitizer-fuzz-harness/1":
        raise AsanProjectProofError("Geçersiz fuzz harness paketi; sniper-sanitizer-fuzz-harness/1 bekleniyor.")

    bounded_timeout = max(1, min(int(timeout_sec), 15))
    lang = str(harness_bundle.get("language") or "").strip().casefold()
    runtime_avail = bool(harness_bundle.get("runtime_available", False))
    target_rel = _safe_rel_fuzz_member(str(harness_bundle.get("target_file") or "target.py"))
    harness_rel = _safe_rel_fuzz_member(str(harness_bundle.get("harness_filename") or "fuzz_harness.py"))
    harness_code = str(harness_bundle.get("harness_code") or "")
    effective_source = target_source if isinstance(target_source, str) and target_source else str(
        harness_bundle.get("target_source") or ""
    )

    if not harness_code.strip():
        raise AsanProjectProofError("Fuzz harness kodu boş olamaz.")

    if lang not in {"python", "javascript", "typescript"}:
        return {
            "format": "sniper-bounded-fuzz-execution/1",
            "language": lang,
            "target_verified": False,
            "runtime_available": runtime_avail,
            "execution": "unsupported_language_or_runtime_missing",
            "crash_reproduced": False,
            "exit_code": -1,
        }

    target_ok = False
    crash_reproduced = False
    exec_status = "target_verification_failed"
    rc = -1

    with tempfile.TemporaryDirectory(prefix="sniper_bounded_fuzz_") as tmp_dir:
        root = Path(tmp_dir).resolve()
        target_file_path = (root / target_rel.as_posix()).resolve()
        harness_file_path = (root / harness_rel.as_posix()).resolve()
        target_file_path.relative_to(root)
        harness_file_path.relative_to(root)

        if effective_source:
            target_file_path.parent.mkdir(parents=True, exist_ok=True)
            target_file_path.write_text(effective_source, encoding="utf-8")

        harness_file_path.parent.mkdir(parents=True, exist_ok=True)
        harness_file_path.write_text(harness_code, encoding="utf-8")

        if lang == "python":
            check_cmd = [sys.executable, harness_rel.as_posix(), "--check-target"]
        else:
            node_bin = shutil.which("node")
            if node_bin is None:
                return {
                    "format": "sniper-bounded-fuzz-execution/1",
                    "language": lang,
                    "target_verified": False,
                    "runtime_available": False,
                    "execution": "node_runtime_missing",
                    "crash_reproduced": False,
                    "exit_code": -1,
                }
            check_cmd = [node_bin, harness_rel.as_posix(), "--check-target"]

        try:
            proc = subprocess.run(
                check_cmd,
                cwd=str(root),
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=bounded_timeout,
                check=False,
            )
            rc = proc.returncode
            stdout_text = proc.stdout or ""
            stderr_text = proc.stderr or ""
        except subprocess.TimeoutExpired:
            return {
                "format": "sniper-bounded-fuzz-execution/1",
                "language": lang,
                "target_verified": False,
                "runtime_available": runtime_avail,
                "execution": "timeout",
                "crash_reproduced": False,
                "exit_code": 124,
            }

        if rc == 0 and "_FUZZ_TARGET_OK" in stdout_text:
            target_ok = True
        elif rc != 0 and "fuzz target " not in stderr_text.casefold() and (
            "traceback" in stderr_text.casefold() or "error" in stderr_text.casefold()
        ):
            target_ok = True
            crash_reproduced = True
            exec_status = "crash_reproduced"

        if target_ok and not crash_reproduced and lang == "python":
            target_symbol = str(harness_bundle.get("target_symbol") or "")
            target_input = str(harness_bundle.get("target_input") or "bytes")
            probe_seeds: list[bytes] = []
            if seeds is not None:
                for s in seeds[:32]:
                    probe_seeds.append(s.encode("utf-8") if isinstance(s, str) else bytes(s))
                allow_value_error_crash = True
            else:
                probe_seeds = [b"", b"\x00", b"CRASH", b"A" * 32, b"\xff\xff\xff\xff"]
                allow_value_error_crash = False

            probe_script = (
                "import importlib.util, json, sys\n"
                "from pathlib import Path\n"
                f"spec = importlib.util.spec_from_file_location('_t', Path({target_rel.as_posix()!r}).resolve())\n"
                "mod = importlib.util.module_from_spec(spec)\n"
                "spec.loader.exec_module(mod)\n"
                f"fn = getattr(mod, {target_symbol!r})\n"
                f"seeds = {[list(b) for b in probe_seeds]!r}\n"
                f"input_kind = {target_input!r}\n"
                f"allow_ve = {allow_value_error_crash!r}\n"
                "for raw in seeds:\n"
                "    b = bytes(raw)\n"
                "    val = b if input_kind == 'bytes' else b.decode('utf-8', errors='surrogateescape')\n"
                "    try:\n"
                "        fn(val)\n"
                "    except UnicodeError:\n"
                "        continue\n"
                "    except ValueError as exc:\n"
                "        msg = str(exc).lower()\n"
                "        if allow_ve or any(k in msg for k in ('crash', 'boom', 'oob', 'overflow', 'panic')):\n"
                "            raise\n"
                "        continue\n"
            )
            try:
                seed_proc = subprocess.run(
                    [sys.executable, "-c", probe_script],
                    cwd=str(root),
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    timeout=bounded_timeout,
                    check=False,
                )
                if seed_proc.returncode != 0:
                    crash_reproduced = True
                    rc = seed_proc.returncode
                    exec_status = "crash_reproduced"
            except subprocess.TimeoutExpired:
                crash_reproduced = True
                rc = 124
                exec_status = "crash_reproduced"

        if target_ok and not crash_reproduced:
            if runtime_avail:
                run_cmd = (
                    [sys.executable, harness_rel.as_posix(), f"-max_total_time={bounded_timeout}", "-runs=100"]
                    if lang == "python"
                    else [shutil.which("node") or "node", harness_rel.as_posix()]
                )
                try:
                    fuzz_proc = subprocess.run(
                        run_cmd,
                        cwd=str(root),
                        stdin=subprocess.DEVNULL,
                        capture_output=True,
                        text=True,
                        timeout=bounded_timeout,
                        check=False,
                    )
                    rc = fuzz_proc.returncode
                    if rc != 0:
                        crash_reproduced = True
                        exec_status = "crash_reproduced"
                    else:
                        exec_status = "bounded_fuzz_completed"
                except subprocess.TimeoutExpired:
                    exec_status = "bounded_fuzz_completed"
                    rc = 0
            else:
                exec_status = "target_verified_runtime_missing"

    return {
        "format": "sniper-bounded-fuzz-execution/1",
        "language": lang,
        "target_verified": target_ok,
        "runtime_available": runtime_avail,
        "execution": exec_status,
        "crash_reproduced": crash_reproduced,
        "exit_code": rc,
    }

