"""Sabit C fixture'larıyla AddressSanitizer derleme/çalışma zamanı öz sınaması.

Kullanıcı projesi, derleme sistemi, ağ veya kabuk çalıştırılmaz. Temiz ve kasıtlı heap-use-after-free fixture'ları
aynı güvenilir sistem clang/GCC ikilisiyle geçici 0700 dizinde derlenir; yalnız toplu sonuç ve hash'ler döndürülür.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import threading
from typing import Any

FORMAT = "sniper-asan-selftest/1"
COMPILE_TIMEOUT = 20
RUN_TIMEOUT = 5
MAX_OUTPUT = 256_000
_LOCK = threading.Lock()

FIXTURES = {
    "clean": """#include <stdlib.h>
int main(void) {
    int *p = (int *)malloc(sizeof(int));
    if (p == NULL) return 2;
    *p = 7;
    int value = *p;
    free(p);
    return value == 7 ? 0 : 3;
}
""",
    "uaf": """#include <stdlib.h>
volatile int sniper_asan_sink;
int main(void) {
    int *p = (int *)malloc(sizeof(int));
    if (p == NULL) return 2;
    *p = 7;
    free(p);
    sniper_asan_sink = *p;
    return 0;
}
""",
}


class AsanSelftestError(ValueError):
    """Geçersiz onay ya da çalışma zamanı sonucu."""


class AsanUnavailable(AsanSelftestError):
    """Güvenilir clang/ASan çalışma zamanı kullanılamıyor."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _compiler(configured: str) -> tuple[Path, str]:
    path = Path(configured)
    if not path.is_absolute() or not re.fullmatch(r"(?:clang|gcc)(?:-[0-9]+)?", path.name):
        raise AsanUnavailable("ASan öz sınaması için mutlak clang veya gcc yolu gerekli.")
    try:
        resolved = path.resolve(strict=True)
        meta = resolved.stat()
    except OSError as exc:
        raise AsanUnavailable("Clang/GCC bulunamadı.") from exc
    if not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0 or meta.st_mode & 0o022 or not os.access(resolved, os.X_OK):
        raise AsanUnavailable("Derleyici güvenilir sistem ikilisi değil.")
    digest = _sha256(resolved)
    expected = os.environ.get("SNIPER_CLANG_ASAN_SHA256", "").strip().lower()
    if expected and (not re.fullmatch(r"[0-9a-f]{64}", expected) or expected != digest):
        raise AsanUnavailable("Derleyici SHA-256 sabitlemesi eşleşmedi.")
    return resolved, digest


def _limit(pid: int, *, runtime: bool) -> None:
    try:
        import resource

        resource.prlimit(pid, resource.RLIMIT_CPU, ((RUN_TIMEOUT if runtime else COMPILE_TIMEOUT) + 2,) * 2)
        resource.prlimit(pid, resource.RLIMIT_CORE, (0, 0))
        resource.prlimit(pid, resource.RLIMIT_FSIZE, (16 * 1024 * 1024, 16 * 1024 * 1024))
        if not runtime:
            resource.prlimit(pid, resource.RLIMIT_AS, (2 << 30, 2 << 30))
    except (ImportError, ValueError, OSError, AttributeError):
        pass


def _execute(argv: list[str], *, cwd: Path, env: dict[str, str], timeout: int, runtime: bool) -> tuple[int, bytes, bytes]:
    try:
        with subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, start_new_session=True) as process:
            _limit(process.pid, runtime=runtime)
            try:
                out, err = process.communicate(timeout=timeout)
            except subprocess.TimeoutExpired as exc:
                import process_group_runner

                process_group_runner.kill_process_group(process)
                process.communicate(timeout=2)
                raise AsanUnavailable("ASan öz sınaması süre sınırını aştı.") from exc
            return int(process.returncode), (out or b"")[:MAX_OUTPUT], (err or b"")[:MAX_OUTPUT]
    except OSError as exc:
        raise AsanUnavailable("ASan öz sınaması başlatılamadı.") from exc


def _fixture(clang: Path, work: Path, name: str, source: str) -> dict[str, Any]:
    source_path, binary_path = work / f"{name}.c", work / name
    fd = os.open(source_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, source.encode("ascii"))
    finally:
        os.close(fd)
    compile_env = {"PATH": "/usr/bin:/bin", "HOME": str(work), "TMPDIR": str(work), "LC_ALL": "C"}
    diagnostics = ["-fno-caret-diagnostics"] if clang.name.startswith("clang") \
        else ["-fno-diagnostics-show-caret", "-fdiagnostics-color=never"]
    command = [str(clang), "-x", "c", "-std=c11", "-O0", "-g0", "-fsanitize=address",
               "-fno-omit-frame-pointer", *diagnostics, str(source_path), "-o", str(binary_path)]
    code, _out, _err = _execute(command, cwd=work, env=compile_env, timeout=COMPILE_TIMEOUT, runtime=False)
    if code != 0 or not binary_path.is_file():
        raise AsanUnavailable(f"{name} ASan fixture'ı derlenemedi.")
    run_env = {**compile_env, "ASAN_OPTIONS": "abort_on_error=1:halt_on_error=1:detect_leaks=0:symbolize=0"}
    code, out, err = _execute([str(binary_path)], cwd=work, env=run_env, timeout=RUN_TIMEOUT, runtime=True)
    diagnostic = (err + b"\n" + out).decode("utf-8", "replace")
    return {"compiled": True, "exit_ok": code == 0, "asan_error": "AddressSanitizer" in diagnostic,
            "error_class": "heap-use-after-free" if "heap-use-after-free" in diagnostic else ""}


def run(*, confirm_local: object) -> dict[str, Any]:
    if confirm_local is not True:
        raise AsanSelftestError("ASan öz sınaması için confirm_local tam olarak true olmalı.")
    if not _LOCK.acquire(blocking=False):
        raise AsanUnavailable("Başka bir ASan öz sınaması çalışıyor.")
    try:
        explicitly_configured = "SNIPER_CLANG_BINARY" in os.environ
        candidates = [os.environ["SNIPER_CLANG_BINARY"]] if explicitly_configured else ["/usr/bin/clang", "/usr/bin/gcc"]
        last_error: AsanUnavailable | None = None
        for candidate in candidates:
            try:
                clang, clang_sha = _compiler(candidate)
                work = Path(tempfile.mkdtemp(prefix="sniper-asan-selftest-"))
                os.chmod(work, 0o700)
                try:
                    clean = _fixture(clang, work, "clean", FIXTURES["clean"])
                    uaf = _fixture(clang, work, "uaf", FIXTURES["uaf"])
                finally:
                    shutil.rmtree(work, ignore_errors=True)
                break
            except AsanUnavailable as exc:
                last_error = exc
                if explicitly_configured:
                    raise
        else:
            raise last_error or AsanUnavailable("Clang/GCC ASan çalışma zamanı bulunamadı.")
    finally:
        _LOCK.release()
    clean_public = {key: clean[key] for key in ("compiled", "exit_ok", "asan_error")}
    uaf_public = {key: uaf[key] for key in ("compiled", "exit_ok", "asan_error", "error_class")}
    passed = clean_public == {"compiled": True, "exit_ok": True, "asan_error": False} \
        and uaf_public == {"compiled": True, "exit_ok": False, "asan_error": True,
                           "error_class": "heap-use-after-free"}
    return {
        "format": FORMAT,
        "available": True,
        "verdict": "passed" if passed else "failed",
        "clean": clean_public,
        "uaf": uaf_public,
        "fixture_sha256": {name: hashlib.sha256(source.encode("ascii")).hexdigest()
                           for name, source in FIXTURES.items()},
        "compiler": clang.name,
        "compiler_sha256": clang_sha,
        "project_code_executed": False,
        "network_used": False,
    }
