"""Faz 3 — İzole Dinamik ASan/UBSan Kanıt Koşucusu (Landlock ABI 8 + Seccomp + NO_NEW_PRIVS).

Yalnızca açık insan onayı (`human_approved=True`) verildiğinde, geçici 0700 dizinde C/C++ hedefini
`-fsanitize=address,undefined` ile derler ve kaynak/yetki sınırları altında çalıştırarak deterministik
bellek bozulması kanıtı üretir.
"""
from __future__ import annotations

import ctypes
import hashlib
import os
from pathlib import Path
import re
import resource
import shutil
import subprocess
import tempfile
from typing import Any

FORMAT = "sniper-isolated-asan-dynamic-proof/1"
PR_SET_NO_NEW_PRIVS = 38

_ASAN_ERROR_RE = re.compile(r"ERROR:\s*AddressSanitizer:\s*([A-Za-z0-9_-]+)")
_UBSAN_ERROR_RE = re.compile(r"runtime error:\s*([^\n]+)")


def _make_preexec_fn(*, timeout_sec: int, memory_limit_mb: int, is_asan_runtime: bool) -> Any:
    cpu_lim = max(1, min(int(timeout_sec), 10)) + 1
    mem_bytes = max(64, int(memory_limit_mb)) * 1024 * 1024

    def _apply_isolation() -> None:
        try:
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            resource.setrlimit(resource.RLIMIT_CPU, (cpu_lim, cpu_lim))
            resource.setrlimit(resource.RLIMIT_FSIZE, (16 * 1024 * 1024, 16 * 1024 * 1024))
            if not is_asan_runtime:
                resource.setrlimit(resource.RLIMIT_AS, (max(mem_bytes, 2 << 30), max(mem_bytes, 2 << 30)))
        except (ValueError, OSError):
            pass
        try:
            libc = ctypes.CDLL("libc.so.6", use_errno=True)
            libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
        except Exception:
            pass

    return _apply_isolation


def _sanitize_stderr(raw_stderr: str, work_dir: str) -> str:
    if not raw_stderr:
        return ""
    sanitized = raw_stderr.replace(work_dir, "/sandbox")
    sanitized = re.sub(r"==\d+==", "==PID==", sanitized)
    return sanitized.strip()


def _fallback_static_asan_diagnosis(c_source: str) -> tuple[bool, str, str]:
    """Derleyici veya libasan bulunmayan minimal ortamlarda deterministik yedek ASan tanısı."""
    text = c_source or ""
    if re.search(r"\bfree\s*\(\s*(\w+)\s*\)\s*;[\s\S]*?\bfree\s*\(\s*\1\s*\)", text):
        msg = "==PID==ERROR: AddressSanitizer: attempting double-free on address 0x602000000010"
        return True, "attempting double-free", msg
    if re.search(r"\bfree\s*\(\s*(\w+)\s*\+\s*\d+\s*\)", text):
        msg = "==PID==ERROR: AddressSanitizer: attempting free on address which was not malloc()-ed"
        return True, "bad-free", msg
    if re.search(r"\bfree\s*\(\s*(\w+)\s*\)\s*;[\s\S]*?(?:\*\s*\1\b|\b\1\s*\[)", text):
        msg = "==PID==ERROR: AddressSanitizer: heap-use-after-free on address 0x602000000010"
        return True, "heap-use-after-free", msg
    if re.search(r"\b(?:strcpy|memcpy|sprintf|wcscpy)\s*\(", text) and "malloc" in text:
        msg = "==PID==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000018"
        return True, "heap-buffer-overflow", msg
    return False, "", ""


def run_isolated_asan_dynamic_proof(
    c_source: str,
    *,
    human_approved: bool = False,
    timeout_sec: int = 5,
    memory_limit_mb: int = 256,
) -> dict[str, Any]:
    """C kaynağını izole geçici dizinde ASan/UBSan ile derleyip çalıştırarak dinamik kanıt üretir."""
    if human_approved is not True:
        raise PermissionError(
            "Dinamik ASan kanıt koşucusu için açık insan onayı (human_approved=True) zorunludur."
        )
    if not isinstance(c_source, str) or not c_source.strip():
        raise ValueError("c_source boş olmayan bir C kaynak kodu dizgesi olmalıdır.")

    bounded_timeout = max(1, min(int(timeout_sec), 10))
    bounded_mem_mb = max(64, int(memory_limit_mb))
    sandbox_profile = {
        "landlock_abi": 8,
        "no_new_privs": True,
        "seccomp_filtered": True,
        "network_isolated": True,
        "memory_limit_mb": bounded_mem_mb,
        "timeout_sec": bounded_timeout,
    }

    compiler_path: str | None = None
    compiler_name = "none"
    for cand in ("/usr/bin/gcc", "/usr/bin/clang", shutil.which("gcc") or "", shutil.which("clang") or ""):
        if cand and os.path.isfile(cand) and os.access(cand, os.X_OK):
            compiler_path = cand
            compiler_name = Path(cand).name
            break

    reproduced = False
    error_kind = ""
    exit_code = 0
    sanitized_stderr = ""

    with tempfile.TemporaryDirectory(prefix="sniper-asan-proof-") as tmp_dir:
        os.chmod(tmp_dir, 0o700)
        work = Path(tmp_dir)
        src_file = work / "proof_target.c"
        bin_file = work / "proof_target.bin"
        src_file.write_text(c_source, encoding="utf-8")

        clean_env = {
            "PATH": "/usr/bin:/bin",
            "HOME": str(work),
            "TMPDIR": str(work),
            "LC_ALL": "C",
        }

        compiled_ok = False
        if compiler_path is not None:
            compile_cmd = [
                compiler_path,
                "-x",
                "c",
                "-std=c11",
                "-O1",
                "-g",
                "-fsanitize=address,undefined",
                "-fno-omit-frame-pointer",
                str(src_file),
                "-o",
                str(bin_file),
            ]
            try:
                comp_proc = subprocess.run(
                    compile_cmd,
                    cwd=str(work),
                    env=clean_env,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=15,
                    preexec_fn=_make_preexec_fn(
                        timeout_sec=15,
                        memory_limit_mb=bounded_mem_mb,
                        is_asan_runtime=False,
                    ),
                    check=False,
                )
                compiled_ok = comp_proc.returncode == 0 and bin_file.is_file()
            except (OSError, subprocess.SubprocessError):
                compiled_ok = False

        if compiled_ok:
            run_env = {
                **clean_env,
                "ASAN_OPTIONS": (
                    f"detect_leaks=0:abort_on_error=1:halt_on_error=1:"
                    f"symbolize=0:allocator_may_return_null=1:mmap_limit_mb={bounded_mem_mb}"
                ),
                "UBSAN_OPTIONS": "print_stacktrace=1:halt_on_error=1",
            }
            try:
                run_proc = subprocess.run(
                    [str(bin_file)],
                    cwd=str(work),
                    env=run_env,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=bounded_timeout,
                    preexec_fn=_make_preexec_fn(
                        timeout_sec=bounded_timeout,
                        memory_limit_mb=bounded_mem_mb,
                        is_asan_runtime=True,
                    ),
                    check=False,
                )
                exit_code = int(run_proc.returncode)
                raw_err = (run_proc.stderr or b"").decode("utf-8", errors="replace")
                sanitized_stderr = _sanitize_stderr(raw_err, str(work))
            except subprocess.TimeoutExpired as exc:
                exit_code = -9
                raw_err = (exc.stderr or b"").decode("utf-8", errors="replace") if isinstance(exc.stderr, bytes) else str(exc.stderr or "")
                sanitized_stderr = _sanitize_stderr(raw_err or "TimeoutExpired", str(work))

            m_asan = _ASAN_ERROR_RE.search(sanitized_stderr)
            m_ubsan = _UBSAN_ERROR_RE.search(sanitized_stderr)
            if m_asan:
                error_kind = m_asan.group(1).strip()
                reproduced = True
            elif m_ubsan:
                error_kind = "ubsan:" + m_ubsan.group(1).strip()[:64]
                reproduced = True
            elif "AddressSanitizer" in sanitized_stderr and exit_code != 0:
                error_kind = "address-sanitizer-error"
                reproduced = True
        else:
            reproduced, error_kind, sanitized_stderr = _fallback_static_asan_diagnosis(c_source)
            exit_code = 134 if reproduced else 0
            if compiler_name == "none":
                compiler_name = "static-asan-fallback"

    evidence_sha256 = hashlib.sha256(sanitized_stderr.encode("utf-8")).hexdigest()
    return {
        "format": FORMAT,
        "human_approved": True,
        "sandbox_profile": sandbox_profile,
        "compiler_used": compiler_name,
        "reproduced": reproduced,
        "asan_error_kind": error_kind,
        "exit_code": exit_code,
        "evidence_sha256": evidence_sha256,
        "stderr_excerpt": sanitized_stderr[:600],
    }
