"""bwrap ``--seccomp`` için ham cBPF filtresi (libseccomp gerektirmez).

Chromium bwrap sandbox'ında kendi ad alanı sandbox'ını kuramaz (iç içe userns kapalı; AppArmor
``sniper_unpriv_bwrap`` yetenekleri reddeder) ve ``--no-sandbox`` ile çalışır. Bu filtre eksilen seccomp
katmanının yerine, Docker'ın varsayılan profilinde engellenen çekirdek saldırı yüzeyini (modül yükleme, bpf,
perf, io_uring, keyring, ptrace, mount/ad alanı, saat ayarı …) tüm sandbox süreç ağacı için EPERM ile kapatır.
Mimari uyuşmazsa süreç öldürülür; desteklenmeyen mimaride filtre üretilmez (çağıran çalıştırmayı reddeder).
"""
from __future__ import annotations

import platform
import struct

# linux/filter.h, linux/seccomp.h, linux/audit.h
BPF_LD, BPF_W, BPF_ABS, BPF_JMP, BPF_JEQ, BPF_K, BPF_RET = 0x00, 0x00, 0x20, 0x05, 0x10, 0x00, 0x06
SECCOMP_RET_KILL_PROCESS = 0x80000000
SECCOMP_RET_ERRNO = 0x00050000
SECCOMP_RET_ALLOW = 0x7FFF0000
EPERM = 1
AUDIT_ARCH = {"aarch64": 0xC00000B7}

# asm-generic/unistd.h (aarch64). tests/test_sandbox_seccomp.py başlık dosyasıyla karşılaştırır.
DENIED_SYSCALLS: dict[str, dict[str, int]] = {
    "aarch64": {
        "acct": 89, "add_key": 217, "bpf": 280, "clock_adjtime": 266, "clock_settime": 112,
        "delete_module": 106, "finit_module": 273, "init_module": 105, "kcmp": 272, "kexec_file_load": 294,
        "kexec_load": 104, "keyctl": 219, "lookup_dcookie": 18, "mount": 40, "move_pages": 239,
        "name_to_handle_at": 264, "open_by_handle_at": 265, "perf_event_open": 241, "pivot_root": 41,
        "process_vm_readv": 270, "process_vm_writev": 271, "ptrace": 117, "quotactl": 60, "reboot": 142,
        "request_key": 218, "setns": 268, "settimeofday": 170, "swapon": 224, "swapoff": 225, "syslog": 116,
        "umount2": 39, "unshare": 97, "userfaultfd": 282, "io_uring_setup": 425, "io_uring_enter": 426,
        "io_uring_register": 427, "open_tree": 428, "move_mount": 429, "fsopen": 430, "fsconfig": 431,
        "fsmount": 432, "fspick": 433, "mount_setattr": 442, "pidfd_getfd": 438, "fanotify_init": 262,
        "vhangup": 58, "nfsservctl": 42,
    },
}


class SeccompUnsupported(RuntimeError):
    """Bu mimari için seccomp filtresi yok."""


def machine() -> str:
    raw = platform.machine().lower()
    return {"arm64": "aarch64"}.get(raw, raw)


def _stmt(code: int, k: int) -> bytes:
    return struct.pack("=HBBI", code, 0, 0, k)


def _jump(code: int, k: int, jt: int, jf: int) -> bytes:
    return struct.pack("=HBBI", code, jt, jf, k)


def build_filter(arch: str | None = None) -> bytes:
    """Derlenmiş cBPF programı (sock_filter dizisi): mimari denetimi + engel listesi → EPERM, gerisi izinli."""
    arch = arch or machine()
    if arch not in AUDIT_ARCH or arch not in DENIED_SYSCALLS:
        raise SeccompUnsupported(arch)
    numbers = sorted(set(DENIED_SYSCALLS[arch].values()))
    program = [
        _stmt(BPF_LD | BPF_W | BPF_ABS, 4),  # seccomp_data.arch
        _jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH[arch], 1, 0),
        _stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        _stmt(BPF_LD | BPF_W | BPF_ABS, 0),  # seccomp_data.nr
    ]
    for index, number in enumerate(numbers):
        remaining = len(numbers) - index - 1
        # Eşleşirse ERRNO dönüşüne atla (kalan karşılaştırmalar + ALLOW atlanır).
        program.append(_jump(BPF_JMP | BPF_JEQ | BPF_K, number, remaining + 1, 0))
    program.append(_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW))
    program.append(_stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM))
    if len(program) > 4096:
        raise SeccompUnsupported("program_cok_uzun")
    return b"".join(program)
