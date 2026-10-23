"""Fail-closed no-egress launcher for the pinned, offline OSV-Scanner binary.

Run only as a separate subprocess with close_fds=True, a minimal environment,
and no pass_fds. The seccomp filter is inherited across exec and descendants.
"""
from __future__ import annotations

import ctypes
import errno
import os
import resource
import stat
import sys


PR_SET_NO_NEW_PRIVS = 38
SCMP_ACT_ALLOW = 0x7FFF0000
SCMP_ACT_ERRNO = 0x00050000 | errno.EPERM
SCMP_CMP_MASKED_EQ = 7
CLONE_THREAD = 0x00010000
DENIED_SYSCALLS = (
    b"socket", b"socketpair", b"connect", b"sendto", b"sendmsg",
    b"sendmmsg", b"io_uring_setup", b"io_uring_enter", b"io_uring_register",
    # A scanner child must never detach from the process group monitored by
    # the caller. Go may create threads, but not independent processes.
    b"clone3", b"setsid", b"setpgid", b"unshare", b"setns",
)
# arm64 has no fork/vfork syscall numbers; on architectures that do, deny
# them as well. The clone rule below is mandatory everywhere.
OPTIONAL_PROCESS_SYSCALLS = (b"fork", b"vfork")


class ScmpArgCmp(ctypes.Structure):
    _fields_ = [("arg", ctypes.c_uint), ("op", ctypes.c_int),
                ("datum_a", ctypes.c_uint64), ("datum_b", ctypes.c_uint64)]


def main() -> int:
    if len(sys.argv) < 3 or not os.path.isabs(sys.argv[1]):
        return 125
    binary = sys.argv[1]
    try:
        info = os.lstat(binary)
        if not stat.S_ISREG(info.st_mode) or not os.access(binary, os.X_OK):
            return 125
        # The parent closes inherited descriptors before this interpreter is
        # launched. Close again before exec as defense in depth: an inherited
        # connected socket could bypass a socket/connect-only filter.
        soft, _hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        limit = 1_048_576 if soft == resource.RLIM_INFINITY else min(soft, 1_048_576)
        os.closerange(3, limit)
        resource.setrlimit(resource.RLIMIT_AS, (4 * 1024 ** 3, 4 * 1024 ** 3))
        resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
            return 125
        sec = ctypes.CDLL("libseccomp.so.2", use_errno=True)
        sec.seccomp_init.argtypes = [ctypes.c_uint32]
        sec.seccomp_init.restype = ctypes.c_void_p
        sec.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
        sec.seccomp_syscall_resolve_name.restype = ctypes.c_int
        sec.seccomp_rule_add.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint]
        sec.seccomp_rule_add.restype = ctypes.c_int
        sec.seccomp_rule_add_array.argtypes = [ctypes.c_void_p, ctypes.c_uint32,
                                               ctypes.c_int, ctypes.c_uint,
                                               ctypes.POINTER(ScmpArgCmp)]
        sec.seccomp_rule_add_array.restype = ctypes.c_int
        sec.seccomp_load.argtypes = [ctypes.c_void_p]
        sec.seccomp_load.restype = ctypes.c_int
        sec.seccomp_release.argtypes = [ctypes.c_void_p]
        ctx = sec.seccomp_init(SCMP_ACT_ALLOW)
        if not ctx:
            return 125
        try:
            for name in DENIED_SYSCALLS:
                nr = sec.seccomp_syscall_resolve_name(name)
                if nr < 0 or sec.seccomp_rule_add(ctx, SCMP_ACT_ERRNO, nr, 0) != 0:
                    return 125
            for name in OPTIONAL_PROCESS_SYSCALLS:
                nr = sec.seccomp_syscall_resolve_name(name)
                if nr >= 0 and sec.seccomp_rule_add(ctx, SCMP_ACT_ERRNO, nr, 0) != 0:
                    return 125
            # clone without CLONE_THREAD creates a process that can outlive
            # the scanner leader. Retain Go's normal thread creation only.
            clone_nr = sec.seccomp_syscall_resolve_name(b"clone")
            clone_cmp = ScmpArgCmp(0, SCMP_CMP_MASKED_EQ, CLONE_THREAD, 0)
            if clone_nr < 0 or sec.seccomp_rule_add_array(
                ctx, SCMP_ACT_ERRNO, clone_nr, 1, ctypes.byref(clone_cmp)
            ) != 0:
                return 125
            if sec.seccomp_load(ctx) != 0:
                return 125
        finally:
            sec.seccomp_release(ctx)
        os.execve(binary, [binary, *sys.argv[2:]], os.environ)
    except (OSError, ValueError):
        return 125
    return 125


if __name__ == "__main__":
    raise SystemExit(main())
