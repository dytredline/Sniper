import ctypes
import os
import signal
import sys
from typing import List

libc = ctypes.CDLL("libc.so.6", use_errno=True)
PR_SET_PDEATHSIG = 1


def _validate_args(argv: List[str]) -> bool:
    if len(argv) < 3:
        return False
    # argv[0] is interpreter, argv[1] is expected_parent_pid_decimal
    pid_str = argv[1]
    # Must be ASCII decimal digits only and canonical
    if not pid_str.isdigit() or len(pid_str) == 0:
        return False
    try:
        expected_parent_pid = int(pid_str)
        if expected_parent_pid <= 0:
            return False
        if str(expected_parent_pid) != pid_str:
            return False
    except ValueError:
        return False
    # argv[2] must be absolute path to binary
    binary_path = argv[2]
    if not os.path.isabs(binary_path):
        return False
    if not os.path.isfile(binary_path):
        return False
    if os.path.islink(binary_path):
        return False
    if not os.access(binary_path, os.X_OK):
        return False
    return True


def main() -> None:
    argv = sys.argv

    if not _validate_args(argv):
        sys.exit(1)

    expected_parent_pid = int(argv[1])
    binary = argv[2]
    binary_args = argv[3:]

    # Verify parent still matches at start
    if os.getppid() != expected_parent_pid:
        sys.exit(1)

    # Set parent-death signal
    ret = libc.prctl(PR_SET_PDEATHSIG, signal.SIGKILL)
    if ret != 0:
        errno = ctypes.get_errno()
        sys.exit(1)

    # Re-verify parent still matches after prctl (in case parent died synchronously)
    if os.getppid() != expected_parent_pid:
        sys.exit(1)

    # Prepare sanitized environment
    env = {}
    safe_keys = {"HOME", "TMPDIR", "PATH", "LANG"}
    for k, v in os.environ.items():
        if k in safe_keys:
            env[k] = v

    # Final execve — do not log or echo argv/binary/report
    os.execve(binary, [binary] + binary_args, env)


if __name__ == "__main__":
    main()
