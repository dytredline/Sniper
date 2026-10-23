import hashlib
import os
import stat
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path

from verified_exec import VerificationError, file_sha256, open_verified_executable


def _script(path: Path, body: str, mode: int = 0o700) -> Path:
    path.write_text("#!/bin/sh\n" + body, encoding="utf-8")
    path.chmod(mode)
    return path


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class VerifiedExecTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sniper_vexec_")
        self.root = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)

    def run_verified(self, verified, *args):
        return subprocess.run([verified.argv0, *args], **verified.popen_kwargs(
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10, text=True))

    def test_pinned_binary_runs_from_verified_descriptor(self):
        tool = _script(self.root / "tool", "echo dogru-ikili\n")
        with open_verified_executable(str(tool), {_sha(tool): "test"}, label="Araç") as verified:
            self.assertEqual(verified.provenance, "test")
            self.assertEqual(self.run_verified(verified).stdout.strip(), "dogru-ikili")
        self.assertEqual(verified.fd, -1)

    def test_path_swap_after_verification_still_runs_hashed_inode(self):
        tool = _script(self.root / "tool", "echo dogru-ikili\n")
        evil = _script(self.root / "evil", "echo kotu-ikili\n")
        with open_verified_executable(str(tool), {_sha(tool): "test"}, label="Araç") as verified:
            os.replace(evil, tool)  # doğrulamadan sonra yol değiştirilir
            self.assertEqual(self.run_verified(verified).stdout.strip(), "dogru-ikili")

    def test_digest_mismatch_never_executes(self):
        marker = self.root / "ran"
        tool = _script(self.root / "tool", f"touch '{marker}'\n")
        with self.assertRaises(VerificationError) as ctx:
            open_verified_executable(str(tool), {"0" * 64: "baska"}, label="Gitleaks")
        self.assertEqual(ctx.exception.reason, "binary_digest_mismatch")
        self.assertIn("uyuşmuyor", str(ctx.exception))
        self.assertNotIn(str(self.root), str(ctx.exception))
        self.assertFalse(marker.exists())

    def test_missing_pin_is_rejected(self):
        tool = _script(self.root / "tool", "exit 0\n")
        with self.assertRaises(VerificationError) as ctx:
            open_verified_executable(str(tool), {}, label="Semgrep")
        self.assertEqual(ctx.exception.reason, "pin_missing")

    def test_unsafe_files_are_rejected(self):
        tool = _script(self.root / "tool", "exit 0\n")
        link = self.root / "link"
        link.symlink_to(tool)
        writable = _script(self.root / "writable", "exit 0\n", mode=0o775)
        plain = _script(self.root / "plain", "exit 0\n", mode=0o600)
        cases = {
            str(link): "binary_unavailable",
            str(writable): "binary_writable_by_others",
            str(plain): "binary_not_executable",
            str(self.root): "binary_not_regular",
            "relative/tool": "binary_path_not_absolute",
            "": "binary_unconfigured",
        }
        for path, reason in cases.items():
            with self.subTest(path=path):
                with self.assertRaises(VerificationError) as ctx:
                    open_verified_executable(path, {_sha(tool): "x"}, label="Araç")
                self.assertEqual(ctx.exception.reason, reason)

    def test_fifo_does_not_block(self):
        fifo = self.root / "fifo"
        os.mkfifo(fifo)
        box = {}

        def target():
            try:
                file_sha256(str(fifo))
            except VerificationError as exc:
                box["reason"] = exc.reason

        thread = threading.Thread(target=target, daemon=True)
        thread.start()
        thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(box.get("reason"), "binary_not_regular")

    def test_close_fds_false_is_refused(self):
        tool = _script(self.root / "tool", "exit 0\n")
        with open_verified_executable(str(tool), {_sha(tool): "t"}, label="Araç") as verified:
            with self.assertRaises(ValueError):
                verified.popen_kwargs(close_fds=False)
            self.assertEqual(verified.popen_kwargs(pass_fds=(0,))["pass_fds"], tuple(sorted({0, verified.fd})))


if __name__ == "__main__":
    unittest.main()
