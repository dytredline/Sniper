"""Gitleaks Git geçmişi taraması yalnız SHA-256 sabitli ikiliyi, doğrulanan tanıtıcıdan çalıştırır."""
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import gitleaks_git_active
import tool_pins
from gitleaks_git_active import GitleaksGitUnavailable, run_local_gitleaks_git_history
from tests.pin_helpers import pin_env

FAKE = """#!/bin/sh
touch '{marker}'
out=""
prev=""
for a in "$@"; do
  if [ "$prev" = "--report-path" ]; then out="$a"; fi
  prev="$a"
done
printf '[]' > "$out"
exit 0
"""


class GitleaksGitHistoryPinTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path.home(), prefix="sniper_gl_git_pin_")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / "repo"
        self.data = self.root / "data"
        self.data.mkdir()
        self.marker = self.root / "ran"
        for args in (["init", "-q", str(self.repo)],
                     ["-C", str(self.repo), "config", "user.email", "test@example.invalid"],
                     ["-C", str(self.repo), "config", "user.name", "Test"]):
            subprocess.run(["/usr/bin/git", *args], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        (self.repo / "a.txt").write_text("sentetik\n")
        for args in (["add", "a.txt"], ["commit", "-q", "-m", "fixture"]):
            subprocess.run(["/usr/bin/git", "-C", str(self.repo), *args], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.binary = self.root / "fake-gitleaks"
        self.binary.write_text(FAKE.format(marker=self.marker))
        self.binary.chmod(0o700)

    def env(self, **extra):
        return {"SNIPER_DATA_DIR": str(self.data), "SNIPER_GITLEAKS_BINARY": str(self.binary),
                "SNIPER_GITLEAKS_SHA256": "", **extra}

    def test_pinned_binary_runs_via_proc_fd(self):
        seen = []
        real = gitleaks_git_active._run_bounded

        def spy(command, env, cwd, pass_fds=()):
            seen.append((command[0], pass_fds))
            return real(command, env, cwd, pass_fds)

        with mock.patch.dict(os.environ, self.env(**pin_env("gitleaks", self.binary))), \
                mock.patch.object(gitleaks_git_active, "_run_bounded", spy):
            result = run_local_gitleaks_git_history(str(self.repo))
        self.assertEqual(result["total_findings"], 0)
        self.assertTrue(self.marker.exists())
        argv0, pass_fds = seen[0]
        self.assertEqual(argv0, f"/proc/self/fd/{pass_fds[0]}")

    def test_unpinned_binary_is_never_started(self):
        # Bu beklenti, gömülü Gitleaks pininin bulunduğu desteklenen mimaride
        # yanlış bir ikilinin digest uyuşmazlığı vermesini sınar.
        with mock.patch.dict(os.environ, self.env()), \
                mock.patch.object(tool_pins, "machine", return_value="aarch64"):
            with self.assertRaisesRegex(GitleaksGitUnavailable, "uyuşmuyor"):
                run_local_gitleaks_git_history(str(self.repo))
        self.assertFalse(self.marker.exists())

    def test_unsupported_x86_architecture_fails_closed_before_start(self):
        with mock.patch.dict(os.environ, self.env()), \
                mock.patch.object(tool_pins, "machine", return_value="x86_64"):
            with self.assertRaisesRegex(GitleaksGitUnavailable, "sabitlenmiş SHA-256 yok"):
                run_local_gitleaks_git_history(str(self.repo))
        self.assertFalse(self.marker.exists())


if __name__ == "__main__":
    unittest.main()
