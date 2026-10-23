"""Zaman aşımında tüm süreç grubunun öldürüldüğünü doğrular (gerçek araç çağrılmaz).

Sahte "araç" küçük bir sh betiğidir: arka planda bir torun ``sleep`` başlatır,
pid'ini dosyaya yazar ve bekler. Zaman aşımında yalnız doğrudan çocuk
öldürülseydi torun yaşamaya devam ederdi.
"""

from __future__ import annotations

import functools
import hashlib
import json
import os
import signal
import subprocess
import tempfile
import time
import unittest
from tests.pin_helpers import pin_env
from pathlib import Path
from unittest import mock

import gitleaks_active
import nmap_active
import npm_audit_active
import process_group_runner
import semgrep_active
import trivy_active
from process_group_runner import kill_process_group, run_in_process_group
from verified_exec import open_verified_executable


def _process_gone(pid: int) -> bool:
    try:
        raw = Path(f"/proc/{pid}/stat").read_text()
    except (FileNotFoundError, ProcessLookupError):
        return True
    # Biçim: "pid (comm) S ..."; zombi (Z) veya ölü (X) süreç artık çalışmıyor.
    state = raw.rsplit(")", 1)[1].split()[0]
    return state in {"Z", "X"}


def _wait_gone(pid: int, timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _process_gone(pid):
            return True
        time.sleep(0.05)
    return _process_gone(pid)


def _write_tree_script(path: Path, pidfile: Path) -> None:
    path.write_text(
        "#!/bin/sh\n"
        f"sleep 60 &\n"
        f"echo $! > '{pidfile}'\n"
        "wait\n",
        encoding="utf-8",
    )
    path.chmod(0o755)


def _read_pid(pidfile: Path, timeout: float = 5.0) -> int:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            text = pidfile.read_text().strip()
        except FileNotFoundError:
            text = ""
        if text:
            return int(text)
        time.sleep(0.02)
    raise AssertionError("torun süreç pid dosyası yazılmadı")


def _force_timeout(seconds: float):
    real = process_group_runner.run_in_process_group

    @functools.wraps(real)
    def wrapper(cmd, **kwargs):
        kwargs["timeout"] = seconds
        return real(cmd, **kwargs)

    return wrapper


class _TreeMixin:
    def make_tree(self, root: Path, name: str = "fake_tool") -> tuple[Path, Path]:
        script = root / name
        pidfile = root / f"{name}.pid"
        _write_tree_script(script, pidfile)
        return script, pidfile

    def assert_grandchild_killed(self, pidfile: Path) -> None:
        pid = _read_pid(pidfile)
        try:
            self.assertTrue(_wait_gone(pid), "zaman aşımından sonra torun süreç hâlâ çalışıyor")
        finally:
            if not _process_gone(pid):
                os.kill(pid, signal.SIGKILL)


class RunInProcessGroupTests(_TreeMixin, unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="sniper_pgrp_")
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_timeout_kills_whole_process_group(self) -> None:
        script, pidfile = self.make_tree(self.root)
        started = time.monotonic()
        with self.assertRaises(subprocess.TimeoutExpired):
            run_in_process_group(
                [str(script)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=0.5, check=False,
            )
        self.assertLess(time.monotonic() - started, 10)
        self.assert_grandchild_killed(pidfile)

    def test_timeout_with_stdout_pipe_held_by_grandchild(self) -> None:
        # nmap yolu stdout=PIPE kullanır; boruyu tutan torun da öldürülmeli, çağrı takılmamalı.
        script, pidfile = self.make_tree(self.root)
        started = time.monotonic()
        with self.assertRaises(subprocess.TimeoutExpired):
            run_in_process_group([str(script)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=0.5)
        self.assertLess(time.monotonic() - started, 10)
        self.assert_grandchild_killed(pidfile)

    def test_stdlib_run_leaves_grandchild_alive_reference(self) -> None:
        # Bulgunun doğrulanması: subprocess.run(timeout=...) yalnız doğrudan çocuğu öldürür.
        script, pidfile = self.make_tree(self.root)
        with self.assertRaises(subprocess.TimeoutExpired):
            subprocess.run([str(script)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=0.5)
        pid = _read_pid(pidfile)
        try:
            self.assertFalse(_process_gone(pid))
        finally:
            os.kill(pid, signal.SIGKILL)
            _wait_gone(pid)

    def test_success_returns_completed_process_with_output(self) -> None:
        result = run_in_process_group(
            ["/bin/sh", "-c", "printf out; printf err >&2; exit 3"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10, check=False,
        )
        self.assertIsInstance(result, subprocess.CompletedProcess)
        self.assertEqual(result.returncode, 3)
        self.assertEqual(result.stdout, b"out")
        self.assertEqual(result.stderr, b"err")

    def test_check_raises_called_process_error(self) -> None:
        with self.assertRaises(subprocess.CalledProcessError):
            run_in_process_group(["/bin/sh", "-c", "exit 2"], stdout=subprocess.DEVNULL, timeout=10, check=True)

    def test_stdout_file_object_is_supported(self) -> None:
        out = self.root / "out.txt"
        with out.open("wb") as handle:
            result = run_in_process_group(["/bin/sh", "-c", "printf data"], stdout=handle, timeout=10)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(out.read_bytes(), b"data")

    def test_missing_binary_raises_oserror(self) -> None:
        with self.assertRaises(OSError):
            run_in_process_group([str(self.root / "missing")], timeout=5)

    def test_child_runs_in_new_session(self) -> None:
        result = run_in_process_group(
            ["/bin/sh", "-c", "ps -o pgid= -p $$; ps -o sid= -p $$; echo $$"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10,
        )
        pgid, sid, pid = result.stdout.decode().split()
        self.assertEqual(pgid, pid)
        self.assertEqual(sid, pid)
        self.assertNotEqual(int(pgid), os.getpgrp())

    def test_kill_process_group_ignores_finished_group(self) -> None:
        proc = subprocess.Popen(["/bin/sh", "-c", "exit 0"], start_new_session=True)
        proc.wait()
        kill_process_group(proc)  # ProcessLookupError yutulmalı


class ActiveModuleTimeoutTests(_TreeMixin, unittest.TestCase):
    """Her aktif modülün zaman aşımı yolu grubu öldürür ve mevcut hata mesajını korur."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(dir=Path.home(), prefix="sniper_pgrp_mod_")
        self.root = Path(self.temp.name)
        self.data_dir = self.root / "data"
        self.data_dir.mkdir()
        self.project = self.root / "project"
        self.project.mkdir()
        (self.project / "main.py").write_text("x = 1\n", encoding="utf-8")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_nmap_timeout_kills_group(self) -> None:
        script, pidfile = self.make_tree(self.root, "fake_nmap")
        with mock.patch("nmap_active._find_nmap_binary", return_value=script), \
                mock.patch.object(nmap_active, "SUBPROCESS_TIMEOUT_SECONDS", 0.5):
            with self.assertRaisesRegex(RuntimeError, "^nmap zaman aşımına uğradı$"):
                nmap_active._run_nmap("203.0.113.9", False, [80])
        self.assert_grandchild_killed(pidfile)

    def test_gitleaks_timeout_kills_group(self) -> None:
        script, pidfile = self.make_tree(self.root, "fake_gitleaks")
        env = {"SNIPER_DATA_DIR": str(self.data_dir), "SNIPER_GITLEAKS_BINARY": str(script), **pin_env("gitleaks", script)}
        with mock.patch.dict(os.environ, env), \
                mock.patch.object(gitleaks_active, "run_in_process_group", _force_timeout(0.5)):
            with self.assertRaisesRegex(RuntimeError, "^Gitleaks çalıştırması zaman aşımına uğradı\\.$"):
                gitleaks_active.run_local_gitleaks(str(self.project))
        self.assert_grandchild_killed(pidfile)

    def test_trivy_timeout_kills_group(self) -> None:
        script, pidfile = self.make_tree(self.root, "fake_trivy")
        env = {
            "SNIPER_DATA_DIR": str(self.data_dir),
            "SNIPER_TRIVY_BINARY": str(script),
            "SNIPER_TRIVY_BINARY_SHA256": hashlib.sha256(script.read_bytes()).hexdigest(),
        }
        with mock.patch.dict(os.environ, env), \
                mock.patch.object(trivy_active, "run_in_process_group", _force_timeout(0.5)):
            with self.assertRaisesRegex(RuntimeError, "^Trivy çalıştırması zaman aşımına uğradı\\.$"):
                trivy_active.run_local_trivy_secret(str(self.project))
        self.assert_grandchild_killed(pidfile)

    def test_semgrep_timeout_kills_group(self) -> None:
        script, pidfile = self.make_tree(self.root, "fake_semgrep")
        rules = self.root / "rules.yaml"
        rules.write_text(
            "rules:\n"
            "  - id: python.lang.security.audit.eval-detected\n"
            "    languages: [python]\n"
            "    severity: ERROR\n"
            "    pattern: eval(...)\n",
            encoding="utf-8",
        )
        env = {
            "SNIPER_DATA_DIR": str(self.data_dir),
            "SNIPER_SEMGREP_BINARY": str(script),
            "SNIPER_SEMGREP_RULES": str(rules),
            **pin_env("semgrep", script),
        }
        with mock.patch.dict(os.environ, env), \
                mock.patch.object(semgrep_active, "run_in_process_group", _force_timeout(0.5)):
            with self.assertRaisesRegex(RuntimeError, "^Semgrep çalıştırması zaman aşımına uğradı\\.$"):
                semgrep_active.run_local_semgrep(str(self.project))
        self.assert_grandchild_killed(pidfile)

    def test_npm_audit_timeout_kills_group(self) -> None:
        script, pidfile = self.make_tree(self.root, "fake_node")
        script_sha256 = hashlib.sha256(script.read_bytes()).hexdigest()
        lock = {
            "name": "x", "version": "1.0.0", "lockfileVersion": 3,
            "packages": {
                "": {"name": "x", "version": "1.0.0", "dependencies": {"lodash": "4.17.21"}},
                "node_modules/lodash": {
                    "version": "4.17.21",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                },
            },
        }
        (self.project / "package-lock.json").write_text(json.dumps(lock), encoding="utf-8")
        with mock.patch.dict(os.environ, {"SNIPER_DATA_DIR": str(self.data_dir)}), \
                mock.patch.object(
                    npm_audit_active,
                    "open_pinned",
                    side_effect=lambda _tool: open_verified_executable(
                        script, {script_sha256: "test fixture"}, label="Node.js"
                    ),
                ), \
                mock.patch.object(npm_audit_active, "_pinned_runtime", return_value=self.root / "npm-cli.js"), \
                mock.patch.object(npm_audit_active, "run_in_process_group", _force_timeout(0.5)):
            with self.assertRaisesRegex(npm_audit_active.NpmAuditExecutionError, "^npm audit çalıştırması başarısız oldu\\.$"):
                npm_audit_active.run_local_npm_audit_local(str(self.project))
        self.assert_grandchild_killed(pidfile)


if __name__ == "__main__":
    unittest.main()
