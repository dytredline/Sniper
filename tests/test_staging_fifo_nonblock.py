"""lstat ile open arasında FIFO'ya çevrilen dosya staging'i kilitlememeli.

Yarış, ``os.lstat`` sahte olarak "normal dosya" döndürecek şekilde yamalanıp
gerçekte yolda bir FIFO bırakılarak benzetilir. ``O_NONBLOCK`` olmadan
``os.open(O_RDONLY)`` yazan olmayan FIFO'da süresiz bekler (ve tarama kilidi
tutulur); düzeltilmiş kod hemen açar, ``fstat`` ile FIFO olduğunu görür ve
reddeder. Gerçek araç çalıştırılmaz.
"""

from __future__ import annotations

import hashlib
import os
import stat
import tempfile
import threading
import unittest
from tests.pin_helpers import pin_env
from pathlib import Path
from unittest import mock

import gitleaks_active
import npm_audit_active
import trivy_active
import trufflehog_active

_REAL_LSTAT = os.lstat
_CALL_TIMEOUT = 10.0


def _fake_regular_lstat(fifo_paths: set[str], size: int = 5):
    def wrapper(path, *args, **kwargs):
        result = _REAL_LSTAT(path, *args, **kwargs)
        try:
            key = os.fspath(path)
        except TypeError:
            return result
        if key in fifo_paths:
            values = list(result)
            values[stat.ST_MODE] = stat.S_IFREG | 0o644
            values[stat.ST_SIZE] = size
            return os.stat_result(values)
        return result

    return wrapper


def _call_with_deadline(testcase: unittest.TestCase, fifo: Path, func, *args):
    box: dict[str, BaseException | object] = {}

    def target() -> None:
        try:
            box["result"] = func(*args)
        except BaseException as exc:  # noqa: BLE001 - test sonucu olarak taşınır
            box["error"] = exc

    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    thread.join(_CALL_TIMEOUT)
    if thread.is_alive():
        # Takılan okuyucuyu serbest bırak ki test süreci asılı kalmasın.
        try:
            fd = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK)
            os.close(fd)
        except OSError:
            pass
        thread.join(5)
        testcase.fail("FIFO açılırken staging süresiz bekledi (O_NONBLOCK yok)")
    return box


class _FifoProjectMixin:
    def make_project(self) -> tuple[Path, Path]:
        project = self.root / "project"
        project.mkdir()
        (project / "a_ok.txt").write_text("hello", encoding="utf-8")
        fifo = project / "b_swapped.txt"
        os.mkfifo(fifo)
        return project, fifo

    def make_fake_binary(self, name: str) -> Path:
        script = self.root / name
        script.write_text("#!/bin/sh\nexit 99\n", encoding="utf-8")
        script.chmod(0o755)
        return script


class StagingFifoTests(_FifoProjectMixin, unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(dir=Path.home(), prefix="sniper_fifo_stage_")
        self.root = Path(self.temp.name)
        self.data_dir = self.root / "data"
        self.data_dir.mkdir()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _assert_fifo_rejected_and_lock_released(self, func, env: dict[str, str], busy_text: str) -> None:
        project, fifo = self.make_project()
        with mock.patch.dict(os.environ, env), mock.patch("os.lstat", _fake_regular_lstat({str(fifo)})):
            for _attempt in range(2):  # ikinci deneme kilidin bırakıldığını kanıtlar
                box = _call_with_deadline(self, fifo, func, str(project))
                self.assertNotIn("result", box)
                error = box.get("error")
                self.assertIsInstance(error, RuntimeError)
                self.assertIn("Dosya lstat sonrasında değişti", str(error))
                self.assertNotIn(busy_text, str(error))

    def test_gitleaks_staging_rejects_fifo_swap_without_blocking(self) -> None:
        binary = self.make_fake_binary("gl")
        env = {"SNIPER_DATA_DIR": str(self.data_dir), "SNIPER_GITLEAKS_BINARY": str(binary), **pin_env("gitleaks", binary)}
        self._assert_fifo_rejected_and_lock_released(gitleaks_active.run_local_gitleaks, env, "in progress")

    def test_trivy_staging_rejects_fifo_swap_without_blocking(self) -> None:
        binary = self.make_fake_binary("tv")
        env = {
            "SNIPER_DATA_DIR": str(self.data_dir),
            "SNIPER_TRIVY_BINARY": str(binary),
            "SNIPER_TRIVY_BINARY_SHA256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        }
        self._assert_fifo_rejected_and_lock_released(trivy_active.run_local_trivy_secret, env, "in progress")

    def test_trufflehog_staging_rejects_fifo_swap_without_blocking(self) -> None:
        binary = self.make_fake_binary("th")
        env = {
            "SNIPER_DATA_DIR": str(self.data_dir),
            "SNIPER_TRUFFLEHOG_BINARY": str(binary),
            **pin_env("trufflehog", binary),
        }
        self._assert_fifo_rejected_and_lock_released(
            trufflehog_active.run_local_trufflehog_filesystem, env, "in progress",
        )

    def test_npm_lockfile_fifo_swap_rejected_without_blocking(self) -> None:
        project = self.root / "npm_project"
        project.mkdir()
        fifo = project / "package-lock.json"
        os.mkfifo(fifo)
        with mock.patch("os.lstat", _fake_regular_lstat({str(fifo)}, size=10)):
            box = _call_with_deadline(self, fifo, npm_audit_active._read_lockfile, project)
        self.assertIsInstance(box.get("error"), ValueError)
        self.assertIn("anlık görüntü sırasında değişti", str(box["error"]))

    def test_regular_file_size_change_still_detected(self) -> None:
        # fstat ile boyutun yeniden doğrulanması korunuyor.
        project = self.root / "size_project"
        project.mkdir()
        target = project / "grown.txt"
        target.write_text("0123456789", encoding="utf-8")
        binary = self.make_fake_binary("gl2")
        env = {"SNIPER_DATA_DIR": str(self.data_dir), "SNIPER_GITLEAKS_BINARY": str(binary), **pin_env("gitleaks", binary)}
        with mock.patch.dict(os.environ, env), mock.patch("os.lstat", _fake_regular_lstat({str(target)}, size=3)):
            with self.assertRaisesRegex(RuntimeError, "Dosya boyutu lstat sonrasında değişti"):
                gitleaks_active.run_local_gitleaks(str(project))


if __name__ == "__main__":
    unittest.main()
