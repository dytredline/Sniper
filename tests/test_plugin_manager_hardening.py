"""PluginManager sertleştirme testleri: chmod yok, sembolik bağ yok, yerleşik SHA-256, zaman aşımı."""

from pathlib import Path
import os
import shutil
import stat
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import core.plugin_manager as plugin_manager  # noqa: E402
from core.plugin_manager import BUILTIN_PLUGIN_SHA256, PluginManager  # noqa: E402
from plugins.base_plugin import BasePlugin, PluginInfo  # noqa: E402


BUILTIN_DIR = ROOT / "plugins" / "user"

USER_PLUGIN_SOURCE = '''
from plugins.base_plugin import BasePlugin, PluginInfo

class UserPlugin(BasePlugin):
    @property
    def info(self):
        return PluginInfo("{name}", "1.0", "local", "user plugin")

    def scan(self, target):
        return [{{"severity": "info", "title": "user", "description": "user plugin finding"}}]

PLUGIN = UserPlugin()
'''


def _write(path: Path, content: str, mode: int = 0o600) -> Path:
    path.write_text(content, encoding="utf-8")
    os.chmod(path, mode)  # test fikstürü; üretim kodu chmod yapmaz
    return path


def _forbid_chmod(*_args, **_kwargs):
    raise AssertionError("PluginManager chmod çağırmamalı")


class _StaticPlugin(BasePlugin):
    def __init__(self, name: str, blocker: threading.Event | None = None):
        self._name = name
        self._blocker = blocker

    @property
    def info(self):
        return PluginInfo(self._name, "1.0", "test", "test")

    def scan(self, target):
        if self._blocker is not None:
            self._blocker.wait(30)
        return [{"severity": "low", "title": f"{self._name} bulgu", "description": "açıklama"}]


class PermissionHardeningTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.plugin_dir = self.root / "plugins"
        self.plugin_dir.mkdir(mode=0o700)
        os.chmod(self.plugin_dir, 0o700)
        chmod_patch = mock.patch("os.chmod", side_effect=_forbid_chmod)
        self.addCleanup(self._tmp.cleanup)
        # os.chmod yalnız reload süresince yasaklanır (fikstür kurulumunda serbest).
        self._chmod_patch = chmod_patch

    def _reload(self, **kwargs) -> PluginManager:
        manager = PluginManager(self.plugin_dir, enabled=True, **kwargs)
        with self._chmod_patch:
            manager.reload()
        return manager

    def test_group_writable_plugin_is_rejected_and_mode_untouched(self):
        path = _write(self.plugin_dir / "grp.py", USER_PLUGIN_SOURCE.format(name="grp"), 0o664)
        manager = self._reload(allow_user_plugins=True)
        status = manager.public_status()
        self.assertEqual(status["loaded"], 0)
        self.assertIn("yazılabilen eklenti reddedildi", " ".join(status["errors"]))
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o664)

    def test_symlink_to_outside_file_is_skipped_without_chmod(self):
        outside = _write(self.root / "outside.py", USER_PLUGIN_SOURCE.format(name="outside"), 0o644)
        (self.plugin_dir / "link.py").symlink_to(outside)
        manager = self._reload(allow_user_plugins=True)
        status = manager.public_status()
        self.assertEqual(status["loaded"], 0)
        self.assertIn("Sembolik bağ", " ".join(status["errors"]))
        self.assertEqual(stat.S_IMODE(outside.stat().st_mode), 0o644)

    def test_symlinked_builtin_name_is_skipped(self):
        outside = self.root / "ip_literal_target_advisor.py"
        shutil.copyfile(BUILTIN_DIR / "ip_literal_target_advisor.py", outside)
        os.chmod(outside, 0o600)
        (self.plugin_dir / "ip_literal_target_advisor.py").symlink_to(outside)
        manager = self._reload(allow_user_plugins=False)
        self.assertEqual(manager.loaded_count, 0)
        self.assertIn("Sembolik bağ", " ".join(manager.public_status()["errors"]))

    def test_group_writable_directory_rejects_everything_and_is_not_chmodded(self):
        _write(self.plugin_dir / "ok.py", USER_PLUGIN_SOURCE.format(name="ok"))
        os.chmod(self.plugin_dir, 0o770)
        manager = self._reload(allow_user_plugins=True)
        status = manager.public_status()
        self.assertEqual(status["loaded"], 0)
        self.assertIn("Eklenti dizini grup veya diğer", " ".join(status["errors"]))
        self.assertEqual(stat.S_IMODE(self.plugin_dir.stat().st_mode), 0o770)

    def test_symlinked_plugin_directory_is_rejected(self):
        real = self.root / "real"
        real.mkdir(mode=0o700)
        _write(real / "ok.py", USER_PLUGIN_SOURCE.format(name="ok"))
        manager = PluginManager(self.plugin_dir, enabled=True, allow_user_plugins=True)
        # Oluşturulduktan sonra dizin sembolik bağla değiştirilir.
        self.plugin_dir.rmdir()
        self.plugin_dir.symlink_to(real, target_is_directory=True)
        with self._chmod_patch:
            manager.reload()
        self.assertEqual(manager.loaded_count, 0)
        self.assertIn("Eklenti dizini", " ".join(manager.public_status()["errors"]))

    def test_foreign_owner_is_rejected(self):
        _write(self.plugin_dir / "ok.py", USER_PLUGIN_SOURCE.format(name="ok"))
        with mock.patch("os.geteuid", return_value=os.geteuid() + 4242):
            manager = self._reload(allow_user_plugins=True)
        self.assertEqual(manager.loaded_count, 0)
        self.assertIn("sahibi bu süreç kullanıcısı değil", " ".join(manager.public_status()["errors"]))

    def test_fifo_is_rejected_without_blocking(self):
        if not hasattr(os, "mkfifo"):
            self.skipTest("mkfifo yok")
        os.mkfifo(self.plugin_dir / "pipe.py", 0o600)
        manager = self._reload(allow_user_plugins=True)
        self.assertEqual(manager.loaded_count, 0)
        self.assertIn("normal bir dosya değil", " ".join(manager.public_status()["errors"]))

    def test_oversized_plugin_is_rejected(self):
        _write(self.plugin_dir / "big.py", "#" * (plugin_manager.MAX_PLUGIN_BYTES + 10))
        manager = self._reload(allow_user_plugins=True)
        self.assertEqual(manager.loaded_count, 0)
        self.assertIn("boyut sınırını", " ".join(manager.public_status()["errors"]))

    def test_source_is_loaded_from_verified_fd_bytes(self):
        _write(self.plugin_dir / "ok.py", USER_PLUGIN_SOURCE.format(name="ok"))
        manager = PluginManager(self.plugin_dir, enabled=True, allow_user_plugins=True)
        with self._chmod_patch, mock.patch(
            "importlib.util.spec_from_file_location", side_effect=AssertionError("yol yeniden açılmamalı")
        ):
            manager.reload()
        self.assertEqual(manager.loaded_count, 1)


class BuiltinSeparationTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.plugin_dir = Path(self._tmp.name) / "user"
        self.plugin_dir.mkdir(mode=0o700)
        os.chmod(self.plugin_dir, 0o700)
        for name in BUILTIN_PLUGIN_SHA256:
            shutil.copyfile(BUILTIN_DIR / name, self.plugin_dir / name)
            os.chmod(self.plugin_dir / name, 0o600)

    def test_pinned_hashes_match_shipped_builtins(self):
        manager = PluginManager(BUILTIN_DIR, enabled=True, allow_user_plugins=False)
        with mock.patch("os.chmod", side_effect=_forbid_chmod):
            manager.reload()
        self.assertEqual(manager.loaded_count, len(BUILTIN_PLUGIN_SHA256), manager.public_status()["errors"])

    def test_builtins_load_but_user_plugins_need_explicit_opt_in(self):
        _write(self.plugin_dir / "custom.py", USER_PLUGIN_SOURCE.format(name="custom"))
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop(plugin_manager.USER_PLUGINS_ENV, None)
            manager = PluginManager(self.plugin_dir, enabled=True)
            manager.reload()
        status = manager.public_status()
        self.assertEqual(status["loaded"], len(BUILTIN_PLUGIN_SHA256))
        self.assertFalse(status["user_plugins_allowed"])
        self.assertNotIn("custom", [p["name"] for p in status["plugins"]])
        self.assertIn(plugin_manager.USER_PLUGINS_ENV, " ".join(status["errors"]))

    def test_env_opt_in_loads_user_plugins(self):
        _write(self.plugin_dir / "custom.py", USER_PLUGIN_SOURCE.format(name="custom"))
        with mock.patch.dict(os.environ, {plugin_manager.USER_PLUGINS_ENV: "1"}):
            manager = PluginManager(self.plugin_dir, enabled=True)
            manager.reload()
            self.assertTrue(manager.public_status()["user_plugins_allowed"])
        self.assertEqual(manager.loaded_count, len(BUILTIN_PLUGIN_SHA256) + 1)

    def test_allowlist_limits_user_plugins(self):
        _write(self.plugin_dir / "custom.py", USER_PLUGIN_SOURCE.format(name="custom"))
        _write(self.plugin_dir / "other.py", USER_PLUGIN_SOURCE.format(name="other"))
        manager = PluginManager(
            self.plugin_dir, enabled=True, allow_user_plugins=True, user_plugin_allowlist=["custom.py"]
        )
        manager.reload()
        names = [p["name"] for p in manager.public_status()["plugins"]]
        self.assertIn("custom", names)
        self.assertNotIn("other", names)
        self.assertIn("izin listesinde değil", " ".join(manager.public_status()["errors"]))

    def test_tampered_builtin_is_rejected_even_with_user_opt_in(self):
        target = self.plugin_dir / "ip_literal_target_advisor.py"
        with open(target, "a", encoding="utf-8") as handle:
            handle.write("\n# değiştirildi\n")
        for allow in (False, True):
            manager = PluginManager(self.plugin_dir, enabled=True, allow_user_plugins=allow)
            manager.reload()
            status = manager.public_status()
            self.assertEqual(status["loaded"], len(BUILTIN_PLUGIN_SHA256) - 1)
            self.assertNotIn("ip-literal-target-advisor", [p["name"] for p in status["plugins"]])
            self.assertIn("SHA-256 uyuşmuyor", " ".join(status["errors"]))


class ScanTimeoutTests(unittest.TestCase):
    def test_hung_plugin_times_out_and_other_plugins_continue(self):
        release = threading.Event()
        self.addCleanup(release.set)
        manager = PluginManager(Path(tempfile.gettempdir()), enabled=False)
        manager._plugins = {
            "hang": _StaticPlugin("hang", blocker=release),
            "fast": _StaticPlugin("fast"),
        }
        with mock.patch.object(plugin_manager, "PLUGIN_SCAN_TIMEOUT_SECONDS", 0.2):
            started = time.monotonic()
            findings = manager.scan_all("http://127.0.0.1/")
            elapsed = time.monotonic() - started
            self.assertLess(elapsed, 5)
            self.assertEqual([f["plugin"] for f in findings], ["fast"])
            errors = " ".join(manager.public_status()["errors"])
            self.assertIn("hang tarama hatası: zaman aşımı", errors)
            hung = [t for t in threading.enumerate() if t.name == "sniper-plugin-hang"]
            self.assertTrue(hung and all(t.daemon for t in hung))

            # Asılı çağrı sürerken eklenti yeniden çağrılmaz (iş parçacığı birikmez).
            findings = manager.scan_all("http://127.0.0.1/")
            self.assertEqual([f["plugin"] for f in findings], ["fast"])
            self.assertIn("hâlâ sürüyor", manager.public_status()["errors"][-1])
            self.assertEqual(len([t for t in threading.enumerate() if t.name == "sniper-plugin-hang"]), 1)

            release.set()
            for thread in hung:
                thread.join(5)
            findings = manager.scan_all("http://127.0.0.1/")
            self.assertEqual(sorted(f["plugin"] for f in findings), ["fast", "hang"])

    def test_concurrent_scans_do_not_skip_each_other(self):
        gate = threading.Event()
        manager = PluginManager(Path(tempfile.gettempdir()), enabled=False)
        manager._plugins = {"slow": _StaticPlugin("slow", blocker=gate)}
        results: list[list] = []

        def run():
            results.append(manager.scan_all("http://127.0.0.1/"))

        workers = [threading.Thread(target=run) for _ in range(2)]
        for worker in workers:
            worker.start()
        time.sleep(0.1)
        gate.set()
        for worker in workers:
            worker.join(10)
        self.assertEqual([len(r) for r in results], [1, 1])

    def test_plugin_exception_is_recorded(self):
        class Broken(_StaticPlugin):
            def scan(self, target):
                raise RuntimeError("bozuk")

        manager = PluginManager(Path(tempfile.gettempdir()), enabled=False)
        manager._plugins = {"broken": Broken("broken"), "fast": _StaticPlugin("fast")}
        findings = manager.scan_all("http://127.0.0.1/")
        self.assertEqual([f["plugin"] for f in findings], ["fast"])
        self.assertIn("broken tarama hatası: RuntimeError", manager.public_status()["errors"])


if __name__ == "__main__":
    unittest.main()


SLOW_PLUGIN_SOURCE = '''
import threading
from plugins.base_plugin import BasePlugin, PluginInfo

_HOLD = threading.Event()
{import_block}

class SlowPlugin(BasePlugin):
    @property
    def info(self):
        return PluginInfo("{name}", "1.0", "local", "yavaş eklenti")

    def initialize(self, config):
        {init_block}

    def cleanup(self):
        {cleanup_block}

    def scan(self, target):
        return []

PLUGIN = SlowPlugin()
'''


class LifecycleTimeoutTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.plugin_dir = Path(self._tmp.name) / "plugins"
        self.plugin_dir.mkdir(mode=0o700)
        os.chmod(self.plugin_dir, 0o700)
        for name, value in (("PLUGIN_LOAD_TIMEOUT_SECONDS", 0.3), ("PLUGIN_LIFECYCLE_TIMEOUT_SECONDS", 0.3)):
            patcher = mock.patch.object(plugin_manager, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def _plugin(self, filename, *, import_block="pass", init_block="pass", cleanup_block="pass"):
        _write(self.plugin_dir / filename, SLOW_PLUGIN_SOURCE.format(
            name=filename[:-3], import_block=import_block, init_block=init_block, cleanup_block=cleanup_block))

    def _manager(self):
        manager = PluginManager(self.plugin_dir, enabled=True, allow_user_plugins=True)
        manager.reload()
        return manager

    def test_slow_module_import_is_rejected(self):
        self._plugin("slow_import.py", import_block="_HOLD.wait(5)")
        self._plugin("ok_plugin.py")
        started = time.monotonic()
        manager = self._manager()
        self.assertLess(time.monotonic() - started, 3)
        names = set(manager._plugins)
        self.assertIn("ok_plugin", names)
        self.assertNotIn("slow_import", names)
        self.assertTrue(any("slow_import.py" in e and "zaman aşımı" in e for e in manager._errors), manager._errors)

    def test_slow_initialize_is_rejected(self):
        self._plugin("slow_init.py", init_block="_HOLD.wait(5)")
        manager = self._manager()
        self.assertNotIn("slow_init", manager._plugins)
        self.assertTrue(any("slow_init.py" in e and "zaman aşımı" in e for e in manager._errors), manager._errors)

    def test_slow_cleanup_does_not_block_reload(self):
        self._plugin("slow_cleanup.py", cleanup_block="_HOLD.wait(5)")
        manager = self._manager()
        self.assertIn("slow_cleanup", manager._plugins)
        started = time.monotonic()
        manager.reload()
        self.assertLess(time.monotonic() - started, 3)
        self.assertIn("slow_cleanup", manager._plugins)
        self.assertTrue(any("cleanup() zaman aşımı" in e for e in manager._errors), manager._errors)
