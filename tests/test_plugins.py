from pathlib import Path
import os
import stat
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.plugin_manager import PluginManager  # noqa: E402


PLUGIN_SOURCE = '''
from plugins.base_plugin import BasePlugin, PluginInfo

class DemoPlugin(BasePlugin):
    @property
    def info(self):
        return PluginInfo("demo", "1.0", "local", "test plugin")

    def scan(self, target):
        return [{
            "id": "demo-passive",
            "severity": "low",
            "title": "Demo passive finding",
            "description": "Validated plugin result",
            "evidence": target,
            "recommendation": "Review locally",
            "reference": "TEST",
        }]

PLUGIN = DemoPlugin()
'''


class PluginManagerTests(unittest.TestCase):
    def test_plugins_are_opt_in(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "demo.py"
            path.write_text(PLUGIN_SOURCE, encoding="utf-8")
            manager = PluginManager(Path(directory), enabled=False)
            manager.reload()
            self.assertEqual(manager.loaded_count, 0)

    def test_loads_trusted_plugin_and_validates_finding(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "demo.py"
            path.write_text(PLUGIN_SOURCE, encoding="utf-8")
            os.chmod(path, 0o600)
            # demo.py yerleşik değil: kullanıcı eklentisi ayrı açık izin ister.
            manager = PluginManager(Path(directory), enabled=True, allow_user_plugins=True)
            manager.reload()
            self.assertEqual(manager.loaded_count, 1)
            findings = manager.scan_all("https://example.test/")
            self.assertEqual(findings[0]["plugin"], "demo")
            self.assertEqual(findings[0]["detection"], "trusted-local-plugin")

    def test_rejects_world_writable_plugin(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "unsafe.py"
            path.write_text(PLUGIN_SOURCE, encoding="utf-8")
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IWOTH)
            manager = PluginManager(Path(directory), enabled=True, allow_user_plugins=True)
            manager.reload()
            status = manager.public_status()
            self.assertEqual(status["loaded"], 0)
            self.assertIn("yazılabilen eklenti reddedildi", status["errors"][0])


if __name__ == "__main__":
    unittest.main()

# Yeni test eklemeleri için marker
TEST_ADDED = "test extension added for coverage"
