import os
import re
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

APP_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(APP_ROOT))

import tool_runtime_autodiscover  # noqa: E402


class StartupSafetyTests(unittest.TestCase):
    def test_autodiscover_never_overrides_operator_pins(self):
        pinned = {
            "SNIPER_NUCLEI_SHA256": "operator-pinned-nuclei",
            "SNIPER_NODE_SHA256": "operator-pinned-node",
            "SNIPER_TRIVY_BINARY": "/operator/pinned/trivy",
        }
        with patch.dict(os.environ, pinned, clear=False):
            os.environ.pop("SNIPER_DATA_DIR", None)
            tool_runtime_autodiscover.autodiscover_and_bind_runtimes(apply_env=True, persist=False)
            for key, value in pinned.items():
                self.assertEqual(os.environ.get(key), value, key)

    def test_server_main_keeps_plugins_opt_in(self):
        source = (APP_ROOT / "server.py").read_text(encoding="utf-8")
        main_body = source[source.index("def main() -> None:"):]
        self.assertIn('os.getenv("SNIPER_ENABLE_PLUGINS") == "1"', main_body)
        self.assertNotRegex(main_body, re.compile(r'SNIPER_ENABLE_PLUGINS"\)\s*!=\s*"0"'))
        self.assertIn('enabled=os.getenv("SNIPER_ENABLE_PLUGINS", "0") == "1"', source)


if __name__ == "__main__":
    unittest.main()


class PinnedBindingTests(unittest.TestCase):
    """Onaylı (ilk onayda sabitlenen) bağlamalar sonraki başlangıçlarda sessizce yenilenmez."""

    def setUp(self):
        import tempfile
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.data = Path(self._tmp.name)
        self.values = {"SNIPER_NUCLEI_BINARY": "/opt/nuclei", "SNIPER_NUCLEI_SHA256": "a" * 64}

    def _run(self, values, *, trust_disk=False):
        env = {"SNIPER_DATA_DIR": str(self.data)}
        with patch.dict(os.environ, env, clear=False):
            for key in self.values:
                os.environ.pop(key, None)
            with patch.object(tool_runtime_autodiscover, "_discover_bindings", return_value=(dict(values), [])), \
                    patch.object(tool_runtime_autodiscover, "runtime_readiness_payload", return_value={"tools": []}):
                result = tool_runtime_autodiscover.autodiscover_and_bind_runtimes(
                    apply_env=True, persist=True, trust_disk=trust_disk)
            applied = {key: os.environ.get(key) for key in self.values}
        return result, applied

    def test_first_start_records_then_detects_tampering(self):
        result, applied = self._run(self.values)
        self.assertEqual(applied, self.values)
        self.assertTrue(result["pins_recorded"])
        pins = self.data / tool_runtime_autodiscover.PINS_FILE
        self.assertEqual(oct(pins.stat().st_mode & 0o777), "0o600")
        tampered = dict(self.values, SNIPER_NUCLEI_SHA256="b" * 64)
        result, applied = self._run(tampered)
        self.assertEqual(result["pin_mismatches"], ["SNIPER_NUCLEI_SHA256"])
        self.assertEqual(applied["SNIPER_NUCLEI_SHA256"], "a" * 64)
        # Açık onay yeni değeri kayda geçirir.
        result, applied = self._run(tampered, trust_disk=True)
        self.assertEqual(result["pin_mismatches"], [])
        self.assertEqual(applied["SNIPER_NUCLEI_SHA256"], "b" * 64)
        result, applied = self._run(tampered)
        self.assertEqual(result["pin_mismatches"], [])

    def test_group_writable_pins_file_is_ignored(self):
        self._run(self.values)
        pins = self.data / tool_runtime_autodiscover.PINS_FILE
        os.chmod(pins, 0o666)
        self.assertIsNone(tool_runtime_autodiscover._load_pins(pins))
