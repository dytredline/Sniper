from __future__ import annotations

import json
from pathlib import Path
import unittest
from unittest import mock

import joern_active
import nuclei_catalog_integrity
import nuclei_catalog_resolver
import schemathesis_active
import schemathesis_loopback_active
import tool_pins
from scripts import install_nuclei_catalog


ROOT = Path(__file__).resolve().parents[1]
PHP_8_3_36 = ROOT.parent / "runtimes" / "php" / "8.3.36"
PHP_8_3_36_SHA256 = "5f80b719c8f00d1045fbc02b4349011cb75d412b3c6fb033475fd30ef9355416"


class CompleteRuntimeRefreshR77Tests(unittest.TestCase):
    def test_scanner_and_analysis_runtime_pins_are_current(self) -> None:
        self.assertEqual(tool_pins.PINS["opengrep"].version, "1.33.1")
        self.assertEqual(tool_pins.PINS["node"].version, "26.13.0")
        self.assertEqual(tool_pins.PINS["joern-jdk"].version, "25.0.5+8")
        self.assertEqual(joern_active.JOERN_VERSION, "4.0.670")

    def test_nuclei_template_catalog_pin_is_current(self) -> None:
        self.assertEqual(install_nuclei_catalog.VERSION, "v10.5.1")
        self.assertEqual(install_nuclei_catalog.ARCHIVE_PREFIX, "nuclei-templates-10.5.1")
        self.assertEqual(nuclei_catalog_integrity.EXPECTED_INDEX_VERSION, "v10.5.1")
        self.assertEqual(nuclei_catalog_resolver.EXPECTED_INDEX_VERSION, "v10.5.1")

    def test_schemathesis_runtime_and_loopback_image_are_current(self) -> None:
        self.assertIn("schemathesis-4.33.0", str(schemathesis_active.ST_EXECUTABLE))
        self.assertEqual(
            schemathesis_active.ST_EXECUTABLE_SHA256,
            "ba97f7abc3529c2d94d9cbb9e12b8e00276a9cae2aaecedb0f1f76eba38d48ad",
        )
        self.assertEqual(
            schemathesis_loopback_active.DOCKER_IMAGE_ID,
            "sha256:6cd257797e2aa4b59497614799f7c2ac7cdce4a066d0781503c5c0799af7e906",
        )
        container = (ROOT / "schemathesis_loopback_container.py").read_text(encoding="utf-8")
        self.assertIn('version("schemathesis") != "4.33.0"', container)

    def test_community_lock_uses_current_opengrep_assets(self) -> None:
        lock = json.loads((ROOT / "COMMUNITY-TOOLS.lock.json").read_text(encoding="utf-8"))
        spec = lock["tools"]["opengrep"]
        self.assertEqual(spec["version"], "1.33.1")
        self.assertEqual(spec["destination"], "opengrep-1.33.1")
        self.assertEqual(
            spec["platforms"]["linux-aarch64"]["sha256"],
            "d1433f63a90b8bc0b6ad4b498a13b372b856ce9a754a43484ba4920fe2d76dcf",
        )
        self.assertEqual(
            spec["platforms"]["linux-x86_64"]["sha256"],
            "46e8133cc490f9f50518061590ce2f6be5a08afaeda034471c0ceda4b3899808",
        )

    def test_ci_and_container_dependency_contract_is_current(self) -> None:
        runtime = (ROOT / "requirements-runtime.lock").read_text(encoding="utf-8")
        tests = (ROOT / "requirements-test.lock").read_text(encoding="utf-8")
        dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        workflows = "\n".join(
            (ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8")
            for name in ("ci.yml", "release.yml")
        )

        for expected in (
            "cffi==2.1.1",
            "cryptography==50.0.2",
            "packaging==26.3",
            "pycparser==3.12",
            "PyYAML==6.0.3",
            "regex==2026.9.29",
        ):
            self.assertIn(expected, runtime)
        self.assertIn("pluggy==1.7.0", tests)
        self.assertIn("pytest==9.2.0", tests)
        self.assertIn("FROM python:3.15-slim", dockerfile)
        self.assertIn("prom/prometheus:v3.15.1", compose)
        self.assertIn("grafana/grafana:13.3.0", compose)
        self.assertEqual(workflows.count('python-version: "3.15"'), 2)
        self.assertEqual(workflows.count('node-version: "26.13.0"'), 2)

    @unittest.skipUnless((PHP_8_3_36 / "bin" / "php").is_file(), "doğrulanmış PHP 8.3.36 adayı yok")
    def test_verified_php_security_runtime_is_approved_and_usable(self) -> None:
        self.assertIn(PHP_8_3_36_SHA256, joern_active.PHP_APPROVED_BINARY_SHA256)
        with mock.patch.object(joern_active, "php_home", return_value=PHP_8_3_36):
            binary = joern_active.verified_php()
            self.assertTrue(binary.startswith(b"\x7fELF"))


if __name__ == "__main__":
    unittest.main()
