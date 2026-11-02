from __future__ import annotations

import json
from pathlib import Path
import unittest

import joern_active
import tool_pins


ROOT = Path(__file__).resolve().parents[1]


class CompleteRuntimeRefreshR77Tests(unittest.TestCase):
    def test_scanner_and_analysis_runtime_pins_are_current(self) -> None:
        self.assertEqual(tool_pins.PINS["opengrep"].version, "1.33.1")
        self.assertEqual(tool_pins.PINS["node"].version, "26.13.0")
        self.assertEqual(tool_pins.PINS["joern-jdk"].version, "25.0.5+8")
        self.assertEqual(joern_active.JOERN_VERSION, "4.0.670")

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
        ):
            self.assertIn(expected, runtime)
        self.assertIn("pluggy==1.7.0", tests)
        self.assertIn("pytest==9.2.0", tests)
        self.assertIn("FROM python:3.15-slim", dockerfile)
        self.assertIn("prom/prometheus:v3.15.1", compose)
        self.assertIn("grafana/grafana:13.3.0", compose)
        self.assertEqual(workflows.count('python-version: "3.15"'), 2)
        self.assertEqual(workflows.count('node-version: "26.13.0"'), 2)


if __name__ == "__main__":
    unittest.main()
