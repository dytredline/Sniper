from __future__ import annotations

import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import zap_authorized


class ZapAuthorizedRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="sniper_zap_authorized_runtime_")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.data_dir = self.root / "data"
        self.data_dir.mkdir(mode=0o700)
        self.env = mock.patch.dict(os.environ, {"SNIPER_DATA_DIR": str(self.data_dir)})
        self.env.start()
        self.addCleanup(self.env.stop)

    def test_plan_is_same_origin_path_scoped_and_budgeted(self) -> None:
        plan = zap_authorized.build_plan("http://127.0.0.1:43117/app", self.root)
        pattern = None
        lines = plan.splitlines()
        for index, line in enumerate(lines):
            if line.strip() == "includePaths:":
                pattern = json.loads(lines[index + 1].strip()[2:])
                break
        self.assertIsNotNone(pattern)
        self.assertRegex("http://127.0.0.1:43117/app", pattern)
        self.assertRegex("http://127.0.0.1:43117/app/page?q=1", pattern)
        self.assertIsNone(re.fullmatch(pattern, "http://127.0.0.1:43117/outside"))
        self.assertIsNone(re.fullmatch(pattern, "http://127.0.0.1:43118/app"))
        self.assertIn("type: spider", plan)
        self.assertIn("type: activeScan", plan)
        self.assertIn("maxDuration: 210", plan)
        self.assertIn("maxScanDurationInMins: 2", plan)
        self.assertIn("maxRuleDurationInMins: 1", plan)
        self.assertIn("threadPerHost: 1", plan)
        self.assertIn("delayInMs: 1000", plan)
        self.assertNotIn("authentication:", plan)

    def test_resolution_accepts_loopback_and_private_but_rejects_unusable_addresses(self) -> None:
        def rows(*addresses: str) -> list[tuple]:
            return [(socket.AF_INET6 if ":" in address else socket.AF_INET,
                     socket.SOCK_STREAM, 6, "", (address, 443, 0, 0) if ":" in address else (address, 443))
                    for address in addresses]

        with mock.patch.object(socket, "getaddrinfo", return_value=rows("127.0.0.1", "10.0.0.8")):
            self.assertEqual(
                zap_authorized.resolve_authorized_ips("https://lab.internal/"),
                ["10.0.0.8", "127.0.0.1"],
            )
        for address in ("0.0.0.0", "224.0.0.1", "::"):
            with self.subTest(address=address), \
                 mock.patch.object(socket, "getaddrinfo", return_value=rows(address)), \
                 self.assertRaises(ValueError):
                zap_authorized.resolve_authorized_ips("https://lab.internal/")

    def test_fake_runtime_executes_real_subprocess_and_cleans_work_directory(self) -> None:
        fake_systemd = self.root / "fake-systemd-run"
        fake_systemd.write_text(
            f"#!{sys.executable}\n"
            "import json, pathlib, sys\n"
            "plan = pathlib.Path(sys.argv[-1])\n"
            "report = plan.parent / 'report.json'\n"
            "report.write_text(json.dumps({'site':[{'alerts':[{'riskcode':'1','count':'2'}]}]}))\n",
            encoding="utf-8",
        )
        fake_systemd.chmod(0o700)
        with mock.patch.object(zap_authorized, "_trusted_runtime", return_value=(str(fake_systemd), self.root)), \
             mock.patch.object(zap_authorized, "resolve_authorized_ips", return_value=["127.0.0.1"]):
            result = zap_authorized.run_zap_authorized("http://127.0.0.1:43117/app")

        self.assertEqual(result["format"], "zap-authorized-v1")
        self.assertEqual(result["profile"], "same-origin-authorized-spider-active-v1")
        self.assertEqual(result["instance_count"], 2)
        self.assertEqual(result["risk_counts"]["low"], 1)
        self.assertFalse(any(self.data_dir.glob("sniper_zap_authorized_*")))

    def test_readiness_names_the_exact_missing_prerequisite(self) -> None:
        missing = self.root / "missing-systemd-run"
        with mock.patch.object(zap_authorized, "SYSTEMD_RUN", missing):
            result = zap_authorized.runtime_readiness()
        self.assertFalse(result["ready"])
        self.assertTrue(any(item.startswith(f"systemd-run:missing:{missing}") for item in result["missing"]))
        row = next(item for item in result["checks"] if item["id"] == "systemd-run")
        self.assertEqual(row["reason"], "missing")

    def test_timeout_stops_unit_kills_process_and_cleans_work_directory(self) -> None:
        process = mock.Mock()
        process.wait.side_effect = [subprocess.TimeoutExpired(cmd="zap", timeout=250), 0]
        with mock.patch.object(zap_authorized, "_trusted_runtime", return_value=("/fake/systemd-run", self.root)), \
             mock.patch.object(zap_authorized, "resolve_authorized_ips", return_value=["127.0.0.1"]), \
             mock.patch.object(zap_authorized.subprocess, "Popen", return_value=process), \
             mock.patch.object(zap_authorized, "_stop_unit") as stop_unit, \
             self.assertRaises(zap_authorized.ZapExecutionError):
            zap_authorized.run_zap_authorized("http://127.0.0.1:43117/app")
        stop_unit.assert_called_once()
        self.assertTrue(stop_unit.call_args.args[0].startswith("sniper-zap-authorized-"))
        process.kill.assert_called_once_with()
        self.assertEqual(process.wait.call_count, 2)
        self.assertFalse(any(self.data_dir.glob("sniper_zap_authorized_*")))

    def test_target_normalization_and_ambiguous_paths_fail_closed(self) -> None:
        self.assertEqual(
            zap_authorized.normalize_authorized_target("HTTP://Example.TEST:80/app"),
            "http://example.test/app",
        )
        for target in (
            "https://example.test/app%2fadmin",
            "https://example.test/app/../admin",
            "https://example.test/app//admin",
            "https://example.test/app;session=1",
        ):
            with self.subTest(target=target), self.assertRaises(ValueError):
                zap_authorized.normalize_authorized_target(target)


if __name__ == "__main__":
    unittest.main()
