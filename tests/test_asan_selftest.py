from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

import asan_selftest
import server


class AsanSelftestTests(unittest.TestCase):
    def test_fixed_clean_and_uaf_controls_prove_runtime(self) -> None:
        if shutil.which("clang") is None:
            self.skipTest("clang yok")
        result = asan_selftest.run(confirm_local=True)
        self.assertEqual(result["format"], "sniper-asan-selftest/1")
        self.assertTrue(result["available"], result)
        self.assertEqual(result["clean"], {"compiled": True, "exit_ok": True, "asan_error": False})
        self.assertEqual(result["uaf"], {"compiled": True, "exit_ok": False, "asan_error": True,
                                          "error_class": "heap-use-after-free"})
        self.assertEqual(result["verdict"], "passed")
        self.assertEqual(set(result["fixture_sha256"]), {"clean", "uaf"})
        self.assertNotIn("stderr", result)
        self.assertNotIn("source", result)

    def test_consent_and_compiler_boundary_fail_closed(self) -> None:
        with self.assertRaises(asan_selftest.AsanSelftestError):
            asan_selftest.run(confirm_local=False)
        with mock.patch.dict(os.environ, {"SNIPER_CLANG_BINARY": "/bin/sh"}):
            with self.assertRaises(asan_selftest.AsanUnavailable):
                asan_selftest.run(confirm_local=True)
        with mock.patch.dict(os.environ, {"SNIPER_CLANG_BINARY": "/usr/bin/clang",
                                          "SNIPER_CLANG_ASAN_SHA256": "0" * 64}):
            with self.assertRaises(asan_selftest.AsanUnavailable):
                asan_selftest.run(confirm_local=True)

    def test_sources_are_fixed_and_no_project_argument_exists(self) -> None:
        self.assertEqual(set(asan_selftest.FIXTURES), {"clean", "uaf"})
        for name, source in asan_selftest.FIXTURES.items():
            self.assertIn("int main(void)", source, name)
        with self.assertRaises(TypeError):
            asan_selftest.run(confirm_local=True, project_path="/tmp/project")


class AsanSelftestApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(dir=Path.home())
        self.addCleanup(self.temp.cleanup)
        self.client = server.SniperHandler.__new__(server.SniperHandler)
        self.responses: list[tuple[int, dict]] = []
        self.client._json = lambda body, status=200, **_kw: self.responses.append((int(status), body))
        self.client._error = lambda status, message: self.responses.append((int(status), {"error": message}))

    def test_handler_returns_sanitized_result_and_rejects_extra_fields(self) -> None:
        expected = {"format": "sniper-asan-selftest/1", "available": True, "verdict": "passed"}
        with mock.patch.object(asan_selftest, "run", return_value=expected) as run:
            self.client._asan_selftest_post({"confirm_local": True})
        self.assertEqual(self.responses.pop(), (200, expected))
        run.assert_called_once_with(confirm_local=True)

        self.client._asan_selftest_post({"confirm_local": True, "project_path": "/tmp/x"})
        self.assertEqual(self.responses.pop()[0], 400)


if __name__ == "__main__":
    unittest.main()
