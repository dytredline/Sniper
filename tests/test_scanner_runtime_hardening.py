from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import gitleaks_active
import lsp_server
import nmap_active
import testssl_active
import container_scan
from verified_exec import VerifiedExecutable


class ScannerRuntimeHardeningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(dir=Path.home(), prefix="vulkill_tool_env_")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def _script(self, name: str, body: str) -> Path:
        path = self.root / name
        path.write_text("#!/bin/sh\nset -eu\n" + body, encoding="utf-8")
        path.chmod(0o700)
        return path

    def test_real_child_receives_only_explicit_environment(self) -> None:
        from tool_child_env import isolated_tool_environment

        home = self.root / "home"
        cache = self.root / "cache"
        home.mkdir()
        cache.mkdir()
        poisoned = {
            "VULKILL_CANARY_SECRET": "must-not-cross",
            "AWS_SECRET_ACCESS_KEY": "also-must-not-cross",
            "HTTP_PROXY": "http://secret-user:secret-pass@proxy.invalid:8080",
            "PYTHONPATH": "/tmp/inject",
            "JAVA_TOOL_OPTIONS": "-javaagent:/tmp/inject.jar",
        }
        with mock.patch.dict(os.environ, poisoned, clear=False):
            env = isolated_tool_environment(
                home=home,
                tmpdir=home,
                overrides={"XDG_CACHE_HOME": str(cache), "TOOL_MODE": "offline"},
            )
            child = subprocess.run(
                [sys.executable, "-c", "import json,os; print(json.dumps(dict(os.environ),sort_keys=True))"],
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
                text=True,
            )
        observed = json.loads(child.stdout)
        self.assertEqual(observed["HOME"], str(home))
        self.assertEqual(observed["TMPDIR"], str(home))
        self.assertEqual(observed["XDG_CACHE_HOME"], str(cache))
        self.assertEqual(observed["TOOL_MODE"], "offline")
        for name in poisoned.keys() - {"HTTP_PROXY"}:
            self.assertNotIn(name, observed)
        self.assertEqual(observed["HTTP_PROXY"], "")

    def test_gitleaks_scan_keeps_coverage_without_inheriting_service_secret(self) -> None:
        project = self.root / "project"
        project.mkdir()
        (project / "app.py").write_text("token = 'fixture'\n", encoding="utf-8")
        data = self.root / "data"
        data.mkdir()
        tool = self._script(
            "fake-gitleaks",
            """
if [ -n "${VULKILL_CANARY_SECRET:-}" ]; then exit 77; fi
report=''
previous=''
for argument in "$@"; do
  if [ "$previous" = '--report-path' ]; then report="$argument"; fi
  previous="$argument"
done
[ -n "$report" ] || exit 78
printf '[]' > "$report"
""",
        )
        digest = hashlib.sha256(tool.read_bytes()).hexdigest()
        env = {
            "SNIPER_DATA_DIR": str(data),
            "SNIPER_GITLEAKS_BINARY": str(tool),
            "SNIPER_GITLEAKS_SHA256": digest,
            "VULKILL_CANARY_SECRET": "must-not-cross",
        }
        with mock.patch.dict(os.environ, env, clear=False):
            result = gitleaks_active.run_local_gitleaks(str(project))
        self.assertEqual(result["format"], "gitleaks-native-json")
        self.assertEqual(result["total_findings"], 0)

    def test_authorized_nmap_executes_verified_inode_after_path_replacement(self) -> None:
        good = self._script(
            "nmap",
            """cat <<'EOF'
<nmaprun><host><status state="up"/><ports><port protocol="tcp" portid="80"><state state="open"/></port></ports></host></nmaprun>
EOF
""",
        )
        replacement = self._script("replacement", "exit 77\n")
        digest = hashlib.sha256(good.read_bytes()).hexdigest()
        with mock.patch.dict(
            os.environ,
            {"SNIPER_NMAP_BINARY": str(good), "SNIPER_NMAP_SHA256": digest},
            clear=False,
        ):
            executable = nmap_active._trusted_authorized_nmap_binary()
        self.assertIsInstance(executable, VerifiedExecutable)
        os.replace(replacement, good)
        try:
            _xml, hosts, up, open_count, ports = nmap_active._run_nmap(
                "127.0.0.1", False, [80], binary=executable
            )
        finally:
            executable.close()
        self.assertEqual((hosts, up, open_count, ports), (1, 1, 1, [80]))

    def test_registered_target_nmap_discovery_is_also_fd_bound(self) -> None:
        tool = self._script("registered-nmap", "exit 0\n")
        digest = hashlib.sha256(tool.read_bytes()).hexdigest()
        with mock.patch.dict(
            os.environ,
            {"SNIPER_NMAP_BINARY": str(tool), "SNIPER_NMAP_SHA256": digest},
            clear=False,
        ):
            executable = nmap_active._find_nmap_binary()
        self.assertIsInstance(executable, VerifiedExecutable)
        assert executable is not None
        try:
            self.assertEqual(executable.sha256, digest)
        finally:
            executable.close()

    def test_loopback_testssl_opens_verified_executable(self) -> None:
        tool = self._script("testssl", "exit 0\n")
        digest = hashlib.sha256(tool.read_bytes()).hexdigest()
        with mock.patch.dict(
            os.environ,
            {"SNIPER_TESTSSL_BINARY": str(tool), "SNIPER_TESTSSL_SHA256": digest},
            clear=False,
        ):
            executable = testssl_active._trusted_testssl_binary()
        try:
            self.assertIsInstance(executable, VerifiedExecutable)
            self.assertEqual(executable.sha256, digest)
        finally:
            executable.close()

    def test_lsp_worker_keeps_analysis_limits_without_service_secrets(self) -> None:
        project = self.root / "lsp-project"
        project.mkdir()
        document = project / "app.py"
        document.write_text("print('fixture')\n", encoding="utf-8")
        server = lsp_server.VulKillLanguageServer(
            io.BytesIO(),
            io.BytesIO(),
            cache_dir=self.root / "lsp-cache",
            synchronous=True,
        )
        captured: dict[str, str] = {}

        class Child:
            returncode = 0

            def communicate(self, _input: bytes, timeout: float):
                del timeout
                return b'{"ok":true,"findings":[]}', b""

        def fake_popen(*_args, **kwargs):
            captured.update(kwargs["env"])
            return Child()

        poisoned = {
            "VULKILL_CANARY_SECRET": "must-not-cross",
            "AWS_SECRET_ACCESS_KEY": "must-not-cross",
            "PYTHONPATH": "/tmp/inject",
            "JAVA_TOOL_OPTIONS": "-javaagent:/tmp/inject.jar",
            "SNIPER_PROJECT_MAX_FILES": "12345",
            "SNIPER_TAINT_MAX_ROUNDS": "17",
        }
        doc = lsp_server.Document(document.as_uri(), document, project, "app.py", "", 1)
        with mock.patch.dict(os.environ, poisoned, clear=False), mock.patch(
            "lsp_server.subprocess.Popen", side_effect=fake_popen
        ):
            self.assertEqual(server._run_worker(doc, {}), [])
        self.assertEqual(captured["SNIPER_PROJECT_MAX_FILES"], "12345")
        self.assertEqual(captured["SNIPER_TAINT_MAX_ROUNDS"], "17")
        for name in ("VULKILL_CANARY_SECRET", "AWS_SECRET_ACCESS_KEY", "PYTHONPATH", "JAVA_TOOL_OPTIONS"):
            self.assertNotIn(name, captured)

    def test_zstd_decoder_does_not_receive_service_secret(self) -> None:
        decoder = self._script(
            "zstd",
            """
if [ -n "${VULKILL_CANARY_SECRET:-}" ]; then exit 77; fi
cat
""",
        )
        payload = b"zstd-decoder-fixture"
        with mock.patch.dict(os.environ, {"VULKILL_CANARY_SECRET": "must-not-cross"}, clear=False):
            reader = container_scan._ZstdReader(io.BytesIO(payload), str(decoder))
            try:
                self.assertEqual(reader.read(), payload)
            finally:
                reader.close()


if __name__ == "__main__":
    unittest.main()
